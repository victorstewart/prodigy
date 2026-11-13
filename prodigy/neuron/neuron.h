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
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
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
#include <prodigy/debug.h>
#include <prodigy/brain/base.h>
#include <prodigy/brain/timing.knobs.h>
#include <prodigy/neuron/bgp.runtime.h>
#include <prodigy/neuron/private.tunnel.bgp.runtime.h>
#include <prodigy/neuron/masque.gateway.launch.h>
#include <prodigy/neuron/containers.h>
#include <prodigy/bundle.artifact.h>
#include <prodigy/artifact.io.h>
#include <prodigy/persistent.state.h>
#include <prodigy/machine.hardware.h>
#include <prodigy/netdev.detect.h>
#include <prodigy/transport.artifact.h>
#include <prodigy/cluster.pair.projection.h>
#include <prodigy/cross.cluster.mesh.route.h>
#include <prodigy/cousin.discovery.h>
#include <prodigy/cousin.session.h>
#include <switchboard/overlay.route.h>
#include <switchboard/pair.control.h>
#include <switchboard/switchboard.h>
#include <switchboard/whitehole.route.h>
#include <switchboard/host.tcx.retention.h>
#include <prodigy/ingress.validation.h>
#include <prodigy/additional.ingress.h>
#include <prodigy/wire.h>

class NeuronBrainControlStream : public RingInterface, public ProdigyArtifactStream {
public:

  bool connected = false;
  bool initialMachineHardwareProfileQueued = false;
  bool transitionAfterBundleAck = false;
  bool transportLifecycleCandidate = false;
  bool closeAfterTransportLifecycleAck = false;
  bool commandsRejected = false;
  std::shared_ptr<uint8_t> connectionLifetime = std::make_shared<uint8_t>(0);

  void reset(void) override
  {
    ProdigyArtifactStream::reset();
    connectionLifetime = std::make_shared<uint8_t>(0);
    connected = false;
    initialMachineHardwareProfileQueued = false;
    transitionAfterBundleAck = false;
    transportLifecycleCandidate = false;
    closeAfterTransportLifecycleAck = false;
    commandsRejected = false;
  }
};

class Neuron : public NeuronBase, public RingInterface {
protected:

  // This is deliberately a local receipt cache, not a second authority
  // ledger. Mothership/Brain supplies the durable authority and the typed
  // system-container plan; Switchboard supplies the authenticated data-plane
  // observation. A changed authority invalidates the old receipt before any
  // /96 can remain originated.
  struct CrossClusterMasqueGatewayRuntime {
    struct PendingLaunch {
      ContainerPlan plan;
      uint64_t controlGeneration = 0;
      uint128_t replaceContainerUUID = 0;
      NeuronContainerMetricPolicy metricPolicy;
      RetainedContainerStorageSource retainedSource;
    };
    // A physical gateway can terminate two independent pair authorities, but
    // they must never share credentials, readiness, or a BGP lifecycle.
    // `pairUUID` is the lifecycle key; gatewaySlot is an admission bound.
    static constexpr uint8_t maximumAuthoritiesPerMachine = 2;
    CrossClusterMasqueGatewayAuthority authority = {};
    ProdigyCrossClusterMasqueGatewayReadiness readiness = {};
    uint128_t systemContainerUUID = 0;
    String readinessLaunchToken;
    String recoveryLaunchToken;
    bool systemPlanAdmitted = false;
    bool sitePrefixAdvertised = false;
    SwitchboardOverlayMachineRoute privateBGPFallback = {};
    bool privateBGPFallbackInstalled = false;
    bool privateBGPFallbackProgrammed = false;
    // A failed program removal must survive a BGP-owner observer/replay.  The
    // next authenticated terminal withdrawal retries the existing overlay
    // reconciler instead of inferring absence from cleared desired-state bits.
    bool privateBGPFallbackRemovalPending = false;
    std::unique_ptr<NeuronPrivateTunnelBGPRuntime> privateTunnelBGP;
    ProdigyCrossClusterPathFaultRequest faultLease = {};
    ProdigyCrossClusterPathFaultRequest completedFaultLease = {};
    bool faultLeaseActive = false, faultResumeAcknowledged = false;
    uint64_t faultMonotonicDeadlineNs = 0;
    // Volatile Vault delivery only. Neither this material nor the deferred
    // launch frame is serialized into a Brain snapshot or container plan.
    std::unique_ptr<ProdigyPairPrivateBGPSecretDeliveryResponse> gatewayBootstrap;
    std::unique_ptr<PendingLaunch> pendingLaunch;

    void revokeReadiness(void)
    {
      readiness = {};
    }

    bool authorityMatches(const CrossClusterMasqueGatewayAuthority& candidate) const
    {
      if (authority.pairUUID == 0 || candidate.generation != authority.generation)
      {
        return false;
      }
      String expected = {};
      String observed = {};
      auto expectedCopy = authority;
      auto observedCopy = candidate;
      return BitseryEngine::serialize(expected, expectedCopy) &&
          BitseryEngine::serialize(observed, observedCopy) && expected == observed;
    }
  };

  // This local Unix stream is intentionally not a NeuronHub stream: gateway
  // health is an observation made after mTLS/routing, not a control command.
  class CrossClusterMasqueGatewayReadinessListener final : public SocketBase {
  public:
    struct PeerIdentity {
      pid_t pid = -1;
      uint64_t startTime = 0;
      String cgroupLeaf = {};
      uint64_t netnsDevice = 0, netnsInode = 0;
      bool operator==(const PeerIdentity& rhs) const
      { return pid == rhs.pid && startTime == rhs.startTime && cgroupLeaf == rhs.cgroupLeaf && netnsDevice == rhs.netnsDevice && netnsInode == rhs.netnsInode; }
    };
    using PeerIdentityCapture = std::function<bool(pid_t, PeerIdentity&)>;
    static constexpr uint32_t maximumFrameBytes = 512;
    uint128_t containerUUID = 0;
    String path;
    String expectedCgroup;
    uint32_t expectedHostID = 0;
    bool recovery = false;
    uint64_t recoveryEpoch = 0;
    ProdigyGatewayLocalTuple recoveryTuple = {};
    String recoveryToken = {};
    PeerIdentity retainedIdentity = {};
    PeerIdentityCapture capturePeerIdentity = capturePeerIdentityFromProc;

    static bool capturePeerIdentityFromProc(pid_t pid, PeerIdentity& identity)
    {
      identity = {};
      if (pid <= 0) return false;
      String stat = {}, cgroup = {}, proc = {};
      proc.snprintf<"/proc/{itoa}/stat"_ctv>(uint64_t(pid));
      Filesystem::openReadAtClose(-1, proc, stat, 4096);
      proc.snprintf<"/proc/{itoa}/cgroup"_ctv>(uint64_t(pid));
      Filesystem::openReadAtClose(-1, proc, cgroup, 512);
      if (stat.empty() || cgroup.empty()) return false;
      const char *closing = strrchr(stat.c_str(), ')');
      if (closing == nullptr || closing[1] != ' ') return false;
      // starttime is field 22; the post-comm tail begins at field 3.
      const char *cursor = closing + 2;
      for (uint32_t field = 3; field < 22; ++field) {
        cursor = strchr(cursor, ' '); if (cursor == nullptr) return false; ++cursor;
      }
      char *end = nullptr; errno = 0;
      const unsigned long long start = strtoull(cursor, &end, 10);
      if (errno || end == cursor || start == 0) return false;
      const char *prefix = "0::";
      if (strncmp(cgroup.c_str(), prefix, 3) != 0) return false;
      const char *newline = strchr(cgroup.c_str(), '\n');
      if (newline == nullptr || newline[1] != '\0' || newline == cgroup.c_str() + 3) return false;
      proc.snprintf<"/proc/{itoa}/ns/net"_ctv>(uint64_t(pid));
      struct stat netns = {};
      if (::stat(proc.c_str(), &netns) != 0 || netns.st_dev == 0 || netns.st_ino == 0) return false;
      identity.pid = pid; identity.startTime = uint64_t(start);
      identity.cgroupLeaf.assign(cgroup.c_str() + 3, uint32_t(newline - (cgroup.c_str() + 3)));
      identity.netnsDevice = uint64_t(netns.st_dev); identity.netnsInode = uint64_t(netns.st_ino);
      return true;
    }

    void closeListener(void)
    {
      if (fd >= 0)
      {
        (void)::close(fd);
        fd = -1;
      }
    }

    void reset(void) override
    {
      SocketBase::reset();
      containerUUID = 0;
      path.clear();
      expectedCgroup.clear();
      recovery = false; recoveryEpoch = 0; recoveryTuple = {}; recoveryToken.clear(); retainedIdentity = {};
    }

    bool peerCgroupMatches(pid_t peerPID) const
    {
      if (peerPID <= 0 || expectedCgroup.size() == 0) return false;
      String proc = {};
      proc.snprintf<"/proc/{itoa}/cgroup"_ctv>(uint64_t(peerPID));
      String actual = {};
      Filesystem::openReadAtClose(-1, proc, actual, 512);
      if (actual.size() == 0) return false;
      String expected = {};
      expected.assign("0::"_ctv);
      expected.append(expectedCgroup);
      expected.append("\n"_ctv);
      return actual.equal(expected);
    }

    bool openFor(const Container& container, String *failure = nullptr)
    {
      closeListener();
      containerUUID = container.plan.uuid;
      expectedHostID = container.executionHostID;
      if (container.runtimePath.empty() ||
          !Container::gatewayReadinessSocketPath(container.plan.uuid, container.plan.system.gatewayLaunchToken, path) ||
          path != container.plan.system.gatewayReadinessSocket) return false;
      prodigyContainerCgroupProcLeafSuffix(container.name, expectedCgroup);
      if (path.size() >= sizeof(sockaddr_un::sun_path)) return false;
      fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      if (fd < 0) return false;
      (void)unlink(path.c_str());
      sockaddr_un address = {};
      address.sun_family = AF_UNIX;
      memcpy(address.sun_path, path.data(), path.size());
      const socklen_t length = socklen_t(offsetof(sockaddr_un, sun_path) + path.size() + 1);
      if (::bind(fd, reinterpret_cast<sockaddr *>(&address), length) != 0 ||
          ::chown(path.c_str(), uid_t(expectedHostID), gid_t(expectedHostID)) != 0 ||
          ::chmod(path.c_str(), 0600) != 0 || ::listen(fd, 4) != 0)
      {
        if (failure) failure->assign("cross-cluster MASQUE readiness listener bind failed"_ctv);
        closeListener();
        (void)unlink(path.c_str());
        return false;
      }
      return true;
    }

    bool openForRecovery(const Container& container, const String& socket, const String& token,
                         const ProdigyGatewayLocalTuple& tuple, uint64_t epoch, String *failure = nullptr)
    {
      if (!prodigyGatewayLocalTupleValid(tuple) || !ContainerManager::gatewayRecoveryTokenValid(token) ||
          socket.empty() || container.pid <= 0 || !capturePeerIdentity(container.pid, retainedIdentity)) return false;
      closeListener(); containerUUID = container.plan.uuid; expectedHostID = container.executionHostID;
      path.assign(socket); recovery = true; recoveryEpoch = epoch; recoveryTuple = tuple; recoveryToken.assign(token);
      prodigyContainerCgroupProcLeafSuffix(container.name, expectedCgroup);
      if (retainedIdentity.cgroupLeaf != expectedCgroup || path.size() >= sizeof(sockaddr_un::sun_path)) return false;
      fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); if (fd < 0) return false;
      (void)unlink(path.c_str()); sockaddr_un address = {}; address.sun_family = AF_UNIX;
      memcpy(address.sun_path, path.data(), path.size());
      const socklen_t length = socklen_t(offsetof(sockaddr_un, sun_path) + path.size() + 1);
      if (::bind(fd, reinterpret_cast<sockaddr *>(&address), length) != 0 ||
          ::chown(path.c_str(), uid_t(expectedHostID), gid_t(expectedHostID)) != 0 ||
          ::chmod(path.c_str(), 0600) != 0 || ::listen(fd, 4) != 0) {
        if (failure) failure->assign("cross-cluster MASQUE recovery listener bind failed"_ctv);
        closeListener(); (void)unlink(path.c_str()); return false;
      }
      return true;
    }

    void teardown(void)
    {
      closeListener();
      if (path.size()) (void)unlink(path.c_str());
      path.clear(); expectedCgroup.clear(); containerUUID = 0; recovery = false; recoveryEpoch = 0; recoveryTuple = {}; recoveryToken.clear(); retainedIdentity = {};
    }

    // The accepted stream itself is the readiness lease.  Neuron retains it
    // after the initial record so EOF is an immediate withdrawal rather than
    // a one-shot startup observation that can remain cached after path loss.
    bool acceptCarrier(int& stream, pid_t& peerPID)
    {
      stream = -1;
      peerPID = -1;
      stream = accept4(fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (stream < 0) return false;
#ifdef SO_PEERCRED
      ucred peer = {};
      socklen_t peerLength = sizeof(peer);
      PeerIdentity observed = {};
      const bool credentialsOK = getsockopt(stream, SOL_SOCKET, SO_PEERCRED, &peer, &peerLength) == 0 &&
          peerLength >= sizeof(peer) && Container::gatewayReadinessPeerIDsMatch(expectedHostID, peer.uid, peer.gid) &&
          peerCgroupMatches(peer.pid) && (!recovery || (capturePeerIdentity(peer.pid, observed) && observed == retainedIdentity));
      peerPID = credentialsOK ? peer.pid : -1;
#else
      const bool credentialsOK = false;
#endif
      if (!credentialsOK)
      {
        (void)::close(stream);
        stream = -1;
        return false;
      }
      return true;
    }
  };

  class CrossClusterMasqueGatewayReadinessCarrier final : public StreamBase, public SocketBase {
  public:
    uint128_t containerUUID = 0;
    pid_t peerPID = -1;
    bool receiptAccepted = false;
    bool recovery = false;
    uint64_t recoveryEpoch = 0;
    ProdigyGatewayLocalTuple recoveryTuple = {};
    String recoveryToken = {};
    uint8_t recoveryNonce[16] = {};
    CrossClusterMasqueGatewayReadinessListener::PeerIdentity retainedIdentity = {};
    CrossClusterMasqueGatewayReadinessListener::PeerIdentityCapture capturePeerIdentity =
        CrossClusterMasqueGatewayReadinessListener::capturePeerIdentityFromProc;
    ProdigyGatewayLocalCarrierMode localMode = ProdigyGatewayLocalCarrierMode::undecided;
    ProdigyGatewayLocalCarrierPhase localPhase = ProdigyGatewayLocalCarrierPhase::initial;
    // The local carrier owns at most one in-flight gateway frame and one
    // exact lease. Neither is an assertion that the dataplane is ready.
    ProdigyCrossClusterPathFaultControl faultControl = {};
    ProdigyCrossClusterPathFaultGatewayControlPayload faultFrame = {};
    bool faultFramePending = false;
    bool faultWaitingDown = false, faultWaitingRestore = false;
    uint64_t faultDeadlineNs = 0;

    CrossClusterMasqueGatewayReadinessCarrier()
    {
      rBuffer.reserve(CrossClusterMasqueGatewayReadinessListener::maximumFrameBytes);
    }

    void reset(void) override
    {
      StreamBase::reset();
      SocketBase::reset();
      containerUUID = 0;
      peerPID = -1;
      receiptAccepted = false;
      recovery = false; recoveryEpoch = 0; recoveryTuple = {}; recoveryToken.clear(); memset(recoveryNonce, 0, sizeof(recoveryNonce));
      retainedIdentity = {}; capturePeerIdentity = CrossClusterMasqueGatewayReadinessListener::capturePeerIdentityFromProc;
      localMode = ProdigyGatewayLocalCarrierMode::undecided; localPhase = ProdigyGatewayLocalCarrierPhase::initial;
      faultControl = {}; faultFrame = {};
      faultFramePending = false; faultWaitingDown = false; faultWaitingRestore = false; faultDeadlineNs = 0;
      rBuffer.reserve(CrossClusterMasqueGatewayReadinessListener::maximumFrameBytes);
    }
  };

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

  struct PendingReceivedBundleArtifact {
    NeuronBrainControlStream *stream = nullptr;
    uint64_t streamGeneration = 0;
    uint128_t peerUUID = 0;
    String bundle = {};
    String expectedDigest = {};
    String actualDigest = {};
    String failure = {};
    ProdigyPreparedBundleArtifact prepared = {};
    bool durable = false;
  };

  NeuronIaaS *iaas;
  std::unique_ptr<NeuronBGPRuntime> bgp;
  // Separate from `bgp`: this contains only authenticated MASQUE tunnel BGP
  // desired state and can never add a provider peer or provider announcement.
  Vector<CrossClusterMasqueGatewayRuntime> crossClusterMasqueGatewayRuntimes;
  // Keep listener addresses stable while they are registered with Ring.
  Vector<std::unique_ptr<CrossClusterMasqueGatewayReadinessListener>> crossClusterMasqueGatewayReadinessListeners;
  // One held Unix stream per live gateway session.  Its lifetime, not merely
  // receipt arrival, is the local proof that MASQUE still owns the route.
  Vector<std::unique_ptr<CrossClusterMasqueGatewayReadinessCarrier>> crossClusterMasqueGatewayReadinessCarriers;
  bytell_hash_map<uint128_t, CrossClusterMasqueGatewayReadinessCarrier *> activeCrossClusterMasqueGatewayReadinessCarriers;
  std::unique_ptr<Switchboard> switchboard;
  std::unique_ptr<EthDevice> additionalIngressEth;
  std::unique_ptr<EthDevice> privateOverlayEth;
  // These are local ownership receipts for the exact links this Neuron made
  // restart-recoverable. They are not a second lifecycle authority: the pins
  // survive an unexpected same-boot process death, while the Guardian's
  // ordinary shutdown path releases them before it tears the service down.
  SwitchboardHostTCXRetentionPair retainedPrimaryHostTCX = {};
  SwitchboardHostTCXRetentionPair retainedPrivateOverlayHostTCX = {};
  bool retainedPrimaryHostTCXPresent = false;
  bool retainedPrivateOverlayHostTCXPresent = false;
  SwitchboardOverlayRoutingConfig overlayRoutingConfig;
  ProdigyOverlayPresenceMirror<switchboard_overlay_prefix4_key> installedIngressOverlayPrefixes4;
  ProdigyOverlayPresenceMirror<switchboard_overlay_prefix6_key> installedIngressOverlayPrefixes6;
  ProdigyOverlayValueMirror<switchboard_overlay_machine_route_key, switchboard_overlay_machine_route> installedIngressOverlayRouteKeysFull;
  ProdigyOverlayValueMirror<switchboard_overlay_machine_route_key, switchboard_overlay_machine_route> installedIngressOverlayRouteKeysLow8;
  ProdigyOverlayValueMirror<switchboard_overlay_machine_route_key, switchboard_overlay_site_route_set> installedIngressOverlaySiteRouteSets;
  ProdigyOverlayValueMirror<switchboard_overlay_prefix4_key, switchboard_overlay_hosted_ingress_route4> installedIngressHostedIngressRouteKeys4;
  ProdigyOverlayValueMirror<switchboard_overlay_prefix6_key, switchboard_overlay_hosted_ingress_route6> installedIngressHostedIngressRouteKeys6;
  ProdigyOverlayPresenceMirror<switchboard_overlay_ingress_peer4_key> installedIngressOverlayPeers4;
  ProdigyOverlayPresenceMirror<switchboard_overlay_ingress_peer6_key> installedIngressOverlayPeers6;
  ProdigyOverlayPresenceMirror<switchboard_overlay_prefix4_key> installedEgressOverlayPrefixes4;
  ProdigyOverlayPresenceMirror<switchboard_overlay_prefix6_key> installedEgressOverlayPrefixes6;
  ProdigyOverlayValueMirror<switchboard_overlay_machine_route_key, switchboard_overlay_machine_route> installedOverlayRouteKeysFull;
  ProdigyOverlayValueMirror<switchboard_overlay_machine_route_key, switchboard_overlay_machine_route> installedOverlayRouteKeysLow8;
  ProdigyOverlayValueMirror<switchboard_overlay_machine_route_key, switchboard_overlay_site_route_set> installedOverlaySiteRouteSets;
  ProdigyOverlayValueMirror<switchboard_overlay_prefix4_key, switchboard_overlay_hosted_ingress_route4> installedHostedIngressRouteKeys4;
  ProdigyOverlayValueMirror<switchboard_overlay_prefix6_key, switchboard_overlay_hosted_ingress_route6> installedHostedIngressRouteKeys6;
  ProdigyOverlayPresenceMirror<switchboard_overlay_prefix4_key> installedBalancerOverlayPrefixes4;
  ProdigyOverlayPresenceMirror<switchboard_overlay_prefix6_key> installedBalancerOverlayPrefixes6;
  ProdigyOverlayValueMirror<switchboard_overlay_machine_route_key, switchboard_overlay_machine_route> installedBalancerOverlayRouteKeysFull;
  ProdigyOverlayValueMirror<switchboard_overlay_machine_route_key, switchboard_overlay_machine_route> installedBalancerOverlayRouteKeysLow8;
  ProdigyOverlayValueMirror<switchboard_overlay_machine_route_key, switchboard_overlay_site_route_set> installedBalancerOverlaySiteRouteSets;
  ProdigyOverlayValueMirror<switchboard_overlay_prefix4_key, switchboard_overlay_hosted_ingress_route4> installedBalancerHostedIngressRouteKeys4;
  ProdigyOverlayValueMirror<switchboard_overlay_prefix6_key, switchboard_overlay_hosted_ingress_route6> installedBalancerHostedIngressRouteKeys6;
  ProdigyOverlayValueMirror<portal_definition, switchboard_whitehole_binding> installedIngressWhiteholeBindingKeys;
  ProdigyOverlayValueMirror<portal_definition, switchboard_whitehole_binding> installedEgressWhiteholeBindingKeys;
  bytell_hash_subvector<uint32_t, LocalWhiteholeBindingEntry> whiteholeBindingsByContainer;
  bytell_hash_subvector<uint64_t, CoroutineStack *> pendingContainerDownloads;
  std::unique_ptr<ProdigyArtifactIO> artifactIO;
  // Receipt-driven operations may complete after their control stream was
  // replaced.  The callback must not touch a destroyed Neuron.
  std::shared_ptr<uint8_t> asyncOperationLifetime = std::make_shared<uint8_t>(0);
  // A state upload can restore a live process before it has a Neuron control
  // socket.  Keep that candidate and its coroutine together until the
  // Netlink operation has reached a terminal callback; `containers` remains
  // the published, connectable set only.
  struct StateUploadRestoreOperation final {
    CoroutineStack coro;
    std::unique_ptr<Container> container;
    local_container_subnet6 fragment = {};
    NeuronBrainControlStream *stream = nullptr;
    uint64_t streamGeneration = 0;
    uint64_t epoch = 0;
    NeuronBrainControlStream *requestedStream = nullptr;
    uint64_t requestedGeneration = 0;
    bool settled = false;
    bool terminalRetirementPending = false;
    uint64_t launchAdmissionGeneration = 0;
    String planIdentity = {};
    String boundGatewayRecoveryToken = {};
    bool gatewayRecoveryTokenBound = false;
    // Unlike a retained-process restore, this candidate has no surviving PID
    // after an OS reboot. It stays under the same state-upload owner until the
    // exact authority and bootstrap can perform an ordinary cold restart.
    bool coldRestart = false;
    // Exact retained plans keep their adopted network while readiness rebinds.
    bool networkRestored = false;
    std::unique_ptr<CoroutineGenerator<uint8_t>> runner;

    ~StateUploadRestoreOperation()
    {
      // Destroying the outer coroutine destroys the HostTask awaiter, which
      // detaches its pending Netlink/command callback before this candidate
      // is released.
      coro.cancelSuspended();
      runner.reset();
      if (container != nullptr)
      {
        // This Neuron can be destroyed for bundle replacement while the
        // adopted process and its netkit pair remain live. The Container
        // handoff disarms link removal and retires only wrapper resources;
        // the replacement Neuron discovers the retained process.
        container->abandonRetainedNetworkForNeuronReplacement();
      }
    }
  };

  struct BGPConfigurationRefreshOperation final {
    CoroutineStack coro;
    uint64_t generation = 0;
    bool settled = false;
    std::unique_ptr<CoroutineGenerator<uint8_t>> runner;

    ~BGPConfigurationRefreshOperation()
    {
      coro.cancelSuspended();
      runner.reset();
    }
  };
  std::unique_ptr<BGPConfigurationRefreshOperation> bgpConfigurationRefresh;
  uint64_t runtimeEnvironmentGeneration = 0;
  TimeoutPacket bgpIPv6ReadinessRetryTick;
  TimeoutPacket crossClusterPathFaultTick;
  bool crossClusterPathFaultTickQueued = false;
  bool bgpIPv6ReadinessRetryQueued = false;
  uint32_t bgpIPv6ReadinessRetryAttempts = 0;
  uint64_t bgpIPv6ReadinessRetryPendingGeneration = 0;
  bytell_hash_map<uint128_t, std::unique_ptr<StateUploadRestoreOperation>> pendingStateUploadRestores;
  constexpr static uint32_t maximumPendingStateUploadRestores = 64;
  // An authenticated state upload may arrive while the prior control
  // generation still owns artifact/cgroup cleanup for this UUID. Keep its
  // canonical replay beside the existing pending-launch owner until that
  // owner signals its final drain callback.
  struct PendingContainerLaunchReplay final {
    ContainerPlan plan;
    NeuronContainerMetricPolicy metricPolicy;
    String identity;
  };
  bytell_hash_map<uint128_t, PendingContainerLaunchReplay> pendingContainerLaunchReplays;
  uint64_t stateUploadRestoreEpoch = 0;
  uint32_t stateUploadRestoreRemaining = 0;
  bool stateUploadRestoreReplyPending = false;
  std::shared_ptr<PendingReceivedBundleArtifact> pendingBundleArtifact;
  bool deferredBundleTransition = false;
  String installedBundleDigest = {};
  bool installedBundleDigestReady = false;
  bool installedBundleDigestInFlight = false;
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
  TimeoutPacket bundleExecRetryTick;
  bool bundleExecRetryTickQueued = false;
  // Once bundle exec begins, container control sockets must drain without
  // reconnecting. The replacement Neuron reopens them after stateUpload.
  bool bundleExecQuiescing = false;
  class WormholeFlowGC final : public TimeoutDispatcher {
    class PinnedMap {
    public:
      uint32_t ifindex = 0;

      template <typename Name, typename Callback>
      void openMap(Name&& name, Callback&& callback)
      {
        String path = {};
        if (name.equal("wh_flows"_ctv))
        {
          switchboardWormholeFlowPinPath(path, ifindex);
        }
        else if (name.equal("wh_pending"_ctv))
        {
          switchboardWormholePendingFlowPinPath(path, ifindex);
        }
        else if (name.equal("wh_pair_grants"_ctv))
        {
          switchboardPairAdmissionGrantPinPath(path, ifindex);
        }
        else if (name.equal("wh_pair_routes"_ctv))
        {
          switchboardPairAdmissionRoutePinPath(path, ifindex);
        }
        else
        {
          callback(-1);
          return;
        }
        int mapFD = bpf_obj_get(path.c_str());
        callback(mapFD);
        if (mapFD >= 0)
        {
          ::close(mapFD);
        }
      }
    } map;

    TimeoutPacket tick;
    SwitchboardWormholeFlowGCCursor cursor;
    SwitchboardPairAdmissionGCCursor pairAdmissionCursor;
    bool stopping = false;

    void arm(void)
    {
      tick.clear();
      tick.dispatcher = this;
      tick.setTimeoutMs(WORMHOLE_FLOW_GC_INTERVAL_MS);
      Ring::queueTimeout(&tick);
    }

  public:
    explicit WormholeFlowGC(uint32_t ifindex)
    {
      map.ifindex = ifindex;
      arm();
    }

    void stop(void)
    {
      if (stopping == false)
      {
        stopping = true;
        Ring::queueCancelTimeout(&tick);
      }
    }

    void dispatchTimeout(TimeoutPacket *packet) override
    {
      if (packet != &tick)
      {
        return;
      }
      if (stopping)
      {
        delete this;
        return;
      }
      (void)switchboardCleanupExpiredWormholeFlows(&map, monotonicNowNs(), cursor);
      (void)switchboardCleanupExpiredPairAdmissionMaps(&map, monotonicNowNs(), pairAdmissionCursor);
      arm();
    }
  };
  WormholeFlowGC *wormholeFlowGC = nullptr;
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
    // Construct an owning String. Returning the compile-time view directly
    // retains its terminator in this String implementation, so a later path
    // append is placed after NUL and atomic persistence targets the directory.
    String path = {};
    path.assign("/var/lib/prodigy/task-attempts"_ctv);
    return path;
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

  bool retireContainerControlBeforeRestart(Container *container)
  {
    if (Ring::socketIsClosing(container))
    {
      container->restartAfterClose = true;
      return true;
    }
    if (rawStreamIsActive(container))
    {
      container->restartAfterClose = true;
      Ring::queueClose(container);
      return true;
    }

    container->reset();
    return false;
  }

  virtual bool resumeFailedContainerRestart(Container *container)
  {
    return retireContainerControlBeforeRestart(container) || ContainerManager::restartContainer(container);
  }

  void scheduleFailedContainerRestart(Container *container, int64_t failureTimeMs)
  {
    if (container == nullptr || container->pendingDestroy || container->restartTimer != nullptr)
    {
      return;
    }

    uint32_t nextStreak = 0;
    uint32_t delayMs = ContainerManager::failedContainerRestartDelayMs(
        container->restartFailureStreak,
        container->lastRestartFailureMs,
        failureTimeMs,
        nextStreak);
    container->lastRestartFailureMs = failureTimeMs;
    container->restartFailureStreak = nextStreak;
    TimeoutPacket *timer = new TimeoutPacket();
    timer->identifier = container->plan.uuid;
    timer->flags = uint64_t(NeuronTimeoutFlags::restartContainer);
    timer->originator = this;
    timer->setTimeoutMs(delayMs);
    container->restartTimer = timer;
    basics_log("neuron scheduling failed container restart uuid=%llu streak=%u delayMs=%u\n",
               (unsigned long long)container->plan.uuid,
               container->restartFailureStreak,
               delayMs);
    Ring::queueTimeout(timer);
  }

  virtual bool beginAcceptedBrainTransportTLS(NeuronBrainControlStream *stream)
  {
    if (controlTransportCredentials.enabled)
    {
      if (!stream) return false;
      if (controlTransportCredentialLifecycleProjection.protocolVersion == 1 &&
          controlTransportCredentialLifecycleProjection.operation.predecessor.role == ProdigyTransportCredentialNodeRole::neuron &&
          controlTransportCredentialLifecycleProjection.operation.lifecycleKind == ProdigyTransportCredentialLifecycleKind::revoke &&
          uint8_t(controlTransportCredentialLifecycleProjection.operation.lifecyclePhase) >= uint8_t(ProdigyTransportCredentialLifecyclePhase::active))
      {
        const auto& operation = controlTransportCredentialLifecycleProjection.operation;
        std::fprintf(stderr, "transport lifecycle credential-refused role=neuron node=%016llx%016llx operation=%016llx%016llx generation=%llu reason=revoked\n",
            (unsigned long long)(uuid >> 64), (unsigned long long)uuid,
            (unsigned long long)(operation.lifecycleOperationUUID >> 64), (unsigned long long)operation.lifecycleOperationUUID,
            (unsigned long long)controlTransportCredentialLifecycleProjection.committedAuthorityGeneration);
        return false;
      }
      // A server cannot initiate a retry with its staged credential. Alternate
      // only on new accepted connections, retaining the selected bundle for
      // this handshake. Ordinary commands stay fenced until activation.
      const bool staged = controlTransportCredentialLifecycleProjection.protocolVersion == 1 &&
          uint8_t(controlTransportCredentialLifecycleProjection.operation.lifecyclePhase) < uint8_t(ProdigyTransportCredentialLifecyclePhase::active);
      stream->transportLifecycleCandidate = staged && tryStagedTransportCredentialOnNextAccept;
      tryStagedTransportCredentialOnNextAccept = staged && !tryStagedTransportCredentialOnNextAccept;
      auto selected = stream->transportLifecycleCandidate ? controlTransportCredentialLifecycleProjection.target : controlTransportCredentials;
      if (!prodigyTransportCredentialBootstrapValid(selected) ||
          selected.self.role != ProdigyTransportCredentialNodeRole::neuron) return false;
      String prelude;
      if (!prodigyRenderLocalTransportCredentialPrelude(selected, prelude)) return false;
      return stream->beginTransportAEGISWithPrelude(true, selected.self.nodeUUID, prelude,
          [selected = std::move(selected)](const String& peer, std::array<uint8_t, 32>& psk, String& context, uint128_t& peerUUID) {
            return prodigyResolveTransportCredentialBootstrapPeer(selected, peer,
                "brain-neuron"_ctv, psk.data(), context, peerUUID);
          });
    }
    return stream->beginTransportTLS(true);
  }

  const SwitchboardOverlayRoutingConfig *overlayRoutingConfigForContainerNetworking(void) const override
  {
    return &overlayRoutingConfig;
  }

  bool syncContainerOverlayRoutingPrograms(void)
  {
    bool converged = true;
    for (const auto& [uuid, container] : containers)
    {
      (void)uuid;
      if (container == nullptr || container->plan.useHostNetworkNamespace)
      {
        continue;
      }

      converged = container->syncPeerOverlayRoutingProgram() && converged;
    }
    return converged;
  }

  bool syncSwitchboardBalancerOverlayRoutingProgram(void)
  {
    if (switchboard == nullptr)
    {
      return false;
    }

    return prodigySyncOverlayEgressRoutingProgram(switchboard->boundaryRouterProgram(),
                                                  overlayRoutingConfig,
                                                  installedBalancerOverlayPrefixes4,
                                                  installedBalancerOverlayPrefixes6,
                                                  installedBalancerOverlayRouteKeysFull,
                                                  installedBalancerOverlayRouteKeysLow8,
                                                  installedBalancerOverlaySiteRouteSets,
                                                  installedBalancerHostedIngressRouteKeys4,
                                                  installedBalancerHostedIngressRouteKeys6);
  }

  bool syncOverlayRoutingPrograms(void)
  {
    bool converged = prodigySyncOverlayEgressRoutingProgram(tcx_ingress_program,
                                           overlayRoutingConfig,
                                           installedIngressOverlayPrefixes4,
                                           installedIngressOverlayPrefixes6,
                                           installedIngressOverlayRouteKeysFull,
                                           installedIngressOverlayRouteKeysLow8,
                                           installedIngressOverlaySiteRouteSets,
                                           installedIngressHostedIngressRouteKeys4,
                                           installedIngressHostedIngressRouteKeys6,
                                           true);
    converged = prodigySyncOverlayIngressPeers(tcx_ingress_program,
                                               overlayRoutingConfig,
                                               installedIngressOverlayPeers4,
                                               installedIngressOverlayPeers6) && converged;

    converged = prodigySyncOverlayEgressRoutingProgram(tcx_egress_program,
                                           overlayRoutingConfig,
                                           installedEgressOverlayPrefixes4,
                                           installedEgressOverlayPrefixes6,
                                           installedOverlayRouteKeysFull,
                                           installedOverlayRouteKeysLow8,
                                           installedOverlaySiteRouteSets,
                                           installedHostedIngressRouteKeys4,
                                           installedHostedIngressRouteKeys6) && converged;

    converged = syncSwitchboardBalancerOverlayRoutingProgram() && converged;
    converged = syncContainerOverlayRoutingPrograms() && converged;
    return converged;
  }

  bool crossClusterPrivateBGPFallbackProgrammed(
      const SwitchboardOverlayMachineRoute& route) const
  {
    if (!prodigyOverlaySiteRouteMirrorContains(installedIngressOverlaySiteRouteSets, route) ||
        !prodigyOverlaySiteRouteMirrorContains(installedOverlaySiteRouteSets, route) ||
        !prodigyOverlaySiteRouteMirrorContains(installedBalancerOverlaySiteRouteSets, route)) return false;
    for (const auto& [uuid, container] : containers)
    {
      (void)uuid;
      if (container == nullptr || container->plan.useHostNetworkNamespace) continue;
      if (!container->peerOverlaySiteRouteInstalled(route)) return false;
    }
    return true;
  }

  void collectWhiteholeBindings(Vector<std::pair<portal_definition, switchboard_whitehole_binding>>& desiredBindings)
  {
    desiredBindings.reserve(whiteholeBindingsByContainer.size());

    for (const auto& [containerID, bindings] : whiteholeBindingsByContainer)
    {
      (void)containerID;
      for (const LocalWhiteholeBindingEntry& binding : bindings)
      {
        desiredBindings.emplace_back(binding.key, binding.value);
      }
    }
  }

  void syncTrackedContainerPeerWhiteholeBindings(void)
  {
    Vector<std::pair<portal_definition, switchboard_whitehole_binding>> desiredBindings = {};
    collectWhiteholeBindings(desiredBindings);

    for (const auto& [uuid, container] : containers)
    {
      (void)uuid;
      if (container != nullptr && container->pendingDestroy == false)
      {
        container->syncPeerWhiteholeBindingEntries(desiredBindings);
      }
    }
  }

  void syncWhiteholeBindingsProgram(void)
  {
    Vector<std::pair<portal_definition, switchboard_whitehole_binding>> desiredBindings = {};
    collectWhiteholeBindings(desiredBindings);

    prodigySyncOverlayValueMap(tcx_ingress_program,
                               "whiteholes"_ctv,
                               installedIngressWhiteholeBindingKeys,
                               desiredBindings,
                               prodigyPortalDefinitionLess,
                               switchboardWhiteholeBindingEquals);
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
    syncTrackedContainerPeerWhiteholeBindings();
  }

  void closeLocalWhiteholesToContainer(uint32_t containerID)
  {
    whiteholeBindingsByContainer.erase(containerID);
    syncWhiteholeBindingsProgram();
    syncTrackedContainerPeerWhiteholeBindings();
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
      String executablePath = {};
      if (prodigyResolveCurrentExecutablePath(executablePath) == false)
      {
        return false;
      }

      String executableDirectory = {};
      prodigyDirname(executablePath, executableDirectory);
      hostIngressPath.assign(executableDirectory);
      hostEgressPath.assign(executableDirectory);
      if (hostIngressPath.size() > 0 && hostIngressPath[hostIngressPath.size() - 1] != '/')
      {
        hostIngressPath.append('/');
        hostEgressPath.append('/');
      }
      hostIngressPath.append("host.ingress.router.ebpf.o"_ctv);
      hostEgressPath.append("host.egress.router.ebpf.o"_ctv);

      bool defaultIngressReadable = prodigyFileReadable(hostIngressPath);
      bool defaultEgressReadable = prodigyFileReadable(hostEgressPath);
      if (defaultIngressReadable != defaultEgressReadable)
      {
        if (failureReport)
        {
          failureReport->assign("bundled host ingress and egress BPF objects must be present together"_ctv);
        }
        hostIngressPath.clear();
        hostEgressPath.clear();
        return false;
      }
      if (defaultIngressReadable == false)
      {
        hostIngressPath.clear();
        hostEgressPath.clear();
        return false;
      }
      return true;
    }

    hostIngressPath.assign(ingressEnv);
    hostEgressPath.assign(egressEnv);
    return true;
  }

  bool resolveOptionalAdditionalIngressDevice(String& device, String *failureReport = nullptr) const
  {
    return prodigyResolveOptionalAdditionalIngressDevice(device, failureReport);
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
    if (brain != nullptr && brain->transportAEGISEnabled() && brain->tlsPeerVerified)
    {
      // The stream has just published the mutual proof. Preserve the same
      // post-authentication hardware-profile kick as the TLS path.
      if (!brain->transportLifecycleCandidate)
        (void)queueMachineHardwareProfileToBrainIfReady("transport-aegis-peer-verified");
      return true;
    }
    if (brain == nullptr || brain->transportEncryptionEnabled() == false || brain->tlsPeerVerified)
    {
      return true;
    }

    if (brain->isTransportNegotiated() == false)
    {
      return true;
    }

    uint128_t peerUUID = 0;
    if (brain->extractAuthenticatedPeerUUID(peerUUID) == false)
    {
      basics_log("neuron transport tls missing brain peer uuid fd=%d fslot=%d\n", brain->fd, brain->fslot);
      PRODIGY_DEBUG_LOG(
                   "neuron brain tls-verify missing-peer-uuid fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d\n",
                   brain->fd,
                   brain->fslot,
                   int(brain->pendingSend),
                   int(brain->pendingRecv),
                   int(brain->isTransportNegotiated()));
      PRODIGY_DEBUG_FLUSH();
      return false;
    }

    brain->tlsPeerUUID = peerUUID;
    brain->tlsPeerVerified = true;
    basics_log("neuron brain transport tls peer verified fd=%d fslot=%d\n", brain->fd, brain->fslot);
    PRODIGY_DEBUG_LOG(
                 "neuron brain tls-verify ok peerUUID=%llu fd=%d fslot=%d pendingSend=%d pendingRecv=%d queued=%llu\n",
                 (unsigned long long)peerUUID,
                 brain->fd,
                 brain->fslot,
                 int(brain->pendingSend),
                 int(brain->pendingRecv),
                 (unsigned long long)brain->queuedSendOutstandingBytes());
    PRODIGY_DEBUG_FLUSH();
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

  void fenceStateUploadRestoresForControl(NeuronBrainControlStream *stream)
  {
    // Pointer plus socket generation does not identify a newly allocated
    // stream at a retired address. Revoke the old identity before deletion;
    // only a newly admitted state upload can authorize another attempt.
    for (auto& [uuid, operation] : pendingStateUploadRestores)
    {
      (void)uuid;
      if (operation->stream == stream) operation->stream = nullptr;
      if (operation->requestedStream == stream) operation->requestedStream = nullptr;
    }
  }

  void resetContainerLaunchControlForBrainReplacement(void)
  {
    // Keep ordinary pending plans visible until the replacement stream has
    // authenticated and replayed them. Their old generation remains fenced,
    // and explicit terminal kills remain terminal across this handoff.
    resetContainerLaunchControlGeneration(true);
    // A replay is authorized by one exact Brain-control stream. The next
    // replacement must authenticate and supply it again.
    pendingContainerLaunchReplays.clear();
    // Retained-process restoration owns an already-live process, so preserve
    // that exact owner while invalidating ordinary queued launches. The
    // operation still needs a new authenticated state upload before its
    // stream identity can become current again.
    for (auto& [containerUUID, operation] : pendingStateUploadRestores)
    {
      (void)containerUUID;
      if (operation != nullptr && operation->container != nullptr &&
          operation->container->pendingDestroy == false)
      {
        if (operation->terminalRetirementPending)
        {
          const bool rebound = rebindPendingContainerLaunchForStateUploadRestore(
              operation->container->plan.uuid, operation->launchAdmissionGeneration);
          operation->launchAdmissionGeneration =
              rebound ? containerLaunchControlGeneration : 0;
          (void)retireContainerLaunch(operation->container->plan.uuid);
        }
        else
        {
          // This retained-process operation already owns the exact pending
          // claim. Rebind that claim to the replacement control generation;
          // it must continue through admitRepeatedStateUploadRestore rather
          // than be treated as an ordinary artifact replay.
          if (!rebindPendingContainerLaunchForStateUploadRestore(
                  operation->container->plan.uuid, operation->launchAdmissionGeneration))
          {
            operation->launchAdmissionGeneration =
                beginPendingContainerLaunch(operation->container->plan);
          }
          else
          {
            operation->launchAdmissionGeneration = containerLaunchControlGeneration;
          }
        }
      }
    }
  }

  bool queuePendingContainerLaunchReplay(ContainerPlan plan,
                                         NeuronContainerMetricPolicy metricPolicy)
  {
    auto pending = pendingContainerLaunchPlans.find(plan.uuid);
    if (pending == pendingContainerLaunchPlans.end())
    {
      return false;
    }
    String pendingIdentity = {};
    if (!BitseryEngine::serialize(pendingIdentity, pending->second))
    {
      return false;
    }
    String replayIdentity = {};
    NeuronContainerBootstrap bootstrap = {};
    bootstrap.plan = plan;
    bootstrap.metricPolicy = metricPolicy;
    if (!BitseryEngine::serialize(replayIdentity, bootstrap) || replayIdentity.size() == 0)
    {
      return false;
    }
    String suppliedPlanIdentity = {};
    if (!BitseryEngine::serialize(suppliedPlanIdentity, plan) || suppliedPlanIdentity != pendingIdentity)
    {
      return false;
    }
    auto existing = pendingContainerLaunchReplays.find(plan.uuid);
    if (existing != pendingContainerLaunchReplays.end())
    {
      return existing->second.identity == replayIdentity;
    }
    PendingContainerLaunchReplay replay = {};
    replay.plan = std::move(plan);
    replay.metricPolicy = metricPolicy;
    replay.identity = std::move(replayIdentity);
    const uint128_t uuid = replay.plan.uuid;
    pendingContainerLaunchReplays.insert_or_assign(uuid, std::move(replay));
    return true;
  }

  void resumeDrainedPendingContainerLaunchReplay(uint128_t uuid)
  {
    auto found = pendingContainerLaunchReplays.find(uuid);
    if (found == pendingContainerLaunchReplays.end())
    {
      return;
    }
    PendingContainerLaunchReplay replay = std::move(found->second);
    pendingContainerLaunchReplays.erase(found);
    if (isContainerLaunchRetired(uuid) ||
        !handoffDrainedPendingContainerLaunchForAuthenticatedReplay(uuid))
    {
      return;
    }
    launchContainerFromBrain(std::move(replay.plan), 0, replay.metricPolicy);
  }

  void pendingContainerLaunchDrained(uint128_t uuid) override
  {
    resumeDrainedPendingContainerLaunchReplay(uuid);
  }

  void retireBrainControlStream(NeuronBrainControlStream *stream, const char *reason = nullptr)
  {
    if (stream == nullptr)
    {
      return;
    }

    fenceStateUploadRestoresForControl(stream);

    if (pendingBundleArtifact != nullptr && pendingBundleArtifact->stream == stream)
    {
      pendingBundleArtifact.reset();
      deferredBundleTransition = false;
    }

    if (stream == brain)
    {
      // Frames and suspended launches belong to this exact control stream.
      // A replacement stream starts a new bounded launch generation; stale
      // coroutines verify their generation before they can publish.
      resetContainerLaunchControlForBrainReplacement();
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

  void ensureWormholeFlowGCTickQueued(void)
  {
    if (wormholeFlowGC == nullptr && tcx_egress_program != nullptr && eth.ifidx != 0)
    {
      wormholeFlowGC = new WormholeFlowGC(uint32_t(eth.ifidx));
    }
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
    // This already runs on the deferred inventory worker.  Route discovery is
    // required for family-specific egress placement, while benchmarks remain
    // outside the boot path.
    hardwareCollectorOptions.allowLocalCommands = true;
    hardwareCollectorOptions.collectOptionalBenchmarks = false;
    prodigyCollectMachineHardwareProfile(result.hardware, hardwareCollectorOptions);
    serializeMachineHardwareProfileForBrainTransport(result.hardware, result.serializedHardwareProfile);
    return result;
  }

  static void serializeMachineHardwareProfileForBrainTransport(const MachineHardwareProfile& hardware, String& serialized)
  {
    MachineHardwareProfile transportHardware = hardware;
    // The brain needs one bounded kernel-route capture to distinguish an
    // on-link IPv6 prefix from a routed one. Other large tool captures stay
    // local so the initial neuron-control frame remains compact.
    prodigyStripMachineHardwareCapturesForBrainTransport(transportHardware);
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

    PRODIGY_DEBUG_LOG( "neuron deferred hardware begin wakeFD=%d\n", deferredHardwareInventoryWake.fd);
    PRODIGY_DEBUG_FLUSH();

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

      PRODIGY_DEBUG_LOG( "neuron deferred hardware collected inventoryComplete=%d serializedBytes=%llu logicalCores=%u memoryMB=%u disks=%llu nics=%llu failure=%s\n",
                   int(result.hardware.inventoryComplete),
                   (unsigned long long)result.serializedHardwareProfile.size(),
                   result.hardware.cpu.logicalCores,
                   result.hardware.memory.totalMB,
                   (unsigned long long)result.hardware.disks.size(),
                   (unsigned long long)result.hardware.network.nics.size(),
                   result.hardware.inventoryFailure.c_str());
      PRODIGY_DEBUG_FLUSH();

      {
        std::lock_guard<std::mutex> lock(deferredHardwareInventoryMutex);
        deferredHardwareInventoryReady = std::move(result);
      }

      if (deferredHardwareInventoryWake.fd >= 0)
      {
        uint64_t signal = 1;
        ssize_t wrote = ::write(deferredHardwareInventoryWake.fd, &signal, sizeof(signal));
        PRODIGY_DEBUG_LOG( "neuron deferred hardware wake-signaled fd=%d wrote=%lld errno=%d(%s)\n",
                     deferredHardwareInventoryWake.fd,
                     (long long)wrote,
                     (wrote < 0 ? errno : 0),
                     (wrote < 0 ? strerror(errno) : "ok"));
        PRODIGY_DEBUG_FLUSH();
      }
      else
      {
        PRODIGY_DEBUG_LOG( "neuron deferred hardware wake-skipped fd=%d\n", deferredHardwareInventoryWake.fd);
        PRODIGY_DEBUG_FLUSH();
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
    // The master uses this attestation together with the following stateUpload
    // before it advances the next worker.
    if (controlTransportCredentials.enabled)
      Message::construct(outbound, NeuronTopic::registration, bootTimeMs, kernel, osID, osVersionID,
                         haveFragments(), installedBundleDigest, uint8_t(1), uint8_t(3), uint8_t(1), uint8_t(1), uint8_t(3));
    else
      Message::construct(outbound, NeuronTopic::registration, bootTimeMs, kernel, osID, osVersionID,
                         haveFragments(), installedBundleDigest);
  }

  void queueAttestedInitialBrainControlFrames(NeuronBrainControlStream *stream)
  {
    if (installedBundleDigestReady == false || stream != brain || streamIsActive(stream) == false)
    {
      return;
    }
    stream->initialMachineHardwareProfileQueued = false;
    appendInitialBrainControlFrames(stream->wBuffer);
    if (stream->transportLifecycleCandidate)
    {
      Ring::queueSend(stream);
      return;
    }
    for (const auto& [deploymentID, coros] : pendingContainerDownloads)
    {
      (void)coros;
      Message::construct(stream->wBuffer, NeuronTopic::requestContainerBlob, deploymentID);
    }
    (void)queueMachineHardwareProfileToBrainIfReady("brain-control-accept");
    (void)appendHealthyContainerFrames(stream->wBuffer);
    if (stream->pendingSend == false)
    {
      Ring::queueSend(stream);
    }
    Ring::submitPending();
  }

  void queueInstalledBundleDigestAttestation(NeuronBrainControlStream *stream)
  {
    if (installedBundleDigestReady)
    {
      queueAttestedInitialBrainControlFrames(stream);
      return;
    }
    if (installedBundleDigestInFlight || artifactIO == nullptr)
    {
      if (artifactIO == nullptr && stream == brain) queueCloseIfActive(stream);
      return;
    }
    String executable = {};
    if (prodigyResolveCurrentExecutablePath(executable) == false)
    {
      if (stream == brain) queueCloseIfActive(stream);
      return;
    }
    installedBundleDigestInFlight = true;
    auto digest = std::make_shared<String>();
    const uint64_t streamGeneration = stream->ioGeneration;
    if (artifactIO->submit(
            0,
            [executable, digest] { (void)prodigyResolveInstalledBundleDigestForExecutable(executable, *digest); },
            [this, stream, streamGeneration, digest] {
              installedBundleDigestInFlight = false;
              if (digest->empty())
              {
                if (brain == stream && stream->ioGeneration == streamGeneration)
                {
                  queueCloseIfActive(stream);
                }
                else if (brain != nullptr)
                {
                  queueInstalledBundleDigestAttestation(brain);
                }
                return;
              }
              installedBundleDigest = std::move(*digest);
              installedBundleDigestReady = true;
              if (brain == stream && stream->ioGeneration == streamGeneration)
              {
                queueAttestedInitialBrainControlFrames(stream);
              }
              else if (brain != nullptr)
              {
                queueInstalledBundleDigestAttestation(brain);
              }
            },
            [this, stream, streamGeneration](std::exception_ptr) {
              installedBundleDigestInFlight = false;
              if (brain == stream && stream->ioGeneration == streamGeneration)
              {
                queueCloseIfActive(stream);
              }
              else if (brain != nullptr)
              {
                queueInstalledBundleDigestAttestation(brain);
              }
            }) == false)
    {
      installedBundleDigestInFlight = false;
      if (stream == brain) queueCloseIfActive(stream);
    }
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
    bool brainAppReady = (brainPresent && brainActive && (brain->transportEncryptionEnabled() == false || (brain->isTransportNegotiated() && brain->tlsPeerVerified)));
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

      PRODIGY_DEBUG_LOG( "neuron machineHardwareProfile unavailable reason=%s deferredReady=%d deferredInFlight=%d fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d\n",
                   (reason != nullptr ? reason : ""),
                   int(deferredReadyPresent),
                   int(deferredInFlight),
                   (brainPresent ? brain->fd : -1),
                   (brainPresent ? brain->fslot : -1),
                   int(brainPresent ? brain->pendingSend : 0),
                   int(brainPresent ? brain->pendingRecv : 0),
                   int(brainPresent ? brain->isTransportNegotiated() : 0),
                   int(brainPresent ? brain->tlsPeerVerified : 0));
      PRODIGY_DEBUG_FLUSH();
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
               int(brainPresent ? brain->isTransportNegotiated() : 0),
               int(brainPresent ? brain->tlsPeerVerified : 0));
#endif
    return queuedHardwareProfile;
  }

  void adoptDeferredHardwareInventoryResult(DeferredHardwareInventoryResult result)
  {
    bool brainPresentBeforeAdopt = (brain != nullptr);
    bool brainActiveBeforeAdopt = (brainPresentBeforeAdopt && streamIsActive(brain));
    PRODIGY_DEBUG_LOG(
                 "neuron deferred hardware adopt-begin inventoryComplete=%d serializedBytes=%llu brainPresent=%d brainActive=%d fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d\n",
                 int(result.hardware.inventoryComplete),
                 (unsigned long long)result.serializedHardwareProfile.size(),
                 int(brainPresentBeforeAdopt),
                 int(brainActiveBeforeAdopt),
                 (brainPresentBeforeAdopt ? brain->fd : -1),
                 (brainPresentBeforeAdopt ? brain->fslot : -1),
                 int(brainPresentBeforeAdopt ? brain->pendingSend : 0),
                 int(brainPresentBeforeAdopt ? brain->pendingRecv : 0),
                 int(brainPresentBeforeAdopt ? brain->isTransportNegotiated() : 0),
                 int(brainPresentBeforeAdopt ? brain->tlsPeerVerified : 0));
    PRODIGY_DEBUG_FLUSH();
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
    PRODIGY_DEBUG_LOG(
                 "neuron deferred hardware adopt-end brainPresent=%d brainActive=%d queued=%d serializedBytes=%llu fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d\n",
                 int(brainPresent),
                 int(brainActive),
                 int(queuedHardwareProfile),
                 (unsigned long long)serializedHardwareProfile.size(),
                 (brainPresent ? brain->fd : -1),
                 (brainPresent ? brain->fslot : -1),
                 int(brainPresent ? brain->pendingSend : 0),
                 int(brainPresent ? brain->pendingRecv : 0),
                 int(brainPresent ? brain->isTransportNegotiated() : 0),
                 int(brainPresent ? brain->tlsPeerVerified : 0));
    PRODIGY_DEBUG_FLUSH();

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
               int(brainPresent ? brain->isTransportNegotiated() : 0),
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
        PRODIGY_DEBUG_LOG(
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
                     int(brain ? brain->isTransportNegotiated() : 0),
                     int(brain ? brain->tlsPeerVerified : 0));
        PRODIGY_DEBUG_FLUSH();
        return completed;
      }

      ready = std::move(deferredHardwareInventoryReady);
      deferredHardwareInventoryReady.reset();
      deferredHardwareInventoryInFlight = false;
    }

    if (ready == std::nullopt)
    {
      PRODIGY_DEBUG_LOG(
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
                   int(brain ? brain->isTransportNegotiated() : 0),
                   int(brain ? brain->tlsPeerVerified : 0));
      PRODIGY_DEBUG_FLUSH();
      return true;
    }

    DeferredHardwareInventoryResult result = std::move(*ready);
    PRODIGY_DEBUG_LOG(
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
                 int(brain ? brain->isTransportNegotiated() : 0),
                 int(brain ? brain->tlsPeerVerified : 0));
    PRODIGY_DEBUG_FLUSH();
    if (deferredHardwareInventoryResultReadyForAdoption(result) == false)
    {
      PRODIGY_DEBUG_LOG(
                   "neuron deferred hardware complete-retry inventoryComplete=%d serializedBytes=%llu failure=%s\n",
                   int(result.hardware.inventoryComplete),
                   (unsigned long long)result.serializedHardwareProfile.size(),
                   result.hardware.inventoryFailure.c_str());
      PRODIGY_DEBUG_FLUSH();
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
          bool replayRuntime = false;
          if (ProdigyWire::deserializeAdvertisementPairingControlPayload(
                  payload.data(),
                  payload.size(),
                  secret,
                  address,
                  service,
                  applicationID,
                  activate,
                  replayRuntime) == false)
          {
            continue;
          }

          uint16_t advertisedPort = 0;
          if (auto advertisement = container->plan.advertisements.find(service);
              advertisement != container->plan.advertisements.end())
          {
            advertisedPort = advertisement->second.port;
          }
          if (container->plan.applyAdvertisementPairing(AdvertisementPairing(secret, address, service), activate) &&
              container->syncDeclaredNetworkPairingPolicy(activate == false, address, advertisedPort, true) == false)
          {
            basics_log("neuron advertisementPairing network policy sync failed containerUUID=%llu\n",
                       (unsigned long long)container->plan.uuid);
            if (container->pid > 0)
            {
              kill(container->pid, SIGKILL);
            }
            continue;
          }
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
          bool replayRuntime = false;
          if (ProdigyWire::deserializeSubscriptionPairingControlPayload(
                  payload.data(),
                  payload.size(),
                  secret,
                  address,
                  service,
                  port,
                  applicationID,
                  activate,
                  replayRuntime) == false)
          {
            continue;
          }

          if (container->plan.applySubscriptionPairing(SubscriptionPairing(secret, address, service, port), activate) &&
              container->syncDeclaredNetworkPairingPolicy(activate == false, address, port, false) == false)
          {
            basics_log("neuron subscriptionPairing network policy sync failed containerUUID=%llu\n",
                       (unsigned long long)container->plan.uuid);
            if (container->pid > 0)
            {
              kill(container->pid, SIGKILL);
            }
            continue;
          }
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
      // Direct retained startup has already accepted this fragment before the
      // first optional ingress asks for Switchboard. Seed it on creation so
      // boundary-router setup does not observe the default empty subnet.
      switchboard->setLocalContainerSubnet(lcsubnet6);
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

  std::function<void(bool)> wormholeOperationReply(SwitchboardWormholeOperation operation)
  {
    NeuronBrainControlStream *requestStream = brain;
    const uint64_t requestGeneration = requestStream ? requestStream->ioGeneration : 0;
    const std::weak_ptr<uint8_t> lifetime = asyncOperationLifetime;
    operation.desired.clear();
    return [this, lifetime, requestStream, requestGeneration, operation = std::move(operation)](bool ready) mutable {
      if (lifetime.expired() || brain != requestStream || requestStream == nullptr ||
          requestStream->ioGeneration != requestGeneration || !streamIsActive(requestStream)) return;
      if (!ready && operation.status == SwitchboardWormholeOperationStatus::applied)
        operation.status = SwitchboardWormholeOperationStatus::rollbackFailed;
      String response = {};
      BitseryEngine::serialize(response, operation);
      Message::construct(requestStream->wBuffer, NeuronTopic::openSwitchboardWormholes, response);
      Ring::queueSend(requestStream);
    };
  }

  std::function<void(bool)> wormholeContainerRefresh(Container *container)
  {
    const uint128_t containerUUID = container->plan.uuid;
    const uint64_t containerGeneration = container->ioGeneration;
    NeuronBrainControlStream *requestStream = brain;
    const uint64_t requestGeneration = requestStream ? requestStream->ioGeneration : 0;
    const std::weak_ptr<uint8_t> lifetime = asyncOperationLifetime;
    return [this, lifetime, container, containerUUID, containerGeneration, requestStream, requestGeneration](bool ready) {
      if (lifetime.expired() || !ready || brain != requestStream || requestStream == nullptr ||
          requestStream->ioGeneration != requestGeneration || !streamIsActive(requestStream)) return;
      const auto current = containers.find(containerUUID);
      if (current == containers.end() || current->second != container || container->pendingDestroy ||
          container->ioGeneration != containerGeneration || !streamIsActive(container)) return;
      // The waiter coalesces newer refreshes for this container. Serialize the
      // current owned plan only after its routing is ready, never retain a
      // view into the original receive buffer across worker completion.
      String serialized = {};
      BitseryEngine::serialize(serialized, container->plan.wormholes);
      Message::construct(container->wBuffer, ContainerTopic::wormholesRefresh, serialized);
      Ring::queueSend(container);
    };
  }

  static bool buildContainerWormholeDesiredState(const ContainerPlan& plan,
                                                 const Vector<Wormhole>& wormholes,
                                                 SwitchboardWormholeDesiredState& desired)
  {
    return prodigyBuildCousinWormholeDesiredState(
        wormholes, plan.isStateful, plan.statefulMeshRoles.cousin, plan.advertisements, desired);
  }

  // A fleet replay can predate the protected desired-state envelope.  The
  // locally retained plan is still sufficient to derive its required listener
  // protection, so preserve every incoming protected port and add the local
  // requirement before handing state to Switchboard.
  static bool strengthenWormholeDesiredStateForLocalPlan(const ContainerPlan& plan,
                                                         SwitchboardWormholeDesiredState& desired)
  {
    SwitchboardWormholeDesiredState local = {};
    if (buildContainerWormholeDesiredState(plan, desired.wormholes, local) == false)
    {
      return false;
    }

    for (uint16_t requiredPort : local.pairAdmissionTCPPorts)
    {
      bool present = false;
      for (uint16_t port : desired.pairAdmissionTCPPorts)
      {
        if (port == requiredPort)
        {
          present = true;
          break;
        }
      }
      if (present)
      {
        continue;
      }

      Vector<uint16_t> merged = {};
      merged.reserve(desired.pairAdmissionTCPPorts.size() + 1);
      bool inserted = false;
      for (uint16_t port : desired.pairAdmissionTCPPorts)
      {
        if (inserted == false && requiredPort < port)
        {
          merged.push_back(requiredPort);
          inserted = true;
        }
        merged.push_back(port);
      }
      if (inserted == false)
      {
        merged.push_back(requiredPort);
      }
      desired.pairAdmissionTCPPorts = std::move(merged);
    }
    return prodigyWormholeDesiredStateValid(desired);
  }

  bool applyContainerSwitchboardWormholes(Container *container, const SwitchboardWormholeDesiredState& desired)
  {
    if (container == nullptr)
    {
      return false;
    }

    Switchboard *activeSwitchboard = ensureSwitchboard();
    uint32_t containerID = generateLocalContainerID(container->plan.fragment);

    if (prodigyWormholeDesiredStateValid(desired) == false)
    {
      basics_log("neuron wormhole refresh rejected invalid cousin protection containerID=%u count=%u\n",
                 containerID,
                 unsigned(container->plan.wormholes.size()));
      return false;
    }

    bool gatewayListener = false;
    if (container->plan.system.kind == SystemContainerKind::crossClusterMasqueGateway)
    {
      const auto *runtime = crossClusterMasqueGatewayRuntimeForContainer(container->plan.uuid);
      if (runtime == nullptr || !runtime->systemPlanAdmitted ||
          !admitCrossClusterMasqueGatewaySystemPlan(container->plan) ||
          !prodigyCrossClusterMasqueGatewayWormholesMatch(runtime->authority, desired.wormholes) ||
          !desired.pairAdmissionTCPPorts.empty()) return false;
      gatewayListener = runtime->authority.localRole == CrossClusterMasqueGatewayRole::listener;
    }
    activeSwitchboard->setLocalContainerSubnet(lcsubnet6);
    SwitchboardWormholeOperationStatus status = activeSwitchboard->openWormholes(containerID, desired, gatewayListener);
    if (status != SwitchboardWormholeOperationStatus::applied)
    {
      basics_log("neuron wormhole refresh failed containerID=%u count=%u\n",
                 containerID,
                 unsigned(container->plan.wormholes.size()));
      return false;
    }
    syncSwitchboardBalancerOverlayRoutingProgram();

    // Include the live peer and primary programs in the same reconciliation
    // barrier as the broader Switchboard state. The refresh receipt is held
    // until their egress bindings and the current routing generation converge.
    syncContainerSwitchboardRuntime(container);
    return true;
  }

  void refreshContainerSwitchboardWormholes(Container *container) override
  {
    if (container == nullptr)
    {
      return;
    }

    SwitchboardWormholeDesiredState desired = {};
    if (buildContainerWormholeDesiredState(container->plan, container->plan.wormholes, desired) == false)
    {
      basics_log("neuron wormhole refresh rejected invalid local cousin protection count=%u\n",
                 unsigned(container->plan.wormholes.size()));
      return;
    }
    (void)applyContainerSwitchboardWormholes(container, desired);
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

  void syncWhiteholeBindingsForContainerPeer(Container *container) override
  {
    if (container == nullptr || container->pendingDestroy)
    {
      return;
    }

    Vector<std::pair<portal_definition, switchboard_whitehole_binding>> desiredBindings = {};
    collectWhiteholeBindings(desiredBindings);
    container->syncPeerWhiteholeBindingEntries(desiredBindings);
  }

  void syncContainerSwitchboardRuntime(Container *container) override
  {
    if (switchboard == nullptr || container == nullptr || container->plan.useHostNetworkNamespace ||
        container->peer_program == nullptr || container->primary_program == nullptr)
    {
      return;
    }

    switchboard->syncContainerProgramRuntimeState(container->peer_program, container->primary_program);
  }

  NeuronBGPRuntime *ensureBGP(void)
  {
    if (!bgp)
    {
      bgp = std::make_unique<NeuronBGPRuntime>();

      NeuronBGPConfig config = {};
      (void)iaas->gatherBGPConfig(config, eth, private4);
      bgp->configure(config);
    }

    return bgp.get();
  }

  CrossClusterMasqueGatewayRuntime *crossClusterMasqueGatewayRuntimeForPair(uint128_t pairUUID)
  {
    if (pairUUID == 0) return nullptr;
    for (auto& runtime : crossClusterMasqueGatewayRuntimes)
      if (runtime.authority.pairUUID == pairUUID) return &runtime;
    return nullptr;
  }

  CrossClusterMasqueGatewayRuntime *crossClusterMasqueGatewayRuntimeForContainer(uint128_t containerUUID)
  {
    if (containerUUID == 0) return nullptr;
    for (auto& runtime : crossClusterMasqueGatewayRuntimes)
      if (runtime.systemContainerUUID == containerUUID) return &runtime;
    return nullptr;
  }

  CrossClusterMasqueGatewayReadinessListener *crossClusterMasqueGatewayListenerForContainer(uint128_t containerUUID)
  {
    for (const auto& listener : crossClusterMasqueGatewayReadinessListeners)
      if (listener != nullptr && listener->containerUUID == containerUUID) return listener.get();
    return nullptr;
  }

  CrossClusterMasqueGatewayReadinessCarrier *crossClusterMasqueGatewayCarrierForContainer(uint128_t containerUUID)
  {
    const auto found = activeCrossClusterMasqueGatewayReadinessCarriers.find(containerUUID);
    return found == activeCrossClusterMasqueGatewayReadinessCarriers.end() ? nullptr : found->second;
  }

  void scheduleCrossClusterPathFaultTick()
  {
    if (crossClusterPathFaultTickQueued) return;
    crossClusterPathFaultTick.clear(); crossClusterPathFaultTick.originator = this;
    crossClusterPathFaultTick.setTimeoutMs(250); crossClusterPathFaultTickQueued = true;
    Ring::queueTimeout(&crossClusterPathFaultTick);
  }

  // Admission is against the retained full authority, not against the compact
  // gateway frame. Queueing is not a successful pause: the response must be
  // joined with the gateway's observed session state and private BGP owner.
  bool queueCrossClusterPathFaultGatewayControl(const ProdigyCrossClusterPathFaultControl& control)
  {
    if (!prodigyCrossClusterPathFaultControlValid(control) || control.response) return false;
    auto *runtime = crossClusterMasqueGatewayRuntimeForPair(control.request.authority.pairUUID);
    if (runtime == nullptr || !runtime->systemPlanAdmitted ||
        !runtime->authorityMatches(control.request.authority) || !runtime->privateTunnelBGP) return false;
    auto *carrier = crossClusterMasqueGatewayCarrierForContainer(runtime->systemContainerUUID);
    const auto container = containers.find(runtime->systemContainerUUID);
    if (!carrier || !carrier->receiptAccepted || carrier->fd < 0 || carrier->faultFramePending ||
        carrier->faultWaitingDown || carrier->faultWaitingRestore ||
        carrier->pendingSend || container == containers.end() || !container->second ||
        container->second->pid != carrier->peerPID || container->second->pendingDestroy) return false;
    struct timespec now = {};
    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec < 0) return false;
    const uint64_t nowMs = uint64_t(now.tv_sec) * 1000 + uint64_t(now.tv_nsec) / 1000000;
    if (control.request.expiresAtMilliseconds <= nowMs ||
        control.request.expiresAtMilliseconds - nowMs > 60000) return false;
    if (runtime->faultLeaseActive) {
      if (!prodigyCrossClusterPathFaultRequestEqual(runtime->faultLease, control.request)) return false;
    } else if (control.action != ProdigyCrossClusterPathFaultGatewayAction::pause ||
               !runtime->readiness.authenticatedMasqueQUICReady) return false;
    ProdigyCrossClusterPathFaultGatewayControlPayload frame = {};
    String encoded = {};
    if (!prodigyCrossClusterPathFaultGatewayLeasePayload(control.request, control.action, frame) ||
        !prodigyEncodeCrossClusterPathFaultGatewayControlFrame(frame, encoded)) return false;
    if (!runtime->faultLeaseActive) {
      const uint64_t nowNs = monotonicNowNs(); if (!nowNs) return false;
      if (!runtime->privateTunnelBGP->beginCrossClusterPathFault(control.request, runtime->authority.localIdentitySHA256)) return false;
      runtime->faultMonotonicDeadlineNs = nowNs + (control.request.expiresAtMilliseconds - nowMs) * 1000000ULL;
      runtime->completedFaultLease = {};
    }
    runtime->faultLease = control.request; runtime->faultLeaseActive = true;
    carrier->faultDeadlineNs = runtime->faultMonotonicDeadlineNs;
    carrier->faultControl = control; carrier->faultFrame = frame; carrier->faultFramePending = true;
    if (control.action == ProdigyCrossClusterPathFaultGatewayAction::pause)
      (void)revokeCrossClusterMasqueGatewayReadiness(carrier->containerUUID);
    if (carrier->localMode == ProdigyGatewayLocalCarrierMode::v2) {
      ProdigyGatewayLocalControlFrame local = {};
      local.direction = ProdigyGatewayLocalDirection::neuronToGateway;
      local.kind = ProdigyGatewayLocalKind::pathFault; local.pathFault = frame;
      if (!prodigyGatewayLocalControlFrameAllowedForSend(carrier->localPhase, local) ||
          !prodigyEncodeGatewayLocalControlFrame(local, encoded)) return false;
    }
    carrier->wBuffer.append(encoded); Ring::queueSend(carrier);
    scheduleCrossClusterPathFaultTick();
    return true;
  }

  void finishCrossClusterPathFaultGatewayControl(
      CrossClusterMasqueGatewayReadinessCarrier *carrier,
      const ProdigyCrossClusterPathFaultGatewayControlPayload& response)
  {
    if (!carrier || !carrier->faultFramePending) return;
    auto result = carrier->faultControl;
    result.response = true; result.accepted = false;
    result.sessionReady = response.authenticatedReady; result.bgpReady = false;
    auto *runtime = crossClusterMasqueGatewayRuntimeForContainer(carrier->containerUUID);
    if (runtime && runtime->privateTunnelBGP && !response.accepted && result.action == ProdigyCrossClusterPathFaultGatewayAction::pause) {
      auto acceptedResponse = response; acceptedResponse.accepted = true;
      if (prodigyCrossClusterPathFaultGatewayLeaseResponseMatches(carrier->faultFrame, acceptedResponse)) {
        // The gateway rejected the pause. Its next authenticated readiness
        // frame permits the BGP owner to restore without waiting for expiry.
        runtime->faultResumeAcknowledged = true;
      }
    }
    if (runtime && runtime->authorityMatches(result.request.authority) && runtime->privateTunnelBGP &&
        prodigyCrossClusterPathFaultGatewayLeaseResponseMatches(carrier->faultFrame, response)) {
      struct ObservedSession final : ProdigyCrossClusterPathFaultSessionControl {
        bool ready;
        explicit ObservedSession(bool value) : ready(value) {}
        bool pause(const ProdigyCrossClusterPathFaultRequest&) override { return true; }
        bool query(const ProdigyCrossClusterPathFaultRequest&, bool& value) override { value = ready; return true; }
        bool resume(const ProdigyCrossClusterPathFaultRequest&) override { return true; }
      } observed(response.authenticatedReady);
      if (result.action == ProdigyCrossClusterPathFaultGatewayAction::pause) {
        result.accepted = runtime->privateTunnelBGP->pauseCrossClusterPathFault(
            result.request, runtime->authority.localIdentitySHA256, observed);
        // The exact lease is retained and BGP withdrawn even if QUIC cleanup
        // is still in flight. A later query must establish the down state.
        (void)revokeCrossClusterMasqueGatewayReadiness(carrier->containerUUID);
        carrier->faultWaitingDown = !result.accepted &&
            runtime->privateTunnelBGP->hasCrossClusterPathFault(result.request);
      } else if (result.action == ProdigyCrossClusterPathFaultGatewayAction::query) {
        bool sessionReady = false, bgpReady = false;
        result.accepted = runtime->privateTunnelBGP->queryCrossClusterPathFault(
            result.request, runtime->authority.localIdentitySHA256, observed, sessionReady, bgpReady);
        result.sessionReady = sessionReady; result.bgpReady = bgpReady;
      } else if (result.action == ProdigyCrossClusterPathFaultGatewayAction::resume) {
        // Acceptance only releases the gateway fence. Fresh authenticated
        // readiness and BGP establishment are observed independently.
        runtime->faultResumeAcknowledged = true;
        carrier->faultWaitingRestore = true;
      }
    }
    carrier->faultFramePending = false;
    if (carrier->faultWaitingDown || carrier->faultWaitingRestore) {
      scheduleCrossClusterPathFaultTick(); return;
    }
    if (brain && brain->fd >= 0) {
      String encoded = {}; if (BitseryEngine::serialize(encoded, result)) {
        Message::construct(brain->wBuffer, NeuronTopic::crossClusterPathFault, encoded); Ring::queueSend(brain);
      }
    }
  }

  void closeCrossClusterMasqueGatewayCarriers(uint128_t containerUUID)
  {
    activeCrossClusterMasqueGatewayReadinessCarriers.erase(containerUUID);
    for (const auto& carrier : crossClusterMasqueGatewayReadinessCarriers)
    {
      if (carrier != nullptr && carrier->containerUUID == containerUUID)
        queueCloseIfActive(carrier.get());
    }
  }

  void removeCrossClusterMasqueGatewayListener(uint128_t containerUUID)
  {
    closeCrossClusterMasqueGatewayCarriers(containerUUID);
    for (auto it = crossClusterMasqueGatewayReadinessListeners.begin();
         it != crossClusterMasqueGatewayReadinessListeners.end(); ++it)
    {
      if (*it != nullptr && (*it)->containerUUID == containerUUID)
      {
        RingDispatcher::eraseMultiplexee(it->get());
        (*it)->teardown();
        crossClusterMasqueGatewayReadinessListeners.erase(it);
        return;
      }
    }
  }

  // The authority arrives over the existing authenticated control path. It
  // does not launch anything itself: Mothership owns lifecycle intent and the
  // active Brain projects the typed plan through the ordinary Neuron launcher.
  // Acceptance is independent of BGP readiness: a valid first snapshot must
  // remain installed while the gateway awaits its plan, TLS bootstrap and
  // authenticated QUIC receipt. Reconciliation still withdraws unusable paths.
  bool reconcileCrossClusterMasqueGatewayAuthority(
      const CrossClusterMasqueGatewayAuthority& authority, bool fromAuthorityProjection = false)
  {
    if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(authority) ||
        authority.localMachineUUID != uuid)
    {
      return false;
    }

    auto *runtime = crossClusterMasqueGatewayRuntimeForPair(authority.pairUUID);
    if (runtime != nullptr)
    {
      if (runtime->authorityMatches(authority))
      {
        // Switchboard reset removes process-local portals while the exact
        // admitted gateway can remain alive. Authority replay owns restoring
        // those endpoints; generic application route replay excludes gateways.
        const auto found = containers.find(runtime->systemContainerUUID);
        if (authority.state == CrossClusterMasqueGatewayState::active &&
            authority.localRole == CrossClusterMasqueGatewayRole::listener && runtime->systemPlanAdmitted &&
            found != containers.end() && found->second != nullptr && found->second->pid > 0 &&
            found->second->plan.uuid == runtime->systemContainerUUID &&
            !found->second->pendingDestroy && !found->second->killedOnPurpose &&
            !isContainerLaunchRetired(runtime->systemContainerUUID))
        {
          SwitchboardWormholeDesiredState desired = {};
          if (!buildContainerWormholeDesiredState(found->second->plan, found->second->plan.wormholes, desired) ||
              !applyContainerSwitchboardWormholes(found->second, desired)) return false;
        }
        (void)reconcileCrossClusterMasqueGatewayBGP(*runtime);
        if (!fromAuthorityProjection) retrySettledStateUploadGatewayRecoveries();
        return true;
      }
      if (!prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(runtime->authority, authority))
      {
        return false;
      }
    }
    // A fresh Neuron receives the current authoritative control-stream snapshot,
    // which can already be at a later generation. Direct non-snapshot callers
    // still need the initial generation; existing pairs retain advance checks.
    else if (!fromAuthorityProjection && authority.state == CrossClusterMasqueGatewayState::active && authority.generation != 1)
    {
      return false;
    }

    if (runtime == nullptr)
    {
      for (auto& candidate : crossClusterMasqueGatewayRuntimes)
        if (candidate.authority.pairUUID == 0) { runtime = &candidate; break; }
      if (runtime == nullptr && crossClusterMasqueGatewayRuntimes.size() >=
          CrossClusterMasqueGatewayRuntime::maximumAuthoritiesPerMachine) return false;
      if (runtime == nullptr)
      {
        crossClusterMasqueGatewayRuntimes.emplace_back();
        runtime = &crossClusterMasqueGatewayRuntimes.back();
      }
    }

    // Withdraw the old endpoint before advancing its authority generation.
    if (runtime->systemContainerUUID != 0)
    {
      if (auto it = containers.find(runtime->systemContainerUUID); it != containers.end() && it->second != nullptr)
        ensureSwitchboard()->closeWormholesToContainer(generateLocalContainerID(it->second->plan.fragment));
      removeCrossClusterMasqueGatewayListener(runtime->systemContainerUUID);
    }
    runtime->gatewayBootstrap.reset();
    runtime->pendingLaunch.reset();
    runtime->faultLease = {}; runtime->completedFaultLease = {};
    runtime->faultLeaseActive = false; runtime->faultResumeAcknowledged = false;
    runtime->faultMonotonicDeadlineNs = 0;
    runtime->authority = authority;
    runtime->revokeReadiness();
    runtime->readinessLaunchToken.clear();
    runtime->systemContainerUUID = 0;
    runtime->systemPlanAdmitted = false;
    (void)reconcileCrossClusterMasqueGatewayBGP(*runtime);
    if (!fromAuthorityProjection) retrySettledStateUploadGatewayRecoveries();
    return true;
  }

  // A Brain snapshot is authoritative for this Neuron only.  It may contain
  // the two independent remote-site pairs assigned to this physical host;
  // accepting a record selected for another machine would turn control-plane
  // fanout into a gateway launch primitive.  Absence actively withdraws any
  // locally originated /96.
  bool reconcileCrossClusterMasqueGatewayAuthorityProjection(
      const ProdigyCrossClusterMasqueGatewayAuthorityProjection& projection)
  {
    if (!prodigyCrossClusterMasqueGatewayAuthorityProjectionValid(
            projection, controlTransportCredentials.self.clusterUUID))
    {
      return false;
    }

    Vector<const CrossClusterMasqueGatewayAuthority *> selected = {};
    for (const auto& authority : projection.authorities)
    {
      if (authority.localMachineUUID != uuid) continue;
      if (selected.size() >= CrossClusterMasqueGatewayRuntime::maximumAuthoritiesPerMachine) return false;
      for (const auto *existing : selected)
        if (existing->pairUUID == authority.pairUUID ||
            existing->privateTunnelInterface == authority.privateTunnelInterface)
          return false;
      selected.push_back(&authority);
    }
    // Validate the whole desired snapshot before mutating any live pair.
    for (const auto *authority : selected)
      if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(*authority)) return false;
    uint32_t newPairs = 0;
    for (const auto *authority : selected)
    {
      auto *runtime = crossClusterMasqueGatewayRuntimeForPair(authority->pairUUID);
      if (runtime == nullptr)
      {
        ++newPairs;
        continue;
      }
      if (!runtime->authorityMatches(*authority) &&
          !prodigyCrossClusterMasqueGatewayAuthorityCanAdvance(runtime->authority, *authority))
        return false;
    }
    if (newPairs > CrossClusterMasqueGatewayRuntime::maximumAuthoritiesPerMachine ||
        selected.size() > CrossClusterMasqueGatewayRuntime::maximumAuthoritiesPerMachine)
      return false;
    // Retire absent pairs only after the complete replacement snapshot has
    // passed its advance/slot checks, leaving capacity for a two-pair swap.
    for (auto& runtime : crossClusterMasqueGatewayRuntimes)
    {
      bool retained = false;
      for (const auto *authority : selected) if (authority->pairUUID == runtime.authority.pairUUID) retained = true;
      if (retained) continue;
      runtime.gatewayBootstrap.reset();
      runtime.pendingLaunch.reset();
      runtime.faultLease = {}; runtime.completedFaultLease = {};
      runtime.faultLeaseActive = false; runtime.faultResumeAcknowledged = false;
      runtime.faultMonotonicDeadlineNs = 0;
      runtime.revokeReadiness();
      runtime.readinessLaunchToken.clear();
      runtime.systemPlanAdmitted = false;
      if (runtime.privateTunnelBGP) runtime.privateTunnelBGP->withdrawAll();
      runtime.sitePrefixAdvertised = false;
      if (auto it = containers.find(runtime.systemContainerUUID); it != containers.end() && it->second != nullptr)
        ensureSwitchboard()->closeWormholesToContainer(generateLocalContainerID(it->second->plan.fragment));
      removeCrossClusterMasqueGatewayListener(runtime.systemContainerUUID);
      runtime.systemContainerUUID = 0;
      runtime.authority = {};
    }
    for (const auto *authority : selected)
      if (!reconcileCrossClusterMasqueGatewayAuthority(*authority, true)) return false;

    for (auto& runtime : crossClusterMasqueGatewayRuntimes)
    {
      bool retained = false;
      for (const auto *authority : selected) if (authority->pairUUID == runtime.authority.pairUUID) retained = true;
      if (retained) continue;
      runtime.gatewayBootstrap.reset();
      runtime.pendingLaunch.reset();
      runtime.revokeReadiness();
      runtime.readinessLaunchToken.clear();
      runtime.systemPlanAdmitted = false;
      if (runtime.privateTunnelBGP) runtime.privateTunnelBGP->withdrawAll();
      runtime.sitePrefixAdvertised = false;
      removeCrossClusterMasqueGatewayListener(runtime.systemContainerUUID);
      runtime.systemContainerUUID = 0;
      runtime.authority = {};
    }
    reconcileCrossClusterPrivateBGPSwitchboardFallback();
    // stateUpload can arrive before the typed gateway authority. The retained
    // process remains fenced in that ordering; the completed authoritative
    // snapshot is the event that makes an exact local record retryable.
    retrySettledStateUploadGatewayRecoveries();
    return true;
  }

  // Generic spin dispatch calls this before handing a typed gateway plan to
  // ContainerManager. The plan must be the exact current Mothership authority
  // artifact; an arbitrary system plan cannot manufacture gateway readiness.
  bool admitCrossClusterMasqueGatewaySystemPlan(const ContainerPlan& plan)
  {
    const auto *runtime = crossClusterMasqueGatewayRuntimeForPair(plan.system.gatewayPairUUID);
    Vector<CrossClusterMasqueGatewayAuthority> projectedAuthorities = {};
    for (const auto& candidate : crossClusterMasqueGatewayRuntimes)
      if (candidate.authority.pairUUID != 0)
        projectedAuthorities.push_back(candidate.authority);
    const uint8_t expectedFragment = runtime == nullptr ? 0 :
        prodigyCrossClusterMasqueGatewayRuntimeFragment(
            projectedAuthorities, runtime->authority.pairUUID,
            runtime->authority.localMachineUUID);
    if (plan.system.kind != SystemContainerKind::crossClusterMasqueGateway ||
        runtime == nullptr || !prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(runtime->authority) ||
        runtime->authority.state != CrossClusterMasqueGatewayState::active ||
        runtime->authority.localMachineUUID != uuid || plan.uuid == 0 ||
        !plan.restartOnFailure || plan.useHostNetworkNamespace ||
        plan.config.capabilities.size() != 1 || !plan.config.capabilities.contains(CAP_NET_ADMIN) ||
        plan.fragment != expectedFragment ||
        !prodigyCrossClusterMasqueGatewayRuntimeFragmentValid(plan.fragment) ||
        !plan.system.artifact.sha256.equal(runtime->authority.artifactSHA256) ||
        plan.system.artifact.bytes != runtime->authority.artifactBytes ||
        plan.system.gatewayLocalClusterUUID != runtime->authority.localClusterUUID ||
        plan.system.gatewayLocalMachineUUID != runtime->authority.localMachineUUID ||
        plan.system.gatewayKeyEpoch != runtime->authority.keyGeneration ||
        plan.system.gatewayAuthorityGeneration != runtime->authority.pairAuthorityGeneration ||
        plan.system.gatewayGeneration != runtime->authority.generation ||
        !plan.system.gatewayTunnelInterface.equal(runtime->authority.privateTunnelInterface) ||
        !prodigyCrossClusterMasqueGatewayWormholesMatch(runtime->authority, plan.wormholes) ||
        !prodigyCrossClusterMasqueGatewayWhiteholesValid(runtime->authority, plan.whiteholes))
    {
      return false;
    }
    // The data-plane process gets no ambient network authority.  Its one
    // underlay peer is the endpoint in the signed gateway authority. A
    // listener receives only packets routed through its exclusive publication;
    // a connector accepts the exact endpoint's replies. Any old plan fails before ContainerManager can
    // create a network namespace.
    const auto& egress = plan.system.egress;
    const auto& endpoint = runtime->authority.listenerPublicUDPEndpoint;
    if (!egress.configured() || egress.protocol != IPPROTO_UDP ||
        egress.port != runtime->authority.listenerPublicUDPPort ||
        egress.peerIsIPv6 != endpoint.is6 ||
        egress.allowIngressFromPeer !=
            (runtime->authority.localRole == CrossClusterMasqueGatewayRole::listener))
    {
      return false;
    }
    if (endpoint.is6)
    {
      if (std::memcmp(egress.address6, endpoint.v6, sizeof(egress.address6)) != 0) return false;
    }
    else if (htonl(egress.address4) != endpoint.v4)
    {
      return false;
    }
    return true;
  }

  bool queueCurrentGatewayReadiness(const CrossClusterMasqueGatewayRuntime& runtime)
  {
    if (!runtime.systemPlanAdmitted || runtime.systemContainerUUID == 0 ||
        runtime.authority.state != CrossClusterMasqueGatewayState::active ||
        !runtime.readiness.authenticatedMasqueQUICReady ||
        !prodigyCrossClusterMasqueGatewayReadinessMatches(runtime.authority, runtime.readiness) ||
        brain == nullptr || !streamIsActive(brain)) return false;
    String encoded = {};
    if (!BitseryEngine::serialize(encoded, runtime.readiness)) return false;
    Message::construct(brain->wBuffer, NeuronTopic::crossClusterMasqueGatewayReadinessReceipt, encoded);
    Vault::secureClearString(encoded);
    return true;
  }

  // Brain readiness observations are scoped to its current Neuron stream and
  // are not replicated. Re-attest the retained live lease after its inventory
  // so a replacement master can bind this evidence to the new control stream.
  void replayCurrentGatewayReadinessAfterStateUpload()
  {
    for (const auto& runtime : crossClusterMasqueGatewayRuntimes)
    {
      const auto found = containers.find(runtime.systemContainerUUID);
      auto *carrier = crossClusterMasqueGatewayCarrierForContainer(runtime.systemContainerUUID);
      if (runtime.faultLeaseActive || found == containers.end() || !found->second ||
          found->second->pendingDestroy || found->second->pid <= 0 || !carrier ||
          !carrier->receiptAccepted || !streamIsActive(carrier) ||
          carrier->faultFramePending || carrier->faultWaitingDown || carrier->faultWaitingRestore ||
          carrier->peerPID != found->second->pid) continue;
      (void)queueCurrentGatewayReadiness(runtime);
    }
  }

  // Switchboard calls this only after its selected gateway has authenticated
  // the MASQUE/QUIC data path. The receipt is bound to the live plan plus all
  // authority generations, so replacement, key rotation, or withdrawal
  // immediately revokes the old origin eligibility.
  bool recordCrossClusterMasqueGatewayReadiness(
      uint128_t systemContainerUUID,
      const ProdigyCrossClusterMasqueGatewayReadiness& readiness)
  {
    auto *runtime = crossClusterMasqueGatewayRuntimeForContainer(systemContainerUUID);
    if (runtime == nullptr || !runtime->systemPlanAdmitted || systemContainerUUID == 0 ||
        systemContainerUUID != runtime->systemContainerUUID ||
        !prodigyCrossClusterMasqueGatewayReadinessMatches(runtime->authority, readiness) ||
        !readiness.authenticatedMasqueQUICReady)
    {
      return false;
    }
    runtime->readiness = readiness;
    if (runtime->faultLeaseActive && !restoreExpiredCrossClusterPathFault(*runtime)) {
      const uint64_t nowNs = monotonicNowNs();
      if (!runtime->faultResumeAcknowledged && (!nowNs || nowNs < runtime->faultMonotonicDeadlineNs)) {
        runtime->revokeReadiness(); return false;
      }
      scheduleCrossClusterPathFaultTick(); return true;
    }
    if (queueCurrentGatewayReadiness(*runtime)) Ring::queueSend(brain);
    // The private BGP secret is intentionally delivered only after
    // Mothership observes this MASQUE receipt.  A missing secret can make the
    // routing reconciliation fail here without invalidating the authenticated
    // underlay lease that was just accepted.
    (void)reconcileCrossClusterMasqueGatewayBGP(*runtime);
    return true;
  }

  bool restoreExpiredCrossClusterPathFault(CrossClusterMasqueGatewayRuntime& runtime)
  {
    if (!runtime.faultLeaseActive || !runtime.privateTunnelBGP ||
        !runtime.readiness.authenticatedMasqueQUICReady) return false;
    const uint64_t nowNs = monotonicNowNs();
    if (!runtime.faultResumeAcknowledged && (!nowNs || nowNs < runtime.faultMonotonicDeadlineNs)) return false;
    const auto found = containers.find(runtime.systemContainerUUID);
    if (found == containers.end() || !found->second || found->second->pid <= 0 || found->second->pendingDestroy) return false;
    if (runtime.privateTunnelBGP->hasCrossClusterPathFault(runtime.faultLease)) {
      String path = {}; path.snprintf<"/proc/{itoa}/ns/net"_ctv>(uint64_t(found->second->pid));
      const int fd = Filesystem::openFileAt(-1, path, O_RDONLY | O_CLOEXEC);
      if (fd < 0) return false;
      struct RestoredSession final : ProdigyCrossClusterPathFaultSessionControl {
        bool pause(const ProdigyCrossClusterPathFaultRequest&) override { return false; }
        bool query(const ProdigyCrossClusterPathFaultRequest&, bool& ready) override { ready = true; return true; }
        bool resume(const ProdigyCrossClusterPathFaultRequest&) override { return true; }
      } observed;
      const bool restored = runtime.privateTunnelBGP->resumeCrossClusterPathFault(
          runtime.faultLease, runtime.authority.localIdentitySHA256, observed, runtime.readiness, fd);
      ::close(fd); if (!restored) return false;
    }
    runtime.faultLeaseActive = false; runtime.faultResumeAcknowledged = false;
    runtime.completedFaultLease = runtime.faultLease; runtime.faultLease = {}; runtime.faultMonotonicDeadlineNs = 0;
    return true;
  }

  void serviceCrossClusterPathFaultTick()
  {
    const uint64_t nowNs = monotonicNowNs(); bool reschedule = false;
    for (auto& runtime : crossClusterMasqueGatewayRuntimes) {
      auto *carrier = crossClusterMasqueGatewayCarrierForContainer(runtime.systemContainerUUID);
      const bool beforeDeadline = runtime.faultLeaseActive && nowNs && nowNs < runtime.faultMonotonicDeadlineNs;
      if (runtime.faultLeaseActive && runtime.readiness.authenticatedMasqueQUICReady &&
          (runtime.faultResumeAcknowledged || !beforeDeadline)) {
        auto readiness = runtime.readiness;
        if (restoreExpiredCrossClusterPathFault(runtime))
          (void)recordCrossClusterMasqueGatewayReadiness(runtime.systemContainerUUID, readiness);
      }
      if (!carrier) { if (beforeDeadline) reschedule = true; continue; }
      if (runtime.faultLeaseActive && !beforeDeadline && carrier->faultFramePending) {
        auto response = carrier->faultControl; response.response = true; response.accepted = false;
        response.sessionReady = false; response.bgpReady = false;
        carrier->faultFramePending = false; carrier->faultWaitingDown = false; carrier->faultWaitingRestore = false;
        String encoded = {}; if (brain && brain->fd >= 0 && BitseryEngine::serialize(encoded, response)) {
          Message::construct(brain->wBuffer, NeuronTopic::crossClusterPathFault, encoded); Ring::queueSend(brain);
        }
        // If the frame was never acknowledged, force a fresh authenticated
        // gateway session rather than trusting the pre-fault readiness.
        queueCloseIfActive(carrier);
        continue;
      }
      if (carrier->faultWaitingDown && !carrier->faultFramePending && !carrier->pendingSend && beforeDeadline) {
        ProdigyCrossClusterPathFaultGatewayControlPayload query = {}; String encoded = {};
        if (prodigyCrossClusterPathFaultGatewayLeasePayload(runtime.faultLease,
                ProdigyCrossClusterPathFaultGatewayAction::query, query) &&
            prodigyEncodeCrossClusterPathFaultGatewayControlFrame(query, encoded)) {
          carrier->faultFrame = query; carrier->faultFramePending = true;
          carrier->wBuffer.append(encoded); Ring::queueSend(carrier);
        }
      }
      if (carrier->faultWaitingDown && !beforeDeadline && !carrier->faultFramePending) {
        auto response = carrier->faultControl; response.response = true; response.accepted = false;
        response.sessionReady = false; response.bgpReady = false; carrier->faultWaitingDown = false;
        String encoded = {}; if (brain && brain->fd >= 0 && BitseryEngine::serialize(encoded, response)) {
          Message::construct(brain->wBuffer, NeuronTopic::crossClusterPathFault, encoded); Ring::queueSend(brain);
        }
      }
      if (carrier->faultWaitingRestore && !runtime.faultLeaseActive && runtime.privateTunnelBGP &&
          runtime.privateTunnelBGP->desiredPaths().size() == 1 &&
          prodigyCrossClusterPrivateTunnelBGPPathUsable(runtime.privateTunnelBGP->desiredPaths()[0]) &&
          prodigyCrossClusterMasqueGatewayReady(runtime.authority, &runtime.readiness)) {
        auto response = carrier->faultControl; response.response = true; response.accepted = true;
        response.sessionReady = true; response.bgpReady = true; carrier->faultWaitingRestore = false;
        String encoded = {}; if (brain && brain->fd >= 0 && BitseryEngine::serialize(encoded, response)) {
          Message::construct(brain->wBuffer, NeuronTopic::crossClusterPathFault, encoded); Ring::queueSend(brain);
        }
      }
      if (carrier->faultWaitingRestore && nowNs && nowNs >= carrier->faultDeadlineNs) {
        auto response = carrier->faultControl; response.response = true; response.accepted = false;
        response.sessionReady = false; response.bgpReady = false; carrier->faultWaitingRestore = false;
        String encoded = {}; if (brain && brain->fd >= 0 && BitseryEngine::serialize(encoded, response)) {
          Message::construct(brain->wBuffer, NeuronTopic::crossClusterPathFault, encoded); Ring::queueSend(brain);
        }
      }
      if (beforeDeadline || (runtime.readiness.authenticatedMasqueQUICReady && runtime.faultLeaseActive) ||
          (!runtime.faultLeaseActive && carrier->faultWaitingRestore)) reschedule = true;
    }
    if (reschedule) scheduleCrossClusterPathFaultTick();
  }

  // Called only by the task-owned readiness socket after it has obtained the
  // peer credentials.  The pid/container check prevents a sibling process in
  // the mount namespace from replaying a valid launch token.
  bool recordCrossClusterMasqueGatewayLocalReceipt(
      uint128_t systemContainerUUID, pid_t peerPID,
      const ProdigyCrossClusterMasqueGatewayLocalReceipt& receipt)
  {
    auto *runtime = crossClusterMasqueGatewayRuntimeForContainer(systemContainerUUID);
    const auto found = containers.find(systemContainerUUID);
    if (found == containers.end() || found->second == nullptr ||
        found->second->plan.system.kind != SystemContainerKind::crossClusterMasqueGateway ||
        found->second->pid != peerPID || !receipt.ready ||
        runtime == nullptr || !prodigyCrossClusterMasqueGatewayLocalReceiptValid(
            runtime->authority, runtime->readinessLaunchToken, receipt))
    {
      (void)revokeCrossClusterMasqueGatewayReadiness(systemContainerUUID);
      return false;
    }
    return recordCrossClusterMasqueGatewayReadiness(systemContainerUUID, receipt.readiness);
  }

  // A gateway exit, stream loss, or explicit Switchboard revocation uses the
  // same fail-closed path as an authority update.
  bool revokeCrossClusterMasqueGatewayReadiness(uint128_t systemContainerUUID)
  {
    auto *runtime = crossClusterMasqueGatewayRuntimeForContainer(systemContainerUUID);
    if (runtime == nullptr || systemContainerUUID == 0 || systemContainerUUID != runtime->systemContainerUUID)
    {
      return false;
    }
    runtime->revokeReadiness();
    return reconcileCrossClusterMasqueGatewayBGP(*runtime);
  }

  // This is called by the authenticated, generation-bound Vault delivery
  // handler.  It intentionally accepts the move-only response rather than a
  // serializable control object, so the BGP credential cannot enter Brain
  // state or a replayable authority snapshot.
  static bool crossClusterPrivateBGPSecretScopeMatchesAuthority(
      const ProdigyPairPrivateBGPSecretScope& scope,
      const CrossClusterMasqueGatewayAuthority& authority)
  {
    return prodigyPairPrivateBGPSecretScopeValid(scope) &&
        authority.state == CrossClusterMasqueGatewayState::active &&
        scope.pairUUID == authority.pairUUID && scope.operationUUID == authority.pairOperationUUID &&
        scope.keyEpoch == authority.keyGeneration && scope.tunnelSlot == authority.tunnelSlot &&
        scope.clusterUUID == authority.localClusterUUID && scope.machineUUID == authority.localMachineUUID &&
        scope.authorityGeneration == authority.pairAuthorityGeneration &&
        scope.gatewayGeneration == authority.generation;
  }

  static bool crossClusterPrivateBGPSecretScopeMatchesGatewayPlan(
      const ProdigyPairPrivateBGPSecretScope& scope, const ContainerPlan& plan)
  {
    const auto& gateway = plan.system;
    return gateway.kind == SystemContainerKind::crossClusterMasqueGateway &&
        gateway.gatewayPairUUID == scope.pairUUID &&
        gateway.gatewayLocalClusterUUID == scope.clusterUUID &&
        gateway.gatewayLocalMachineUUID == scope.machineUUID &&
        gateway.gatewayKeyEpoch == scope.keyEpoch &&
        gateway.gatewayAuthorityGeneration == scope.authorityGeneration &&
        gateway.gatewayGeneration == scope.gatewayGeneration;
  }

  // Brain forwards a terminal request only after its durable authority proves
  // the complete scope. A retired, never-admitted authority can therefore be
  // acknowledged here only after proving that no live container or pending
  // launch still names that exact scope. Any local owner remains an anchor and
  // must take the ordinary BGP/fallback cleanup path below.
  bool crossClusterPrivateBGPSecretScopeHasNoGatewayAnchor(
      const ProdigyPairPrivateBGPSecretScope& scope) const
  {
    for (const auto& [containerUUID, container] : containers)
      if (container != nullptr &&
          crossClusterPrivateBGPSecretScopeMatchesGatewayPlan(scope, container->plan))
        return false;
    for (const auto& [containerUUID, plan] : pendingContainerLaunchPlans)
      if (crossClusterPrivateBGPSecretScopeMatchesGatewayPlan(scope, plan)) return false;
    for (const auto& [containerUUID, operation] : pendingStateUploadRestores)
      if (operation != nullptr && operation->container != nullptr &&
          crossClusterPrivateBGPSecretScopeMatchesGatewayPlan(scope, operation->container->plan))
        return false;
    return true;
  }

  bool withdrawCrossClusterPrivateBGPSecret(const ProdigyPairPrivateBGPSecretScope& scope)
  {
    auto *runtime = crossClusterMasqueGatewayRuntimeForPair(scope.pairUUID);
    if (runtime == nullptr) return crossClusterPrivateBGPSecretScopeHasNoGatewayAnchor(scope);
    if (!crossClusterPrivateBGPSecretScopeMatchesAuthority(scope, runtime->authority) ||
        runtime->faultLeaseActive ||
        (runtime->gatewayBootstrap &&
         !prodigyPairPrivateBGPSecretScopeEqual(runtime->gatewayBootstrap->scope, scope)))
      return false;

    // Capture the fallback before withdrawAll() notifies its observer.  That
    // observer can reconcile desired state and clear the ordinary flags even
    // when programming the removal did not converge.
    const bool fallbackInstalled = runtime->privateBGPFallbackInstalled ||
        runtime->privateBGPFallbackProgrammed;
    runtime->privateBGPFallbackRemovalPending |= fallbackInstalled;
    // A BGP owner can exist before secret delivery.  It is terminally empty
    // only when it has no scope, key, path, or unacknowledged fault state.
    if (runtime->privateTunnelBGP &&
        !runtime->privateTunnelBGP->withdrawDeliveredSecret(scope) &&
        !runtime->privateTunnelBGP->empty())
      return false;

    runtime->gatewayBootstrap.reset();
    runtime->pendingLaunch.reset();
    runtime->privateTunnelBGP.reset();
    runtime->faultLease = {};
    runtime->completedFaultLease = {};
    runtime->faultLeaseActive = false;
    runtime->faultResumeAcknowledged = false;
    runtime->faultMonotonicDeadlineNs = 0;
    runtime->sitePrefixAdvertised = false;
    runtime->revokeReadiness();
    // This is the single owner that removes only runtime-owned fallbacks from
    // the overlay config and programs the resulting route set.  An empty BGP
    // owner has no fallback to program; otherwise no receipt is issued until
    // the removal converged.
    if (!runtime->privateBGPFallbackRemovalPending && switchboard == nullptr) return true;
    return reconcileCrossClusterPrivateBGPSwitchboardFallback() &&
        !runtime->privateBGPFallbackRemovalPending &&
        !runtime->privateBGPFallbackInstalled && !runtime->privateBGPFallbackProgrammed;
  }

  bool installCrossClusterPrivateBGPSecret(ProdigyPairPrivateBGPSecretDeliveryResponse& response)
  {
    auto *runtime = crossClusterMasqueGatewayRuntimeForPair(response.scope.pairUUID);
    if (!response.accepted || runtime == nullptr) return false;
    const auto& authority = runtime->authority;
    if (!crossClusterPrivateBGPSecretScopeMatchesAuthority(response.scope, authority))
      return false;
    if (!prodigyPairPrivateGatewayTLSMaterialMatchesAuthority(authority,
            response.gatewayRootCertPem, response.localLeafCertPem, response.localLeafKeyPem,
            response.peerLeafCertDERHex)) return false;
    auto bootstrap = std::make_unique<ProdigyPairPrivateBGPSecretDeliveryResponse>();
    bootstrap->scope = response.scope;
    bootstrap->accepted = true;
    // The receiver extracts views into a control frame. Own the bytes before
    // that frame is consumed; moving a String view would retain a dangling key.
    bootstrap->gatewayRootCertPem.assign(response.gatewayRootCertPem.data(), response.gatewayRootCertPem.size());
    bootstrap->localLeafCertPem.assign(response.localLeafCertPem.data(), response.localLeafCertPem.size());
    bootstrap->localLeafKeyPem.assign(response.localLeafKeyPem.data(), response.localLeafKeyPem.size());
    bootstrap->peerLeafCertDERHex.assign(response.peerLeafCertDERHex.data(), response.peerLeafCertDERHex.size());
    runtime->gatewayBootstrap = std::move(bootstrap);
    // The ordinary Brain launch may beat the bootstrap RPC. Retain only that
    // admitted frame and resume through the same launcher after authentication.
    auto pending = std::move(runtime->pendingLaunch);
    if (pending && pending->controlGeneration == containerLaunchControlGeneration &&
        !isContainerLaunchRetired(pending->plan.uuid))
      launchContainerFromBrain(std::move(pending->plan), pending->replaceContainerUUID,
                               pending->metricPolicy, std::move(pending->retainedSource));
    retrySettledStateUploadGatewayRecoveries();
    if (!runtime->readiness.authenticatedMasqueQUICReady ||
        !prodigyCrossClusterMasqueGatewayReadinessMatches(authority, runtime->readiness))
      return true; // Mothership redelivers after the authenticated QUIC receipt.
    if (!runtime->privateTunnelBGP) {
      runtime->privateTunnelBGP = std::make_unique<NeuronPrivateTunnelBGPRuntime>();
      runtime->privateTunnelBGP->setPathChangedObserver([](void *context) {
        static_cast<Neuron *>(context)->reconcileCrossClusterPrivateBGPSwitchboardFallback();
      }, this);
    }
    if (!runtime->privateTunnelBGP->installDeliveredSecret(response)) return false;
    return reconcileCrossClusterMasqueGatewayBGP(*runtime);
  }

  bool prepareCrossClusterMasqueGatewayExec(const ContainerPlan& plan,
      Vector<String>& arguments, Vector<int32_t>& descriptors, String *failure = nullptr) override
  {
    auto *runtime = crossClusterMasqueGatewayRuntimeForPair(plan.system.gatewayPairUUID);
    if (runtime == nullptr || !runtime->gatewayBootstrap ||
        !admitCrossClusterMasqueGatewaySystemPlan(plan) || runtime->systemContainerUUID != plan.uuid)
    {
      if (failure) failure->assign("MASQUE launch is missing its exact-scope Vault bootstrap"_ctv);
      return false;
    }
    const auto& bootstrap = *runtime->gatewayBootstrap;
    return prodigyBuildMasqueGatewayExecArguments(runtime->authority,
        bootstrap.gatewayRootCertPem, bootstrap.localLeafCertPem,
        bootstrap.localLeafKeyPem, bootstrap.peerLeafCertDERHex, arguments, descriptors, failure);
  }

  bool reconcileCrossClusterMasqueGatewayBGP(CrossClusterMasqueGatewayRuntime& runtime)
  {
    // A projected authority refresh must not republish BGP while an exact
    // fault lease is pending; restoration is driven by a fresh readiness
    // receipt after resume or expiry.
    if (runtime.faultLeaseActive) { runtime.sitePrefixAdvertised = false; return false; }
    if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(runtime.authority))
    {
      if (runtime.privateTunnelBGP) runtime.privateTunnelBGP->withdrawAll();
      runtime.sitePrefixAdvertised = false;
      return false;
    }

    const auto *readiness = runtime.readiness.authenticatedMasqueQUICReady ?
        &runtime.readiness : nullptr;
    if (!runtime.privateTunnelBGP) {
      runtime.privateTunnelBGP = std::make_unique<NeuronPrivateTunnelBGPRuntime>();
      runtime.privateTunnelBGP->setPathChangedObserver([](void *context) {
        static_cast<Neuron *>(context)->reconcileCrossClusterPrivateBGPSwitchboardFallback();
      }, this);
    }
    ProdigyCrossClusterPrivateTunnelBGPDesiredState desired = {};
    desired.pairUUID = runtime.authority.pairUUID;
    desired.pairOperationUUID = runtime.authority.pairOperationUUID;
    desired.localMachineUUID = runtime.authority.localMachineUUID;
    desired.peerMachineUUID = runtime.authority.peerMachineUUID;
    desired.keyEpoch = runtime.authority.keyGeneration;
    desired.authorityGeneration = runtime.authority.pairAuthorityGeneration;
    desired.gatewayGeneration = runtime.authority.generation;
    desired.gatewaySlot = runtime.authority.gatewaySlot;
    desired.localSitePrefix = runtime.authority.localSitePrefix;
    desired.peerSitePrefix = runtime.authority.peerSitePrefix;
    desired.tunnelInterface = runtime.authority.privateTunnelInterface;
    desired.localInsideIPv6 = runtime.authority.privateTunnelLocalIPv6;
    desired.peerInsideIPv6 = runtime.authority.privateTunnelPeerIPv6;
    desired.localASN = runtime.authority.privateLocalASN;
    desired.peerASN = runtime.authority.privatePeerASN;
    desired.localBGPID = runtime.authority.privateLocalBGPID;
    // The authority's SHA-256 is only a public reference.  The runtime
    // replaces this empty field exclusively from the Vault delivery cache.
    desired.sessionKey.clear();
    desired.masqueReady = readiness != nullptr;
    int gatewayNetworkNamespaceFD = -1;
    // Switchboard outer delivery terminates at the gateway container's
    // deterministic /128.  Its source is the host's local container /120
    // address; the private /127 below stays scoped to the gateway TUN/BGP
    // socket and is never a host-routable outer endpoint.
    const auto container = containers.find(runtime.systemContainerUUID);
    if (container != containers.end() && container->second != nullptr &&
        !container->second->pendingDestroy &&
        container->second->plan.system.kind == SystemContainerKind::crossClusterMasqueGateway)
    {
      const IPPrefix expectedGatewayAddress = generateAddress(
          container_network_subnet6, container->second->plan.fragment, 128);
      const bool gatewayAddressAssigned = std::any_of(
          container->second->plan.addresses.begin(), container->second->plan.addresses.end(),
          [&](const IPPrefix& address) { return address.cidr == 128 && address.network.equals(expectedGatewayAddress.network); });
      if (gatewayAddressAssigned)
      {
        desired.localGatewayInjectionIPv6 = expectedGatewayAddress.network;
        desired.localGatewaySourceIPv6 = generateAddress(container_network_subnet6, 0, 120).network;
        desired.localGatewayInjectionFragment = container->second->plan.fragment;
      }
    }
    if (readiness != nullptr)
    {
      if (container != containers.end() && container->second != nullptr &&
          container->second->pid > 0 && !container->second->pendingDestroy &&
          container->second->plan.system.kind == SystemContainerKind::crossClusterMasqueGateway)
      {
        String namespacePath = {};
        namespacePath.snprintf<"/proc/{itoa}/ns/net"_ctv>(uint64_t(container->second->pid));
        gatewayNetworkNamespaceFD = Filesystem::openFileAt(
            -1, namespacePath, O_RDONLY | O_CLOEXEC);
      }
    }
    const bool reconciled = runtime.privateTunnelBGP->reconcile(
        runtime.authority, readiness, &desired, gatewayNetworkNamespaceFD);
    if (gatewayNetworkNamespaceFD >= 0) ::close(gatewayNetworkNamespaceFD);
    runtime.sitePrefixAdvertised = reconciled &&
        runtime.privateTunnelBGP->desiredPaths().size() == 1 &&
        runtime.privateTunnelBGP->desiredPaths()[0].localPrefixAnnounced;
    return reconciled;
  }

  bool reconcileCrossClusterPrivateBGPSwitchboardFallback(void)
  {
    bool needsBoundaryRouter = false;
    for (auto& runtime : crossClusterMasqueGatewayRuntimes) {
      if (runtime.privateBGPFallbackInstalled) {
        auto found = std::find_if(overlayRoutingConfig.machineRoutes.begin(), overlayRoutingConfig.machineRoutes.end(),
            [&](const auto& route) { return route == runtime.privateBGPFallback; });
        if (found != overlayRoutingConfig.machineRoutes.end()) overlayRoutingConfig.machineRoutes.erase(found);
        runtime.privateBGPFallback = {}; runtime.privateBGPFallbackInstalled = false;
      }
      runtime.privateBGPFallbackProgrammed = false;
      if (!runtime.privateTunnelBGP || runtime.privateTunnelBGP->desiredPaths().size() != 1) continue;
      SwitchboardOverlayMachineRoute route = {};
      if (prodigyBuildCrossClusterPrivateTunnelSwitchboardFallback(runtime.authority,
              runtime.privateTunnelBGP->desiredPaths()[0], route)) {
        overlayRoutingConfig.machineRoutes.push_back(route);
        runtime.privateBGPFallback = route;
        runtime.privateBGPFallbackInstalled = true;
        needsBoundaryRouter = true;
      }
    }
    bool boundaryReady = true;
    if (needsBoundaryRouter) boundaryReady = ensureSwitchboard()->setPrivateBGPBoundaryConsumer(true);
    else if (switchboard) boundaryReady = switchboard->setPrivateBGPBoundaryConsumer(false);
    const bool routingConverged = syncOverlayRoutingPrograms() && boundaryReady;
    for (auto& runtime : crossClusterMasqueGatewayRuntimes) {
      if (routingConverged && !runtime.privateBGPFallbackInstalled)
        runtime.privateBGPFallbackRemovalPending = false;
      runtime.privateBGPFallbackProgrammed = routingConverged && runtime.privateBGPFallbackInstalled &&
          crossClusterPrivateBGPFallbackProgrammed(runtime.privateBGPFallback);
      if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(runtime.authority) ||
          runtime.authority.state != CrossClusterMasqueGatewayState::active) continue;
      const ProdigyCrossClusterPrivateTunnelBGPPath *path = nullptr;
      if (runtime.privateTunnelBGP && runtime.privateTunnelBGP->desiredPaths().size() == 1)
        path = &runtime.privateTunnelBGP->desiredPaths()[0];
      ProdigyCrossClusterPrivateBGPReadiness receipt = {};
      if (!prodigyObserveCrossClusterPrivateBGPReadiness(
              runtime.authority, path, runtime.privateBGPFallbackProgrammed, receipt)) continue;
      if (brain && brain->fd >= 0) {
        String encoded = {}; auto copy = receipt; BitseryEngine::serialize(encoded, copy);
        Message::construct(brain->wBuffer, NeuronTopic::crossClusterPrivateBGPReadinessReceipt, encoded);
        Vault::secureClearString(encoded); Ring::queueSend(brain);
      }
    }
    return routingConverged;
  }

  bool retainExactHostTCXForUnexpectedRestart(EthDevice& device,
                                               SwitchboardHostTCXRetentionPair& retained,
                                               bool& retainedPresent,
                                               String *failureReport,
                                               bool *created = nullptr)
  {
    if (created) *created = false;
    SwitchboardHostTCXRetentionPair candidate = {};
    bool present = false;
    if (switchboardHostTCXReadRetainedPair(device, "/sys/fs/bpf"_ctv, candidate, present) == false ||
        (present && switchboardHostTCXVerifyRetainedPair(device, "/sys/fs/bpf"_ctv, candidate) == false))
    {
      if (failureReport) failureReport->assign("invalid retained host TCX pins"_ctv);
      return false;
    }
    if (present == false && switchboardHostTCXRetainCurrentPair(device, "/sys/fs/bpf"_ctv, candidate) == false)
    {
      if (failureReport) failureReport->assign("cannot retain exact host TCX pair"_ctv);
      return false;
    }
    if (switchboardHostTCXVerifyRetainedPair(device, "/sys/fs/bpf"_ctv, candidate) == false)
    {
      // This Neuron created the candidate only after observing no pair. Exact
      // release cannot remove a replacement's pin, and avoids leaving a
      // failed startup's pair to be mistaken for a recovery witness.
      if (present == false)
      {
        (void)switchboardHostTCXReleaseExact("/sys/fs/bpf"_ctv, candidate.ingress);
        (void)switchboardHostTCXReleaseExact("/sys/fs/bpf"_ctv, candidate.egress);
      }
      if (failureReport) failureReport->assign("retained host TCX identity changed"_ctv);
      return false;
    }
    retained = candidate;
    retainedPresent = true;
    if (created) *created = present == false;
    return true;
  }

  void releaseExactHostTCXForGracefulShutdown(SwitchboardHostTCXRetentionPair& retained,
                                               bool& retainedPresent,
                                               const char *scope)
  {
    if (retainedPresent == false) return;
    if (switchboardHostTCXVerifyRetainedPair(retained.ingress.interfaceIndex, "/sys/fs/bpf"_ctv, retained) == false)
    {
      basics_log("neuron graceful shutdown retained %s TCX release rejected ifidx=%u\n", scope,
                 retained.ingress.interfaceIndex);
      return;
    }
    const bool ingressReleased = switchboardHostTCXReleaseExact("/sys/fs/bpf"_ctv, retained.ingress);
    const bool egressReleased = switchboardHostTCXReleaseExact("/sys/fs/bpf"_ctv, retained.egress);
    if (ingressReleased == false || egressReleased == false)
    {
      basics_log("neuron graceful shutdown retained %s TCX release failed ifidx=%u ingress=%d egress=%d\n", scope,
                 retained.ingress.interfaceIndex, int(ingressReleased), int(egressReleased));
      return;
    }
    retained = {};
    retainedPresent = false;
  }

  bool retainHostTCXForUnexpectedRestart(String *failureReport)
  {
    bool primaryCreated = false;
    if (retainExactHostTCXForUnexpectedRestart(eth, retainedPrimaryHostTCX,
                                                retainedPrimaryHostTCXPresent, failureReport, &primaryCreated) == false)
      return false;
    if (privateOverlayEth &&
        retainExactHostTCXForUnexpectedRestart(*privateOverlayEth, retainedPrivateOverlayHostTCX,
                                                retainedPrivateOverlayHostTCXPresent, failureReport) == false)
    {
      if (primaryCreated)
        releaseExactHostTCXForGracefulShutdown(retainedPrimaryHostTCX, retainedPrimaryHostTCXPresent, "primary");
      return false;
    }
    return true;
  }

  // we don't run this until after the brain sends us our fragment and any container plans, because we use
  // haveFragments as a test of whether it was a spurious connection break or a neuron crash/update or machine crash/update
  void setupNetworking(String *failureReport = nullptr)
  {
    IPPrefix containerSubnet6 = generateAddress(container_network_subnet6, 0, 120);
    Vector<IPPrefix> localPrefixes;
    localPrefixes.push_back(containerSubnet6);

    // and obviously we can't install this twice
    String hostIngressPath = {};
    String hostEgressPath = {};
    String hostRouterFailure = {};
    bool hostRouterBPFEnabled = resolveOptionalHostRouterBPFPaths(hostIngressPath, hostEgressPath, &hostRouterFailure);
    SwitchboardHostTCXRetentionPair retainedHostTCX = {};
    bool retainedHostTCXPresent = false;
    if (hostRouterFailure.size() > 0)
    {
      basics_log("setupNetworking invalid host router bpf configuration reason=%s ifidx=%d\n",
                 hostRouterFailure.c_str(),
                 eth.ifidx);
      std::fprintf(stderr, "setupNetworking invalid host router bpf configuration reason=%s ifidx=%d\n",
                   hostRouterFailure.c_str(), eth.ifidx);
    }
    else if (hostRouterBPFEnabled)
    {
      if (switchboardHostTCXReadRetainedPair(eth, "/sys/fs/bpf"_ctv, retainedHostTCX, retainedHostTCXPresent) == false ||
          (retainedHostTCXPresent && switchboardHostTCXVerifyRetainedPair(eth, "/sys/fs/bpf"_ctv, retainedHostTCX) == false))
      {
        std::fprintf(stderr, "setupNetworking rejected invalid retained host TCX pins ifidx=%d\n", eth.ifidx);
        if (failureReport) failureReport->assign("invalid retained host TCX pins"_ctv);
        return;
      }
      if (retainedHostTCXPresent)
        basics_log("setupNetworking retained TCX admitted ifidx=%d ingressLink=%u egressLink=%u\n",
                     eth.ifidx, retainedHostTCX.ingress.linkID, retainedHostTCX.egress.linkID);
      bool reuseWormholeFlowMaps = switchboardPinnedWormholeFlowMapsCompatible(eth.ifidx);
      String whiteholeReplyPinPath = {};
      switchboardWhiteholeReplyFlowPinPath(whiteholeReplyPinPath, eth.ifidx);
      int whiteholeReplyFD = bpf_obj_get(whiteholeReplyPinPath.c_str());
      const bool reuseWhiteholeReplyMap = whiteholeReplyFD >= 0;
      if (whiteholeReplyFD >= 0) ::close(whiteholeReplyFD);
      else if (errno != ENOENT) {
        if (failureReport) failureReport->assign("cannot open pinned whitehole reply flow map"_ctv);
        std::fprintf(stderr, "setupNetworking cannot open pinned whitehole reply flow map ifidx=%d errno=%d\n", eth.ifidx, errno);
        return;
      }
      tcx_egress_program = eth.loadPreattachedProgram(BPF_TCX_EGRESS, hostEgressPath);
      if (tcx_egress_program)
      {
        if ((reuseWhiteholeReplyMap && !switchboardProgramUsesPinnedWhiteholeReplyFlowMap(tcx_egress_program, eth.ifidx)) ||
            switchboardProgramHasCompatibleWormholeFlowMaps(tcx_egress_program,
                                                           SwitchboardWormholeMapConsumer::forwarding) == false ||
            (reuseWormholeFlowMaps &&
             switchboardProgramUsesPinnedWormholeFlowMaps(tcx_egress_program, eth.ifidx,
                                                         SwitchboardWormholeMapConsumer::forwarding) == false))
        {
          basics_log("setupNetworking detaching stale host egress without authoritative wormhole flow maps path=%s ifidx=%d\n",
                     hostEgressPath.c_str(), eth.ifidx);
          if (retainedHostTCXPresent)
          {
            std::fprintf(stderr, "setupNetworking retained host egress TCX link is stale ifidx=%d errno=%d\n", eth.ifidx, errno);
            if (failureReport) failureReport->assign("retained host egress TCX link is stale"_ctv);
            return;
          }
          eth.detachBPF(BPF_TCX_EGRESS);
          tcx_egress_program = nullptr;
        }
      }

      if (tcx_egress_program == nullptr)
      {
        if (retainedHostTCXPresent)
        {
          std::fprintf(stderr, "setupNetworking retained host egress TCX link could not be adopted ifidx=%d errno=%d\n",
                       eth.ifidx, errno);
          if (failureReport) failureReport->assign("retained host egress TCX link could not be adopted"_ctv);
          return;
        }
        bool mapsReused = reuseWormholeFlowMaps == false;
        bool whiteholeMapReused = !reuseWhiteholeReplyMap;
        tcx_egress_program = eth.attachBPF(BPF_TCX_EGRESS, hostEgressPath, "host_egress"_ctv,
                                           [&](struct bpf_object *obj, Vector<int>& inner_map_fds) -> void {
                                             switchboardConfigureDevelopmentWhiteholeMapAllocation(obj);
                                             if (reuseWhiteholeReplyMap)
                                               whiteholeMapReused = switchboardReusePinnedWhiteholeReplyFlowMap(obj, eth.ifidx, inner_map_fds);
                                             if (reuseWormholeFlowMaps)
                                             {
                                               mapsReused = switchboardReusePinnedWormholeFlowMaps(obj, eth.ifidx, inner_map_fds);
                                             }
                                           });
        if (tcx_egress_program &&
            (mapsReused == false || whiteholeMapReused == false ||
             (reuseWhiteholeReplyMap && !switchboardProgramUsesPinnedWhiteholeReplyFlowMap(tcx_egress_program, eth.ifidx)) ||
             (reuseWormholeFlowMaps &&
              switchboardProgramUsesPinnedWormholeFlowMaps(tcx_egress_program, eth.ifidx,
                                                          SwitchboardWormholeMapConsumer::forwarding) == false)))
        {
          basics_log("setupNetworking detaching host egress that failed authoritative wormhole map reuse path=%s ifidx=%d\n",
                     hostEgressPath.c_str(), eth.ifidx);
          eth.detachBPF(BPF_TCX_EGRESS);
          tcx_egress_program = nullptr;
        }
        if (tcx_egress_program)
        {
          basics_log("setupNetworking attached host egress path=%s ifidx=%d\n",
                     hostEgressPath.c_str(), eth.ifidx);
        }
        else
        {
          if (failureReport)
          {
            failureReport->snprintf<"failed to attach host egress router interface={} ifidx={itoa} errno={itoa}({})"_ctv>(
                eth.name, uint32_t(eth.ifidx), uint32_t(errno), String(strerror(errno)));
          }
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
      bool wormholeFlowPinned = false;
      if (tcx_egress_program)
      {
        whiteholeReplyFlowPinned = switchboardPinWhiteholeReplyFlowMap(tcx_egress_program, eth.ifidx);
        wormholeFlowPinned = switchboardPinWormholeFlowMaps(tcx_egress_program, eth.ifidx,
                                                         SwitchboardWormholeMapConsumer::forwarding);
        if (whiteholeReplyFlowPinned == false)
        {
          basics_log("setupNetworking failed to pin host whitehole reply flow map ifidx=%d\n",
                     eth.ifidx);
        }
        if (wormholeFlowPinned == false)
        {
          basics_log("setupNetworking failed to pin host wormhole flow map ifidx=%d\n",
                     eth.ifidx);
        }
      }

      if (whiteholeReplyFlowPinned == false || wormholeFlowPinned == false)
      {
        basics_log("setupNetworking skipping host ingress attach because shared flow map pinning failed ifidx=%d\n",
                   eth.ifidx);
        std::fprintf(stderr, "setupNetworking shared flow map pinning failed ifidx=%d whiteholeReply=%d wormhole=%d\n",
                     eth.ifidx, int(whiteholeReplyFlowPinned), int(wormholeFlowPinned));
        if (failureReport) failureReport->assign("host router shared flow map pinning failed"_ctv);
        return;
      }
      else
      {
        tcx_ingress_program = eth.loadPreattachedProgram(BPF_TCX_INGRESS, hostIngressPath);
        if (tcx_ingress_program)
        {
          bool hasPortalMaps = false;
          tcx_ingress_program->openMap("ext_portals"_ctv, [&](int mapFD) -> void {
            hasPortalMaps = mapFD >= 0;
          });
          if (hasPortalMaps == false ||
              !switchboardProgramUsesPinnedWhiteholeReplyFlowMap(tcx_ingress_program, eth.ifidx) ||
              switchboardProgramUsesPinnedWormholeFlowMaps(tcx_ingress_program, eth.ifidx) == false)
          {
            basics_log("setupNetworking detaching stale host ingress with incompatible maps path=%s ifidx=%d\n",
                       hostIngressPath.c_str(), eth.ifidx);
            if (retainedHostTCXPresent)
            {
              std::fprintf(stderr, "setupNetworking retained host ingress TCX link is stale ifidx=%d errno=%d\n", eth.ifidx, errno);
              if (failureReport) failureReport->assign("retained host ingress TCX link is stale"_ctv);
              return;
            }
            eth.detachBPF(BPF_TCX_INGRESS);
            tcx_ingress_program = nullptr;
          }
        }

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
          if (retainedHostTCXPresent)
          {
            std::fprintf(stderr, "setupNetworking retained host ingress TCX link could not be adopted ifidx=%d errno=%d\n", eth.ifidx, errno);
            if (failureReport) failureReport->assign("retained host ingress TCX link could not be adopted"_ctv);
            return;
          }
          eth.addIP(containerSubnet6);

          // load and setup tcx ingress program
          tcx_ingress_program = eth.attachBPF(BPF_TCX_INGRESS, hostIngressPath, "host_ingress"_ctv,
                                              [&](struct bpf_object *obj, Vector<int>& inner_map_fds) -> void {
                                                switchboardConfigureDevelopmentWhiteholeMapAllocation(obj);
                                                (void)switchboardReusePinnedWhiteholeReplyFlowMap(obj, eth.ifidx, inner_map_fds);
                                                (void)switchboardReusePinnedWormholeFlowMaps(obj, eth.ifidx, inner_map_fds);
                                              });
          if (tcx_ingress_program &&
              (!switchboardProgramUsesPinnedWhiteholeReplyFlowMap(tcx_ingress_program, eth.ifidx) ||
               switchboardProgramUsesPinnedWormholeFlowMaps(tcx_ingress_program, eth.ifidx) == false))
          {
            basics_log("setupNetworking detaching host ingress without shared wormhole flow map path=%s ifidx=%d\n",
                       hostIngressPath.c_str(), eth.ifidx);
            if (retainedHostTCXPresent)
            {
              std::fprintf(stderr, "setupNetworking retained host ingress TCX link is stale ifidx=%d errno=%d\n", eth.ifidx, errno);
              if (failureReport) failureReport->assign("retained host ingress TCX link is stale"_ctv);
              return;
            }
            eth.detachBPF(BPF_TCX_INGRESS);
            tcx_ingress_program = nullptr;
          }
          if (tcx_ingress_program)
          {
            basics_log("setupNetworking attached host ingress path=%s ifidx=%d\n",
                       hostIngressPath.c_str(), eth.ifidx);
            tcx_ingress_program->setArrayElement("lc_subnet"_ctv, 0, lcsubnet6);
          }
          else
          {
            if (failureReport)
            {
              failureReport->snprintf<"failed to attach host ingress router interface={} ifidx={itoa} errno={itoa}({})"_ctv>(
                  eth.name, uint32_t(eth.ifidx), uint32_t(errno), String(strerror(errno)));
            }
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
      tcx_ingress_program->setArrayElement("mac_map"_ctv, 0, eth.mac);
      tcx_ingress_program->setArrayElement("gw_mac_map"_ctv, 0, eth.gateway_mac);
    }

    if (tcx_egress_program)
    {
      tcx_egress_program->setArrayElement("mac_map"_ctv, 0, eth.mac);
      tcx_egress_program->setArrayElement("gw_mac_map"_ctv, 0, eth.gateway_mac);
      (void)switchboardPinWhiteholeReplyFlowMap(tcx_egress_program, eth.ifidx);
      (void)switchboardPinWormholeFlowMaps(tcx_egress_program, eth.ifidx,
                                        SwitchboardWormholeMapConsumer::forwarding);
      ensureWormholeFlowGCTickQueued();
    }

    // Only adopt a retention operation already established by the lifecycle
    // owner. Ordinary runtime startup must not create persistent link pins.
    if (retainedHostTCXPresent &&
        switchboardHostTCXVerifyRetainedPair(eth, "/sys/fs/bpf"_ctv, retainedHostTCX) == false)
    {
      std::fprintf(stderr, "setupNetworking retained host TCX identity changed ifidx=%d\n", eth.ifidx);
      if (failureReport) failureReport->assign("retained host TCX identity changed"_ctv);
      return;
    }

    if (retainedHostTCXPresent)
      basics_log("setupNetworking retained TCX adopted ifidx=%d ingress=%d egress=%d\n",
                   eth.ifidx, int(tcx_ingress_program != nullptr), int(tcx_egress_program != nullptr));
    iaas->setLocalContainerPrefixes(localPrefixes);
    ensureBGP()->setMachinePrefixes(localPrefixes);

    if (switchboard)
    {
      switchboard->setHostIngressRouter(tcx_ingress_program);
      switchboard->setHostEgressRouter(tcx_egress_program);
      switchboard->setLocalContainerSubnet(lcsubnet6);
    }

    syncWhiteholeBindingsProgram();
    syncOverlayRoutingPrograms();

    String privateOverlayFailure = {};
    if (ensurePrivateOverlayHostRoutingReady(&privateOverlayFailure) == false)
    {
      if (failureReport && failureReport->empty()) failureReport->assign(privateOverlayFailure);
      std::fprintf(stderr, "neuron private overlay host routing setup failed reason=%s\n", privateOverlayFailure.c_str());
      return;
    }

    // Retained recovery invokes setupNetworking directly before it restores any
    // container network. Consume the optional, root-owned ingress selection
    // here too, rather than relying on a later container setup to attach it.
    String additionalIngressFailure = {};
    const bool additionalIngressReady = ensureAdditionalIngressReady(&additionalIngressFailure);
    if (additionalIngressReady == false)
    {
      if (failureReport && failureReport->empty())
      {
        failureReport->assign(additionalIngressFailure);
      }
      std::fprintf(stderr, "neuron additional ingress setup failed reason=%s\n",
                   additionalIngressFailure.c_str());
      std::fflush(stderr);
    }

    if (hostRouterBPFEnabled && additionalIngressReady &&
        retainHostTCXForUnexpectedRestart(failureReport) == false)
    {
      std::fprintf(stderr, "neuron host TCX retention setup failed reason=%s ifidx=%d\n",
                   failureReport ? failureReport->c_str() : "retention rejected", eth.ifidx);
      return;
    }
  }

  bool ensurePrivateOverlayHostRoutingReady(String *failureReport = nullptr)
  {
    String device = {};
    if (prodigyResolveOptionalPrivateOverlayDevice(device, failureReport) == false) return false;
    if (device.empty())
    {
      if (privateOverlayEth)
      {
        if (failureReport) failureReport->assign("private overlay selection removed while attached"_ctv);
        return false;
      }
      return true;
    }
    if (tcx_ingress_program == nullptr || tcx_egress_program == nullptr)
    {
      if (failureReport) failureReport->assign("private overlay requires host routing programs"_ctv);
      return false;
    }
    if (!privateOverlayEth) privateOverlayEth = std::make_unique<EthDevice>();
    privateOverlayEth->setDevice(device);
    if (device == "lo"_ctv || privateOverlayEth->ifidx == 0 || privateOverlayEth->ifidx == eth.ifidx)
    {
      if (failureReport) failureReport->assign("private overlay is not a distinct physical interface"_ctv);
      return false;
    }
    auto readDecimal = [&](const char *suffix, unsigned long& value) -> bool {
      String path = {}; path.assign("/sys/class/net/"_ctv); path.append(device); path.append(suffix);
      char text[32] = {}; int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
      const ssize_t bytes = fd >= 0 ? ::read(fd, text, sizeof(text) - 1) : -1;
      if (fd >= 0) ::close(fd);
      char *end = nullptr; value = bytes > 0 ? ::strtoul(text, &end, 10) : 0;
      return bytes > 0 && end != text && (*end == '\n' || *end == '\0');
    };
    unsigned long type = 0, iflink = 0;
    if (!readDecimal("/type", type) || !readDecimal("/iflink", iflink) || type != 1 || iflink != privateOverlayEth->ifidx)
    {
      if (failureReport) failureReport->assign("private overlay does not prove a physical Ethernet interface"_ctv);
      return false;
    }
    SwitchboardHostTCXRetentionPair retained = {}; bool retainedPresent = false;
    if (switchboardHostTCXReadRetainedPair(*privateOverlayEth, "/sys/fs/bpf"_ctv, retained, retainedPresent) == false ||
        (retainedPresent && (!switchboardHostTCXVerifyRetainedPair(*privateOverlayEth, "/sys/fs/bpf"_ctv, retained) ||
                             retained.ingress.programID != Switchboard::kernelProgramID(tcx_ingress_program) ||
                             retained.egress.programID != Switchboard::kernelProgramID(tcx_egress_program))))
    {
      if (failureReport) failureReport->assign("private overlay retained TCX identity invalid"_ctv);
      return false;
    }
    if (!switchboardPinWhiteholeReplyFlowMap(tcx_egress_program, privateOverlayEth->ifidx) ||
        !switchboardAliasPinnedWormholeFlowMaps(eth.ifidx, privateOverlayEth->ifidx) ||
        !ensureSwitchboard()->configurePrivateOverlayHostRouting(*privateOverlayEth, tcx_ingress_program, tcx_egress_program, failureReport))
      return false;
    if (retainedPresent && !switchboardHostTCXVerifyRetainedPair(*privateOverlayEth, "/sys/fs/bpf"_ctv, retained))
    {
      if (failureReport) failureReport->assign("private overlay retained TCX identity changed"_ctv);
      return false;
    }
    return true;
  }

  bool ensureAdditionalIngressReady(String *failureReport = nullptr)
  {
    String device = {};
    if (resolveOptionalAdditionalIngressDevice(device, failureReport) == false)
    {
      std::fprintf(stderr, "ensureAdditionalIngressReady failed reason=%s primaryIfidx=%d\n",
                   failureReport ? failureReport->c_str() : "additional ingress configuration invalid", eth.ifidx);
      return false;
    }
    if (device.size() == 0)
    {
      if (switchboard) switchboard->detachAdditionalIngress();
      additionalIngressEth.reset();
      return true;
    }
    if (tcx_ingress_program == nullptr)
    {
      if (failureReport) failureReport->assign("additional ingress requires host ingress router"_ctv);
      std::fprintf(stderr, "ensureAdditionalIngressReady failed reason=missing-host-ingress-router primaryIfidx=%d device=%s\n",
                   eth.ifidx, device.c_str());
      return false;
    }
    if (!additionalIngressEth) additionalIngressEth = std::make_unique<EthDevice>();
    additionalIngressEth->setDevice(device);
    if (additionalIngressEth->ifidx == 0 || additionalIngressEth->ifidx == eth.ifidx)
    {
      if (failureReport) failureReport->assign("additional ingress is not a distinct veth"_ctv);
      std::fprintf(stderr, "ensureAdditionalIngressReady failed reason=not-distinct-veth primaryIfidx=%d additionalIfidx=%d device=%s\n",
                   eth.ifidx, additionalIngressEth->ifidx, device.c_str());
      return false;
    }
    String iflinkPath = {};
    iflinkPath.assign("/sys/class/net/"_ctv);
    iflinkPath.append(device);
    iflinkPath.append("/iflink"_ctv);
    char iflink[32] = {};
    int iflinkFD = ::open(iflinkPath.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    const ssize_t iflinkBytes = iflinkFD >= 0 ? ::read(iflinkFD, iflink, sizeof(iflink) - 1) : -1;
    if (iflinkFD >= 0) ::close(iflinkFD);
    char *end = nullptr;
    const unsigned long peerIfidx = iflinkBytes > 0 ? ::strtoul(iflink, &end, 10) : 0;
    if (peerIfidx == 0 || end == iflink || peerIfidx == additionalIngressEth->ifidx)
    {
      if (failureReport) failureReport->assign("additional ingress does not prove a veth peer"_ctv);
      std::fprintf(stderr, "ensureAdditionalIngressReady failed reason=unproven-veth-peer primaryIfidx=%d additionalIfidx=%d peerIfidx=%lu device=%s\n",
                   eth.ifidx, additionalIngressEth->ifidx, peerIfidx, device.c_str());
      return false;
    }
    const bool configured = ensureSwitchboard()->configureAdditionalIngress(*additionalIngressEth, tcx_ingress_program, failureReport);
    if (configured)
    {
      // configureAdditionalIngress can create or replace the boundary XDP
      // program after the earlier setupNetworking overlay sync. Populate the
      // new program before it can receive traffic from the tunnel veth.
      syncSwitchboardBalancerOverlayRoutingProgram();
    }
    if (configured == false)
    {
      std::fprintf(stderr, "ensureAdditionalIngressReady failed reason=%s primaryIfidx=%d additionalIfidx=%d peerIfidx=%lu device=%s\n",
                   failureReport ? failureReport->c_str() : "switchboard additional ingress rejected",
                   eth.ifidx, additionalIngressEth->ifidx, peerIfidx, device.c_str());
    }
    return configured;
  }

  virtual bool ensureHostNetworkingReady(String *failureReport = nullptr) override
  {
    // Linux evaluates rp_filter as the maximum of conf/all and the ingress
    // interface value. Keep the global floor disabled so the explicit
    // per-netkit rp_filter=0 policy can apply to addressless L3 peers; physical
    // interfaces retain their own distro-provided setting.
    if (writeProcSysctlValue("/proc/sys/net/ipv4/conf/all/rp_filter", "0") == false)
    {
      if (failureReport)
      {
        failureReport->assign("failed to enable per-interface IPv4 source validation"_ctv);
      }
      return false;
    }

    if (writeProcSysctlValue("/proc/sys/net/ipv4/ip_forward", "1") == false)
    {
      if (failureReport)
      {
        failureReport->assign("failed to enable IPv4 container routing"_ctv);
      }
      return false;
    }

    if (writeProcSysctlValue("/proc/sys/net/ipv6/conf/all/forwarding", "1") == false)
    {
      if (failureReport)
      {
        failureReport->assign("failed to enable IPv6 container routing"_ctv);
      }
      return false;
    }

    if (tcx_ingress_program && tcx_egress_program)
    {
      return ensurePrivateOverlayHostRoutingReady(failureReport) && ensureAdditionalIngressReady(failureReport);
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

    setupNetworking(failureReport);

    if (hostRouterBPFEnabled == false)
    {
      return true;
    }

    if (tcx_ingress_program == nullptr || tcx_egress_program == nullptr)
    {
      if (failureReport && failureReport->size() == 0)
      {
        failureReport->snprintf<"host networking programs unavailable ingress={} egress={}"_ctv>(
            String(tcx_ingress_program ? "ready" : "missing"),
            String(tcx_egress_program ? "ready" : "missing"));
      }

      basics_log("ensureHostNetworkingReady failed ingress=%d egress=%d ifidx=%d\n",
                 int(tcx_ingress_program != nullptr), int(tcx_egress_program != nullptr), eth.ifidx);
      return false;
    }

    return ensurePrivateOverlayHostRoutingReady(failureReport) && ensureAdditionalIngressReady(failureReport) &&
           retainHostTCXForUnexpectedRestart(failureReport);
  }

public:

  // Guardian shutdown does not rely on C++ destruction. Release the exact
  // runtime-owned restart pins, then the optional ingress, while this Neuron
  // still owns the corresponding attachment identities. Unexpected death and
  // bundle exec deliberately do not call this path.
  void detachAdditionalIngressForShutdown(void)
  {
    releaseExactHostTCXForGracefulShutdown(retainedPrivateOverlayHostTCX,
                                           retainedPrivateOverlayHostTCXPresent, "private-overlay");
    releaseExactHostTCXForGracefulShutdown(retainedPrimaryHostTCX,
                                           retainedPrimaryHostTCXPresent, "primary");
    if (switchboard) switchboard->detachAdditionalIngress();
    additionalIngressEth.reset();
  }

  const String *readyInstalledBundleDigest(void) const override
  {
    return installedBundleDigestReady ? &installedBundleDigest : nullptr;
  }

  bool isBrain;
  TCPSocket brainListener;
  NeuronBrainControlStream *brain = nullptr;
  ProdigyTransportCredentialBootstrap controlTransportCredentials;
  ProdigyTransportCredentialLifecycleProjection controlTransportCredentialLifecycleProjection;
  bool tryStagedTransportCredentialOnNextAccept = false;
  bool transportPeerProjectionPersistencePending = false;
  ProdigyLocalClusterPairControlProjection clusterPairControlProjection;
  bool clusterPairControlProjectionPersistencePending = false;
  std::unique_ptr<SwitchboardPairControlRuntime> pairControlRuntime;

  struct CousinSessionLocalPending {
    uint128_t sessionUUID = 0;
    uint64_t leaseGeneration = 0;
    uint128_t containerUUID = 0;
    uint64_t carrierConnectionID = 0;
    uint64_t carrierGeneration = 0;
    CousinRouteHalf localHalf = CousinRouteHalf::source;
    ProdigyCousinSessionRecord session = {};
    uint64_t controlGeneration = 0;
    uint128_t controlPeerUUID = 0;
    ProdigyCousinSessionLocalKind kind = ProdigyCousinSessionLocalKind::install;
    bool acknowledged = false;
    int64_t expiresAtMs = 0;
  };
  Vector<CousinSessionLocalPending> cousinSessionLocalPendings = {};

  struct CousinCarrierDeliveryPending {
    uint128_t containerUUID = 0;
    uint128_t sessionUUID = 0;
    uint64_t leaseGeneration = 0;
    String serialized = {};
  };
  // Pair control commits a frame only after it is admitted here. This bounded
  // queue is the sole backpressure bridge from its authenticated record stream
  // to a busy AF_UNIX container; no accepted carrier record is silently lost.
  Vector<CousinCarrierDeliveryPending> cousinCarrierDeliveries = {};
  uint32_t cousinCarrierDeliveryBytes = 0;
  static constexpr uint32_t cousinCarrierDeliveryMaximumRecords =
      ProdigyCousinSessionMaximumRecords * ProdigyCousinCarrierMaximumCredits;
  static constexpr uint32_t cousinCarrierDeliveryMaximumBytes = cousinCarrierDeliveryMaximumRecords *
      (ProdigyCousinCarrierMaximumPayloadBytes + 128);

  void discardCousinCarrierDeliveries(uint128_t containerUUID, uint128_t sessionUUID = 0,
                                      uint64_t leaseGeneration = 0)
  {
    for (auto it = cousinCarrierDeliveries.begin(); it != cousinCarrierDeliveries.end();) {
      if (it->containerUUID != containerUUID ||
          (sessionUUID != 0 && (it->sessionUUID != sessionUUID || it->leaseGeneration != leaseGeneration))) {
        ++it; continue;
      }
      cousinCarrierDeliveryBytes -= uint32_t(it->serialized.size());
      it = cousinCarrierDeliveries.erase(it);
    }
  }

  struct CousinAdmissionInstalled {
    uint128_t sessionUUID = 0;
    uint64_t leaseGeneration = 0;
    uint32_t destinationContainerID = 0;
    String destinationWormholeRevision = {};
    switchboard_pair_admission_route_key routeKey = {};
    switchboard_pair_admission_grant_key grantKey = {};
    uint64_t rootGeneration = 0;
    uint64_t keyEpoch = 0;
    String digest = {};
    int64_t expiresAtMs = 0;
    uint128_t privateContainerUUID = 0;
    ProdigyCousinSessionRecord privateSession = {};
  };
  Vector<CousinAdmissionInstalled> cousinAdmissionInstalled = {};

  struct CousinSessionReceiptPending {
    String serialized = {};
    uint64_t controlGeneration = 0;
    uint128_t controlPeerUUID = 0;
    uint64_t projectionGeneration = 0;
    int64_t expiresAtMs = 0;
  };
  Vector<CousinSessionReceiptPending> cousinSessionReceiptPendings = {};

  virtual bool installClusterPairControlProjection(const ProdigyLocalClusterPairControlProjection& projection)
  {
    return prodigyLocalClusterPairControlProjectionValid(projection, true) &&
        (!pairControlRuntime || pairControlRuntime->installProjection(projection));
  }

  bool startClusterPairControlRuntime()
  {
    if (pairControlRuntime) return false;
    pairControlRuntime = std::make_unique<SwitchboardPairControlRuntime>();
    pairControlRuntime->onEpochStatus = [this](const ProdigyClusterPairEpochReceipt& receipt) {
      forwardClusterPairEpochStatus(receipt);
    };
    pairControlRuntime->onDiscoverySnapshot = [this](const ProdigyCousinDiscoveryReceipt& receipt) {
      forwardCousinDiscoveryReceipt(receipt);
    };
    pairControlRuntime->onSessionControl = [this](const ProdigyCousinSessionReceipt& receipt) {
      forwardCousinSessionControlReceipt(receipt);
    };
    pairControlRuntime->onCarrierFrame = [this](const ClusterPairControlEndpoint& local,
        const ClusterPairControlEndpoint& remote, uint64_t connectionID, const ProdigyCousinCarrierFrame& frame) {
      return forwardCousinCarrierFrame(local, remote, connectionID, frame);
    };
    // The saved projection fences rollback, but may have been revoked while
    // this node was offline. Only a fresh durable current-master projection
    // may activate its credentials on this process incarnation.
    return pairControlRuntime->start();
  }

  bool cousinSessionCarrierCurrent(NeuronBrainControlStream *stream, uint64_t generation,
                                   uint128_t peerUUID) const
  {
    return pairControlRuntime && controlTransportCredentials.enabled &&
        prodigyLocalClusterPairControlProjectionValid(clusterPairControlProjection, true) &&
        controlPeerCurrentlyAuthorized(peerUUID) &&
        transportPeerProjectionControlCurrent(stream, generation, peerUUID);
  }

  void flushCousinSessionControlReceipts()
  {
    const int64_t now = Time::msSinceBoot();
    while (!cousinSessionReceiptPendings.empty()) {
      const auto& pending = cousinSessionReceiptPendings.front();
      NeuronBrainControlStream *stream = brain;
      if (now >= pending.expiresAtMs ||
          pending.projectionGeneration != clusterPairControlProjection.committedAuthorityGeneration ||
          !cousinSessionCarrierCurrent(stream, pending.controlGeneration, pending.controlPeerUUID)) {
        cousinSessionReceiptPendings.erase(cousinSessionReceiptPendings.begin());
        continue;
      }
      if (stream->pendingSend || stream->wBuffer.outstandingBytes() != 0 ||
          !streamIsActive(stream) || Ring::socketIsClosing(stream)) return;
      Message::construct(stream->wBuffer, NeuronTopic::cousinSessionControlReceipt, pending.serialized);
      cousinSessionReceiptPendings.erase(cousinSessionReceiptPendings.begin());
      Ring::queueSend(stream);
      return;
    }
  }

  void forwardCousinSessionControlReceipt(const ProdigyCousinSessionReceipt& receipt)
  {
    NeuronBrainControlStream *stream = brain;
    const uint64_t generation = stream ? stream->ioGeneration : 0;
    const uint128_t peerUUID = stream ? stream->tlsPeerUUID : 0;
    if (!prodigyCousinSessionReceiptValid(receipt) ||
        receipt.projectionGeneration != clusterPairControlProjection.committedAuthorityGeneration ||
        receipt.localEndpoint.clusterUUID != clusterPairControlProjection.localClusterUUID ||
        receipt.localEndpoint.nodeUUID != clusterPairControlProjection.nodeUUID ||
        !cousinSessionCarrierCurrent(stream, generation, peerUUID)) return;
    flushCousinSessionControlReceipts();
    if (cousinSessionReceiptPendings.size() >= ProdigyCousinSessionMaximumRecords) return;
    CousinSessionReceiptPending pending;
    if (!BitseryEngine::serialize(pending.serialized, receipt) ||
        pending.serialized.size() > ProdigyCousinSessionMaximumBytes) return;
    pending.controlGeneration = generation;
    pending.controlPeerUUID = peerUUID;
    pending.projectionGeneration = receipt.projectionGeneration;
    pending.expiresAtMs = Time::msSinceBoot() + ProdigyCousinSessionPendingMs;
    cousinSessionReceiptPendings.push_back(std::move(pending));
    flushCousinSessionControlReceipts();
  }

  void flushCousinCarrierDeliveries(Container *container)
  {
    if (!container || !streamIsActive(container) || container->pendingSend || container->wBuffer.outstandingBytes() != 0) return;
    auto pending = std::find_if(cousinCarrierDeliveries.begin(), cousinCarrierDeliveries.end(),
        [&](const auto& value) { return value.containerUUID == container->plan.uuid; });
    if (pending == cousinCarrierDeliveries.end()) return;
    // Session/revoke control is written directly to wBuffer and therefore has
    // priority over this idle-only carrier drain.
    Message::construct(container->wBuffer, ContainerTopic::cousinCarrierFrame, pending->serialized);
    cousinCarrierDeliveryBytes -= uint32_t(pending->serialized.size());
    cousinCarrierDeliveries.erase(pending);
    Ring::queueSend(container);
  }

  bool forwardCousinCarrierFrame(const ClusterPairControlEndpoint& local,
                                 const ClusterPairControlEndpoint& remote, uint64_t connectionID,
                                 const ProdigyCousinCarrierFrame& frame)
  {
    if (!pairControlRuntime || connectionID == 0 || !prodigyCousinCarrierFrameValid(frame)) return false;
    pruneCousinSessionEphemeralState(Time::msSinceBoot());
    auto pending = std::find_if(cousinSessionLocalPendings.begin(), cousinSessionLocalPendings.end(),
        [&](const auto& value) {
          if (!value.acknowledged || value.sessionUUID != frame.sessionUUID ||
              value.carrierGeneration != frame.leaseGeneration ||
              value.carrierConnectionID != connectionID ||
              !prodigyCousinReverseCarrierSessionValid(value.session)) return false;
          const auto& expectedLocal = value.localHalf == CousinRouteHalf::source ?
              value.session.sourceCarrier : value.session.destinationCarrier;
          const auto& expectedRemote = value.localHalf == CousinRouteHalf::source ?
              value.session.destinationCarrier : value.session.sourceCarrier;
          return local == expectedLocal && remote == expectedRemote;
        });
    if (pending == cousinSessionLocalPendings.end()) return false;
    auto container = containers.find(pending->containerUUID);
    if (container == containers.end() || !container->second || !streamIsActive(container->second)) return false;
    if (frame.kind == ProdigyCousinCarrierKind::reset)
      discardCousinCarrierDeliveries(pending->containerUUID, frame.sessionUUID, frame.leaseGeneration);
    String encoded = {}; auto copy = frame;
    if (!BitseryEngine::serialize(encoded, copy) || encoded.size() > ProdigyCousinCarrierMaximumPayloadBytes + 128 ||
        cousinCarrierDeliveries.size() >= cousinCarrierDeliveryMaximumRecords ||
        encoded.size() > cousinCarrierDeliveryMaximumBytes - cousinCarrierDeliveryBytes) return false;
    cousinCarrierDeliveryBytes += uint32_t(encoded.size());
    cousinCarrierDeliveries.push_back({pending->containerUUID, frame.sessionUUID, frame.leaseGeneration, std::move(encoded)});
    flushCousinCarrierDeliveries(container->second);
    // A reset is a terminal carrier-flow event.  Remove only this exact local
    // ephemeral authorization; a later Brain renewal must re-install it.
    if (frame.kind == ProdigyCousinCarrierKind::reset) cousinSessionLocalPendings.erase(pending);
    return true;
  }

  void receiveCousinSessionControl(const ProdigyCousinSessionPublication& publication)
  {
    NeuronBrainControlStream *stream = brain;
    const uint64_t generation = stream ? stream->ioGeneration : 0;
    const uint128_t peerUUID = stream ? stream->tlsPeerUUID : 0;
    if (!prodigyCousinSessionPublicationValid(publication) ||
        publication.nodeUUID != controlTransportCredentials.self.nodeUUID ||
        publication.projectionGeneration != clusterPairControlProjection.committedAuthorityGeneration ||
        !cousinSessionCarrierCurrent(stream, generation, peerUUID)) return;
    (void)pairControlRuntime->sendSessionControl(publication);
  }

  void receiveCousinSessionLocalCommand(uint128_t containerUUID,
                                        const ProdigyCousinSessionLocalCommand& command)
  {
    NeuronBrainControlStream *stream = brain;
    const uint64_t generation = stream ? stream->ioGeneration : 0;
    const uint128_t peerUUID = stream ? stream->tlsPeerUUID : 0;
    if (containerUUID == 0 || !prodigyCousinSessionLocalCommandValid(command) ||
        !cousinSessionCarrierCurrent(stream, generation, peerUUID)) return;
    auto containerIt = containers.find(containerUUID);
    if (containerIt == containers.end() || containerIt->second == nullptr || !streamIsActive(containerIt->second)) return;
    Container *container = containerIt->second;
    if (command.kind != ProdigyCousinSessionLocalKind::reject &&
        !cousinSessionCommandMatchesContainer(command, *container)) return;
    pruneCousinSessionEphemeralState(Time::msSinceBoot());
    auto existing = std::find_if(cousinSessionLocalPendings.begin(), cousinSessionLocalPendings.end(),
        [&](const auto& value) { return value.sessionUUID == command.session.sessionUUID; });
    if (command.kind != ProdigyCousinSessionLocalKind::reject) {
      // A renewal deliberately reuses the session identity.  It may replace only
      // its own still-live owner record; installs and activations are one-shot.
      if (existing != cousinSessionLocalPendings.end()) {
        const bool exactRenewal = command.kind == ProdigyCousinSessionLocalKind::renew &&
            command.leaseGeneration == existing->leaseGeneration + 1 &&
            command.localHalf == existing->localHalf && prodigyCousinSessionExact(command.session, existing->session);
        // Cleanup may race a partially delivered renewal: a newer generation
        // only removes this exact retained session and cannot grant authority.
        const bool exactRevocation = command.kind == ProdigyCousinSessionLocalKind::revoke &&
            command.leaseGeneration >= existing->leaseGeneration;
        if ((!exactRenewal && !exactRevocation) || existing->containerUUID != containerUUID ||
            (exactRenewal && existing->carrierGeneration != command.carrierGeneration)) return;
      } else if ((command.kind == ProdigyCousinSessionLocalKind::install ||
                  command.kind == ProdigyCousinSessionLocalKind::activate) && command.leaseGeneration != 1) return;
      else if (cousinSessionLocalPendings.size() >= ProdigyCousinSessionMaximumRecords &&
               command.kind != ProdigyCousinSessionLocalKind::revoke) return;
    }
    String serialized = {}; auto copy = command;
    if (!BitseryEngine::serialize(serialized, copy) || serialized.size() > ProdigyCousinSessionMaximumBytes) return;
    if (command.kind != ProdigyCousinSessionLocalKind::reject &&
        command.localHalf == CousinRouteHalf::source &&
        prodigyCousinSessionUsesPrivateContainerEndpoints(command.session)) {
      const bool revoke = command.kind == ProdigyCousinSessionLocalKind::revoke;
      const uint64_t nowNs = monotonicNowNs();
      const uint64_t lifetime = uint64_t(command.validForMs) * 1000000ULL;
      if (!nowNs || (!revoke && (!lifetime || command.validForMs > ProdigyCousinSessionLeaseMs ||
                                UINT64_MAX - nowNs < lifetime)) ||
          !container->applyPrivateSessionTCPFlow(command.session, command.localHalf,
                                                revoke ? 0 : nowNs + lifetime, revoke)) return;
    }
    Message::construct(container->wBuffer, ContainerTopic::cousinSessionCommand, serialized);
    Ring::queueSend(container);
    if (command.kind != ProdigyCousinSessionLocalKind::reject) {
      // Revocation has no lease by design, but its local acknowledgement must
      // remain admissible long enough to reach the same authenticated Brain.
      const uint32_t acknowledgementWindow = command.validForMs ? command.validForMs : ProdigyCousinSessionPendingMs;
      CousinSessionLocalPending pending = {command.session.sessionUUID, command.leaseGeneration, containerUUID,
          command.carrierConnectionID, command.carrierGeneration, command.localHalf, command.session, generation, peerUUID, command.kind, false,
          Time::msSinceBoot() + int64_t(acknowledgementWindow)};
      if (existing != cousinSessionLocalPendings.end()) *existing = pending;
      else cousinSessionLocalPendings.push_back(std::move(pending));
    }
  }

  const Whitehole *cousinSessionSourceWhitehole(const Container& container, uint64_t nonce) const
  {
    const Whitehole *matched = nullptr;
    for (const Whitehole& whitehole : container.plan.whiteholes) {
      if (whitehole.bindingNonce != nonce) continue;
      if (!whiteholeDeclarationValid(whitehole) || !whitehole.hasAddress || !whitehole.address.is6 ||
          whitehole.transport != ExternalAddressTransport::tcp || whitehole.address.isNull() ||
          whitehole.sourcePort == 0) return nullptr;
      if (matched != nullptr) return nullptr;
      matched = &whitehole;
    }
    return matched;
  }

  bool cousinSessionCommandMatchesContainer(const ProdigyCousinSessionLocalCommand& command,
                                             const Container& container) const
  {
    if (!prodigyCousinSessionLocalCommandValid(command) || !controlTransportCredentials.enabled) return false;
    const uint32_t containerID = generateLocalContainerID(container.plan.fragment);
    const bool source = command.localHalf == CousinRouteHalf::source;
    const auto& permission = source ? command.session.sourcePermission : command.session.destination.permission;
    if (command.kind != ProdigyCousinSessionLocalKind::revoke &&
        !prodigyCousinPermissionContainerPlanMatches(permission, container.plan,
            source ? command.session.sourceService : command.session.destination.service,
            prodigyCousinSessionUsesPrivateContainerEndpoints(command.session))) return false;
    if (prodigyCousinSessionUsesPrivateContainerEndpoints(command.session))
      return privateCousinEndpointMatchesContainer(command.session, command.localHalf, container,
          command.kind != ProdigyCousinSessionLocalKind::revoke);
    if (command.localHalf == CousinRouteHalf::source) {
      const Whitehole *whitehole = cousinSessionSourceWhitehole(container, command.session.sourceBindingNonce);
      return command.session.sourceContainerUUID == container.plan.uuid &&
          command.session.sourceContainerID == containerID &&
          command.session.sourceNodeUUID == controlTransportCredentials.self.nodeUUID &&
          command.session.sourcePermission.localClusterUUID == controlTransportCredentials.self.clusterUUID &&
          whitehole != nullptr && whitehole->address.equals(command.session.sourceAddress) &&
          whitehole->sourcePort == command.session.sourceTCPPort;
    }
    if (command.localHalf != CousinRouteHalf::destination ||
        command.session.destination.containerUUID != container.plan.uuid ||
        command.session.destination.containerID != containerID ||
        command.session.destination.nodeUUID != controlTransportCredentials.self.nodeUUID ||
        command.session.destination.permission.localClusterUUID != controlTransportCredentials.self.clusterUUID) return false;
    uint32_t matches = 0;
    for (const Wormhole& wormhole : container.plan.wormholes) {
      if (wormhole.externalAddress.is6 && wormhole.externalAddress.equals(command.session.destination.publicAddress) &&
          wormhole.externalPort == command.session.destination.publicTCPPort &&
          wormhole.containerPort == command.session.destination.servicePort &&
          wormhole.layer4 == IPPROTO_TCP && !wormhole.isQuic) ++matches;
    }
    return matches == 1;
  }

  bool privateCousinEndpointMatchesContainer(const ProdigyCousinSessionRecord& session,
                                             CousinRouteHalf half, const Container& container,
                                             bool requireCurrentPlan = true) const
  {
    if (!prodigyCousinSessionRecordValid(session) ||
        !prodigyCousinSessionUsesPrivateContainerEndpoints(session) ||
        !cousinRouteHalfValid(half)) return false;
    const bool source = half == CousinRouteHalf::source;
    const auto& permission = source ? session.sourcePermission : session.destination.permission;
    const uint64_t service = source ? session.sourceService : session.destination.service;
    const IPAddress& address = source ? session.sourceAddress : session.destination.publicAddress;
    if ((source ? session.sourceContainerUUID : session.destination.containerUUID) != container.plan.uuid ||
        (source ? session.sourceContainerID : session.destination.containerID) !=
            generateLocalContainerID(container.plan.fragment) ||
        (source ? session.sourceNodeUUID : session.destination.nodeUUID) != controlTransportCredentials.self.nodeUUID ||
        permission.localClusterUUID != controlTransportCredentials.self.clusterUUID) return false;
    // Revocation narrows an exact session token even after its former service
    // is removed from the current plan.
    if (!requireCurrentPlan) return true;
    if (!prodigyValidateContainerPlanMeshIdentity(container.plan, lcsubnet6) ||
        !prodigyCousinPermissionContainerPlanMatches(permission, container.plan, service, true)) return false;
    uint32_t addresses = 0;
    for (const auto& candidate : container.plan.addresses)
      if (candidate.cidr == 128 && candidate.network.equals(address)) ++addresses;
    if (addresses != 1) return false;
    if (source) return true;
    const auto advertised = container.plan.advertisements.find(service);
    return advertised != container.plan.advertisements.end() &&
        advertised->second.port == session.destination.servicePort &&
        session.destination.publicTCPPort == session.destination.servicePort &&
        serviceBlueprintActiveAtContainerState(advertised->second, container.plan.state);
  }

  bool clearPrivateCousinFlow(const CousinSessionLocalPending& pending)
  {
    if (pending.localHalf != CousinRouteHalf::source ||
        !prodigyCousinSessionUsesPrivateContainerEndpoints(pending.session)) return true;
    auto found = containers.find(pending.containerUUID);
    return found == containers.end() || !found->second ||
        found->second->applyPrivateSessionTCPFlow(pending.session, pending.localHalf, 0, true);
  }

  bool clearCousinAdmissionGrant(const CousinAdmissionInstalled& installed)
  {
    if (installed.privateContainerUUID != 0) {
      auto found = containers.find(installed.privateContainerUUID);
      return found == containers.end() || !found->second ||
          found->second->applyPrivateSessionTCPFlow(installed.privateSession, CousinRouteHalf::destination, 0, true);
    }
    if (!tcx_egress_program) return false;
    switchboard_pair_admission_route_policy revoked = {};
    revoked.route_generation = 1; revoked.root_generation = installed.rootGeneration;
    revoked.key_epoch = installed.keyEpoch; revoked.expires_at_ns = monotonicNowNs();
    revoked.state = SWITCHBOARD_PAIR_ADMISSION_ROUTE_REVOKED;
    if (revoked.expires_at_ns == 0 ||
        !Container::revokeVerifiedPairAdmissionRoute(tcx_egress_program, installed.routeKey, revoked)) return false;
    return Container::removeVerifiedPairAdmissionGrant(tcx_egress_program, installed.grantKey,
        installed.routeKey, installed.rootGeneration, installed.keyEpoch);
  }

  void clearPrivateCousinAdmissionsForContainer(uint128_t containerUUID)
  {
    for (auto it = cousinAdmissionInstalled.begin(); it != cousinAdmissionInstalled.end();) {
      if (it->privateContainerUUID != containerUUID) { ++it; continue; }
      if (!clearCousinAdmissionGrant(*it))
        basics_log("neuron private session cleanup deferred to bounded kernel expiry\n");
      it = cousinAdmissionInstalled.erase(it);
    }
  }

  void forwardCousinAdmissionResetInvalidation(const CousinAdmissionInstalled& installed)
  {
    NeuronBrainControlStream *stream = brain;
    const uint64_t generation = stream ? stream->ioGeneration : 0;
    const uint128_t peerUUID = stream ? stream->tlsPeerUUID : 0;
    const bool privateContainer = installed.privateContainerUUID != 0;
    const bool revisionValid = privateContainer ?
        (prodigyCousinSessionRecordValid(installed.privateSession) &&
         prodigyCousinSessionUsesPrivateContainerEndpoints(installed.privateSession) &&
         installed.privateSession.sessionUUID == installed.sessionUUID &&
         installed.privateSession.destination.containerUUID == installed.privateContainerUUID &&
         installed.privateSession.destination.containerID == installed.destinationContainerID &&
         installed.destinationWormholeRevision.empty()) :
        prodigyIsSHA256HexDigest(installed.destinationWormholeRevision);
    if (installed.expiresAtMs <= Time::msSinceBoot() || installed.destinationContainerID == 0 ||
        !revisionValid || !cousinSessionCarrierCurrent(stream, generation, peerUUID)) return;
    ProdigyCousinAdmissionAck acknowledgement = {};
    if (privateContainer) acknowledgement.protocolVersion = ProdigyCousinAdmissionAck::privateContainerVersion;
    acknowledgement.leaseGeneration = installed.leaseGeneration;
    acknowledgement.sessionUUID = installed.sessionUUID;
    acknowledgement.containerID = installed.destinationContainerID;
    acknowledgement.wormholeRevision = installed.destinationWormholeRevision;
    acknowledgement.failure.assign("switchboard reset invalidated cousin admission"_ctv);
    String encoded = {};
    if (BitseryEngine::serialize(encoded, acknowledgement) && encoded.size() <= ProdigyCousinSessionMaximumBytes &&
        cousinSessionCarrierCurrent(stream, generation, peerUUID)) {
      Message::construct(stream->wBuffer, NeuronTopic::cousinAdmissionAck, encoded);
      Ring::queueSend(stream);
    }
  }

  void invalidateCousinAdmissionsForSwitchboardReset()
  {
    uint32_t cleanupFailures = 0;
    for (const CousinAdmissionInstalled& installed : cousinAdmissionInstalled)
    {
      forwardCousinAdmissionResetInvalidation(installed);
      if (!clearCousinAdmissionGrant(installed))
      {
        ++cleanupFailures;
      }
    }
    // Portal slots and target bindings are recreated by resetState. Never
    // renew the old ledger entries after that boundary, even when an exact BPF
    // cleanup must instead age out under its already-bounded lease.
    cousinAdmissionInstalled.clear();
    if (cleanupFailures != 0)
    {
      basics_log("neuron switchboard reset could not immediately clear %u cousin admission grants\n",
                 cleanupFailures);
    }
  }

  void pruneCousinSessionEphemeralState(int64_t now)
  {
    for (auto it = cousinSessionLocalPendings.begin(); it != cousinSessionLocalPendings.end();) {
      if (it->expiresAtMs <= now) {
        (void)clearPrivateCousinFlow(*it);
        discardCousinCarrierDeliveries(it->containerUUID, it->sessionUUID, it->carrierGeneration);
        it = cousinSessionLocalPendings.erase(it);
      } else ++it;
    }
    for (auto it = cousinAdmissionInstalled.begin(); it != cousinAdmissionInstalled.end();) {
      if (it->expiresAtMs > now) { ++it; continue; }
      if (clearCousinAdmissionGrant(*it)) it = cousinAdmissionInstalled.erase(it); else ++it;
    }
  }

  void forwardCousinSessionLocalAck(Container *container, const ProdigyCousinSessionLocalAck& ack)
  {
    if (!container || !prodigyCousinSessionLocalAckValid(ack)) return;
    NeuronBrainControlStream *stream = brain;
    const uint64_t generation = stream ? stream->ioGeneration : 0;
    const uint128_t peerUUID = stream ? stream->tlsPeerUUID : 0;
    pruneCousinSessionEphemeralState(Time::msSinceBoot());
    auto pending = std::find_if(cousinSessionLocalPendings.begin(), cousinSessionLocalPendings.end(),
        [&](const auto& value) { return value.sessionUUID == ack.sessionUUID && value.leaseGeneration == ack.leaseGeneration &&
            value.containerUUID == container->plan.uuid && value.kind == ack.kind &&
            value.controlGeneration == generation && value.controlPeerUUID == peerUUID; });
    // Native stream failure is a narrowing operation. It may revoke an
    // installed/renewed lease without waiting for a separately issued revoke.
    if (pending == cousinSessionLocalPendings.end() && ack.kind == ProdigyCousinSessionLocalKind::revoke && ack.success) {
      pending = std::find_if(cousinSessionLocalPendings.begin(), cousinSessionLocalPendings.end(),
          [&](const auto& value) { return value.sessionUUID == ack.sessionUUID &&
              ack.leaseGeneration <= value.leaseGeneration && value.containerUUID == container->plan.uuid &&
              value.controlGeneration == generation && value.controlPeerUUID == peerUUID; });
    }
    if (pending == cousinSessionLocalPendings.end() ||
        (pending->acknowledged && ack.kind != ProdigyCousinSessionLocalKind::revoke) ||
        !cousinSessionCarrierCurrent(stream, generation, peerUUID)) return;
    String serialized = {}; auto copy = ack;
    if (!BitseryEngine::serialize(serialized, copy) || serialized.size() > ProdigyCousinSessionMaximumBytes) return;
    Message::construct(stream->wBuffer, NeuronTopic::cousinSessionAck, container->plan.uuid, serialized);
    Ring::queueSend(stream);
    if (ack.kind == ProdigyCousinSessionLocalKind::revoke || !ack.success) {
      (void)clearPrivateCousinFlow(*pending);
      if (pending->localHalf == CousinRouteHalf::destination &&
          prodigyCousinSessionUsesPrivateContainerEndpoints(pending->session)) {
        for (auto it = cousinAdmissionInstalled.begin(); it != cousinAdmissionInstalled.end();) {
          if (it->privateContainerUUID != pending->containerUUID || it->sessionUUID != pending->sessionUUID ||
              it->leaseGeneration > pending->leaseGeneration ||
              !prodigyCousinSessionExact(it->privateSession, pending->session)) { ++it; continue; }
          if (!clearCousinAdmissionGrant(*it))
            basics_log("neuron private session failure cleanup deferred to bounded kernel expiry\n");
          it = cousinAdmissionInstalled.erase(it);
        }
      }
      discardCousinCarrierDeliveries(pending->containerUUID, pending->sessionUUID, pending->carrierGeneration);
      cousinSessionLocalPendings.erase(pending);
    } else pending->acknowledged = true;
  }

  bool installCousinAdmissionCommand(const ProdigyCousinAdmissionCommand& command,
                                     ProdigyCousinAdmissionAck& acknowledgement)
  {
    acknowledgement = {};
    // Every command already carries the immutable destination identity, so
    // even a local resolver/map rejection has a typed, fenceable receipt.
    acknowledgement.sessionUUID = command.session.sessionUUID;
    acknowledgement.leaseGeneration = command.leaseGeneration;
    acknowledgement.containerID = command.session.destination.containerID;
    acknowledgement.wormholeRevision = command.session.destination.wormholeRevision;
    if (prodigyCousinSessionUsesPrivateContainerEndpoints(command.session)) {
      acknowledgement.protocolVersion = ProdigyCousinAdmissionAck::privateContainerVersion;
      return installPrivateCousinAdmissionCommand(command, acknowledgement);
    }
    if (!prodigyCousinAdmissionCommandValid(command) ||
        command.session.transport == ProdigyCousinSessionTransport::reverseCarrier ||
        !switchboard || !tcx_egress_program) return false;
    const uint64_t nowNs = monotonicNowNs();
    // Revocations intentionally carry no lease; their tombstone is immediately
    // authoritative. Active/renewed routes remain capped by the session lease.
    if (nowNs == 0 || (!command.revoke && command.validForMs > ProdigyCousinSessionLeaseMs)) return false;
    const uint64_t lifetimeNs = uint64_t(command.validForMs) * 1000000ULL;
    if (!command.revoke && (lifetimeNs == 0 || UINT64_MAX - nowNs < lifetimeNs)) return false;
    const uint64_t expiresAtNs = command.revoke ? nowNs : nowNs + lifetimeNs;
    const uint64_t pairHi = uint64_t(command.session.sourcePermission.pairUUID >> 64);
    const uint64_t pairLo = uint64_t(command.session.sourcePermission.pairUUID);
    const uint64_t sessionHi = uint64_t(command.session.sessionUUID >> 64);
    const uint64_t sessionLo = uint64_t(command.session.sessionUUID);
    switchboard_pair_admission_route_key routeKey = {pairHi, pairLo, sessionHi, sessionLo};
    switchboard_pair_admission_route_policy route = {};
    route.route_generation = 1; route.root_generation = command.session.rootGeneration;
    route.key_epoch = command.session.keyEpoch; route.expires_at_ns = expiresAtNs;
    route.state = command.revoke ? SWITCHBOARD_PAIR_ADMISSION_ROUTE_REVOKED : SWITCHBOARD_PAIR_ADMISSION_ROUTE_ACTIVE;
    auto existing = std::find_if(cousinAdmissionInstalled.begin(), cousinAdmissionInstalled.end(),
        [&](const auto& value) { return value.sessionUUID == command.session.sessionUUID; });
    if (command.revoke) {
      // A missing local entry is already-expired best-effort revocation. A
      // retained entry accepts its current or a newer cleanup generation.
      if (existing != cousinAdmissionInstalled.end() &&
          (command.leaseGeneration < existing->leaseGeneration ||
           existing->routeKey.pair_uuid_hi != routeKey.pair_uuid_hi || existing->routeKey.pair_uuid_lo != routeKey.pair_uuid_lo ||
           existing->routeKey.route_uuid_hi != routeKey.route_uuid_hi || existing->routeKey.route_uuid_lo != routeKey.route_uuid_lo ||
           existing->rootGeneration != command.session.rootGeneration || existing->keyEpoch != command.session.keyEpoch)) return false;
      if (existing != cousinAdmissionInstalled.end()) {
        if (!clearCousinAdmissionGrant(*existing)) return false;
        cousinAdmissionInstalled.erase(existing);
      } else if (!Container::revokeVerifiedPairAdmissionRoute(tcx_egress_program, routeKey, route)) return false;
      acknowledgement.containerID = command.session.destination.containerID;
      acknowledgement.wormholeRevision = command.session.destination.wormholeRevision;
      acknowledgement.revoked = true; acknowledgement.success = true;
      return true;
    }
    String digest = {};
    if (!prodigyCousinSessionDigest(command.session, digest)) return false;
    if (command.protocolVersion == 2) {
      String sourceBytes = {}, bound = {}; auto address = command.authenticatedSourceAddress;
      if (!BitseryEngine::serialize(sourceBytes, address)) return false;
      bound.append(digest); bound.append(sourceBytes);
      if (!prodigyComputeSHA256Hex(bound, digest)) return false;
    }
    pruneCousinSessionEphemeralState(Time::msSinceBoot());
    existing = std::find_if(cousinAdmissionInstalled.begin(), cousinAdmissionInstalled.end(),
        [&](const auto& value) { return value.sessionUUID == command.session.sessionUUID; });
    if (existing != cousinAdmissionInstalled.end() &&
        (existing->digest != digest || command.leaseGeneration != existing->leaseGeneration + 1)) return false;
    if (existing == cousinAdmissionInstalled.end() && command.leaseGeneration != 1) return false;
    // Never install a kernel route that cannot be represented by the bounded
    // renewal ledger used to preserve BPF_NOEXIST grant semantics.
    if (existing == cousinAdmissionInstalled.end() &&
        cousinAdmissionInstalled.size() >= ProdigyCousinSessionMaximumRecords) return false;
    if (!Container::installVerifiedPairAdmissionRoute(tcx_egress_program, routeKey, route)) return false;
    if (existing == cousinAdmissionInstalled.end()) {
      uint32_t portalSlot = 0, machineFragment = 0; uint8_t target[5] = {};
      if (!switchboard->resolveCousinAdmissionTarget(command.session.destination, portalSlot, target, machineFragment)) {
        switchboard_pair_admission_route_policy revoked = route; revoked.state = SWITCHBOARD_PAIR_ADMISSION_ROUTE_REVOKED;
        (void)Container::revokeVerifiedPairAdmissionRoute(tcx_egress_program, routeKey, revoked);
        return false;
      }
      switchboard_pair_admission_grant_key key = {}; key.portal_slot = portalSlot;
      const auto& sourceAddress = command.protocolVersion == 2 ? command.authenticatedSourceAddress : command.session.sourceAddress;
      std::memcpy(key.flow.srcv6, sourceAddress.v6, sizeof(key.flow.srcv6));
      std::memcpy(key.flow.dstv6, command.session.destination.publicAddress.v6, sizeof(key.flow.dstv6));
      key.flow.port16[0] = htons(command.session.sourceTCPPort);
      key.flow.port16[1] = htons(command.session.destination.publicTCPPort); key.flow.proto = IPPROTO_TCP;
      switchboard_pair_admission_grant grant = {};
      grant.pair_uuid_hi = pairHi; grant.pair_uuid_lo = pairLo; grant.route_uuid_hi = sessionHi; grant.route_uuid_lo = sessionLo;
      grant.route_generation = 1; grant.root_generation = command.session.rootGeneration; grant.key_epoch = command.session.keyEpoch;
      grant.expires_at_ns = expiresAtNs; std::memcpy(grant.target_container, target, sizeof(target));
      grant.target_machine_fragment = machineFragment; grant.state = SWITCHBOARD_PAIR_ADMISSION_PENDING;
      if (!Container::installVerifiedPairAdmissionGrant(tcx_egress_program, key, grant)) {
        // The route is otherwise an untracked partial application.  Fail closed
        // immediately; the revoked policy leaves no usable admission route.
        switchboard_pair_admission_route_policy revoked = route;
        revoked.state = SWITCHBOARD_PAIR_ADMISSION_ROUTE_REVOKED;
        (void)Container::revokeVerifiedPairAdmissionRoute(tcx_egress_program, routeKey, revoked);
        return false;
      }
      cousinAdmissionInstalled.push_back({command.session.sessionUUID, command.leaseGeneration,
          command.session.destination.containerID, command.session.destination.wormholeRevision, routeKey, key,
          command.session.rootGeneration, command.session.keyEpoch, std::move(digest),
          Time::msSinceBoot() + command.validForMs});
    } else { existing->leaseGeneration = command.leaseGeneration; existing->expiresAtMs = Time::msSinceBoot() + command.validForMs; }
    acknowledgement.containerID = command.session.destination.containerID;
    acknowledgement.wormholeRevision = command.session.destination.wormholeRevision;
    acknowledgement.success = true;
    return true;
  }

  bool installPrivateCousinAdmissionCommand(const ProdigyCousinAdmissionCommand& command,
                                             ProdigyCousinAdmissionAck& acknowledgement)
  {
    if (!prodigyCousinAdmissionCommandValid(command) ||
        !prodigyCousinSessionUsesPrivateContainerEndpoints(command.session)) return false;
    auto container = containers.find(command.session.destination.containerUUID);
    if (container == containers.end() || !container->second || !streamIsActive(container->second) ||
        !privateCousinEndpointMatchesContainer(command.session, CousinRouteHalf::destination,
                                               *container->second, !command.revoke))
      return false;
    auto existing = std::find_if(cousinAdmissionInstalled.begin(), cousinAdmissionInstalled.end(),
        [&](const auto& value) { return value.sessionUUID == command.session.sessionUUID; });
    if (existing != cousinAdmissionInstalled.end() &&
        (existing->privateContainerUUID != container->first ||
         !prodigyCousinSessionExact(existing->privateSession, command.session) ||
         (command.revoke ? command.leaseGeneration < existing->leaseGeneration :
                          command.leaseGeneration != existing->leaseGeneration + 1))) return false;
    if (existing == cousinAdmissionInstalled.end() && !command.revoke &&
        (command.leaseGeneration != 1 || cousinAdmissionInstalled.size() >= ProdigyCousinSessionMaximumRecords))
      return false;
    const uint64_t nowNs = monotonicNowNs(), lifetime = uint64_t(command.validForMs) * 1000000ULL;
    if (!nowNs || (!command.revoke && (!lifetime || command.validForMs > ProdigyCousinSessionLeaseMs ||
                                     UINT64_MAX - nowNs < lifetime))) return false;
    if (!container->second->applyPrivateSessionTCPFlow(command.session, CousinRouteHalf::destination,
                                                      command.revoke ? 0 : nowNs + lifetime, command.revoke))
      return false;
    if (command.revoke) {
      if (existing != cousinAdmissionInstalled.end()) cousinAdmissionInstalled.erase(existing);
      acknowledgement.revoked = true; acknowledgement.success = true; return true;
    }
    CousinAdmissionInstalled installed = {};
    installed.sessionUUID = command.session.sessionUUID; installed.leaseGeneration = command.leaseGeneration;
    installed.destinationContainerID = command.session.destination.containerID;
    installed.destinationWormholeRevision = command.session.destination.wormholeRevision;
    installed.rootGeneration = command.session.rootGeneration; installed.keyEpoch = command.session.keyEpoch;
    installed.expiresAtMs = Time::msSinceBoot() + command.validForMs;
    installed.privateContainerUUID = container->first; installed.privateSession = command.session;
    if (existing == cousinAdmissionInstalled.end()) cousinAdmissionInstalled.push_back(std::move(installed));
    else *existing = std::move(installed);
    acknowledgement.success = true;
    return true;
  }

  virtual bool persistClusterPairControlProjection(
      const ProdigyLocalClusterPairControlProjection&, uint128_t peerUUID, std::function<void(bool)> completion)
  { (void)peerUUID; (void)completion; return false; }

  void forwardClusterPairEpochStatus(const ProdigyClusterPairEpochReceipt& receipt)
  {
    NeuronBrainControlStream *stream = brain;
    const uint64_t generation = stream ? stream->ioGeneration : 0;
    const uint128_t peerUUID = stream ? stream->tlsPeerUUID : 0;
    const bool credentialMatches = std::any_of(clusterPairControlProjection.credentials.begin(),
        clusterPairControlProjection.credentials.end(), [&](const auto& credential) {
          return credential.pairUUID == receipt.status.pairUUID &&
              credential.rootGeneration == receipt.status.rootGeneration && credential.keyEpoch == receipt.wireEpoch &&
              ((clusterPairControlEndpointEquals(credential.initiator, receipt.localEndpoint) &&
                clusterPairControlEndpointEquals(credential.responder, receipt.remoteEndpoint)) ||
               (clusterPairControlEndpointEquals(credential.responder, receipt.localEndpoint) &&
                clusterPairControlEndpointEquals(credential.initiator, receipt.remoteEndpoint)));
        });
    if (!pairControlRuntime || !prodigyLocalClusterPairControlProjectionValid(clusterPairControlProjection, true) ||
        receipt.projectionGeneration != clusterPairControlProjection.committedAuthorityGeneration ||
        receipt.localEndpoint.clusterUUID != clusterPairControlProjection.localClusterUUID ||
        receipt.localEndpoint.nodeUUID != clusterPairControlProjection.nodeUUID ||
        receipt.status.sourceClusterUUID != receipt.remoteEndpoint.clusterUUID ||
        receipt.status.peerClusterUUID != receipt.localEndpoint.clusterUUID ||
        !prodigyClusterPairEpochStatusAllowsWireEpoch(receipt.status, receipt.wireEpoch) ||
        !prodigyClusterPairEpochStatusValid(receipt.status) || !credentialMatches ||
        !controlPeerCurrentlyAuthorized(peerUUID) ||
        !transportPeerProjectionControlCurrent(stream, generation, peerUUID)) return;
    // Epoch status is periodic carrier evidence.  Do not let a delayed Brain
    // control stream retain an unbounded duplicate queue; the carrier emits it
    // again after the existing bounded interval.
    if (stream->wBuffer.outstandingBytes() > 8192) return;
    String serialized = {};
    BitseryEngine::serialize(serialized, receipt);
    if (serialized.size() > 2048) return;
    Message::construct(stream->wBuffer, NeuronTopic::clusterPairEpochStatus, serialized);
    Ring::queueSend(stream);
  }

  bool discoverySnapshotMatchesCurrentProjection(const ProdigyCousinDiscoverySnapshot& snapshot) const
  {
    if (snapshot.sourceClusterUUID != clusterPairControlProjection.localClusterUUID) return false;
    return std::any_of(clusterPairControlProjection.credentials.begin(), clusterPairControlProjection.credentials.end(),
        [&](const auto& credential) {
          const bool endpointClustersMatch =
              (credential.initiator.clusterUUID == snapshot.sourceClusterUUID &&
               credential.responder.clusterUUID == snapshot.peerClusterUUID) ||
              (credential.responder.clusterUUID == snapshot.sourceClusterUUID &&
               credential.initiator.clusterUUID == snapshot.peerClusterUUID);
          return credential.pairUUID == snapshot.pairUUID && credential.rootGeneration == snapshot.rootGeneration &&
              credential.keyEpoch == snapshot.keyEpoch && endpointClustersMatch;
        });
  }

  void forwardCousinDiscoveryReceipt(const ProdigyCousinDiscoveryReceipt& receipt)
  {
    NeuronBrainControlStream *stream = brain;
    const uint64_t generation = stream ? stream->ioGeneration : 0;
    const uint128_t peerUUID = stream ? stream->tlsPeerUUID : 0;
    const bool credentialMatches = std::any_of(clusterPairControlProjection.credentials.begin(),
        clusterPairControlProjection.credentials.end(), [&](const auto& credential) {
          return credential.pairUUID == receipt.snapshot.pairUUID &&
              credential.rootGeneration == receipt.snapshot.rootGeneration && credential.keyEpoch == receipt.wireEpoch &&
              ((clusterPairControlEndpointEquals(credential.initiator, receipt.localEndpoint) &&
                clusterPairControlEndpointEquals(credential.responder, receipt.remoteEndpoint)) ||
               (clusterPairControlEndpointEquals(credential.responder, receipt.localEndpoint) &&
                clusterPairControlEndpointEquals(credential.initiator, receipt.remoteEndpoint)));
        });
    if (!pairControlRuntime || !prodigyLocalClusterPairControlProjectionValid(clusterPairControlProjection, true) ||
        !prodigyCousinDiscoveryReceiptValid(receipt) ||
        receipt.projectionGeneration != clusterPairControlProjection.committedAuthorityGeneration ||
        receipt.localEndpoint.clusterUUID != clusterPairControlProjection.localClusterUUID ||
        receipt.localEndpoint.nodeUUID != clusterPairControlProjection.nodeUUID ||
        receipt.snapshot.sourceClusterUUID != receipt.remoteEndpoint.clusterUUID ||
        receipt.snapshot.peerClusterUUID != receipt.localEndpoint.clusterUUID || !credentialMatches ||
        !controlPeerCurrentlyAuthorized(peerUUID) ||
        !transportPeerProjectionControlCurrent(stream, generation, peerUUID)) return;
    // Bound queued observations. Live snapshots repeat; if a one-shot close
    // is dropped, Brain's independent receipt expiry still removes the view.
    if (stream->pendingSend || stream->wBuffer.outstandingBytes() != 0) return;
    String serialized = {};
    BitseryEngine::serialize(serialized, receipt);
    if (serialized.size() > ProdigyCousinDiscoveryMaximumBytes) return;
    Message::construct(stream->wBuffer, NeuronTopic::cousinDiscoveryReceipt, serialized);
    Ring::queueSend(stream);
  }

  bool controlPeerAuthorizedByBootstrap(uint128_t peerUUID, const ProdigyTransportCredentialBootstrap& bootstrap) const
  {
    const bool hasBrain = brain != nullptr;
    const bool tlsPeerMatchesStream = hasBrain && brain->tlsPeerUUID == peerUUID;
    const bool enrollmentAuthorized = tlsPeerMatchesStream &&
        bootstrap.currentlyAuthorizes(peerUUID, ProdigyTransportCredentialNodeRole::brain);
    if (!enrollmentAuthorized)
    {
      PRODIGY_DEBUG_LOG(
          "neuron brain credential-authorize reject reason=stream-or-enrollment hasBrain=%d peerMatchesStream=%d bootstrapEnabled=%d selfValid=%d enrollmentAuthorized=%d peerCount=%u\n",
          int(hasBrain), int(tlsPeerMatchesStream), int(bootstrap.enabled), int(bootstrap.self.valid()),
          int(enrollmentAuthorized), unsigned(bootstrap.authorizedPeers.size()));
      PRODIGY_DEBUG_FLUSH();
      return false;
    }
    const String *localBytes = nullptr, *peerBytes = nullptr;
    ProdigyTransportCredentialPrelude local, peer;
    const auto& self = bootstrap.self;
    const bool authenticatedPreludes = brain->authenticatedTransportAEGISPreludes(localBytes, peerBytes);
    const bool localParsed = authenticatedPreludes && localBytes != nullptr &&
        prodigyParseTransportCredentialPrelude(*localBytes, local);
    const bool localMatchesSelf = localParsed && local.operationUUID == self.operationUUID &&
        local.nodeUUID == self.nodeUUID && local.role == self.role &&
        local.authorityEpoch == self.authorityEpoch && local.keyEpoch == self.keyEpoch &&
        local.authorityGeneration == self.authorityGeneration;
    const bool peerParsed = authenticatedPreludes && peerBytes != nullptr &&
        prodigyParseTransportCredentialPrelude(*peerBytes, peer);
    const bool preludePeerMatchesStream = peerParsed && peer.nodeUUID == peerUUID &&
        peer.role == ProdigyTransportCredentialNodeRole::brain;
    const uint32_t peerEnrollmentMatches = localMatchesSelf && preludePeerMatchesStream ? uint32_t(std::count_if(bootstrap.authorizedPeers.begin(),
        bootstrap.authorizedPeers.end(), [&](const auto& entry) {
          return prodigyTransportCredentialPreludeMatches(peer, entry);
        })) : 0;
    const bool authorized = localMatchesSelf && preludePeerMatchesStream && peerEnrollmentMatches == 1;
    if (!authorized)
    {
      PRODIGY_DEBUG_LOG(
          "neuron brain credential-authorize reject reason=prelude authenticated=%d localBytes=%d peerBytes=%d localParsed=%d localMatchesSelf=%d peerParsed=%d peerMatchesStream=%d peerEnrollmentMatches=%u selfRole=%u localRole=%u peerRole=%u selfAuthorityEpoch=%llu localAuthorityEpoch=%llu selfKeyEpoch=%llu localKeyEpoch=%llu selfAuthorityGeneration=%llu localAuthorityGeneration=%llu\n",
          int(authenticatedPreludes), int(localBytes != nullptr), int(peerBytes != nullptr), int(localParsed),
          int(localMatchesSelf), int(peerParsed), int(preludePeerMatchesStream), unsigned(peerEnrollmentMatches),
          unsigned(self.role), unsigned(local.role), unsigned(peer.role),
          (unsigned long long)self.authorityEpoch, (unsigned long long)local.authorityEpoch,
          (unsigned long long)self.keyEpoch, (unsigned long long)local.keyEpoch,
          (unsigned long long)self.authorityGeneration, (unsigned long long)local.authorityGeneration);
      PRODIGY_DEBUG_FLUSH();
    }
    return authorized;
  }

  bool controlPeerCurrentlyAuthorized(uint128_t peerUUID) const
  {
    return controlPeerAuthorizedByBootstrap(peerUUID, controlTransportCredentials);
  }

  bool transportLifecycleControlAuthorized(uint128_t peerUUID) const
  {
    return controlPeerCurrentlyAuthorized(peerUUID) ||
        (brain && brain->transportLifecycleCandidate &&
         controlTransportCredentialLifecycleProjection.protocolVersion == 1 &&
         (controlTransportCredentialLifecycleProjection.operation.lifecycleKind == ProdigyTransportCredentialLifecycleKind::rotate ||
          controlTransportCredentialLifecycleProjection.operation.predecessor.role == ProdigyTransportCredentialNodeRole::brain) &&
         uint8_t(controlTransportCredentialLifecycleProjection.operation.lifecyclePhase) < uint8_t(ProdigyTransportCredentialLifecyclePhase::active) &&
         controlPeerAuthorizedByBootstrap(peerUUID, controlTransportCredentialLifecycleProjection.target));
  }

  void receiveCousinDiscoverySnapshot(const ProdigyCousinDiscoveryPublication& publication)
  {
    NeuronBrainControlStream *stream = brain;
    const uint64_t generation = stream ? stream->ioGeneration : 0;
    const uint128_t peerUUID = stream ? stream->tlsPeerUUID : 0;
    if (!controlTransportCredentials.enabled || !pairControlRuntime ||
        !prodigyLocalClusterPairControlProjectionValid(clusterPairControlProjection, true) ||
        !prodigyCousinDiscoveryPublicationValid(publication) ||
        publication.nodeUUID != controlTransportCredentials.self.nodeUUID ||
        publication.projectionGeneration != clusterPairControlProjection.committedAuthorityGeneration ||
        publication.snapshot.sourceClusterUUID != clusterPairControlProjection.localClusterUUID ||
        !discoverySnapshotMatchesCurrentProjection(publication.snapshot) ||
        !controlPeerCurrentlyAuthorized(peerUUID) ||
        !transportPeerProjectionControlCurrent(stream, generation, peerUUID)) return;
    // The carrier owns the bounded replacement cache and its six-second
    // expiry.  This path adds no persistence or independent lifecycle.
    (void)pairControlRuntime->installDiscoverySnapshot(publication);
  }

  virtual bool persistTransportCredentialPeerProjection(
      const ProdigyTransportCredentialBootstrap&, std::function<void(bool)> completion)
  {
    (void)completion;
    return false;
  }

  bool transportPeerProjectionControlCurrent(NeuronBrainControlStream *stream, uint64_t generation,
                                             uint128_t peerUUID) const
  {
    return brain == stream && stream != nullptr && stream->ioGeneration == generation &&
        streamIsActive(stream) && stream->transportAEGISEnabled() && stream->isTransportNegotiated() &&
        stream->tlsPeerVerified && stream->tlsPeerUUID == peerUUID;
  }

  void receiveTransportCredentialPeerProjection(uint128_t nonce,
                                                const ProdigyTransportCredentialBootstrap& projection)
  {
    NeuronBrainControlStream *stream = brain;
    const uint64_t generation = stream ? stream->ioGeneration : 0;
    const uint128_t peerUUID = stream ? stream->tlsPeerUUID : 0;
    if (nonce == 0 || !controlTransportCredentials.enabled || !controlPeerCurrentlyAuthorized(peerUUID) ||
        !transportPeerProjectionControlCurrent(stream, generation, peerUUID)) return;
    ProdigyTransportCredentialBootstrap updated = {};
    if (!prodigyApplyTransportCredentialPeerProjection(controlTransportCredentials, projection, updated) ||
        std::none_of(projection.authorizedPeers.begin(), projection.authorizedPeers.end(), [&](const auto& peer) {
          return peer.nodeUUID == peerUUID && peer.role == ProdigyTransportCredentialNodeRole::brain;
        }))
    { queueCloseIfActive(stream); return; }
    auto reply = [this, stream, nonce, revision = projection.committedAuthorityGeneration](bool ready) {
      Message::construct(stream->wBuffer, NeuronTopic::transportCredentialPeersAck, nonce, revision, uint8_t(ready));
      Ring::queueSend(stream);
    };
    if (transportPeerProjectionPersistencePending) { reply(false); return; }
    transportPeerProjectionPersistencePending = true;
    const std::weak_ptr<uint8_t> lifetime = asyncOperationLifetime;
    const std::weak_ptr<uint8_t> connectionLifetime = stream->connectionLifetime;
    const bool admitted = persistTransportCredentialPeerProjection(projection,
        [this, lifetime, connectionLifetime, stream, generation, peerUUID, updated = std::move(updated), reply](bool durable) mutable {
          if (lifetime.expired()) return;
          transportPeerProjectionPersistencePending = false;
          if (connectionLifetime.expired() || !transportPeerProjectionControlCurrent(stream, generation, peerUUID) ||
              !controlPeerCurrentlyAuthorized(peerUUID)) return;
          if (!durable) { reply(false); return; }
          // The live receiver still owns this exact stream and credential
          // identity. Publish only after the sole local-record owner commits.
          controlTransportCredentials = std::move(updated);
          std::fprintf(stderr, "neuron transport peer projection durable uuid=%llu generation=%llu peers=%zu\n",
                     (unsigned long long)controlTransportCredentials.self.nodeUUID,
                     (unsigned long long)controlTransportCredentials.committedAuthorityGeneration,
                     size_t(controlTransportCredentials.authorizedPeers.size()));
          std::fflush(stderr);
          reply(true);
        });
    if (!admitted) { transportPeerProjectionPersistencePending = false; reply(false); }
  }

  virtual bool persistTransportCredentialLifecycleProjection(
      const ProdigyTransportCredentialLifecycleProjection&, std::function<void(bool)> completion)
  {
    (void)completion;
    return false;
  }

  bool prepareTransportCredentialLifecycleProjection(
      const ProdigyTransportCredentialLifecycleProjection& projection,
      ProdigyTransportCredentialBootstrap& updated, bool& revoked) const
  {
    ProdigyPersistentLocalBrainState local;
    local.uuid = controlTransportCredentials.self.nodeUUID;
    local.ownerClusterUUID = controlTransportCredentials.self.clusterUUID;
    local.transportCredentials = controlTransportCredentials;
    local.transportCredentialLifecycleProjection = controlTransportCredentialLifecycleProjection;
    return prodigyApplyLocalTransportCredentialLifecycleProjection(local, projection, updated, revoked);
  }

  void receiveTransportCredentialLifecycleProjection(uint128_t nonce,
      const ProdigyTransportCredentialLifecycleProjection& projection)
  {
    auto *stream = brain;
    const uint64_t generation = stream ? stream->ioGeneration : 0;
    const uint128_t peerUUID = stream ? stream->tlsPeerUUID : 0;
    if (nonce == 0 || !controlTransportCredentials.enabled ||
        !transportPeerProjectionControlCurrent(stream, generation, peerUUID) ||
        !transportLifecycleControlAuthorized(peerUUID)) return;
    ProdigyTransportCredentialBootstrap updated;
    bool revoked = false;
    if (!prepareTransportCredentialLifecycleProjection(projection, updated, revoked))
    { queueCloseIfActive(stream); return; }
    auto reply = [this, stream, nonce, revision = projection.committedAuthorityGeneration](bool accepted) {
      Message::construct(stream->wBuffer, NeuronTopic::transportCredentialLifecycleAck, nonce, revision, uint8_t(accepted));
      Ring::queueSend(stream);
    };
    if (transportPeerProjectionPersistencePending) { reply(false); return; }
    transportPeerProjectionPersistencePending = true;
    const std::weak_ptr<uint8_t> lifetime = asyncOperationLifetime;
    const std::weak_ptr<uint8_t> connectionLifetime = stream->connectionLifetime;
    const bool admitted = persistTransportCredentialLifecycleProjection(projection,
        [this, lifetime, connectionLifetime, stream, generation, peerUUID, projection, reply](bool durable) mutable {
          if (lifetime.expired()) return;
          transportPeerProjectionPersistencePending = false;
          if (connectionLifetime.expired() || !transportPeerProjectionControlCurrent(stream, generation, peerUUID) ||
              !transportLifecycleControlAuthorized(peerUUID)) return;
          ProdigyTransportCredentialBootstrap updated;
          bool revoked = false;
          if (!durable || !prepareTransportCredentialLifecycleProjection(projection, updated, revoked))
          { reply(false); return; }
          controlTransportCredentialLifecycleProjection = projection;
          if (revoked)
          {
            OPENSSL_cleanse(controlTransportCredentials.self.secret, sizeof(controlTransportCredentials.self.secret));
            controlTransportCredentials.committedAuthorityGeneration = projection.committedAuthorityGeneration;
          }
          else controlTransportCredentials = std::move(updated);
          const bool activated = uint8_t(projection.operation.lifecyclePhase) >= uint8_t(ProdigyTransportCredentialLifecyclePhase::active);
          if (activated)
          {
            // Flush this exact receipt before retiring its old session.
            stream->closeAfterTransportLifecycleAck = revoked || !controlPeerCurrentlyAuthorized(peerUUID);
            if (!stream->closeAfterTransportLifecycleAck) stream->transportLifecycleCandidate = false;
            tryStagedTransportCredentialOnNextAccept = false;
          }
          std::fprintf(stderr, "transport lifecycle local-durable node=%016llx%016llx operation=%016llx%016llx phase=%u generation=%llu revoked=%u\n",
              (unsigned long long)(uuid >> 64), (unsigned long long)uuid,
              (unsigned long long)(projection.operation.lifecycleOperationUUID >> 64),
              (unsigned long long)projection.operation.lifecycleOperationUUID,
              unsigned(projection.operation.lifecyclePhase), (unsigned long long)projection.committedAuthorityGeneration,
              unsigned(revoked));
          reply(true);
        });
    if (!admitted) { transportPeerProjectionPersistencePending = false; reply(false); }
  }

  void receiveClusterPairControlProjection(uint128_t nonce,
                                           const ProdigyLocalClusterPairControlProjection& projection)
  {
    NeuronBrainControlStream *stream = brain;
    const uint64_t generation = stream ? stream->ioGeneration : 0;
    const uint128_t peerUUID = stream ? stream->tlsPeerUUID : 0;
    if (nonce == 0 || !controlTransportCredentials.enabled ||
        projection.localClusterUUID != controlTransportCredentials.self.clusterUUID ||
        projection.nodeUUID != controlTransportCredentials.self.nodeUUID ||
        !controlPeerCurrentlyAuthorized(peerUUID) ||
        !prodigyLocalClusterPairControlProjectionValid(projection, true) ||
        !transportPeerProjectionControlCurrent(stream, generation, peerUUID)) return;
    auto reply = [this, stream, generation, peerUUID, nonce, committed = projection.committedAuthorityGeneration](bool accepted) {
      if (!transportPeerProjectionControlCurrent(stream, generation, peerUUID)) return;
      Message::construct(stream->wBuffer, NeuronTopic::clusterPairControlCredentialsAck, nonce, committed, uint8_t(accepted));
      Ring::queueSend(stream);
    };
    if (clusterPairControlProjectionPersistencePending) { reply(false); return; }
    clusterPairControlProjectionPersistencePending = true;
    const std::weak_ptr<uint8_t> lifetime = asyncOperationLifetime;
    const std::weak_ptr<uint8_t> connectionLifetime = stream->connectionLifetime;
    const bool admitted = persistClusterPairControlProjection(projection, peerUUID,
      [this, lifetime, connectionLifetime, stream, generation, peerUUID, projection, reply](bool durable) mutable {
        if (lifetime.expired()) return;
        clusterPairControlProjectionPersistencePending = false;
        if (connectionLifetime.expired() || !transportPeerProjectionControlCurrent(stream, generation, peerUUID) ||
            !controlPeerCurrentlyAuthorized(peerUUID)) return;
        if (!durable || !installClusterPairControlProjection(projection)) { reply(false); return; }
        clusterPairControlProjection = projection;
        reply(true);
      });
    if (!admitted) { clusterPairControlProjectionPersistencePending = false; reply(false); }
  }
  bytell_hash_set<NeuronBrainControlStream *> closingBrainControls;
  OSUpdateProcess osUpdateProcess;

  ~Neuron()
  {
    asyncOperationLifetime.reset();
    bgpConfigurationRefresh.reset();
    // Cancel HostTask awaiters before their retained containers or this Ring
    // owner can be destroyed. Late Netlink/command callbacks then observe a
    // detached operation instead of this Neuron.
    pendingStateUploadRestores.clear();
    artifactIO.reset();
    if (wormholeFlowGC)
    {
      WormholeFlowGC *gc = wormholeFlowGC;
      wormholeFlowGC = nullptr;
      gc->stop();
    }
    detachAdditionalIngressForShutdown();
  }

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
      (void)::dup2(nullFD, STDIN_FILENO);
      if (nullFD > STDERR_FILENO)
      {
        (void)syscall(SYS_close, nullFD);
      }
    }

    int logFD = openOSUpdateChildFile("/var/log/prodigy/os-update.log", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (logFD >= 0)
    {
      (void)::dup2(logFD, STDOUT_FILENO);
      (void)::dup2(logFD, STDERR_FILENO);
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

  virtual void startOperatingSystemUpdateAsync(String targetOSID, String targetOSVersionID,
                                               String updateCommand,
                                               std::function<void(bool, String)> completion)
  {
    String failure;
    const bool started = startOperatingSystemUpdate(targetOSID, targetOSVersionID, updateCommand, &failure);
    completion(started, std::move(failure));
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

    PRODIGY_DEBUG_LOG(
                 "neuron updateOS started targetOSID=%s targetOSVersionID=%s launcherPid=%lld pidfd=%d\n",
                 targetOSIDText.c_str(),
                 targetOSVersionIDText.c_str(),
                 (long long)pid,
                 osUpdateProcess.fd);
    PRODIGY_DEBUG_FLUSH();
    basics_log("neuron updateOS started targetOSID=%s targetOSVersionID=%s launcherPid=%lld pidfd=%d\n",
               targetOSIDText.c_str(),
               targetOSVersionIDText.c_str(),
               (long long)pid,
               osUpdateProcess.fd);
    return true;
  }

  virtual void boot(CoroutineStack *coro)
  {
    loadKernelVersion();
    loadOSReleaseMetadata();
    loadTaskAttemptJournal();
    bootTimeMs = registrationBootTimeMs();

    private4.is6 = false;

    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          iaas->gatherSelfData(coro, uuid, metro, isBrain, eth, private4);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }

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
    artifactIO = ProdigyArtifactIO::startOwned();
    if (artifactIO == nullptr)
    {
      std::fprintf(stderr, "neuron artifact I/O worker unavailable\n");
    }
    Ring::installFDIntoFixedFileSlot(&brainListener);
    deferredHardwareInventoryWake.fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (deferredHardwareInventoryWake.fd < 0)
    {
      PRODIGY_DEBUG_LOG( "prodigy deferred hardware wake eventfd failed errno=%d(%s)\n", errno, strerror(errno));
      std::abort();
    }
    deferredHardwareInventoryWake.setNonBlocking();
    // The detached collector thread signals this eventfd via process-fd write(),
    // so it must retain a live process fd instead of being relinquished into a
    // fixed-file-only slot.
    RingDispatcher::installMultiplexee(&deferredHardwareInventoryWake, this);
    armDeferredHardwareInventoryWakePoll();
    queueBrainAccept();
    if (!startClusterPairControlRuntime())
    {
      std::fprintf(stderr, "neuron pair control initialization failed\n");
      std::abort();
    }
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

  void rawFDPollHandler(void *owner, uint64_t generation, uint64_t ticket, int result) override
  {
    Container *container = reinterpret_cast<Container *>(owner);
    if (ContainerManager::completeNonChildPidfdPoll(container, generation, ticket, result) == false)
    {
      return;
    }
    waitidHandler(container);
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
    bool pidfdExitStatusUnknown = container->pidfdExitStatusUnknown;
    bool nonRestartableStartupFailure = (pidfdExitStatusUnknown == false && infop.si_code == CLD_EXITED && infop.si_status == containerStartupFailureExitCode);
    String containerName = container->name;
    {
      containerUUID = container->plan.uuid;
      pendingDestroyBeforeWait = container->pendingDestroy;
      container->waitidPending = false;
      container->pidfdExitStatusUnknown = false;
      if (container->pidfd > 0)
      {
        close(container->pidfd);
        container->pidfd = -1;
      }
      container->disableKillSwitch();
      killedOnPurpose = container->killedOnPurpose;

      resumeAfterShutdown = container->resumeAfterShutdown;
      destroyAfterWait = (killedOnPurpose || container->plan.restartOnFailure == false || nonRestartableStartupFailure);
    }

    bool restart = (destroyAfterWait == false);
    if (restart)
    {
      (void)retireContainerControlBeforeRestart(container);
    }
    else
    {
      container->closeSocket();
    }

    PRODIGY_DEBUG_LOG(
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
    PRODIGY_DEBUG_FLUSH();

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
      if (container->failedArtifactsObservedAtMs <= 0)
      {
        container->failedArtifactsObservedAtMs = failureTimeMs;
      }
      failureTimeMs = container->failedArtifactsObservedAtMs;
    }

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
      else if (pidfdExitStatusUnknown)
      {
        termination.kind = TaskTerminationKind::lost;
        termination.summary.assign("retained process exited; exit status unavailable"_ctv);
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

      if (pidfdExitStatusUnknown)
      {
        crashReport.assign("retained process exited; exit status unavailable"_ctv);
      }
      else if (infop.si_code != CLD_EXITED) // child DID NOT exit via exit()... but by some crash
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

      ContainerLogsOperation outputLogs = {};
      outputLogs.applicationID = container->plan.config.applicationID;
      outputLogs.containerUUID = containerUUID;
      outputLogs.maximumBytes = 8192;
      outputLogs.includeFailed = false;
      String stderrTail = {};
      if (ContainerManager::collectContainerLogs(outputLogs) && outputLogs.entries.size() == 1)
      {
        stderrTail.assign(outputLogs.entries.front().standardError);
      }

      crashReport = ContainerManager::boundedFailureReport(infop, terminalSignal, crashReport, stderrTail);

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
        scheduleFailedContainerRestart(container, failureTimeMs);
      }
      else
      {
        ContainerManager::destroyContainer(container, ContainerManager::DestroyCause::processFailure);
      }
    }
    else if (resumeAfterShutdown)
    {
      // The replacement coroutine owns quiesced storage capture before resource
      // teardown can unmount storage or delete the original artifact root.
      container->resumeAfterShutdown = nullptr;
      resumeAfterShutdown->co_consume();
      return; // The resumed owner may already have destroyed this container.
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
          PRODIGY_DEBUG_LOG(
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
          PRODIGY_DEBUG_FLUSH();

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
            if (verboseNeuronSocketLogsEnabled())
            {
              PRODIGY_DEBUG_LOG(
                           "neuron containerHealthy forward-begin uuid=%llu brain=%p active=%d pendingSend=%d pendingRecv=%d wbytes=%u queued=%llu fd=%d fslot=%d\n",
                           (unsigned long long)container->plan.uuid,
                           static_cast<void *>(brain),
                           int(controllingBrainActive),
                           int(brain->pendingSend),
                           int(brain->pendingRecv),
                           unsigned(brain->wBuffer.outstandingBytes()),
                           (unsigned long long)brain->queuedSendOutstandingBytes(),
                           brain->fd,
                           brain->fslot);
              PRODIGY_DEBUG_FLUSH();
            }
            Message::construct(brain->wBuffer, NeuronTopic::containerHealthy, container->plan.uuid);
            if (verboseNeuronSocketLogsEnabled())
            {
              PRODIGY_DEBUG_LOG(
                           "neuron containerHealthy forward-constructed uuid=%llu pendingSend=%d wbytes=%u queued=%llu fd=%d fslot=%d\n",
                           (unsigned long long)container->plan.uuid,
                           int(brain->pendingSend),
                           unsigned(brain->wBuffer.outstandingBytes()),
                           (unsigned long long)brain->queuedSendOutstandingBytes(),
                           brain->fd,
                           brain->fslot);
              PRODIGY_DEBUG_FLUSH();
            }
            if (controllingBrainActive)
            {
              Ring::queueSend(brain);
              if (verboseNeuronSocketLogsEnabled())
              {
                PRODIGY_DEBUG_LOG(
                             "neuron containerHealthy forward-queued uuid=%llu pendingSend=%d pendingSendBytes=%u wbytes=%u queued=%llu fd=%d fslot=%d\n",
                             (unsigned long long)container->plan.uuid,
                             int(brain->pendingSend),
                             unsigned(brain->pendingSendBytes),
                             unsigned(brain->wBuffer.outstandingBytes()),
                             (unsigned long long)brain->queuedSendOutstandingBytes(),
                             brain->fd,
                             brain->fslot);
                PRODIGY_DEBUG_FLUSH();
              }
            }
            else if (verboseNeuronSocketLogsEnabled())
            {
              PRODIGY_DEBUG_LOG(
                           "neuron containerHealthy forward-buffered uuid=%llu pendingSend=%d wbytes=%u queued=%llu fd=%d fslot=%d\n",
                           (unsigned long long)container->plan.uuid,
                           int(brain->pendingSend),
                           unsigned(brain->wBuffer.outstandingBytes()),
                           (unsigned long long)brain->queuedSendOutstandingBytes(),
                           brain->fd,
                           brain->fslot);
              PRODIGY_DEBUG_FLUSH();
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
      case ContainerTopic::nametagQualificationSeedFault:
        {
          String encoded = {}; Message::extractToStringView(args, encoded);
          ProdigyNametagQualificationSeedFault witness = {};
          NeuronBrainControlStream *stream = brain;
          if (args != terminal || !stream || !BitseryEngine::deserializeSafe(encoded, witness) ||
              !witness.response || !prodigyNametagQualificationSeedFaultValid(witness) ||
              witness.deadlineAtMilliseconds <= Time::now<TimeResolution::ms>() ||
              witness.authority.targetContainerUUID != container->plan.uuid ||
              witness.authority.targetDeploymentID != container->plan.config.deploymentID() ||
              witness.authority.targetClusterUUID != controlTransportCredentials.self.clusterUUID ||
              witness.authority.applicationID != container->plan.config.applicationID ||
              !controlPeerCurrentlyAuthorized(stream->tlsPeerUUID) ||
              !transportPeerProjectionControlCurrent(stream, stream->ioGeneration, stream->tlsPeerUUID)) break;
          Message::construct(stream->wBuffer, NeuronTopic::nametagQualificationSeedFault, container->plan.uuid, encoded);
          if (streamIsActive(stream)) Ring::queueSend(stream);
          break;
        }
      case ContainerTopic::nametagQualificationReplay:
        {
          String encoded = {}; Message::extractToStringView(args, encoded);
          ProdigyNametagQualificationReplay witness = {};
          NeuronBrainControlStream *stream = brain;
          if (args != terminal || !stream || !BitseryEngine::deserializeSafe(encoded, witness) ||
              !witness.response || !prodigyNametagQualificationReplayValid(witness) ||
              !prodigyNametagQualificationReplayRelayTimely(witness, Time::now<TimeResolution::ms>()) ||
              (prodigyNametagQualificationReplayLocalHalf(witness.store, witness.targetSide) == CousinRouteHalf::source ? witness.session.sourceContainerUUID : witness.session.destinationContainerUUID) != container->plan.uuid ||
              (prodigyNametagQualificationReplayLocalHalf(witness.store, witness.targetSide) == CousinRouteHalf::source ? witness.session.sourceDeploymentID : witness.session.destinationDeploymentID) != container->plan.config.deploymentID() ||
              (prodigyNametagQualificationReplayLocalHalf(witness.store, witness.targetSide) == CousinRouteHalf::source ? witness.session.sourceClusterUUID : witness.session.destinationClusterUUID) != controlTransportCredentials.self.clusterUUID ||
              !controlPeerCurrentlyAuthorized(stream->tlsPeerUUID) ||
              !transportPeerProjectionControlCurrent(stream, stream->ioGeneration, stream->tlsPeerUUID)) break;
          Message::construct(stream->wBuffer, NeuronTopic::nametagQualificationReplay, container->plan.uuid, encoded);
          if (streamIsActive(stream)) Ring::queueSend(stream);
          break;
        }
      case ContainerTopic::nametagQualificationCousinTransport:
        {
          String encoded = {}; Message::extractToStringView(args, encoded);
          ProdigyNametagQualificationCousinTransport witness = {};
          NeuronBrainControlStream *stream = brain;
          if (args != terminal || !stream || !BitseryEngine::deserializeSafe(encoded, witness) ||
              !witness.response || !prodigyNametagQualificationCousinTransportValid(witness) ||
              witness.deadlineAtMilliseconds <= Time::now<TimeResolution::ms>() ||
              witness.session.sourceContainerUUID != container->plan.uuid ||
              witness.session.sourceDeploymentID != container->plan.config.deploymentID() ||
              witness.session.sourceClusterUUID != controlTransportCredentials.self.clusterUUID ||
              !controlPeerCurrentlyAuthorized(stream->tlsPeerUUID) ||
              !transportPeerProjectionControlCurrent(stream, stream->ioGeneration, stream->tlsPeerUUID)) break;
          Message::construct(stream->wBuffer, NeuronTopic::nametagQualificationCousinTransport, container->plan.uuid, encoded);
          if (streamIsActive(stream)) Ring::queueSend(stream);
          break;
        }
      case ContainerTopic::statefulStoreSourceCut:
        {
          String encoded = {}; Message::extractToStringView(args, encoded);
          ProdigyStatefulStoreSourceCut cut = {};
          NeuronBrainControlStream *stream = brain;
          if (args != terminal || !stream || !BitseryEngine::deserializeSafe(encoded, cut) ||
              !cut.response || !prodigyStatefulStoreSourceCutValid(cut) ||
              cut.sourceContainerUUID != container->plan.uuid ||
              cut.sourceDeploymentID != container->plan.config.deploymentID() ||
              cut.applicationID != container->plan.config.applicationID ||
              cut.shardGroup != container->plan.shardGroup || cut.nShardGroups != container->plan.nShardGroups ||
              cut.sourceClusterUUID != controlTransportCredentials.self.clusterUUID ||
              !controlPeerCurrentlyAuthorized(stream->tlsPeerUUID) ||
              !transportPeerProjectionControlCurrent(stream, stream->ioGeneration, stream->tlsPeerUUID)) break;
          Message::construct(stream->wBuffer, NeuronTopic::statefulStoreSourceCut, container->plan.uuid, encoded);
          Ring::queueSend(stream);
          break;
        }
      case ContainerTopic::statefulDataAuthority:
        {
          String encoded;
          Message::extractToStringView(args, encoded);
          StatefulDataAuthorityPreparation preparation;
          if (args == terminal && brain && BitseryEngine::deserializeSafe(encoded, preparation) &&
              preparation.response && prodigyStatefulDataAuthorityPreparationValid(preparation)) {
            if (container->plan.config.deploymentID() != preparation.deploymentID ||
                container->plan.config.applicationID != preparation.applicationID ||
                container->plan.shardGroup != preparation.shardGroup || container->plan.nShardGroups != preparation.nShardGroups ||
                !prodigyStatefulDataAuthorityPreparationContextEqual(preparation, container->statefulPreparationRequest)) break;
            Message::construct(brain->wBuffer, NeuronTopic::statefulDataAuthority, container->plan.uuid, encoded);
            Ring::queueSend(brain);
            break;
          }
          StatefulDataAuthorityReceipt receipt;
          if (args != terminal || !brain ||
              !BitseryEngine::deserializeSafe(encoded, receipt) ||
              !prodigyStatefulDataAuthorityReceiptValid(receipt) ||
              container->plan.statefulTopology.servingMode != StatefulTopologyServingMode::applicationDataAuthority ||
              !prodigyStatefulDataAuthorityEqual(receipt.authority, container->plan.statefulTopology.dataAuthority)) break;
          // Container identity comes from the local control socket, never the
          // payload. The Brain rechecks the owning authenticated Neuron.
          Message::construct(brain->wBuffer, NeuronTopic::statefulDataAuthority, container->plan.uuid, encoded);
          Ring::queueSend(brain);
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
          TlsResumptionApplyAck result;
          const bool hasTypedAck = args < terminal &&
                                   ProdigyWire::deserializeTlsResumptionApplyAckFramePayload(args, uint64_t(terminal - args), result);
          if (args < terminal && hasTypedAck == false)
          {
            break;
          }

          const bool controllingBrainActive = brain != nullptr && streamIsActive(brain);
          if (hasTypedAck && thisBrain != nullptr && thisBrain->canControlNeurons())
          {
            // The local master owns this receipt. Keep the one-shot container
            // ACK independent from the replaceable loopback control stream.
            thisBrain->noteLocalContainerTlsResumptionApplyAck(container->plan.uuid, result);
            break;
          }

          if (brain)
          {
            if (hasTypedAck)
            {
              String serializedAck;
              serializedAck.setInvariant(args, uint64_t(terminal - args));
              Message::construct(brain->wBuffer, NeuronTopic::refreshContainerCredentials, container->plan.uuid, serializedAck);
            }
            else
            {
              Message::construct(brain->wBuffer, NeuronTopic::refreshContainerCredentials, container->plan.uuid);
            }
            if (controllingBrainActive)
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
      case ContainerTopic::cousinSessionRequest:
        {
          String serialized = {};
          Message::extractToStringView(args, serialized);
          ProdigyCousinSessionRequest request = {};
          NeuronBrainControlStream *stream = brain;
          const uint64_t generation = stream ? stream->ioGeneration : 0;
          const uint128_t peerUUID = stream ? stream->tlsPeerUUID : 0;
          if (args != terminal || !BitseryEngine::deserializeSafe(serialized, request) ||
              !prodigyCousinSessionRequestValid(request) ||
              cousinSessionSourceWhitehole(*container, request.bindingNonce) == nullptr ||
              !cousinSessionCarrierCurrent(stream, generation, peerUUID) ||
              stream->wBuffer.outstandingBytes() > ProdigyCousinSessionMaximumBytes) break;
          Message::construct(stream->wBuffer, NeuronTopic::cousinSessionRequest, container->plan.uuid, serialized);
          Ring::queueSend(stream);
          break;
        }
      case ContainerTopic::cousinSessionAck:
        {
          String serialized = {};
          Message::extractToStringView(args, serialized);
          ProdigyCousinSessionLocalAck acknowledgement = {};
          if (args == terminal && BitseryEngine::deserializeSafe(serialized, acknowledgement))
            forwardCousinSessionLocalAck(container, acknowledgement);
          break;
        }
      case ContainerTopic::app6TruthMeshReceipt:
        {
          String encoded = {}; Message::extractToStringView(args, encoded);
          ProdigyApp6TruthMeshReceipt receipt = {};
          NeuronBrainControlStream *stream = brain;
          if (args != terminal || !stream || container->plan.config.applicationID != MeshRegistry::Nametag::applicationID ||
              !BitseryEngine::deserializeSafe(encoded, receipt) || !prodigyApp6TruthMeshReceiptValid(receipt) ||
              receipt.localApplicationContainerUUID != container->plan.uuid ||
              receipt.localClusterUUID != controlTransportCredentials.self.clusterUUID ||
              !cousinSessionCarrierCurrent(stream, stream->ioGeneration, stream->tlsPeerUUID)) break;
          Message::construct(stream->wBuffer, NeuronTopic::app6TruthMeshReceipt, encoded);
          Ring::queueSend(stream);
          break;
        }
      case ContainerTopic::globalSingleWriterControl:
        {
          String bytes; Message::extractToStringView(args,bytes);
          ProdigyGlobalSingleWriterControl report{};
          auto* stream = brain;
          const bool localBrainAuthenticated = stream == brain && stream != nullptr && streamIsActive(stream) &&
              (stream->transportEncryptionEnabled() == false ||
               (stream->isTransportNegotiated() && stream->tlsPeerVerified));
          if (args != terminal || !stream || container->pendingDestroy || !prodigyGlobalSingleWriterContainerPlanValid(container->plan) ||
              !BitseryEngine::deserializeSafe(bytes,report) || !prodigyGlobalSingleWriterControlReportValid(report) ||
              report.containerUUID != container->plan.uuid || report.deploymentID != container->plan.config.deploymentID() ||
              report.localClusterUUID != controlTransportCredentials.self.clusterUUID ||
              !localBrainAuthenticated) {
            basics_log("neuron globalSingleWriterControl reject stage=reply-validation member=%d\n", report.memberID);
            break;
          }
          Message::construct(stream->wBuffer,NeuronTopic::globalSingleWriterControl,bytes);
          Ring::queueSend(stream);
          break;
        }
      case ContainerTopic::statefulStoreProofRecovery:
        {
          String encoded = {}; Message::extractToStringView(args, encoded);
          ProdigyStatefulStoreProofRecovery response = {};
          NeuronBrainControlStream *stream = brain;
          if (args != terminal || !stream || !BitseryEngine::deserializeSafe(encoded, response) ||
              !response.response || !prodigyStatefulStoreProofRecoveryValid(response) ||
              response.authority.targetContainerUUID != container->plan.uuid ||
              response.authority.targetDeploymentID != container->plan.config.deploymentID() ||
              response.authority.targetClusterUUID != controlTransportCredentials.self.clusterUUID ||
              !cousinSessionCarrierCurrent(stream, stream->ioGeneration, stream->tlsPeerUUID)) break;
          Message::construct(stream->wBuffer, NeuronTopic::statefulStoreProofRecovery, encoded);
          Ring::queueSend(stream);
          break;
        }
      case ContainerTopic::statefulStoreReceipt:
        {
          String encoded = {}; Message::extractToStringView(args, encoded);
          ProdigyStatefulStoreReceipt receipt = {};
          NeuronBrainControlStream *stream = brain;
          // Bind the observation to the local control socket.  The Brain
          // independently fences its cache to this Neuron incarnation.
          if (args != terminal || !stream || !BitseryEngine::deserializeSafe(encoded, receipt) ||
              !prodigyStatefulStoreReceiptValid(receipt) || receipt.localContainerUUID != container->plan.uuid ||
              receipt.deploymentID != container->plan.config.deploymentID() ||
              receipt.localClusterUUID != controlTransportCredentials.self.clusterUUID ||
              !cousinSessionCarrierCurrent(stream, stream->ioGeneration, stream->tlsPeerUUID)) break;
          Message::construct(stream->wBuffer, NeuronTopic::statefulStoreReceipt, encoded);
          Ring::queueSend(stream);
          break;
        }
      case ContainerTopic::nametagHandoffBarrier:
        {
          String encoded = {}; Message::extractToStringView(args, encoded);
          ProdigyNametagHandoffBarrier barrier = {}; NeuronBrainControlStream *stream = brain;
          if (args != terminal || !stream || !BitseryEngine::deserializeSafe(encoded, barrier) ||
              !prodigyNametagHandoffBarrierValid(barrier) || barrier.clusterUUID != controlTransportCredentials.self.clusterUUID ||
              barrier.deadlineMilliseconds <= Time::now<TimeResolution::ms>() ||
              (barrier.response ? (container->plan.config.applicationID != 6 ||
                  barrier.appContainerUUID != container->plan.uuid || barrier.appDeploymentID != container->plan.config.deploymentID()) :
                 (container->plan.config.applicationID != 11 || barrier.probeContainerUUID != container->plan.uuid ||
                  barrier.probeDeploymentID != container->plan.config.deploymentID()))) break;
          Message::construct(stream->wBuffer, NeuronTopic::nametagHandoffBarrier, encoded);
          if (streamIsActive(stream)) Ring::queueSend(stream);
          break;
        }
      case ContainerTopic::nametagQualificationApplicationReceipt:
        {
          // The container control socket supplies the local container identity;
          // never let receipt payload choose which local deployment reported.
          // Brain performs the durable run/row/deadline join after this relay.
          String encoded = {}; Message::extractToStringView(args, encoded);
          ProdigyNametagQualificationApplicationReceipt receipt = {};
          NeuronBrainControlStream *stream = brain;
          if (args != terminal || !stream || !BitseryEngine::deserializeSafe(encoded, receipt) ||
              !prodigyNametagQualificationApplicationReceiptValid(receipt) ||
              receipt.localContainerUUID != container->plan.uuid ||
              receipt.deploymentID != container->plan.config.deploymentID() ||
              receipt.localClusterUUID != controlTransportCredentials.self.clusterUUID ||
              container->plan.config.applicationID != 11) break;
          Message::construct(stream->wBuffer, NeuronTopic::nametagQualificationApplicationReceipt, encoded);
          if (streamIsActive(stream)) Ring::queueSend(stream);
          break;
        }
      case ContainerTopic::nametagSourceBaseline:
        {
          String encoded = {}; Message::extractToStringView(args, encoded);
          ProdigyNametagSourceBaselineEnvelope envelope = {}; NeuronBrainControlStream *stream = brain;
          if (args != terminal || !stream || !BitseryEngine::deserializeSafe(encoded, envelope) ||
              !prodigyNametagSourceBaselineEnvelopeValid(envelope) ||
              envelope.direction != ProdigyNametagSourceBaselineDirection::receipt ||
              envelope.receipt.localContainerUUID != container->plan.uuid ||
              envelope.receipt.probeDeploymentID != container->plan.config.deploymentID() ||
              envelope.receipt.ewrClusterUUID != controlTransportCredentials.self.clusterUUID ||
              container->plan.config.applicationID != 11) break;
          Message::construct(stream->wBuffer, NeuronTopic::nametagSourceBaseline, encoded);
          if (streamIsActive(stream)) Ring::queueSend(stream);
          break;
        }
      case ContainerTopic::cousinCarrierFrame:
        {
          String serialized = {}; Message::extractToStringView(args, serialized);
          ProdigyCousinCarrierFrame frame = {};
          if (args != terminal || !BitseryEngine::deserializeSafe(serialized, frame) ||
              !prodigyCousinCarrierFrameValid(frame) || !pairControlRuntime) break;
          pruneCousinSessionEphemeralState(Time::msSinceBoot());
          auto pending = std::find_if(cousinSessionLocalPendings.begin(), cousinSessionLocalPendings.end(),
              [&](const auto& value) {
                return value.acknowledged && value.containerUUID == container->plan.uuid &&
                    value.sessionUUID == frame.sessionUUID && value.carrierGeneration == frame.leaseGeneration &&
                    prodigyCousinReverseCarrierSessionValid(value.session);
              });
          if (pending == cousinSessionLocalPendings.end()) break;
          const auto& local = pending->localHalf == CousinRouteHalf::source ?
              pending->session.sourceCarrier : pending->session.destinationCarrier;
          const auto& remote = pending->localHalf == CousinRouteHalf::source ?
              pending->session.destinationCarrier : pending->session.sourceCarrier;
          const bool sent = pairControlRuntime->sendCarrierFrame(pending->session, local, remote,
              pending->carrierConnectionID, frame);
          // A failed reset has not reached the authenticated flow and must not
          // silently withdraw the exact local authorization. On success, drop
          // queued inbound data before retiring just this session.
          if (sent && frame.kind == ProdigyCousinCarrierKind::reset) {
            discardCousinCarrierDeliveries(pending->containerUUID, pending->sessionUUID, pending->carrierGeneration);
            cousinSessionLocalPendings.erase(pending);
          }
          break;
        }
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
      PRODIGY_DEBUG_LOG("neuron downloadContainer request deploymentID=%llu brainPresent=%d brainActive=%d pendingCount=%llu pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d fd=%d fslot=%d\n",
                   (unsigned long long)deploymentID,
                   int(brain != nullptr),
                   int(streamIsActive(brain)),
                   (unsigned long long)pendingContainerDownloads.size(),
                   int(brain ? brain->pendingSend : 0),
                   int(brain ? brain->pendingRecv : 0),
                   int(brain ? brain->isTransportNegotiated() : 0),
                   int(brain ? brain->tlsPeerVerified : 0),
                   (brain ? brain->fd : -1),
                   (brain ? brain->fslot : -1));
      PRODIGY_DEBUG_FLUSH();
      Message::construct(brain->wBuffer, NeuronTopic::requestContainerBlob, deploymentID);
      if (streamIsActive(brain))
      {
        Ring::queueSend(brain);
      }
    }
  }

  // A container-download waiter is embedded in the suspended spinContainer
  // coroutine frame. Resuming its sole continuation may complete and destroy
  // that frame, so the wake path must not read the waiter again afterward.
  static void resumeContainerDownloadWaiter(CoroutineStack *waiter)
  {
    if (waiter == nullptr || waiter->suspended.empty())
    {
      return;
    }
    coroutine_handle<> continuation = waiter->suspended.back();
    waiter->suspended.pop_back();
    continuation.resume();
  }

  void resumeStoredContainerDownload(uint64_t deploymentID)
  {
    auto pendingIt = pendingContainerDownloads.find(deploymentID);
    if (pendingIt == pendingContainerDownloads.end())
    {
      return;
    }

    Vector<CoroutineStack *> toResume = std::move(pendingIt->second);
    pendingContainerDownloads.erase(pendingIt);
    bytell_hash_set<CoroutineStack *> resumed;
    for (CoroutineStack *coro : toResume)
    {
      if (coro != nullptr && resumed.contains(coro) == false)
      {
        resumed.emplace(coro);
        resumeContainerDownloadWaiter(coro);
      }
    }
  }

  struct PendingReceivedContainerArtifact {
    NeuronBrainControlStream *stream = nullptr;
    uint64_t streamGeneration = 0;
    uint128_t peerUUID = 0;
    uint64_t deploymentID = 0;
    String blob = {};
    String storeRoot = {};
    String stagePath = {};
    String failure = {};
    ContainerStore::PreparedAppArtifact prepared = {};
  };

  bool receivedArtifactSourceIsCurrent(const PendingReceivedContainerArtifact& operation) const
  {
    NeuronBrainControlStream *stream = operation.stream;
    if (brain != stream || stream == nullptr || stream->ioGeneration != operation.streamGeneration ||
        streamIsActive(stream) == false || stream->tlsPeerUUID != operation.peerUUID)
    {
      return false;
    }
    return stream->transportEncryptionEnabled() == false ||
           (stream->isTransportNegotiated() && stream->tlsPeerVerified);
  }

  // The default deliberately has no policy effect.  The focused artifact unit
  // uses this terminal Ring callback to distinguish a completed stale worker
  // from a merely queued one while keeping its store outside /containers.
  virtual void receivedContainerArtifactFinished(uint64_t, bool, bool) {}

  void finishReceivedContainerArtifact(const PendingReceivedContainerArtifact& operation, bool adopted)
  {
    receivedContainerArtifactFinished(operation.deploymentID, adopted, receivedArtifactSourceIsCurrent(operation));
  }

  void replayPendingContainerDownloadAfterArtifactFailure(const PendingReceivedContainerArtifact& operation)
  {
    if (receivedArtifactSourceIsCurrent(operation))
    {
      std::fprintf(stderr, "neuron requestContainerBlob replaying after artifact failure deploymentID=%llu\n",
                 (unsigned long long)operation.deploymentID);
      queueCloseIfActive(operation.stream);
    }
  }

  bool queueReceivedContainerArtifact(NeuronBrainControlStream *stream, uint64_t deploymentID, String&& blob)
  {
    if (artifactIO == nullptr || stream == nullptr || streamIsActive(stream) == false ||
        blob.size() == 0 || blob.size() > ProdigyArtifactIO::maximumBytes)
    {
      return false;
    }

    auto operation = std::make_shared<PendingReceivedContainerArtifact>();
    operation->stream = stream;
    operation->streamGeneration = stream->ioGeneration;
    operation->peerUUID = stream->tlsPeerUUID;
    operation->deploymentID = deploymentID;
    operation->blob = std::move(blob);
    operation->storeRoot = containerArtifactStoreRoot();

    const uint64_t bytes = operation->blob.size();
    return artifactIO->submit(
        bytes,
        [operation] {
          operation->stagePath = ContainerStore::pathForContainerImage(operation->deploymentID, &operation->storeRoot);
          operation->stagePath.append(".neuron-incoming.XXXXXX"_ctv);
          operation->stagePath.addNullTerminator();
          const int stageFD = ::mkstemp(reinterpret_cast<char *>(operation->stagePath.data()));
          if (stageFD < 0)
          {
            operation->failure.assign("container artifact stage creation failed"_ctv);
            return;
          }
          (void)::close(stageFD);
          String digest = {};
          if (prodigyComputeSHA256Hex(operation->blob, digest, &operation->failure) == false ||
              ContainerStore::prepareAppArtifactAtPath(operation->prepared,
                                                       operation->deploymentID,
                                                       operation->stagePath,
                                                       operation->blob,
                                                       digest,
                                                       operation->blob.size(),
                                                       &operation->failure,
                                                       &operation->storeRoot) == false)
          {
            (void)::unlink(operation->stagePath.c_str());
            return;
          }
          operation->blob.reset();
        },
        [this, operation] {
          if (operation->prepared.prepared == false || receivedArtifactSourceIsCurrent(*operation) == false)
          {
            finishReceivedContainerArtifact(*operation, false);
            replayPendingContainerDownloadAfterArtifactFailure(*operation);
            (void)artifactIO->continueWith(
                [operation] { ContainerStore::discardPreparedAppArtifact(operation->prepared); },
                [] {},
                [operation](std::exception_ptr) {});
            return;
          }

          // The first worker has only written a verified stage. Publication
          // receives a second, current-stream authorization on the Ring.
          const bool queued = artifactIO->continueWith(
              [operation] {
                if (ContainerStore::publishPreparedAppArtifact(operation->prepared, &operation->failure) == false)
                {
                  ContainerStore::discardPreparedAppArtifact(operation->prepared);
                  return;
                }
              },
              [this, operation] {
                if (operation->prepared.published == false || receivedArtifactSourceIsCurrent(*operation) == false ||
                    ContainerStore::adoptPreparedAppArtifact(operation->prepared) == false)
                {
                  std::fprintf(stderr, "neuron requestContainerBlob publish not adopted deploymentID=%llu\n",
                             (unsigned long long)operation->deploymentID);
                  if (operation->prepared.published)
                  {
                    (void)artifactIO->continueWith(
                        [operation] { ContainerStore::discardPreparedAppArtifact(operation->prepared); },
                        [] {},
                        [operation](std::exception_ptr) {});
                  }
                  finishReceivedContainerArtifact(*operation, false);
                  replayPendingContainerDownloadAfterArtifactFailure(*operation);
                  return;
                }
                resumeStoredContainerDownload(operation->deploymentID);
                finishReceivedContainerArtifact(*operation, true);
              },
              [this, operation](std::exception_ptr) {
                std::fprintf(stderr, "neuron requestContainerBlob publish worker failed deploymentID=%llu\n",
                           (unsigned long long)operation->deploymentID);
                finishReceivedContainerArtifact(*operation, false);
                replayPendingContainerDownloadAfterArtifactFailure(*operation);
              });
          if (queued == false)
          {
            std::fprintf(stderr, "neuron requestContainerBlob publish continuation rejected deploymentID=%llu\n",
                       (unsigned long long)operation->deploymentID);
            replayPendingContainerDownloadAfterArtifactFailure(*operation);
          }
        },
        [this, operation](std::exception_ptr) {
          std::fprintf(stderr, "neuron requestContainerBlob worker failed deploymentID=%llu\n",
                     (unsigned long long)operation->deploymentID);
          finishReceivedContainerArtifact(*operation, false);
          replayPendingContainerDownloadAfterArtifactFailure(*operation);
          (void)artifactIO->continueWith(
              [operation] { ContainerStore::discardPreparedAppArtifact(operation->prepared); },
              [] {},
              [operation](std::exception_ptr) {});
        });
  }

  // Keep live container processes and their mounts intact.  The replacement
  // Neuron re-registers and stateUpload re-adopts them before scheduling any
  // new work; this is deliberately an exec, not a Neuron restart/teardown.
  virtual bool quiesceProcessForBundleExec(void)
  {
    return true;
  }

  ProdigyArtifactIO *containerArtifactIO(void) override
  {
    return artifactIO.get();
  }

  bool quiesceArtifactIOForBundleExec(void) override
  {
    const bool artifactsReady = !artifactIO || artifactIO->quiesceForExec();
    const bool ringsReady = !switchboard || switchboard->quiesceRingPreparationForExec();
    const bool pairControlReady = !pairControlRuntime || pairControlRuntime->quiesce();
    return artifactsReady && ringsReady && pairControlReady;
  }

  bool quiesceContainerControlSocketsForBundleExec(void) override
  {
    bundleExecQuiescing = true;
    bool drained = true;
    for (const auto& [uuid, container] : containers)
    {
      (void)uuid;
      if (container == nullptr || container->exposesNeuronSocket() == false)
      {
        continue;
      }
      if (Ring::socketIsClosing(container))
      {
        drained = false;
        continue;
      }
      if (rawStreamIsActive(container) == false)
      {
        continue;
      }
      drained = false;
      if (container->isFixedFile && container->fslot >= 0)
      {
        Ring::queueCancelAll(container);
      }
      Ring::queueClose(container);
    }
    return drained;
  }

  void queueBundleExecRetry(void)
  {
    if (bundleExecRetryTickQueued)
    {
      return;
    }
    bundleExecRetryTick.clear();
    bundleExecRetryTick.originator = this;
    bundleExecRetryTick.setTimeoutMs(10);
    Ring::queueTimeout(&bundleExecRetryTick);
    bundleExecRetryTickQueued = true;
  }

  virtual void transitionToNewBundle(void)
  {
    // Host-control HTTP, DNS and artifact I/O own raw-fd polls. Their asynchronous shutdown
    // callbacks are the lifetime barrier required by Ring::shutdownForExec().
    // Retry from this Neuron-owned timer after cancellation CQEs are dispatched.
    const bool containerControlsQuiesced = quiesceContainerControlSocketsForBundleExec();
    const bool processQuiesced = quiesceProcessForBundleExec();
    const bool artifactIOQuiesced = quiesceArtifactIOForBundleExec();
    if (containerControlsQuiesced == false || processQuiesced == false || artifactIOQuiesced == false)
    {
      queueBundleExecRetry();
      return;
    }

    String failure = {};
    String installRoot = {};
    if (prodigyResolveCurrentInstallRoot(installRoot, &failure) == false)
    {
      basics_log("neuron transitionToNewBundle current install root resolution failed: %s\n", failure.c_str());
      _exit(EXIT_FAILURE);
    }
    if (prodigyInstallBundleToRoot(prodigyStagedBundlePath(), installRoot, &failure) == false)
    {
      basics_log("neuron transitionToNewBundle install failed: %s\n", failure.c_str());
      _exit(EXIT_FAILURE);
    }

    ProdigyInstallRootPaths paths = {};
    prodigyBuildInstallRootPaths(installRoot, paths);
    String libraryDirectory = {};
    libraryDirectory.assign(paths.libraryDirectory);
    (void)setenv("LD_LIBRARY_PATH", libraryDirectory.c_str(), 1);
    Ring::shutdownForExec();

    long maxFD = sysconf(_SC_OPEN_MAX);
    if (maxFD < 0)
    {
      maxFD = 4096;
    }
    for (int fd = 3; fd < maxFD; ++fd)
    {
      close(fd);
    }

    String binaryPath = {};
    binaryPath.assign(paths.binaryPath);
    Vector<char *> argv = {};
    if (BrainBase::buildLaunchArgumentsForExec(binaryPath, argv))
    {
      execv(binaryPath.c_str(), argv.data());
    }
    execl(binaryPath.c_str(), binaryPath.c_str(), (char *)NULL);
    _exit(EXIT_FAILURE);
  }

  bool receivedBundleSourceIsCurrent(const PendingReceivedBundleArtifact& operation) const
  {
    NeuronBrainControlStream *stream = operation.stream;
    return brain == stream && stream != nullptr && stream->ioGeneration == operation.streamGeneration &&
           streamIsActive(stream) && stream->tlsPeerUUID == operation.peerUUID &&
           (stream->transportEncryptionEnabled() == false || (stream->isTransportNegotiated() && stream->tlsPeerVerified));
  }

  void clearPendingBundleArtifact(const std::shared_ptr<PendingReceivedBundleArtifact>& operation)
  {
    if (pendingBundleArtifact == operation)
    {
      pendingBundleArtifact.reset();
    }
  }

  void queueBundleArtifactResponse(const std::shared_ptr<PendingReceivedBundleArtifact>& operation, bool success)
  {
    if (receivedBundleSourceIsCurrent(*operation) == false)
    {
      return;
    }
    Message::construct(operation->stream->wBuffer,
                       NeuronTopic::updateBundle,
                       success,
                       operation->actualDigest,
                       operation->failure);
    Ring::queueSend(operation->stream);
  }

  // Bundle payloads are release-sized. The worker writes only a private,
  // verified stage; publication follows a Ring-owned source/epoch check.
  [[gnu::noinline]] void handleBundleUpdateMessage(Message *message)
  {
    uint8_t *args = message->args;
    String bundle = {};
    String expectedDigest = {};
    Message::extractToStringView(args, bundle);
    Message::extractToStringView(args, expectedDigest);
    if (artifactIO == nullptr || brain == nullptr || streamIsActive(brain) == false ||
        pendingBundleArtifact != nullptr || bundle.size() == 0 || bundle.size() > ProdigyArtifactIO::maximumBytes)
    {
      std::fprintf(stderr, "neuron updateBundle artifact queue rejected bytes=%llu\n", (unsigned long long)bundle.size());
      if (brain != nullptr) queueCloseIfActive(brain);
      return;
    }

    auto operation = std::make_shared<PendingReceivedBundleArtifact>();
    operation->stream = brain;
    operation->streamGeneration = brain->ioGeneration;
    operation->peerUUID = brain->tlsPeerUUID;
    operation->bundle.assign(bundle);
    operation->expectedDigest.assign(expectedDigest);
    pendingBundleArtifact = operation;
    const uint64_t bytes = operation->bundle.size();
    if (artifactIO->submit(
            bytes,
            [operation] {
              if (prodigyPrepareBundleArtifact(operation->prepared,
                                                prodigyStagedBundlePath(),
                                                operation->bundle,
                                                operation->expectedDigest,
                                                &operation->failure))
              {
                operation->actualDigest.assign(operation->prepared.sha256);
                operation->bundle.reset();
              }
            },
            [this, operation] {
              if (operation->prepared.prepared == false || receivedBundleSourceIsCurrent(*operation) == false)
              {
                queueBundleArtifactResponse(operation, false);
                clearPendingBundleArtifact(operation);
                deferredBundleTransition = false;
                (void)artifactIO->continueWith(
                    [operation] { prodigyDiscardPreparedBundleArtifact(operation->prepared); },
                    [] {},
                    [operation](std::exception_ptr) {});
                return;
              }
              if (prodigyPublishPreparedBundleArtifact(operation->prepared, &operation->failure) == false)
              {
                queueBundleArtifactResponse(operation, false);
                clearPendingBundleArtifact(operation);
                deferredBundleTransition = false;
                (void)artifactIO->continueWith(
                    [operation] { prodigyDiscardPreparedBundleArtifact(operation->prepared); },
                    [] {},
                    [operation](std::exception_ptr) {});
                return;
              }
              if (artifactIO->continueWith(
                      [operation] {
                        operation->durable = prodigyFsyncPublishedBundleArtifact(operation->prepared, &operation->failure);
                      },
                      [this, operation] {
                        if (operation->prepared.published == false || operation->durable == false || receivedBundleSourceIsCurrent(*operation) == false)
                        {
                          queueBundleArtifactResponse(operation, false);
                          clearPendingBundleArtifact(operation);
                          deferredBundleTransition = false;
                          if (operation->prepared.published)
                          {
                            (void)artifactIO->continueWith(
                                [operation] { prodigyDiscardPreparedBundleArtifact(operation->prepared); },
                                [] {},
                                [operation](std::exception_ptr) {});
                          }
                          return;
                        }
                        const bool transitionAfterAck = deferredBundleTransition;
                        deferredBundleTransition = false;
                        queueBundleArtifactResponse(operation, true);
                        clearPendingBundleArtifact(operation);
                        if (transitionAfterAck)
                        {
                          operation->stream->transitionAfterBundleAck = true;
                        }
                      },
                      [this, operation](std::exception_ptr) {
                        operation->failure.assign("bundle artifact worker failed"_ctv);
                        queueBundleArtifactResponse(operation, false);
                        clearPendingBundleArtifact(operation);
                        deferredBundleTransition = false;
                      }) == false)
              {
                operation->failure.assign("bundle artifact publication continuation unavailable"_ctv);
                queueBundleArtifactResponse(operation, false);
                clearPendingBundleArtifact(operation);
                deferredBundleTransition = false;
              }
            },
            [this, operation](std::exception_ptr) {
              operation->failure.assign("bundle artifact worker failed"_ctv);
              queueBundleArtifactResponse(operation, false);
              clearPendingBundleArtifact(operation);
              deferredBundleTransition = false;
              (void)artifactIO->continueWith(
                  [operation] { prodigyDiscardPreparedBundleArtifact(operation->prepared); },
                  [] {},
                  [operation](std::exception_ptr) {});
            }) == false)
    {
      pendingBundleArtifact.reset();
      deferredBundleTransition = false;
      std::fprintf(stderr, "neuron updateBundle artifact worker queue full bytes=%llu\n", (unsigned long long)bytes);
      queueCloseIfActive(brain);
    }
  }

  // The live cgroup root is virtual solely so the retained-owner regression
  // can exercise the production scanner against an isolated filesystem tree.
  virtual String containerCgroupInventoryRoot(void) const
  {
    return "/sys/fs/cgroup/containers.slice"_ctv;
  }

  bool liveContainerInventoryProcessOwned(const std::string& name, pid_t pid) const
  {
    const auto found = containerByPid.find(pid);
    if (found != containerByPid.end() && found->second != nullptr)
    {
      const Container *container = found->second;
      if (container->pendingDestroy == false &&
          container->name.equal(String(name.c_str())) &&
          containers.contains(container->plan.uuid)) return true;
    }

    // An authenticated Brain bootstrap creates this unpublished owner before
    // asynchronous network recovery can publish it.  It is enough to retain
    // the inventory fence only while every identity fence still names the
    // exact live cgroup process; a directory name alone is never ownership.
    for (const auto& [uuid, operation] : pendingStateUploadRestores)
    {
      if (operation == nullptr || operation->container == nullptr ||
          operation->terminalRetirementPending || operation->coldRestart ||
          uuid != operation->container->plan.uuid ||
          operation->container->pid != pid ||
          operation->container->pidfd < 0 || operation->container->cgroup < 0 ||
          operation->container->name.equal(String(name.c_str())) == false ||
          stateUploadRestoreCurrent(*operation, uuid) == false)
      {
        continue;
      }
      return true;
    }
    return false;
  }

  virtual bool liveContainerInventoryComplete(String& failure) const
  {
    return prodigyContainerInventoryCgroupsOwned(
        containerCgroupInventoryRoot().c_str(),
        [this](const std::string& name, pid_t pid) {
          return liveContainerInventoryProcessOwned(name, pid);
        }, failure);
  }

  bool prepareCrossClusterMasqueGatewayLaunch(ContainerPlan& plan,
                                               CrossClusterMasqueGatewayRuntime& runtime,
                                               const String& recoveryToken,
                                               bool replaceLaunch)
  {
    if (!ContainerManager::gatewayRecoveryTokenValid(recoveryToken)) return false;
    if (replaceLaunch)
    {
      runtime.revokeReadiness();
      if (auto it = containers.find(runtime.systemContainerUUID);
          it != containers.end() && it->second != nullptr)
      {
        ensureSwitchboard()->closeWormholesToContainer(generateLocalContainerID(it->second->plan.fragment));
      }
      removeCrossClusterMasqueGatewayListener(runtime.systemContainerUUID);
      runtime.readinessLaunchToken.assignItoh(Random::generateNumberWithNBits<128, uint128_t>());
      runtime.recoveryLaunchToken.assign(recoveryToken);
      runtime.systemContainerUUID = plan.uuid;
      runtime.systemPlanAdmitted = true;
      (void)reconcileCrossClusterMasqueGatewayBGP(runtime);
    }
    else
    {
      runtime.recoveryLaunchToken.assign(recoveryToken);
    }

    // These are launch-scoped authority references, not a NeuronHub payload.
    // The pinned process can only report on this exact launch.
    if (!Container::gatewayReadinessSocketPath(plan.uuid, runtime.readinessLaunchToken,
                                                plan.system.gatewayReadinessSocket)) return false;
    plan.system.gatewayLaunchToken.assign(runtime.readinessLaunchToken);
    if (!ContainerManager::gatewayRecoverySocketPath(plan.uuid, plan.system.gatewayRecoverySocket)) return false;
    plan.system.gatewayRecoveryToken.assign(runtime.recoveryLaunchToken);
    if (runtime.authority.localRole == CrossClusterMasqueGatewayRole::listener)
      plan.system.gatewayRole.assign("listener"_ctv);
    else
      plan.system.gatewayRole.assign("connector"_ctv);
    String routeText = {};
    if (!ClusterMachine::renderIPAddressLiteral(runtime.authority.localSitePrefix.network, routeText)) return false;
    routeText.append("/"_ctv);
    String cidrText = {};
    cidrText.assignItoa(runtime.authority.localSitePrefix.cidr);
    routeText.append(cidrText);
    plan.system.gatewayRoutes.assign(routeText);
    if (!ClusterMachine::renderIPAddressLiteral(runtime.authority.listenerPublicUDPEndpoint,
                                                 plan.system.gatewayEndpoint)) return false;
    plan.system.gatewayLocalIdentity.assign(runtime.authority.localIdentitySHA256);
    plan.system.gatewayPeerIdentity.assign(runtime.authority.peerIdentitySHA256);
    plan.system.gatewayPeerTrust.assign(runtime.authority.peerTrustSHA256);
    return prodigyBindCrossClusterMasqueGatewayRuntimePlanAuthority(plan.system, runtime.authority);
  }

  // Both ordinary Brain spin commands and an authenticated fresh
  // state-upload replay enter through this boundary. Tests can observe their
  // identity without changing the production launch sequencing.
  virtual void launchContainerFromBrain(ContainerPlan plan,
                                        uint128_t replaceContainerUUID,
                                        NeuronContainerMetricPolicy metricPolicy,
                                        RetainedContainerStorageSource retainedSource = {})
  {
    if (plan.system.kind == SystemContainerKind::crossClusterMasqueGateway)
    {
      if (!admitCrossClusterMasqueGatewaySystemPlan(plan))
      {
        basics_log("neuron rejected cross-cluster MASQUE gateway system plan uuid=%llu\n",
                   (unsigned long long)plan.uuid);
        return;
      }
      auto *runtime = crossClusterMasqueGatewayRuntimeForPair(plan.system.gatewayPairUUID);
      if (runtime == nullptr) return;
      if (!runtime->gatewayBootstrap)
      {
        auto pending = std::make_unique<CrossClusterMasqueGatewayRuntime::PendingLaunch>();
        pending->plan = std::move(plan);
        pending->controlGeneration = containerLaunchControlGeneration;
        pending->replaceContainerUUID = replaceContainerUUID;
        pending->metricPolicy = metricPolicy;
        pending->retainedSource = std::move(retainedSource);
        runtime->pendingLaunch = std::move(pending);
        return;
      }
      // stateUpload-local strings are deliberately ignored. Only a record in
      // the verified per-container runtime directory may restore this token.
      String recoveredToken = {};
      const bool recoveredRecord = ContainerManager::readGatewayRecoveryRecord(plan, recoveredToken);
      const bool replaceLaunch = runtime->systemContainerUUID != plan.uuid;
      if (!recoveredRecord && replaceLaunch)
        ContainerManager::generateGatewayRecoveryToken(recoveredToken);
      if (!recoveredRecord && !replaceLaunch)
        recoveredToken.assign(runtime->recoveryLaunchToken);
      if (!prepareCrossClusterMasqueGatewayLaunch(plan, *runtime, recoveredToken, replaceLaunch)) return;
    }
    ContainerManager::spinContainer(std::move(plan), replaceContainerUUID, metricPolicy, retainedSource);
  }

  // Production keeps received application artifacts in the canonical store.
  // Tests override only the root to exercise the identical prepared lifecycle.
  virtual String containerArtifactStoreRoot(void) const
  {
    return "/containers/store"_ctv;
  }

  // The production path is Container-owned; tests use this narrow Neuron
  // boundary to hold and settle a recovery completion without netns/BPF I/O.
  virtual ProdigyHostTask<bool> restoreStateUploadNetworkAsync(
      Container *container,
      CoroutineStack *coro,
      String *failure,
      std::function<bool()> current)
  {
    if (container == nullptr)
    {
      if (failure) failure->assign("state upload restore container missing"_ctv);
      co_return false;
    }
    co_return co_await container->restoreNetworkAsync(coro, failure, std::move(current));
  }

protected:

  void queueNeuronStateUpload(void)
  {
    if (brain == nullptr)
    {
      return;
    }

    String inventoryFailure;
    if (!liveContainerInventoryComplete(inventoryFailure))
    {
      // This is a safety boundary: an empty or partial upload would let the
      // Brain schedule alongside an unaccounted retained process.  basics_log
      // is compiled out when BASICS_DEBUG is disabled, so retain this rare
      // production diagnostic for recovery operators.
      std::fprintf(stderr,
                   "neuron stateUpload withheld reason=%s trackedContainers=%zu pendingLaunches=%zu pendingRestores=%zu\n",
                   inventoryFailure.c_str(), size_t(containers.size()), size_t(pendingContainerLaunchPlans.size()),
                   size_t(pendingStateUploadRestores.size()));
      std::fflush(stderr);
#if PRODIGY_DEBUG
      for (const auto& [uuid, container] : containers)
      {
        PRODIGY_DEBUG_LOG(
            "neuron stateUpload withheld tracked uuid=%016llx%016llx pid=%d pendingDestroy=%d\n",
            (unsigned long long)(uuid >> 64), (unsigned long long)uuid,
            container ? int(container->pid) : -1, int(container && container->pendingDestroy));
      }
      for (const auto& [uuid, plan] : pendingContainerLaunchPlans)
      {
        PRODIGY_DEBUG_LOG(
            "neuron stateUpload withheld pending uuid=%016llx%016llx deploymentID=%llu\n",
            (unsigned long long)(uuid >> 64), (unsigned long long)uuid,
            (unsigned long long)plan.config.deploymentID());
      }
      PRODIGY_DEBUG_FLUSH();
#endif
      return;
    }

    uint32_t headerOffset = Message::appendHeader(brain->wBuffer, NeuronTopic::stateUpload);
    Message::appendAlignedBuffer<Alignment::one>(brain->wBuffer, (uint8_t *)&lcsubnet6, sizeof(struct local_container_subnet6));
    for (const auto& [uuid, container] : containers)
    {
      (void)uuid;
      String serializedPlan = {};
      BitseryEngine::serialize(serializedPlan, container->plan);
      Message::appendValue(brain->wBuffer, serializedPlan);
    }
    for (const auto& [uuid, plan] : pendingContainerLaunchPlans)
    {
      if (containers.contains(uuid)) continue;
      String serializedPlan = {};
      BitseryEngine::serialize(serializedPlan, plan);
      Message::appendValue(brain->wBuffer, serializedPlan);
    }
    Message::finish(brain->wBuffer, headerOffset);
    replayCurrentGatewayReadinessAfterStateUpload();
    if (streamIsActive(brain)) Ring::queueSend(brain);
  }

  bool stateUploadRestoreCurrent(const StateUploadRestoreOperation& operation, uint128_t containerUUID) const
  {
    return operation.container != nullptr && operation.container->pendingDestroy == false &&
           pendingContainerLaunchIsCurrent(containerUUID, operation.launchAdmissionGeneration) &&
           operation.epoch == stateUploadRestoreEpoch &&
           memcmp(&operation.fragment, &lcsubnet6, sizeof(lcsubnet6)) == 0 &&
           brain == operation.stream && brain != nullptr &&
           brain->ioGeneration == operation.streamGeneration && streamIsActive(brain) &&
           containers.contains(containerUUID) == false;
  }

  static ProdigyGatewayLocalTuple gatewayRecoveryTuple(const CrossClusterMasqueGatewayAuthority& authority)
  {
    ProdigyGatewayLocalTuple tuple = {};
    tuple.pairUUID = authority.pairUUID; tuple.localClusterUUID = authority.localClusterUUID;
    tuple.localMachineUUID = authority.localMachineUUID; tuple.keyEpoch = authority.keyGeneration;
    tuple.authorityGeneration = authority.pairAuthorityGeneration; tuple.gatewayGeneration = authority.generation;
    return tuple;
  }

  virtual bool captureRetainedGatewayPeerIdentity(
      pid_t pid, CrossClusterMasqueGatewayReadinessListener::PeerIdentity& identity)
  {
    return CrossClusterMasqueGatewayReadinessListener::capturePeerIdentityFromProc(pid, identity);
  }

  bool armRetainedGatewayRecoveryListener(StateUploadRestoreOperation& operation, uint128_t containerUUID)
  {
    if (!operation.container || !operation.networkRestored ||
        !operation.gatewayRecoveryTokenBound || operation.boundGatewayRecoveryToken.empty() ||
        operation.container->plan.system.gatewayRecoverySocket.empty() ||
        operation.container->plan.system.gatewayRecoveryToken != operation.boundGatewayRecoveryToken ||
        operation.container->pidfd < 0) return false;
    String canonicalSocket = {};
    if (!ContainerManager::gatewayRecoverySocketPath(containerUUID, canonicalSocket) ||
        canonicalSocket != operation.container->plan.system.gatewayRecoverySocket) return false;
    auto *runtime = crossClusterMasqueGatewayRuntimeForPair(operation.container->plan.system.gatewayPairUUID);
    if (!runtime || !admitCrossClusterMasqueGatewaySystemPlan(operation.container->plan) ||
        (runtime->systemContainerUUID != 0 && runtime->systemContainerUUID != containerUUID) ||
        runtime->systemPlanAdmitted != (runtime->systemContainerUUID != 0)) return false;
    const auto tuple = gatewayRecoveryTuple(runtime->authority);
    if (auto *existing = crossClusterMasqueGatewayListenerForContainer(containerUUID))
    {
      CrossClusterMasqueGatewayReadinessListener::PeerIdentity observed = {};
      const auto& retained = existing->recoveryTuple;
      return runtime->systemPlanAdmitted && existing->recovery && existing->fd >= 0 &&
          existing->recoveryEpoch == operation.epoch && existing->path == canonicalSocket &&
          existing->recoveryToken == operation.boundGatewayRecoveryToken &&
          retained.pairUUID == tuple.pairUUID && retained.localClusterUUID == tuple.localClusterUUID &&
          retained.localMachineUUID == tuple.localMachineUUID && retained.keyEpoch == tuple.keyEpoch &&
          retained.authorityGeneration == tuple.authorityGeneration && retained.gatewayGeneration == tuple.gatewayGeneration &&
          captureRetainedGatewayPeerIdentity(operation.container->pid, observed) && observed == existing->retainedIdentity;
    }
    auto listener = std::make_unique<CrossClusterMasqueGatewayReadinessListener>();
    listener->capturePeerIdentity = [this](pid_t pid, CrossClusterMasqueGatewayReadinessListener::PeerIdentity& identity) {
      return captureRetainedGatewayPeerIdentity(pid, identity);
    };
    if (!listener->openForRecovery(*operation.container, canonicalSocket,
                                   operation.boundGatewayRecoveryToken, tuple, operation.epoch)) return false;
    // A fresh runtime has authority but no ordinary launch. Bind only this
    // validated retained process, after its durable token and peer identity
    // have earned the recovery listener. A different live owner is never replaced.
    if (runtime->systemContainerUUID == 0)
    {
      runtime->systemContainerUUID = containerUUID;
      runtime->systemPlanAdmitted = true;
      runtime->revokeReadiness();
    }
    RingDispatcher::installMultiplexee(listener.get(), this);
    Ring::queuePollProcessFD(listener.get(), listener->fd, false, POLLIN);
    crossClusterMasqueGatewayReadinessListeners.push_back(std::move(listener));
    return true;
  }

  bool publishRestoredStateUploadContainer(StateUploadRestoreOperation& operation,
                                           uint128_t containerUUID, uint64_t epoch)
  {
    if (operation.container == nullptr || operation.terminalRetirementPending || containers.contains(containerUUID) ||
        operation.epoch != epoch || operation.container->pendingDestroy) return false;
    finishPendingContainerLaunch(containerUUID, operation.launchAdmissionGeneration);
    Container *container = operation.container.release();
    if (container == nullptr) return false;
    if (container->plan.system.kind != SystemContainerKind::crossClusterMasqueGateway)
    {
      container->assignNeuronListenerPath();
      if (container->neuronListenerPath.size() == 0) { String empty = {}; reportContainerFailed(container->plan.uuid, 0, 0, empty, false); ContainerManager::destroyContainer(container); return false; }
      container->setSocketPath(container->neuronListenerPath.c_str());
    }
    // `pushContainer` remains the sole publication owner. Its gateway branch
    // preserves the established recovery listener/carrier, so this handoff
    // cannot create a second lease or re-enter a launch listener.
    pushContainer(container); noteTaskAttemptRunning(container->plan); queueRestoredStateUploadContainerWaitid(container);
    if (container->exposesNeuronSocket()) Ring::queueConnect(container);
    operation.settled = true;
    if (!stateUploadRestoresPending() && !retainedStateUploadCandidatesPending() && epoch == stateUploadRestoreEpoch)
    {
      stateUploadRestoreReplyPending = false;
      queueNeuronStateUpload();
    }
    return true;
  }

  virtual void queueRestoredStateUploadContainerWaitid(Container *container)
  {
    ContainerManager::queueContainerWaitid(container);
  }

  bool finishStateUploadRestore(uint128_t containerUUID, uint64_t epoch, bool restored, String failure)
  {
    auto it = pendingStateUploadRestores.find(containerUUID);
    if (it == pendingStateUploadRestores.end() || it->second == nullptr || it->second->epoch != epoch)
    {
      return false;
    }

    StateUploadRestoreOperation *operation = it->second.get();
    Container *container = operation->container.get();
    const bool current = stateUploadRestoreCurrent(*operation, containerUUID);
    if (!current)
    {
      // Do not publish a candidate prepared for an obsolete fragment or
      // control generation. Keep its retained process/network wrapper for a
      // later authoritative state upload; destroying it would synchronously
      // delete the adopted netkit pair.
      // A same-fragment upload on a replacement control stream is newer
      // intent. Re-run only after this attempt has settled, preserving the
      // same owned candidate and never publishing on the obsolete stream.
      if (container != nullptr && !container->pendingDestroy && !containers.contains(containerUUID) &&
          operation->requestedStream == brain && brain != nullptr && streamIsActive(brain) &&
          operation->requestedGeneration == brain->ioGeneration &&
          (operation->stream != brain || operation->streamGeneration != brain->ioGeneration) &&
          epoch == stateUploadRestoreEpoch &&
          memcmp(&operation->fragment, &lcsubnet6, sizeof(lcsubnet6)) == 0)
      {
        operation->stream = brain;
        operation->streamGeneration = brain->ioGeneration;
        operation->epoch = stateUploadRestoreEpoch;
        return true;
      }
      if (stateUploadRestoreRemaining > 0) --stateUploadRestoreRemaining;
      if (epoch == stateUploadRestoreEpoch) stateUploadRestoreReplyPending = false;
      operation->settled = true;
      return false;
    }

    if (!restored)
    {
      // A retained candidate owns an already-live process.  A network restore
      // failure says nothing about that process's liveness, so it cannot use
      // the normal failed-launch path: restartContainer clears pid/pidfd and
      // launches a second process with this UUID while the original survives.
      // Keep the wrapper and pending-launch fence until matching authoritative
      // state can retry the restore.
      String retainedIdentity;
      retainedIdentity.snprintf<"{itoh}"_ctv>(containerUUID);
      std::fprintf(stderr,
                   "restoreContainer retained network restore failed uuid=%s pid=%d reason=%s; preserving retained process for authoritative retry\n",
                   retainedIdentity.c_str(),
                   container ? int(container->pid) : -1,
                   failure.c_str());
      std::fflush(stderr);
      if (stateUploadRestoreRemaining > 0) --stateUploadRestoreRemaining;
      stateUploadRestoreReplyPending = false;
      operation->settled = true;
      return false;
    }

    if (stateUploadRestoreRemaining > 0) --stateUploadRestoreRemaining;
    operation->networkRestored = true;

    if (container != nullptr &&
        container->plan.system.kind == SystemContainerKind::crossClusterMasqueGateway)
    {
      // A gateway deliberately has no NeuronHub socket. Its launch readiness
      // listener is detached into the process mount namespace and the current
      // artifact accepts its FD only on the one-shot startup channel. Do not
      // turn a retained gateway into a generic container here: that would
      // trust checkpoint-local socket/token state or publish without a fresh,
      // authenticated readiness receipt. Keep the exact process and launch
      // fence for an authoritative retry once the artifact can acknowledge a
      // post-exec readiness rebind.
      // The new host routing programs begin empty after exec, whereas the
      // retained gateway's egress program may still have learned reply flows.
      // Replay the durable plan binding before the rebind so peer replies can
      // reach the exact retained netkit; this does not publish the container
      // or assert readiness.
      if (container->plan.whiteholes.empty() == false)
      {
        openWhiteholesForLocalContainer(container->plan.fragment,
                                        container->plan.whiteholes);
      }
      auto *runtime = crossClusterMasqueGatewayRuntimeForPair(
          container->plan.system.gatewayPairUUID);
      if (runtime != nullptr && runtime->systemContainerUUID == containerUUID)
      {
        (void)revokeCrossClusterMasqueGatewayReadiness(containerUUID);
      }
      if (!armRetainedGatewayRecoveryListener(*operation, containerUUID))
      {
        basics_log("restoreContainer retained MASQUE gateway recovery listener remains fenced uuid=%llu pid=%d\n",
                   (unsigned long long)containerUUID, int(container->pid));
      }
      else basics_log("restoreContainer retained MASQUE gateway awaits authenticated readiness rebind uuid=%llu pid=%d\n",
                      (unsigned long long)containerUUID, int(container->pid));
      stateUploadRestoreReplyPending = false;
      operation->settled = true;
      return false;
    }

    (void)publishRestoredStateUploadContainer(*operation, containerUUID, epoch);
    return false;
  }

  CoroutineGenerator<uint8_t> restoreStateUploadContainer(std::weak_ptr<uint8_t> lifetime, uint128_t containerUUID, uint64_t epoch)
  {
    auto it = pendingStateUploadRestores.find(containerUUID);
    if (it == pendingStateUploadRestores.end() || it->second == nullptr || it->second->epoch != epoch) co_return;
    // The map can rehash while suspended. Its individually owned operation
    // stays at a stable address until this runner is retired.
    StateUploadRestoreOperation *operation = it->second.get();
    for (;;)
    {
      String failure = {};
      auto current = [this, lifetime, containerUUID, epoch]() -> bool {
        if (lifetime.expired()) return false;
        auto found = pendingStateUploadRestores.find(containerUUID);
        return found != pendingStateUploadRestores.end() && found->second != nullptr &&
               found->second->epoch == epoch && stateUploadRestoreCurrent(*found->second, containerUUID);
      };
      const bool restored = operation->networkRestored || co_await restoreStateUploadNetworkAsync(
          operation->container.get(), &operation->coro, &failure, std::move(current));
      if (lifetime.expired()) co_return;
      if (!finishStateUploadRestore(containerUUID, epoch, restored, std::move(failure))) break;
      epoch = operation->epoch;
    }
    // The owning operation retains this frame until a later Ring turn retires
    // it. A void fire-and-forget coroutine has no owner to cancel safely.
    co_yield uint8_t(0);
  }

  void resumeStateUploadRestore(StateUploadRestoreOperation& operation, uint128_t containerUUID, uint64_t epoch)
  {
    operation.coro.cancelSuspended();
    operation.runner.reset();
    operation.fragment = lcsubnet6;
    operation.stream = brain;
    operation.streamGeneration = brain ? brain->ioGeneration : 0;
    operation.requestedStream = operation.stream;
    operation.requestedGeneration = operation.streamGeneration;
    operation.epoch = epoch;
    operation.settled = false;
    stateUploadRestoreRemaining += 1;
    operation.runner = std::make_unique<CoroutineGenerator<uint8_t>>(
        restoreStateUploadContainer(asyncOperationLifetime, containerUUID, epoch));
    (void)operation.runner->advance();
  }

  CoroutineGenerator<uint8_t> refreshRuntimeEnvironmentBGP(
      std::weak_ptr<uint8_t> lifetime,
      uint64_t generation)
  {
    BGPConfigurationRefreshOperation *operation = bgpConfigurationRefresh.get();
    if (operation == nullptr || operation->generation != generation)
    {
      co_return;
    }

    std::fprintf(stderr, "neuron BGP provider refresh start generation=%llu\n",
                 (unsigned long long)generation);
    const bool ready = co_await iaas->refreshBGPConfiguration(&operation->coro);
    if (lifetime.expired() || bgpConfigurationRefresh.get() != operation ||
        operation->generation != generation || runtimeEnvironmentGeneration != generation)
    {
      co_return;
    }

    if (ready)
    {
      NeuronBGPConfig bgpConfig = {};
      const NeuronBGPConfigurationRetry configurationRetry =
          iaas->gatherBGPConfig(bgpConfig, eth, private4);
      std::fprintf(stderr, "neuron BGP provider refresh complete generation=%llu enabled=%d peers=%u\n",
                   (unsigned long long)generation, int(bgpConfig.enabled),
                   unsigned(bgpConfig.peers.size()));
      if (!bgp)
      {
        bgp = std::make_unique<NeuronBGPRuntime>();
      }
      bgp->configure(bgpConfig);

      if (bgpConfig.enabled)
      {
        bgpIPv6ReadinessRetryAttempts = 0;
        bgpIPv6ReadinessRetryPendingGeneration = 0;
        if (bgpIPv6ReadinessRetryQueued)
        {
          Ring::queueCancelTimeout(&bgpIPv6ReadinessRetryTick);
        }
      }
      else if (prodigyBGPIPv6ReadinessRetryEligible(
                   true, bgpConfig, configurationRetry,
                   bgpIPv6ReadinessRetryAttempts))
      {
        bgpIPv6ReadinessRetryPendingGeneration = generation;
        if (bgpIPv6ReadinessRetryQueued == false)
        {
          bgpIPv6ReadinessRetryTick.clear();
          bgpIPv6ReadinessRetryTick.flags = uint64_t(NeuronTimeoutFlags::bgpIPv6ReadinessRetry);
          bgpIPv6ReadinessRetryTick.identifier = generation;
          bgpIPv6ReadinessRetryTick.originator = this;
          const uint32_t delayMs = prodigyBGPIPv6ReadinessRetryDelayMs(bgpIPv6ReadinessRetryAttempts++);
          bgpIPv6ReadinessRetryTick.setTimeoutMs(delayMs);
          bgpIPv6ReadinessRetryQueued = true;
          std::fprintf(stderr,
                       "neuron BGP IPv6 readiness retry scheduled generation=%llu attempt=%u delayMs=%u\n",
                       (unsigned long long)generation,
                       unsigned(bgpIPv6ReadinessRetryAttempts), unsigned(delayMs));
          Ring::queueTimeout(&bgpIPv6ReadinessRetryTick);
        }
      }
      else
      {
        bgpIPv6ReadinessRetryPendingGeneration = 0;
      }
    }
    else
    {
      std::fprintf(stderr, "neuron BGP provider refresh failed generation=%llu\n",
                   (unsigned long long)generation);
    }
    operation->settled = true;

    // Retain an owner for the coroutine frame until the next configuration or
    // Neuron teardown. A detached HostTask could otherwise resume after its
    // provider delegate has been replaced.
    co_yield uint8_t(0);
  }

  void beginRuntimeEnvironmentReconfiguration(void)
  {
    runtimeEnvironmentGeneration += 1;
    bgpConfigurationRefresh.reset();
    bgpIPv6ReadinessRetryAttempts = 0;
    bgpIPv6ReadinessRetryPendingGeneration = 0;
    if (bgpIPv6ReadinessRetryQueued)
    {
      Ring::queueCancelTimeout(&bgpIPv6ReadinessRetryTick);
    }
  }

  void scheduleRuntimeEnvironmentBGPRefresh(void)
  {
    auto operation = std::make_unique<BGPConfigurationRefreshOperation>();
    operation->generation = runtimeEnvironmentGeneration;
    BGPConfigurationRefreshOperation *owned = operation.get();
    bgpConfigurationRefresh = std::move(operation);
    owned->runner = std::make_unique<CoroutineGenerator<uint8_t>>(
        refreshRuntimeEnvironmentBGP(asyncOperationLifetime, owned->generation));
    (void)owned->runner->advance();
  }

  void retireCompletedStateUploadRestores(void)
  {
    Vector<uint128_t> completed = {};
    for (const auto& [uuid, operation] : pendingStateUploadRestores)
    {
      if (operation != nullptr && operation->settled && operation->container == nullptr)
      {
        completed.push_back(uuid);
      }
    }
    for (uint128_t uuid : completed) pendingStateUploadRestores.erase(uuid);
  }

  bool stateUploadRestoresPending(void) const { return stateUploadRestoreRemaining != 0; }

  virtual bool readGatewayRecoveryRecordForStateUpload(const ContainerPlan& plan, String& token)
  {
    return ContainerManager::readGatewayRecoveryRecord(plan, token);
  }

  bool gatewayRecoveryRecordAbsentForColdStateUpload(const ContainerPlan& plan) const
  {
    String path = {};
    if (!Container::gatewayReadinessDirectoryPath(plan.uuid, path)) return false;
    path.append("/masque-gateway-recovery.v1"_ctv);
    struct stat record = {};
    return lstat(path.c_str(), &record) != 0 && errno == ENOENT;
  }

  bool bindColdStateUploadGatewayRecovery(ContainerPlan& plan)
  {
    if (!admitCrossClusterMasqueGatewaySystemPlan(plan)) return false;
    auto *runtime = crossClusterMasqueGatewayRuntimeForPair(plan.system.gatewayPairUUID);
    if (runtime == nullptr || !runtime->gatewayBootstrap ||
        (runtime->systemContainerUUID != 0 && runtime->systemContainerUUID != plan.uuid) ||
        runtime->systemPlanAdmitted != (runtime->systemContainerUUID != 0)) return false;

    plan.system.gatewayRecoverySocket.clear();
    plan.system.gatewayRecoveryToken.clear();
    String token = {};
    if (!readGatewayRecoveryRecordForStateUpload(plan, token))
    {
      // An extant malformed record remains a hard fence. The secure writer
      // also refuses replacement if one appears after this absence check.
      if (!gatewayRecoveryRecordAbsentForColdStateUpload(plan)) return false;
      ContainerManager::generateGatewayRecoveryToken(token);
    }
    return prepareCrossClusterMasqueGatewayLaunch(plan, *runtime, token, true);
  }

  bool beginColdStateUploadGatewayRestore(std::unique_ptr<Container> container, uint64_t epoch)
  {
    if (container == nullptr) return false;
    const uint64_t admission = beginPendingContainerLaunch(container->plan);
    if (pendingStateUploadRestores.size() >= maximumPendingStateUploadRestores || admission == 0)
    {
      finishPendingContainerLaunch(container->plan.uuid, admission);
      return false;
    }
    const uint128_t uuid = container->plan.uuid;
    auto operation = std::make_unique<StateUploadRestoreOperation>();
    operation->container = std::move(container);
    operation->fragment = lcsubnet6;
    operation->epoch = epoch;
    operation->stream = brain;
    operation->streamGeneration = brain ? brain->ioGeneration : 0;
    operation->requestedStream = operation->stream;
    operation->requestedGeneration = operation->streamGeneration;
    operation->launchAdmissionGeneration = admission;
    operation->coldRestart = true;
    operation->settled = true;
    ContainerPlan canonical = operation->container->plan;
    canonical.system.gatewayRecoverySocket.clear();
    canonical.system.gatewayRecoveryToken.clear();
    if (!BitseryEngine::serialize(operation->planIdentity, canonical))
    {
      finishPendingContainerLaunch(uuid, admission);
      return false;
    }
    pendingStateUploadRestores.insert_or_assign(uuid, std::move(operation));
    return true;
  }

  void finishColdStateUploadGatewayRestore(uint128_t uuid, bool restart)
  {
    auto found = pendingStateUploadRestores.find(uuid);
    if (found == pendingStateUploadRestores.end() || found->second == nullptr) return;
    StateUploadRestoreOperation& pending = *found->second;
    if (pending.container == nullptr) return;
    bool restarted = false;
    if (!restart)
    {
      if (!retireContainerLaunch(uuid))
      {
        if (brain) { brain->commandsRejected = true; queueCloseIfActive(brain); }
        return;
      }
    }
    else
    {
      Container *raw = pending.container.release();
      restarted = ContainerManager::restartContainer(raw);
      if (!restarted && !retireContainerLaunch(uuid))
      {
        if (brain) { brain->commandsRejected = true; queueCloseIfActive(brain); }
        return;
      }
    }
    std::unique_ptr<StateUploadRestoreOperation> operation = std::move(found->second);
    pendingStateUploadRestores.erase(found);
    finishPendingContainerLaunch(uuid, operation->launchAdmissionGeneration);
    std::unique_ptr<Container> container = std::move(operation->container);
    if (!restart)
      ContainerManager::cleanupContainerAfterFailedCreate(container.release(), true, false);
    String empty = {};
    reportContainerFailed(uuid, 0, 0, empty, restarted);
    if (!stateUploadRestoresPending() && !retainedStateUploadCandidatesPending() && stateUploadRestoreReplyPending)
    {
      stateUploadRestoreReplyPending = false;
      queueNeuronStateUpload();
    }
  }

  void resumeColdStateUploadGatewayRestore(uint128_t uuid)
  {
    auto found = pendingStateUploadRestores.find(uuid);
    if (found == pendingStateUploadRestores.end() || found->second == nullptr) return;
    StateUploadRestoreOperation& operation = *found->second;
    if (!operation.coldRestart || operation.container == nullptr || operation.terminalRetirementPending ||
        !stateUploadRestoreCurrent(operation, uuid)) return;
    const auto *runtime = crossClusterMasqueGatewayRuntimeForPair(operation.container->plan.system.gatewayPairUUID);
    if (runtime == nullptr || runtime->authority.state != CrossClusterMasqueGatewayState::active ||
        !runtime->gatewayBootstrap) return;
    if (!bindColdStateUploadGatewayRecovery(operation.container->plan))
    {
      finishColdStateUploadGatewayRestore(uuid, false);
      return;
    }
    finishColdStateUploadGatewayRestore(uuid, true);
  }

  bool retainedStateUploadCandidatesPending(void) const
  {
    for (const auto& [uuid, operation] : pendingStateUploadRestores)
      if (operation != nullptr && operation->container != nullptr) return true;
    return false;
  }

  uint64_t currentStateUploadRestoreRound(void)
  {
    // Awaiting a gateway receipt is still the same restoration round.
    // Authority replay must not invalidate its already-issued challenge.
    return stateUploadRestoresPending() || retainedStateUploadCandidatesPending()
        ? stateUploadRestoreEpoch : ++stateUploadRestoreEpoch;
  }

  void retrySettledStateUploadGatewayRecoveries(void)
  {
    if (brain == nullptr || !streamIsActive(brain)) return;
    Vector<uint128_t> candidates = {};
    for (const auto& [uuid, operation] : pendingStateUploadRestores)
    {
      if (operation == nullptr || !operation->settled || operation->terminalRetirementPending ||
          operation->container == nullptr || operation->container->pendingDestroy ||
          operation->container->plan.system.kind != SystemContainerKind::crossClusterMasqueGateway)
        continue;
      const auto *runtime = crossClusterMasqueGatewayRuntimeForPair(
          operation->container->plan.system.gatewayPairUUID);
      if (operation->coldRestart || (runtime != nullptr && runtime->authority.pairUUID != 0)) candidates.push_back(uuid);
    }
    if (candidates.empty()) return;
    const uint64_t epoch = currentStateUploadRestoreRound();
    for (uint128_t uuid : candidates)
    {
      auto found = pendingStateUploadRestores.find(uuid);
      if (found == pendingStateUploadRestores.end() || found->second == nullptr ||
          found->second->container == nullptr) continue;
      if (found->second->coldRestart)
      {
        const auto *runtime = crossClusterMasqueGatewayRuntimeForPair(
            found->second->container->plan.system.gatewayPairUUID);
        if (runtime == nullptr)
          continue;
        if (runtime->authority.state != CrossClusterMasqueGatewayState::active)
          (void)retirePendingStateUploadRestore(uuid);
        else
          resumeColdStateUploadGatewayRestore(uuid);
        continue;
      }
      NeuronContainerMetricPolicy metrics = {};
      metrics.scalingDimensionsMask = found->second->container->neuronScalingDimensionsMask;
      metrics.metricsCadenceMs = found->second->container->neuronMetricsCadenceMs;
      if (!admitRepeatedStateUploadRestore(found->second->container->plan, metrics, epoch))
      {
        basics_log("retained MASQUE gateway authority retry remains fenced uuid=%llu\n",
                   (unsigned long long)uuid);
      }
    }
  }

  bool hydrateStateUploadGatewayRecovery(ContainerPlan& plan, String& canonicalIdentity, String& token)
  {
    if (!admitCrossClusterMasqueGatewaySystemPlan(plan)) return false;
    token.clear(); String socket = {};
    if (!readGatewayRecoveryRecordForStateUpload(plan, token) ||
        !ContainerManager::gatewayRecoverySocketPath(plan.uuid, socket) ||
        !ContainerManager::gatewayRecoveryTokenValid(token)) return false;
    plan.system.gatewayRecoverySocket.assign(socket);
    plan.system.gatewayRecoveryToken.assign(token);
    ContainerPlan canonical = plan;
    canonical.system.gatewayRecoverySocket.clear();
    canonical.system.gatewayRecoveryToken.clear();
    canonicalIdentity.clear();
    return BitseryEngine::serialize(canonicalIdentity, canonical);
  }

  void fenceStateUploadGatewayRecovery(StateUploadRestoreOperation& operation)
  {
    if (!operation.settled && stateUploadRestoreRemaining > 0) --stateUploadRestoreRemaining;
    operation.coro.cancelSuspended();
    operation.runner.reset();
    operation.stream = nullptr;
    operation.requestedStream = nullptr;
    operation.streamGeneration = 0;
    operation.requestedGeneration = 0;
    if (operation.container != nullptr)
    {
      operation.container->plan.system.gatewayRecoverySocket.clear();
      operation.container->plan.system.gatewayRecoveryToken.clear();
    }
    operation.settled = true;
    stateUploadRestoreReplyPending = false;
  }

  bool admitRepeatedStateUploadRestore(const ContainerPlan& plan,
      const NeuronContainerMetricPolicy& metrics, uint64_t epoch)
  {
    auto found = pendingStateUploadRestores.find(plan.uuid);
    if (found == pendingStateUploadRestores.end()) return true; // Existing launch owner.
    StateUploadRestoreOperation& operation = *found->second;
    ContainerPlan admittedPlan = plan;
    String identity, token;
    if (operation.coldRestart)
    {
      admittedPlan.system.gatewayRecoverySocket.clear();
      admittedPlan.system.gatewayRecoveryToken.clear();
      if (!BitseryEngine::serialize(identity, admittedPlan) || !operation.container ||
          identity != operation.planIdentity ||
          memcmp(&operation.fragment, &lcsubnet6, sizeof(lcsubnet6)) != 0) return false;
      operation.container->neuronScalingDimensionsMask = metrics.scalingDimensionsMask;
      operation.container->neuronMetricsCadenceMs = metrics.metricsCadenceMs;
      operation.container->plan = std::move(admittedPlan);
      operation.stream = brain;
      operation.streamGeneration = brain ? brain->ioGeneration : 0;
      operation.requestedStream = operation.stream;
      operation.requestedGeneration = operation.streamGeneration;
      operation.epoch = epoch;
      // The complete validated stateUpload batch resumes this candidate.
      return true;
    }
    if (plan.system.kind == SystemContainerKind::crossClusterMasqueGateway)
    {
      if (!hydrateStateUploadGatewayRecovery(admittedPlan, identity, token))
      {
        fenceStateUploadGatewayRecovery(operation);
        return true;
      }
    }
    else if (!BitseryEngine::serialize(identity, admittedPlan)) return false;
    if (!operation.container || identity != operation.planIdentity ||
        memcmp(&operation.fragment, &lcsubnet6, sizeof(lcsubnet6)) != 0) return false;
    if (plan.system.kind == SystemContainerKind::crossClusterMasqueGateway &&
        operation.gatewayRecoveryTokenBound && token != operation.boundGatewayRecoveryToken)
    {
      fenceStateUploadGatewayRecovery(operation);
      return true;
    }
    operation.container->neuronScalingDimensionsMask = metrics.scalingDimensionsMask;
    operation.container->neuronMetricsCadenceMs = metrics.metricsCadenceMs;
    operation.requestedStream = brain;
    operation.requestedGeneration = brain ? brain->ioGeneration : 0;
    if (plan.system.kind == SystemContainerKind::crossClusterMasqueGateway)
    {
      operation.container->plan = std::move(admittedPlan);
      if (!operation.gatewayRecoveryTokenBound)
      {
        operation.boundGatewayRecoveryToken.assign(token);
        operation.gatewayRecoveryTokenBound = true;
      }
    }
    if (operation.settled) resumeStateUploadRestore(operation, plan.uuid, epoch);
    return true;
  }

  bool beginStateUploadRestore(std::unique_ptr<Container> container, uint64_t epoch)
  {
    if (container == nullptr) return false;
    const uint64_t launchAdmissionGeneration = beginPendingContainerLaunch(container->plan);
    if (pendingStateUploadRestores.size() >= maximumPendingStateUploadRestores ||
        launchAdmissionGeneration == 0)
    {
      finishPendingContainerLaunch(container->plan.uuid, launchAdmissionGeneration);
      container->abandonRetainedNetworkForNeuronReplacement();
      return false;
    }
    const uint128_t containerUUID = container->plan.uuid;
    auto operation = std::make_unique<StateUploadRestoreOperation>();
    operation->container = std::move(container);
    operation->launchAdmissionGeneration = launchAdmissionGeneration;
    // A gateway can be fenced before its first asynchronous restore starts
    // (for example, while its authority or durable record is still absent).
    // Preserve the admitting Neuron fragment so a later exact retry is not
    // mistaken for a cross-fragment stateUpload.
    operation->fragment = lcsubnet6;
    operation->epoch = epoch;
    ContainerPlan canonicalPlan = operation->container->plan;
    if (canonicalPlan.system.kind == SystemContainerKind::crossClusterMasqueGateway)
    {
      canonicalPlan.system.gatewayRecoverySocket.clear();
      canonicalPlan.system.gatewayRecoveryToken.clear();
    }
    if (!BitseryEngine::serialize(operation->planIdentity, canonicalPlan))
    {
      finishPendingContainerLaunch(containerUUID, launchAdmissionGeneration);
      return false;
    }
    pendingStateUploadRestores.insert_or_assign(containerUUID, std::move(operation));
    StateUploadRestoreOperation& retainedOperation = *pendingStateUploadRestores.find(containerUUID)->second;
    if (retainedOperation.container->plan.system.kind == SystemContainerKind::crossClusterMasqueGateway)
    {
      String identity = {}, token = {};
      if (!hydrateStateUploadGatewayRecovery(retainedOperation.container->plan, identity, token))
      {
        // The checkpoint carries no durable recovery token/socket. Keep the
        // retained process fenced until exact local recovery evidence exists.
        retainedOperation.settled = true;
        return true;
      }
      if (identity != retainedOperation.planIdentity)
      {
        retainedOperation.settled = true;
        return true;
      }
      retainedOperation.boundGatewayRecoveryToken.assign(token);
      retainedOperation.gatewayRecoveryTokenBound = true;
    }
    resumeStateUploadRestore(retainedOperation, containerUUID, epoch);
    return true;
  }

  bool retirePendingStateUploadRestore(uint128_t containerUUID)
  {
    auto found = pendingStateUploadRestores.find(containerUUID);
    if (found == pendingStateUploadRestores.end() || found->second == nullptr)
    {
      return false;
    }

    StateUploadRestoreOperation *pending = found->second.get();
    if (pending->coldRestart)
    {
      std::unique_ptr<StateUploadRestoreOperation> operation = std::move(found->second);
      pendingStateUploadRestores.erase(found);
      finishPendingContainerLaunch(containerUUID, operation->launchAdmissionGeneration);
      if (operation->container != nullptr)
        ContainerManager::cleanupContainerAfterFailedCreate(operation->container.release(), true, false);
      if (!stateUploadRestoresPending() && !retainedStateUploadCandidatesPending() && stateUploadRestoreReplyPending)
      {
        stateUploadRestoreReplyPending = false;
        queueNeuronStateUpload();
      }
      return true;
    }
    if (pending->container != nullptr && pending->container->pid > 0 &&
        pending->container->pidfd < 0)
    {
      // An adopted process is not this Neuron's child and a numeric PID can be
      // recycled. Without a pidfd, retain the exact candidate and terminal
      // fence without signalling or acknowledging an unproven identity.
      if (pending->settled == false && stateUploadRestoreRemaining > 0)
      {
        --stateUploadRestoreRemaining;
      }
      pending->coro.cancelSuspended();
      pending->runner.reset();
      pending->settled = true;
      pending->terminalRetirementPending = true;
      stateUploadRestoreReplyPending = false;
      return true;
    }

    std::unique_ptr<StateUploadRestoreOperation> operation = std::move(found->second);
    pendingStateUploadRestores.erase(found);
    if (operation->settled == false && stateUploadRestoreRemaining > 0)
    {
      --stateUploadRestoreRemaining;
    }
    operation->coro.cancelSuspended();
    operation->runner.reset();
    finishPendingContainerLaunch(containerUUID, operation->launchAdmissionGeneration);

    std::unique_ptr<Container> ownedContainer = std::move(operation->container);
    if (ownedContainer == nullptr)
    {
      return false;
    }

    // The candidate owns an already-live process but has not entered the
    // published container map. Move it under the ordinary waitid/destroy owner
    // before signalling it, so a kill acknowledgement still means that the
    // exact process has exited and all runtime resources were retired.
    Container *container = ownedContainer.release();
    container->killedOnPurpose = true;
    container->pendingKillAckToBrain = true;
    containers.insert_or_assign(containerUUID, container);
    if (container->pid > 0)
    {
      containerByPid.insert_or_assign(container->pid, container);
    }
    RingDispatcher::installMultiplexee(container, this);

    if (container->pid > 0)
    {
      ContainerManager::queueContainerWaitid(container);
      int signalResult = -1;
#ifdef SYS_pidfd_send_signal
      signalResult = int(syscall(SYS_pidfd_send_signal, container->pidfd, SIGKILL, nullptr, 0));
#else
      errno = ENOSYS;
#endif
      if (signalResult != 0 && errno != ESRCH)
      {
        basics_log("neuron retained restore kill failed uuid=%llu pid=%d errno=%d(%s); retaining lifecycle owner\n",
                   (unsigned long long)containerUUID,
                   int(container->pid),
                   errno,
                   strerror(errno));
      }
    }
    else
    {
      ContainerManager::destroyContainer(container);
    }

    if (!stateUploadRestoresPending() && stateUploadRestoreReplyPending)
    {
      stateUploadRestoreReplyPending = false;
      queueNeuronStateUpload();
    }
    return true;
  }

public:

  void neuronHandler(Message *message)
  {
    if (brain != nullptr && brain->commandsRejected)
    {
      PRODIGY_DEBUG_LOG("neuron brain control reject reason=commands-rejected topic=%u\n", unsigned(message->topic));
      PRODIGY_DEBUG_FLUSH();
      return;
    }
    const NeuronTopic topic = NeuronTopic(message->topic);
    const bool permitsLifecycleBootstrap = topic == NeuronTopic::transportCredentialLifecycle ||
        topic == NeuronTopic::registration;
    const bool currentlyAuthorized = controlTransportCredentials.enabled && brain != nullptr &&
        controlPeerCurrentlyAuthorized(brain->tlsPeerUUID);
    const bool lifecycleAuthorized = controlTransportCredentials.enabled && brain != nullptr && !currentlyAuthorized && permitsLifecycleBootstrap &&
        transportLifecycleControlAuthorized(brain->tlsPeerUUID);
    if (controlTransportCredentials.enabled && (!brain || (!currentlyAuthorized && !lifecycleAuthorized)))
    {
      PRODIGY_DEBUG_LOG(
          "neuron brain control reject reason=credential-gate topic=%u hasBrain=%d permitsLifecycleBootstrap=%d currentlyAuthorized=%d lifecycleAuthorized=%d lifecycleCandidate=%d\n",
          unsigned(message->topic), int(brain != nullptr), int(permitsLifecycleBootstrap), int(currentlyAuthorized),
          int(lifecycleAuthorized), int(brain != nullptr && brain->transportLifecycleCandidate));
      PRODIGY_DEBUG_FLUSH();
      if (brain) { brain->rBuffer.clear(); queueCloseIfActive(brain); }
      return;
    }
    uint8_t *args = message->args;
    uint8_t *terminal = message->terminal();

    if (ProdigyIngressValidation::validateNeuronPayloadForNeuron(message->topic, args, terminal) == false)
    {
      PRODIGY_DEBUG_LOG(
          "neuron brain control reject reason=invalid-payload topic=%u argsBytes=%llu emptyPayload=%d\n",
          unsigned(message->topic),
          (unsigned long long)(terminal >= args ? terminal - args : 0), int(args == terminal));
      PRODIGY_DEBUG_FLUSH();
      if (brain)
      {
        brain->rBuffer.clear();
        queueCloseIfActive(brain);
      }
      return;
    }

    switch (NeuronTopic(message->topic))
    {
      case NeuronTopic::crossClusterPrivateBGPSecretDelivery:
        {
          ProdigyPairPrivateBGPSecretDeliveryResponse response = {};
          Message::extractArg<ArgumentNature::fixed>(args, response.scope.pairUUID);
          Message::extractArg<ArgumentNature::fixed>(args, response.scope.operationUUID);
          Message::extractArg<ArgumentNature::fixed>(args, response.scope.keyEpoch);
          Message::extractArg<ArgumentNature::fixed>(args, response.scope.tunnelSlot);
          Message::extractArg<ArgumentNature::fixed>(args, response.scope.clusterUUID);
          Message::extractArg<ArgumentNature::fixed>(args, response.scope.machineUUID);
          Message::extractArg<ArgumentNature::fixed>(args, response.scope.authorityGeneration);
          Message::extractArg<ArgumentNature::fixed>(args, response.scope.gatewayGeneration);
          Message::extractToStringView(args, response.credential);
          Message::extractToStringView(args, response.gatewayRootCertPem);
          Message::extractToStringView(args, response.localLeafCertPem);
          Message::extractToStringView(args, response.localLeafKeyPem);
          Message::extractToStringView(args, response.peerLeafCertDERHex);
          response.accepted = args == terminal && response.scope.machineUUID == uuid &&
              response.scope.clusterUUID == controlTransportCredentials.self.clusterUUID;
          (void)(response.accepted && installCrossClusterPrivateBGPSecret(response));
          break;
        }
      case NeuronTopic::withdrawCrossClusterPrivateBGPSecret:
        {
          ProdigyPairPrivateBGPSecretScope scope = {};
          Message::extractArg<ArgumentNature::fixed>(args, scope.pairUUID); Message::extractArg<ArgumentNature::fixed>(args, scope.operationUUID);
          Message::extractArg<ArgumentNature::fixed>(args, scope.keyEpoch); Message::extractArg<ArgumentNature::fixed>(args, scope.tunnelSlot);
          Message::extractArg<ArgumentNature::fixed>(args, scope.clusterUUID); Message::extractArg<ArgumentNature::fixed>(args, scope.machineUUID);
          Message::extractArg<ArgumentNature::fixed>(args, scope.authorityGeneration); Message::extractArg<ArgumentNature::fixed>(args, scope.gatewayGeneration);
          const bool acknowledged = args == terminal && scope.machineUUID == uuid &&
              scope.clusterUUID == controlTransportCredentials.self.clusterUUID &&
              withdrawCrossClusterPrivateBGPSecret(scope);
          if (brain && brain->fd >= 0) { Message::construct(brain->wBuffer, NeuronTopic::crossClusterPrivateBGPSecretRevocationAck,
              scope.pairUUID, scope.operationUUID, scope.keyEpoch, scope.tunnelSlot, scope.clusterUUID, scope.machineUUID,
              scope.authorityGeneration, scope.gatewayGeneration, uint8_t(acknowledged)); Ring::queueSend(brain); }
          break;
        }
      case NeuronTopic::crossClusterMasqueGatewayAuthoritySnapshot:
        {
          String encoded = {};
          Message::extractToStringView(args, encoded);
          ProdigyCrossClusterMasqueGatewayAuthorityProjection projection = {};
          if (args != terminal || !BitseryEngine::deserializeSafe(encoded, projection) ||
              !reconcileCrossClusterMasqueGatewayAuthorityProjection(projection))
          { if (brain) queueCloseIfActive(brain); }
          break;
        }
      case NeuronTopic::crossClusterPathFault:
        {
          String encoded = {}; Message::extractToStringView(args, encoded);
          ProdigyCrossClusterPathFaultControl control = {};
          if (args != terminal || !BitseryEngine::deserializeSafe(encoded, control) ||
              !prodigyCrossClusterPathFaultControlValid(control) || control.response) {
            if (brain) queueCloseIfActive(brain); break;
          }
          auto *runtime = crossClusterMasqueGatewayRuntimeForPair(control.request.authority.pairUUID);
          if (runtime && !runtime->faultLeaseActive && runtime->authorityMatches(control.request.authority) &&
              control.action != ProdigyCrossClusterPathFaultGatewayAction::pause &&
              prodigyCrossClusterPathFaultRequestEqual(runtime->completedFaultLease, control.request)) {
            control.response = true;
            control.sessionReady = prodigyCrossClusterMasqueGatewayReady(runtime->authority, &runtime->readiness);
            control.bgpReady = runtime->privateTunnelBGP && runtime->privateTunnelBGP->desiredPaths().size() == 1 &&
                prodigyCrossClusterPrivateTunnelBGPPathUsable(runtime->privateTunnelBGP->desiredPaths()[0]);
            control.accepted = control.sessionReady && control.bgpReady;
            encoded.clear(); if (brain && brain->fd >= 0 && BitseryEngine::serialize(encoded, control)) {
              Message::construct(brain->wBuffer, NeuronTopic::crossClusterPathFault, encoded); Ring::queueSend(brain);
            }
            break;
          }
          if (!queueCrossClusterPathFaultGatewayControl(control) && brain && brain->fd >= 0) {
            control.response = true; control.accepted = false; control.sessionReady = false; control.bgpReady = false;
            encoded.clear(); if (BitseryEngine::serialize(encoded, control)) {
              Message::construct(brain->wBuffer, NeuronTopic::crossClusterPathFault, encoded); Ring::queueSend(brain);
            }
          }
          break;
        }
      case NeuronTopic::transportCredentialLifecycle:
        {
          uint128_t nonce = 0;
          String serialized;
          Message::extractArg<ArgumentNature::fixed>(args, nonce);
          Message::extractToStringView(args, serialized);
          ProdigyTransportCredentialLifecycleProjection projection;
          if (!BitseryEngine::deserializeSafe(serialized, projection) ||
              !prodigyTransportCredentialLifecycleProjectionValid(projection))
          { if (brain) queueCloseIfActive(brain); break; }
          receiveTransportCredentialLifecycleProjection(nonce, projection);
          break;
        }
      case NeuronTopic::transportCredentialPeers:
        {
          uint128_t nonce = 0;
          String serialized;
          Message::extractArg<ArgumentNature::fixed>(args, nonce);
          Message::extractToStringView(args, serialized);
          ProdigyTransportCredentialBootstrap projection = {};
          if (!BitseryEngine::deserializeSafe(serialized, projection) ||
              !prodigyTransportCredentialBootstrapValid(projection, false))
          { if (brain) queueCloseIfActive(brain); break; }
          receiveTransportCredentialPeerProjection(nonce, projection);
          break;
        }
      case NeuronTopic::clusterPairControlCredentials:
        {
          uint128_t nonce = 0;
          String serialized;
          Message::extractArg<ArgumentNature::fixed>(args, nonce);
          Message::extractToStringView(args, serialized);
          ProdigyLocalClusterPairControlProjection projection = {};
          if (!BitseryEngine::deserializeSafe(serialized, projection) ||
              !prodigyLocalClusterPairControlProjectionValid(projection, true))
          { if (brain) queueCloseIfActive(brain); break; }
          receiveClusterPairControlProjection(nonce, projection);
          break;
        }
      case NeuronTopic::cousinDiscoverySnapshot:
        {
          String serialized = {};
          Message::extractToStringView(args, serialized);
          ProdigyCousinDiscoveryPublication publication = {};
          if (!BitseryEngine::deserializeSafe(serialized, publication) ||
              !prodigyCousinDiscoveryPublicationValid(publication))
          { if (brain) queueCloseIfActive(brain); break; }
          receiveCousinDiscoverySnapshot(publication);
          break;
        }
      case NeuronTopic::cousinSessionCommand:
        {
          uint128_t containerUUID = 0; String serialized = {};
          Message::extractArg<ArgumentNature::fixed>(args, containerUUID);
          Message::extractToStringView(args, serialized);
          ProdigyCousinSessionLocalCommand command = {};
          if (args != terminal || !BitseryEngine::deserializeSafe(serialized, command) ||
              !prodigyCousinSessionLocalCommandValid(command)) { if (brain) queueCloseIfActive(brain); break; }
          receiveCousinSessionLocalCommand(containerUUID, command);
          break;
        }
      case NeuronTopic::nametagHandoffBarrier:
        {
          uint128_t containerUUID = 0; String encoded = {};
          Message::extractArg<ArgumentNature::fixed>(args, containerUUID); Message::extractToStringView(args, encoded);
          ProdigyNametagHandoffBarrier barrier = {}; auto live = containers.find(containerUUID);
          if (args != terminal || live == containers.end() || !live->second || live->second->pendingDestroy ||
              !live->second->plan.runtimeReady || !BitseryEngine::deserializeSafe(encoded, barrier) ||
              !prodigyNametagHandoffBarrierValid(barrier) || barrier.clusterUUID != controlTransportCredentials.self.clusterUUID ||
              barrier.deadlineMilliseconds <= Time::now<TimeResolution::ms>() ||
              (barrier.response ? (containerUUID != barrier.probeContainerUUID || live->second->plan.config.applicationID != 11 ||
                  barrier.probeDeploymentID != live->second->plan.config.deploymentID()) :
                 (containerUUID != barrier.appContainerUUID || live->second->plan.config.applicationID != 6 ||
                  barrier.appDeploymentID != live->second->plan.config.deploymentID()))) {
            if (brain) queueCloseIfActive(brain); break;
          }
          Message::construct(live->second->wBuffer, ContainerTopic::nametagHandoffBarrier, encoded);
          if (streamIsActive(live->second)) Ring::queueSend(live->second);
          break;
        }
      case NeuronTopic::nametagQualificationApplicationCommand:
        {
          // The Brain sender frames the immutable execution tuple as
          // { exactContainerUUID, serializedCommand }.  This Neuron does not
          // reinterpret or enrich it; its role is solely to bind the command
          // to the currently authenticated local App11 control socket.
          uint128_t containerUUID = 0;
          String encoded = {};
          Message::extractArg<ArgumentNature::fixed>(args, containerUUID);
          Message::extractToStringView(args, encoded);
          ProdigyNametagQualificationApplicationCommand command = {};
          auto live = containers.find(containerUUID);
          if (args != terminal || live == containers.end() || live->second == nullptr ||
              live->second->pendingDestroy || !live->second->plan.runtimeReady ||
              !BitseryEngine::deserializeSafe(encoded, command) ||
              !prodigyNametagQualificationApplicationCommandValid(command) ||
              command.localClusterUUID != controlTransportCredentials.self.clusterUUID ||
              command.deploymentID != live->second->plan.config.deploymentID() ||
              live->second->plan.config.applicationID != 11)
          {
            if (brain) queueCloseIfActive(brain);
            break;
          }
          Message::construct(live->second->wBuffer,
                             ContainerTopic::nametagQualificationApplicationCommand, encoded);
          if (streamIsActive(live->second)) Ring::queueSend(live->second);
          break;
        }
      case NeuronTopic::nametagSourceBaseline:
        {
          uint128_t containerUUID = 0; String encoded = {};
          Message::extractArg<ArgumentNature::fixed>(args, containerUUID); Message::extractToStringView(args, encoded);
          ProdigyNametagSourceBaselineEnvelope envelope = {}; auto live = containers.find(containerUUID);
          if (args != terminal || live == containers.end() || live->second == nullptr || live->second->pendingDestroy ||
              !live->second->plan.runtimeReady || !BitseryEngine::deserializeSafe(encoded, envelope) ||
              !prodigyNametagSourceBaselineEnvelopeValid(envelope) ||
              (envelope.direction != ProdigyNametagSourceBaselineDirection::execute && envelope.direction != ProdigyNametagSourceBaselineDirection::query) ||
              envelope.command.ewrClusterUUID != controlTransportCredentials.self.clusterUUID ||
              envelope.command.probeDeploymentID != live->second->plan.config.deploymentID() ||
              live->second->plan.config.applicationID != 11) { if (brain) queueCloseIfActive(brain); break; }
          Message::construct(live->second->wBuffer, ContainerTopic::nametagSourceBaseline, encoded);
          if (streamIsActive(live->second)) Ring::queueSend(live->second);
          break;
        }
      case NeuronTopic::nametagQualificationMachineBoot:
        {
          String encoded = {}; Message::extractToStringView(args, encoded);
          ProdigyNametagQualificationMachineBoot request = {};
          if (args != terminal || !brain || !controlTransportCredentials.enabled ||
              !controlPeerCurrentlyAuthorized(brain->tlsPeerUUID) || !BitseryEngine::deserializeSafe(encoded, request) || request.response ||
              !prodigyNametagQualificationMachineBootValid(request) || request.machineUUID != uuid ||
              request.clusterUUID != controlTransportCredentials.self.clusterUUID ||
              request.deadlineAtMilliseconds <= Time::now<TimeResolution::ms>()) { if (brain) queueCloseIfActive(brain); break; }
          auto response = request; response.response = true;
          char boot[38] = {}; int fd = ::open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
          const ssize_t count = fd < 0 ? -1 : ::read(fd, boot, sizeof(boot)); if (fd >= 0) ::close(fd);
          if (count == 37 && boot[36] == '\n') { response.bootID.assign(boot, 36); response.ready = true; }
          if (!response.ready || !prodigyNametagQualificationMachineBootValid(response)) {
            response.bootID.clear(); response.ready = false; response.failure.assign("kernel boot identity unavailable"_ctv);
          }
          String reply; if (!BitseryEngine::serialize(reply, response)) break;
          Message::construct(brain->wBuffer, NeuronTopic::nametagQualificationMachineBoot, reply);
          Ring::queueSend(brain); break;
        }
      case NeuronTopic::nametagQualificationSeedFault:
        {
          uint128_t uuid = 0; String encoded = {};
          Message::extractArg<ArgumentNature::fixed>(args, uuid); Message::extractToStringView(args, encoded);
          ProdigyNametagQualificationSeedFault witness = {}; auto live = containers.find(uuid);
          NeuronBrainControlStream *stream = brain;
          if (args != terminal || !stream || !controlPeerCurrentlyAuthorized(stream->tlsPeerUUID) ||
              !transportPeerProjectionControlCurrent(stream, stream->ioGeneration, stream->tlsPeerUUID) ||
              live == containers.end() || !live->second || live->second->pendingDestroy || !live->second->plan.runtimeReady ||
              !BitseryEngine::deserializeSafe(encoded, witness) || witness.response ||
              !prodigyNametagQualificationSeedFaultValid(witness) || witness.deadlineAtMilliseconds <= Time::now<TimeResolution::ms>() ||
              witness.authority.targetContainerUUID != uuid ||
              witness.authority.targetClusterUUID != controlTransportCredentials.self.clusterUUID ||
              witness.authority.targetDeploymentID != live->second->plan.config.deploymentID() ||
              witness.authority.applicationID != live->second->plan.config.applicationID) break;
          Message::construct(live->second->wBuffer, ContainerTopic::nametagQualificationSeedFault, encoded);
          if (streamIsActive(live->second)) Ring::queueSend(live->second);
          break;
        }
      case NeuronTopic::nametagQualificationReplay:
        {
          uint128_t uuid = 0; String encoded = {};
          Message::extractArg<ArgumentNature::fixed>(args, uuid); Message::extractToStringView(args, encoded);
          ProdigyNametagQualificationReplay witness = {}; auto live = containers.find(uuid);
          NeuronBrainControlStream *stream = brain;
          if (args != terminal || !stream || !controlPeerCurrentlyAuthorized(stream->tlsPeerUUID) ||
              !transportPeerProjectionControlCurrent(stream, stream->ioGeneration, stream->tlsPeerUUID) ||
              live == containers.end() || !live->second || live->second->pendingDestroy || !live->second->plan.runtimeReady ||
              !BitseryEngine::deserializeSafe(encoded, witness) || witness.response ||
              !prodigyNametagQualificationReplayValid(witness) || !prodigyNametagQualificationReplayRelayTimely(witness, Time::now<TimeResolution::ms>()) ||
              (prodigyNametagQualificationReplayLocalHalf(witness.store, witness.targetSide) == CousinRouteHalf::source ? witness.session.sourceContainerUUID : witness.session.destinationContainerUUID) != uuid ||
              (prodigyNametagQualificationReplayLocalHalf(witness.store, witness.targetSide) == CousinRouteHalf::source ? witness.session.sourceClusterUUID : witness.session.destinationClusterUUID) != controlTransportCredentials.self.clusterUUID ||
              (prodigyNametagQualificationReplayLocalHalf(witness.store, witness.targetSide) == CousinRouteHalf::source ? witness.session.sourceDeploymentID : witness.session.destinationDeploymentID) != live->second->plan.config.deploymentID()) break;
          Message::construct(live->second->wBuffer, ContainerTopic::nametagQualificationReplay, encoded);
          if (streamIsActive(live->second)) Ring::queueSend(live->second);
          break;
        }
      case NeuronTopic::nametagQualificationWriterIsolation:
        {
          uint128_t uuid = 0; String encoded = {};
          Message::extractArg<ArgumentNature::fixed>(args, uuid); Message::extractToStringView(args, encoded);
          ProdigyNametagQualificationWriterIsolation request = {}; auto found = containers.find(uuid);
          NeuronBrainControlStream *stream = brain;
          if (args != terminal || !stream || !controlPeerCurrentlyAuthorized(stream->tlsPeerUUID) ||
              !transportPeerProjectionControlCurrent(stream, stream->ioGeneration, stream->tlsPeerUUID) ||
              found == containers.end() || !found->second || found->second->pendingDestroy ||
              !BitseryEngine::deserializeSafe(encoded, request) || request.response ||
              !prodigyNametagQualificationWriterIsolationValid(request)) break;
          const int64_t wallNow = Time::now<TimeResolution::ms>();
          if (request.deadlineAtMilliseconds <= wallNow &&
              (request.stage != ProdigyNametagQualificationWriterIsolationStage::release ||
               wallNow - request.deadlineAtMilliseconds > 60000)) break;
          Container *target = found->second;
          if (request.clusterUUID != controlTransportCredentials.self.clusterUUID ||
              request.targetMachineUUID != controlTransportCredentials.self.nodeUUID || request.targetContainerUUID != uuid ||
              request.deploymentID != target->plan.config.deploymentID() ||
              request.applicationID != target->plan.config.applicationID || request.shardGroup != target->plan.shardGroup ||
              !target->plan.isStateful || !target->plan.runtimeReady || target->plan.state != ContainerState::healthy ||
              target->plan.useHostNetworkNamespace || !prodigyValidateContainerPlanMeshIdentity(target->plan, lcsubnet6)) break;
          uint32_t matchingAddresses = 0;
          for (const auto& address : target->plan.addresses) {
            uint128_t value = 0;
            if (!address.network.is6 || address.cidr != 128) continue;
            std::memcpy(&value, address.network.v6, sizeof(value));
            if (value == request.targetAddress) ++matchingAddresses;
          }
          if (matchingAddresses != 1 || !Container::containerNetworkPolicyMapCompatible(target->peer_program) ||
              !Container::containerNetworkPolicyMapCompatible(target->primary_program)) break;
          const uint64_t now = monotonicNowNs(); if (!now) break;
          auto response = request; response.response = true;
          auto sameArm = [&]() {
            auto left = target->qualificationIsolationArm, right = request;
            right.stage = ProdigyNametagQualificationWriterIsolationStage::arm;
            String a = {}, b = {};
            return BitseryEngine::serialize(a, left) && BitseryEngine::serialize(b, right) && a == b;
          };
          if (request.stage == ProdigyNametagQualificationWriterIsolationStage::arm) {
            uint128_t existingOwner = 0; uint64_t existingDeadline = 0;
            if (!target->qualificationIsolationState(existingOwner, existingDeadline)) break;
            // After an owner restart, an unexpired kernel lease remains effective;
            // its lost in-memory context must not be replaced or prolonged.
            if (existingDeadline > now && (!target->qualificationIsolationArm.challengeUUID ||
                                           existingOwner != request.challengeUUID)) break;
            if ((target->qualificationIsolationDeadlineNs && target->qualificationIsolationDeadlineNs <= now) ||
                (target->qualificationIsolationArm.challengeUUID && existingDeadline <= now &&
                 target->qualificationIsolationArm.deadlineAtMilliseconds <= Time::now<TimeResolution::ms>())) {
              target->qualificationIsolationArm = {}; target->qualificationIsolationDeadlineNs = 0;
            }
            if (target->qualificationIsolationArm.challengeUUID && !sameArm()) break;
            target->qualificationIsolationArm = request; response.ready = true;
          } else {
            if (!sameArm()) break;
            if (request.stage == ProdigyNametagQualificationWriterIsolationStage::isolate) {
              if (!target->qualificationIsolationDeadlineNs) {
                const int64_t remaining = request.deadlineAtMilliseconds - Time::now<TimeResolution::ms>();
                if (remaining <= 0) break;
                const uint64_t remainingMs = uint64_t(remaining);
                const uint64_t durationMs = std::min<uint64_t>(request.validForMilliseconds, remainingMs);
                if (!durationMs) break;
                target->qualificationIsolationDeadlineNs = now + durationMs * 1'000'000ULL;
              }
              if (!target->applyQualificationIsolation(request.challengeUUID, now,
                                                       target->qualificationIsolationDeadlineNs, false)) break;
              bool active = false;
              if (!target->qualificationIsolationActive(request.challengeUUID, now, active) || !active) break;
              response.ready = response.isolated = true;
            } else if (request.stage == ProdigyNametagQualificationWriterIsolationStage::query) {
              bool active = false;
              if (!target->qualificationIsolationActive(request.challengeUUID, now, active)) break;
              response.ready = true; response.isolated = active;
            } else if (request.stage == ProdigyNametagQualificationWriterIsolationStage::release) {
              uint128_t owner = 0; uint64_t deadline = 0;
              if (!target->qualificationIsolationState(owner, deadline)) break;
              if (owner == request.challengeUUID) {
                if (!target->applyQualificationIsolation(request.challengeUUID, now, 0, true)) break;
              } else if (deadline > now) break;
              target->qualificationIsolationArm = {}; target->qualificationIsolationDeadlineNs = 0;
              response.ready = true;
            } else break;
          }
          String reply = {};
          if (!prodigyNametagQualificationWriterIsolationValid(response) || !BitseryEngine::serialize(reply, response)) break;
          Message::construct(stream->wBuffer, NeuronTopic::nametagQualificationWriterIsolation, uuid, reply);
          if (streamIsActive(stream)) Ring::queueSend(stream);
          break;
        }
      case NeuronTopic::nametagQualificationCousinTransport:
        {
          uint128_t uuid = 0; String encoded = {};
          Message::extractArg<ArgumentNature::fixed>(args, uuid); Message::extractToStringView(args, encoded);
          ProdigyNametagQualificationCousinTransport witness = {}; auto live = containers.find(uuid);
          NeuronBrainControlStream *stream = brain;
          if (args != terminal || !stream || !controlPeerCurrentlyAuthorized(stream->tlsPeerUUID) ||
              !transportPeerProjectionControlCurrent(stream, stream->ioGeneration, stream->tlsPeerUUID) ||
              live == containers.end() || !live->second || live->second->pendingDestroy || !live->second->plan.runtimeReady ||
              !BitseryEngine::deserializeSafe(encoded, witness) || witness.response ||
              !prodigyNametagQualificationCousinTransportValid(witness) ||
              witness.deadlineAtMilliseconds <= Time::now<TimeResolution::ms>() ||
              witness.session.sourceContainerUUID != uuid ||
              witness.session.sourceClusterUUID != controlTransportCredentials.self.clusterUUID ||
              witness.session.sourceDeploymentID != live->second->plan.config.deploymentID()) break;
          Message::construct(live->second->wBuffer, ContainerTopic::nametagQualificationCousinTransport, encoded);
          if (streamIsActive(live->second)) Ring::queueSend(live->second);
          break;
        }
      case NeuronTopic::statefulStoreSourceCut:
        {
          uint128_t uuid = 0; String encoded = {};
          Message::extractArg<ArgumentNature::fixed>(args, uuid); Message::extractToStringView(args, encoded);
          ProdigyStatefulStoreSourceCut cut = {}; auto live = containers.find(uuid);
          NeuronBrainControlStream *stream = brain;
          if (args != terminal || !stream || !controlPeerCurrentlyAuthorized(stream->tlsPeerUUID) ||
              !transportPeerProjectionControlCurrent(stream, stream->ioGeneration, stream->tlsPeerUUID) ||
              live == containers.end() || !live->second || live->second->pendingDestroy ||
              !BitseryEngine::deserializeSafe(encoded, cut) || cut.response || cut.memberRequestUUID == 0 ||
              !prodigyStatefulStoreSourceCutValid(cut) || cut.sourceContainerUUID != uuid ||
              cut.sourceClusterUUID != controlTransportCredentials.self.clusterUUID ||
              cut.sourceDeploymentID != live->second->plan.config.deploymentID() ||
              cut.applicationID != live->second->plan.config.applicationID ||
              cut.shardGroup != live->second->plan.shardGroup || cut.nShardGroups != live->second->plan.nShardGroups) break;
          Message::construct(live->second->wBuffer, ContainerTopic::statefulStoreSourceCut, encoded);
          if (streamIsActive(live->second)) Ring::queueSend(live->second);
          break;
        }
      case NeuronTopic::statefulDataAuthority:
        {
          uint128_t uuid = 0;
          String encoded;
          Message::extractArg<ArgumentNature::fixed>(args, uuid);
          Message::extractToStringView(args, encoded);
          StatefulDataAuthorityPreparation preparation;
          if (args == terminal && BitseryEngine::deserializeSafe(encoded, preparation) && !preparation.response &&
              preparation.memberRequestUUID != 0 && prodigyStatefulDataAuthorityPreparationValid(preparation)) {
            auto current = containers.find(uuid);
            if (current == containers.end() || !current->second ||
                current->second->plan.config.applicationID != preparation.applicationID ||
                current->second->plan.config.deploymentID() != preparation.deploymentID ||
                current->second->plan.shardGroup != preparation.shardGroup ||
                current->second->plan.nShardGroups != preparation.nShardGroups ||
                preparation.clusterUUID != controlTransportCredentials.self.clusterUUID) break;
            current->second->statefulPreparationRequest = preparation;
            Message::construct(current->second->wBuffer, ContainerTopic::statefulDataAuthority, encoded);
            Ring::queueSend(current->second);
            break;
          }
          StatefulDataAuthorityReceipt command;
          auto live = containers.find(uuid);
          if (args != terminal || live == containers.end() || !live->second ||
              !BitseryEngine::deserializeSafe(encoded, command) || command.ready ||
              !command.snapshotReceiptSHA256.empty() || !command.appliedWatermarkSHA256.empty() ||
              !command.fenceReceiptSHA256.empty() || !command.cleanupReceiptSHA256.empty() || !prodigyStatefulDataAuthorityValid(command.authority) ||
              (live->second->plan.config.applicationID != 3 && live->second->plan.config.applicationID != 4) ||
              live->second->plan.shardGroup != command.authority.shardGroup ||
              command.authority.localClusterUUID != controlTransportCredentials.self.clusterUUID) break;
          auto& topology = live->second->plan.statefulTopology;
          if (topology.servingMode == StatefulTopologyServingMode::applicationDataAuthority
              ? !prodigyStatefulDataAuthorityCanAdvance(topology.dataAuthority, command.authority)
              : command.authority.mode != StatefulDataAuthorityMode::snapshotPreparing) break;
          // Brain sends this projection only after its existing durable serving
          // package and exact cohort have peer ACKs. That package is the plan
          // persistence owner; Neuron updates its retained inventory projection.
          topology.servingMode = StatefulTopologyServingMode::applicationDataAuthority;
          topology.dataAuthority = command.authority;
          Message::construct(live->second->wBuffer, ContainerTopic::statefulDataAuthority, encoded);
          Ring::queueSend(live->second);
          break;
        }
      case NeuronTopic::globalSingleWriterControl:
        {
          uint128_t uuid = 0; String bytes;
          Message::extractArg<ArgumentNature::fixed>(args,uuid); Message::extractToStringView(args,bytes);
          auto live = containers.find(uuid);
          ProdigyGlobalSingleWriterControl command{};
          if (args != terminal || live == containers.end() || !live->second || live->second->pendingDestroy ||
              !prodigyGlobalSingleWriterContainerPlanValid(live->second->plan) || !BitseryEngine::deserializeSafe(bytes,command) ||
              !prodigyGlobalSingleWriterControlRequestValid(command) || !command.exchangeUUID || command.containerUUID != uuid ||
              !prodigyGlobalSingleWriterControlForProjection(command,command.bindings) ||
              command.membershipUUID != live->second->plan.globalSingleWriterMembership.membershipUUID ||
              command.localClusterUUID != controlTransportCredentials.self.clusterUUID ||
              command.deploymentID != live->second->plan.config.deploymentID() ||
              !streamIsActive(live->second)) {
            basics_log("neuron globalSingleWriterControl reject stage=request-validation member=%d\n", command.memberID);
            break;
          }
          Message::construct(live->second->wBuffer,ContainerTopic::globalSingleWriterControl,bytes);
          Ring::queueSend(live->second);
          break;
        }
      case NeuronTopic::statefulStoreProofRecovery:
        {
          uint128_t uuid = 0; String encoded = {};
          Message::extractArg<ArgumentNature::fixed>(args, uuid);
          Message::extractToStringView(args, encoded);
          ProdigyStatefulStoreProofRecovery request = {};
          auto live = containers.find(uuid);
          if (args != terminal || live == containers.end() || !live->second ||
              !BitseryEngine::deserializeSafe(encoded, request) || request.response ||
              !prodigyStatefulStoreProofRecoveryValid(request) || request.authority.targetContainerUUID != uuid ||
              request.authority.targetClusterUUID != controlTransportCredentials.self.clusterUUID ||
              request.authority.targetDeploymentID != live->second->plan.config.deploymentID() ||
              request.authority.applicationID != live->second->plan.config.applicationID ||
              request.authority.shardGroup != live->second->plan.shardGroup ||
              request.authority.nShardGroups != live->second->plan.nShardGroups) break;
          Message::construct(live->second->wBuffer, ContainerTopic::statefulStoreProofRecovery, encoded);
          Ring::queueSend(live->second);
          break;
        }
      case NeuronTopic::statefulStoreSeedAuthority:
        {
          uint128_t uuid = 0; String encoded = {};
          Message::extractArg<ArgumentNature::fixed>(args, uuid);
          Message::extractToStringView(args, encoded);
          ProdigyStatefulStoreSeedAuthority authority = {};
          auto live = containers.find(uuid);
          if (args != terminal || live == containers.end() || !live->second ||
              !BitseryEngine::deserializeSafe(encoded, authority) || !prodigyStatefulStoreSeedAuthorityValid(authority) ||
              authority.targetContainerUUID != uuid || authority.targetClusterUUID != controlTransportCredentials.self.clusterUUID ||
              authority.targetDeploymentID != live->second->plan.config.deploymentID() ||
              authority.applicationID != live->second->plan.config.applicationID ||
              authority.shardGroup != live->second->plan.shardGroup || authority.nShardGroups != live->second->plan.nShardGroups) break;
          Message::construct(live->second->wBuffer, ContainerTopic::statefulStoreSeedAuthority, encoded);
          Ring::queueSend(live->second);
          break;
        }
      case NeuronTopic::cousinSessionControlSend:
        {
          String serialized = {}; Message::extractToStringView(args, serialized);
          ProdigyCousinSessionPublication publication = {};
          if (args != terminal || !BitseryEngine::deserializeSafe(serialized, publication) ||
              !prodigyCousinSessionPublicationValid(publication)) { if (brain) queueCloseIfActive(brain); break; }
          receiveCousinSessionControl(publication);
          break;
        }
      case NeuronTopic::cousinAdmissionCommand:
        {
          String serialized = {}; Message::extractToStringView(args, serialized);
          ProdigyCousinAdmissionCommand command = {};
          NeuronBrainControlStream *stream = brain;
          const uint64_t generation = stream ? stream->ioGeneration : 0;
          const uint128_t peerUUID = stream ? stream->tlsPeerUUID : 0;
          if (args != terminal || !BitseryEngine::deserializeSafe(serialized, command) ||
              !prodigyCousinAdmissionCommandValid(command) ||
              command.session.destination.permission.localClusterUUID != controlTransportCredentials.self.clusterUUID ||
              !cousinSessionCarrierCurrent(stream, generation, peerUUID)) { if (brain) queueCloseIfActive(brain); break; }
          ProdigyCousinAdmissionAck acknowledgement = {};
          const bool applied = installCousinAdmissionCommand(command, acknowledgement);
          acknowledgement.success = applied;
          if (!applied && acknowledgement.failure.empty()) acknowledgement.failure.assign("cousin admission rejected"_ctv);
          String encoded = {};
          if (BitseryEngine::serialize(encoded, acknowledgement) && encoded.size() <= ProdigyCousinSessionMaximumBytes &&
              cousinSessionCarrierCurrent(stream, generation, peerUUID)) {
            Message::construct(stream->wBuffer, NeuronTopic::cousinAdmissionAck, encoded);
            Ring::queueSend(stream);
          }
          break;
        }
      case NeuronTopic::registration:
        {
          if (brain && brain->transportLifecycleCandidate)
          {
            queueAttestedInitialBrainControlFrames(brain);
            break;
          }
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
          retireCompletedStateUploadRestores();
          // fragment(4, 1) containerPlan{4}...
          struct local_container_subnet6 uploadedFragment = {};
          Message::extractBytes<Alignment::one>(args, (uint8_t *)&uploadedFragment, sizeof(struct local_container_subnet6));
          const bool hadFragments = haveFragments();
          const bool fragmentChanged = (memcmp(&lcsubnet6, &uploadedFragment, sizeof(uploadedFragment)) != 0);
          if ((stateUploadRestoreRemaining != 0 || retainedStateUploadCandidatesPending()) && fragmentChanged)
          {
            // A pending restore is bound to its assigned fragment. Let the
            // normal reconnect path obtain a fresh authoritative upload
            // rather than publishing either generation under the other.
            std::fprintf(stderr,
                         "neuron stateUpload rejected reason=pending-restore-fragment-changed\n");
            std::fflush(stderr);
            if (brain)
            {
              brain->rBuffer.clear();
              queueCloseIfActive(brain);
            }
            break;
          }
          const uint64_t restoreEpoch = currentStateUploadRestoreRound();
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

          // Container re-adoption carries several large domain values. Keep
          // them in a separate non-inlined frame so the bounded control
          // dispatcher does not reserve that storage for every Neuron topic.
          const char *stateUploadRejection = "unknown";
          auto applyStateUploadPlans = [this, &args, terminal, restoreEpoch, &stateUploadRejection]() __attribute__((noinline)) -> bool {
            bool malformedStateUpload = false;
            while (args < terminal) // it's possible that some of these containers died right?
            {
            String buffer;
            Message::extractToStringView(args, buffer);
            if (buffer.data() > terminal || buffer.size() > uint64_t(terminal - buffer.data()))
            {
              stateUploadRejection = "plan-frame-bounds";
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
              stateUploadRejection = "plan-decode";
              malformedStateUpload = true;
              break;
            }

            if (isContainerLaunchRetired(restoredPlan.uuid))
            {
              if (containers.contains(restoredPlan.uuid) ||
                  pendingStateUploadRestores.contains(restoredPlan.uuid))
              {
                // An explicit kill can still be draining the live owner. Its
                // normal close/waitid path owns the terminal acknowledgement.
                continue;
              }
              // Re-acknowledge the terminal decision after a repeated upload.
              // A queued spin carrying this UUID is stale and must stay fenced.
              String empty = {};
              reportContainerFailed(restoredPlan.uuid, 0, 0, empty, false);
              continue;
            }
            if (isPendingContainerLaunch(restoredPlan.uuid))
            {
              if (pendingContainerLaunchIsCurrent(restoredPlan.uuid,
                                                  containerLaunchControlGeneration) == false)
              {
                // The previous worker may still own cgroup/rootfs cleanup.
                // Retain this exact authenticated replay until its final
                // pending-launch callback marks the UUID drained; no second
                // worker may materialize the same UUID concurrently.
                const uint128_t replayUUID = restoredPlan.uuid;
                if (!queuePendingContainerLaunchReplay(std::move(restoredPlan), metricPolicy))
                {
                  stateUploadRejection = "pending-replay-identity";
                  malformedStateUpload = true;
                  break;
                }
                if (pendingContainerLaunchIsDrained(replayUUID))
                {
                  resumeDrainedPendingContainerLaunchReplay(replayUUID);
                }
                continue;
              }
              if (!admitRepeatedStateUploadRestore(restoredPlan, metricPolicy, restoreEpoch))
              {
                stateUploadRejection = "repeat-restore-admission";
                malformedStateUpload = true;
                break;
              }
              // The same UUID is still owned by a suspended spin coroutine.
              // Re-adoption is idempotent: wait for that launch rather than
              // manufacturing an absent-launch failure.
              continue;
            }
            if (auto existing = containers.find(restoredPlan.uuid); existing != containers.end() && existing->second != nullptr)
            {
              Container *liveContainer = existing->second;
              if (liveContainer->pendingDestroy == false)
              {
                liveContainer->neuronScalingDimensionsMask = metricPolicy.scalingDimensionsMask;
                liveContainer->neuronMetricsCadenceMs = metricPolicy.metricsCadenceMs;
                // A fresh host router has no static Whitehole bindings. Rehydrate
                // them from the locally owned live plan before skipping this
                // idempotent state-upload entry.
                if (liveContainer->plan.whiteholes.empty() == false)
                {
                  openWhiteholesForLocalContainer(liveContainer->plan.fragment,
                                                  liveContainer->plan.whiteholes);
                }
                basics_log("neuron stateUpload skipped existing live container uuid=%llu pid=%d state=%u\n",
                           (unsigned long long)liveContainer->plan.uuid,
                           int(liveContainer->pid),
                           unsigned(liveContainer->plan.state));
                continue;
              }
            }
            if (auto quarantined = quarantinedContainerNetworks.find(restoredPlan.uuid);
                quarantined != quarantinedContainerNetworks.end())
            {
              Container *retained = quarantined->second;
              if (retained == nullptr || retained->plan.uuid != restoredPlan.uuid ||
                  retained->networkQuarantineRetained == false)
              {
                stateUploadRejection = "quarantined-owner-invalid";
                malformedStateUpload = true;
                break;
              }
              basics_log("neuron stateUpload skipped quarantined container network uuid=%llu state=%u\n",
                         (unsigned long long)retained->plan.uuid,
                         unsigned(retained->plan.state));
              continue;
            }

            uint32_t userID = 0;
            uint32_t executionHostID = 0;
            if (prodigyDeriveContainerHostIDs(restoredPlan, userID, executionHostID) == false)
            {
              stateUploadRejection = "container-host-id-derivation";
              malformedStateUpload = true;
              break;
            }

            Container *container = new Container();
            container->plan = std::move(restoredPlan);
            container->neuronScalingDimensionsMask = metricPolicy.scalingDimensionsMask;
            container->neuronMetricsCadenceMs = metricPolicy.metricsCadenceMs;

            container->name.assignItoa(container->plan.uuid);
            container->userID = userID;
            container->executionHostID = executionHostID;

            String output;
            String path;
            const String cgroupRoot = containerCgroupInventoryRoot();
            path.snprintf<"{}/{}.slice/leaf"_ctv>(cgroupRoot, container->name);

            container->cgroup = Filesystem::openDirectoryAt(-1, path);
            const int cgroupLookupErrno = container->cgroup < 0 ? errno : 0;
            if (container->cgroup >= 0)
            {
              Filesystem::openReadAtClose(container->cgroup, "cgroup.procs"_ctv, output);
            }
            pid_t restoredPID = -1;
            const bool processPresent = prodigyParseFirstCgroupPID(output, restoredPID);

            memset(container->lcores, 0, sizeof(container->lcores));
            // A launch that never reached Neuron has no cpuset to recover.
            // Let the existing missing-process failure path resolve its UUID.
            if (processPresent && container->plan.usesIsolatedCPUs())
            {
              String configuredCPUs = {};
              String effectiveCPUs = {};
              path.snprintf<"{}/{}.slice/cpuset.cpus"_ctv>(cgroupRoot, container->name);
              Filesystem::openReadAtClose(-1, path, configuredCPUs);
              path.snprintf<"{}/{}.slice/cpuset.cpus.effective"_ctv>(cgroupRoot, container->name);
              Filesystem::openReadAtClose(-1, path, effectiveCPUs);
              if (prodigyResolveRestoredLogicalCores(
                      configuredCPUs,
                      effectiveCPUs,
                      container->plan.logicalCores(),
                      container->lcores,
                      std::size(container->lcores)) == false)
              {
                stateUploadRejection = "restored-cpuset-recovery";
                basics_log("restoreContainer cpuset recovery failed uuid=%llu configured=%s effective=%s requested=%u\n",
                           (unsigned long long)container->plan.uuid,
                           configuredCPUs.c_str(),
                           effectiveCPUs.c_str(),
                           unsigned(container->plan.logicalCores()));
                delete container;
                malformedStateUpload = true;
                break;
              }
            }

            if (processPresent)
            {
              // in the future if we ever need to run multiple processes inside a container,
              // then we'd need to check /proc/{pid}/status and line NSpid: 12345 1 to get the pid mapping to select pid 1
              container->pid = restoredPID;
              String storageHydrationFailure = {};
              if (ContainerManager::hydrateObservedContainerStorageBackend(container, &storageHydrationFailure) == false)
              {
                // Keep the observed process under its normal lifecycle owner.
                // The backend fields remain empty, so a later crash-backoff
                // replacement safely refuses an unproven storage handoff.
                std::fprintf(stderr,
                             "restoreContainer retained storage backend unavailable uuid=%llu reason=%s\n",
                             (unsigned long long)container->plan.uuid,
                             storageHydrationFailure.c_str());
              }
              container->pidfd = syscall(SYS_pidfd_open, container->pid, 0);
              container->nonChildPidfdLiveness = false;
              if (container->pidfd >= 0)
              {
                // A self-upgrade can retain a direct child. Preserve normal
                // waitid reaping there; only an adopted process reports ECHILD.
                siginfo_t waitability = {};
                int waitabilityResult = -1;
                do
                {
                  waitabilityResult = ::waitid(static_cast<idtype_t>(3), id_t(container->pidfd), &waitability, WEXITED | WNOHANG | WNOWAIT);
                } while (waitabilityResult < 0 && errno == EINTR);
                if (waitabilityResult < 0 && errno == ECHILD)
                {
                  container->nonChildPidfdLiveness = true;
                }
                else if (waitabilityResult < 0)
                {
                  container->retainedPidfdWaitabilityFailed = true;
                  std::fprintf(stderr, "restoreContainer retained pidfd waitability probe failed uuid=%llu pid=%d pidfd=%d errno=%d; retaining lifecycle owner\n",
                             (unsigned long long)container->plan.uuid,
                             int(container->pid),
                             container->pidfd,
                             errno);
                }
              }

              if (container->plan.useHostNetworkNamespace == false)
              {
                std::unique_ptr<Container> candidate(container);
                if (beginStateUploadRestore(std::move(candidate), restoreEpoch) == false)
                {
                  // A duplicate UUID was filtered above. Reaching this path
                  // therefore means the bounded restore queue could not own
                  // the candidate, so reject this malformed/overfull round.
                  stateUploadRejection = "restore-queue-admission";
                  malformedStateUpload = true;
                  break;
                }
                continue;
              }
              else
              {
                for (const IPPrefix& prefix : container->plan.addresses)
                {
                  eth.addIP(prefix);
                }

                installContainerMeshRoutes(eth);
              }

              container->assignNeuronListenerPath();
              if (container->neuronListenerPath.size() == 0)
              {
                String empty;
                reportContainerFailed(container->plan.uuid, 0, 0, empty, false);
                continue;
              }
              container->setSocketPath(container->neuronListenerPath.c_str());
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
                const auto ownerProof = ContainerManager::proveMissingScheduledStateUploadOwner(
                    container->plan, container->cgroup, cgroupLookupErrno);
                if (container->plan.restartOnFailure &&
                    ContainerManager::canFreshLaunchMissingScheduledStateUpload(container->plan, ownerProof))
                {
                  // This is a never-launched scheduled bootstrap.  It has no
                  // process, cgroup, artifact, or storage owner, so resume
                  // the ordinary spin instead of reporting a failed cold
                  // restart.  spinContainer owns its UUID deduplication.
                  ContainerPlan freshPlan = std::move(container->plan);
                  delete container;
                  launchContainerFromBrain(std::move(freshPlan), 0, metricPolicy);
                  continue;
                }

                bool restarted = false;
                uint128_t restoredUUID = container->plan.uuid;
                if (container->plan.restartOnFailure)
                {
                  // This wrapper was reconstructed from state upload, but its
                  // cgroup had no process to re-adopt.  It is not a warm
                  // restart owner: discard the observed descriptor so the
                  // cold restart owner rebuilds the cgroup and hydrates storage.
                  if (container->cgroup >= 0)
                  {
                    close(container->cgroup);
                    container->cgroup = -1;
                  }
                  if (container->plan.system.kind == SystemContainerKind::crossClusterMasqueGateway)
                  {
                    std::unique_ptr<Container> candidate(container);
                    if (!beginColdStateUploadGatewayRestore(std::move(candidate), restoreEpoch))
                    {
                      stateUploadRejection = "cold-gateway-restore-admission";
                      malformedStateUpload = true;
                      break;
                    }
                    continue;
                  }
                  else
                  {
                    restarted = ContainerManager::restartContainer(container);
                  }
                }
                else
                {
                  ContainerManager::destroyContainer(container, ContainerManager::DestroyCause::processFailure);
                }

                if (restarted == false)
                {
                  // The terminal failure can be followed by a spin frame that
                  // Brain queued before this upload completed. Retire the exact
                  // UUID before reporting failure so that frame cannot create an
                  // owner which Brain will no longer track.
                  if (retireContainerLaunch(restoredUUID) == false)
                  {
                    stateUploadRejection = "terminal-launch-retirement";
                    malformedStateUpload = true;
                    break;
                  }
                }
                String empty;
                reportContainerFailed(restoredUUID, 0, 0, empty, restarted);
              }
            }
            }
            return malformedStateUpload == false;
          };
          const bool malformedStateUpload = applyStateUploadPlans() == false;

          if (malformedStateUpload)
          {
            basics_log("neuron stateUpload malformed plan payload\n");
            std::fprintf(stderr,
                         "neuron stateUpload rejected reason=%s\n",
                         stateUploadRejection);
            std::fflush(stderr);
            if (brain)
            {
              brain->rBuffer.clear();
              queueCloseIfActive(brain);
            }
          }
          else
          {
            stateUploadRestoreReplyPending = true;
            // A complete batch may have supplied authority/credentials before
            // its missing-process gateway was admitted. Retry only now, after
            // every plan in this stateUpload has been validated.
            retrySettledStateUploadGatewayRecoveries();
            if (!stateUploadRestoresPending() && !retainedStateUploadCandidatesPending() &&
                stateUploadRestoreReplyPending)
            {
              stateUploadRestoreReplyPending = false;
              queueNeuronStateUpload();
            }
          }

          break;
        }
      case NeuronTopic::updateBundle:
        {
          handleBundleUpdateMessage(message);
          break;
        }
      case NeuronTopic::transitionToNewBundle:
        {
          uint8_t marker = 0;
          Message::extractArg<ArgumentNature::fixed>(args, marker);
          if (marker == 1)
          {
            if (pendingBundleArtifact != nullptr)
            {
              deferredBundleTransition = true;
            }
            else
            {
              transitionToNewBundle();
            }
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

          NeuronBrainControlStream *requestStream = brain;
          const uint64_t requestGeneration = requestStream ? requestStream->ioGeneration : 0;
          const std::weak_ptr<uint8_t> lifetime = asyncOperationLifetime;
          startOperatingSystemUpdateAsync(std::move(targetOSIDText), std::move(targetOSVersionIDText),
                                          std::move(updateCommandText),
              [this, requestStream, requestGeneration, lifetime](bool started, String failure) mutable {
                if (lifetime.expired() || started) return;
                if (failure.empty()) failure.assign("OS update persistence failed"_ctv);
                PRODIGY_DEBUG_LOG("neuron updateOS receipt failed reason=%s\n", failure.c_str());
                PRODIGY_DEBUG_FLUSH();
                basics_log("neuron updateOS receipt failed reason=%s\n", failure.c_str());
                // A failure belongs to the request's authenticated control
                // stream. Do not report it on a replacement generation.
                if (brain != requestStream || requestStream == nullptr ||
                    requestStream->ioGeneration != requestGeneration || streamIsActive(requestStream) == false)
                {
                  return;
                }
                Message::construct(requestStream->wBuffer, NeuronTopic::hardwareFailure, failure);
                Ring::queueSend(requestStream);
              });

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
            // Cancel an older provider-bound HTTP operation before replacing
            // its delegate. A late completion is then detached from this
            // Neuron and the new generation owns the only admissible result.
            beginRuntimeEnvironmentReconfiguration();
            iaas->configureRuntimeEnvironment(config);
            scheduleRuntimeEnvironmentBGPRefresh();
          }

          break;
        }
      case NeuronTopic::pullContainerLogs:
        {
          String serialized = {};
          Message::extractToStringView(args, serialized);
          ContainerLogsOperation operation = {};
          if (serialized.size() > containerLogsMaximumWireBytes ||
              BitseryEngine::deserializeSafe(serialized, operation) == false || operation.requestID == 0)
          {
            break;
          }
          (void)ContainerManager::collectContainerLogs(operation);
          String response = {};
          BitseryEngine::serialize(response, operation);
          if (brain != nullptr && streamIsActive(brain))
          {
            Message::construct(brain->wBuffer, NeuronTopic::pullContainerLogs, response);
            Ring::queueSend(brain);
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
          PRODIGY_DEBUG_LOG("neuron requestContainerBlob response deploymentID=%llu bytes=%u pendingWaiters=%llu\n",
                       (unsigned long long)deploymentID,
                       unsigned(containerBlob.size()),
                       (unsigned long long)(pendingContainerDownloads.contains(deploymentID) ? pendingContainerDownloads.countEntriesFor(deploymentID) : 0));
          PRODIGY_DEBUG_FLUSH();

          String ownedBlob = containerBlob.substr(0, containerBlob.size(), Copy::yes);
          if (queueReceivedContainerArtifact(brain, deploymentID, std::move(ownedBlob)) == false)
          {
            std::fprintf(stderr, "neuron requestContainerBlob artifact queue rejected deploymentID=%llu\n",
                       (unsigned long long)deploymentID);
            if (brain != nullptr)
            {
              queueCloseIfActive(brain);
            }
          }

          break;
        }
      case NeuronTopic::spinContainer:
        {
          // replaceContainerUUID(16) bootstrap{4}, optional retained source{4}.

          String inventoryFailure;
          if (!liveContainerInventoryComplete(inventoryFailure))
          {
            basics_log("neuron spinContainer withheld: %s\n", inventoryFailure.c_str());
            queueCloseIfActive(brain);
            break;
          }

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
          PRODIGY_DEBUG_LOG("neuron spinContainer deploymentID=%llu appID=%u replaceUUID=%llu blobBytes=%llu blobSHA=%s\n",
                       (unsigned long long)plan.config.deploymentID(),
                       unsigned(plan.config.applicationID),
                       (unsigned long long)replaceContainerUUID,
                       (unsigned long long)plan.config.containerBlobBytes,
                       plan.config.containerBlobSHA256.c_str());
          PRODIGY_DEBUG_FLUSH();

          RetainedContainerStorageSource retainedSource;
          if (args != terminal)
          {
            String serializedSource;
            Message::extractToStringView(args, serializedSource);
            if (args != terminal || BitseryEngine::deserializeSafe(serializedSource, retainedSource) == false ||
                retainedSource.sourceContainerUUID == 0 || replaceContainerUUID != retainedSource.sourceContainerUUID)
            {
              basics_log("neuron spinContainer retained source deserialize failed\n");
              break;
            }
          }
          launchContainerFromBrain(std::move(plan), replaceContainerUUID, metricPolicy, retainedSource);
          // Replacement is asynchronous and can reject before stopping the old
          // owner. Its destruction finalizer, not dispatch, acknowledges removal.

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
          if (!ProdigyIngressValidation::validateNeuronPayloadForNeuron(message->topic, args, terminal)) break;
          // containerUUID(16) nLogicalCores(2) memoryMB(4) storageMB(4) [isDownscale(1)] [graceSeconds(4)] [observationVersion(1)]

          uint128_t containerUUID = 0;
          uint16_t targetCores = 0;
          uint32_t targetMemoryMB = 0;
          uint32_t targetStorageMB = 0;
          bool isDownscale = false;
          uint32_t graceSeconds = 0;
          uint8_t observationVersion = 0;

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
          if (args < terminal) Message::extractArg<ArgumentNature::fixed>(args, observationVersion);
          if (args != terminal || observationVersion > 1) break;

          if (auto it = containers.find(containerUUID); it != containers.end())
          {
            Container *container = it->second;
            String failureReport;
            const bool applied = ContainerManager::adjustRunningContainerResources(container, targetCores, targetMemoryMB, targetStorageMB, &failureReport);
            if (applied)
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
            // Legacy callers never requested a reply. New serving-authority
            // callers need the applied observation, not an optimistic send
            // receipt and not a disruptive full stateUpload/routing reset.
            if (observationVersion == 1 && brain != nullptr && streamIsActive(brain))
            {
              Message::construct(brain->wBuffer, NeuronTopic::adjustContainerResources, uint8_t(1),
                  containerUUID, uint16_t(applicationSharedCPUCoreHint(container->plan.config)),
                  container->plan.config.memoryMB, container->plan.config.storageMB, uint8_t(applied));
              Ring::queueSend(brain);
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
            PRODIGY_DEBUG_LOG(
                         "neuron changeContainerLifetime uuid=%llu deploymentID=%llu old=%u\n",
                         (unsigned long long)containerUUID,
                         (unsigned long long)container->plan.config.deploymentID(),
                         unsigned(container->plan.lifetime));
            PRODIGY_DEBUG_FLUSH();
            Message::extractArg<ArgumentNature::fixed>(args, container->plan.lifetime);
          }

          break;
        }
      case NeuronTopic::killContainer:
        {
          // containerUUID(16)

          uint128_t containerUUID;
          Message::extractArg<ArgumentNature::fixed>(args, containerUUID);

          // Kill is terminal for this UUID. It can overtake a queued spin whose
          // coroutine has not claimed the pending-launch map yet.
          if (retireContainerLaunch(containerUUID) == false)
          {
            // The bounded control-local fence is full. Closing this stream
            // discards all queued frames and advances the launch generation.
            if (brain != nullptr)
            {
              brain->commandsRejected = true;
              queueCloseIfActive(brain);
            }
            break;
          }

          if (retirePendingStateUploadRestore(containerUUID))
          {
            break;
          }
          if (auto it = containers.find(containerUUID); it != containers.end())
          {
            Container *container = it->second;
            PRODIGY_DEBUG_LOG(
                         "neuron killContainer command uuid=%llu deploymentID=%llu lifetime=%u pendingDestroy=%d killedOnPurpose=%d pid=%d\n",
                         (unsigned long long)containerUUID,
                         (unsigned long long)container->plan.config.deploymentID(),
                         unsigned(container->plan.lifetime),
                         int(container->pendingDestroy),
                         int(container->killedOnPurpose),
                         int(container->pid));
            PRODIGY_DEBUG_FLUSH();
            container->pendingKillAckToBrain = true;
            // A container between restart attempts has no process that can
            // consume the cooperative stop frame.  Waiting for its normal
            // sTilKillable deadline would strand deployment destruction (and
            // an accepted operator cancellation) for the full application
            // shutdown timeout.  Cancel the pending restart and retire the
            // already-stopped container through the normal destruction owner.
            if (container->restartTimer != nullptr || container->pid <= 0)
            {
              if (container->restartTimer != nullptr)
              {
                Ring::queueCancelTimeout(container->restartTimer);
                container->restartTimer = nullptr;
              }
              container->killedOnPurpose = true;
              ContainerManager::destroyContainer(container);
            }
            else
            {
              container->stop();
            }
          }
          else if (brain)
          {
            queueContainerKillAck(containerUUID);
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

          invalidateCousinAdmissionsForSwitchboardReset();
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
          // The Brain refresh owns ordinary routes only. Reconcile the current
          // usable private-BGP fallback before publishing so this refresh cannot
          // withdraw its runtime-owned remote-site route.
          reconcileCrossClusterPrivateBGPSwitchboardFallback();
          break;
        }
      case NeuronTopic::openSwitchboardWormholes:
        {
          String serialized;
          Message::extractToStringView(args, serialized);
          SwitchboardWormholeOperation operation = {};
          SwitchboardWormholeDesiredState desired = {};
          String expectedRevision = {};
          bool valid = BitseryEngine::deserializeSafe(serialized, operation) &&
                       operation.status == SwitchboardWormholeOperationStatus::request &&
                       operation.containerID != 0 && operation.revision.size() == 64 &&
                       operation.desired.size() <= SwitchboardWormholeOperation::maximumDesiredBytes &&
                       prodigyComputeWormholeDesiredStateRevision(operation.containerID, operation.desired, expectedRevision) &&
                       expectedRevision.equals(operation.revision) &&
                       prodigyDecodeWormholeDesiredState(operation.desired, desired);
          if (valid && (operation.containerID == generateLocalContainerID(prodigyCrossClusterMasqueGatewayRuntimeFragmentFirst) ||
                        operation.containerID == generateLocalContainerID(prodigyCrossClusterMasqueGatewayRuntimeFragmentSecond)))
            valid = false;
          if (valid)
          {
            if (Container *container = findTrackedContainerByLocalID(operation.containerID); container != nullptr)
            {
              valid = strengthenWormholeDesiredStateForLocalPlan(container->plan, desired);
              // The operation revision covers the sender's exact desired
              // bytes.  Do not acknowledge an applied local strengthening as
              // that older/raw revision: Brain must retry with its own
              // protected-envelope state and matching revision.
              String strengthenedBytes = {};
              valid = valid && prodigyEncodeWormholeDesiredState(desired, strengthenedBytes) &&
                      strengthenedBytes.equals(operation.desired);
            }
          }
          if (valid == false)
          {
            basics_log("neuron openSwitchboardWormholes deserialize failed\n");
          }
          else
          {
            ensureSwitchboard()->setLocalContainerSubnet(lcsubnet6);
            operation.status = ensureSwitchboard()->openWormholes(operation.containerID, desired);
            syncSwitchboardBalancerOverlayRoutingProgram();

            // The open topic must converge the live local peer runtime immediately
            // for the owning container, otherwise first in-cluster packets can race
            // ahead of the peer-program map update and miss the wormhole binding.
            if (Container *container = findTrackedContainerByLocalID(operation.containerID); container != nullptr)
            {
              syncContainerSwitchboardRuntime(container);
            }
          }
          if (valid == false)
          {
            operation.status = SwitchboardWormholeOperationStatus::rejected;
          }
          const uint32_t requestContainerID = operation.containerID;
          const bool admitted = valid && operation.status == SwitchboardWormholeOperationStatus::applied;
          auto respond = wormholeOperationReply(std::move(operation));
          if (admitted)
            ensureSwitchboard()->whenRingsReady(requestContainerID, std::move(respond));
          else
            respond(false);
          break;
        }
      case NeuronTopic::refreshContainerWormholes:
        {
          uint128_t containerUUID = 0;
          Message::extractArg<ArgumentNature::fixed>(args, containerUUID);

          String serialized;
          Message::extractToStringView(args, serialized);

          SwitchboardWormholeDesiredState desired = {};
          if (prodigyDecodeWormholeDesiredState(serialized, desired) == false)
          {
            basics_log("neuron refreshContainerWormholes deserialize failed\n");
            break;
          }

          if (auto it = containers.find(containerUUID); it != containers.end())
          {
            Container *container = it->second;
            if (container == nullptr || container->pendingDestroy ||
                container->plan.system.kind == SystemContainerKind::crossClusterMasqueGateway)
            {
              break;
            }

            if (strengthenWormholeDesiredStateForLocalPlan(container->plan, desired) == false)
            {
              basics_log("neuron refreshContainerWormholes rejected local cousin protection containerUUID=%llu\n",
                         (unsigned long long)containerUUID);
              break;
            }

            if (applyContainerSwitchboardWormholes(container, desired) == false)
            {
              break;
            }
            container->plan.wormholes = desired.wormholes;
            ensureSwitchboard()->whenRingsReady(
                generateLocalContainerID(container->plan.fragment), wormholeContainerRefresh(container),
                Switchboard::RingConsumer::containerRefresh);
          }

          break;
        }
      case NeuronTopic::closeSwitchboardWormholesToContainer:
        {
          uint32_t containerID = 0;
          Message::extractArg<ArgumentNature::fixed>(args, containerID);

          ensureSwitchboard()->setLocalContainerSubnet(lcsubnet6);
          ensureSwitchboard()->closeWormholesToContainer(containerID);
          if (Container *container = findTrackedContainerByLocalID(containerID); container != nullptr)
          {
            syncContainerSwitchboardRuntime(container);
          }
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
          bool replayRuntime = false;
          if (ProdigyWire::deserializeAdvertisementPairingControlPayload(
                  args,
                  uint64_t(terminal - args),
                  secret,
                  address,
                  service,
                  applicationID,
                  activate,
                  replayRuntime) == false)
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

            uint16_t advertisedPort = 0;
            if (auto advertisement = container->plan.advertisements.find(service);
                advertisement != container->plan.advertisements.end())
            {
              advertisedPort = advertisement->second.port;
            }
            bool changed = container->plan.applyAdvertisementPairing(AdvertisementPairing(secret, address, service), activate);
            basics_log("neuron advertisementPairing apply containerUUID=%llu payloadBytes=%u streamActive=%d\n",
                       (unsigned long long)containerUUID,
                       unsigned(payloadBytes),
                       int(streamIsActive(container)));

            if (changed || replayRuntime)
            {
              if (changed &&
                  container->syncDeclaredNetworkPairingPolicy(activate == false, address, advertisedPort, true) == false)
              {
                basics_log("neuron advertisementPairing network policy sync failed containerUUID=%llu\n",
                           (unsigned long long)containerUUID);
                if (container->pid > 0)
                {
                  kill(container->pid, SIGKILL);
                }
                break;
              }
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
          bool replayRuntime = false;
          if (ProdigyWire::deserializeSubscriptionPairingControlPayload(
                  args,
                  uint64_t(terminal - args),
                  secret,
                  address,
                  service,
                  port,
                  applicationID,
                  activate,
                  replayRuntime) == false)
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

            if (changed || replayRuntime)
            {
              if (changed && container->syncDeclaredNetworkPairingPolicy(activate == false, address, port, false) == false)
              {
                basics_log("neuron subscriptionPairing network policy sync failed containerUUID=%llu\n",
                           (unsigned long long)containerUUID);
                if (container->pid > 0)
                {
                  kill(container->pid, SIGKILL);
                }
                break;
              }
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

  // The recovery parser deliberately owns only protocol and admission state.
  // Its three I/O edges are injected so tests can observe the exact transition
  // without using Ring send/recv/close as their assertion mechanism.
  struct RecoveryFrameDispatch {
    std::function<void(CrossClusterMasqueGatewayReadinessCarrier *)> send;
    std::function<void(CrossClusterMasqueGatewayReadinessCarrier *)> recv;
    std::function<void(CrossClusterMasqueGatewayReadinessCarrier *)> close;
    std::function<bool(uint8_t *, uint32_t)> nonce;
  };

  void processRecoveryFrame(CrossClusterMasqueGatewayReadinessCarrier *carrier,
                            const RecoveryFrameDispatch& dispatch)
  {
    if (carrier == nullptr) return;
    const auto reject = [&]() {
      (void)revokeCrossClusterMasqueGatewayReadiness(carrier->containerUUID);
      carrier->rBuffer.clear();
      if (dispatch.close) dispatch.close(carrier);
    };
    const auto tupleMatches = [](const ProdigyGatewayLocalTuple& lhs, const ProdigyGatewayLocalTuple& rhs) {
      return lhs.pairUUID == rhs.pairUUID && lhs.localClusterUUID == rhs.localClusterUUID && lhs.localMachineUUID == rhs.localMachineUUID &&
          lhs.keyEpoch == rhs.keyEpoch && lhs.authorityGeneration == rhs.authorityGeneration && lhs.gatewayGeneration == rhs.gatewayGeneration;
    };

    // Recovery never falls back to v1. Before publication it is a two-message
    // handshake; once established it carries only correlated v2 path-fault
    // replies. A second receipt can therefore never re-enter launch.
    if (carrier->receiptAccepted) {
      const uint64_t available = carrier->rBuffer.outstandingBytes();
      if (available < sizeof(uint32_t)) { if (dispatch.recv) dispatch.recv(carrier); return; }
      uint32_t payloadBytes = 0; memcpy(&payloadBytes, carrier->rBuffer.pHead(), sizeof(payloadBytes));
      const uint64_t frameBytes = uint64_t(sizeof(uint32_t)) + payloadBytes;
      if (!payloadBytes || frameBytes > CrossClusterMasqueGatewayReadinessListener::maximumFrameBytes || available != frameBytes) { reject(); return; }
      CrossClusterMasqueGatewayReadinessListener::PeerIdentity observed = {};
      ProdigyGatewayLocalControlFrame frame = {};
      if (!carrier->capturePeerIdentity || !carrier->capturePeerIdentity(carrier->peerPID, observed) || observed != carrier->retainedIdentity ||
          !prodigyGatewayLocalCarrierLockMode(carrier->localMode, carrier->rBuffer.pHead(), uint32_t(frameBytes), true) ||
          !prodigyDecodeGatewayLocalControlFrame(carrier->rBuffer.pHead(), uint32_t(frameBytes), frame) ||
          !prodigyGatewayLocalControlFrameAllowed(carrier->localMode, ProdigyGatewayLocalCarrierPhase::established, frame) ||
          !carrier->faultFramePending || !frame.pathFault.fromGateway) { reject(); return; }
      carrier->rBuffer.consume(frameBytes, true);
      finishCrossClusterPathFaultGatewayControl(carrier, frame.pathFault);
      if (dispatch.recv) dispatch.recv(carrier);
      return;
    }
    const uint64_t available = carrier->rBuffer.outstandingBytes();
    if (available < sizeof(uint32_t)) { if (dispatch.recv) dispatch.recv(carrier); return; }
    uint32_t payloadBytes = 0; memcpy(&payloadBytes, carrier->rBuffer.pHead(), sizeof(payloadBytes));
    const uint64_t frameBytes = uint64_t(sizeof(uint32_t)) + payloadBytes;
    if (!payloadBytes || frameBytes > CrossClusterMasqueGatewayReadinessListener::maximumFrameBytes || available > frameBytes) {
      reject(); return;
    }
    if (available < frameBytes) { if (dispatch.recv) dispatch.recv(carrier); return; }
    ProdigyGatewayLocalControlFrame frame = {};
    CrossClusterMasqueGatewayReadinessListener::PeerIdentity observed = {};
    const bool identityCurrent = carrier->capturePeerIdentity && carrier->capturePeerIdentity(carrier->peerPID, observed) && observed == carrier->retainedIdentity;
    if (!identityCurrent || !prodigyGatewayLocalCarrierLockMode(carrier->localMode, carrier->rBuffer.pHead(), uint32_t(frameBytes), true) ||
        !prodigyDecodeGatewayLocalControlFrame(carrier->rBuffer.pHead(), uint32_t(frameBytes), frame) ||
        !prodigyGatewayLocalControlFrameAllowed(carrier->localMode, carrier->localPhase, frame)) {
      reject(); return;
    }
    if (carrier->localPhase == ProdigyGatewayLocalCarrierPhase::rebindHello) {
      if (frame.rebindHello.recoveryToken != carrier->recoveryToken || !tupleMatches(frame.rebindHello.tuple, carrier->recoveryTuple)) {
        reject(); return;
      }
      if (!dispatch.nonce || !dispatch.nonce(carrier->recoveryNonce, sizeof(carrier->recoveryNonce)) ||
          !prodigyGatewayLocalNonceValid(carrier->recoveryNonce)) { reject(); return; }
      ProdigyGatewayLocalControlFrame challenge = {};
      challenge.direction = ProdigyGatewayLocalDirection::neuronToGateway; challenge.kind = ProdigyGatewayLocalKind::rebindChallenge;
      challenge.rebindChallenge.tuple = carrier->recoveryTuple; memcpy(challenge.rebindChallenge.nonce, carrier->recoveryNonce, sizeof(carrier->recoveryNonce));
      String encoded = {};
      if (!prodigyGatewayLocalControlFrameAllowedForSend(carrier->localPhase, challenge) ||
          !prodigyEncodeGatewayLocalControlFrame(challenge, encoded)) { reject(); return; }
      carrier->wBuffer.append(encoded); carrier->localPhase = ProdigyGatewayLocalCarrierPhase::rebindReceipt;
      carrier->rBuffer.consume(frameBytes, true);
      if (dispatch.send) dispatch.send(carrier);
      if (dispatch.recv) dispatch.recv(carrier);
      return;
    }
    auto found = pendingStateUploadRestores.find(carrier->containerUUID);
    auto *runtime = crossClusterMasqueGatewayRuntimeForContainer(carrier->containerUUID);
    ProdigyCrossClusterMasqueGatewayReadiness readiness = {};
    readiness.pairUUID = frame.rebindReceipt.tuple.pairUUID;
    readiness.localClusterUUID = frame.rebindReceipt.tuple.localClusterUUID;
    readiness.localMachineUUID = frame.rebindReceipt.tuple.localMachineUUID;
    readiness.keyEpoch = frame.rebindReceipt.tuple.keyEpoch;
    readiness.authorityGeneration = frame.rebindReceipt.tuple.authorityGeneration;
    readiness.gatewayGeneration = frame.rebindReceipt.tuple.gatewayGeneration;
    readiness.authenticatedMasqueQUICReady = frame.rebindReceipt.authenticatedMasqueQUICReady && frame.rebindReceipt.ready &&
        prodigyIsSHA256HexDigest(frame.rebindReceipt.routeSetSHA256);
    CrossClusterMasqueGatewayReadinessListener::PeerIdentity candidateIdentity = {};
    const bool admissionCurrent = carrier->localPhase == ProdigyGatewayLocalCarrierPhase::rebindReceipt &&
        tupleMatches(frame.rebindReceipt.tuple, carrier->recoveryTuple) &&
        memcmp(frame.rebindReceipt.nonce, carrier->recoveryNonce, sizeof(carrier->recoveryNonce)) == 0 && runtime != nullptr &&
        runtime->systemPlanAdmitted && runtime->systemContainerUUID == carrier->containerUUID &&
        tupleMatches(gatewayRecoveryTuple(runtime->authority), carrier->recoveryTuple) && found != pendingStateUploadRestores.end() && found->second != nullptr &&
        found->second->container != nullptr && found->second->settled && !found->second->terminalRetirementPending &&
        found->second->container->pid == carrier->peerPID && found->second->container->pidfd >= 0 &&
        carrier->capturePeerIdentity && carrier->capturePeerIdentity(found->second->container->pid, candidateIdentity) && candidateIdentity == carrier->retainedIdentity &&
        found->second->epoch == carrier->recoveryEpoch && carrier->recoveryEpoch == stateUploadRestoreEpoch && found->second->gatewayRecoveryTokenBound &&
        found->second->boundGatewayRecoveryToken == carrier->recoveryToken &&
        found->second->stream == brain && found->second->requestedStream == brain && brain != nullptr &&
        found->second->streamGeneration == brain->ioGeneration && found->second->requestedGeneration == brain->ioGeneration &&
        streamIsActive(brain) && memcmp(&found->second->fragment, &lcsubnet6, sizeof(lcsubnet6)) == 0 &&
        pendingContainerLaunchIsCurrent(carrier->containerUUID, found->second->launchAdmissionGeneration) &&
        prodigyCrossClusterMasqueGatewayReadinessMatches(runtime->authority, readiness);
    if (!admissionCurrent || !publishRestoredStateUploadContainer(*found->second, carrier->containerUUID, carrier->recoveryEpoch)) { reject(); return; }
    carrier->receiptAccepted = true; carrier->localPhase = ProdigyGatewayLocalCarrierPhase::established;
    carrier->rBuffer.consume(frameBytes, true);
    // The candidate is now owned by `containers`; a later readiness/BGP fence
    // may revoke route eligibility, but must not undo or reject publication.
    (void)recordCrossClusterMasqueGatewayReadiness(carrier->containerUUID, readiness);
    if (dispatch.recv) dispatch.recv(carrier);
  }

  void recvCrossClusterMasqueGatewayReadinessCarrier(
      CrossClusterMasqueGatewayReadinessCarrier *carrier, int result)
  {
    if (carrier == nullptr || !carrier->pendingRecv) return;
    carrier->pendingRecv = false;
    if (result <= 0)
    {
      (void)revokeCrossClusterMasqueGatewayReadiness(carrier->containerUUID);
      queueCloseIfActive(carrier);
      return;
    }
    if (uint64_t(result) > carrier->rBuffer.remainingCapacity())
    {
      (void)revokeCrossClusterMasqueGatewayReadiness(carrier->containerUUID);
      carrier->rBuffer.clear();
      queueCloseIfActive(carrier);
      return;
    }
    carrier->rBuffer.advance(result);
    if (carrier->recovery)
    {
      const RecoveryFrameDispatch dispatch = {
        [](CrossClusterMasqueGatewayReadinessCarrier *item) { Ring::queueSend(item); },
        [](CrossClusterMasqueGatewayReadinessCarrier *item) { Ring::queueRecv(item); },
        [this](CrossClusterMasqueGatewayReadinessCarrier *item) { queueCloseIfActive(item); },
        [](uint8_t *bytes, uint32_t size) {
          if (bytes == nullptr || size != 16) return false;
          uint128_t value = 0;
          while (value == 0) value = Random::generateNumberWithNBits<128, uint128_t>();
          memcpy(bytes, &value, size);
          return true;
        }};
      processRecoveryFrame(carrier, dispatch);
      return;
    }
    // After the initial PID/token-authenticated receipt this same carrier may
    // contain correlated fault replies or a fresh readiness receipt after a
    // paused session reconnects. Frames remain independently bounded.
    if (carrier->receiptAccepted)
    {
      while (carrier->rBuffer.outstandingBytes() >= sizeof(uint32_t)) {
        uint32_t payloadBytes = 0;
        memcpy(&payloadBytes, carrier->rBuffer.pHead(), sizeof(payloadBytes));
        const uint64_t frameBytes = uint64_t(sizeof(uint32_t)) + payloadBytes;
        if (!payloadBytes || frameBytes > CrossClusterMasqueGatewayReadinessListener::maximumFrameBytes) {
          (void)revokeCrossClusterMasqueGatewayReadiness(carrier->containerUUID);
          carrier->rBuffer.clear(); queueCloseIfActive(carrier); return;
        }
        if (carrier->rBuffer.outstandingBytes() < frameBytes) break;
        ProdigyCrossClusterPathFaultGatewayControlPayload response = {};
        ProdigyCrossClusterMasqueGatewayLocalReceipt receipt = {};
        const bool fault = carrier->faultFramePending &&
            prodigyDecodeCrossClusterPathFaultGatewayControlFrame(carrier->rBuffer.pHead(), uint32_t(frameBytes), response) &&
            response.fromGateway;
        const auto *runtime = crossClusterMasqueGatewayRuntimeForContainer(carrier->containerUUID);
        const bool ready = !fault && runtime && runtime->faultLeaseActive &&
            prodigyDecodeCrossClusterMasqueGatewayLocalReceiptFrame(carrier->rBuffer.pHead(), uint32_t(frameBytes), receipt) &&
            recordCrossClusterMasqueGatewayLocalReceipt(carrier->containerUUID, carrier->peerPID, receipt);
        if (!fault && !ready) {
          (void)revokeCrossClusterMasqueGatewayReadiness(carrier->containerUUID);
          carrier->rBuffer.clear(); queueCloseIfActive(carrier); return;
        }
        carrier->rBuffer.consume(frameBytes, true);
        if (fault) finishCrossClusterPathFaultGatewayControl(carrier, response);
      }
      Ring::queueRecv(carrier);
      return;
    }
    const uint64_t available = carrier->rBuffer.outstandingBytes();
    if (available < sizeof(uint32_t))
    {
      Ring::queueRecv(carrier);
      return;
    }
    uint32_t payloadBytes = 0;
    memcpy(&payloadBytes, carrier->rBuffer.pHead(), sizeof(payloadBytes));
    const uint64_t frameBytes = uint64_t(sizeof(uint32_t)) + payloadBytes;
    if (payloadBytes == 0 || payloadBytes >
            CrossClusterMasqueGatewayReadinessListener::maximumFrameBytes - sizeof(uint32_t) ||
        available > frameBytes)
    {
      (void)revokeCrossClusterMasqueGatewayReadiness(carrier->containerUUID);
      carrier->rBuffer.clear();
      queueCloseIfActive(carrier);
      return;
    }
    if (available < frameBytes)
    {
      Ring::queueRecv(carrier);
      return;
    }
    ProdigyCrossClusterMasqueGatewayLocalReceipt receipt = {};
    if (!prodigyDecodeCrossClusterMasqueGatewayLocalReceiptFrame(
            carrier->rBuffer.pHead(), uint32_t(frameBytes), receipt) ||
        !recordCrossClusterMasqueGatewayLocalReceipt(
            carrier->containerUUID, carrier->peerPID, receipt))
    {
      (void)revokeCrossClusterMasqueGatewayReadiness(carrier->containerUUID);
      carrier->rBuffer.clear();
      queueCloseIfActive(carrier);
      return;
    }
    carrier->receiptAccepted = true;
    carrier->rBuffer.consume(frameBytes, true);
    Ring::queueRecv(carrier);
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

      if constexpr (requires (T *s) { s->transportEncryptionEnabled(); })
      {
        if (stream->transportEncryptionEnabled())
        {
          const bool decrypted = stream->decryptTransportTLS(uint32_t(result));
          const bool brainPeerVerified = decrypted && ((void *)stream != (void *)brain || verifyBrainTransportTLSPeer());
          if (!decrypted || !brainPeerVerified)
          {
            if constexpr (std::is_same_v<T, NeuronBrainControlStream>)
            {
              PRODIGY_DEBUG_LOG(
                  "neuron brain recv reject reason=%s result=%d tlsNegotiated=%d peerVerified=%d pendingSend=%d pendingRecv=%d fd=%d fslot=%d\n",
                  !decrypted ? "tls-decrypt" : "tls-peer-verify", result,
                  int(stream->isTransportNegotiated()), int(stream->tlsPeerVerified), int(stream->pendingSend),
                  int(stream->pendingRecv), stream->fd, stream->fslot);
              PRODIGY_DEBUG_FLUSH();
            }
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
      bool artifactFailed = false;
      stream->template extractMessages<Message>([&](Message *message, bool& stop) -> void {
        if constexpr (std::is_same_v<T, NeuronBrainControlStream>)
        {
          String artifactFailure = {};
          const ProdigyBulkTransfer::ConsumeResult artifactResult = stream->artifacts.consume(
              message,
              [&](String&& completeFrame) -> void {
                Message *completeMessage = reinterpret_cast<Message *>(completeFrame.data());
                const NeuronTopic completeTopic = NeuronTopic(completeMessage->topic);
                if (completeTopic != NeuronTopic::requestContainerBlob && completeTopic != NeuronTopic::updateBundle)
                {
                  artifactFailed = true;
                  artifactFailure.assign("bulk artifact completed with a disallowed control topic"_ctv);
                  return;
                }
                // neuronHandler remains the single owner of ordinary Neuron
                // payload validation and topic semantics after transport has
                // reassembled this owned complete Message.
                dispatch(completeMessage);
              },
              &artifactFailure);
          if (artifactResult == ProdigyBulkTransfer::ConsumeResult::invalid || artifactFailed)
          {
            std::fprintf(stderr, "neuron artifact recv invalid reason=%s fd=%d fslot=%d\n",
                       (artifactFailure.size() > 0 ? artifactFailure.c_str() : "unknown"),
                       stream->fd,
                       stream->fslot);
            artifactFailed = true;
            stop = true;
            return;
          }
          if (artifactResult != ProdigyBulkTransfer::ConsumeResult::notFragment)
          {
            return;
          }
        }
        const uint16_t dispatchedTopic = message->topic;
        if constexpr (std::is_same_v<T, NeuronBrainControlStream>)
        {
          PRODIGY_DEBUG_LOG(
              "neuron brain dispatch enter topic=%u argsBytes=%llu fd=%d fslot=%d closing=%d\n",
              unsigned(dispatchedTopic),
              (unsigned long long)(message->terminal() >= message->args ? message->terminal() - message->args : 0),
              stream->fd, stream->fslot, int(Ring::socketIsClosing(stream)));
          PRODIGY_DEBUG_FLUSH();
        }
        dispatch(message);
        if constexpr (std::is_same_v<T, NeuronBrainControlStream>)
        {
          PRODIGY_DEBUG_LOG(
              "neuron brain dispatch exit topic=%u closing=%d active=%d commandsRejected=%d pendingSend=%d pendingRecv=%d queued=%llu\n",
              unsigned(dispatchedTopic), int(Ring::socketIsClosing(stream)), int(streamIsActive(stream)),
              int(stream->commandsRejected), int(stream->pendingSend), int(stream->pendingRecv),
              (unsigned long long)stream->queuedSendOutstandingBytes());
          PRODIGY_DEBUG_FLUSH();
          if (stream->commandsRejected)
          {
            stop = true;
          }
        }
      },
                                                true, UINT32_MAX, 16, ProdigyWire::maxControlFrameBytes, parseFailed);
      if (parseFailed || artifactFailed)
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
        if constexpr (std::is_same_v<T, NeuronBrainControlStream>)
        {
          PRODIGY_DEBUG_LOG(
              "neuron brain recv reject reason=parse-failure outstanding=%llu peekSize=%u fd=%d fslot=%d\n",
              (unsigned long long)outstanding, unsigned(peekSize), stream->fd, stream->fslot);
          PRODIGY_DEBUG_FLUSH();
        }
        stream->rBuffer.clear();
        queueCloseIfActive(stream);
        return;
      }

      if constexpr (requires (T *s) { s->transportEncryptionEnabled(); })
      {
        if (stream->transportEncryptionEnabled() && streamIsActive(stream) && stream->needsTransportTLSSendKick())
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
        PRODIGY_DEBUG_LOG(
                     "neuron brain recv-terminal result=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d fd=%d fslot=%d queued=%llu rbytes=%llu\n",
                     result,
                     int(stream->pendingSend),
                     int(stream->pendingRecv),
                     int(stream->isTransportNegotiated()),
                     int(stream->tlsPeerVerified),
                     stream->fd,
                     stream->fslot,
                     (unsigned long long)stream->queuedSendOutstandingBytes(),
                     (unsigned long long)stream->rBuffer.outstandingBytes());
        PRODIGY_DEBUG_FLUSH();
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
    for (const auto& carrier : crossClusterMasqueGatewayReadinessCarriers)
    {
      if (socket != static_cast<void *>(carrier.get())) continue;
      recvCrossClusterMasqueGatewayReadinessCarrier(carrier.get(), result);
      return;
    }
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
      if constexpr (requires (T *s) { s->prepareNextArtifactChunk(); })
      {
        stream->prepareNextArtifactChunk();
      }

      bool queueAnotherSend = (stream->wBuffer.outstandingBytes() > 0);
      if constexpr (requires (T *s) { s->transportEncryptionEnabled(); })
      {
        if (stream->transportEncryptionEnabled() && stream->needsTransportTLSSendKick())
        {
          queueAnotherSend = true;
        }
      }

      if (queueAnotherSend && streamIsActive(stream))
      {
        Ring::queueSend(stream);
      }

      if constexpr (std::is_same_v<T, NeuronBrainControlStream>)
      {
        if (stream->closeAfterTransportLifecycleAck && !queueAnotherSend && stream->wBuffer.outstandingBytes() == 0 &&
            stream == brain && streamIsActive(stream))
        {
          stream->closeAfterTransportLifecycleAck = false;
          queueCloseIfActive(stream);
          return;
        }
        if (stream->transitionAfterBundleAck && queueAnotherSend == false && stream->wBuffer.outstandingBytes() == 0 &&
            stream == brain && streamIsActive(stream))
        {
          stream->transitionAfterBundleAck = false;
          transitionToNewBundle();
          return;
        }
      }

      int tlsNegotiated = 0;
      int needsSendKick = 0;
      if constexpr (requires (T *s) { s->isTransportNegotiated(); s->needsTransportTLSSendKick(); })
      {
        tlsNegotiated = int(stream->isTransportNegotiated());
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
        PRODIGY_DEBUG_LOG(
                     "neuron brain send-terminal result=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d fd=%d fslot=%d queued=%llu wbytes=%u\n",
                     result,
                     int(stream->pendingSend),
                     int(stream->pendingRecv),
                     int(stream->isTransportNegotiated()),
                     int(stream->tlsPeerVerified),
                     stream->fd,
                     stream->fslot,
                     (unsigned long long)stream->queuedSendOutstandingBytes(),
                     unsigned(stream->wBuffer.size()));
        PRODIGY_DEBUG_FLUSH();
      }
      stream->noteSendCompleted();
      // Do not replay partial frame tails after reconnect.
      stream->clearQueuedSendBytes();
      queueCloseIfActive(stream);
    }
  }

  void sendHandler(void *socket, int result) override
  {
    for (const auto& carrier : crossClusterMasqueGatewayReadinessCarriers) {
      if (carrier.get() == socket) { sendHandler(carrier.get(), result); return; }
    }
    if (socket == (void *)brain)
    {
      sendHandler(brain, result);
      flushCousinSessionControlReceipts();
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
      if (!container->pendingDestroy) flushCousinCarrierDeliveries(container);
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
      PRODIGY_DEBUG_LOG( "neuron brain control accepted-live stream=%p fd=%d fslot=%d retained=%zu\n",
                   static_cast<void *>(brain),
                   brain->fd,
                   brain->fslot,
                   size_t(closingBrainControls.size()));
      PRODIGY_DEBUG_FLUSH();

      if ((controlTransportCredentials.enabled || ProdigyTransportTLSRuntime::configured()) &&
          beginAcceptedBrainTransportTLS(brain) == false)
      {
        queueCloseIfActive(brain);
        return;
      }

      RingDispatcher::installMultiplexee(brain, this);
      if (brain->needsTransportTLSSendKick()) Ring::queueSend(brain);
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

      queueInstalledBundleDigestAttestation(brain);
    }
    else
    {
      queueBrainAccept();
    }
  }

  void pollHandler(void *socket, int result) override
  {
    for (const auto& listener : crossClusterMasqueGatewayReadinessListeners)
    {
      if (socket != static_cast<void *>(listener.get())) continue;
      int acceptedFD = -1;
      pid_t peerPID = -1;
      const uint128_t containerUUID = listener->containerUUID;
      if (result >= 0 && listener->acceptCarrier(acceptedFD, peerPID))
      {
        // A reconnect replaces the prior liveness lease and must earn a new
        // READY receipt.  Queueing close first revokes stale route readiness
        // even if the old peer has not delivered EOF yet.
        (void)revokeCrossClusterMasqueGatewayReadiness(containerUUID);
        closeCrossClusterMasqueGatewayCarriers(containerUUID);
        auto carrier = std::make_unique<CrossClusterMasqueGatewayReadinessCarrier>();
        carrier->fd = acceptedFD;
        carrier->isNonBlocking = true;
        carrier->containerUUID = containerUUID;
        carrier->peerPID = peerPID;
        carrier->recovery = listener->recovery;
        if (carrier->recovery) {
          carrier->recoveryEpoch = listener->recoveryEpoch;
          carrier->recoveryTuple = listener->recoveryTuple;
          carrier->recoveryToken.assign(listener->recoveryToken);
          carrier->retainedIdentity = listener->retainedIdentity;
          carrier->capturePeerIdentity = listener->capturePeerIdentity;
          carrier->localPhase = ProdigyGatewayLocalCarrierPhase::rebindHello;
        }
        RingDispatcher::installMultiplexee(carrier.get(), this);
        Ring::queueRecv(carrier.get());
        activeCrossClusterMasqueGatewayReadinessCarriers.insert_or_assign(containerUUID, carrier.get());
        crossClusterMasqueGatewayReadinessCarriers.push_back(std::move(carrier));
      }
      else if (result < 0)
      {
        // The listener itself was lost.  Invalid unauthenticated connection
        // attempts do not revoke an already authenticated carrier.
        (void)revokeCrossClusterMasqueGatewayReadiness(containerUUID);
        closeCrossClusterMasqueGatewayCarriers(containerUUID);
      }
      if (listener->fd >= 0)
      {
        Ring::queuePollProcessFD(listener.get(), listener->fd, false, POLLIN);
      }
      return;
    }
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
      PRODIGY_DEBUG_LOG(
                   "neuron updateOS launcher-poll targetOSID=%s targetOSVersionID=%s launcherPid=%lld result=%d code=%d status=%d\n",
                   osUpdateProcess.targetOSID.c_str(),
                   osUpdateProcess.targetOSVersionID.c_str(),
                   (long long)osUpdateProcess.pid,
                   result,
                   int(infop.si_code),
                   int(infop.si_status));
      PRODIGY_DEBUG_FLUSH();
      clearOSUpdateProcess();
      return;
    }

    if (socket == (void *)&deferredHardwareInventoryWake)
    {
      deferredHardwareInventoryWakePollQueued = false;
      PRODIGY_DEBUG_LOG( "neuron deferred hardware wake result=%d fd=%d\n", result, deferredHardwareInventoryWake.fd);
      PRODIGY_DEBUG_FLUSH();
      if (result != -ECANCELED)
      {
        drainDeferredHardwareInventoryWake();
        bool completed = completeDeferredHardwareInventoryIfReady();
        PRODIGY_DEBUG_LOG( "neuron deferred hardware wake-drain-complete result=%d completed=%d\n",
                     result,
                     int(completed));
        PRODIGY_DEBUG_FLUSH();
        armDeferredHardwareInventoryWakePoll();
      }
      return;
    }
  }

  void closeHandler(void *socket) override
  {
    for (auto it = crossClusterMasqueGatewayReadinessCarriers.begin();
         it != crossClusterMasqueGatewayReadinessCarriers.end(); ++it)
    {
      if (socket != static_cast<void *>(it->get())) continue;
      const uint128_t containerUUID = (*it)->containerUUID;
      if (crossClusterMasqueGatewayCarrierForContainer(containerUUID) == it->get())
      {
        activeCrossClusterMasqueGatewayReadinessCarriers.erase(containerUUID);
        (void)revokeCrossClusterMasqueGatewayReadiness(containerUUID);
      }
      RingDispatcher::eraseMultiplexee(it->get());
      crossClusterMasqueGatewayReadinessCarriers.erase(it);
      return;
    }
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
                 int(closingBrain->isTransportNegotiated()),
                 int(closingBrain->tlsPeerVerified));
      PRODIGY_DEBUG_LOG( "neuron brain control close-live stream=%p fd=%d fslot=%d retained=%zu\n",
                   static_cast<void *>(closingBrain),
                   closingBrain->fd,
                   closingBrain->fslot,
                   size_t(closingBrainControls.size()));
      PRODIGY_DEBUG_FLUSH();

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
        discardCousinCarrierDeliveries(container->plan.uuid);
        container->destroyCloseCompleted = true;
        ContainerManager::finalizeContainerDestroyIfReady(container);
        return;
      }

      if (bundleExecQuiescing)
      {
        // Bundle exec retains the live process and its mount. The close CQE is
        // only a lifetime barrier; the replacement Neuron reopens control.
        return;
      }

      if (container->restartAfterClose)
      {
        container->restartAfterClose = false;
        container->reset();
        // A stateful replacement can claim an already-observed crash during
        // its backoff.  Its owner cancels the timer before this CQE is
        // dispatched; never let this delayed close recreate that predecessor.
        if (container->pendingDestroy == false && container->killedOnPurpose == false &&
            container->restartTimer == nullptr)
        {
          ContainerManager::restartContainer(container);
        }
        return;
      }

      basics_log("neuron container socket closed uuid=%llu pid=%d fd=%d fslot=%d pendingSend=%d pendingRecv=%d\n",
                 (unsigned long long)container->plan.uuid,
                 int(container->pid),
                 container->fd,
                 container->fslot,
                 int(container->pendingSend),
                 int(container->pendingRecv));

      // A carrier lease authorizes one exact live AF_UNIX control stream. A
      // reconnect must receive a fresh Brain command; retaining queued bytes
      // or the old pending authorization would accept frames for a dead peer.
      discardCousinCarrierDeliveries(container->plan.uuid);
      for (auto it = cousinSessionLocalPendings.begin(); it != cousinSessionLocalPendings.end();) {
        if (it->containerUUID == container->plan.uuid) {
          (void)clearPrivateCousinFlow(*it);
          it = cousinSessionLocalPendings.erase(it);
        } else ++it;
      }
      clearPrivateCousinAdmissionsForContainer(container->plan.uuid);

      bool processAlive = false;
      if (container->pid > 0 && kill(container->pid, 0) == 0)
      {
        processAlive = true;
      }

      if (processAlive)
      {
        // The initial container control path can start as a unix socketpair,
        // but once the process is live the stable reconnect endpoint is the
        // host-owned runtime listener passed through exec. Reconnect through
        // that addressful socket for both pair-backed and non-pair streams.
        if (container->neuronListenerPath.size() == 0)
        {
          return;
        }
        container->setSocketPath(container->neuronListenerPath.c_str());
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
    if (bundleExecQuiescing)
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

    if (packet == &crossClusterPathFaultTick) {
      crossClusterPathFaultTickQueued = false;
      if (result != -ECANCELED) serviceCrossClusterPathFaultTick();
      return;
    }

    if (packet == &bundleExecRetryTick)
    {
      bundleExecRetryTickQueued = false;
      if (result != -ECANCELED)
      {
        transitionToNewBundle();
      }
      return;
    }

    if (packet == &bgpIPv6ReadinessRetryTick)
    {
      bgpIPv6ReadinessRetryQueued = false;
      // A cancellation can race the next runtime-environment refresh.  That
      // refresh records its own generation only after it has independently
      // re-observed missing IPv6; never let the old timer's identifier alone
      // restart a superseded provider configuration.
      if (bgpIPv6ReadinessRetryPendingGeneration == runtimeEnvironmentGeneration)
      {
        std::fprintf(stderr, "neuron BGP IPv6 readiness retry start generation=%llu attempt=%u\n",
                     (unsigned long long)runtimeEnvironmentGeneration,
                     unsigned(bgpIPv6ReadinessRetryAttempts));
        scheduleRuntimeEnvironmentBGPRefresh();
      }
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
    else if (packet == &containerNetworkCleanupTick)
    {
      containerNetworkCleanupTickQueued = false;
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
      if (packet == &containerNetworkCleanupTick)
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
      else if (NeuronTimeoutFlags(packet->flags) == NeuronTimeoutFlags::restartContainer)
      {
        if (auto it = containers.find(packet->identifier); it != containers.end() && it->second->restartTimer == packet)
        {
          it->second->restartTimer = nullptr;
        }
      }

      delete packet;
      return;
    }

    flushCousinSessionControlReceipts();

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
      case NeuronTimeoutFlags::restartContainer:
        {
          if (auto it = containers.find(packet->identifier); it != containers.end())
          {
            Container *container = it->second;
            if (container->restartTimer == packet)
            {
              container->restartTimer = nullptr;
              if (container->pendingDestroy == false && container->killedOnPurpose == false)
              {
                // The failed process can outlive its control-stream close CQE.
                // Reuse the existing retirement owner so a delayed restart
                // never overlaps the old fixed-file/control-socket lifetime.
                (void)resumeFailedContainerRestart(container);
              }
            }
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
      case NeuronTimeoutFlags::networkCleanup:
        {
          ContainerManager::retryQuarantinedContainerNetworks();
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
    syncTrackedContainerPeerWhiteholeBindings();

    if (container->plan.system.kind == SystemContainerKind::crossClusterMasqueGateway)
    {
      // The directory is created by ContainerManager before exec. Register
      // this separate listener with the Ring; it never shares NeuronHub's
      // framing or accepted stream ownership.
      container->gatewayReadinessListenerReady = false;
      auto *runtime = crossClusterMasqueGatewayRuntimeForContainer(container->plan.uuid);
      if (runtime == nullptr)
      {
        (void)revokeCrossClusterMasqueGatewayReadiness(container->plan.uuid);
      }
      else
      {
        // A retained recovery listener is already bound to the exact recovery
        // socket. Publishing its receipt must not replace it with a launch
        // listener or assign a new NeuronHub path.
        if (auto *existing = crossClusterMasqueGatewayListenerForContainer(container->plan.uuid);
            existing != nullptr && existing->recovery)
        {
          container->gatewayReadinessListenerReady = true;
        }
        else
        {
          removeCrossClusterMasqueGatewayListener(container->plan.uuid);
          auto listener = std::make_unique<CrossClusterMasqueGatewayReadinessListener>();
          if (listener->openFor(*container))
          {
            RingDispatcher::installMultiplexee(listener.get(), this);
            Ring::queuePollProcessFD(listener.get(), listener->fd, false, POLLIN);
            crossClusterMasqueGatewayReadinessListeners.push_back(std::move(listener));
            container->gatewayReadinessListenerReady = true;
          }
          else (void)revokeCrossClusterMasqueGatewayReadiness(container->plan.uuid);
        }
      }
    }

    // Network setup can request runtime-map convergence before the candidate
    // is visible in containers. A wormhole refresh below requests another
    // sweep after publication; containers without wormholes need the same
    // post-publication fence for their peer and primary programs.
    if (container->plan.wormholes.empty())
    {
      syncContainerSwitchboardRuntime(container);
    }

    if (container->exposesNeuronSocket() == false)
    {
      if (container->plan.system.kind == SystemContainerKind::crossClusterMasqueGateway &&
          !container->plan.wormholes.empty())
        refreshContainerSwitchboardWormholes(container);
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
    if (container->plan.system.kind == SystemContainerKind::crossClusterMasqueGateway)
    {
      (void)revokeCrossClusterMasqueGatewayReadiness(container->plan.uuid);
      removeCrossClusterMasqueGatewayListener(container->plan.uuid);
      if (auto *runtime = crossClusterMasqueGatewayRuntimeForContainer(container->plan.uuid);
          runtime != nullptr)
      {
        ensureSwitchboard()->closeWormholesToContainer(generateLocalContainerID(container->plan.fragment));
        runtime->systemContainerUUID = 0;
        runtime->systemPlanAdmitted = false;
      }
    }
    discardCousinCarrierDeliveries(container->plan.uuid);
    for (auto it = cousinSessionLocalPendings.begin(); it != cousinSessionLocalPendings.end();) {
      if (it->containerUUID == container->plan.uuid) {
        (void)clearPrivateCousinFlow(*it);
        it = cousinSessionLocalPendings.erase(it);
      } else ++it;
    }
    clearPrivateCousinAdmissionsForContainer(container->plan.uuid);
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
