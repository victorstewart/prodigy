#pragma once

// Private-site BGP is intentionally a different plane from NeuronBGPRuntime.
// The latter owns provider peers and must never receive a container /96 from a
// cross-cluster gateway.  This owner is deliberately desired-state first: the
// MASQUE owner supplies the authenticated tunnel tuple before a socket is ever
// permitted to exist.

#include <prodigy/cross.cluster.mesh.route.h>
#include <prodigy/cross.cluster.path.fault.h>
#include <prodigy/pair.private.bgp.secret.h>
#include <networking/bgp.h>

class ProdigyCrossClusterPrivateTunnelBGPDesiredState {
public:
  uint128_t pairUUID = 0;
  uint128_t pairOperationUUID = 0;
  uint128_t localMachineUUID = 0;
  uint128_t peerMachineUUID = 0;
  uint64_t keyEpoch = 0;
  uint64_t authorityGeneration = 0;
  uint64_t gatewayGeneration = 0;
  // This is independent of the BGP tunnel slot: a host can carry two
  // authorities whose private tuples happen to use different pair slots.
  uint8_t gatewaySlot = 0;
  IPPrefix localSitePrefix = {};
  IPPrefix peerSitePrefix = {};
  String tunnelInterface;
  // These are the local veth boundary for outer Switchboard delivery.  They
  // are deliberately separate from the private /127, which belongs only to
  // the gateway's TUN/BGP session.
  IPAddress localGatewayInjectionIPv6 = {};
  IPAddress localGatewaySourceIPv6 = {};
  uint8_t localGatewayInjectionFragment = 0;
  IPAddress localInsideIPv6 = {};
  IPAddress peerInsideIPv6 = {};
  uint16_t localASN = 0;
  uint16_t peerASN = 0;
  uint32_t localBGPID = 0;
  // Only the transient Vault delivery response populates this field.  The
  // authority contains the digest reference, never this value.
  String sessionKey;
  bool masqueReady = false;
};

static inline bool prodigyCrossClusterPrivateTunnelBGPDesiredStateValid(
    const ProdigyCrossClusterPrivateTunnelBGPDesiredState& state)
{
  return state.pairUUID != 0 && state.pairOperationUUID != 0 && state.localMachineUUID != 0 && state.peerMachineUUID != 0 &&
      state.localMachineUUID != state.peerMachineUUID && state.keyEpoch != 0 &&
      state.authorityGeneration != 0 && state.gatewayGeneration != 0 &&
      state.localSitePrefix.network.is6 && state.localSitePrefix.cidr == 96 &&
      state.peerSitePrefix.network.is6 && state.peerSitePrefix.cidr == 96 &&
      state.localSitePrefix.equals(state.localSitePrefix.canonicalized()) &&
      state.peerSitePrefix.equals(state.peerSitePrefix.canonicalized()) &&
      !state.localSitePrefix.equals(state.peerSitePrefix) && state.tunnelInterface.size() != 0 &&
      state.tunnelInterface.size() <= 15 && state.localInsideIPv6.is6 && state.peerInsideIPv6.is6 &&
      !state.localInsideIPv6.isNull() && !state.peerInsideIPv6.isNull() &&
      !state.localInsideIPv6.equals(state.peerInsideIPv6) && state.localASN != 0 && state.peerASN != 0 &&
      state.localBGPID != 0 && state.localGatewayInjectionIPv6.is6 &&
      !state.localGatewayInjectionIPv6.isNull() && state.localGatewaySourceIPv6.is6 &&
      !state.localGatewaySourceIPv6.isNull() &&
      !state.localGatewayInjectionIPv6.equals(state.localGatewaySourceIPv6) &&
      switchboardMasqueGatewayContainerFragmentValid(state.localGatewayInjectionFragment) &&
      state.sessionKey.size() >= 32 && state.masqueReady;
}

static inline bool prodigyCrossClusterPrivateTunnelBGPMatchesAuthority(
    const CrossClusterMasqueGatewayAuthority& authority,
    const ProdigyCrossClusterMasqueGatewayReadiness* readiness,
    const ProdigyCrossClusterPrivateTunnelBGPDesiredState& state)
{
  return prodigyCrossClusterMasqueGatewayReady(authority, readiness) &&
      prodigyCrossClusterPrivateTunnelBGPDesiredStateValid(state) &&
      state.pairUUID == authority.pairUUID && state.pairOperationUUID == authority.pairOperationUUID &&
      state.localMachineUUID == authority.localMachineUUID &&
      state.peerMachineUUID == authority.peerMachineUUID && state.keyEpoch == authority.keyGeneration &&
      state.authorityGeneration == authority.pairAuthorityGeneration &&
      state.gatewayGeneration == authority.generation && state.gatewaySlot == authority.gatewaySlot &&
      state.localSitePrefix.equals(authority.localSitePrefix) &&
      state.peerSitePrefix.equals(authority.peerSitePrefix) && state.tunnelInterface == authority.privateTunnelInterface &&
      state.localInsideIPv6.equals(authority.privateTunnelLocalIPv6) && state.peerInsideIPv6.equals(authority.privateTunnelPeerIPv6) &&
      state.localASN == authority.privateLocalASN && state.peerASN == authority.privatePeerASN && state.localBGPID == authority.privateLocalBGPID &&
      state.sessionKey.size() == 32 && [&]() { String digest = {}; const bool ok = prodigyComputeSHA256Hex(state.sessionKey, digest) &&
          digest == authority.privateSessionCredentialSHA256; Vault::secureClearString(digest); return ok; }();
}

// BGP UPDATE admission is deliberately narrower than generic BGP import:
// exactly one enrolled remote /96, from this session's exact peer, and only
// while the MASQUE tuple that authenticated the session is current.
static inline bool prodigyCrossClusterPrivateTunnelBGPImportAllowed(
    const ProdigyCrossClusterPrivateTunnelBGPDesiredState& state,
    const IPAddress& reportingPeer, const IPPrefix& prefix, bool withdrawn)
{
  return prodigyCrossClusterPrivateTunnelBGPDesiredStateValid(state) &&
      reportingPeer.equals(state.peerInsideIPv6) && prefix.equals(state.peerSitePrefix) &&
      // A withdrawal is legal only for that same exact NLRI; callers use it
      // to remove the Switchboard fallback immediately.
      (withdrawn || state.masqueReady);
}

class ProdigyCrossClusterPrivateTunnelBGPPath {
public:
  ProdigyCrossClusterPrivateTunnelBGPDesiredState state = {};
  ProdigyCrossClusterSiteBGPRoutePlan siteRoutePlan = {};
  bool sessionEstablished = false;
  bool peerPrefixImported = false;
  // Kept with the path so a replacement or key loss withdraws the exact
  // locally-owned NLRI before the authenticated peer is closed.
  bool localPrefixAnnounced = false;
};

static inline bool prodigyCrossClusterPrivateTunnelBGPPathUsable(
    const ProdigyCrossClusterPrivateTunnelBGPPath& path)
{
  return prodigyCrossClusterPrivateTunnelBGPDesiredStateValid(path.state) &&
      path.localPrefixAnnounced && path.sessionEstablished && path.peerPrefixImported;
}

static inline bool prodigyObserveCrossClusterPrivateBGPReadiness(
    const CrossClusterMasqueGatewayAuthority& authority,
    const ProdigyCrossClusterPrivateTunnelBGPPath *path,
    bool switchboardFallbackInstalled,
    ProdigyCrossClusterPrivateBGPReadiness& receipt)
{
  receipt = {};
  if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(authority)) return false;
  receipt.scope.pairUUID = authority.pairUUID;
  receipt.scope.operationUUID = authority.pairOperationUUID;
  receipt.scope.keyEpoch = authority.keyGeneration;
  receipt.scope.tunnelSlot = authority.tunnelSlot;
  receipt.scope.clusterUUID = authority.localClusterUUID;
  receipt.scope.machineUUID = authority.localMachineUUID;
  receipt.scope.authorityGeneration = authority.pairAuthorityGeneration;
  receipt.scope.gatewayGeneration = authority.generation;
  receipt.peerMachineUUID = authority.peerMachineUUID;
  receipt.localSitePrefix = authority.localSitePrefix;
  receipt.peerSitePrefix = authority.peerSitePrefix;
  if (path != nullptr &&
      path->state.pairUUID == authority.pairUUID &&
      path->state.pairOperationUUID == authority.pairOperationUUID &&
      path->state.localMachineUUID == authority.localMachineUUID &&
      path->state.peerMachineUUID == authority.peerMachineUUID &&
      path->state.keyEpoch == authority.keyGeneration &&
      path->state.authorityGeneration == authority.pairAuthorityGeneration &&
      path->state.gatewayGeneration == authority.generation &&
      path->state.localSitePrefix.equals(authority.localSitePrefix) &&
      path->state.peerSitePrefix.equals(authority.peerSitePrefix))
  {
    receipt.localSitePrefixAnnounced = path->localPrefixAnnounced;
    receipt.sessionEstablished = path->sessionEstablished;
    receipt.peerSitePrefixImported = path->peerPrefixImported;
  }
  receipt.switchboardFallbackInstalled = switchboardFallbackInstalled;
  return prodigyCrossClusterPrivateBGPReadinessMatchesAuthority(receipt, authority);
}

// The Switchboard fallback is programmed only after the matching private BGP
// NLRI was imported.  It is removed by returning false on session/readiness or
// NLRI loss; callers reconcile this output into the existing overlay owner.
static inline bool prodigyBuildCrossClusterPrivateTunnelSwitchboardFallback(
    const CrossClusterMasqueGatewayAuthority& authority,
    const ProdigyCrossClusterPrivateTunnelBGPPath& path,
    SwitchboardOverlayMachineRoute& route)
{
  route = {};
  if (!prodigyCrossClusterPrivateTunnelBGPPathUsable(path)) return false;
  ProdigyCrossClusterMasqueGatewayReadiness readiness = {};
  readiness.pairUUID = authority.pairUUID;
  readiness.localClusterUUID = authority.localClusterUUID;
  readiness.localMachineUUID = authority.localMachineUUID;
  readiness.keyEpoch = authority.keyGeneration;
  readiness.authorityGeneration = authority.pairAuthorityGeneration;
  readiness.gatewayGeneration = authority.generation;
  readiness.authenticatedMasqueQUICReady = true;
  if (!prodigyCrossClusterPrivateTunnelBGPMatchesAuthority(authority, &readiness, path.state)) return false;
  ProdigyCrossClusterMeshRoute mesh = {};
  if (!prodigyBuildCrossClusterMeshRoute(authority, mesh)) return false;
  ProdigyCrossClusterAuthenticatedOverlayUnderlay underlay = {};
  underlay.pairUUID = path.state.pairUUID;
  underlay.localMachineUUID = path.state.localMachineUUID;
  underlay.peerMachineUUID = path.state.peerMachineUUID;
  underlay.keyEpoch = path.state.keyEpoch;
  underlay.authorityGeneration = path.state.authorityGeneration;
  underlay.gatewayGeneration = path.state.gatewayGeneration;
  // The encapsulated packet must enter the local gateway's veth.  The
  // authenticated private /127 remains exclusively the BGP/TUN binding and
  // must never be emitted as an outer Switchboard address.
  underlay.nextHop = path.state.localGatewayInjectionIPv6;
  underlay.sourceAddress = path.state.localGatewaySourceIPv6;
  if (!prodigyBuildCrossClusterOverlayDatacenterRoute(mesh, underlay, route)) return false;
  route.localContainerRedirectFragment = path.state.localGatewayInjectionFragment;
  return true;
}

// A stable flow hash picks among up to three independently authenticated
// gateway paths.  Losing any path simply removes it from the candidate set;
// there is no application-layer relay or a default-route escape hatch.
static inline bool prodigySelectCrossClusterPrivateTunnelBGPPath(
    const Vector<ProdigyCrossClusterPrivateTunnelBGPPath>& paths, uint64_t flowHash,
    ProdigyCrossClusterPrivateTunnelBGPPath& selected)
{
  selected = {};
  Vector<uint32_t> usable = {};
  for (uint32_t i = 0; i < paths.size(); ++i) {
    if (!prodigyCrossClusterPrivateTunnelBGPPathUsable(paths[i])) continue;
    // Only one candidate may represent a pair.  This keeps replacement from
    // becoming an unintended weighted path and makes exact-pair withdrawal
    // independent from every other candidate.
    for (uint32_t prior : usable)
      if (paths[prior].state.pairUUID == paths[i].state.pairUUID) return false;
    usable.push_back(i);
  }
  if (usable.empty() || usable.size() > 3) return false;
  std::sort(usable.begin(), usable.end(), [&](uint32_t left, uint32_t right) {
    const auto& a = paths[left].state; const auto& b = paths[right].state;
    return a.pairUUID != b.pairUUID ? a.pairUUID < b.pairUUID : a.gatewaySlot < b.gatewaySlot;
  });
  selected = paths[usable[uint32_t(flowHash % usable.size())]];
  return true;
}

// This owner records the currently authorized private paths.  Socket creation
// is intentionally deferred until the authority projection grows the missing
// tunnel-inside tuple; until then it withdraws, which is safer than falling
// back to provider BGP.
class NeuronPrivateTunnelBGPRuntime {
  class PrivateBGPHub final : public BGPHub { public: void hasShutdownBGP(void) override {} };
  PrivateBGPHub hub;
  Vector<ProdigyCrossClusterPrivateTunnelBGPPath> paths;
  ProdigyPairPrivateBGPSecretScope deliveredScope = {};
  String deliveredSecret;
  // This retains the exact pause intent and delivered credential in the
  // existing path owner.  It is intentionally distinct from terminal secret
  // withdrawal: resume must recreate the same authenticated session.
  bool pathFaultPaused = false;
  ProdigyCrossClusterPathFaultRequest pathFaultRequest = {};
  ProdigyCrossClusterPathFaultRequest completedPathFaultRequest = {};
  ProdigyCrossClusterPrivateTunnelBGPDesiredState pathFaultPausedState = {};
  void (*pathChanged)(void *) = nullptr;
  void *pathChangedContext = nullptr;
  static void imported(void *context, const BGPIPv6UnicastImport& update)
  {
    auto *runtime = static_cast<NeuronPrivateTunnelBGPRuntime *>(context);
    if (runtime == nullptr || runtime->paths.size() != 1) return;
    auto& path = runtime->paths[0];
    IPAddress prefixAddress = {}; prefixAddress.is6 = true;
    std::memcpy(prefixAddress.v6, update.prefix.data(), sizeof(prefixAddress.v6));
    IPPrefix prefix = {}; prefix.network = prefixAddress; prefix.cidr = update.cidr;
    if (!prodigyCrossClusterPrivateTunnelBGPImportAllowed(path.state, path.state.peerInsideIPv6, prefix, update.withdrawn)) return;
    path.peerPrefixImported = !update.withdrawn;
    runtime->notifyPathChanged();
  }
  static void sessionChanged(void *context, const IPAddress& peer, bool established)
  {
    auto *runtime = static_cast<NeuronPrivateTunnelBGPRuntime *>(context);
    if (runtime == nullptr || runtime->paths.size() != 1 || !peer.equals(runtime->paths[0].state.peerInsideIPv6)) return;
    auto& path = runtime->paths[0];
    path.sessionEstablished = established;
    // A disconnect invalidates every NLRI learned on that TCP session.
    if (!established) path.peerPrefixImported = false;
    runtime->notifyPathChanged();
  }
  void notifyPathChanged(void) { if (pathChanged) pathChanged(pathChangedContext); }
public:
  ~NeuronPrivateTunnelBGPRuntime() { withdrawAll(); }
  void withdrawAll(void) { clearPaths(); Vault::secureClearString(deliveredSecret); deliveredScope = {}; pathFaultPaused = false; pathFaultRequest = {}; completedPathFaultRequest = {}; Vault::secureClearString(pathFaultPausedState.sessionKey); pathFaultPausedState = {}; }
  void setPathChangedObserver(void (*observer)(void *), void *context)
  { pathChanged = observer; pathChangedContext = context; }
  bool installDeliveredSecret(ProdigyPairPrivateBGPSecretDeliveryResponse& response)
  {
    if (!response.accepted || !prodigyPairPrivateBGPSecretScopeValid(response.scope) || response.credential.size() != 32) return false;
    Vault::secureClearString(deliveredSecret);
    deliveredSecret.assign(response.credential.data(), response.credential.size());
    deliveredScope = response.scope;
    response.accepted = false; response.scope = {}; return true;
  }
  bool withdrawDeliveredSecret(const ProdigyPairPrivateBGPSecretScope& scope)
  { if (!prodigyPairPrivateBGPSecretScopeEqual(deliveredScope, scope)) return false; withdrawAll(); return true; }
  bool beginCrossClusterPathFault(const ProdigyCrossClusterPathFaultRequest& request,
                                  const String& authenticatedControlIdentitySHA256)
  {
    if (!prodigyCrossClusterPathFaultControlAuthenticated(request, authenticatedControlIdentitySHA256) ||
        !sameDeliveredScope(request.scope)) return false;
    if (pathFaultPaused) return prodigyCrossClusterPathFaultRequestEqual(pathFaultRequest, request);
    if (paths.size() != 1 || prodigyCrossClusterPathFaultRequestEqual(completedPathFaultRequest, request)) return false;
    auto& path = paths[0];
    ProdigyCrossClusterMasqueGatewayReadiness ready = {};
    ready.pairUUID = request.authority.pairUUID; ready.localClusterUUID = request.authority.localClusterUUID;
    ready.localMachineUUID = request.authority.localMachineUUID; ready.keyEpoch = request.authority.keyGeneration;
    ready.authorityGeneration = request.authority.pairAuthorityGeneration; ready.gatewayGeneration = request.authority.generation;
    ready.authenticatedMasqueQUICReady = true;
    if (!prodigyCrossClusterPrivateTunnelBGPMatchesAuthority(request.authority, &ready, path.state) ||
        !prodigyCrossClusterPrivateTunnelBGPPathUsable(path)) return false;
    // Retain the exact lease before sending a gateway command. A lost reply
    // must not discard the credential needed to restore the existing path.
    pathFaultPausedState = path.state; pathFaultRequest = request; pathFaultPaused = true;
    if (path.localPrefixAnnounced) hub.withdrawPrefix(path.siteRoutePlan.localSitePrefix);
    hub.withdrawPeer(path.state.peerInsideIPv6);
    path.localPrefixAnnounced = false; path.sessionEstablished = false; path.peerPrefixImported = false;
    notifyPathChanged();
    return true;
  }
  bool pauseCrossClusterPathFault(const ProdigyCrossClusterPathFaultRequest& request,
                                  const String& authenticatedControlIdentitySHA256,
                                  ProdigyCrossClusterPathFaultSessionControl& sessionControl)
  {
    if (!beginCrossClusterPathFault(request, authenticatedControlIdentitySHA256) || !sessionControl.pause(request)) return false;
    bool sessionReady = true;
    return sessionControl.query(request, sessionReady) && !sessionReady;
  }
  bool queryCrossClusterPathFault(const ProdigyCrossClusterPathFaultRequest& request,
                                  const String& authenticatedControlIdentitySHA256,
                                  ProdigyCrossClusterPathFaultSessionControl& sessionControl,
                                  bool& masqueReady, bool& privateBGPReady) const
  {
    masqueReady = privateBGPReady = false;
    if (!prodigyCrossClusterPathFaultControlAuthenticated(request, authenticatedControlIdentitySHA256) ||
        !pathFaultPaused || !prodigyCrossClusterPathFaultRequestEqual(pathFaultRequest, request) ||
        paths.size() > 1 || !sameDeliveredScope(request.scope) || !sessionControl.query(request, masqueReady)) return false;
    privateBGPReady = paths.size() == 1 && prodigyCrossClusterPrivateTunnelBGPPathUsable(paths[0]);
    return !masqueReady && !privateBGPReady;
  }
  bool resumeCrossClusterPathFault(const ProdigyCrossClusterPathFaultRequest& request,
                                   const String& authenticatedControlIdentitySHA256,
                                   ProdigyCrossClusterPathFaultSessionControl& sessionControl,
                                   const ProdigyCrossClusterMasqueGatewayReadiness& readiness,
                                   int gatewayNetworkNamespaceFD)
  {
    if (!prodigyCrossClusterPathFaultControlAuthenticated(request, authenticatedControlIdentitySHA256) ||
        !sameDeliveredScope(request.scope) ||
        !prodigyCrossClusterMasqueGatewayReady(request.authority, &readiness)) return false;
    if (!pathFaultPaused) {
      bool sessionReady = false;
      return prodigyCrossClusterPathFaultRequestEqual(completedPathFaultRequest, request) && paths.size() == 1 &&
          sessionControl.query(request, sessionReady) && sessionReady &&
          prodigyCrossClusterPrivateTunnelBGPPathUsable(paths[0]);
    }
    if (!prodigyCrossClusterPathFaultRequestEqual(pathFaultRequest, request) ||
        (paths.size() != 1 && paths.size() != 0)) return false;
    const auto state = paths.empty() ? pathFaultPausedState : paths[0].state;
    if (!sessionControl.resume(request)) return false;
    bool sessionReady = false;
    if (!sessionControl.query(request, sessionReady) || !sessionReady) return false;
    // Keep the pause marker until reconciliation has rebuilt the same exact
    // private peer and its /96 import path; a failed resume remains fail-closed.
    if (!reconcile(request.authority, &readiness, &state, gatewayNetworkNamespaceFD)) return false;
    pathFaultPaused = false; pathFaultRequest = {}; completedPathFaultRequest = request;
    Vault::secureClearString(pathFaultPausedState.sessionKey); pathFaultPausedState = {};
    return true;
  }
  bool reconcile(const CrossClusterMasqueGatewayAuthority& authority,
                 const ProdigyCrossClusterMasqueGatewayReadiness* readiness,
                 const ProdigyCrossClusterPrivateTunnelBGPDesiredState* state,
                 int gatewayNetworkNamespaceFD)
  {
    if (state == nullptr || gatewayNetworkNamespaceFD < 0 || !sameDeliveredScope(authority))
    { if (pathFaultPaused) clearPaths(); else withdrawAll(); return false; }
    ProdigyCrossClusterPrivateTunnelBGPDesiredState resolved = *state;
    Vault::secureClearString(resolved.sessionKey); resolved.sessionKey = deliveredSecret;
    if (!prodigyCrossClusterPrivateTunnelBGPMatchesAuthority(authority, readiness, resolved))
    { Vault::secureClearString(resolved.sessionKey); if (pathFaultPaused) clearPaths(); else withdrawAll(); return false; }
    // Only an exact current tuple counts as retained.  A new generation may
    // keep the same pair identity while rotating the peer, key, or local /96;
    // treating that old UPDATE as current would suppress the required replace.
    const bool currentlyAdvertised = paths.size() == 1 && paths[0].localPrefixAnnounced &&
        paths[0].state.sessionKey == deliveredSecret &&
        prodigyCrossClusterPrivateTunnelBGPMatchesAuthority(authority, readiness, paths[0].state);
    ProdigyCrossClusterSiteBGPRoutePlan routePlan = {};
    if (!prodigyBuildCrossClusterSiteBGPRoutePlan(authority, readiness, currentlyAdvertised, routePlan))
    { Vault::secureClearString(resolved.sessionKey); if (pathFaultPaused) clearPaths(); else withdrawAll(); return false; }
    // A matching retained publication is idempotent.  Its route remains on
    // this authenticated private peer; it is never handed to provider BGP.
    if (routePlan.action == BGPIPv6UnicastAdvertisementAction::none)
    { Vault::secureClearString(resolved.sessionKey); return true; }
    if (routePlan.action != BGPIPv6UnicastAdvertisementAction::announce ||
        !routePlan.localSitePrefix.equals(resolved.localSitePrefix))
    { Vault::secureClearString(resolved.sessionKey); if (pathFaultPaused) clearPaths(); else withdrawAll(); return false; }
    clearPaths();
    ProdigyCrossClusterPrivateTunnelBGPPath path = {};
    path.state = std::move(resolved);
    path.siteRoutePlan = routePlan;
    // This is the only point a socket can be created: a matching MASQUE
    // receipt and authenticated Vault secret have both been admitted.  The
    // common BGPHub owns the peer and closes it again on any loss above.
    hub.ourBGPID = path.state.localBGPID;
    hub.ourASN = path.state.localASN;
    const bool transportStarted = authority.localRole == CrossClusterMasqueGatewayRole::listener ?
        hub.listenPrivatePeer(path.state.peerASN, path.state.peerInsideIPv6,
                              path.state.localInsideIPv6, path.state.sessionKey,
                              &imported, this, &sessionChanged, this,
                              gatewayNetworkNamespaceFD, path.state.tunnelInterface) :
        authority.localRole == CrossClusterMasqueGatewayRole::connector &&
        hub.addPeer(path.state.peerASN, path.state.peerInsideIPv6,
                    path.state.localInsideIPv6, path.state.sessionKey, BGP_PRIVATE_MASQUE_HOP_LIMIT,
                    &imported, this, &sessionChanged, this,
                    gatewayNetworkNamespaceFD, &path.state.tunnelInterface);
    if (!transportStarted)
    {
      Vault::secureClearString(path.state.sessionKey);
      return false;
    }
    // BGPHub retains this UPDATE for the authenticated private peer and sends
    // it once established.  This private hub never receives provider peers.
    hub.announceLocalPrefix(path.siteRoutePlan.localSitePrefix, path.state.localInsideIPv6);
    path.localPrefixAnnounced = true;
    // Session establishment and import notifications are the only later
    // transitions allowed to make this path usable.
    paths.push_back(path);
    return true;
  }
  const Vector<ProdigyCrossClusterPrivateTunnelBGPPath>& desiredPaths(void) const { return paths; }
  bool hasCrossClusterPathFault(const ProdigyCrossClusterPathFaultRequest& request) const
  { return pathFaultPaused && prodigyCrossClusterPathFaultRequestEqual(pathFaultRequest, request); }
private:
  void clearPaths(void) { for (auto& path : paths) { if (path.localPrefixAnnounced) hub.withdrawPrefix(path.siteRoutePlan.localSitePrefix); hub.withdrawPeer(path.state.peerInsideIPv6); Vault::secureClearString(path.state.sessionKey); } paths.clear(); notifyPathChanged(); }
  bool sameDeliveredScope(const CrossClusterMasqueGatewayAuthority& authority) const
  { return deliveredSecret.size() == 32 && deliveredScope.pairUUID == authority.pairUUID && deliveredScope.operationUUID == authority.pairOperationUUID &&
      deliveredScope.keyEpoch == authority.keyGeneration && deliveredScope.tunnelSlot == authority.tunnelSlot &&
      deliveredScope.clusterUUID == authority.localClusterUUID && deliveredScope.machineUUID == authority.localMachineUUID &&
      deliveredScope.authorityGeneration == authority.pairAuthorityGeneration && deliveredScope.gatewayGeneration == authority.generation; }
  bool sameDeliveredScope(const ProdigyPairPrivateBGPSecretScope& scope) const
  { return deliveredScope.pairUUID == scope.pairUUID && deliveredScope.operationUUID == scope.operationUUID && deliveredScope.keyEpoch == scope.keyEpoch &&
      deliveredScope.tunnelSlot == scope.tunnelSlot && deliveredScope.clusterUUID == scope.clusterUUID && deliveredScope.machineUUID == scope.machineUUID &&
      deliveredScope.authorityGeneration == scope.authorityGeneration && deliveredScope.gatewayGeneration == scope.gatewayGeneration; }
};
