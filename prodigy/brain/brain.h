#include <limits.h>
#include <cerrno>
#include <cctype>
#include <cpp-sort/adapters/verge_adapter.h>
#include <services/debug.h>
#include <cpp-sort/sorters/ska_sorter.h>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <ifaddrs.h>
#include <macros/time.h>
#include <memory>
#include <net/if.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <signal.h>
#include <sys/wait.h>

static inline cppsort::verge_adapter<cppsort::ska_sorter> sorter;

#include <services/time.h>
#include <services/bitsery.h>
#include <services/filesystem.h>
#include <networking/time.h>
#include <networking/ip.h>
#include <networking/socket.h>
#include <networking/pool.h>
#include <networking/stream.h>
#include <networking/message.h>
#include <networking/ring.h>
#include <networking/reconnector.h>

#include <prodigy/bootstrap.config.h>
#include <prodigy/bundle.artifact.h>
#include <prodigy/acme.certbot.h>
#include <prodigy/brain.reachability.h>
#include <prodigy/cluster.bootstrap.h>
#include <prodigy/cluster.machine.helpers.h>
#include <prodigy/dns.provider.h>
#include <prodigy/debug.h>
#include <prodigy/ingress.validation.h>
#include <prodigy/mothership/mothership.cluster.types.h>
#include <prodigy/mothership/mothership.tunnel.auth.h>
#include <prodigy/mothership/mothership.tunnel.policy.h>
#include <prodigy/routable.address.helpers.h>
#include <prodigy/remote.bootstrap.h>
#include <prodigy/brain/timing.knobs.h>
#include <prodigy/brain/dns.operations.h>
#include <prodigy/brain/elastic.address.operations.h>
#include <prodigy/brain/machine.lifecycle.h>
#include <prodigy/brain/rack.h>
#include <prodigy/brain/machine.h>

#include <prodigy/brain/base.h>

#include <prodigy/brain/mesh.node.h>
#include <prodigy/brain/mesh.h>

#include <prodigy/brain/containerviews.h>

#include <prodigy/brain/deployments.h>

#include <prodigy/metro.networkmonitor.h>
#include <prodigy/memfd.blob.h>
#include <prodigy/wire.h>
#include <services/vault.h>

#pragma once

#ifndef NAMETAG_PRODIGY_DEV_FAKE_IPV4_ROUTE
#define NAMETAG_PRODIGY_DEV_FAKE_IPV4_ROUTE 0
#endif

enum class BrainTimeoutFlags : uint64_t {

  canceled = 0,
  updateOSWakeup,
  ignition,
  brainPeerHeartbeat,
  brainPeerReconnect,
  brainPeerLiveness,
  brainPeerHandshake,
  neuronControlReconnect,
  neuronControlHandshake,
  osUpdateCommandDeadline,
  hardRebootedMachine,
  brainMissing,
  softEscalationCheck,
  transitionStuck,
  performHardReboot,
  postIgnitionRecovery,
  spotDecomissionChecker,
  dnsReconcileRetry
};

static inline bool brainAddCertificateSubjectAltNames(X509 *cert, const Vector<String>& dnsSans, const Vector<IPAddress>& ipSans)
{
  if (cert == nullptr || (dnsSans.size() == 0 && ipSans.size() == 0))
  {
    return cert != nullptr;
  }

  GENERAL_NAMES *names = sk_GENERAL_NAME_new_null();
  if (names == nullptr)
  {
    return false;
  }

  bool ok = true;
  auto appendDns = [&](const String& san) -> bool {
    if (san.size() == 0)
    {
      return false;
    }

    GENERAL_NAME *name = GENERAL_NAME_new();
    ASN1_IA5STRING *value = ASN1_IA5STRING_new();
    String copy = {};
    copy.assign(san);
    if (name == nullptr || value == nullptr || ASN1_STRING_set(value, copy.c_str(), int(copy.size())) != 1)
    {
      if (name)
      {
        GENERAL_NAME_free(name);
      }
      if (value)
      {
        ASN1_IA5STRING_free(value);
      }
      return false;
    }

    GENERAL_NAME_set0_value(name, GEN_DNS, value);
    if (sk_GENERAL_NAME_push(names, name) <= 0)
    {
      GENERAL_NAME_free(name);
      return false;
    }

    return true;
  };

  auto appendIP = [&](const IPAddress& san) -> bool {
    if (san.isNull())
    {
      return false;
    }

    GENERAL_NAME *name = GENERAL_NAME_new();
    ASN1_OCTET_STRING *value = ASN1_OCTET_STRING_new();
    const int length = san.is6 ? 16 : 4;
    if (name == nullptr || value == nullptr || ASN1_OCTET_STRING_set(value, san.v6, length) != 1)
    {
      if (name)
      {
        GENERAL_NAME_free(name);
      }
      if (value)
      {
        ASN1_OCTET_STRING_free(value);
      }
      return false;
    }

    GENERAL_NAME_set0_value(name, GEN_IPADD, value);
    if (sk_GENERAL_NAME_push(names, name) <= 0)
    {
      GENERAL_NAME_free(name);
      return false;
    }

    return true;
  };

  for (const String& san : dnsSans)
  {
    if (appendDns(san) == false)
    {
      ok = false;
      break;
    }
  }

  if (ok)
  {
    for (const IPAddress& san : ipSans)
    {
      if (appendIP(san) == false)
      {
        ok = false;
        break;
      }
    }
  }

  if (ok)
  {
    ok = (X509_add1_ext_i2d(cert, NID_subject_alt_name, names, 1, X509V3_ADD_APPEND) == 1);
  }

  sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
  return ok;
}

inline void BrainBase::sendNeuronSwitchboardRoutableSubnets(void)
{
  Vector<DistributableExternalSubnet> subnets = {};
  buildSwitchboardFleetRoutableSubnets(subnets);

  String serializedSubnets;
  BitseryEngine::serialize(serializedSubnets, subnets);

  for (Machine *machine : machines)
  {
    if (neuronControlStreamActive(machine) == false)
    {
      continue;
    }

    Message::construct(machine->neuron.wBuffer, NeuronTopic::configureSwitchboardRoutableSubnets, serializedSubnets);
    Ring::queueSend(&machine->neuron);
  }
}

inline void BrainBase::buildSwitchboardFleetRoutableSubnets(Vector<DistributableExternalSubnet>& subnets) const
{
  subnets.clear();
  for (const DistributableExternalSubnet& subnet : brainConfig.distributableExternalSubnets)
  {
    if (subnet.ingressScope == RoutableIngressScope::switchboardFleet)
    {
      subnets.push_back(subnet);
    }
  }
}

inline void BrainBase::buildHostedSwitchboardIngressPrefixes(Machine *machine, Vector<IPPrefix>& prefixes) const
{
  prefixes.clear();
  if (machine == nullptr)
  {
    return;
  }

  auto appendPrefixIfMissing = [&](const IPPrefix& candidate) -> void {
    for (const IPPrefix& existing : prefixes)
    {
      if (existing.equals(candidate))
      {
        return;
      }
    }

    prefixes.push_back(candidate);
  };

  for (const DistributableExternalSubnet& subnet : brainConfig.distributableExternalSubnets)
  {
    if (subnet.ingressScope == RoutableIngressScope::singleMachine && subnet.machineUUID != 0 && subnet.subnet.network.isNull() == false)
    {
      appendPrefixIfMissing(distributableExternalSubnetSwitchboardSubnet(subnet).canonicalized());
    }
  }
}

inline bool BrainBase::whiteholeTargetsNeuronMachine(ContainerView *container, Machine *targetMachine, const Whitehole& whitehole) const
{
  (void)whitehole;
  if (container == nullptr || targetMachine == nullptr)
  {
    return false;
  }

  return container->machine == targetMachine;
}

inline void BrainBase::collectWhiteholesForNeuronMachine(ContainerView *container, Machine *targetMachine, const Vector<Whitehole>& sourceWhiteholes, Vector<Whitehole>& whiteholes) const
{
  whiteholes.clear();
  if (container == nullptr || targetMachine == nullptr)
  {
    return;
  }

  for (const Whitehole& whitehole : sourceWhiteholes)
  {
    if (whitehole.hasAddress == false || whitehole.address.isNull() || whitehole.sourcePort == 0 || whitehole.bindingNonce == 0)
    {
      continue;
    }

    if (whiteholeTargetsNeuronMachine(container, targetMachine, whitehole) == false)
    {
      continue;
    }

    whiteholes.push_back(whitehole);
  }
}

inline void BrainBase::sendNeuronSwitchboardHostedIngressPrefixes(Machine *machine)
{
  if (neuronControlStreamActive(machine) == false)
  {
    return;
  }

  Vector<IPPrefix> prefixes = {};
  buildHostedSwitchboardIngressPrefixes(machine, prefixes);

  String serializedPrefixes = {};
  BitseryEngine::serialize(serializedPrefixes, prefixes);
  Message::construct(machine->neuron.wBuffer, NeuronTopic::configureSwitchboardHostedIngressPrefixes, serializedPrefixes);
  Ring::queueSend(&machine->neuron);
}

inline void BrainBase::sendNeuronSwitchboardHostedIngressPrefixes(void)
{
  for (Machine *machine : machines)
  {
    if (machine == nullptr)
    {
      continue;
    }

    sendNeuronSwitchboardHostedIngressPrefixes(machine);
  }
}

inline void BrainBase::sendNeuronRuntimeEnvironmentConfig(void)
{
  String serializedEnvironment;
  BitseryEngine::serialize(serializedEnvironment, brainConfig.runtimeEnvironment);

  for (Machine *machine : machines)
  {
    if (neuronControlStreamActive(machine) == false)
    {
      continue;
    }

    Message::construct(machine->neuron.wBuffer, NeuronTopic::configureRuntimeEnvironment, serializedEnvironment);
    Ring::queueSend(&machine->neuron);
  }
}

inline bool BrainBase::environmentBGPEnabled(void) const
{
  return iaas && iaas->bgpEnabledForEnvironment();
}

inline bool BrainBase::buildSwitchboardOverlayRoutingConfig(Machine *machine, SwitchboardOverlayRoutingConfig& config) const
{
  config = {};
  // Private container-network traffic between machines must route by machine
  // fragment through the overlay path. Hosted-ingress / pinned external
  // prefixes layer on top of that same machine-routing substrate; they do not
  // replace cross-machine private container delivery.
  config.containerNetworkViaOverlay = true;

  for (const DistributableExternalSubnet& subnet : brainConfig.distributableExternalSubnets)
  {
    if (subnet.routing == ExternalSubnetRouting::switchboardPinnedRoute)
    {
      config.overlaySubnets.push_back(distributableExternalSubnetSwitchboardSubnet(subnet));
    }
  }

  if (machine == nullptr)
  {
    return true;
  }

  auto appendHostedIngressRouteIfMissing = [&](const IPPrefix& prefix, uint32_t machineFragment) -> void {
    if (machineFragment == 0)
    {
      return;
    }

    for (const SwitchboardOverlayHostedIngressRoute& existing : config.hostedIngressRoutes)
    {
      if (existing.machineFragment == machineFragment && existing.prefix.equals(prefix))
      {
        return;
      }
    }

    SwitchboardOverlayHostedIngressRoute route = {};
    route.prefix = prefix;
    route.machineFragment = machineFragment;
    config.hostedIngressRoutes.push_back(route);
  };

  auto appendHostedIngressAddressIfMissing = [&](const IPAddress& address, uint32_t machineFragment) -> void {
    IPPrefix prefix = {};
    if (machineFragment == 0 || address.isNull() || makeHostedIngressPrefixForAddress(address, prefix) == false)
    {
      return;
    }

    appendHostedIngressRouteIfMissing(prefix, machineFragment);
  };

  Vector<ClusterMachinePeerAddress> localCandidates = {};
  prodigyCollectMachineOverlayRouteAddresses(*machine, localCandidates);

  Vector<Machine *> sortedMachines = {};
  sortedMachines.reserve(machines.size());
  for (Machine *candidate : machines)
  {
    if (candidate != nullptr)
    {
      sortedMachines.push_back(candidate);
    }
  }

  std::sort(sortedMachines.begin(), sortedMachines.end(), [](const Machine *lhs, const Machine *rhs) -> bool {
    return prodigyMachineIdentityComesBefore(*lhs, *rhs);
  });

  for (Machine *candidate : sortedMachines)
  {
    if (candidate == nullptr || candidate == machine || prodigyMachinesShareIdentity(*candidate, *machine) || candidate->fragment == 0)
    {
      continue;
    }

    Vector<ClusterMachinePeerAddress> remoteCandidates = {};
    prodigyCollectMachineOverlayRouteAddresses(*candidate, remoteCandidates);

    auto appendIPv6Route = [&]() -> bool {
      for (const ClusterMachinePeerAddress& remoteCandidate : remoteCandidates)
      {
        IPAddress transportAddress = {};
        if (ClusterMachine::parseIPAddressLiteral(remoteCandidate.address, transportAddress) == false || transportAddress.is6 == false)
        {
          continue;
        }

        IPAddress nextHop = {};
        nextHop = transportAddress;
        if (remoteCandidate.gateway.size() > 0)
        {
          if (ClusterMachine::parseIPAddressLiteral(remoteCandidate.gateway, nextHop) == false || nextHop.is6 == false)
          {
            continue;
          }
        }

        IPAddress sourceAddress = {};
        if (const MachineNicHardwareProfile *localNextHopNic = prodigyFindMachineNicContainingAddress(*machine, nextHop);
            localNextHopNic != nullptr)
        {
          const MachineNicSubnetHardwareProfile *localNextHopSubnet = nullptr;
          localNextHopNic = prodigyFindMachineNicContainingAddress(*machine, nextHop, &localNextHopSubnet);
          if (localNextHopSubnet == nullptr || localNextHopSubnet->address.is6 == false)
          {
            continue;
          }

          sourceAddress = localNextHopSubnet->address;
        }
        else if (prodigyResolvePreferredLocalSourceAddress(localCandidates, remoteCandidate, sourceAddress) == false || sourceAddress.is6 == false)
        {
          continue;
        }

        SwitchboardOverlayMachineRoute route = {};
        route.machineFragment = candidate->fragment;
        route.nextHop = nextHop;
        route.sourceAddress = sourceAddress;

        const MachineNicSubnetHardwareProfile *localDirectSubnet = nullptr;
        const MachineNicHardwareProfile *localDirectNic = prodigyFindMachineNicContainingAddress(*machine, transportAddress, &localDirectSubnet);
        const MachineNicHardwareProfile *remoteDirectNic = prodigyFindMachineNicByAssignedAddress(*candidate, transportAddress);
        bool directPeerRoute = (remoteCandidate.gateway.size() == 0 && localDirectNic != nullptr && localDirectSubnet != nullptr && localDirectSubnet->address.equals(sourceAddress));
        if (directPeerRoute)
        {
          if (remoteDirectNic != nullptr && remoteDirectNic->mac.size() > 0)
          {
            route.useGatewayMAC = false;
            route.nextHopMAC.assign(remoteDirectNic->mac);
          }
          else
          {
            route.useGatewayMAC = true;
          }
        }
        else
        {
          route.useGatewayMAC = true;
        }

        config.machineRoutes.push_back(route);
        return true;
      }

      return false;
    };

    (void)appendIPv6Route();

    if (candidate->publicAddress.size() > 0)
    {
      IPAddress publicAddress = {};
      if (ClusterMachine::parseIPAddressLiteral(candidate->publicAddress, publicAddress))
      {
        appendHostedIngressAddressIfMissing(publicAddress, candidate->fragment);
      }
    }

    for (const ClusterMachinePeerAddress& publicCandidate : candidate->peerAddresses)
    {
      if (prodigyClusterMachinePeerAddressIsPrivate(publicCandidate))
      {
        continue;
      }

      IPAddress publicAddress = {};
      if (ClusterMachine::parseIPAddressLiteral(publicCandidate.address, publicAddress))
      {
        appendHostedIngressAddressIfMissing(publicAddress, candidate->fragment);
      }
    }
  }

  for (const DistributableExternalSubnet& subnet : brainConfig.distributableExternalSubnets)
  {
    if (subnet.ingressScope != RoutableIngressScope::singleMachine || subnet.machineUUID == 0 || subnet.machineUUID == machine->uuid || subnet.subnet.network.isNull())
    {
      continue;
    }

    Machine *owner = nullptr;
    for (Machine *candidate : machines)
    {
      if (candidate != nullptr && candidate->uuid == subnet.machineUUID)
      {
        owner = candidate;
        break;
      }
    }

    if (owner == nullptr || owner->fragment == 0 || prodigyMachinesShareIdentity(*owner, *machine))
    {
      continue;
    }

    appendHostedIngressRouteIfMissing(distributableExternalSubnetSwitchboardSubnet(subnet).canonicalized(), owner->fragment);
  }

  return true;
}

inline void BrainBase::sendNeuronSwitchboardOverlayRoutes(Machine *machine)
{
  if (neuronControlStreamActive(machine) == false)
  {
    return;
  }

  SwitchboardOverlayRoutingConfig config = {};
  if (buildSwitchboardOverlayRoutingConfig(machine, config) == false)
  {
    return;
  }

  String serializedConfig = {};
  BitseryEngine::serialize(serializedConfig, config);
  Message::construct(machine->neuron.wBuffer, NeuronTopic::configureSwitchboardOverlayRoutes, serializedConfig);
  Ring::queueSend(&machine->neuron);
}

inline void BrainBase::sendNeuronSwitchboardOverlayRoutes(void)
{
  for (Machine *machine : machines)
  {
    if (machine == nullptr)
    {
      continue;
    }

    sendNeuronSwitchboardOverlayRoutes(machine);
  }
}

inline void BrainBase::sendNeuronSwitchboardStateSync(Machine *machine)
{
  if (neuronControlStreamActive(machine) == false)
  {
    return;
  }

  Message::appendEcho(machine->neuron.wBuffer, static_cast<uint16_t>(NeuronTopic::resetSwitchboardState));

  String serializedEnvironment;
  BitseryEngine::serialize(serializedEnvironment, brainConfig.runtimeEnvironment);
  Message::construct(machine->neuron.wBuffer, NeuronTopic::configureRuntimeEnvironment, serializedEnvironment);

  String serializedSubnets;
  Vector<DistributableExternalSubnet> subnets = {};
  buildSwitchboardFleetRoutableSubnets(subnets);
  BitseryEngine::serialize(serializedSubnets, subnets);
  Message::construct(machine->neuron.wBuffer, NeuronTopic::configureSwitchboardRoutableSubnets, serializedSubnets);

  Vector<IPPrefix> hostedPrefixes = {};
  buildHostedSwitchboardIngressPrefixes(machine, hostedPrefixes);
  String serializedHostedPrefixes = {};
  BitseryEngine::serialize(serializedHostedPrefixes, hostedPrefixes);
  Message::construct(machine->neuron.wBuffer, NeuronTopic::configureSwitchboardHostedIngressPrefixes, serializedHostedPrefixes);

  SwitchboardOverlayRoutingConfig overlayConfig = {};
  if (buildSwitchboardOverlayRoutingConfig(machine, overlayConfig))
  {
    String serializedOverlayConfig = {};
    BitseryEngine::serialize(serializedOverlayConfig, overlayConfig);
    Message::construct(machine->neuron.wBuffer, NeuronTopic::configureSwitchboardOverlayRoutes, serializedOverlayConfig);
  }

  for (const auto& [uuid, container] : containers)
  {
    (void)uuid;
    if (container == nullptr || container->wormholes.empty())
    {
      continue;
    }

    if (container->state != ContainerState::healthy && container->state != ContainerState::crashedRestarting)
    {
      continue;
    }

    String serializedWormholes = {};
    BitseryEngine::serialize(serializedWormholes, container->wormholes);
    Message::construct(
        machine->neuron.wBuffer,
        NeuronTopic::openSwitchboardWormholes,
        container->generateContainerID(),
        serializedWormholes);
  }

  for (const auto& [uuid, container] : containers)
  {
    (void)uuid;
    if (container == nullptr || container->whiteholes.empty())
    {
      continue;
    }

    if (container->state != ContainerState::scheduled && container->state != ContainerState::healthy && container->state != ContainerState::crashedRestarting)
    {
      continue;
    }

    Vector<Whitehole> whiteholesForMachine = {};
    collectWhiteholesForNeuronMachine(container, machine, container->whiteholes, whiteholesForMachine);
    if (whiteholesForMachine.empty())
    {
      continue;
    }

    uint32_t headerOffset = Message::appendHeader(machine->neuron.wBuffer, static_cast<uint16_t>(NeuronTopic::openSwitchboardWhiteholes));
    Message::append(machine->neuron.wBuffer, container->generateContainerID());

    for (const Whitehole& whitehole : whiteholesForMachine)
    {
      Message::append(machine->neuron.wBuffer, whitehole.sourcePort);
      Message::appendAlignedBuffer<Alignment::one>(machine->neuron.wBuffer, whitehole.address.v6, 16);
      Message::append(machine->neuron.wBuffer, whitehole.address.is6);
      Message::append(machine->neuron.wBuffer, whitehole.transport);
      Message::append(machine->neuron.wBuffer, whitehole.bindingNonce);
    }

    Message::finish(machine->neuron.wBuffer, headerOffset);
  }

  Ring::queueSend(&machine->neuron);
}

inline void BrainBase::sendNeuronOpenSwitchboardWormholes(ContainerView *container, const Vector<Wormhole>& wormholes)
{
  if (container == nullptr || wormholes.empty())
  {
    return;
  }

  bool refreshHostedIngressPrefixes = false;
  for (const Wormhole& wormhole : wormholes)
  {
    if (wormhole.source == ExternalAddressSource::registeredRoutablePrefix)
    {
      refreshHostedIngressPrefixes = true;
      break;
    }
  }

  String serializedWormholes = {};
  BitseryEngine::serialize(serializedWormholes, wormholes);

  for (Machine *machine : machines)
  {
    if (neuronControlStreamActive(machine) == false)
    {
      continue;
    }

    if (refreshHostedIngressPrefixes)
    {
      sendNeuronSwitchboardHostedIngressPrefixes(machine);
    }

    Message::construct(
        machine->neuron.wBuffer,
        NeuronTopic::openSwitchboardWormholes,
        container->generateContainerID(),
        serializedWormholes);
    Ring::queueSend(&machine->neuron);
  }
}

inline void BrainBase::sendNeuronRefreshContainerWormholes(ContainerView *container, const Vector<Wormhole>& wormholes)
{
  if (container == nullptr)
  {
    return;
  }

  String serializedWormholes = {};
  BitseryEngine::serialize(serializedWormholes, wormholes);
  container->proxySend(NeuronTopic::refreshContainerWormholes, container->uuid, serializedWormholes);
}

inline void BrainBase::sendNeuronCloseSwitchboardWormholesToContainer(ContainerView *container)
{
  if (container == nullptr)
  {
    return;
  }

  uint32_t containerID = container->generateContainerID();

  for (Machine *machine : machines)
  {
    if (neuronControlStreamActive(machine) == false)
    {
      continue;
    }

    Message::construct(machine->neuron.wBuffer, NeuronTopic::closeSwitchboardWormholesToContainer, containerID);
    Ring::queueSend(&machine->neuron);
  }
}

inline void BrainBase::sendNeuronOpenSwitchboardWhiteholes(ContainerView *container, const Vector<Whitehole>& whiteholes)
{
  if (container == nullptr || container->machine == nullptr || whiteholes.empty())
  {
    return;
  }

  for (Machine *machine : machines)
  {
    if (neuronControlStreamActive(machine) == false)
    {
      continue;
    }

    Vector<Whitehole> whiteholesForMachine = {};
    collectWhiteholesForNeuronMachine(container, machine, whiteholes, whiteholesForMachine);
    if (whiteholesForMachine.empty())
    {
      continue;
    }

    uint32_t headerOffset = Message::appendHeader(machine->neuron.wBuffer, static_cast<uint16_t>(NeuronTopic::openSwitchboardWhiteholes));
    Message::append(machine->neuron.wBuffer, container->generateContainerID());

    for (const Whitehole& whitehole : whiteholesForMachine)
    {
      Message::append(machine->neuron.wBuffer, whitehole.sourcePort);
      Message::appendAlignedBuffer<Alignment::one>(machine->neuron.wBuffer, whitehole.address.v6, 16);
      Message::append(machine->neuron.wBuffer, whitehole.address.is6);
      Message::append(machine->neuron.wBuffer, whitehole.transport);
      Message::append(machine->neuron.wBuffer, whitehole.bindingNonce);
    }

    Message::finish(machine->neuron.wBuffer, headerOffset);
    Ring::queueSend(&machine->neuron);
  }
}

inline void BrainBase::sendNeuronCloseSwitchboardWhiteholesToContainer(ContainerView *container)
{
  if (container == nullptr || container->machine == nullptr)
  {
    return;
  }

  uint32_t containerID = container->generateContainerID();
  Machine *machine = container->machine;
  if (neuronControlStreamActive(machine) == false)
  {
    return;
  }

  Message::construct(machine->neuron.wBuffer, NeuronTopic::closeSwitchboardWhiteholesToContainer, containerID);
  Ring::queueSend(&machine->neuron);
}

class Mothership : public TCPStream, public CoroutineStack {
private:

public:

  bool closeAfterSendDrain = false;
  uint64_t connectionIncarnation = 0;

  Mothership()
  {
    rBuffer.reserve(8_KB);
    wBuffer.reserve(16_KB);
  }
};

class BrainTlsResumptionAckState {
public:

  uint64_t generation = 0;
  bool success = false;
  String failureReason;
};

class BrainTlsResumptionWormholeState {
public:

  TlsResumptionSnapshot snapshot;
  bytell_hash_map<uint128_t, BrainTlsResumptionAckState> acksByContainer;
};

class BrainTlsResumptionDeploymentState {
public:

  bytell_hash_map<String, BrainTlsResumptionWormholeState> wormholes;
};

class PublicTlsCertbotJob {
public:

  pid_t pid = -1;
  int64_t startedAtMs = 0;
  int lockFD = -1;
};

class ProdigyMasterAuthorityStateTransition
{
public:

  constexpr static uint8_t currentVersion = 1;

  uint8_t version = currentVersion;
  ProdigyMasterAuthorityRuntimeState runtimeState;
  BrainConfig brainConfig;
};

template <typename S>
static void serialize(S&& serializer, ProdigyMasterAuthorityStateTransition& transition)
{
  serializer.value1b(transition.version);
  serializer.object(transition.runtimeState);
  serializer.object(transition.brainConfig);
}

class Brain : public BrainBase, public TimeoutDispatcher {
public:

  class PendingElasticAddressControlOperation
  {
  public:

    Mothership *mothership = nullptr;
    BrainIaaS *provider = nullptr;
    ProdigyBrainElasticAddressCoordinator::Action action = ProdigyBrainElasticAddressCoordinator::Action::prepareAssignment;
    uint64_t operationID = 0;
    uint64_t mothershipIncarnation = 0;
    uint64_t authorityEpoch = 0;
    uint64_t sagaOperationID = 0;
    uint128_t transactionNonce = 0;
    uint128_t machineUUID = 0;
    bool providerOperationEnqueued = false;
    String machineCloudID;
    IPPrefix expectedDeliveryPrefix;
    RoutableSubnetRegistration registration;
    RoutableSubnetUnregistration unregistration;
    DistributableExternalSubnet releasedPrefix;
  };

  class MasterAuthorityReplicationPeerState
  {
  public:

    uint128_t uuid = 0;
    int64_t bootNs = 0;
    uint64_t acknowledgedGeneration = 0;
    bytell_hash_map<uint64_t, bytell_hash_set<uint64_t>> sentElasticOperationIDsByGeneration;
    bytell_hash_map<uint64_t, String> sentTransitionDigestsByGeneration;
    bytell_hash_set<uint64_t> acknowledgedElasticOperationIDs;
  };

  // any brain
  uint8_t nBrains = 0;
  uint32_t brainPeerKeepaliveSeconds = prodigyBrainPeerKeepaliveSeconds;
  uint32_t brainPeerHeartbeatIntervalMs = prodigyBrainPeerHeartbeatIntervalMs;
  uint32_t brainPeerHeartbeatTimeoutMs = prodigyBrainPeerHeartbeatTimeoutMs;
  int64_t lastBrainPeerHeartbeatTickMs = 0;
  int64_t boottimens;

  TCPSocket brainSocket;
  struct sockaddr_storage brain_saddr = {};
  socklen_t brain_saddrlen = sizeof(struct sockaddr_storage);
  IPAddress localBrainPeerAddress = {};
  String localBrainPeerAddressText;
  Vector<ClusterMachinePeerAddress> localBrainPeerAddresses;

  bool noMasterYet = true;
  bool weAreMaster = false;
  uint64_t masterAuthorityEpoch = 1;
  uint64_t lastMothershipConnectionIncarnation = 0;
  uint64_t durableMasterAuthorityRuntimeStateGeneration = 0;
  bool masterAuthorityRuntimeStateDurable = false;
  bytell_hash_map<uint64_t, uint64_t> durableElasticOperationTransitions;
  bool hasCompletedInitialMasterElection = false;

  enum class UpdateSelfState : uint8_t {
    idle,
    waitingForBundleEchos,
    waitingForFollowerReboots,
    waitingForRelinquishEchos
  };
  UpdateSelfState updateSelfState = UpdateSelfState::idle;
  uint32_t updateSelfExpectedEchos = 0;
  uint32_t updateSelfBundleEchos = 0;
  uint32_t updateSelfRelinquishEchos = 0;
  uint128_t updateSelfPlannedMasterPeerKey = 0;
  uint128_t pendingDesignatedMasterPeerKey = 0;
  bool updateSelfUseStagedBundleOnly = false;
  bool updateSelfTransitionAfterMothershipAck = false;
  String updateSelfBundleBlob;
  bytell_hash_set<uint128_t> updateSelfBundleIssuedPeerKeys;
  bytell_hash_set<uint128_t> updateSelfBundleEchoPeerKeys;
  bytell_hash_set<uint128_t> updateSelfRelinquishEchoPeerKeys;
  bytell_hash_map<uint128_t, int64_t> updateSelfFollowerBootNsByPeerKey;
  bytell_hash_set<uint128_t> updateSelfFollowerReconnectedPeerKeys;
  bytell_hash_set<uint128_t> updateSelfFollowerRebootedPeerKeys;
  bytell_hash_set<uint128_t> updateSelfTransitionIssuedPeerKeys;
  bytell_hash_set<uint128_t> updateSelfRelinquishIssuedPeerKeys;
  constexpr static int64_t connectFailureLogIntervalMs = prodigyBrainConnectFailureLogIntervalMs;
  constexpr static int64_t certificateLifecycleBaseRetryDelayMs = 5 * 60 * 1000;
  constexpr static int64_t certificateLifecycleMaxRetryDelayMs = 60 * 60 * 1000;
  constexpr static int64_t certificateLifecycleMaxJitterMs = 15 * 60 * 1000;
  constexpr static int64_t credentialDeltaAckTimeoutMs = 5 * 60 * 1000;
  constexpr static int64_t publicTlsCertbotTimeoutMs = 60 * 60 * 1000;
  constexpr static int64_t mothershipTunnelProviderBaseRetryDelayMs = 5 * 1000;
  constexpr static int64_t mothershipTunnelProviderMaxRetryDelayMs = 5 * 60 * 1000;
  constexpr static int64_t mothershipTunnelProviderSessionHealthTtlMs = 60 * 1000;
  bytell_hash_map<uint64_t, int64_t> connectFailureNextLogMsByKey;

  // not master brain
  bool isMasterMissing = false;
  bool masterQuorumDegraded = false;

  // master brain
  bool ignited = false;

  TimeoutPacket osUpdateTimer;
  bool osUpdateTimerInstalled = false;
  bool osUpdateTimerArmed = false;
  int64_t lastOperatingSystemUpdateStartMs = 0;
  TimeoutPacket ignitionSwitch;
  TimeoutPacket brainPeerHeartbeatTicker;
  TimeoutPacket spotDecomissionChecker;
  bool spotDecommissionCheckActive = false;
  CoroutineStack spotDecommissionCheckCoroutine;
  ProdigyBrainMachineLifecycleCoordinator machineLifecycle;
  ProdigyBrainElasticAddressCoordinator elasticAddressOperations;
  ProdigyBrainDNSOperationCoordinator dnsOperations;
  TimeoutPacket dnsReconcileRetry;
  bool dnsReconcileRetryInstalled = false;
  bool dnsReconcileRetryArmed = false;
  uint32_t dnsReconcileFailureCount = 0;
  enum class PendingDNSOperationKind : uint8_t
  {
    lease,
    challenge
  };
  class PendingDNSOperation
  {
  public:

    PendingDNSOperationKind kind = PendingDNSOperationKind::lease;
    ProdigyBrainDNSOperationCoordinator::Action action = ProdigyBrainDNSOperationCoordinator::Action::upsert;
    RoutableResourceLease lease;
    ProdigyDNSRecordBinding record;
    String certificateKey;
    Mothership *stream = nullptr;
    uint64_t streamIncarnation = 0;
    MothershipTopic topic = MothershipTopic::presentACMEDNS01Challenge;
    AcmeDNS01ChallengeResponse *inlineResponse = nullptr;
    uint64_t controlID = 0;
  };
  class PendingDNSControl
  {
  public:

    Mothership *stream = nullptr;
    uint64_t streamIncarnation = 0;
    MothershipTopic topic = MothershipTopic::upsertDNSBinding;
    RoutableResourceLeaseReport response;
    RoutableResourceLeaseReport *inlineResponse = nullptr;
    uint32_t outstanding = 0;
  };
  class PendingContainerLogs
  {
  public:

    Mothership *stream = nullptr;
    uint64_t streamIncarnation = 0;
    int64_t deadlineMs = 0;
    uint32_t maximumBytesPerNeuron = 0;
    ContainerLogsOperation operation;
    bytell_hash_set<uint128_t> outstandingMachines;
  };
  bytell_hash_map<uint64_t, PendingDNSOperation> pendingDNSOperations;
  bytell_hash_map<uint64_t, PendingDNSControl> pendingDNSControls;
  bytell_hash_map<uint64_t, PendingContainerLogs> pendingContainerLogs;
  Vector<RoutableResourceLease> appliedDNSRecordLeases;
  bytell_hash_set<uint64_t> deploymentsWaitingForDNS;
  uint64_t nextDNSOperationOwner = 1;
  uint64_t nextContainerLogRequestID = 1;
  bytell_hash_map<uint64_t, PendingElasticAddressControlOperation> pendingElasticAddressControlOperations;
  bytell_hash_map<BrainView *, MasterAuthorityReplicationPeerState> masterAuthorityReplicationByPeer;
  CoroutineStack brainInventoryCoroutine;
  bytell_hash_map<BrainView *, TimeoutPacket *> brainWaiters;
  bytell_hash_map<BrainView *, TimeoutPacket *> brainReconnectWaiters;
  bytell_hash_map<BrainView *, TimeoutPacket *> brainLivenessWaiters;
  bytell_hash_map<BrainView *, TimeoutPacket *> brainHandshakeWaiters;
  bytell_hash_map<NeuronView *, TimeoutPacket *> neuronReconnectWaiters;
  bytell_hash_map<NeuronView *, TimeoutPacket *> neuronHandshakeWaiters;
  Vector<Machine *> operatingSystemUpdateOrder;

  bytell_hash_set<NeuronView *> neurons;

  // just create a new ssh instance each time we need it... simplies everything for now.. unless we intended to use it regularly
  bytell_hash_set<MachineSSH *> sshs;

  Mothership *mothership = nullptr;
  bytell_hash_set<Mothership *> activeMotherships;
  bytell_hash_set<Mothership *> closingMotherships;
  UnixSocket mothershipUnixSocket;
  bool mothershipUnixAcceptArmed = false;
  String mothershipUnixSocketPath;
  bool mothershipUnixSocketPathInodeRecorded = false;
  dev_t mothershipUnixSocketPathDevice = 0;
  ino_t mothershipUnixSocketPathInode = 0;
  bytell_hash_map<uint64_t, Mothership *> spinApplicationMotherships;
  bytell_hash_map<uint128_t, Machine *> machinesByUUID;
  ProdigyDNSProvider *dnsProvider = nullptr;

  bytell_hash_map<uint16_t, ApplicationTlsVaultFactory> tlsVaultFactoriesByApp;
  bytell_hash_map<uint16_t, ApplicationApiCredentialSet> apiCredentialSetsByApp;
  bytell_hash_map<uint64_t, BrainTlsResumptionDeploymentState> tlsResumptionStateByDeployment;
  bytell_hash_map<String, PublicTlsCertbotJob> publicTlsCertbotJobs;
  bytell_hash_map<String, uint16_t> reservedApplicationIDsByName;
  bytell_hash_map<uint16_t, String> reservedApplicationNamesByID;
  bytell_hash_map<String, ApplicationServiceIdentity> reservedApplicationServicesByNameKey;
  bytell_hash_map<uint64_t, ApplicationServiceIdentity> reservedApplicationServicesByID;
  bytell_hash_map<uint32_t, String> reservedApplicationServiceNamesBySlotKey;
  bytell_hash_map<uint16_t, uint8_t> nextReservableServiceSlotByApplication;
  MothershipConnectivity mothershipConnectivity;
  MothershipTunnelGatewayAuth mothershipTunnelGatewayAuth;
  struct {
    TunnelProviderPhase phase = TunnelProviderPhase::disabled;
    uint128_t localContainerUUID = 0;
    uint32_t failureCount = 0;
    int64_t nextRetryMs = 0;
    int64_t lastHealthyAtMs = 0;
    String lastFailure;
  } mothershipTunnelProviderRuntimeState;
  uint16_t nextReservableApplicationID = 1;
  uint64_t nextMintedClientTlsGeneration = 1;
  uint64_t nextTlsResumptionGeneration = 1;
  ProdigyMasterAuthorityRuntimeState masterAuthorityRuntimeState;
  bytell_hash_map<uint64_t, Vector<BrainReplicatedContainerRuntimeState>> pendingReplicatedContainerRuntimeStates;

  // 2,592,000 seconds in 30 days. so even if each reboot took 20 seconds (in reality it'll be closer to 10 seconds, but should be more like 5 seconds)
  // we'd still have capacity to be rebooting to update the OS on over 125,000 machines a month, never doing more than 1 machine at at time.
  // google updates their machines at least once a month
  // removed legacy OS update order; updates now driven by explicit targets

  bool isValidReservedApplicationName(const String& applicationName) const
  {
    uint32_t n = uint32_t(applicationName.size());
    if (n == 0 || n > 96)
    {
      return false;
    }

    const char *chars = reinterpret_cast<const char *>(applicationName.data());
    for (uint32_t i = 0; i < n; i += 1)
    {
      char c = chars[i];
      bool isAlpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
      bool isDigit = (c >= '0' && c <= '9');
      bool isAllowedPunct = (c == '_' || c == '-' || c == '.');
      if (isAlpha == false && isDigit == false && isAllowedPunct == false)
      {
        return false;
      }
    }

    return true;
  }

  bool isValidReservedServiceName(const String& serviceName) const
  {
    uint32_t n = uint32_t(serviceName.size());
    if (n == 0 || n > 96)
    {
      return false;
    }

    const char *chars = reinterpret_cast<const char *>(serviceName.data());
    for (uint32_t i = 0; i < n; i += 1)
    {
      char c = chars[i];
      bool isAlpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
      bool isDigit = (c >= '0' && c <= '9');
      bool isAllowedPunct = (c == '_' || c == '-');
      if (isAlpha == false && isDigit == false && isAllowedPunct == false)
      {
        return false;
      }
    }

    return true;
  }

  static uint32_t makeReservedServiceSlotKey(uint16_t applicationID, uint8_t serviceSlot)
  {
    return (uint32_t(applicationID) << 8) | uint32_t(serviceSlot);
  }

  static uint64_t materializeReservedService(const ApplicationServiceIdentity& identity)
  {
    if (identity.kind == ApplicationServiceIdentity::Kind::stateful)
    {
      return (uint64_t(identity.applicationID) << 48) | (uint64_t(identity.serviceSlot) << 40) | ((1ull << 10) - 1);
    }

    return (uint64_t(identity.applicationID) << 48) | (uint64_t(identity.serviceSlot) << 40);
  }

  String makeReservedServiceNameKey(uint16_t applicationID, const String& serviceName) const
  {
    String key;
    key.snprintf<"{itoa}:{}"_ctv>(applicationID, serviceName);
    return key;
  }

  bool resolveReservedApplicationID(const String& applicationName, uint16_t& applicationID) const
  {
    if (auto byName = reservedApplicationIDsByName.find(applicationName); byName != reservedApplicationIDsByName.end())
    {
      applicationID = byName->second;
      return true;
    }

    return false;
  }

  bool reserveApplicationIDMapping(const String& applicationName, uint16_t applicationID, String *failure = nullptr)
  {
    if (applicationID == 0)
    {
      if (failure)
      {
        failure->assign("applicationID invalid"_ctv);
      }
      return false;
    }

    if (isValidReservedApplicationName(applicationName) == false)
    {
      if (failure)
      {
        failure->assign("applicationName invalid"_ctv);
      }
      return false;
    }

    if (auto byName = reservedApplicationIDsByName.find(applicationName); byName != reservedApplicationIDsByName.end() && byName->second != applicationID)
    {
      if (failure)
      {
        failure->assign("applicationName already reserved with different applicationID"_ctv);
      }
      return false;
    }

    if (auto byID = reservedApplicationNamesByID.find(applicationID); byID != reservedApplicationNamesByID.end() && byID->second.equals(applicationName) == false)
    {
      if (failure)
      {
        failure->assign("applicationID already reserved by a different applicationName"_ctv);
      }
      return false;
    }

    String ownedApplicationName = {};
    ownedApplicationName.assign(applicationName);
    reservedApplicationIDsByName.insert_or_assign(ownedApplicationName, applicationID);
    reservedApplicationNamesByID.insert_or_assign(applicationID, ownedApplicationName);
    if (applicationID >= nextReservableApplicationID && applicationID < UINT16_MAX)
    {
      nextReservableApplicationID = uint16_t(applicationID + 1);
    }

    return true;
  }

  bool reserveApplicationServiceMapping(const ApplicationServiceIdentity& identity, String *failure = nullptr)
  {
    if (identity.applicationID == 0 || isApplicationIDReserved(identity.applicationID) == false)
    {
      if (failure)
      {
        failure->assign("applicationID not reserved"_ctv);
      }
      return false;
    }

    if (isValidReservedServiceName(identity.serviceName) == false)
    {
      if (failure)
      {
        failure->assign("serviceName invalid"_ctv);
      }
      return false;
    }

    if (identity.serviceSlot == 0)
    {
      if (failure)
      {
        failure->assign("serviceSlot invalid"_ctv);
      }
      return false;
    }

    if (identity.kind != ApplicationServiceIdentity::Kind::stateless && identity.kind != ApplicationServiceIdentity::Kind::stateful)
    {
      if (failure)
      {
        failure->assign("service kind invalid"_ctv);
      }
      return false;
    }

    String nameKey = makeReservedServiceNameKey(identity.applicationID, identity.serviceName);
    if (auto byName = reservedApplicationServicesByNameKey.find(nameKey); byName != reservedApplicationServicesByNameKey.end())
    {
      const ApplicationServiceIdentity& existing = byName->second;
      if (existing.serviceSlot != identity.serviceSlot || existing.kind != identity.kind)
      {
        if (failure)
        {
          failure->assign("serviceName already reserved with different shape"_ctv);
        }
        return false;
      }
    }

    uint32_t slotKey = makeReservedServiceSlotKey(identity.applicationID, identity.serviceSlot);
    if (auto bySlot = reservedApplicationServiceNamesBySlotKey.find(slotKey); bySlot != reservedApplicationServiceNamesBySlotKey.end() && bySlot->second.equals(identity.serviceName) == false)
    {
      if (failure)
      {
        failure->assign("serviceSlot already reserved by a different serviceName"_ctv);
      }
      return false;
    }

    uint64_t service = materializeReservedService(identity);
    if (auto byService = reservedApplicationServicesByID.find(service); byService != reservedApplicationServicesByID.end())
    {
      const ApplicationServiceIdentity& existing = byService->second;
      if (existing.applicationID != identity.applicationID || existing.serviceSlot != identity.serviceSlot || existing.serviceName.equals(identity.serviceName) == false || existing.kind != identity.kind)
      {
        if (failure)
        {
          failure->assign("service already reserved by a different mapping"_ctv);
        }
        return false;
      }
    }

    ApplicationServiceIdentity ownedIdentity = identity;
    String ownedServiceName = {};
    ownedServiceName.assign(identity.serviceName.data(), identity.serviceName.size());
    ownedIdentity.serviceName = std::move(ownedServiceName);
    String ownedNameKey = makeReservedServiceNameKey(ownedIdentity.applicationID, ownedIdentity.serviceName);

    reservedApplicationServicesByNameKey.insert_or_assign(ownedNameKey, ownedIdentity);
    reservedApplicationServicesByID.insert_or_assign(service, ownedIdentity);
    reservedApplicationServiceNamesBySlotKey.insert_or_assign(slotKey, ownedIdentity.serviceName);

    uint8_t nextSlot = uint8_t(identity.serviceSlot + 1);
    if (identity.serviceSlot < UINT8_MAX)
    {
      auto it = nextReservableServiceSlotByApplication.find(identity.applicationID);
      if (it == nextReservableServiceSlotByApplication.end() || it->second <= identity.serviceSlot)
      {
        nextReservableServiceSlotByApplication.insert_or_assign(identity.applicationID, nextSlot);
      }
    }

    return true;
  }

  bool resolveReservedApplicationService(uint16_t applicationID, const String& serviceName, ApplicationServiceIdentity& identity) const
  {
    String nameKey = makeReservedServiceNameKey(applicationID, serviceName);
    if (auto byName = reservedApplicationServicesByNameKey.find(nameKey); byName != reservedApplicationServicesByNameKey.end())
    {
      identity = byName->second;
      return true;
    }

    return false;
  }

  void capturePersistentReservedApplicationServices(Vector<ApplicationServiceIdentity>& services) const
  {
    services.clear();
    services.reserve(reservedApplicationServicesByID.size());
    for (const auto& [service, identity] : reservedApplicationServicesByID)
    {
      (void)service;
      services.push_back(identity);
    }

    std::sort(services.begin(), services.end(), [](const ApplicationServiceIdentity& lhs, const ApplicationServiceIdentity& rhs) -> bool {
      if (lhs.applicationID != rhs.applicationID)
      {
        return lhs.applicationID < rhs.applicationID;
      }

      if (lhs.serviceSlot != rhs.serviceSlot)
      {
        return lhs.serviceSlot < rhs.serviceSlot;
      }

      if (lhs.kind != rhs.kind)
      {
        return uint8_t(lhs.kind) < uint8_t(rhs.kind);
      }

      return std::lexicographical_compare(
          lhs.serviceName.data(),
          lhs.serviceName.data() + lhs.serviceName.size(),
          rhs.serviceName.data(),
          rhs.serviceName.data() + rhs.serviceName.size());
    });
  }

  void restorePersistentReservedApplicationServices(const Vector<ApplicationServiceIdentity>& services)
  {
    initializeApplicationServiceReservationState();
    for (const ApplicationServiceIdentity& identity : services)
    {
      String failure;
      if (reserveApplicationServiceMapping(identity, &failure) == false)
      {
        String serviceName = {};
        serviceName.assign(identity.serviceName);
        basics_log("restorePersistentReservedApplicationServices reject appID=%u service=%s reason=%s\n",
                   unsigned(identity.applicationID),
                   serviceName.c_str(),
                   failure.c_str());
      }
    }

    armMachineUpdateTimerIfNeeded();
  }

  void initializeApplicationIDReservationState(void)
  {
    reservedApplicationIDsByName.clear();
    reservedApplicationNamesByID.clear();
    nextReservableApplicationID = 1;
    for (const auto& [applicationName, applicationID] : MeshRegistry::applicationIDMappings)
    {
      if (applicationID == 0)
      {
        continue;
      }

      String failure;
      if (reserveApplicationIDMapping(applicationName, applicationID, &failure) == false)
      {
        basics_log("initializeApplicationIDReservationState conflict appID=%u reason=%s\n",
                   unsigned(applicationID),
                   failure.c_str());
      }
    }
  }

  void initializeApplicationServiceReservationState(void)
  {
    reservedApplicationServicesByNameKey.clear();
    reservedApplicationServicesByID.clear();
    reservedApplicationServiceNamesBySlotKey.clear();
    nextReservableServiceSlotByApplication.clear();

    for (const auto& [serviceName, service] : MeshRegistry::serviceMappings)
    {
      int64_t colon = serviceName.rfindChar(':');
      if (colon <= 0 || colon >= int64_t(serviceName.size() - 1))
      {
        continue;
      }

      if (serviceName.data()[colon - 1] != ':')
      {
        continue;
      }

      ApplicationServiceIdentity identity;
      identity.applicationID = uint16_t(service >> 48);
      identity.serviceName.assign(serviceName.substr(uint64_t(colon + 1), serviceName.size() - uint64_t(colon + 1), Copy::no));
      identity.serviceSlot = uint8_t((service >> 40) & 0xFFu);
      identity.kind = MeshServices::isPrefix(service) ? ApplicationServiceIdentity::Kind::stateful : ApplicationServiceIdentity::Kind::stateless;

      String failure;
      if (reserveApplicationServiceMapping(identity, &failure) == false)
      {
        basics_log("initializeApplicationServiceReservationState conflict appID=%u service=%s reason=%s\n",
                   unsigned(identity.applicationID),
                   identity.serviceName.c_str(),
                   failure.c_str());
      }
    }
  }

  uint16_t takeNextReservableApplicationID(void)
  {
    for (uint32_t candidate = nextReservableApplicationID; candidate <= UINT16_MAX; candidate += 1)
    {
      if (candidate == 0)
      {
        continue;
      }

      uint16_t applicationID = uint16_t(candidate);
      if (reservedApplicationNamesByID.find(applicationID) == reservedApplicationNamesByID.end())
      {
        if (candidate < UINT16_MAX)
        {
          nextReservableApplicationID = uint16_t(candidate + 1);
        }
        else
        {
          nextReservableApplicationID = UINT16_MAX;
        }

        return applicationID;
      }
    }

    return 0;
  }

  uint8_t takeNextReservableServiceSlot(uint16_t applicationID)
  {
    uint32_t candidate = 1;
    if (auto it = nextReservableServiceSlotByApplication.find(applicationID); it != nextReservableServiceSlotByApplication.end() && it->second > 0)
    {
      candidate = it->second;
    }

    for (; candidate <= UINT8_MAX; candidate += 1)
    {
      uint8_t serviceSlot = uint8_t(candidate);
      uint32_t slotKey = makeReservedServiceSlotKey(applicationID, serviceSlot);
      if (reservedApplicationServiceNamesBySlotKey.find(slotKey) == reservedApplicationServiceNamesBySlotKey.end())
      {
        if (candidate < UINT8_MAX)
        {
          nextReservableServiceSlotByApplication.insert_or_assign(applicationID, uint8_t(candidate + 1));
        }
        else
        {
          nextReservableServiceSlotByApplication.insert_or_assign(applicationID, UINT8_MAX);
        }

        return serviceSlot;
      }
    }

    return 0;
  }

  uint128_t updateSelfPeerTrackingKey(const BrainView *brain) const
  {
    if (brain == nullptr)
    {
      return 0;
    }

    if (brain->private4 != 0)
    {
      return uint128_t(brain->private4);
    }

    IPAddress peerAddress = brain->peerAddress;
    if (peerAddress.isNull())
    {
      for (const ClusterMachinePeerAddress& candidate : brain->peerAddresses)
      {
        if (ClusterMachine::parseIPAddressLiteral(candidate.address, peerAddress))
        {
          break;
        }
      }
    }

    if (peerAddress.isNull() == false)
    {
      if (peerAddress.is6 == false)
      {
        peerAddress = peerAddress.create4in6();
      }

      uint128_t key = 0;
      memcpy(&key, peerAddress.v6, sizeof(key));
      return key;
    }

    return brain->uuid;
  }

  uint128_t updateSelfLocalPeerTrackingKey(void) const
  {
    if (thisNeuron != nullptr && thisNeuron->private4.isNull() == false && thisNeuron->private4.v4 != 0)
    {
      return uint128_t(thisNeuron->private4.v4);
    }

    IPAddress selfAddress = localBrainPeerAddress;
    if (selfAddress.isNull())
    {
      for (const ClusterMachinePeerAddress& candidate : localBrainPeerAddresses)
      {
        if (ClusterMachine::parseIPAddressLiteral(candidate.address, selfAddress))
        {
          break;
        }
      }
    }

    if (selfAddress.isNull())
    {
      return selfBrainUUID();
    }

    if (selfAddress.is6 == false)
    {
      selfAddress = selfAddress.create4in6();
    }

    uint128_t key = 0;
    memcpy(&key, selfAddress.v6, sizeof(key));
    return key;
  }

  ProdigyPersistentUpdateSelfState capturePersistentUpdateSelfState(void) const
  {
    ProdigyPersistentUpdateSelfState state = {};
    state.state = uint8_t(updateSelfState);
    state.expectedEchos = updateSelfExpectedEchos;
    state.bundleEchos = updateSelfBundleEchos;
    state.relinquishEchos = updateSelfRelinquishEchos;
    state.plannedMasterPeerKey = updateSelfPlannedMasterPeerKey;
    state.pendingDesignatedMasterPeerKey = pendingDesignatedMasterPeerKey;
    state.useStagedBundleOnly = updateSelfUseStagedBundleOnly;
    state.bundleBlob = updateSelfBundleBlob;

    for (uint128_t peerKey : updateSelfBundleEchoPeerKeys)
    {
      state.bundleEchoPeerKeys.push_back(peerKey);
    }
    for (uint128_t peerKey : updateSelfRelinquishEchoPeerKeys)
    {
      state.relinquishEchoPeerKeys.push_back(peerKey);
    }
    for (const auto& [peerKey, bootNs] : updateSelfFollowerBootNsByPeerKey)
    {
      ProdigyPersistentUpdateSelfFollowerBoot follower = {};
      follower.peerKey = peerKey;
      follower.bootNs = bootNs;
      state.followerBootNsByPeerKey.push_back(follower);
    }
    for (uint128_t peerKey : updateSelfFollowerRebootedPeerKeys)
    {
      state.followerRebootedPeerKeys.push_back(peerKey);
    }

    std::sort(state.bundleEchoPeerKeys.begin(), state.bundleEchoPeerKeys.end());
    std::sort(state.relinquishEchoPeerKeys.begin(), state.relinquishEchoPeerKeys.end());
    std::sort(state.followerBootNsByPeerKey.begin(), state.followerBootNsByPeerKey.end(),
              [](const ProdigyPersistentUpdateSelfFollowerBoot& lhs, const ProdigyPersistentUpdateSelfFollowerBoot& rhs) {
                return lhs.peerKey < rhs.peerKey;
              });
    std::sort(state.followerRebootedPeerKeys.begin(), state.followerRebootedPeerKeys.end());
    return state;
  }

  void restorePersistentUpdateSelfState(const ProdigyPersistentUpdateSelfState& state)
  {
    updateSelfState = UpdateSelfState::idle;
    if (state.state <= uint8_t(UpdateSelfState::waitingForRelinquishEchos))
    {
      updateSelfState = UpdateSelfState(state.state);
    }

    updateSelfExpectedEchos = state.expectedEchos;
    updateSelfBundleEchos = state.bundleEchos;
    updateSelfRelinquishEchos = state.relinquishEchos;
    updateSelfPlannedMasterPeerKey = state.plannedMasterPeerKey;
    pendingDesignatedMasterPeerKey = state.pendingDesignatedMasterPeerKey;
    if (pendingDesignatedMasterPeerKey > 0)
    {
      String pendingPeerKeyText = {};
      pendingPeerKeyText.snprintf<"{itoa}"_ctv>(pendingDesignatedMasterPeerKey);
      basics_log("restorePersistentUpdateSelfState pendingDesignatedMasterPeerKey=%s\n",
                 pendingPeerKeyText.c_str());
    }
    updateSelfUseStagedBundleOnly = state.useStagedBundleOnly;
    updateSelfBundleBlob = state.bundleBlob;

    updateSelfBundleEchoPeerKeys.clear();
    updateSelfRelinquishEchoPeerKeys.clear();
    updateSelfFollowerBootNsByPeerKey.clear();
    updateSelfFollowerRebootedPeerKeys.clear();

    for (uint128_t peerKey : state.bundleEchoPeerKeys)
    {
      updateSelfBundleEchoPeerKeys.insert(peerKey);
    }
    for (uint128_t peerKey : state.relinquishEchoPeerKeys)
    {
      updateSelfRelinquishEchoPeerKeys.insert(peerKey);
    }
    for (const ProdigyPersistentUpdateSelfFollowerBoot& follower : state.followerBootNsByPeerKey)
    {
      updateSelfFollowerBootNsByPeerKey.insert_or_assign(follower.peerKey, follower.bootNs);
    }
    for (uint128_t peerKey : state.followerRebootedPeerKeys)
    {
      updateSelfFollowerRebootedPeerKeys.insert(peerKey);
    }
  }

  ProdigyResumptionRegistry::SnapshotMap captureTlsResumptionSnapshotsByWormhole(void) const
  {
    ProdigyResumptionRegistry::SnapshotMap snapshots;
    for (const auto& [deploymentID, deploymentState] : tlsResumptionStateByDeployment)
    {
      for (const auto& [wormholeName, state] : deploymentState.wormholes)
      {
        snapshots.insert_or_assign(tlsResumptionRegistryKey(deploymentID, wormholeName), state.snapshot);
      }
    }
    return snapshots;
  }

  void restoreTlsResumptionSnapshotsByWormhole(const ProdigyResumptionRegistry::SnapshotMap& snapshots, bool preserveMatchingGenerationAcks)
  {
    bytell_hash_map<uint64_t, BrainTlsResumptionDeploymentState> restored;
    for (const auto& [registryKey, snapshot] : snapshots)
    {
      uint64_t deploymentID = 0;
      String wormholeName = {};
      if (tlsResumptionParseRegistryKey(registryKey, deploymentID, wormholeName) == false)
      {
        continue;
      }

      BrainTlsResumptionWormholeState state = {};
      state.snapshot = snapshot;

      const BrainTlsResumptionWormholeState *existing = preserveMatchingGenerationAcks ? tlsResumptionStateForWormhole(deploymentID, wormholeName) : nullptr;
      if (existing != nullptr && existing->snapshot.generation == snapshot.generation)
      {
        state.acksByContainer = existing->acksByContainer;
      }

      restored[deploymentID].wormholes.insert_or_assign(wormholeName, std::move(state));
    }
    tlsResumptionStateByDeployment = std::move(restored);
  }

  void refreshMasterAuthorityRuntimeStateFromLiveFields(void)
  {
    if (nextMintedClientTlsGeneration == 0)
    {
      nextMintedClientTlsGeneration = 1;
    }
    if (nextTlsResumptionGeneration == 0)
    {
      nextTlsResumptionGeneration = 1;
    }

    if (masterAuthorityRuntimeState.nextPendingAddMachinesOperationID == 0)
    {
      masterAuthorityRuntimeState.nextPendingAddMachinesOperationID = 1;
    }
    if (masterAuthorityRuntimeState.nextPendingElasticAddressOperationID == 0)
    {
      masterAuthorityRuntimeState.nextPendingElasticAddressOperationID = 1;
    }
    if (masterAuthorityRuntimeState.nextDNSIntentRevision == 0)
    {
      masterAuthorityRuntimeState.nextDNSIntentRevision = 1;
    }

    masterAuthorityRuntimeState.statefulWorkerTopologyUpgradeOperations = statefulWorkerTopologyUpgradeRuntimeState;
    masterAuthorityRuntimeState.deferredStatefulScaleIntents = deferredStatefulScaleIntentRuntimeState;
    masterAuthorityRuntimeState.routableResourceLeases = routableResourceLeaseRuntimeState;
    masterAuthorityRuntimeState.hasCompletedInitialMasterElection = hasCompletedInitialMasterElection;
    masterAuthorityRuntimeState.nextMintedClientTlsGeneration = nextMintedClientTlsGeneration;
    masterAuthorityRuntimeState.nextTlsResumptionGeneration = nextTlsResumptionGeneration;
    masterAuthorityRuntimeState.tlsResumptionSnapshotsByWormhole = captureTlsResumptionSnapshotsByWormhole();
    masterAuthorityRuntimeState.mothershipTunnelProviderDesiredState = {mothershipConnectivity, mothershipTunnelGatewayAuth};
    masterAuthorityRuntimeState.updateSelf = capturePersistentUpdateSelfState();
  }

  void noteStatefulWorkerTopologyUpgradeRuntimeStateChanged(void) override
  {
    noteMasterAuthorityRuntimeStateChanged();
  }

  void noteDeferredStatefulScaleIntentRuntimeStateChanged(void) override
  {
    noteMasterAuthorityRuntimeStateChanged();
  }

  void noteRoutableResourceLeaseRuntimeStateChanged(void) override
  {
    noteMasterAuthorityRuntimeStateChanged();
  }

  virtual ProdigyDNSProvider *resolveDNSProvider(const String& provider)
  {
    if (dnsProvider == nullptr || brainConfig.dnsProvider.size() == 0 || routableResourceDNSPartEquals(provider, brainConfig.dnsProvider, false) == false)
    {
      return nullptr;
    }
    return dnsProvider->supportsProvider(provider) ? dnsProvider : nullptr;
  }

  static void ownDNSRecordLease(RoutableResourceLease& target, const RoutableResourceLease& source)
  {
    target = source;
    target.owner.name.assign(source.owner.name);
    target.dnsProvider.assign(source.dnsProvider);
    target.dnsCredentialName.assign(source.dnsCredentialName);
    target.dnsZone.assign(source.dnsZone);
    target.dnsName.assign(source.dnsName);
    target.dnsType.assign(source.dnsType);
  }

  static void ownDNSRecordBinding(ProdigyDNSRecordBinding& target,
                                  const ProdigyDNSRecordBinding& source)
  {
    target.provider.assign(source.provider);
    target.credentialName.assign(source.credentialName);
    target.zone.assign(source.zone);
    target.name.assign(source.name);
    target.type.assign(source.type);
    target.ttl = source.ttl;
    target.values.clear();
    for (const String& value : source.values)
    {
      target.values.emplace_back().assign(value);
    }
  }

  bool dnsRecordLeaseOperationPending(const RoutableResourceLease& lease,
                                      ProdigyBrainDNSOperationCoordinator::Action action) const
  {
    for (const auto& [owner, pending] : pendingDNSOperations)
    {
      (void)owner;
      if (pending.kind == PendingDNSOperationKind::lease && pending.action == action && pending.lease == lease)
      {
        return true;
      }
    }
    return false;
  }

  bool dnsRecordLeaseApplied(const RoutableResourceLease& lease) const
  {
    for (const RoutableResourceLease& applied : appliedDNSRecordLeases)
    {
      if (applied == lease)
      {
        return true;
      }
    }
    return false;
  }

  uint64_t mintDNSOperationOwner(void)
  {
    uint64_t owner = nextDNSOperationOwner++;
    if (owner == 0)
    {
      owner = nextDNSOperationOwner++;
    }
    return owner;
  }

  uint64_t mintDNSIntentRevision(void)
  {
    uint64_t revision = masterAuthorityRuntimeState.nextDNSIntentRevision++;
    if (revision == 0)
    {
      revision = masterAuthorityRuntimeState.nextDNSIntentRevision++;
    }
    if (masterAuthorityRuntimeState.nextDNSIntentRevision == 0)
    {
      masterAuthorityRuntimeState.nextDNSIntentRevision = 1;
    }
    return revision;
  }

  uint64_t beginDNSControl(Mothership *stream,
                           MothershipTopic topic,
                           uint32_t outstanding,
                           RoutableResourceLeaseReport *inlineResponse)
  {
    const uint64_t identifier = mintDNSOperationOwner();
    PendingDNSControl control;
    control.stream = stream;
    control.streamIncarnation = stream == nullptr ? 0 : stream->connectionIncarnation;
    control.topic = topic;
    control.inlineResponse = inlineResponse;
    control.outstanding = outstanding;
    pendingDNSControls.insert_or_assign(identifier, std::move(control));
    return identifier;
  }

  void finishDNSControl(uint64_t controlID,
                        const RoutableResourceLease& lease,
                        bool success,
                        const String& failure)
  {
    auto controlIt = pendingDNSControls.find(controlID);
    if (controlIt == pendingDNSControls.end())
    {
      return;
    }
    PendingDNSControl& control = controlIt->second;
    if (success)
    {
      if (control.topic == MothershipTopic::upsertDNSBinding)
      {
        control.response.leases.push_back(dnsBindingAddressLease(lease));
      }
      control.response.leases.push_back(lease);
    }
    else if (control.response.failure.empty())
    {
      control.response.failure.assign(failure);
    }
    if (control.outstanding > 0)
    {
      control.outstanding -= 1;
    }
    if (control.outstanding != 0)
    {
      return;
    }

    control.response.success = control.response.failure.empty();
    if (control.inlineResponse != nullptr)
    {
      *control.inlineResponse = control.response;
    }
    if (control.stream != nullptr && activeMotherships.contains(control.stream) &&
        control.stream->connectionIncarnation == control.streamIncarnation)
    {
      String serializedResponse;
      BitseryEngine::serialize(serializedResponse, control.response);
      Message::construct(control.stream->wBuffer, control.topic, serializedResponse);
      (void)flushActiveMothershipSendBuffer(control.stream, "dns-control-complete");
    }
    pendingDNSControls.erase(controlIt);
  }

  uint64_t mintContainerLogRequestID(void)
  {
    uint64_t identifier = nextContainerLogRequestID++;
    if (identifier == 0)
    {
      identifier = nextContainerLogRequestID++;
    }
    return identifier;
  }

  static uint64_t containerLogBytes(const ContainerLogsOperation& operation)
  {
    uint64_t bytes = 0;
    for (const ContainerLogEntry& entry : operation.entries)
    {
      bytes += entry.standardOutput.size() + entry.standardError.size();
    }
    return bytes;
  }

  static void appendContainerLogFailure(PendingContainerLogs& pending, uint128_t machineUUID, const String& failure)
  {
    if (pending.operation.failure.size() > 0)
    {
      pending.operation.failure.append("; "_ctv);
    }
    String machine = {};
    machine.assignItoh(machineUUID);
    pending.operation.failure.snprintf_add<"machine {}: {}"_ctv>(machine, failure);
  }

  void finishContainerLogRequest(uint64_t requestID)
  {
    auto pendingIt = pendingContainerLogs.find(requestID);
    if (pendingIt == pendingContainerLogs.end())
    {
      return;
    }
    PendingContainerLogs& pending = pendingIt->second;
    pending.operation.success = pending.operation.failure.size() == 0;
    if (pending.stream != nullptr && activeMotherships.contains(pending.stream) &&
        pending.stream->connectionIncarnation == pending.streamIncarnation)
    {
      String serialized = {};
      BitseryEngine::serialize(serialized, pending.operation);
      Message::construct(pending.stream->wBuffer, MothershipTopic::pullContainerLogs, serialized);
      (void)flushActiveMothershipSendBuffer(pending.stream, "container-logs-complete");
    }
    pendingContainerLogs.erase(pendingIt);
  }

  void beginContainerLogRequest(Mothership *stream, ContainerLogsOperation operation)
  {
    bool requestShapeValid = operation.requestID == 0 && operation.success == false &&
                             operation.failure.size() == 0 && operation.entries.empty();
    operation.success = false;
    operation.truncated = false;
    operation.failure.clear();
    operation.entries.clear();
    if (stream == nullptr)
    {
      return;
    }
    if (requestShapeValid == false || operation.applicationID == 0 || operation.maximumBytes < 1024 ||
        operation.maximumBytes > containerLogsMaximumBytes ||
        (operation.includeRunning == false && operation.includeFailed == false))
    {
      operation.failure.assign("container log request is invalid"_ctv);
      String serialized = {};
      BitseryEngine::serialize(serialized, operation);
      Message::construct(stream->wBuffer, MothershipTopic::pullContainerLogs, serialized);
      return;
    }

    Vector<Machine *> targets = {};
    for (Machine *machine : machines)
    {
      if (machine != nullptr && streamIsActive(&machine->neuron))
      {
        targets.push_back(machine);
      }
    }
    if (targets.empty())
    {
      operation.failure.assign("no connected neurons are available"_ctv);
      String serialized = {};
      BitseryEngine::serialize(serialized, operation);
      Message::construct(stream->wBuffer, MothershipTopic::pullContainerLogs, serialized);
      return;
    }

    operation.requestID = mintContainerLogRequestID();
    PendingContainerLogs pending = {};
    pending.stream = stream;
    pending.streamIncarnation = stream->connectionIncarnation;
    pending.deadlineMs = Time::now<TimeResolution::ms>() + 15'000;
    pending.maximumBytesPerNeuron = operation.maximumBytes / uint32_t(targets.size());
    pending.operation = operation;
    for (Machine *machine : targets)
    {
      pending.outstandingMachines.insert(machine->uuid);
    }
    pendingContainerLogs.insert_or_assign(operation.requestID, std::move(pending));

    operation.maximumBytes /= uint32_t(targets.size());
    String serialized = {};
    BitseryEngine::serialize(serialized, operation);
    for (Machine *machine : targets)
    {
      machine->queueSend(NeuronTopic::pullContainerLogs, serialized);
    }
  }

  void noteContainerLogResponse(NeuronView *neuron, ContainerLogsOperation& response)
  {
    auto pendingIt = pendingContainerLogs.find(response.requestID);
    if (pendingIt == pendingContainerLogs.end() || neuron == nullptr || neuron->machine == nullptr)
    {
      return;
    }
    PendingContainerLogs& pending = pendingIt->second;
    uint128_t machineUUID = neuron->machine->uuid;
    if (pending.outstandingMachines.contains(machineUUID) == false)
    {
      return;
    }
    pending.outstandingMachines.erase(machineUUID);

    bool entriesValid = true;
    for (const ContainerLogEntry& entry : response.entries)
    {
      entriesValid &= (response.containerUUID == 0 || entry.containerUUID == response.containerUUID) &&
                      ((entry.running && pending.operation.includeRunning) ||
                       (entry.running == false && pending.operation.includeFailed));
    }
    if (response.applicationID != pending.operation.applicationID ||
        response.containerUUID != pending.operation.containerUUID ||
        response.maximumBytes != pending.maximumBytesPerNeuron ||
        response.includeRunning != pending.operation.includeRunning ||
        response.includeFailed != pending.operation.includeFailed ||
        entriesValid == false ||
        containerLogBytes(response) > pending.maximumBytesPerNeuron)
    {
      appendContainerLogFailure(pending, machineUUID, "invalid container log response"_ctv);
    }
    else
    {
      pending.operation.truncated |= response.truncated;
      if (response.success == false)
      {
        String failure = response.failure.size() ? response.failure : String("container log read failed"_ctv);
        appendContainerLogFailure(pending, machineUUID, failure);
      }
      for (ContainerLogEntry& entry : response.entries)
      {
        if (pending.operation.entries.size() >= containerLogsMaximumEntries)
        {
          pending.operation.truncated = true;
          break;
        }
        entry.machineUUID = machineUUID;
        pending.operation.entries.push_back(std::move(entry));
      }
    }
    if (pending.outstandingMachines.empty())
    {
      finishContainerLogRequest(response.requestID);
    }
  }

  void expireContainerLogRequests(void)
  {
    const int64_t nowMs = Time::now<TimeResolution::ms>();
    Vector<uint64_t> expired = {};
    for (auto& [requestID, pending] : pendingContainerLogs)
    {
      if (pending.deadlineMs <= nowMs)
      {
        for (uint128_t machineUUID : pending.outstandingMachines)
        {
          appendContainerLogFailure(pending, machineUUID, "container log request timed out"_ctv);
        }
        pending.outstandingMachines.clear();
        expired.push_back(requestID);
      }
    }
    for (uint64_t requestID : expired)
    {
      finishContainerLogRequest(requestID);
    }
  }

  void clearContainerLogRequestsForStream(Mothership *stream)
  {
    for (auto it = pendingContainerLogs.begin(); it != pendingContainerLogs.end();)
    {
      if (it->second.stream == stream)
      {
        it = pendingContainerLogs.erase(it);
      }
      else
      {
        ++it;
      }
    }
  }

  bool enqueueDNSRecordLease(const RoutableResourceLease& lease,
                             String& failure,
                             uint64_t controlID = 0)
  {
    failure.clear();
    if (lease.kind != RoutableResourceLeaseKind::dnsRecord)
    {
      return true;
    }

    ProdigyDNSRecordBinding binding = {};
    if (prodigyBuildDNSRecordBinding(lease, binding, &failure) == false)
    {
      return false;
    }

    const ApiCredential *credential = findDNSCredential(lease.owner.applicationID, lease.dnsCredentialName);
    if (credential == nullptr)
    {
      failure.assign("DNS credential is not registered"_ctv);
      return false;
    }
    if (routableResourceDNSPartEquals(credential->provider, lease.dnsProvider, false) == false)
    {
      failure.assign("DNS credential provider mismatch"_ctv);
      return false;
    }

    ProdigyDNSProvider *provider = resolveDNSProvider(lease.dnsProvider);
    if (provider == nullptr)
    {
      failure.assign("DNS provider is not configured"_ctv);
      return false;
    }

    const ProdigyBrainDNSOperationCoordinator::Action action = lease.dnsDeletePending ?
                                                                   ProdigyBrainDNSOperationCoordinator::Action::remove :
                                                                   ProdigyBrainDNSOperationCoordinator::Action::upsert;
    if (dnsRecordLeaseOperationPending(lease, action))
    {
      if (controlID == 0)
      {
        return true;
      }
      failure.assign("DNS operation is already pending; retry the control request"_ctv);
      return false;
    }
    if (dnsOperations.canEnqueue() == false)
    {
      failure.assign("DNS operation queue is full; authoritative intent remains pending"_ctv);
      return false;
    }

    const uint64_t owner = mintDNSOperationOwner();
    PendingDNSOperation pending;
    pending.kind = PendingDNSOperationKind::lease;
    pending.action = action;
    pending.controlID = controlID;
    ownDNSRecordLease(pending.lease, lease);
    pendingDNSOperations.insert_or_assign(owner, std::move(pending));
    if (dnsOperations.enqueue(*provider,
                              action,
                              binding,
                              lease.owner.applicationID,
                              credential->generation,
                              owner))
    {
      return true;
    }
    pendingDNSOperations.erase(owner);
    failure.assign("DNS operation queue rejected authoritative intent"_ctv);
    return false;
  }

  static bool credentialBundleHasTlsIdentityGeneration(const CredentialBundle& bundle, const String& name, uint64_t generation)
  {
    for (const TlsIdentity& identity : bundle.tlsIdentities)
    {
      if (identity.name.equals(name) && identity.generation == generation)
      {
        return true;
      }
    }
    return false;
  }

  static void noteContainerCredentialBundleApplied(ContainerView *container, const CredentialBundle *bundle)
  {
    if (container == nullptr)
    {
      return;
    }
    container->hasPendingCredentialBundle = false;
    container->pendingCredentialBundleSinceMs = 0;
    container->pendingCredentialBundle = {};
    container->hasCredentialBundle = bundle != nullptr;
    container->credentialBundle = bundle == nullptr ? CredentialBundle {} : *bundle;
    container->credentialRefreshFailure.clear();
  }

  static void noteContainerCredentialDeltaPending(ContainerView *container, const CredentialDelta& delta)
  {
    if (container == nullptr)
    {
      return;
    }
    CredentialBundle next = container->hasPendingCredentialBundle ? container->pendingCredentialBundle : container->credentialBundle;
    applyCredentialDelta(next, delta);
    container->pendingCredentialBundle = std::move(next);
    container->hasPendingCredentialBundle = true;
    container->pendingCredentialBundleSinceMs = Time::now<TimeResolution::ms>();
    container->credentialRefreshFailure.clear();
  }

  bool noteContainerCredentialRefreshAck(uint128_t containerUUID)
  {
    auto containerIt = containers.find(containerUUID);
    if (containerIt == containers.end() || containerIt->second == nullptr || containerIt->second->hasPendingCredentialBundle == false)
    {
      return false;
    }
    ContainerView *container = containerIt->second;
    container->credentialBundle = std::move(container->pendingCredentialBundle);
    container->pendingCredentialBundle = {};
    container->hasCredentialBundle = true;
    container->hasPendingCredentialBundle = false;
    container->pendingCredentialBundleSinceMs = 0;
    container->credentialRefreshFailure.clear();
    return true;
  }

  static bool credentialBundleHasTlsIdentityApplyResult(const CredentialBundle& bundle, const TlsIdentityApplyResult& result)
  {
    for (const TlsIdentity& identity : bundle.tlsIdentities)
    {
      if (identity.name.equals(result.identityName) && identity.generation == result.generation)
      {
        return true;
      }
    }
    return false;
  }

  bool noteContainerCredentialApplyAck(uint128_t containerUUID, const CredentialApplyAck& ack)
  {
    auto containerIt = containers.find(containerUUID);
    if (containerIt == containers.end() || containerIt->second == nullptr)
    {
      return false;
    }
    ContainerView *container = containerIt->second;
    if (container->hasPendingCredentialBundle == false || ack.tlsResults.empty())
    {
      return noteContainerCredentialRefreshAck(containerUUID);
    }

    bool accepted = true;
    String failure = {};
    for (const TlsIdentityApplyResult& result : ack.tlsResults)
    {
      if (result.success == false || credentialBundleHasTlsIdentityApplyResult(container->pendingCredentialBundle, result) == false)
      {
        accepted = false;
        failure = result.failureReason.size() ? result.failureReason : "TLS identity refresh was rejected"_ctv;
        break;
      }
    }
    for (const TlsIdentity& identity : container->pendingCredentialBundle.tlsIdentities)
    {
      bool found = false;
      for (const TlsIdentityApplyResult& result : ack.tlsResults)
      {
        if (identity.name.equals(result.identityName) && identity.generation == result.generation && result.success)
        {
          found = true;
          break;
        }
      }
      if (found == false)
      {
        accepted = false;
        if (failure.size() == 0)
        {
          failure.assign("TLS identity refresh ACK did not cover every pending identity"_ctv);
        }
        break;
      }
    }
    if (accepted)
    {
      return noteContainerCredentialRefreshAck(containerUUID);
    }

    container->pendingCredentialBundle = {};
    container->hasPendingCredentialBundle = false;
    container->pendingCredentialBundleSinceMs = 0;
    container->credentialRefreshFailure = std::move(failure);
    return false;
  }

  const PublicTlsCertificateState *findPublicTlsCertificateState(uint16_t applicationID, uint64_t deploymentID, const String& wormholeName, const String& certName) const
  {
    for (const PublicTlsCertificateState& certificate : masterAuthorityRuntimeState.publicTlsCertificates)
    {
      const String& storedCertName = certificate.certbotCertName.size() ? certificate.certbotCertName : certificate.spec.identityName;
      if (certificate.spec.applicationID == applicationID &&
          certificate.spec.deploymentID == deploymentID &&
          certificate.spec.wormholeName.equals(wormholeName) &&
          storedCertName.equals(certName))
      {
        return &certificate;
      }
    }
    return nullptr;
  }

  PublicTlsCertificateState *findPublicTlsCertificateState(uint16_t applicationID, uint64_t deploymentID, const String& wormholeName, const String& certName)
  {
    return const_cast<PublicTlsCertificateState *>(static_cast<const Brain *>(this)->findPublicTlsCertificateState(applicationID, deploymentID, wormholeName, certName));
  }

  static bool publicTlsCertificateCoversIdentifier(const PublicTlsCertificateState& certificate, const String& identifier)
  {
    for (const String& domain : certificate.spec.domains)
    {
      if (routableResourceDNSPartEquals(domain, identifier, true))
      {
        return true;
      }
    }
    return false;
  }

  static uint32_t publicTlsDomainMatchCount(const Vector<String>& domains, const String& target)
  {
    uint32_t count = 0;
    for (const String& domain : domains)
    {
      count += routableResourceDNSPartEquals(domain, target, true) ? 1 : 0;
    }
    return count;
  }

  static bool publicTlsDomainSetsEqual(const Vector<String>& lhs, const Vector<String>& rhs)
  {
    if (lhs.size() != rhs.size())
    {
      return false;
    }
    for (const String& domain : lhs)
    {
      if (publicTlsDomainMatchCount(lhs, domain) != publicTlsDomainMatchCount(rhs, domain))
      {
        return false;
      }
    }
    return true;
  }

  static uint64_t certificateLifecycleMix(uint64_t seed, const String& value)
  {
    uint64_t hash = seed ? seed : 1'469'598'103'934'665'603ULL;
    for (uint64_t index = 0; index < value.size(); index += 1)
    {
      hash ^= uint8_t(value[index]);
      hash *= 1'099'511'628'211ULL;
    }
    return hash;
  }

  static int64_t certificateLifecycleJitterMs(uint64_t seed)
  {
    return certificateLifecycleMaxJitterMs <= 0 ? 0 : int64_t(seed % uint64_t(certificateLifecycleMaxJitterMs + 1));
  }

  static int64_t certificateLifecycleJitteredRenewAtMs(int64_t renewAtMs, uint64_t seed)
  {
    return renewAtMs <= 0 ? 0 : renewAtMs + certificateLifecycleJitterMs(seed);
  }

  static int64_t certificateLifecycleBackoffMs(uint32_t failureCount, uint64_t seed)
  {
    uint32_t shifts = failureCount > 1 ? std::min<uint32_t>(failureCount - 1, 5) : 0;
    int64_t delay = certificateLifecycleBaseRetryDelayMs << shifts;
    return std::min<int64_t>(delay, certificateLifecycleMaxRetryDelayMs) + certificateLifecycleJitterMs(seed);
  }

  static bool certificateLifecycleBackoffActive(int64_t nowMs, int64_t lastAttemptMs, int64_t lastSuccessMs, uint32_t failureCount, uint64_t seed)
  {
    return lastAttemptMs > lastSuccessMs && (nowMs <= lastAttemptMs || nowMs - lastAttemptMs < certificateLifecycleBackoffMs(failureCount, seed));
  }

  static uint64_t publicTlsCertificateJitterSeed(const PublicTlsCertificateState& certificate)
  {
    uint64_t seed = (uint64_t(certificate.spec.applicationID) << 48) ^ certificate.spec.deploymentID;
    seed = certificateLifecycleMix(seed, certificate.spec.wormholeName);
    seed = certificateLifecycleMix(seed, certificate.spec.identityName);
    for (const String& domain : certificate.spec.domains)
    {
      seed = certificateLifecycleMix(seed, domain);
    }
    return seed;
  }

  static uint64_t privateTlsVaultJitterSeed(const ApplicationTlsVaultFactory& factory)
  {
    return (uint64_t(factory.applicationID) << 32) ^ factory.factoryGeneration;
  }

  static uint64_t privateTlsVaultJitterSeed(const PrivateTlsVaultLifecycleState& lifecycle)
  {
    return (uint64_t(lifecycle.applicationID) << 32) ^ lifecycle.factoryGeneration;
  }

  template <typename T>
  static int64_t privateTlsVaultRenewAtMs(const T& seedSource, int64_t notBeforeMs, int64_t notAfterMs, uint64_t salt)
  {
    return certificateLifecycleJitteredRenewAtMs(prodigyCertificateRenewAtMs(notBeforeMs, notAfterMs, prodigyDefaultCertificateRenewAfterLifetimePermille), privateTlsVaultJitterSeed(seedSource) ^ salt);
  }

  static void noteCertificateFailure(uint32_t& failureCount, String& storedFailure, const String& failure)
  {
    storedFailure = failure;
    if (failureCount < UINT32_MAX)
    {
      failureCount += 1;
    }
  }

  static bool acmeDNSCredentialListAllows(const String& list, const String& recordName, bool zoneMatch)
  {
    for (size_t index = 0; index < list.size();)
    {
      while (index < list.size() && (list[index] == ',' || list[index] == ';' || std::isspace(static_cast<unsigned char>(list[index]))))
      {
        index += 1;
      }
      size_t begin = index;
      while (index < list.size() && list[index] != ',' && list[index] != ';' && std::isspace(static_cast<unsigned char>(list[index])) == false)
      {
        index += 1;
      }
      if (index == begin)
      {
        continue;
      }

      String token;
      token.assign(list.data() + begin, index - begin);
      if (zoneMatch == false && routableResourceDNSPartEquals(token, recordName, true))
      {
        return true;
      }
      if (zoneMatch)
      {
        size_t recordSize = recordName.size();
        size_t tokenSize = token.size();
        while (recordSize > 0 && recordName[recordSize - 1] == '.')
        {
          recordSize -= 1;
        }
        while (tokenSize > 0 && token[tokenSize - 1] == '.')
        {
          tokenSize -= 1;
        }
        if (tokenSize > 0 &&
            recordSize >= tokenSize &&
            (recordSize == tokenSize || recordName[recordSize - tokenSize - 1] == '.') &&
            routableResourceDNSPartEquals(recordName.substr(recordSize - tokenSize, tokenSize, Copy::no), token.substr(0, tokenSize, Copy::no), true))
        {
          return true;
        }
      }
    }
    return false;
  }

  static bool acmeDNSCredentialAllowsRecord(const ApiCredential& credential, const String& recordName, String& failure)
  {
    failure.clear();
    auto scopeIt = credential.metadata.find("dnsScope"_ctv);
    if (scopeIt == credential.metadata.end())
    {
      failure.assign("ACME DNS credential scope is not declared"_ctv);
      return false;
    }
    const String& scope = scopeIt->second;
    if (routableResourceDNSPartEquals(scope, "native-account"_ctv, false))
    {
      auto intentIt = credential.metadata.find("dnsAccountScopeAccepted"_ctv);
      if (intentIt != credential.metadata.end() && (intentIt->second.equal("1"_ctv) || routableResourceDNSPartEquals(intentIt->second, "true"_ctv, false)))
      {
        return true;
      }
      failure.assign("ACME DNS native-account scope requires dnsAccountScopeAccepted=true"_ctv);
      return false;
    }
    if (routableResourceDNSPartEquals(scope, "native-zone"_ctv, false))
    {
      auto zonesIt = credential.metadata.find("dnsZones"_ctv);
      if (zonesIt == credential.metadata.end())
      {
        zonesIt = credential.metadata.find("dnsZone"_ctv);
      }
      if (zonesIt != credential.metadata.end() && acmeDNSCredentialListAllows(zonesIt->second, recordName, true))
      {
        return true;
      }
      failure.assign("ACME DNS credential does not cover challenge zone"_ctv);
      return false;
    }
    if (routableResourceDNSPartEquals(scope, "native-exact"_ctv, false) || routableResourceDNSPartEquals(scope, "webhook-exact"_ctv, false))
    {
      auto recordsIt = credential.metadata.find("dnsRecords"_ctv);
      if (recordsIt == credential.metadata.end())
      {
        recordsIt = credential.metadata.find("dnsRecord"_ctv);
      }
      if (recordsIt != credential.metadata.end() && acmeDNSCredentialListAllows(recordsIt->second, recordName, false))
      {
        return true;
      }
      failure.assign("ACME DNS credential does not cover challenge record"_ctv);
      return false;
    }
    failure.assign("ACME DNS credential scope is invalid"_ctv);
    return false;
  }

  static bool acmeDNSRecordCoveredByDeclaredDNS(const WormholeDNSConfig& dns, const ApiCredential& credential, const String& recordName)
  {
    String declaredRecord = {};
    if (dns.name.size() && prodigyACMEDNS01RecordName(dns.name, declaredRecord) && declaredRecord.equals(recordName))
    {
      return true;
    }
    if (dns.zone.size() && acmeDNSCredentialListAllows(dns.zone, recordName, true))
    {
      return true;
    }
    if (auto zonesIt = credential.metadata.find("dnsZones"_ctv); zonesIt != credential.metadata.end() && acmeDNSCredentialListAllows(zonesIt->second, recordName, true))
    {
      return true;
    }
    if (auto zoneIt = credential.metadata.find("dnsZone"_ctv); zoneIt != credential.metadata.end() && acmeDNSCredentialListAllows(zoneIt->second, recordName, true))
    {
      return true;
    }
    if (auto recordsIt = credential.metadata.find("dnsRecords"_ctv); recordsIt != credential.metadata.end() && acmeDNSCredentialListAllows(recordsIt->second, recordName, false))
    {
      return true;
    }
    if (auto recordIt = credential.metadata.find("dnsRecord"_ctv); recordIt != credential.metadata.end() && acmeDNSCredentialListAllows(recordIt->second, recordName, false))
    {
      return true;
    }
    return false;
  }

  static size_t publicTlsFindLiteral(const String& text, const char *literal, size_t start = 0)
  {
    const size_t literalSize = std::strlen(literal);
    if (literalSize == 0 || start > text.size() || literalSize > text.size() - start)
    {
      return SIZE_MAX;
    }
    for (size_t index = start; index + literalSize <= text.size(); ++index)
    {
      if (std::memcmp(text.data() + index, literal, literalSize) == 0)
      {
        return index;
      }
    }
    return SIZE_MAX;
  }

  static bool splitFirstPEMCertificate(const String& fullchainPem, String& leafPem, String& chainPem, String& failure)
  {
    leafPem.clear();
    chainPem.clear();
    const char *beginMarker = "-----BEGIN CERTIFICATE-----";
    const char *endMarker = "-----END CERTIFICATE-----";
    size_t begin = publicTlsFindLiteral(fullchainPem, beginMarker);
    size_t end = begin == SIZE_MAX ? SIZE_MAX : publicTlsFindLiteral(fullchainPem, endMarker, begin);
    if (begin == SIZE_MAX || end == SIZE_MAX)
    {
      failure.assign("ACME fullchain is missing a PEM certificate"_ctv);
      return false;
    }
    end += std::strlen(endMarker);
    while (end < fullchainPem.size() && (fullchainPem[end] == '\n' || fullchainPem[end] == '\r'))
    {
      end += 1;
    }
    leafPem.assign(fullchainPem.substr(begin, end - begin, Copy::yes));
    chainPem.assign(fullchainPem.substr(end, fullchainPem.size() - end, Copy::yes));
    if (publicTlsFindLiteral(chainPem, beginMarker) == SIZE_MAX)
    {
      failure.assign("ACME fullchain is missing chain certificates"_ctv);
      return false;
    }
    return true;
  }

  static void freeX509Certificates(Vector<X509 *>& certs)
  {
    for (X509 *cert : certs)
    {
      if (cert)
      {
        X509_free(cert);
      }
    }
    certs.clear();
  }

  static bool x509PEMCertificates(const String& pem, Vector<X509 *>& certs, String& failure)
  {
    certs.clear();
    const char *beginMarker = "-----BEGIN CERTIFICATE-----";
    const char *endMarker = "-----END CERTIFICATE-----";
    for (size_t offset = 0;;)
    {
      size_t begin = publicTlsFindLiteral(pem, beginMarker, offset);
      if (begin == SIZE_MAX)
      {
        break;
      }
      size_t end = publicTlsFindLiteral(pem, endMarker, begin);
      if (end == SIZE_MAX)
      {
        failure.assign("ACME certificate chain PEM is incomplete"_ctv);
        freeX509Certificates(certs);
        return false;
      }
      end += std::strlen(endMarker);
      String certPem = {};
      certPem.assign(pem.substr(begin, end - begin, Copy::yes));
      X509 *cert = VaultPem::x509FromPem(certPem);
      if (cert == nullptr)
      {
        failure.assign("ACME certificate chain PEM is invalid"_ctv);
        freeX509Certificates(certs);
        return false;
      }
      certs.push_back(cert);
      offset = end;
    }
    return true;
  }

  static bool x509CertificateIssuedBy(X509 *cert, X509 *issuer)
  {
    EVP_PKEY *issuerKey = issuer == nullptr ? nullptr : X509_get_pubkey(issuer);
    bool ok = cert != nullptr && issuer != nullptr && issuerKey != nullptr &&
              X509_check_issued(issuer, cert) == X509_V_OK &&
              X509_verify(cert, issuerKey) == 1;
    if (issuerKey)
    {
      EVP_PKEY_free(issuerKey);
    }
    return ok;
  }

  static bool x509ChainLinksValid(X509 *leafCert, const String& chainPem, String& failure)
  {
    Vector<X509 *> chain = {};
    if (x509PEMCertificates(chainPem, chain, failure) == false)
    {
      return false;
    }
    if (chain.empty())
    {
      failure.assign("ACME fullchain is missing chain certificates"_ctv);
      return false;
    }

    X509 *issued = leafCert;
    for (X509 *issuer : chain)
    {
      if (x509CertificateIssuedBy(issued, issuer) == false)
      {
        failure.assign("ACME certificate chain is invalid"_ctv);
        freeX509Certificates(chain);
        return false;
      }
      issued = issuer;
    }
    freeX509Certificates(chain);
    return true;
  }

  static bool x509ChainTrustedBySystem(X509 *leafCert, const String& chainPem, String& failure)
  {
    Vector<X509 *> chain = {};
    if (x509PEMCertificates(chainPem, chain, failure) == false)
    {
      return false;
    }

    STACK_OF(X509) *untrusted = sk_X509_new_null();
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    bool ok = leafCert != nullptr && untrusted != nullptr && store != nullptr && ctx != nullptr &&
              X509_STORE_set_default_paths(store) == 1;
    for (X509 *cert : chain)
    {
      ok = ok && sk_X509_push(untrusted, cert) != 0;
    }
    ok = ok &&
         X509_STORE_CTX_init(ctx, store, leafCert, untrusted) == 1 &&
         X509_verify_cert(ctx) == 1;

    if (ctx)
    {
      X509_STORE_CTX_free(ctx);
    }
    if (store)
    {
      X509_STORE_free(store);
    }
    if (untrusted)
    {
      sk_X509_free(untrusted);
    }
    freeX509Certificates(chain);
    if (ok == false)
    {
      failure.assign("ACME certificate chain is not trusted"_ctv);
    }
    return ok;
  }

  static bool readACMELineageFile(const String& lineagePath, const char *name, String& output, String& failure)
  {
    String path = {};
    path.snprintf<"{}/{}"_ctv>(lineagePath, String(name));
    Filesystem::openReadAtClose(-1, path, output);
    if (output.size() == 0)
    {
      failure.snprintf<"failed to read ACME lineage file {}"_ctv>(path);
      return false;
    }
    return true;
  }

  static bool acmeLineagePathMatchesExpected(const String& lineagePath, const String& certName, const String& expectedLineagePath)
  {
    if (lineagePath.size() == 0 || lineagePath[0] != '/' || expectedLineagePath.size() == 0 || expectedLineagePath[0] != '/' || prodigySafePathSegment(certName) == false)
    {
      return false;
    }
    uint64_t lineageEnd = lineagePath.size();
    uint64_t expectedEnd = expectedLineagePath.size();
    while (lineageEnd > 1 && lineagePath[lineageEnd - 1] == '/')
    {
      lineageEnd -= 1;
    }
    while (expectedEnd > 1 && expectedLineagePath[expectedEnd - 1] == '/')
    {
      expectedEnd -= 1;
    }
    return lineageEnd == expectedEnd && lineagePath.substr(0, lineageEnd, Copy::yes).equals(expectedLineagePath.substr(0, expectedEnd, Copy::yes));
  }

  static bool x509DNSSubjectAltNames(X509 *cert, Vector<String>& dnsSans, String& failure)
  {
    dnsSans.clear();
    GENERAL_NAMES *names = cert == nullptr ? nullptr : static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (names == nullptr)
    {
      failure.assign("ACME certificate is missing DNS SANs"_ctv);
      return false;
    }

    for (int index = 0; index < sk_GENERAL_NAME_num(names); ++index)
    {
      const GENERAL_NAME *name = sk_GENERAL_NAME_value(names, index);
      if (name == nullptr || name->type != GEN_DNS || name->d.dNSName == nullptr)
      {
        continue;
      }
      const int length = ASN1_STRING_length(name->d.dNSName);
      const unsigned char *bytes = ASN1_STRING_get0_data(name->d.dNSName);
      if (length <= 0 || bytes == nullptr)
      {
        continue;
      }
      String dns = {};
      dns.assign(reinterpret_cast<const char *>(bytes), size_t(length));
      dnsSans.push_back(std::move(dns));
    }

    sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
    if (dnsSans.empty())
    {
      failure.assign("ACME certificate is missing DNS SANs"_ctv);
      return false;
    }
    return true;
  }

  static bool x509HasIPAddressSubjectAltName(X509 *cert)
  {
    GENERAL_NAMES *names = cert == nullptr ? nullptr : static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (names == nullptr)
    {
      return false;
    }
    bool found = false;
    for (int index = 0; index < sk_GENERAL_NAME_num(names); ++index)
    {
      const GENERAL_NAME *name = sk_GENERAL_NAME_value(names, index);
      if (name != nullptr && name->type == GEN_IPADD)
      {
        found = true;
        break;
      }
    }
    sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
    return found;
  }

  static bool x509HasExtendedKeyUsage(X509 *cert, int nid)
  {
    EXTENDED_KEY_USAGE *usage = cert == nullptr ? nullptr : static_cast<EXTENDED_KEY_USAGE *>(X509_get_ext_d2i(cert, NID_ext_key_usage, nullptr, nullptr));
    if (usage == nullptr)
    {
      return false;
    }
    bool found = false;
    for (int index = 0; index < sk_ASN1_OBJECT_num(usage); ++index)
    {
      const ASN1_OBJECT *object = sk_ASN1_OBJECT_value(usage, index);
      if (object != nullptr && OBJ_obj2nid(object) == nid)
      {
        found = true;
        break;
      }
    }
    sk_ASN1_OBJECT_pop_free(usage, ASN1_OBJECT_free);
    return found;
  }

  static bool publicTlsKeyMatchesSpec(EVP_PKEY *key, const String& keyType)
  {
    int baseID = key == nullptr ? EVP_PKEY_NONE : EVP_PKEY_base_id(key);
    return (keyType.equal("ecdsa"_ctv) && baseID == EVP_PKEY_EC) ||
           (keyType.equal("rsa"_ctv) && baseID == EVP_PKEY_RSA);
  }

  static bool publicTlsCertificateMatchesDeployment(const DeploymentPlan& plan, const PublicTlsCertificateState& certificate)
  {
    if (plan.config.applicationID != certificate.spec.applicationID || plan.config.deploymentID() != certificate.spec.deploymentID)
    {
      return false;
    }
    for (const WormholePublicTLSConfig& config : plan.publicTLS)
    {
      if (config.wormholeName.equals(certificate.spec.wormholeName) && config.identityName.equals(certificate.spec.identityName))
      {
        return true;
      }
    }
    return false;
  }

  static bool publicTlsCertificateTransferCompatible(const PublicTlsCertificateState& certificate, const PublicTlsCertificateSpec& spec)
  {
    return certificate.identity.certPem.size() > 0 &&
           certificate.spec.applicationID == spec.applicationID &&
           certificate.spec.identityName.equals(spec.identityName) &&
           certificate.spec.issuer.equals(spec.issuer) &&
           certificate.spec.keyType.equals(spec.keyType) &&
           certificate.spec.staging == spec.staging &&
           publicTlsDomainSetsEqual(certificate.spec.domains, spec.domains);
  }

  static void publicTlsCertbotName(const PublicTlsCertificateSpec& spec, String& certName)
  {
    String applicationID = {};
    applicationID.snprintf<"{itoa}"_ctv>(uint64_t(spec.applicationID));
    certName.assign("app"_ctv);
    certName.append(applicationID);
    certName.append("-"_ctv);
    certName.append(spec.identityName);
  }

  static String publicTlsCertificateRuntimeKey(const PublicTlsCertificateSpec& spec, const String& certName)
  {
    String key = {};
    key.snprintf<"{itoa}:{}:{}:{}"_ctv>(spec.deploymentID, spec.wormholeName, spec.identityName, certName);
    return key;
  }

  static String publicTlsCertificateRuntimeKey(const PublicTlsCertificateState& certificate)
  {
    return publicTlsCertificateRuntimeKey(certificate.spec, certificate.certbotCertName.size() ? certificate.certbotCertName : certificate.spec.identityName);
  }

  static AcmeDNS01ChallengeState acmeDNS01ChallengeStateFromRecord(const ProdigyDNSRecordBinding& record)
  {
    AcmeDNS01ChallengeState state = {};
    state.provider = record.provider;
    state.credentialName = record.credentialName;
    state.zone = record.zone;
    state.name = record.name;
    state.validation = record.values.empty() ? String() : record.values[0];
    state.ttl = record.ttl;
    return state;
  }

  static ProdigyDNSRecordBinding acmeDNS01ChallengeRecordFromState(const AcmeDNS01ChallengeState& state)
  {
    ProdigyDNSRecordBinding record = {};
    record.provider = state.provider;
    record.credentialName = state.credentialName;
    record.zone = state.zone;
    record.name = state.name;
    record.type.assign("TXT"_ctv);
    record.values.push_back(state.validation);
    record.ttl = state.ttl;
    return record;
  }

  static bool rememberPublicTlsPendingDNS01Challenge(PublicTlsCertificateState& certificate, const ProdigyDNSRecordBinding& record)
  {
    AcmeDNS01ChallengeState state = acmeDNS01ChallengeStateFromRecord(record);
    for (const AcmeDNS01ChallengeState& existing : certificate.pendingDNS01Challenges)
    {
      if (prodigyACMEDNS01ChallengeStatesEqual(existing, state))
      {
        return false;
      }
    }
    certificate.pendingDNS01Challenges.push_back(std::move(state));
    return true;
  }

  static bool forgetPublicTlsPendingDNS01Challenge(PublicTlsCertificateState& certificate, const ProdigyDNSRecordBinding& record)
  {
    AcmeDNS01ChallengeState state = acmeDNS01ChallengeStateFromRecord(record);
    for (auto it = certificate.pendingDNS01Challenges.begin(); it != certificate.pendingDNS01Challenges.end(); ++it)
    {
      if (prodigyACMEDNS01ChallengeStatesEqual(*it, state))
      {
        certificate.pendingDNS01Challenges.erase(it);
        return true;
      }
    }
    return false;
  }

  bool cleanupPublicTlsPendingDNS01Challenges(PublicTlsCertificateState& certificate)
  {
    if (weAreMaster == false)
    {
      return false;
    }
    const String certificateKey = publicTlsCertificateRuntimeKey(certificate);
    for (const AcmeDNS01ChallengeState& challenge : certificate.pendingDNS01Challenges)
    {
      ProdigyDNSRecordBinding record = acmeDNS01ChallengeRecordFromState(challenge);
      bool alreadyPending = false;
      for (const auto& [owner, pending] : pendingDNSOperations)
      {
        (void)owner;
        alreadyPending = pending.kind == PendingDNSOperationKind::challenge &&
                         pending.action == ProdigyBrainDNSOperationCoordinator::Action::cleanupTXT &&
                         pending.certificateKey.equals(certificateKey) &&
                         prodigyACMEDNS01ChallengeStatesEqual(acmeDNS01ChallengeStateFromRecord(pending.record), challenge);
        if (alreadyPending)
        {
          break;
        }
      }
      if (alreadyPending)
      {
        continue;
      }

      const ApiCredential *credential = findDNSCredential(certificate.spec.applicationID, challenge.credentialName);
      ProdigyDNSProvider *provider = credential == nullptr ||
                                             routableResourceDNSPartEquals(credential->provider, challenge.provider, false) == false ?
                                         nullptr :
                                         resolveDNSProvider(challenge.provider);
      if (provider == nullptr || dnsOperations.canEnqueue() == false)
      {
        armDNSReconciliationRetry();
        break;
      }
      const uint64_t owner = mintDNSOperationOwner();
      PendingDNSOperation pending;
      pending.kind = PendingDNSOperationKind::challenge;
      pending.action = ProdigyBrainDNSOperationCoordinator::Action::cleanupTXT;
      ownDNSRecordBinding(pending.record, record);
      pending.certificateKey.assign(certificateKey);
      pendingDNSOperations.insert_or_assign(owner, std::move(pending));
      if (!dnsOperations.enqueue(*provider,
                                ProdigyBrainDNSOperationCoordinator::Action::cleanupTXT,
                                record,
                                certificate.spec.applicationID,
                                credential->generation,
                                owner))
      {
        pendingDNSOperations.erase(owner);
        armDNSReconciliationRetry();
        break;
      }
    }
    return false;
  }

  PublicTlsCertificateState *findPublicTlsCertificateStateByRuntimeKey(const String& key)
  {
    for (PublicTlsCertificateState& certificate : masterAuthorityRuntimeState.publicTlsCertificates)
    {
      if (publicTlsCertificateRuntimeKey(certificate).equals(key))
      {
        return &certificate;
      }
    }
    return nullptr;
  }

  static void releasePublicTlsCertbotLock(PublicTlsCertbotJob& job)
  {
    if (job.lockFD < 0)
    {
      return;
    }
    prodigyReleaseCertbotLockFD(job.lockFD);
    job.lockFD = -1;
  }

  void cancelPublicTlsCertbotProcess(const String& key)
  {
    auto jobIt = publicTlsCertbotJobs.find(key);
    if (jobIt == publicTlsCertbotJobs.end())
    {
      return;
    }
    pid_t pid = jobIt->second.pid;
    if (pid > 0)
    {
      int status = 0;
      kill(pid, SIGTERM);
      if (waitpid(pid, &status, WNOHANG) == 0)
      {
        kill(pid, SIGKILL);
        (void)waitpid(pid, &status, 0);
      }
    }
    releasePublicTlsCertbotLock(jobIt->second);
    publicTlsCertbotJobs.erase(jobIt);
  }

  PublicTlsCertificateState *findTransferablePublicTlsCertificateState(const PublicTlsCertificateSpec& spec)
  {
    for (PublicTlsCertificateState& certificate : masterAuthorityRuntimeState.publicTlsCertificates)
    {
      if (certificate.releasePending == false &&
          certificate.spec.deploymentID != spec.deploymentID &&
          publicTlsCertbotJobs.find(publicTlsCertificateRuntimeKey(certificate)) == publicTlsCertbotJobs.end() &&
          publicTlsCertificateTransferCompatible(certificate, spec))
      {
        return &certificate;
      }
    }
    return nullptr;
  }

  static const Wormhole *findDeploymentWormholeByName(const DeploymentPlan& plan, const String& name)
  {
    for (const Wormhole& wormhole : plan.wormholes)
    {
      if (wormhole.name.equals(name))
      {
        return &wormhole;
      }
    }
    return nullptr;
  }

  bool buildPublicTlsCertificateSpecForDeployment(const DeploymentPlan& plan, const WormholePublicTLSConfig& config, PublicTlsCertificateSpec& spec, String& certName, String& failure) const
  {
    spec = {};
    certName.clear();
    failure.clear();

    const Wormhole *wormhole = findDeploymentWormholeByName(plan, config.wormholeName);
    if (wormhole == nullptr)
    {
      failure.assign("public TLS wormhole was not found"_ctv);
      return false;
    }
    if (brainConfig.acme.accountEmail.size() == 0 || brainConfig.acme.termsAgreed == false)
    {
      failure.assign("public TLS requires cluster ACME accountEmail and termsAgreed"_ctv);
      return false;
    }
    if (wormhole->hasDNSConfig == false || wormhole->dns.provider.size() == 0 || wormhole->dns.credentialName.size() == 0 || wormhole->dns.zone.size() == 0 || wormhole->dns.ttl == 0)
    {
      failure.assign("public TLS requires resolved wormhole DNS provider, credentialName, zone, and ttl"_ctv);
      return false;
    }

    spec.applicationID = plan.config.applicationID;
    spec.deploymentID = plan.config.deploymentID();
    spec.wormholeName = config.wormholeName;
    spec.identityName = config.identityName;
    Vector<String> domains = config.domains;
    if (domains.empty() && wormhole->dns.name.size() > 0)
    {
      domains.push_back(wormhole->dns.name);
    }
    for (const String& domain : domains)
    {
      String canonical = {};
      if (prodigyCanonicalACMEDNSIdentifier(domain, canonical, &failure) == false)
      {
        return false;
      }
      spec.domains.push_back(std::move(canonical));
    }
    if (spec.identityName.size() == 0 || spec.domains.empty())
    {
      failure.assign("public TLS requires identityName and domains"_ctv);
      return false;
    }
    if (prodigySafePathSegment(spec.identityName) == false)
    {
      failure.assign("public TLS identityName must be a safe path segment"_ctv);
      return false;
    }
    if (plan.hasTlsIssuancePolicy && plan.tlsIssuancePolicy.enablePerContainerLeafs)
    {
      for (const String& privateIdentityName : plan.tlsIssuancePolicy.identityNames)
      {
        if (privateIdentityName.equals(spec.identityName))
        {
          failure.assign("public TLS identityName conflicts with private TLS identityName"_ctv);
          return false;
        }
      }
    }
    if (config.issuer.equal("letsencrypt"_ctv) == false)
    {
      failure.assign("public TLS issuer must be letsencrypt"_ctv);
      return false;
    }
    if (config.keyType.equal("ecdsa"_ctv) == false && config.keyType.equal("rsa"_ctv) == false)
    {
      failure.assign("public TLS keyType must be ecdsa or rsa"_ctv);
      return false;
    }
    if (config.renewAfterLifetimePermille == 0 || config.renewAfterLifetimePermille >= 1000)
    {
      failure.assign("public TLS renewAfterLifetimePermille must be in 1..999"_ctv);
      return false;
    }
    const ApiCredential *credential = findDNSCredential(plan.config.applicationID, wormhole->dns.credentialName);
    if (credential == nullptr)
    {
      failure.assign("public TLS DNS credential is not registered"_ctv);
      return false;
    }
    if (routableResourceDNSPartEquals(credential->provider, wormhole->dns.provider, false) == false)
    {
      failure.assign("public TLS DNS credential provider mismatch"_ctv);
      return false;
    }
    for (const String& domain : spec.domains)
    {
      String recordName;
      if (prodigyACMEDNS01RecordName(domain, recordName, &failure) == false)
      {
        return false;
      }
      if (acmeDNSRecordCoveredByDeclaredDNS(wormhole->dns, *credential, recordName) == false)
      {
        failure.assign("public TLS domain is not covered by wormhole DNS"_ctv);
        return false;
      }
      if (acmeDNSCredentialAllowsRecord(*credential, recordName, failure) == false)
      {
        return false;
      }
    }
    spec.issuer = config.issuer;
    spec.keyType = config.keyType;
    spec.staging = config.staging;
    spec.dnsProvider = wormhole->dns.provider;
    spec.dnsCredentialName = wormhole->dns.credentialName;
    spec.dnsZone = wormhole->dns.zone;
    spec.dnsTTL = wormhole->dns.ttl;
    spec.renewAfterLifetimePermille = config.renewAfterLifetimePermille;
    publicTlsCertbotName(spec, certName);
    return true;
  }

  bool reconcilePublicTlsCertificateStatesForDeployment(const DeploymentPlan& plan, String& failure)
  {
    failure.clear();
    bool changed = false;
    Vector<PublicTlsCertificateSpec> desiredSpecs = {};
    Vector<String> desiredKeys = {};
    Vector<String> desiredCertNames = {};

    for (const WormholePublicTLSConfig& config : plan.publicTLS)
    {
      PublicTlsCertificateSpec spec = {};
      String certName = {};
      if (buildPublicTlsCertificateSpecForDeployment(plan, config, spec, certName, failure) == false)
      {
        return false;
      }
      for (const String& desiredCertName : desiredCertNames)
      {
        if (desiredCertName.equals(certName))
        {
          failure.assign("public TLS identityName is already used"_ctv);
          return false;
        }
      }
      desiredCertNames.push_back(certName);
      desiredSpecs.push_back(std::move(spec));
      desiredKeys.push_back(publicTlsCertificateRuntimeKey(desiredSpecs.back(), certName));
    }

    for (uint32_t index = 0; index < desiredSpecs.size(); ++index)
    {
      const PublicTlsCertificateSpec& spec = desiredSpecs[index];
      const String& certName = desiredCertNames[index];
      const String& key = desiredKeys[index];
      PublicTlsCertificateState *existing = findPublicTlsCertificateStateByRuntimeKey(key);
      if (existing == nullptr)
      {
        existing = findTransferablePublicTlsCertificateState(spec);
      }
      if (existing == nullptr)
      {
        PublicTlsCertificateState state = {};
        state.spec = spec;
        state.certbotCertName = certName;
        masterAuthorityRuntimeState.publicTlsCertificates.push_back(std::move(state));
        changed = true;
        continue;
      }

      bool keepIdentity = existing->identity.certPem.size() > 0 &&
                          existing->spec.identityName.equals(spec.identityName) &&
                          existing->spec.issuer.equals(spec.issuer) &&
                          existing->spec.keyType.equals(spec.keyType) &&
                          existing->spec.staging == spec.staging &&
                          publicTlsDomainSetsEqual(existing->spec.domains, spec.domains);
      if (prodigyPublicTlsCertificateSpecsEqual(existing->spec, spec) == false || existing->certbotCertName.equals(certName) == false)
      {
        existing->spec = spec;
        existing->certbotCertName = certName;
        if (keepIdentity == false)
        {
          existing->identity = {};
          existing->nextRenewAtMs = 0;
        }
        else if (existing->identity.notAfterMs > existing->identity.notBeforeMs)
        {
          existing->nextRenewAtMs = certificateLifecycleJitteredRenewAtMs(
              prodigyCertificateRenewAtMs(existing->identity.notBeforeMs, existing->identity.notAfterMs, existing->spec.renewAfterLifetimePermille),
              publicTlsCertificateJitterSeed(*existing));
        }
        changed = true;
      }
    }

    for (auto it = masterAuthorityRuntimeState.publicTlsCertificates.begin(); it != masterAuthorityRuntimeState.publicTlsCertificates.end();)
    {
      if (it->spec.deploymentID != plan.config.deploymentID())
      {
        ++it;
        continue;
      }
      bool retained = false;
      String key = publicTlsCertificateRuntimeKey(*it);
      for (const String& desired : desiredKeys)
      {
        if (desired.equals(key))
        {
          retained = true;
          break;
        }
      }
      if (retained)
      {
        ++it;
      }
      else
      {
        cancelPublicTlsCertbotProcess(key);
        it->releasePending = true;
        (void)cleanupPublicTlsPendingDNS01Challenges(*it);
        if (it->pendingDNS01Challenges.empty())
        {
          it = masterAuthorityRuntimeState.publicTlsCertificates.erase(it);
        }
        else
        {
          ++it;
        }
        changed = true;
      }
    }

    if (changed)
    {
      noteMasterAuthorityRuntimeStateChanged();
    }
    return true;
  }

  bool transferPublicTlsCertificateToApplicationHead(PublicTlsCertificateState& certificate)
  {
    auto appIt = deploymentsByApp.find(certificate.spec.applicationID);
    if (appIt == deploymentsByApp.end() || appIt->second == nullptr || appIt->second->plan.config.deploymentID() == certificate.spec.deploymentID ||
        publicTlsCertbotJobs.find(publicTlsCertificateRuntimeKey(certificate)) != publicTlsCertbotJobs.end())
    {
      return false;
    }

    for (const WormholePublicTLSConfig& config : appIt->second->plan.publicTLS)
    {
      PublicTlsCertificateSpec spec = {};
      String certName = {};
      String failure = {};
      if (buildPublicTlsCertificateSpecForDeployment(appIt->second->plan, config, spec, certName, failure) == false ||
          publicTlsCertificateTransferCompatible(certificate, spec) == false)
      {
        continue;
      }
      String newKey = publicTlsCertificateRuntimeKey(spec, certName);
      PublicTlsCertificateState *existing = findPublicTlsCertificateStateByRuntimeKey(newKey);
      if (existing != nullptr && existing != &certificate)
      {
        return false;
      }
      (void)cleanupPublicTlsPendingDNS01Challenges(certificate);
      certificate.spec = spec;
      certificate.certbotCertName = certName;
      certificate.releasePending = false;
      return true;
    }
    return false;
  }

  uint32_t releasePublicTlsCertificatesForDeployment(uint64_t deploymentID)
  {
    uint32_t changed = 0;
    for (auto it = masterAuthorityRuntimeState.publicTlsCertificates.begin(); it != masterAuthorityRuntimeState.publicTlsCertificates.end();)
    {
      if (it->spec.deploymentID != deploymentID)
      {
        ++it;
        continue;
      }
      if (transferPublicTlsCertificateToApplicationHead(*it))
      {
        changed += 1;
        ++it;
        continue;
      }
      cancelPublicTlsCertbotProcess(publicTlsCertificateRuntimeKey(*it));
      it->releasePending = true;
      (void)cleanupPublicTlsPendingDNS01Challenges(*it);
      if (it->pendingDNS01Challenges.empty())
      {
        it = masterAuthorityRuntimeState.publicTlsCertificates.erase(it);
      }
      else
      {
        ++it;
      }
      changed += 1;
    }
    if (changed > 0)
    {
      noteMasterAuthorityRuntimeStateChanged();
    }
    return changed;
  }

  bool applyACMEDNS01Challenge(const AcmeDNS01ChallengeRequest& request,
                               bool cleanup,
                               AcmeDNS01ChallengeResponse& response,
                               Mothership *replyStream = nullptr)
  {
    response = {};
    if (request.clusterUUID == 0 || brainConfig.clusterUUID == 0 || request.clusterUUID != brainConfig.clusterUUID)
    {
      response.failure.assign("ACME hook cluster UUID mismatch"_ctv);
      return false;
    }
    if (request.applicationID == 0 || request.deploymentID == 0 || request.wormholeName.size() == 0 || request.certName.size() == 0 || request.identifier.size() == 0 || request.validation.size() == 0)
    {
      response.failure.assign("ACME DNS-01 request is incomplete"_ctv);
      return false;
    }

    PublicTlsCertificateState *certificate = findPublicTlsCertificateState(request.applicationID, request.deploymentID, request.wormholeName, request.certName);
    if (certificate == nullptr)
    {
      response.failure.assign("ACME certificate state is not registered"_ctv);
      return false;
    }
    if (publicTlsCertificateCoversIdentifier(*certificate, request.identifier) == false)
    {
      response.failure.assign("ACME identifier is not in certificate domains"_ctv);
      return false;
    }

    ProdigyDNSRecordBinding record = {};
    record.provider = certificate->spec.dnsProvider;
    record.credentialName = certificate->spec.dnsCredentialName;
    record.zone = certificate->spec.dnsZone;
    record.type.assign("TXT"_ctv);
    record.values.push_back(request.validation);
    record.ttl = certificate->spec.dnsTTL ? certificate->spec.dnsTTL : 60;
    if (record.provider.size() == 0 || record.credentialName.size() == 0 || record.zone.size() == 0 ||
        prodigyACMEDNS01RecordName(request.identifier, record.name, &response.failure) == false)
    {
      if (response.failure.size() == 0)
      {
        response.failure.assign("ACME certificate DNS config is incomplete"_ctv);
      }
      return false;
    }

    const ApiCredential *credential = findDNSCredential(request.applicationID, record.credentialName);
    if (credential == nullptr)
    {
      response.failure.assign("ACME DNS credential is not registered"_ctv);
      return false;
    }
    if (routableResourceDNSPartEquals(credential->provider, record.provider, false) == false)
    {
      response.failure.assign("ACME DNS credential provider mismatch"_ctv);
      return false;
    }
    if (acmeDNSCredentialAllowsRecord(*credential, record.name, response.failure) == false)
    {
      return false;
    }

    ProdigyDNSProvider *provider = resolveDNSProvider(record.provider);
    if (provider == nullptr)
    {
      response.failure.assign("ACME DNS provider is not configured"_ctv);
      return false;
    }

    const uint64_t owner = mintDNSOperationOwner();
    PendingDNSOperation pending;
    pending.kind = PendingDNSOperationKind::challenge;
    pending.action = cleanup ? ProdigyBrainDNSOperationCoordinator::Action::cleanupTXT :
                               ProdigyBrainDNSOperationCoordinator::Action::presentTXT;
    ownDNSRecordBinding(pending.record, record);
    pending.certificateKey.assign(publicTlsCertificateRuntimeKey(*certificate));
    pending.stream = replyStream;
    pending.streamIncarnation = replyStream == nullptr ? 0 : replyStream->connectionIncarnation;
    pending.topic = cleanup ? MothershipTopic::cleanupACMEDNS01Challenge :
                              MothershipTopic::presentACMEDNS01Challenge;
    pending.inlineResponse = replyStream == nullptr ? &response : nullptr;
    pendingDNSOperations.insert_or_assign(owner, std::move(pending));
    const uint64_t propagationDelayUs = cleanup ? 0 : uint64_t(acmeDNSPropagationDelayMs(record, *credential)) * 1000;
    if (!dnsOperations.enqueue(*provider,
                              cleanup ? ProdigyBrainDNSOperationCoordinator::Action::cleanupTXT :
                                        ProdigyBrainDNSOperationCoordinator::Action::presentTXT,
                              record,
                              request.applicationID,
                              credential->generation,
                              owner,
                              propagationDelayUs))
    {
      pendingDNSOperations.erase(owner);
      response.failure.assign("ACME DNS operation queue is full"_ctv);
      return false;
    }
    if (auto it = pendingDNSOperations.find(owner); it != pendingDNSOperations.end())
    {
      it->second.inlineResponse = nullptr;
    }
    return true;
  }

  static uint32_t acmeDNSPropagationDelayMs(const ProdigyDNSRecordBinding& record, const ApiCredential& credential)
  {
    String key = {};
    key.assign("acmePropagationDelayMs"_ctv);
    if (auto it = credential.metadata.find(key); it != credential.metadata.end())
    {
      char *end = nullptr;
      errno = 0;
      String raw = it->second;
      unsigned long parsed = std::strtoul(raw.c_str(), &end, 10);
      if (end != raw.c_str() && *end == '\0' && errno == 0)
      {
        return uint32_t(std::min<unsigned long>(parsed, 300'000UL));
      }
    }
    uint64_t ttlMs = uint64_t(record.ttl ? record.ttl : 60) * 1000;
    return uint32_t(std::min<uint64_t>(std::max<uint64_t>(ttlMs, 5000), 60'000));
  }

  bool importACMELineage(const AcmeLineageImportRequest& request, AcmeLineageImportResponse& response)
  {
    response = {};
    response.certName = request.certName;
    if (request.clusterUUID == 0 || brainConfig.clusterUUID == 0 || request.clusterUUID != brainConfig.clusterUUID)
    {
      response.failure.assign("ACME hook cluster UUID mismatch"_ctv);
      return false;
    }
    if (request.applicationID == 0 || request.deploymentID == 0 || request.wormholeName.size() == 0 || request.certName.size() == 0 || request.lineagePath.size() == 0 || request.renewedDomains.empty())
    {
      response.failure.assign("ACME lineage import request is incomplete"_ctv);
      return false;
    }
    PublicTlsCertificateState *certificate = findPublicTlsCertificateState(request.applicationID, request.deploymentID, request.wormholeName, request.certName);
    if (certificate == nullptr)
    {
      response.failure.assign("ACME certificate state is not registered"_ctv);
      return false;
    }

    certificate->lastAttemptMs = Time::now<TimeResolution::ms>();
    auto fail = [&]() -> bool {
      noteCertificateFailure(certificate->failureCount, certificate->lastFailure, response.failure);
      noteMasterAuthorityRuntimeStateChanged();
      return false;
    };

    if (publicTlsDomainSetsEqual(certificate->spec.domains, request.renewedDomains) == false)
    {
      response.failure.assign("ACME renewed domains do not match certificate spec"_ctv);
      return fail();
    }
    String expectedLineagePath = certificate->lineagePath;
    if (expectedLineagePath.size() == 0)
    {
      prodigyCertbotLineagePath(brainConfig, *certificate, {}, expectedLineagePath);
    }
    if (acmeLineagePathMatchesExpected(request.lineagePath, request.certName, expectedLineagePath) == false)
    {
      response.failure.assign("ACME lineage path is not managed by this cluster"_ctv);
      return fail();
    }

    String fullchainPem = {};
    String keyPem = {};
    String leafPem = {};
    String chainPem = {};
    if (readACMELineageFile(request.lineagePath, "fullchain.pem", fullchainPem, response.failure) == false ||
        readACMELineageFile(request.lineagePath, "privkey.pem", keyPem, response.failure) == false ||
        splitFirstPEMCertificate(fullchainPem, leafPem, chainPem, response.failure) == false)
    {
      return fail();
    }

    X509 *leafCert = VaultPem::x509FromPem(leafPem);
    EVP_PKEY *leafKey = VaultPem::privateKeyFromPem(keyPem);
    Vector<String> certDNSNames = {};
    int64_t notBeforeMs = 0;
    int64_t notAfterMs = 0;
    bool ok = leafCert != nullptr && leafKey != nullptr;
    if (ok && X509_check_private_key(leafCert, leafKey) != 1)
    {
      response.failure.assign("ACME certificate does not match private key"_ctv);
      ok = false;
    }
    if (ok && x509ChainLinksValid(leafCert, chainPem, response.failure) == false)
    {
      ok = false;
    }
    if (ok && certificate->spec.staging == false && x509ChainTrustedBySystem(leafCert, chainPem, response.failure) == false)
    {
      ok = false;
    }
    if (ok && publicTlsKeyMatchesSpec(leafKey, certificate->spec.keyType) == false)
    {
      response.failure.assign("ACME private key type does not match certificate spec"_ctv);
      ok = false;
    }
    if (ok && x509DNSSubjectAltNames(leafCert, certDNSNames, response.failure) == false)
    {
      ok = false;
    }
    if (ok && publicTlsDomainSetsEqual(certificate->spec.domains, certDNSNames) == false)
    {
      response.failure.assign("ACME certificate SANs do not match certificate spec"_ctv);
      ok = false;
    }
    if (ok && x509HasIPAddressSubjectAltName(leafCert))
    {
      response.failure.assign("ACME certificate contains unexpected IP SANs"_ctv);
      ok = false;
    }
    if (ok && x509HasExtendedKeyUsage(leafCert, NID_server_auth) == false)
    {
      response.failure.assign("ACME certificate is not valid for server authentication"_ctv);
      ok = false;
    }
    if (ok && (x509TimeToEpochMs(X509_get0_notBefore(leafCert), notBeforeMs) == false || x509TimeToEpochMs(X509_get0_notAfter(leafCert), notAfterMs) == false || notAfterMs <= notBeforeMs))
    {
      response.failure.assign("ACME certificate lifetime is invalid"_ctv);
      ok = false;
    }

    if (leafCert)
    {
      X509_free(leafCert);
    }
    if (leafKey)
    {
      EVP_PKEY_free(leafKey);
    }
    if (ok == false)
    {
      if (response.failure.size() == 0)
      {
        response.failure.assign("ACME lineage import failed"_ctv);
      }
      return fail();
    }

    uint64_t generation = certificate->generation > certificate->identity.generation ? certificate->generation : certificate->identity.generation;
    generation += generation < UINT64_MAX ? 1 : 0;

    TlsIdentity identity = {};
    identity.name = certificate->spec.identityName;
    identity.generation = generation;
    identity.notBeforeMs = notBeforeMs;
    identity.notAfterMs = notAfterMs;
    identity.certPem = std::move(leafPem);
    identity.keyPem = std::move(keyPem);
    identity.chainPem = std::move(chainPem);
    identity.dnsSans = certificate->spec.domains;
    identity.tags.push_back("public"_ctv);
    identity.tags.push_back(certificate->spec.issuer.size() ? certificate->spec.issuer : "letsencrypt"_ctv);
    String wormholeTag = {};
    wormholeTag.snprintf<"wormhole:{}"_ctv>(certificate->spec.wormholeName);
    identity.tags.push_back(std::move(wormholeTag));

    certificate->identity = std::move(identity);
    certificate->certbotCertName = request.certName;
    certificate->lineagePath = request.lineagePath;
    certificate->generation = generation;
    certificate->nextRenewAtMs = certificateLifecycleJitteredRenewAtMs(prodigyCertificateRenewAtMs(notBeforeMs, notAfterMs, certificate->spec.renewAfterLifetimePermille), publicTlsCertificateJitterSeed(*certificate));
    certificate->lastSuccessMs = certificate->lastAttemptMs;
    certificate->failureCount = 0;
    certificate->lastFailure.clear();
    (void)cleanupPublicTlsPendingDNS01Challenges(*certificate);
    response.success = true;
    response.generation = generation;
    response.nextRenewAtMs = certificate->nextRenewAtMs;

    noteMasterAuthorityRuntimeStateChanged();
    (void)pushPublicTlsIdentityDeltaToLiveContainers(*certificate, "acme-lineage-import"_ctv);
    return true;
  }

  bool applyDeploymentDNSRecordLeases(const Vector<RoutableResourceLease>& leases, String& failure)
  {
    failure.clear();
    for (const RoutableResourceLease& lease : leases)
    {
      if (lease.kind != RoutableResourceLeaseKind::dnsRecord)
      {
        continue;
      }
      String enqueueFailure;
      if (enqueueDNSRecordLease(lease, enqueueFailure) == false)
      {
        if (failure.empty())
        {
          failure.assign(enqueueFailure);
        }
        break;
      }
    }
    // The durable leases are authoritative. Admission pressure leaves the
    // unqueued suffix pending for the deterministic reconciliation refill.
    return true;
  }

  uint32_t reconcileDNSRecordLeases(String *failure = nullptr)
  {
    if (failure)
    {
      failure->clear();
    }
    if (weAreMaster == false)
    {
      return 0;
    }

    for (auto applied = appliedDNSRecordLeases.begin(); applied != appliedDNSRecordLeases.end();)
    {
      bool current = false;
      for (const RoutableResourceLease& lease : routableResourceLeaseRuntimeState)
      {
        if (lease == *applied && lease.dnsDeletePending == false)
        {
          current = true;
          break;
        }
      }
      applied = current ? applied + 1 : appliedDNSRecordLeases.erase(applied);
    }

    uint32_t applied = 0;
    bool rejected = false;
    for (const RoutableResourceLease& lease : routableResourceLeaseRuntimeState)
    {
      if (lease.kind != RoutableResourceLeaseKind::dnsRecord)
      {
        continue;
      }

      if (dnsRecordLeaseApplied(lease) ||
          dnsRecordLeaseOperationPending(lease,
                                         lease.dnsDeletePending ?
                                             ProdigyBrainDNSOperationCoordinator::Action::remove :
                                             ProdigyBrainDNSOperationCoordinator::Action::upsert))
      {
        applied += dnsRecordLeaseApplied(lease) ? 1 : 0;
        continue;
      }

      String leaseFailure = {};
      if (enqueueDNSRecordLease(lease, leaseFailure))
      {
        continue;
      }

      if (failure != nullptr && failure->size() == 0)
      {
        *failure = leaseFailure;
      }
      rejected = true;
      basics_log("dns reconcile failed failure=%s\n", leaseFailure.c_str());
    }
    if (rejected)
    {
      armDNSReconciliationRetry();
    }
    return applied;
  }

  void reconcileAuthoritativeDNSState(void)
  {
    (void)reconcileDNSRecordLeases();
    for (PublicTlsCertificateState& certificate : masterAuthorityRuntimeState.publicTlsCertificates)
    {
      (void)cleanupPublicTlsPendingDNS01Challenges(certificate);
    }
  }

  bool resolveDeploymentWormholeDNSBinding(const DeploymentPlan& plan, Wormhole& wormhole, String& failure) const
  {
    failure.clear();
    if (wormhole.hasDNSConfig == false || wormhole.dns.bindingName.size() == 0)
    {
      return true;
    }

    RoutableResourceLeaseOwner owner = deploymentRoutableResourceLeaseOwner(plan);
    const RoutableResourceLease *binding = nullptr;
    for (const RoutableResourceLease& lease : routableResourceLeaseRuntimeState)
    {
      if (lease.kind != RoutableResourceLeaseKind::dnsRecord || lease.owner.applicationID != plan.config.applicationID || lease.owner.name.equals(wormhole.dns.bindingName) == false || routableResourceLeaseOwnersCompatible(lease.owner, owner) == false)
      {
        continue;
      }
      if (binding != nullptr)
      {
        failure.assign("wormhole DNS binding name is ambiguous"_ctv);
        return false;
      }
      binding = &lease;
    }
    if (binding == nullptr)
    {
      failure.assign("wormhole DNS binding was not found"_ctv);
      return false;
    }
    if (binding->address.isNull() || binding->registeredPrefixUUID == 0)
    {
      failure.assign("wormhole DNS binding has no attached routable address"_ctv);
      return false;
    }

    String requestedType = wormhole.dns.type;
    if (requestedType.size() > 0 && normalizeDNSRecordType(requestedType) == false)
    {
      failure.assign("wormhole DNS record type must be A, AAAA, CNAME, or TXT"_ctv);
      return false;
    }
    if ((wormhole.dns.provider.size() > 0 && routableResourceDNSPartEquals(wormhole.dns.provider, binding->dnsProvider, false) == false) ||
        (wormhole.dns.credentialName.size() > 0 && wormhole.dns.credentialName.equals(binding->dnsCredentialName) == false) ||
        (wormhole.dns.zone.size() > 0 && routableResourceDNSPartEquals(wormhole.dns.zone, binding->dnsZone, true) == false) ||
        (wormhole.dns.name.size() > 0 && routableResourceDNSPartEquals(wormhole.dns.name, binding->dnsName, true) == false) ||
        (requestedType.size() > 0 && routableResourceDNSPartEquals(requestedType, binding->dnsType, false) == false) ||
        (wormhole.dns.ttl != 0 && wormhole.dns.ttl != binding->dnsTTL))
    {
      failure.assign("wormhole DNS binding config conflicts with binding"_ctv);
      return false;
    }

    String bindingName = wormhole.dns.bindingName;
    bool allowSingleMachine = wormhole.dns.allowSingleMachine;
    wormhole.source = ExternalAddressSource::registeredRoutablePrefix;
    wormhole.routablePrefixUUID = binding->registeredPrefixUUID;
    wormhole.externalAddress = binding->address;
    wormhole.dns = WormholeDNSConfig();
    wormhole.dns.bindingName = bindingName;
    wormhole.dns.provider = binding->dnsProvider;
    wormhole.dns.credentialName = binding->dnsCredentialName;
    wormhole.dns.zone = binding->dnsZone;
    wormhole.dns.name = binding->dnsName;
    wormhole.dns.type = binding->dnsType;
    if (wormhole.dns.type.size() == 0)
    {
      wormhole.dns.type.assign(wormhole.externalAddress.is6 ? "AAAA" : "A");
    }
    wormhole.dns.ttl = binding->dnsTTL;
    wormhole.dns.allowSingleMachine = allowSingleMachine;
    return true;
  }

  bool reserveDeploymentWormholeAddressLeases(const DeploymentPlan& plan, String& failure, bool commit)
  {
    failure.clear();
    RoutableResourceLeaseOwner owner = deploymentRoutableResourceLeaseOwner(plan);

    Vector<RoutableResourceLease> leases = {};
    auto reserveLease = [&](RoutableResourceLease&& lease, StringType auto&& conflictFailure, StringType auto&& duplicateFailure) -> bool {
      if (lease.registeredPrefixUUID != 0 && routablePrefixReleasePending(lease.registeredPrefixUUID))
      {
        failure.assign("routable prefix cleanup is pending"_ctv);
        return false;
      }
      bool present = false;
      for (const RoutableResourceLease& existing : routableResourceLeaseRuntimeState)
      {
        if (existing.kind == lease.kind && routableResourceLeaseResourcesIntersect(existing, lease) && routableResourceLeaseOwnersCompatible(existing.owner, lease.owner))
        {
          present = true;
          break;
        }
        if (routableResourceLeasesConflict(existing, lease))
        {
          failure.assign(conflictFailure);
          return false;
        }
      }
      for (const RoutableResourceLease& pending : leases)
      {
        if (pending.kind != lease.kind || routableResourceLeaseResourcesIntersect(pending, lease) == false)
        {
          continue;
        }
        if (lease.kind == RoutableResourceLeaseKind::dnsRecord)
        {
          failure.assign(duplicateFailure);
          return false;
        }
        present = true;
        break;
      }
      if (present == false)
      {
        leases.push_back(std::move(lease));
      }
      return true;
    };

    for (const Wormhole& wormhole : plan.wormholes)
    {
      if (wormhole.externalAddress.isNull())
      {
        failure.assign("wormhole routable address is empty"_ctv);
        return false;
      }

      RoutableResourceLease lease = {};
      lease.kind = RoutableResourceLeaseKind::wormholeAddress;
      lease.owner = owner;
      lease.owner.name = wormhole.name;
      lease.registeredPrefixUUID = wormhole.routablePrefixUUID;
      lease.address = wormhole.externalAddress;

      if (reserveLease(std::move(lease), "wormhole routable address is already owned"_ctv, "wormhole routable address is already declared"_ctv) == false)
      {
        return false;
      }

      if (wormhole.hasDNSConfig)
      {
        String dnsType = {};
        if (wormholeDNSRecordType(wormhole, dnsType, &failure) == false)
        {
          return false;
        }

        RoutableResourceLease dnsLease = {};
        dnsLease.kind = RoutableResourceLeaseKind::dnsRecord;
        dnsLease.owner = owner;
        dnsLease.owner.name = wormhole.name;
        dnsLease.registeredPrefixUUID = wormhole.routablePrefixUUID;
        dnsLease.address = wormhole.externalAddress;
        dnsLease.dnsProvider = wormhole.dns.provider;
        dnsLease.dnsCredentialName = wormhole.dns.credentialName;
        dnsLease.dnsZone = wormhole.dns.zone;
        dnsLease.dnsName = wormhole.dns.name;
        dnsLease.dnsType = dnsType;
        dnsLease.dnsTTL = wormhole.dns.ttl;
        if (reserveLease(std::move(dnsLease), "wormhole DNS record is already owned"_ctv, "wormhole DNS record is already declared"_ctv) == false)
        {
          return false;
        }
      }
    }

    if (commit && leases.empty() == false)
    {
      for (RoutableResourceLease& lease : leases)
      {
        if (lease.kind == RoutableResourceLeaseKind::dnsRecord)
        {
          lease.dnsIntentRevision = mintDNSIntentRevision();
        }
      }
      routableResourceLeaseRuntimeState.insert(routableResourceLeaseRuntimeState.end(), leases.begin(), leases.end());
      noteRoutableResourceLeaseRuntimeStateChanged();
      (void)applyDeploymentDNSRecordLeases(leases, failure);
    }
    return true;
  }

  bool transferRoutableResourceLeaseToApplicationHead(RoutableResourceLease& lease)
  {
    if (lease.kind != RoutableResourceLeaseKind::wormholeAddress && lease.kind != RoutableResourceLeaseKind::whiteholeAddressPort && lease.kind != RoutableResourceLeaseKind::dnsRecord)
    {
      return false;
    }

    auto appIt = deploymentsByApp.find(lease.owner.applicationID);
    if (appIt == deploymentsByApp.end() || appIt->second == nullptr || appIt->second->plan.config.deploymentID() == lease.owner.deploymentID)
    {
      return false;
    }

    RoutableResourceLeaseOwner owner = deploymentRoutableResourceLeaseOwner(appIt->second->plan);
    if (routableResourceLeaseOwnersCompatible(lease.owner, owner) == false)
    {
      return false;
    }

    if (lease.kind == RoutableResourceLeaseKind::whiteholeAddressPort)
    {
      for (const auto& [shardGroup, containers] : appIt->second->containersByShardGroup)
      {
        (void)shardGroup;
        for (ContainerView *container : containers)
        {
          if (container == nullptr || container->state == ContainerState::destroying || container->state == ContainerState::destroyed)
          {
            continue;
          }
          for (const Whitehole& whitehole : container->whiteholes)
          {
            if (whitehole.hasAddress && whitehole.address.equals(lease.address) && whitehole.sourcePort == lease.sourcePort)
            {
              lease.owner = owner;
              return true;
            }
          }
        }
      }
      return false;
    }

    for (const Wormhole& wormhole : appIt->second->plan.wormholes)
    {
      if (wormhole.externalAddress.equals(lease.address) == false)
      {
        continue;
      }
      if (lease.kind == RoutableResourceLeaseKind::dnsRecord)
      {
        String dnsType = {};
        if (wormhole.hasDNSConfig == false || wormholeDNSRecordType(wormhole, dnsType) == false)
        {
          continue;
        }

        RoutableResourceLease candidate = {};
        candidate.kind = RoutableResourceLeaseKind::dnsRecord;
        candidate.dnsProvider = wormhole.dns.provider;
        candidate.dnsCredentialName = wormhole.dns.credentialName;
        candidate.dnsZone = wormhole.dns.zone;
        candidate.dnsName = wormhole.dns.name;
        candidate.dnsType = dnsType;
        candidate.dnsTTL = wormhole.dns.ttl;
        if (routableResourceDNSIdentityMatches(lease, candidate) == false)
        {
          continue;
        }

        lease.dnsProvider = candidate.dnsProvider;
        lease.dnsCredentialName = candidate.dnsCredentialName;
        lease.dnsZone = candidate.dnsZone;
        lease.dnsName = candidate.dnsName;
        lease.dnsType = candidate.dnsType;
        lease.dnsTTL = candidate.dnsTTL;
      }

      lease.owner = owner;
      lease.owner.name = wormhole.name;
      lease.registeredPrefixUUID = wormhole.routablePrefixUUID;
      lease.address = wormhole.externalAddress;
      if (lease.kind == RoutableResourceLeaseKind::dnsRecord)
      {
        lease.dnsDeletePending = false;
        lease.dnsIntentRevision = mintDNSIntentRevision();
      }
      return true;
    }

    return false;
  }

  bool validateDNSBindingLease(RoutableResourceLease& lease, String& failure) const
  {
    failure.clear();
    lease.kind = RoutableResourceLeaseKind::dnsRecord;
    lease.dnsDeletePending = false;
    lease.dnsIntentRevision = 0;
    if (lease.owner.applicationID == 0)
    {
      failure.assign("DNS binding applicationID required"_ctv);
      return false;
    }
    if (lease.owner.name.size() == 0 || lease.dnsProvider.size() == 0 || lease.dnsCredentialName.size() == 0 || lease.dnsZone.size() == 0 || lease.dnsName.size() == 0 || lease.dnsTTL == 0)
    {
      failure.assign("DNS binding requires bindingName, provider, credentialName, zone, name, and ttl"_ctv);
      return false;
    }
    if (lease.address.isNull() || lease.registeredPrefixUUID == 0)
    {
      failure.assign("DNS binding requires routablePrefixUUID and address"_ctv);
      return false;
    }
    if (routablePrefixReleasePending(lease.registeredPrefixUUID))
    {
      failure.assign("DNS binding routable prefix cleanup is pending"_ctv);
      return false;
    }
    if (brainConfig.dnsProvider.size() == 0 || routableResourceDNSPartEquals(lease.dnsProvider, brainConfig.dnsProvider, false) == false)
    {
      failure.assign("DNS binding provider is not enabled for this cluster"_ctv);
      return false;
    }

    const DistributableExternalSubnet *prefix = findRegisteredRoutablePrefix(brainConfig.distributableExternalSubnets, lease.registeredPrefixUUID);
    if (prefix == nullptr)
    {
      failure.assign("DNS binding routablePrefixUUID is not registered"_ctv);
      return false;
    }
    if (distributableExternalSubnetAllowsWormholes(*prefix) == false)
    {
      failure.assign("DNS binding registered prefix is not usable for wormholes"_ctv);
      return false;
    }
    if (prefix->ingressScope != RoutableIngressScope::switchboardFleet)
    {
      failure.assign("DNS binding requires switchboardFleet ingressScope"_ctv);
      return false;
    }
    if (prefix->subnet.canonicalized().containsAddress(lease.address) == false)
    {
      failure.assign("DNS binding address is outside registered routable prefix"_ctv);
      return false;
    }

    if (lease.dnsType.size() == 0)
    {
      lease.dnsType.assign(lease.address.is6 ? "AAAA" : "A");
    }
    if (normalizeDNSRecordType(lease.dnsType) == false)
    {
      failure.assign("DNS binding record type must be A, AAAA, CNAME, or TXT"_ctv);
      return false;
    }
    if ((lease.dnsType.equal("A"_ctv) && lease.address.is6) || (lease.dnsType.equal("AAAA"_ctv) && lease.address.is6 == false) || lease.dnsType.equal("CNAME"_ctv) || lease.dnsType.equal("TXT"_ctv))
    {
      failure.assign("DNS binding record type must match the address family"_ctv);
      return false;
    }

    if (lease.owner.lineageID == 0)
    {
      lease.owner.lineageID = lease.owner.applicationID;
    }

    const ApiCredential *credential = findDNSCredential(lease.owner.applicationID, lease.dnsCredentialName);
    if (credential == nullptr)
    {
      failure.assign("DNS binding credential is not registered"_ctv);
      return false;
    }
    if (routableResourceDNSPartEquals(credential->provider, lease.dnsProvider, false) == false)
    {
      failure.assign("DNS binding credential provider mismatch"_ctv);
      return false;
    }
    return true;
  }

  static RoutableResourceLease dnsBindingAddressLease(const RoutableResourceLease& dnsLease)
  {
    RoutableResourceLease lease = {};
    lease.kind = RoutableResourceLeaseKind::wormholeAddress;
    lease.owner = dnsLease.owner;
    lease.registeredPrefixUUID = dnsLease.registeredPrefixUUID;
    lease.address = dnsLease.address;
    return lease;
  }

  bool routablePrefixHasOwnedResourceLease(uint128_t prefixUUID) const
  {
    for (const RoutableResourceLease& lease : routableResourceLeaseRuntimeState)
    {
      if (prefixUUID != 0 && lease.registeredPrefixUUID == prefixUUID)
      {
        return true;
      }
    }
    return false;
  }

  bool deploymentUsesDNSBinding(const DeploymentPlan& plan, const RoutableResourceLease& dnsLease) const
  {
    RoutableResourceLeaseOwner owner = deploymentRoutableResourceLeaseOwner(plan);
    if (routableResourceLeaseOwnersCompatible(dnsLease.owner, owner) == false)
    {
      return false;
    }
    for (const Wormhole& wormhole : plan.wormholes)
    {
      if (wormhole.hasDNSConfig == false)
      {
        continue;
      }
      if (wormhole.dns.bindingName.size() > 0 && wormhole.dns.bindingName.equals(dnsLease.owner.name))
      {
        return true;
      }
      if (wormhole.externalAddress.equals(dnsLease.address) == false)
      {
        continue;
      }

      String dnsType = {};
      if (wormholeDNSRecordType(wormhole, dnsType) == false)
      {
        continue;
      }
      RoutableResourceLease candidate = {};
      candidate.kind = RoutableResourceLeaseKind::dnsRecord;
      candidate.dnsProvider = wormhole.dns.provider;
      candidate.dnsZone = wormhole.dns.zone;
      candidate.dnsName = wormhole.dns.name;
      candidate.dnsType = dnsType;
      if (routableResourceDNSIdentityMatches(dnsLease, candidate))
      {
        return true;
      }
    }
    return false;
  }

  bool dnsBindingLeaseInUse(const RoutableResourceLease& dnsLease) const
  {
    for (const auto& [deploymentID, deployment] : deployments)
    {
      (void)deploymentID;
      if (deployment != nullptr && deploymentUsesDNSBinding(deployment->plan, dnsLease))
      {
        return true;
      }
    }
    return false;
  }

  bool upsertDNSBindingLease(RoutableResourceLease lease,
                             RoutableResourceLeaseReport& response,
                             Mothership *replyStream = nullptr)
  {
    response = {};
    if (validateDNSBindingLease(lease, response.failure) == false)
    {
      return false;
    }

    RoutableResourceLease addressLease = dnsBindingAddressLease(lease);
    Vector<RoutableResourceLease> retained;
    retained.reserve(routableResourceLeaseRuntimeState.size() + 2);
    for (const RoutableResourceLease& existing : routableResourceLeaseRuntimeState)
    {
      if (existing.kind == RoutableResourceLeaseKind::dnsRecord && existing.owner.name.equals(lease.owner.name) && routableResourceLeaseOwnersCompatible(existing.owner, lease.owner) &&
          (routableResourceDNSIdentityMatches(existing, lease) == false || existing.registeredPrefixUUID != lease.registeredPrefixUUID || existing.address.equals(lease.address) == false))
      {
        response.failure.assign("DNS binding name is already owned"_ctv);
        return false;
      }
      if (existing.kind == RoutableResourceLeaseKind::dnsRecord && routableResourceDNSIdentityMatches(existing, lease) && routableResourceLeaseOwnersCompatible(existing.owner, lease.owner))
      {
        RoutableResourceLease sameRevision = lease;
        sameRevision.dnsIntentRevision = existing.dnsIntentRevision;
        if (existing.dnsDeletePending == false && existing == sameRevision)
        {
          lease.dnsIntentRevision = existing.dnsIntentRevision;
        }
        continue;
      }
      if (existing.kind == RoutableResourceLeaseKind::wormholeAddress && existing.registeredPrefixUUID == lease.registeredPrefixUUID && existing.address.equals(lease.address) && existing.owner == lease.owner)
      {
        continue;
      }
      retained.push_back(existing);
    }
    for (const RoutableResourceLease& existing : retained)
    {
      if (routableResourceLeasesConflict(existing, addressLease) || routableResourceLeasesConflict(existing, lease))
      {
        response.failure.assign("DNS binding conflicts with an owned routable resource"_ctv);
        return false;
      }
    }
    if (lease.dnsIntentRevision == 0)
    {
      lease.dnsIntentRevision = mintDNSIntentRevision();
    }
    retained.push_back(addressLease);
    retained.push_back(lease);
    routableResourceLeaseRuntimeState = std::move(retained);
    noteRoutableResourceLeaseRuntimeStateChanged();
    const uint64_t controlID = beginDNSControl(replyStream,
                                               MothershipTopic::upsertDNSBinding,
                                               1,
                                               replyStream == nullptr ? &response : nullptr);
    String failure;
    if (enqueueDNSRecordLease(routableResourceLeaseRuntimeState.back(), failure, controlID) == false)
    {
      finishDNSControl(controlID, lease, false, failure);
      return false;
    }
    if (auto it = pendingDNSControls.find(controlID); it != pendingDNSControls.end())
    {
      it->second.inlineResponse = nullptr;
    }
    return true;
  }

  bool deleteDNSBindingLease(RoutableResourceLease request,
                             RoutableResourceLeaseReport& response,
                             Mothership *replyStream = nullptr)
  {
    response = {};
    request.kind = RoutableResourceLeaseKind::dnsRecord;
    if (request.dnsProvider.size() == 0 || request.dnsZone.size() == 0 || request.dnsName.size() == 0 || request.dnsType.size() == 0)
    {
      response.failure.assign("delete DNS binding requires provider, zone, name, and type"_ctv);
      return false;
    }
    if (normalizeDNSRecordType(request.dnsType) == false)
    {
      response.failure.assign("delete DNS binding record type invalid"_ctv);
      return false;
    }

    const RoutableResourceLease *matched = nullptr;
    for (const RoutableResourceLease& lease : routableResourceLeaseRuntimeState)
    {
      if (lease.kind == RoutableResourceLeaseKind::dnsRecord && routableResourceDNSIdentityMatches(lease, request))
      {
        matched = &lease;
        break;
      }
    }
    if (matched == nullptr)
    {
      response.success = true;
      return true;
    }

    RoutableResourceLease dnsLease = *matched;
    RoutableResourceLease addressLease = dnsBindingAddressLease(dnsLease);
    if (dnsBindingLeaseInUse(dnsLease))
    {
      response.failure.assign("DNS binding is in use"_ctv);
      return false;
    }
    for (RoutableResourceLease& lease : routableResourceLeaseRuntimeState)
    {
      if (lease.kind == RoutableResourceLeaseKind::dnsRecord && lease == dnsLease)
      {
        if (lease.dnsDeletePending == false)
        {
          lease.dnsDeletePending = true;
          lease.dnsIntentRevision = mintDNSIntentRevision();
        }
        dnsLease = lease;
        break;
      }
    }
    noteRoutableResourceLeaseRuntimeStateChanged();
    const uint64_t controlID = beginDNSControl(replyStream,
                                               MothershipTopic::deleteDNSBinding,
                                               1,
                                               replyStream == nullptr ? &response : nullptr);
    String failure;
    if (enqueueDNSRecordLease(dnsLease, failure, controlID) == false)
    {
      finishDNSControl(controlID, dnsLease, false, failure);
      return false;
    }
    if (auto it = pendingDNSControls.find(controlID); it != pendingDNSControls.end())
    {
      it->second.inlineResponse = nullptr;
    }
    return true;
  }

  bool teardownDNSBindingLeases(RoutableResourceLeaseReport& response,
                                Mothership *replyStream = nullptr)
  {
    response = {};
    for (RoutableResourceLease& lease : routableResourceLeaseRuntimeState)
    {
      if (lease.kind != RoutableResourceLeaseKind::dnsRecord)
      {
        continue;
      }
      if (lease.dnsDeletePending == false)
      {
        lease.dnsDeletePending = true;
        lease.dnsIntentRevision = mintDNSIntentRevision();
      }
      response.leases.push_back(lease);
    }
    if (response.leases.empty())
    {
      response.success = true;
      return false;
    }
    const uint64_t controlID = beginDNSControl(replyStream,
                                               MothershipTopic::teardownDNSBindings,
                                               uint32_t(response.leases.size()),
                                               replyStream == nullptr ? &response : nullptr);
    noteRoutableResourceLeaseRuntimeStateChanged();
    for (const RoutableResourceLease& lease : response.leases)
    {
      String failure;
      if (enqueueDNSRecordLease(lease, failure, controlID) == false)
      {
        finishDNSControl(controlID, lease, false, failure);
      }
    }
    if (auto it = pendingDNSControls.find(controlID); it != pendingDNSControls.end())
    {
      it->second.inlineResponse = nullptr;
    }
    return true;
  }

  bool validateDeploymentWormholeDNSConfig(const DeploymentPlan& plan, const Wormhole& wormhole, String& failure) const
  {
    failure.clear();
    if (wormhole.hasDNSConfig == false)
    {
      return true;
    }
    if (wormhole.source != ExternalAddressSource::registeredRoutablePrefix)
    {
      failure.assign("wormhole DNS requires source=registeredRoutablePrefix"_ctv);
      return false;
    }
    if (wormhole.externalAddress.isNull())
    {
      failure.assign("wormhole DNS requires a claimed routable address"_ctv);
      return false;
    }
    if (wormhole.dns.provider.size() == 0 || wormhole.dns.credentialName.size() == 0 || wormhole.dns.zone.size() == 0 || wormhole.dns.name.size() == 0 || wormhole.dns.ttl == 0)
    {
      failure.assign("wormhole DNS config requires provider, credentialName, zone, name, and ttl"_ctv);
      return false;
    }
    if (brainConfig.dnsProvider.size() == 0)
    {
      failure.assign("cluster DNS provider is not configured"_ctv);
      return false;
    }
    if (routableResourceDNSPartEquals(wormhole.dns.provider, brainConfig.dnsProvider, false) == false)
    {
      failure.assign("wormhole DNS provider is not enabled for this cluster"_ctv);
      return false;
    }

    const DistributableExternalSubnet *prefix = findRegisteredRoutablePrefix(brainConfig.distributableExternalSubnets, wormhole.routablePrefixUUID);
    if (prefix == nullptr)
    {
      failure.assign("wormhole DNS routablePrefixUUID is not registered"_ctv);
      return false;
    }
    if (distributableExternalSubnetAllowsWormholes(*prefix) == false)
    {
      failure.assign("wormhole DNS registered prefix is not usable for wormholes"_ctv);
      return false;
    }
    if (prefix->subnet.canonicalized().containsAddress(wormhole.externalAddress) == false)
    {
      failure.assign("wormhole DNS claimed address is outside registered routable prefix"_ctv);
      return false;
    }
    if (prefix->ingressScope == RoutableIngressScope::singleMachine && wormhole.dns.allowSingleMachine == false)
    {
      failure.assign("wormhole DNS on singleMachine prefixes requires allowSingleMachine=true"_ctv);
      return false;
    }

    String dnsType = {};
    if (wormholeDNSRecordType(wormhole, dnsType, &failure) == false)
    {
      return false;
    }

    const ApiCredential *credential = findDNSCredential(plan.config.applicationID, wormhole.dns.credentialName);
    if (credential == nullptr)
    {
      failure.assign("wormhole DNS credential is not registered"_ctv);
      return false;
    }
    if (routableResourceDNSPartEquals(credential->provider, wormhole.dns.provider, false) == false)
    {
      failure.assign("wormhole DNS credential provider mismatch"_ctv);
      return false;
    }

    return true;
  }

  uint32_t releaseRoutableResourceLeasesForDeployment(uint64_t deploymentID) override
  {
    uint32_t publicTlsChanged = releasePublicTlsCertificatesForDeployment(deploymentID);
    uint32_t changed = 0;
    bool dnsChanged = false;
    for (RoutableResourceLease& lease : routableResourceLeaseRuntimeState)
    {
      if (lease.owner.deploymentID == deploymentID && transferRoutableResourceLeaseToApplicationHead(lease))
      {
        changed += 1;
      }
    }

    for (RoutableResourceLease& lease : routableResourceLeaseRuntimeState)
    {
      if (lease.owner.deploymentID != deploymentID || lease.kind != RoutableResourceLeaseKind::dnsRecord)
      {
        continue;
      }

      if (lease.dnsDeletePending == false)
      {
        lease.dnsDeletePending = true;
        lease.dnsIntentRevision = mintDNSIntentRevision();
        dnsChanged = true;
      }
    }

    for (auto it = routableResourceLeaseRuntimeState.begin(); it != routableResourceLeaseRuntimeState.end();)
    {
      if (it->owner.deploymentID != deploymentID ||
          it->kind == RoutableResourceLeaseKind::dnsRecord ||
          (it->kind == RoutableResourceLeaseKind::wormholeAddress &&
           std::any_of(routableResourceLeaseRuntimeState.begin(), routableResourceLeaseRuntimeState.end(), [&](const RoutableResourceLease& lease) {
             return lease.kind == RoutableResourceLeaseKind::dnsRecord && lease.owner == it->owner && lease.dnsDeletePending;
           })))
      {
        ++it;
        continue;
      }

      it = routableResourceLeaseRuntimeState.erase(it);
      changed += 1;
    }
    if (changed > 0 || dnsChanged)
    {
      noteRoutableResourceLeaseRuntimeStateChanged();
    }
    reconcileAuthoritativeDNSState();
    return publicTlsChanged + changed;
  }

  void upsertManagedMachineSchemaConfig(const ProdigyManagedMachineSchema& managedSchema)
  {
    MachineConfig machineConfig = {};
    prodigyBuildMachineConfigFromManagedMachineSchema(managedSchema, machineConfig);
    brainConfig.configBySlug.insert_or_assign(managedSchema.schema, std::move(machineConfig));
  }

  void eraseManagedMachineSchemaConfig(const String& schemaKey)
  {
    auto it = brainConfig.configBySlug.find(schemaKey);
    if (it != brainConfig.configBySlug.end())
    {
      brainConfig.configBySlug.erase(it);
    }
  }

  void syncManagedMachineSchemaConfigs(const Vector<ProdigyManagedMachineSchema>& previousSchemas, const Vector<ProdigyManagedMachineSchema>& incomingSchemas)
  {
    for (const ProdigyManagedMachineSchema& previousSchema : previousSchemas)
    {
      bool stillPresent = false;
      for (const ProdigyManagedMachineSchema& incomingSchema : incomingSchemas)
      {
        if (incomingSchema.schema.equals(previousSchema.schema))
        {
          stillPresent = true;
          break;
        }
      }

      if (stillPresent == false)
      {
        eraseManagedMachineSchemaConfig(previousSchema.schema);
      }
    }

    for (const ProdigyManagedMachineSchema& incomingSchema : incomingSchemas)
    {
      upsertManagedMachineSchemaConfig(incomingSchema);
    }
  }

  ProdigyPendingAutonomousProvisioningOperation *findPendingAutonomousProvisioningOperation(
      uint64_t deploymentID,
      ApplicationLifetime lifetime)
  {
    for (ProdigyPendingAutonomousProvisioningOperation& operation :
         masterAuthorityRuntimeState.pendingAutonomousProvisioningOperations)
    {
      if (operation.deploymentID == deploymentID &&
          operation.applicationLifetime == uint8_t(lifetime))
      {
        return &operation;
      }
    }
    return nullptr;
  }

  bool journalAutonomousProvisioningOperation(
      uint64_t deploymentID,
      ApplicationLifetime lifetime,
      const String& machineSchema,
      uint32_t count,
      uint64_t& operationID)
  {
    operationID = 0;
    if (deploymentID == 0 || machineSchema.empty() || count == 0 ||
        masterAuthorityRuntimeState.nextPendingAddMachinesOperationID == 0 ||
        masterAuthorityRuntimeState.nextPendingAddMachinesOperationID == UINT64_MAX)
    {
      return false;
    }

    const uint64_t previousGeneration = masterAuthorityRuntimeState.generation;
    const uint64_t previousNextOperationID =
        masterAuthorityRuntimeState.nextPendingAddMachinesOperationID;
    const bool previousDurable = masterAuthorityRuntimeStateDurable;
    const uint64_t previousDurableGeneration =
        durableMasterAuthorityRuntimeStateGeneration;

    ProdigyPendingAutonomousProvisioningOperation operation;
    operation.operationID = previousNextOperationID;
    operation.deploymentID = deploymentID;
    operation.applicationLifetime = uint8_t(lifetime);
    operation.machineSchema.assign(machineSchema);
    operation.count = count;
    masterAuthorityRuntimeState.nextPendingAddMachinesOperationID += 1;
    masterAuthorityRuntimeState.pendingAutonomousProvisioningOperations.push_back(
        std::move(operation));

    if (commitMasterAuthorityStateChange() == false)
    {
      masterAuthorityRuntimeState.pendingAutonomousProvisioningOperations.pop_back();
      masterAuthorityRuntimeState.nextPendingAddMachinesOperationID =
          previousNextOperationID;
      masterAuthorityRuntimeState.generation = previousGeneration;
      masterAuthorityRuntimeStateDurable = previousDurable;
      durableMasterAuthorityRuntimeStateGeneration = previousDurableGeneration;
      return false;
    }

    operationID = previousNextOperationID;
    return true;
  }

  bool settleAutonomousProvisioningOperation(uint64_t operationID)
  {
    auto& operations =
        masterAuthorityRuntimeState.pendingAutonomousProvisioningOperations;
    for (auto it = operations.begin(); it != operations.end(); ++it)
    {
      if (it->operationID != operationID)
      {
        continue;
      }

      const uint64_t previousGeneration = masterAuthorityRuntimeState.generation;
      const bool previousDurable = masterAuthorityRuntimeStateDurable;
      const uint64_t previousDurableGeneration =
          durableMasterAuthorityRuntimeStateGeneration;
      ProdigyPendingAutonomousProvisioningOperation operation = std::move(*it);
      const uint32_t index = uint32_t(it - operations.begin());
      operations.erase(it);
      if (commitMasterAuthorityStateChange())
      {
        return true;
      }

      operations.insert(operations.begin() + index, std::move(operation));
      masterAuthorityRuntimeState.generation = previousGeneration;
      masterAuthorityRuntimeStateDurable = previousDurable;
      durableMasterAuthorityRuntimeStateGeneration = previousDurableGeneration;
      return false;
    }
    return true;
  }

  ProdigyPendingAddMachinesOperation *findPendingAddMachinesOperation(uint64_t operationID)
  {
    for (ProdigyPendingAddMachinesOperation& operation : masterAuthorityRuntimeState.pendingAddMachinesOperations)
    {
      if (operation.operationID == operationID)
      {
        return &operation;
      }
    }

    return nullptr;
  }

  const ProdigyPendingAddMachinesOperation *findPendingAddMachinesOperation(uint64_t operationID) const
  {
    for (const ProdigyPendingAddMachinesOperation& operation : masterAuthorityRuntimeState.pendingAddMachinesOperations)
    {
      if (operation.operationID == operationID)
      {
        return &operation;
      }
    }

    return nullptr;
  }

  uint64_t journalAddMachinesOperation(const AddMachines& request, const ClusterTopology& plannedTopology, const Vector<ClusterMachine>& machinesToBootstrap)
  {
    refreshMasterAuthorityRuntimeStateFromLiveFields();

    uint64_t operationID = masterAuthorityRuntimeState.nextPendingAddMachinesOperationID++;
    if (operationID == 0)
    {
      operationID = masterAuthorityRuntimeState.nextPendingAddMachinesOperationID++;
    }

    ProdigyPendingAddMachinesOperation operation = {};
    operation.operationID = operationID;
    operation.request = request;
    operation.plannedTopology = plannedTopology;
    operation.machinesToBootstrap = machinesToBootstrap;
    operation.updatedAtMs = Time::now<TimeResolution::ms>();
    masterAuthorityRuntimeState.pendingAddMachinesOperations.push_back(std::move(operation));
    noteMasterAuthorityRuntimeStateChanged();
    return operationID;
  }

  bool upsertPendingAddMachinesOperationMachine(uint64_t operationID, const ClusterMachine& machine, bool queueForBootstrap, bool replicate = true, bool persist = true)
  {
    if (ProdigyPendingAddMachinesOperation *operation = findPendingAddMachinesOperation(operationID); operation != nullptr)
    {
      bool changed = prodigyUpsertClusterMachineByIdentity(operation->plannedTopology.machines, machine);
      if (queueForBootstrap)
      {
        changed = prodigyUpsertClusterMachineByIdentity(operation->machinesToBootstrap, machine) || changed;
      }

      if (changed)
      {
        operation->updatedAtMs = Time::now<TimeResolution::ms>();
        noteMasterAuthorityRuntimeStateChanged(replicate, persist);
      }

      return changed;
    }

    return false;
  }

  bool erasePendingAddMachinesOperationBootstrapMachine(uint64_t operationID, const ClusterMachine& machine, bool replicate = true, bool persist = true)
  {
    if (ProdigyPendingAddMachinesOperation *operation = findPendingAddMachinesOperation(operationID); operation != nullptr)
    {
      if (prodigyEraseClusterMachineByIdentity(operation->machinesToBootstrap, machine))
      {
        operation->updatedAtMs = Time::now<TimeResolution::ms>();
        noteMasterAuthorityRuntimeStateChanged(replicate, persist);
        return true;
      }
    }

    return false;
  }

  bool erasePendingAddMachinesOperation(uint64_t operationID, bool replicate = true, bool persist = true)
  {
    auto& operations = masterAuthorityRuntimeState.pendingAddMachinesOperations;
    auto it = std::remove_if(operations.begin(), operations.end(), [=](const ProdigyPendingAddMachinesOperation& operation) {
      return operation.operationID == operationID;
    });

    if (it == operations.end())
    {
      return false;
    }

    operations.erase(it, operations.end());
    noteMasterAuthorityRuntimeStateChanged(replicate, persist);
    return true;
  }

  void updatePendingAddMachinesOperationFailure(uint64_t operationID, const String& failure, bool replicate = true, bool persist = true)
  {
    if (ProdigyPendingAddMachinesOperation *operation = findPendingAddMachinesOperation(operationID); operation != nullptr)
    {
      operation->resumeAttempts += 1;
      operation->updatedAtMs = Time::now<TimeResolution::ms>();
      operation->lastFailure = failure;
      noteMasterAuthorityRuntimeStateChanged(replicate, persist);
    }
  }

  bool pendingAddMachinesOperationHasUnreadyCreatedMachines(const ProdigyPendingAddMachinesOperation& operation) const
  {
    for (const ClusterMachine& machine : operation.plannedTopology.machines)
    {
      if (machine.source == ClusterMachineSource::created && machine.backing == ClusterMachineBacking::cloud && prodigyClusterMachineBootstrapReady(machine) == false)
      {
        return true;
      }
    }

    return false;
  }

  bool refreshPendingAddMachinesOperationCreatedMachines(ProdigyPendingAddMachinesOperation& operation, String& failure)
  {
    failure.clear();
    if (pendingAddMachinesOperationHasUnreadyCreatedMachines(operation) == false)
    {
      return true;
    }

    String lookupScope = {};
    if (thisNeuron != nullptr && thisNeuron->metro.size() > 0)
    {
      lookupScope.assign(thisNeuron->metro);
    }
    else if (brainConfig.runtimeEnvironment.providerScope.size() > 0)
    {
      lookupScope.assign(brainConfig.runtimeEnvironment.providerScope);
    }

    bytell_hash_set<Machine *> providerMachines = {};
    if (brainConfig.runtimeEnvironment.kind == ProdigyEnvironmentKind::gcp)
    {
      failure.assign("gcp pending-machine refresh requires asynchronous inventory"_ctv);
      return false;
    }
    iaas->getMachines(nullptr, lookupScope, providerMachines, failure);
    if (failure.size() > 0)
    {
      return false;
    }

    bool changed = false;
    for (ClusterMachine& machine : operation.plannedTopology.machines)
    {
      if (machine.source != ClusterMachineSource::created || machine.backing != ClusterMachineBacking::cloud || prodigyClusterMachineBootstrapReady(machine))
      {
        continue;
      }

      for (Machine *candidate : providerMachines)
      {
        if (candidate == nullptr || prodigyClusterMachineMatchesMachineIdentity(machine, *candidate) == false)
        {
          continue;
        }

        ClusterMachine refreshed = machine;
        prodigyRefreshCreatedClusterMachineFromSnapshot(
            refreshed,
            candidate,
            operation.request.bootstrapSshUser,
            operation.request.bootstrapSshPrivateKeyPath,
            operation.request.bootstrapSshHostKeyPackage.publicKeyOpenSSH,
            brainConfig.machineReservedResources);
        if (refreshed != machine)
        {
          machine = std::move(refreshed);
          changed = true;
        }

        if (prodigyClusterMachineBootstrapReady(machine))
        {
          changed = prodigyUpsertClusterMachineByIdentity(operation.machinesToBootstrap, machine) || changed;
        }

        break;
      }
    }

    for (Machine *candidate : providerMachines)
    {
      delete candidate;
    }

    if (changed)
    {
      prodigyNormalizeClusterTopologyPeerAddresses(operation.plannedTopology);
      operation.updatedAtMs = Time::now<TimeResolution::ms>();
      noteMasterAuthorityRuntimeStateChanged();
    }

    if (pendingAddMachinesOperationHasUnreadyCreatedMachines(operation))
    {
      failure.assign("pending created machines are not yet ready to resume addMachines bootstrap"_ctv);
      return false;
    }

    return true;
  }

  bool mergePendingAddMachinesTopology(const ProdigyPendingAddMachinesOperation& operation, ClusterTopology& mergedTopology, String& failure) const
  {
    failure.clear();

    ClusterTopology authoritativeTopology = {};
    if (loadAuthoritativeClusterTopology(authoritativeTopology) == false)
    {
      failure.assign("failed to load authoritative topology for addMachines resume"_ctv);
      return false;
    }

    mergedTopology = authoritativeTopology;
    for (const ClusterMachine& machine : operation.plannedTopology.machines)
    {
      if (clusterTopologyContainsMachineIdentity(mergedTopology, machine))
      {
        continue;
      }

      mergedTopology.machines.push_back(machine);
    }

    for (const ClusterMachine& removedMachine : operation.request.removedMachines)
    {
      auto it = std::remove_if(mergedTopology.machines.begin(), mergedTopology.machines.end(), [&](const ClusterMachine& existing) {
        return existing.sameIdentityAs(removedMachine);
      });
      mergedTopology.machines.erase(it, mergedTopology.machines.end());
    }

    prodigyNormalizeClusterTopologyPeerAddresses(mergedTopology);
    mergedTopology.version = authoritativeTopology.version + 1;
    return true;
  }

  virtual bool canSuspendRemoteBootstrap(void) const
  {
    return RingDispatcher::dispatcher != nullptr && Ring::getRingFD() > 0;
  }

  virtual bool queueClusterMachineBootstrapAsync(
      ProdigyRemoteBootstrapCoordinator& coordinator,
      ProdigyRemoteBootstrapBundleApprovalCache& bundleApprovalCache,
      const ClusterMachine& clusterMachine,
      const AddMachines& request,
      const ClusterTopology& topology,
      String& failure) const
  {
    ProdigyRemoteBootstrapPlan plan = {};
    if (prodigyBuildRemoteBootstrapPlan(clusterMachine, request, topology, brainConfig.runtimeEnvironment, plan, &failure) == false)
    {
      return false;
    }

    String internalSSHAddress = {};
    if (prodigyResolveClusterMachineInternalSSHAddress(clusterMachine, internalSSHAddress))
    {
      plan.ssh.address = internalSSHAddress;
    }

    ProdigyPreparedRemoteBootstrapPlan prepared = {};
    if (prodigyPrepareRemoteBootstrapPlan(clusterMachine, plan, prepared, &bundleApprovalCache, &failure) == false)
    {
      return false;
    }

    coordinator.startPreparedPlan(prepared);
    return true;
  }

  virtual bool bootstrapClusterMachineBlocking(
      const ClusterMachine& clusterMachine,
      const AddMachines& request,
      const ClusterTopology& topology,
      String& failure,
      ProdigyRemoteBootstrapBundleApprovalCache *bundleApprovalCache = nullptr) const
  {
    ProdigyRemoteBootstrapPlan plan = {};
    if (prodigyBuildRemoteBootstrapPlan(clusterMachine, request, topology, brainConfig.runtimeEnvironment, plan, &failure) == false)
    {
      return false;
    }

    String internalSSHAddress = {};
    if (prodigyResolveClusterMachineInternalSSHAddress(clusterMachine, internalSSHAddress))
    {
      plan.ssh.address = internalSSHAddress;
    }

    auto failBootstrap = [&]() -> bool {
      String label = {};
      clusterMachine.renderIdentityLabel(label);
      String reason = failure;
      failure.snprintf<"failed to bootstrap machine '{}': {}"_ctv>(label, reason);
      return false;
    };

    ProdigyPreparedRemoteBootstrapPlan prepared = {};
    if (prodigyPrepareRemoteBootstrapPlan(clusterMachine, plan, prepared, bundleApprovalCache, &failure) == false)
    {
      return failBootstrap();
    }

    Vector<ProdigyPreparedRemoteBootstrapPlan> preparedPlans = {};
    preparedPlans.push_back(std::move(prepared));
    if (prodigyExecutePreparedRemoteBootstrapPlans(preparedPlans, nullptr, &failure) == false)
    {
      return failBootstrap();
    }

    return true;
  }

  virtual void stopClusterMachineBootstrap(const ClusterMachine& clusterMachine) const
  {
    ProdigyRemoteBootstrapPlan plan = {};
    if (prodigyResolveClusterMachineSSHAddress(clusterMachine, plan.ssh.address) == false || clusterMachine.ssh.user.size() == 0 || clusterMachine.ssh.hostPublicKeyOpenSSH.size() == 0)
    {
      return;
    }

    plan.ssh.port = clusterMachine.ssh.port > 0 ? clusterMachine.ssh.port : 22;
    plan.ssh.user = clusterMachine.ssh.user;
    plan.ssh.privateKeyPath = clusterMachine.ssh.privateKeyPath;
    plan.ssh.hostPublicKeyOpenSSH = clusterMachine.ssh.hostPublicKeyOpenSSH;
    plan.stopCommand.assign("systemctl stop prodigy"_ctv);

    bool useBootstrapSshKeyPackage = prodigyBootstrapSSHKeyPackageConfigured(brainConfig.bootstrapSshKeyPackage) && (plan.ssh.privateKeyPath.size() == 0 || plan.ssh.privateKeyPath.equals(brainConfig.bootstrapSshPrivateKeyPath) || ::access(plan.ssh.privateKeyPath.c_str(), R_OK) != 0);
    if (useBootstrapSshKeyPackage == false && plan.ssh.privateKeyPath.size() == 0)
    {
      return;
    }

    LIBSSH2_SESSION *session = nullptr;
    int fd = -1;
    String failure = {};
    if (useBootstrapSshKeyPackage)
    {
      (void)prodigyConnectBlockingSSHSession(
          plan.ssh.address,
          plan.ssh.port,
          plan.ssh.hostPublicKeyOpenSSH,
          plan.ssh.user,
          plan.ssh.privateKeyPath,
          &brainConfig.bootstrapSshKeyPackage,
          session,
          fd,
          &failure);
    }
    else
    {
      (void)prodigyConnectBlockingSSHSession(
          plan.ssh.address,
          plan.ssh.port,
          plan.ssh.hostPublicKeyOpenSSH,
          plan.ssh.user,
          plan.ssh.privateKeyPath,
          session,
          fd,
          &failure);
    }
    if (session == nullptr || fd < 0)
    {
      if (session)
      {
        libssh2_session_free(session);
      }
      if (fd >= 0)
      {
        ::close(fd);
      }
      return;
    }

    (void)prodigyRunBlockingSSHCommand(session, fd, plan.stopCommand, nullptr);
    libssh2_session_free(session);
    ::close(fd);
  }

  bool resumePendingAddMachinesOperation(uint64_t operationID)
  {
    if (operationID == 0)
    {
      return true;
    }

    ProdigyPendingAddMachinesOperation *persistedOperation = findPendingAddMachinesOperation(operationID);
    if (persistedOperation == nullptr)
    {
      return true;
    }

    String failure = {};
    Vector<ClusterMachine> startedMachines = {};

    if (refreshPendingAddMachinesOperationCreatedMachines(*persistedOperation, failure) == false)
    {
      updatePendingAddMachinesOperationFailure(operationID, failure);
      return false;
    }

    if (persistedOperation->machinesToBootstrap.empty() == false)
    {
      ProdigyRemoteBootstrapBundleApprovalCache bootstrapBundleApprovalCache = {};
      if (prodigyBootstrapItemsConcurrently<ClusterMachine>(
              persistedOperation->machinesToBootstrap,
              [this, &persistedOperation, &bootstrapBundleApprovalCache](const ClusterMachine& clusterMachine, String& bootstrapFailure) -> bool {
                return bootstrapClusterMachineBlocking(
                    clusterMachine,
                    persistedOperation->request,
                    persistedOperation->plannedTopology,
                    bootstrapFailure,
                    &bootstrapBundleApprovalCache);
              },
              [this](const ClusterMachine& clusterMachine) -> void {
                stopClusterMachineBootstrap(clusterMachine);
              },
              &startedMachines,
              failure) == false)
      {
        for (const ClusterMachine& clusterMachine : startedMachines)
        {
          stopClusterMachineBootstrap(clusterMachine);
        }

        updatePendingAddMachinesOperationFailure(operationID, failure);
        return false;
      }
    }

    ClusterTopology mergedTopology = {};
    if (mergePendingAddMachinesTopology(*persistedOperation, mergedTopology, failure) == false)
    {
      updatePendingAddMachinesOperationFailure(operationID, failure);
      return false;
    }

    restoreBrainsFromClusterTopology(mergedTopology);
    restoreMachinesFromClusterTopology(mergedTopology);
    nBrains = clusterTopologyBrainCount(mergedTopology);
    initializeAllBrainPeersIfNeeded();

    if (persistAuthoritativeClusterTopology(mergedTopology) == false)
    {
      updatePendingAddMachinesOperationFailure(persistedOperation->operationID, "failed to persist authoritative cluster topology during addMachines resume"_ctv);
      return false;
    }

    if (nBrains > 1)
    {
      String serializedTopology = {};
      BitseryEngine::serialize(serializedTopology, mergedTopology);
      queueBrainReplication(BrainTopic::replicateClusterTopology, serializedTopology);
    }

    erasePendingAddMachinesOperation(operationID);
    return true;
  }

  void resumePendingAddMachinesOperations(void)
  {
    if (weAreMaster == false || masterAuthorityRuntimeState.pendingAddMachinesOperations.empty())
    {
      return;
    }

    Vector<uint64_t> operationIDs = {};
    operationIDs.reserve(masterAuthorityRuntimeState.pendingAddMachinesOperations.size());
    for (const ProdigyPendingAddMachinesOperation& operation : masterAuthorityRuntimeState.pendingAddMachinesOperations)
    {
      operationIDs.push_back(operation.operationID);
    }

    for (uint64_t operationID : operationIDs)
    {
      if (findPendingAddMachinesOperation(operationID) == nullptr)
      {
        continue;
      }

      (void)resumePendingAddMachinesOperation(operationID);
    }
  }

  void queueMasterAuthorityRuntimeStateReplication(void)
  {
    refreshMasterAuthorityRuntimeStateFromLiveFields();
    if (weAreMaster == false || nBrains <= 1)
    {
      return;
    }
    if ((masterAuthorityRuntimeState.pendingElasticAddressAssignments.empty() == false ||
         masterAuthorityRuntimeState.pendingElasticAddressReleases.empty() == false) &&
        (masterAuthorityRuntimeStateDurable == false ||
         durableMasterAuthorityRuntimeStateGeneration != masterAuthorityRuntimeState.generation))
    {
      return;
    }

    if (prodigyDebugDeployHeapEnabled())
    {
      const ProdigyDeployHeapMetrics heap = prodigyReadDeployHeapMetrics();
      PRODIGY_DEBUG_LOG(
                   "prodigy debug runtime-state-replication-begin generation=%llu deployments=%zu apps=%zu brains=%zu heapUsed=%llu heapMapped=%llu heapFree=%llu\n",
                   (unsigned long long)masterAuthorityRuntimeState.generation,
                   size_t(deployments.size()),
                   size_t(deploymentsByApp.size()),
                   size_t(brains.size()) + 1,
                   (unsigned long long)heap.used,
                   (unsigned long long)heap.mapped,
                   (unsigned long long)heap.free);
      PRODIGY_DEBUG_FLUSH();
    }

    String serialized;
    ProdigyMasterAuthorityStateTransition transition;
    transition.runtimeState = masterAuthorityRuntimeState;
    transition.runtimeState.updateSelf = {};
    ownBrainConfig(brainConfig, transition.brainConfig);
    BitseryEngine::serialize(serialized, transition);
    String transitionDigest;
    if (prodigyComputeSHA256Hex(serialized, transitionDigest) == false)
    {
      return;
    }

    if (prodigyDebugDeployHeapEnabled())
    {
      const ProdigyDeployHeapMetrics heap = prodigyReadDeployHeapMetrics();
      PRODIGY_DEBUG_LOG(
                   "prodigy debug runtime-state-replication-serialized generation=%llu bytes=%zu deployments=%zu apps=%zu heapUsed=%llu heapMapped=%llu heapFree=%llu\n",
                   (unsigned long long)masterAuthorityRuntimeState.generation,
                   size_t(serialized.size()),
                   size_t(deployments.size()),
                   size_t(deploymentsByApp.size()),
                   (unsigned long long)heap.used,
                   (unsigned long long)heap.mapped,
                   (unsigned long long)heap.free);
      PRODIGY_DEBUG_FLUSH();
    }
    for (BrainView *peer : brains)
    {
      noteMasterAuthorityTransitionSentToPeer(peer,
                                              transition.runtimeState,
                                              transitionDigest);
    }
    queueBrainReplication(BrainTopic::replicateMasterAuthorityState, serialized);
  }

  void noteMasterAuthorityRuntimeStateChanged(bool replicate = true, bool persist = true)
  {
    refreshMasterAuthorityRuntimeStateFromLiveFields();
    if (masterAuthorityRuntimeState.generation < UINT64_MAX)
    {
      masterAuthorityRuntimeState.generation += 1;
    }

    if (persist)
    {
      masterAuthorityRuntimeStateDurable = false;
      if (persistLocalRuntimeState() == false)
      {
        return;
      }
      masterAuthorityRuntimeStateDurable = true;
      durableMasterAuthorityRuntimeStateGeneration =
          masterAuthorityRuntimeState.generation;
      captureDurableElasticAddressOperations();
    }

    if (replicate)
    {
      queueMasterAuthorityRuntimeStateReplication();
    }
  }

  bool commitMasterAuthorityStateChange(bool advanceGeneration = true)
  {
    refreshMasterAuthorityRuntimeStateFromLiveFields();
    if (advanceGeneration)
    {
      if (masterAuthorityRuntimeState.generation == UINT64_MAX)
      {
        return false;
      }
      masterAuthorityRuntimeState.generation += 1;
    }
    masterAuthorityRuntimeStateDurable = false;
    if (persistLocalRuntimeState() == false)
    {
      return false;
    }
    masterAuthorityRuntimeStateDurable = true;
    durableMasterAuthorityRuntimeStateGeneration = masterAuthorityRuntimeState.generation;
    captureDurableElasticAddressOperations();
    queueMasterAuthorityRuntimeStateReplication();
    return true;
  }

  bool pruneExpiredTaskExecutionRecords(int64_t nowMs)
  {
    if (weAreMaster == false)
    {
      return false;
    }

    bool changed = false;
    for (auto it = masterAuthorityRuntimeState.taskExecutions.begin(); it != masterAuthorityRuntimeState.taskExecutions.end();)
    {
      if (it->second.expired(nowMs))
      {
        it = masterAuthorityRuntimeState.taskExecutions.erase(it);
        changed = true;
      }
      else
      {
        ++it;
      }
    }

    if (changed)
    {
      noteMasterAuthorityRuntimeStateChanged();
    }

    return changed;
  }

  void captureAuthoritativeDeploymentPlans(bytell_hash_map<uint64_t, DeploymentPlan>& plans) const
  {
    plans = deploymentPlans;
    for (const auto& [deploymentID, deployment] : deployments)
    {
      if (deployment == nullptr)
      {
        continue;
      }

      plans.insert_or_assign(deploymentID, deployment->plan);
    }
  }

  void capturePersistentMasterAuthorityPackage(ProdigyPersistentMasterAuthorityPackage& package) const
  {
    package = {};
    package.tlsVaultFactoriesByApp = tlsVaultFactoriesByApp;
    package.apiCredentialSetsByApp = apiCredentialSetsByApp;
    package.reservedApplicationIDsByName = reservedApplicationIDsByName;
    package.reservedApplicationNamesByID = reservedApplicationNamesByID;
    capturePersistentReservedApplicationServices(package.reservedApplicationServices);
    package.nextReservableApplicationID = nextReservableApplicationID;
    captureAuthoritativeDeploymentPlans(package.deploymentPlans);
    package.failedDeployments = failedDeployments;
    package.runtimeState = masterAuthorityRuntimeState;
    package.runtimeState.hasCompletedInitialMasterElection = hasCompletedInitialMasterElection;
    package.runtimeState.nextMintedClientTlsGeneration = (nextMintedClientTlsGeneration == 0) ? 1 : nextMintedClientTlsGeneration;
    package.runtimeState.nextTlsResumptionGeneration = (nextTlsResumptionGeneration == 0) ? 1 : nextTlsResumptionGeneration;
    package.runtimeState.tlsResumptionSnapshotsByWormhole = captureTlsResumptionSnapshotsByWormhole();
    package.runtimeState.updateSelf = capturePersistentUpdateSelfState();
  }

  void applyPersistentMasterAuthorityPackage(const ProdigyPersistentMasterAuthorityPackage& package)
  {
    ProdigyMasterAuthorityRuntimeState restoredRuntimeState = package.runtimeState;
    if (restoredRuntimeState.nextPendingElasticAddressOperationID == 0)
    {
      restoredRuntimeState.nextPendingElasticAddressOperationID = 1;
    }
    if (restoredRuntimeState.nextDNSIntentRevision == 0)
    {
      restoredRuntimeState.nextDNSIntentRevision = 1;
    }
    if (validatePendingElasticAddressOperations(restoredRuntimeState) == false ||
        configurePendingElasticAddressReleaseFence(restoredRuntimeState) == false)
    {
      return;
    }
    Vector<ProdigyManagedMachineSchema> previousSchemas = masterAuthorityRuntimeState.machineSchemas;
    tlsVaultFactoriesByApp = package.tlsVaultFactoriesByApp;
    apiCredentialSetsByApp = package.apiCredentialSetsByApp;
    reservedApplicationIDsByName = package.reservedApplicationIDsByName;
    reservedApplicationNamesByID = package.reservedApplicationNamesByID;
    restorePersistentReservedApplicationServices(package.reservedApplicationServices);
    nextReservableApplicationID = (package.nextReservableApplicationID == 0) ? 1 : package.nextReservableApplicationID;
    deploymentPlans = package.deploymentPlans;
    failedDeployments = package.failedDeployments;
    masterAuthorityRuntimeState = std::move(restoredRuntimeState);
    masterAuthorityRuntimeStateDurable = true;
    durableMasterAuthorityRuntimeStateGeneration = masterAuthorityRuntimeState.generation;
    captureDurableElasticAddressOperations();
    hasCompletedInitialMasterElection = masterAuthorityRuntimeState.hasCompletedInitialMasterElection;
    statefulWorkerTopologyUpgradeRuntimeState = masterAuthorityRuntimeState.statefulWorkerTopologyUpgradeOperations;
    deferredStatefulScaleIntentRuntimeState = masterAuthorityRuntimeState.deferredStatefulScaleIntents;
    routableResourceLeaseRuntimeState = masterAuthorityRuntimeState.routableResourceLeases;
    appliedDNSRecordLeases.clear();
    if (masterAuthorityRuntimeState.nextPendingAddMachinesOperationID == 0)
    {
      masterAuthorityRuntimeState.nextPendingAddMachinesOperationID = 1;
    }
    if (masterAuthorityRuntimeState.nextPendingElasticAddressOperationID == 0)
    {
      masterAuthorityRuntimeState.nextPendingElasticAddressOperationID = 1;
    }
    if (masterAuthorityRuntimeState.nextDNSIntentRevision == 0)
    {
      masterAuthorityRuntimeState.nextDNSIntentRevision = 1;
    }
    nextMintedClientTlsGeneration = (masterAuthorityRuntimeState.nextMintedClientTlsGeneration == 0)
                                        ? 1
                                        : masterAuthorityRuntimeState.nextMintedClientTlsGeneration;
    nextTlsResumptionGeneration = (masterAuthorityRuntimeState.nextTlsResumptionGeneration == 0)
                                      ? 1
                                      : masterAuthorityRuntimeState.nextTlsResumptionGeneration;
    restoreTlsResumptionSnapshotsByWormhole(masterAuthorityRuntimeState.tlsResumptionSnapshotsByWormhole, false);
    restorePersistentUpdateSelfState(masterAuthorityRuntimeState.updateSelf);
    restoreMothershipTunnelProviderDesiredStateFromMasterAuthority();
    syncManagedMachineSchemaConfigs(previousSchemas, masterAuthorityRuntimeState.machineSchemas);
    (void)quarantinePendingElasticAddressReleasePrefixes(masterAuthorityRuntimeState);
    reconcileAuthoritativeDNSState();
    if (masterAuthorityRuntimeState.pendingElasticAddressAssignments.empty() &&
        masterAuthorityRuntimeState.pendingElasticAddressReleases.empty() && iaas != nullptr)
    {
      (void)iaas->setElasticAddressReleaseFenceActive(false);
    }
  }

  bool applyReplicatedMasterAuthorityRuntimeState(const ProdigyMasterAuthorityRuntimeState& incoming, bool persist = true)
  {
    ProdigyMasterAuthorityRuntimeState sanitizedIncoming = incoming;
    sanitizedIncoming.updateSelf = {};
    if (sanitizedIncoming.nextPendingAddMachinesOperationID == 0)
    {
      sanitizedIncoming.nextPendingAddMachinesOperationID = 1;
    }
    if (sanitizedIncoming.nextPendingElasticAddressOperationID == 0 ||
        validatePendingElasticAddressOperations(sanitizedIncoming) == false)
    {
      return false;
    }
    if (sanitizedIncoming.nextDNSIntentRevision == 0)
    {
      sanitizedIncoming.nextDNSIntentRevision = 1;
    }
    if (sanitizedIncoming.nextTlsResumptionGeneration == 0)
    {
      sanitizedIncoming.nextTlsResumptionGeneration = 1;
    }

    const bool shouldApply = sanitizedIncoming.generation > masterAuthorityRuntimeState.generation;

    if (sanitizedIncoming.generation == masterAuthorityRuntimeState.generation &&
        sanitizedIncoming != masterAuthorityRuntimeState)
    {
      return false;
    }
    const bool currentHasPendingElasticOperations =
        masterAuthorityRuntimeState.pendingElasticAddressAssignments.empty() == false ||
        masterAuthorityRuntimeState.pendingElasticAddressReleases.empty() == false;
    const bool incomingHasPendingElasticOperations =
        sanitizedIncoming.pendingElasticAddressAssignments.empty() == false ||
        sanitizedIncoming.pendingElasticAddressReleases.empty() == false;
    const ProdigyMasterAuthorityRuntimeState& fenceState =
        currentHasPendingElasticOperations && incomingHasPendingElasticOperations == false
            ? masterAuthorityRuntimeState
            : sanitizedIncoming;
    if (configurePendingElasticAddressReleaseFence(fenceState) == false)
    {
      return false;
    }

    if (shouldApply == false && sanitizedIncoming == masterAuthorityRuntimeState && persist &&
        (masterAuthorityRuntimeStateDurable == false ||
         durableMasterAuthorityRuntimeStateGeneration != sanitizedIncoming.generation))
    {
      masterAuthorityRuntimeStateDurable = persistLocalRuntimeState();
      if (masterAuthorityRuntimeStateDurable)
      {
        durableMasterAuthorityRuntimeStateGeneration = sanitizedIncoming.generation;
        captureDurableElasticAddressOperations();
      }
      return masterAuthorityRuntimeStateDurable;
    }
    if (shouldApply == false && sanitizedIncoming == masterAuthorityRuntimeState)
    {
      return persist == false ||
             (masterAuthorityRuntimeStateDurable &&
              durableMasterAuthorityRuntimeStateGeneration == sanitizedIncoming.generation);
    }
    if (shouldApply == false)
    {
      return false;
    }

    ProdigyMasterAuthorityRuntimeState previousRuntimeState =
        std::move(masterAuthorityRuntimeState);
    const bool previousDurable = masterAuthorityRuntimeStateDurable;
    const uint64_t previousDurableGeneration = durableMasterAuthorityRuntimeStateGeneration;
    const bool previousCompletedInitialElection = hasCompletedInitialMasterElection;
    const uint64_t previousNextMintedClientTlsGeneration = nextMintedClientTlsGeneration;
    const uint64_t previousNextTlsResumptionGeneration = nextTlsResumptionGeneration;
    ProdigyResumptionRegistry::SnapshotMap previousTlsResumptionSnapshots =
        captureTlsResumptionSnapshotsByWormhole();
    Vector<ProdigyManagedMachineSchema> previousSchemas = previousRuntimeState.machineSchemas;
    masterAuthorityRuntimeState = std::move(sanitizedIncoming);
    masterAuthorityRuntimeStateDurable = false;
    hasCompletedInitialMasterElection = masterAuthorityRuntimeState.hasCompletedInitialMasterElection;
    nextMintedClientTlsGeneration = masterAuthorityRuntimeState.nextMintedClientTlsGeneration;
    nextTlsResumptionGeneration = masterAuthorityRuntimeState.nextTlsResumptionGeneration;
    restoreTlsResumptionSnapshotsByWormhole(
        masterAuthorityRuntimeState.tlsResumptionSnapshotsByWormhole,
        true);

    if (persist && persistLocalRuntimeState() == false)
    {
      masterAuthorityRuntimeState = std::move(previousRuntimeState);
      masterAuthorityRuntimeStateDurable = previousDurable;
      durableMasterAuthorityRuntimeStateGeneration = previousDurableGeneration;
      hasCompletedInitialMasterElection = previousCompletedInitialElection;
      nextMintedClientTlsGeneration = previousNextMintedClientTlsGeneration;
      nextTlsResumptionGeneration = previousNextTlsResumptionGeneration;
      restoreTlsResumptionSnapshotsByWormhole(previousTlsResumptionSnapshots, true);
      (void)configurePendingElasticAddressReleaseFence(masterAuthorityRuntimeState);
      return false;
    }

    statefulWorkerTopologyUpgradeRuntimeState = masterAuthorityRuntimeState.statefulWorkerTopologyUpgradeOperations;
    deferredStatefulScaleIntentRuntimeState = masterAuthorityRuntimeState.deferredStatefulScaleIntents;
    routableResourceLeaseRuntimeState = masterAuthorityRuntimeState.routableResourceLeases;
    appliedDNSRecordLeases.clear();
    restoreMothershipTunnelProviderDesiredStateFromMasterAuthority();
    syncManagedMachineSchemaConfigs(previousSchemas, masterAuthorityRuntimeState.machineSchemas);
    (void)quarantinePendingElasticAddressReleasePrefixes(masterAuthorityRuntimeState);
    reconcileAuthoritativeDNSState();

    if (persist)
    {
      masterAuthorityRuntimeStateDurable = true;
      durableMasterAuthorityRuntimeStateGeneration = masterAuthorityRuntimeState.generation;
      captureDurableElasticAddressOperations();
    }

    if (masterAuthorityRuntimeState.pendingElasticAddressAssignments.empty() &&
        masterAuthorityRuntimeState.pendingElasticAddressReleases.empty() && iaas != nullptr)
    {
      (void)iaas->setElasticAddressReleaseFenceActive(false);
    }

    onMasterAuthorityRuntimeStateApplied();
    if (weAreMaster && (persist == false || masterAuthorityRuntimeStateDurable))
    {
      reconcilePendingElasticAddressAssignments();
      reconcilePendingElasticAddressReleases();
    }
    return persist == false || masterAuthorityRuntimeStateDurable;
  }

  bool applyReplicatedMasterAuthorityTransition(
      const ProdigyMasterAuthorityStateTransition& incoming,
      bool persist = true)
  {
    const bool incomingHasPendingElasticOperations =
        incoming.runtimeState.pendingElasticAddressAssignments.empty() == false ||
        incoming.runtimeState.pendingElasticAddressReleases.empty() == false;
    if (incoming.version != ProdigyMasterAuthorityStateTransition::currentVersion ||
        validatePendingElasticAddressOperations(incoming.runtimeState, &incoming.brainConfig) == false ||
        elasticAddressSagaFencesRuntimeEnvironment(incoming.brainConfig.runtimeEnvironment) ||
        (brainConfig.clusterUUID != 0 && incomingHasPendingElasticOperations &&
         incoming.brainConfig.runtimeEnvironment != brainConfig.runtimeEnvironment))
    {
      return false;
    }

    if (incoming.runtimeState.generation < masterAuthorityRuntimeState.generation)
    {
      return false;
    }

    String currentConfig;
    String incomingConfig;
    BitseryEngine::serialize(currentConfig, brainConfig);
    BrainConfig ownedIncoming;
    ownBrainConfig(incoming.brainConfig, ownedIncoming);
    BitseryEngine::serialize(incomingConfig, ownedIncoming);
    const bool configChanged = currentConfig.equals(incomingConfig) == false;
    if (brainConfig.clusterUUID != 0 && ownedIncoming.clusterUUID == 0)
    {
      return false;
    }
    if (incoming.runtimeState.generation == masterAuthorityRuntimeState.generation &&
        (incoming.runtimeState != masterAuthorityRuntimeState ||
         configChanged))
    {
      return false;
    }
    String ownershipFailure;
    if (claimLocalClusterOwnership(ownedIncoming.clusterUUID, &ownershipFailure) == false)
    {
      basics_log("replicateMasterAuthorityState reject clusterUUID=%llu reason=%s\n",
                 (unsigned long long)ownedIncoming.clusterUUID,
                 ownershipFailure.c_str());
      return false;
    }
    if (incoming.runtimeState.generation == masterAuthorityRuntimeState.generation)
    {
      return applyReplicatedMasterAuthorityRuntimeState(incoming.runtimeState, persist);
    }

    BrainConfig previousConfig = std::move(brainConfig);
    brainConfig = std::move(ownedIncoming);
    if (applyReplicatedMasterAuthorityRuntimeState(incoming.runtimeState, persist))
    {
      if (configChanged)
      {
        refreshMachineFragmentAssignmentsIfPossible();
        loadBrainConfigIf();
      }
      return true;
    }
    brainConfig = std::move(previousConfig);
    (void)configurePendingElasticAddressReleaseFence(masterAuthorityRuntimeState);
    return false;
  }

  bool peerCanReplicateMasterAuthorityState(BrainView *peer)
  {
    if (peer == nullptr || peer->quarantined || peer->registrationFresh == false ||
        peer->uuid == 0 || peer->boottimens == 0 || peer->isFixedFile == false ||
        peer->fslot < 0 || peerSocketActive(peer) == false ||
        peer->isMasterBrain == false)
    {
      return false;
    }
    return peer->transportTLSEnabled() == false ||
           (peer->isTLSNegotiated() && peer->tlsPeerVerified && peer->tlsPeerUUID == peer->uuid);
  }

  virtual void onMasterAuthorityRuntimeStateApplied(void)
  {
  }

  virtual bool claimLocalClusterOwnership(uint128_t clusterUUID, String *failure = nullptr)
  {
    (void)clusterUUID;
    if (failure)
    {
      failure->clear();
    }
    return true;
  }

  static uint64_t wormholeQuicCidRotationIntervalMs(const Wormhole& wormhole)
  {
    uint32_t rotationHours = wormhole.quicCidKeyState.rotationHours;
    if (rotationHours == 0)
    {
      rotationHours = 24;
    }

    return uint64_t(rotationHours) * 60ULL * 60ULL * 1000ULL;
  }

  static void mintWormholeQuicCidKeyMaterial(uint128_t& keyMaterial, uint8_t phase)
  {
    uint8_t key[16] = {};
    Crypto::fillWithSecureRandomBytes(key, sizeof(key));
    prodigyForceBiphasalKeyPhase(key, phase);
    wormholeQuicCidStoreKeyBytes(keyMaterial, key);
  }

  bool ensureWormholeQuicCidKeyState(Wormhole& wormhole, int64_t nowMs, bool allowRotation)
  {
    if (wormholeUsesQuicCidEncryption(wormhole) == false)
    {
      return false;
    }

    bool changed = false;
    if (wormhole.quicCidKeyState.rotationHours == 0)
    {
      wormhole.quicCidKeyState.rotationHours = 24;
      changed = true;
    }

    if (wormhole.quicCidKeyState.activeKeyIndex > 1)
    {
      wormhole.quicCidKeyState.activeKeyIndex &= 0x01;
      changed = true;
    }

    if (wormhole.hasQuicCidKeyState == false)
    {
      mintWormholeQuicCidKeyMaterial(wormhole.quicCidKeyState.keyMaterialByIndex[0], 0);
      mintWormholeQuicCidKeyMaterial(wormhole.quicCidKeyState.keyMaterialByIndex[1], 1);
      wormhole.quicCidKeyState.activeKeyIndex = 0;
      wormhole.quicCidKeyState.rotatedAtMs = nowMs;
      wormhole.hasQuicCidKeyState = true;
      return true;
    }

    for (uint8_t keyIndex = 0; keyIndex < 2; ++keyIndex)
    {
      if (wormhole.quicCidKeyState.keyMaterialByIndex[keyIndex] == uint128_t(0))
      {
        mintWormholeQuicCidKeyMaterial(wormhole.quicCidKeyState.keyMaterialByIndex[keyIndex], keyIndex);
        changed = true;
      }
      else if (wormholeQuicCidForceKeyMaterialPhase(wormhole.quicCidKeyState.keyMaterialByIndex[keyIndex], keyIndex))
      {
        changed = true;
      }
    }

    if (wormhole.quicCidKeyState.rotatedAtMs <= 0)
    {
      wormhole.quicCidKeyState.rotatedAtMs = nowMs;
      changed = true;
    }

    if (allowRotation == false)
    {
      return changed;
    }

    uint64_t rotationIntervalMs = wormholeQuicCidRotationIntervalMs(wormhole);
    if (rotationIntervalMs == 0 || nowMs < wormhole.quicCidKeyState.rotatedAtMs || uint64_t(nowMs - wormhole.quicCidKeyState.rotatedAtMs) < rotationIntervalMs)
    {
      return changed;
    }

    uint8_t nextKeyIndex = wormholeQuicCidInactiveKeyIndex(wormhole.quicCidKeyState);
    mintWormholeQuicCidKeyMaterial(wormhole.quicCidKeyState.keyMaterialByIndex[nextKeyIndex], nextKeyIndex);
    wormhole.quicCidKeyState.activeKeyIndex = nextKeyIndex;
    wormhole.quicCidKeyState.rotatedAtMs = nowMs;
    wormhole.hasQuicCidKeyState = true;
    return true;
  }

  bool prepareDeploymentPlanWormholeQuicCidState(DeploymentPlan& plan, int64_t nowMs)
  {
    bool changed = false;
    for (Wormhole& wormhole : plan.wormholes)
    {
      if (ensureWormholeQuicCidKeyState(wormhole, nowMs, false))
      {
        changed = true;
      }
    }

    return changed;
  }

  void applyReplicatedDeploymentPlanLiveState(const DeploymentPlan& plan)
  {
    (void)removeTlsResumptionStateNotEnabledByPlan(plan, true);

    auto deploymentIt = deployments.find(plan.config.deploymentID());
    if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
    {
      return;
    }

    ApplicationDeployment *deployment = deploymentIt->second;
    deployment->plan = plan;
    for (ContainerView *container : deployment->containers)
    {
      if (container == nullptr)
      {
        continue;
      }

      container->wormholes = plan.wormholes;
      container->whiteholes = plan.whiteholes;
      container->networkAccess = plan.networkAccess;
    }
  }

  Machine *findMachineForReplicatedContainerRuntimeState(const BrainReplicatedContainerRuntimeState& state)
  {
    if (state.machineUUID != 0)
    {
      if (auto it = machinesByUUID.find(state.machineUUID); it != machinesByUUID.end())
      {
        return it->second;
      }
    }

    if (state.machinePrivate4 != 0)
    {
      for (Machine *machine : machines)
      {
        if (machine != nullptr && machine->private4 == state.machinePrivate4)
        {
          return machine;
        }
      }
    }

    return nullptr;
  }

  void detachContainerRuntimeState(ContainerView *container)
  {
    if (container == nullptr)
    {
      return;
    }

    Machine *previousMachine = container->machine;
    uint64_t previousDeploymentID = container->deploymentID;
    uint32_t previousShardGroup = container->shardGroup;

    if (previousMachine != nullptr)
    {
      previousMachine->removeContainerIndexEntry(previousDeploymentID, container);
    }

    if (previousDeploymentID > 0)
    {
      if (auto prevDeployment = deployments.find(previousDeploymentID); prevDeployment != deployments.end() && prevDeployment->second != nullptr)
      {
        prevDeployment->second->containers.erase(container);
        if (prevDeployment->second->plan.isStateful)
        {
          while (prevDeployment->second->containersByShardGroup.eraseEntry(previousShardGroup, container))
          {
          }
        }
      }
    }
  }

  void applyContainerRuntimePlanToView(ContainerView *container, Machine *machine, ApplicationDeployment *deployment, ContainerPlan& plan)
  {
    container->subscriptions.clear();
    container->advertisements.clear();
    container->advertisingOnPorts.clear();

    container->uuid = plan.uuid;
    container->deploymentID = plan.config.deploymentID();
    container->applicationID = plan.config.applicationID;
    container->lifetime = plan.lifetime;
    container->state = plan.state;
    container->runtimeReady = plan.runtimeReady;
    if (container->runtimeReady == false)
    {
      container->clearStatefulTopologyCutoverBarrier();
    }
    container->machine = machine;
    container->createdAtMs = plan.createdAtMs;
    container->taskAttemptNumber = plan.taskAttemptNumber;
    container->runtime_nLogicalCores = static_cast<uint16_t>(applicationSharedCPUCoreHint(plan.config));
    container->runtime_memoryMB = plan.config.totalMemoryMB();
    container->runtime_storageMB = plan.config.totalStorageMB();
    container->addresses = plan.addresses;
    container->wormholes = plan.wormholes;
    container->whiteholes = plan.whiteholes;
    container->networkAccess = plan.networkAccess;
    container->assignedGPUMemoryMBs = plan.assignedGPUMemoryMBs;
    container->assignedGPUDevices = plan.assignedGPUDevices;
    container->fragment = plan.fragment;
    container->setMeshAddress(container_network_subnet6, brainConfig.datacenterFragment, machine->fragment, container->fragment);
    container->isStateful = plan.isStateful;
    container->shardGroup = plan.shardGroup;
    container->explicitStatefulMeshRoles = plan.statefulMeshRoles;
    container->explicitStatefulTopology = plan.statefulTopology;
    container->subscriptions = plan.subscriptions;
    container->advertisements = plan.advertisements;
    noteContainerCredentialBundleApplied(container, plan.hasCredentialBundle ? &plan.credentialBundle : nullptr);
    container->remainingSubscriberCapacity = deployment->plan.minimumSubscriberCapacity;

    if (mesh != nullptr)
    {
      for (const auto& [service, subscription] : container->subscriptions)
      {
        mesh->logSubscription(container, subscription.service, subscription.nature);
      }

      for (const auto& [service, advertisement] : container->advertisements)
      {
        mesh->logAdvertisement(container, advertisement.service);
        container->advertisingOnPorts.insert(advertisement.port);
      }

      for (const auto& [secret, pairings] : plan.advertisementPairings)
      {
        for (const AdvertisementPairing& pairing : pairings)
        {
          mesh->logAdvertisementPairing(pairing.secret, container, pairing);
          container->remainingSubscriberCapacity -= 1;
        }
      }

      for (const auto& [secret, pairings] : plan.subscriptionPairings)
      {
        for (const SubscriptionPairing& pairing : pairings)
        {
          mesh->logSubscriptionPairing(pairing.secret, container, pairing);
        }
      }
    }
  }

  bool applyReplicatedContainerRuntimeStateNow(const BrainReplicatedContainerRuntimeState& state)
  {
    uint64_t deploymentID = state.plan.config.deploymentID();
    auto deploymentIt = deployments.find(deploymentID);
    if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
    {
      return false;
    }

    Machine *machine = findMachineForReplicatedContainerRuntimeState(state);
    if (machine == nullptr)
    {
      return false;
    }

    ApplicationDeployment *deployment = deploymentIt->second;
    ContainerView *container = nullptr;
    bool created = false;
    if (auto existing = containers.find(state.plan.uuid); existing != containers.end())
    {
      container = existing->second;
    }
    else
    {
      container = new ContainerView();
      created = true;
    }

    detachContainerRuntimeState(container);

    bool uploadedRuntimeReady = state.plan.runtimeReady;
    ContainerPlan plan = state.plan;
    plan.runtimeReady = false;
    applyContainerRuntimePlanToView(container, machine, deployment, plan);
    container->runtime_nLogicalCores = state.runtimeLogicalCores;
    container->runtime_memoryMB = state.runtimeMemoryMB;
    container->runtime_storageMB = state.runtimeStorageMB;

    containers.insert_or_assign(container->uuid, container);
    machine->upsertContainerIndexEntry(container->deploymentID, container);
    deployment->containers.insert(container);
    if (deployment->plan.isStateful)
    {
      deployment->containersByShardGroup.insert(container->shardGroup, container);
    }

    if (uploadedRuntimeReady)
    {
      deployment->containerIsRuntimeReady(container);
    }

    if (weAreMaster)
    {
      deployment->recoverAfterReboot();
    }

    basics_log("brain replicated container runtime applied uuid=%llu deploymentID=%llu machinePrivate4=%u state=%u runtimeReady=%d created=%d master=%d\n",
               (unsigned long long)container->uuid,
               (unsigned long long)container->deploymentID,
               unsigned(machine->private4),
               unsigned(container->state),
               int(container->runtimeReady),
               int(created),
               int(weAreMaster));
    return true;
  }

  void applyPendingReplicatedContainerRuntimeStates(uint64_t deploymentID)
  {
    auto pendingIt = pendingReplicatedContainerRuntimeStates.find(deploymentID);
    if (pendingIt == pendingReplicatedContainerRuntimeStates.end())
    {
      return;
    }

    Vector<BrainReplicatedContainerRuntimeState> pending = std::move(pendingIt->second);
    pendingReplicatedContainerRuntimeStates.erase(pendingIt);

    for (const BrainReplicatedContainerRuntimeState& state : pending)
    {
      if (applyReplicatedContainerRuntimeStateNow(state) == false)
      {
        pendingReplicatedContainerRuntimeStates[state.plan.config.deploymentID()].push_back(state);
      }
    }
  }

  void applyReplicatedContainerRuntimeState(const BrainReplicatedContainerRuntimeState& state)
  {
    if (applyReplicatedContainerRuntimeStateNow(state))
    {
      persistLocalRuntimeState();
      return;
    }

    pendingReplicatedContainerRuntimeStates[state.plan.config.deploymentID()].push_back(state);
  }

  bool captureReplicatedContainerRuntimeState(ContainerView *container, BrainReplicatedContainerRuntimeState& state)
  {
    if (container == nullptr || container->machine == nullptr)
    {
      return false;
    }

    auto deploymentIt = deployments.find(container->deploymentID);
    if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
    {
      return false;
    }

    ApplicationDeployment *deployment = deploymentIt->second;
    ApplicationConfig replayConfig = deployment->resourceConfigForContainer(container);
    state = {};
    state.machineUUID = container->machine->uuid;
    state.machinePrivate4 = container->machine->private4;
    state.plan = container->generatePlan(deployment->plan, deployment->nShardGroups, &replayConfig);
    applyCredentialsToContainerPlan(deployment->plan, *container, state.plan);
    state.runtimeLogicalCores = container->runtime_nLogicalCores;
    state.runtimeMemoryMB = container->runtime_memoryMB;
    state.runtimeStorageMB = container->runtime_storageMB;
    return true;
  }

  void replicateContainerRuntimeStateToFollowers(ContainerView *container)
  {
    if (weAreMaster == false)
    {
      return;
    }

    BrainReplicatedContainerRuntimeState state = {};
    if (captureReplicatedContainerRuntimeState(container, state) == false)
    {
      return;
    }

    String serialized = {};
    BitseryEngine::serialize(serialized, state);
    queueBrainReplication(BrainTopic::replicateContainerRuntimeState, serialized);
  }

  bool publishDeploymentWormholeState(ApplicationDeployment *deployment)
  {
    if (deployment == nullptr)
    {
      return false;
    }

    deploymentPlans.insert_or_assign(deployment->plan.config.deploymentID(), deployment->plan);
    applyReplicatedDeploymentPlanLiveState(deployment->plan);

    for (ContainerView *container : deployment->containers)
    {
      if (container == nullptr)
      {
        continue;
      }

      container->wormholes = deployment->plan.wormholes;
      if (container->state != ContainerState::scheduled && container->state != ContainerState::healthy && container->state != ContainerState::crashedRestarting)
      {
        continue;
      }

      sendNeuronOpenSwitchboardWormholes(container, container->wormholes);
      sendNeuronRefreshContainerWormholes(container, container->wormholes);
    }

    String serializedPlan = {};
    BitseryEngine::serialize(serializedPlan, deployment->plan);
    if (nBrains > 1)
    {
      queueBrainDeploymentReplication(serializedPlan, ""_ctv);
    }

    persistLocalRuntimeState();
    return true;
  }

  bool refreshDeploymentRegisteredRoutablePrefixWormholes(ApplicationDeployment *deployment)
  {
    if (deployment == nullptr)
    {
      return false;
    }

    bool changed = false;
    for (Wormhole& wormhole : deployment->plan.wormholes)
    {
      if (wormhole.source != ExternalAddressSource::registeredRoutablePrefix || wormhole.routablePrefixUUID == 0)
      {
        continue;
      }

      IPAddress previousAddress = wormhole.externalAddress;
      String resolveFailure = {};
      RoutableResourceLeaseOwner owner = deployment->routableResourceLeaseOwner();
      if (resolveWormholeRegisteredRoutablePrefix(brainConfig.distributableExternalSubnets, wormhole, &resolveFailure, &routableResourceLeaseRuntimeState, &owner) == false)
      {
        continue;
      }

      if (previousAddress.equals(wormhole.externalAddress) == false)
      {
        changed = true;
      }
    }

    if (changed == false)
    {
      return false;
    }

    return publishDeploymentWormholeState(deployment);
  }

  void refreshAllDeploymentRegisteredRoutablePrefixWormholes(void)
  {
    if (weAreMaster == false)
    {
      return;
    }

    for (const auto& [deploymentID, deployment] : deployments)
    {
      (void)deploymentID;
      (void)refreshDeploymentRegisteredRoutablePrefixWormholes(deployment);
    }
  }

  bool refreshDeploymentWormholeQuicCidState(ApplicationDeployment *deployment, int64_t nowMs, bool allowRotation)
  {
    if (deployment == nullptr)
    {
      return false;
    }

    if (prepareDeploymentPlanWormholeQuicCidState(deployment->plan, nowMs) == false)
    {
      bool rotated = false;
      for (Wormhole& wormhole : deployment->plan.wormholes)
      {
        if (ensureWormholeQuicCidKeyState(wormhole, nowMs, allowRotation))
        {
          rotated = true;
        }
      }

      if (rotated == false)
      {
        return false;
      }
    }
    else
    {
      for (Wormhole& wormhole : deployment->plan.wormholes)
      {
        (void)ensureWormholeQuicCidKeyState(wormhole, nowMs, allowRotation);
      }
    }

    return publishDeploymentWormholeState(deployment);
  }

  void refreshAllDeploymentWormholeQuicCidState(bool allowRotation)
  {
    if (weAreMaster == false)
    {
      return;
    }

    int64_t nowMs = Time::now<TimeResolution::ms>();
    for (const auto& [deploymentID, deployment] : deployments)
    {
      (void)deploymentID;
      (void)refreshDeploymentWormholeQuicCidState(deployment, nowMs, allowRotation);
    }
  }

  static bool x509TimeToEpochMs(const ASN1_TIME *time, int64_t& epochMs)
  {
    epochMs = 0;
    if (time == nullptr)
    {
      return false;
    }

    std::tm tm = {};
    if (ASN1_TIME_to_tm(time, &tm) != 1)
    {
      return false;
    }

    time_t seconds = timegm(&tm);
    if (seconds < 0 || seconds > INT64_MAX / 1000)
    {
      return false;
    }
    epochMs = int64_t(seconds) * 1000;
    return true;
  }

  bool buildPrivateTlsVaultLifecycleState(const ApplicationTlsVaultFactory& factory, int64_t leafNotBeforeMs, PrivateTlsVaultLifecycleState& state, String *failure = nullptr) const
  {
    state = {};
    if (failure)
    {
      failure->clear();
    }

    X509 *rootCert = VaultPem::x509FromPem(factory.rootCertPem);
    X509 *intermediateCert = VaultPem::x509FromPem(factory.intermediateCertPem);
    bool ok = rootCert != nullptr && intermediateCert != nullptr &&
              x509TimeToEpochMs(X509_get0_notBefore(rootCert), state.rootNotBeforeMs) &&
              x509TimeToEpochMs(X509_get0_notAfter(rootCert), state.rootNotAfterMs) &&
              x509TimeToEpochMs(X509_get0_notBefore(intermediateCert), state.intermediateNotBeforeMs) &&
              x509TimeToEpochMs(X509_get0_notAfter(intermediateCert), state.intermediateNotAfterMs);
    if (rootCert)
    {
      X509_free(rootCert);
    }
    if (intermediateCert)
    {
      X509_free(intermediateCert);
    }
    if (ok == false)
    {
      if (failure)
      {
        failure->assign("failed to read tls vault certificate lifetimes"_ctv);
      }
      return false;
    }

    uint32_t leafValidityDays = privateTlsLeafValidityDays(factory);
    state.applicationID = factory.applicationID;
    state.factoryGeneration = factory.factoryGeneration;
    state.mode = factory.keySourceMode == 0 ? ProdigyCertificateLifecycleMode::managed : ProdigyCertificateLifecycleMode::externalManual;
    state.leafNotBeforeMs = leafNotBeforeMs;
    state.leafNotAfterMs = leafNotBeforeMs + int64_t(leafValidityDays) * 24 * 60 * 60 * 1000;
    int64_t rootRenewAtMs = privateTlsVaultRenewAtMs(factory, state.rootNotBeforeMs, state.rootNotAfterMs, 0xA11CE001ULL);
    int64_t intermediateRenewAtMs = privateTlsVaultRenewAtMs(factory, state.intermediateNotBeforeMs, state.intermediateNotAfterMs, 0xA11CE002ULL);
    state.leafNextRenewAtMs = privateTlsVaultRenewAtMs(factory, state.leafNotBeforeMs, state.leafNotAfterMs, 0xA11CE003ULL);
    state.nextRenewAtMs = prodigyEarliestPositiveMs(
        prodigyEarliestPositiveMs(rootRenewAtMs, intermediateRenewAtMs),
        state.leafNextRenewAtMs);
    return true;
  }

  uint32_t privateTlsLeafValidityDays(const ApplicationTlsVaultFactory& factory) const
  {
    uint32_t days = factory.defaultLeafValidityDays ? factory.defaultLeafValidityDays : 15;
    for (const auto& [deploymentID, deployment] : deployments)
    {
      (void)deploymentID;
      if (deployment == nullptr || deployment->plan.hasTlsIssuancePolicy == false)
      {
        continue;
      }
      const DeploymentTlsIssuancePolicy& policy = deployment->plan.tlsIssuancePolicy;
      if (policy.applicationID == factory.applicationID && policy.enablePerContainerLeafs && policy.identityNames.empty() == false && policy.leafValidityDays > 0 && policy.leafValidityDays < days)
      {
        days = policy.leafValidityDays;
      }
    }
    return days;
  }

  bool refreshPrivateTlsLeafSchedule(const ApplicationTlsVaultFactory& factory, PrivateTlsVaultLifecycleState& lifecycle)
  {
    int64_t leafNotAfterMs = lifecycle.leafNotBeforeMs + int64_t(privateTlsLeafValidityDays(factory)) * 24 * 60 * 60 * 1000;
    int64_t leafNextRenewAtMs = privateTlsVaultRenewAtMs(lifecycle, lifecycle.leafNotBeforeMs, leafNotAfterMs, 0xA11CE003ULL);
    if (leafNextRenewAtMs <= 0 || (lifecycle.leafNextRenewAtMs > 0 && leafNextRenewAtMs >= lifecycle.leafNextRenewAtMs))
    {
      return false;
    }
    lifecycle.leafNotAfterMs = leafNotAfterMs;
    lifecycle.leafNextRenewAtMs = leafNextRenewAtMs;
    lifecycle.nextRenewAtMs = prodigyEarliestPositiveMs(
        prodigyEarliestPositiveMs(
            privateTlsVaultRenewAtMs(lifecycle, lifecycle.rootNotBeforeMs, lifecycle.rootNotAfterMs, 0xA11CE001ULL),
            privateTlsVaultRenewAtMs(lifecycle, lifecycle.intermediateNotBeforeMs, lifecycle.intermediateNotAfterMs, 0xA11CE002ULL)),
        lifecycle.leafNextRenewAtMs);
    return true;
  }

  static bool generateManagedTlsVaultFactoryMaterial(ApplicationTlsVaultFactory& factory, String *failure = nullptr)
  {
    if (failure)
    {
      failure->clear();
    }

    X509 *rootCert = nullptr;
    EVP_PKEY *rootKey = nullptr;
    X509 *interCert = nullptr;
    EVP_PKEY *interKey = nullptr;

    CryptoScheme scheme = (factory.scheme == uint8_t(CryptoScheme::ed25519)) ? CryptoScheme::ed25519 : CryptoScheme::p256;
    VaultCertificateRequest rootRequest = {};
    rootRequest.type = CertificateType::root;
    rootRequest.scheme = scheme;
    generateCertificateAndKeys(rootRequest, nullptr, nullptr, rootCert, rootKey);

    VaultCertificateRequest intermediateRequest = {};
    intermediateRequest.type = CertificateType::intermediary;
    intermediateRequest.scheme = scheme;
    generateCertificateAndKeys(intermediateRequest, rootCert, rootKey, interCert, interKey);

    bool ok = rootCert != nullptr && rootKey != nullptr && interCert != nullptr && interKey != nullptr &&
              VaultPem::x509ToPem(rootCert, factory.rootCertPem) &&
              VaultPem::privateKeyToPem(rootKey, factory.rootKeyPem) &&
              VaultPem::x509ToPem(interCert, factory.intermediateCertPem) &&
              VaultPem::privateKeyToPem(interKey, factory.intermediateKeyPem);

    if (rootCert)
    {
      X509_free(rootCert);
    }
    if (rootKey)
    {
      EVP_PKEY_free(rootKey);
    }
    if (interCert)
    {
      X509_free(interCert);
    }
    if (interKey)
    {
      EVP_PKEY_free(interKey);
    }

    if (ok == false && failure)
    {
      failure->assign("failed to generate tls vault material"_ctv);
    }
    return ok;
  }

  bool upsertPrivateTlsVaultLifecycleState(const ApplicationTlsVaultFactory& factory, int64_t leafNotBeforeMs, String *failure = nullptr)
  {
    PrivateTlsVaultLifecycleState state = {};
    if (buildPrivateTlsVaultLifecycleState(factory, leafNotBeforeMs, state, failure) == false)
    {
      return false;
    }

    for (PrivateTlsVaultLifecycleState& existing : masterAuthorityRuntimeState.privateTlsVaultLifecycles)
    {
      if (existing.applicationID == state.applicationID)
      {
        existing = state;
        return true;
      }
    }
    masterAuthorityRuntimeState.privateTlsVaultLifecycles.push_back(state);
    return true;
  }

  bool validateApplicationTlsVaultFactoryMaterial(const ApplicationTlsVaultFactory& factory, String *failure = nullptr) const
  {
    if (failure)
    {
      failure->clear();
    }

    X509 *rootCert = VaultPem::x509FromPem(factory.rootCertPem);
    EVP_PKEY *rootKey = VaultPem::privateKeyFromPem(factory.rootKeyPem);
    X509 *intermediateCert = VaultPem::x509FromPem(factory.intermediateCertPem);
    EVP_PKEY *intermediateKey = VaultPem::privateKeyFromPem(factory.intermediateKeyPem);

    bool ok = (rootCert != nullptr) && (rootKey != nullptr) && (intermediateCert != nullptr) && (intermediateKey != nullptr);

    if (ok && X509_check_private_key(rootCert, rootKey) != 1)
    {
      ok = false;
      if (failure)
      {
        failure->assign("root certificate does not match root key"_ctv);
      }
    }

    if (ok && X509_check_private_key(intermediateCert, intermediateKey) != 1)
    {
      ok = false;
      if (failure)
      {
        failure->assign("intermediate certificate does not match intermediate key"_ctv);
      }
    }

    if (ok && X509_check_issued(rootCert, intermediateCert) != X509_V_OK)
    {
      ok = false;
      if (failure)
      {
        failure->assign("intermediate certificate is not issued by root certificate"_ctv);
      }
    }

    if (ok && X509_verify(intermediateCert, rootKey) != 1)
    {
      ok = false;
      if (failure)
      {
        failure->assign("intermediate certificate signature invalid for root key"_ctv);
      }
    }

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

    if (ok == false && failure && failure->size() == 0)
    {
      failure->assign("invalid tls vault factory material"_ctv);
    }

    return ok;
  }

  bool isApplicationIDReserved(uint16_t applicationID) const
  {
    return reservedApplicationNamesByID.find(applicationID) != reservedApplicationNamesByID.end();
  }

  bool validateDeploymentApplicationIdentity(const DeploymentPlan& plan, String& failure) const
  {
    (void)plan;
    failure.clear();
    return true;
  }

  static bool validateTaskDeploymentPlan(const DeploymentPlan& plan, String& failure)
  {
    failure.clear();
    if (plan.config.type != ApplicationType::task)
    {
      return true;
    }

    if (plan.config.taskExecutionPolicy != TaskExecutionPolicy::runOnce && plan.config.taskExecutionPolicy != TaskExecutionPolicy::untilSucceeded)
    {
      failure.assign("invalid plan: taskExecutionPolicy must be runOnce or untilSucceeded"_ctv);
      return false;
    }
    if (plan.isStateful)
    {
      failure.assign("invalid plan: task deployments cannot be stateful"_ctv);
      return false;
    }
    if (plan.stateless.nBase != 1)
    {
      failure.assign("invalid plan: task deployments require the normalized implicit single attempt"_ctv);
      return false;
    }
    if (plan.canaryCount > 0 || plan.canariesMustLiveForMinutes > 0)
    {
      failure.assign("invalid plan: task deployments cannot configure canaries"_ctv);
      return false;
    }
    if (plan.horizontalScalers.empty() == false || plan.verticalScalers.empty() == false)
    {
      failure.assign("invalid plan: task deployments cannot configure scalers"_ctv);
      return false;
    }
    if (plan.wormholes.empty() == false || plan.publicTLS.empty() == false || plan.advertisements.empty() == false)
    {
      failure.assign("invalid plan: task deployments cannot publish inbound services"_ctv);
      return false;
    }

    return true;
  }

  static bool computeTaskExecutionFingerprint(const DeploymentPlan& plan, String& fingerprint, String *failure = nullptr)
  {
    fingerprint.clear();
    if (failure)
    {
      failure->clear();
    }

    DeploymentPlan normalized = plan;
    String payload = {};
    BitseryEngine::serialize(payload, normalized);
    return prodigyComputeSHA256Hex(payload, fingerprint, failure);
  }

  static bool containsCredentialName(const Vector<String>& names, const String& target)
  {
    for (const String& name : names)
    {
      if (name.equals(target))
      {
        return true;
      }
    }

    return false;
  }

  const ApiCredential *findApiCredential(const ApplicationApiCredentialSet& set, const String& name) const
  {
    for (const ApiCredential& credential : set.credentials)
    {
      if (credential.name.equals(name))
      {
        return &credential;
      }
    }

    return nullptr;
  }

  const ApiCredential *findDNSCredential(uint16_t applicationID, const String& name) const
  {
    if (brainConfig.dnsCredential.name.size() > 0 && brainConfig.dnsCredential.name.equals(name))
    {
      return &brainConfig.dnsCredential;
    }
    auto setIt = apiCredentialSetsByApp.find(applicationID);
    return setIt == apiCredentialSetsByApp.end() ? nullptr : findApiCredential(setIt->second, name);
  }

  static bool apiCredentialMayReachContainer(const DeploymentPlan& plan, const ApiCredential& credential)
  {
    if (credential.metadata.find("dnsScope"_ctv) != credential.metadata.end() ||
        credential.metadata.find("dnsZones"_ctv) != credential.metadata.end() ||
        credential.metadata.find("dnsZone"_ctv) != credential.metadata.end() ||
        credential.metadata.find("dnsRecords"_ctv) != credential.metadata.end())
    {
      return false;
    }
    for (const Wormhole& wormhole : plan.wormholes)
    {
      if (wormhole.hasDNSConfig && credential.name.equals(wormhole.dns.credentialName))
      {
        return false;
      }
    }
    return true;
  }

  bool shouldAcceptTlsFactoryReplication(const ApplicationTlsVaultFactory& incoming, const ApplicationTlsVaultFactory *existing) const
  {
    if (incoming.applicationID == 0)
    {
      return false;
    }

    if (existing == nullptr)
    {
      return true;
    }

    if (incoming.factoryGeneration != existing->factoryGeneration)
    {
      return incoming.factoryGeneration > existing->factoryGeneration;
    }

    return incoming.updatedAtMs >= existing->updatedAtMs;
  }

  bool shouldAcceptApiCredentialSetReplication(const ApplicationApiCredentialSet& incoming, const ApplicationApiCredentialSet *existing) const
  {
    if (incoming.applicationID == 0)
    {
      return false;
    }

    if (existing == nullptr)
    {
      return true;
    }

    if (incoming.setGeneration != existing->setGeneration)
    {
      return incoming.setGeneration > existing->setGeneration;
    }

    return incoming.updatedAtMs >= existing->updatedAtMs;
  }

  bool buildTlsBundleForContainer(const DeploymentPlan& deploymentPlan, const ContainerView& container, CredentialBundle& bundle, uint64_t& bundleGeneration)
  {
    (void)container;
    const bool trace = deploymentPlan.hasTlsIssuancePolicy || deploymentPlan.hasApiCredentialPolicy || deploymentPlan.config.applicationID == 6;

    if (trace)
    {
      basics_log(
          "buildTlsBundleForContainer enter appID=%u hasTlsPolicy=%u tlsAppID=%u enablePerContainerLeafs=%u identityNames=%u existingTls=%u existingApi=%u\n",
          unsigned(deploymentPlan.config.applicationID),
          unsigned(deploymentPlan.hasTlsIssuancePolicy),
          unsigned(deploymentPlan.tlsIssuancePolicy.applicationID),
          unsigned(deploymentPlan.tlsIssuancePolicy.enablePerContainerLeafs),
          unsigned(deploymentPlan.tlsIssuancePolicy.identityNames.size()),
          unsigned(bundle.tlsIdentities.size()),
          unsigned(bundle.apiCredentials.size()));
    }

    if (deploymentPlan.hasTlsIssuancePolicy == false)
    {
      if (trace)
      {
        basics_log("buildTlsBundleForContainer skip appID=%u reason=no_tls_policy\n", unsigned(deploymentPlan.config.applicationID));
      }
      return false;
    }

    const DeploymentTlsIssuancePolicy& tlsPolicy = deploymentPlan.tlsIssuancePolicy;
    if (tlsPolicy.enablePerContainerLeafs == false || tlsPolicy.identityNames.size() == 0)
    {
      if (trace)
      {
        basics_log(
            "buildTlsBundleForContainer skip appID=%u reason=policy_non_issuable enablePerContainerLeafs=%u identityNames=%u\n",
            unsigned(deploymentPlan.config.applicationID),
            unsigned(tlsPolicy.enablePerContainerLeafs),
            unsigned(tlsPolicy.identityNames.size()));
      }
      return false;
    }

    auto factoryIt = tlsVaultFactoriesByApp.find(tlsPolicy.applicationID);
    if (factoryIt == tlsVaultFactoriesByApp.end())
    {
      if (trace)
      {
        basics_log(
            "buildTlsBundleForContainer skip appID=%u reason=factory_missing tlsAppID=%u\n",
            unsigned(deploymentPlan.config.applicationID),
            unsigned(tlsPolicy.applicationID));
      }
      return false;
    }

    const ApplicationTlsVaultFactory& factory = factoryIt->second;
    X509 *interCert = VaultPem::x509FromPem(factory.intermediateCertPem);
    EVP_PKEY *interKey = VaultPem::privateKeyFromPem(factory.intermediateKeyPem);
    if (interCert == nullptr || interKey == nullptr)
    {
      if (trace)
      {
        basics_log(
            "buildTlsBundleForContainer skip appID=%u reason=intermediate_parse_failed cert=%u key=%u factoryGeneration=%llu\n",
            unsigned(deploymentPlan.config.applicationID),
            unsigned(interCert != nullptr),
            unsigned(interKey != nullptr),
            (unsigned long long)factory.factoryGeneration);
      }
      if (interCert)
      {
        X509_free(interCert);
      }
      if (interKey)
      {
        EVP_PKEY_free(interKey);
      }
      return false;
    }

    const CryptoScheme scheme = (factory.scheme == uint8_t(CryptoScheme::ed25519)) ? CryptoScheme::ed25519 : CryptoScheme::p256;
    uint32_t validityDays = tlsPolicy.leafValidityDays > 0 ? tlsPolicy.leafValidityDays : factory.defaultLeafValidityDays;
    if (validityDays == 0)
    {
      validityDays = 15;
    }

    int64_t nowMs = Time::now<TimeResolution::ms>();
    bool produced = false;

    for (const String& identityName : tlsPolicy.identityNames)
    {
      if (identityName.size() == 0)
      {
        continue;
      }

      X509 *leafCert = nullptr;
      EVP_PKEY *leafKey = nullptr;
      VaultCertificateRequest request = {};
      request.type = CertificateType::server;
      request.scheme = scheme;
      request.subjectCommonName = identityName;
      request.enableServerAuth = true;
      generateCertificateAndKeys(request, interCert, interKey, leafCert, leafKey);
      if (leafCert == nullptr || leafKey == nullptr || brainAddCertificateSubjectAltNames(leafCert, tlsPolicy.dnsSans, tlsPolicy.ipSans) == false)
      {
        if (leafCert)
        {
          X509_free(leafCert);
        }
        if (leafKey)
        {
          EVP_PKEY_free(leafKey);
        }
        continue;
      }

      X509_gmtime_adj(X509_getm_notBefore(leafCert), 0);
      X509_time_adj_ex(X509_getm_notAfter(leafCert), int(validityDays), 0, nullptr);
      (void)X509_sign(leafCert, interKey, (scheme == CryptoScheme::ed25519) ? nullptr : EVP_sha256());

      TlsIdentity identity;
      identity.name.assign(identityName);
      identity.generation = factory.factoryGeneration;
      identity.notBeforeMs = nowMs;
      identity.notAfterMs = nowMs + int64_t(validityDays) * 24 * 60 * 60 * 1000;
      identity.dnsSans = tlsPolicy.dnsSans;
      identity.ipSans = tlsPolicy.ipSans;

      bool ok = VaultPem::x509ToPem(leafCert, identity.certPem) && VaultPem::privateKeyToPem(leafKey, identity.keyPem);
      if (ok)
      {
        identity.chainPem.assign(factory.intermediateCertPem);
        identity.chainPem.append(factory.rootCertPem);
        bundle.tlsIdentities.push_back(identity);
        produced = true;
      }

      if (leafCert)
      {
        X509_free(leafCert);
      }
      if (leafKey)
      {
        EVP_PKEY_free(leafKey);
      }
    }

    X509_free(interCert);
    EVP_PKEY_free(interKey);

    if (produced && factory.factoryGeneration > bundleGeneration)
    {
      bundleGeneration = factory.factoryGeneration;
    }

    if (trace)
    {
      basics_log(
          "buildTlsBundleForContainer done appID=%u produced=%u tlsIdentities=%u bundleGeneration=%llu factoryGeneration=%llu\n",
          unsigned(deploymentPlan.config.applicationID),
          unsigned(produced),
          unsigned(bundle.tlsIdentities.size()),
          (unsigned long long)bundleGeneration,
          (unsigned long long)factory.factoryGeneration);
    }

    return produced;
  }

  bool buildPublicTlsBundleForContainer(const DeploymentPlan& deploymentPlan, CredentialBundle& bundle, uint64_t& bundleGeneration) const
  {
    bool produced = false;
    for (const PublicTlsCertificateState& certificate : masterAuthorityRuntimeState.publicTlsCertificates)
    {
      if (publicTlsCertificateMatchesDeployment(deploymentPlan, certificate) == false ||
          certificate.identity.certPem.size() == 0 ||
          certificate.identity.keyPem.size() == 0)
      {
        continue;
      }
      bundle.tlsIdentities.push_back(certificate.identity);
      produced = true;
      if (certificate.identity.generation > bundleGeneration)
      {
        bundleGeneration = certificate.identity.generation;
      }
    }
    return produced;
  }

  static String tlsResumptionRegistryKey(uint64_t deploymentID, const String& wormholeName)
  {
    String key = {};
    key.snprintf<"{itoa}:"_ctv>(deploymentID);
    key.append(wormholeName);
    return key;
  }

  static bool tlsResumptionParseRegistryKey(const String& key, uint64_t& deploymentID, String& wormholeName)
  {
    uint64_t parsedDeploymentID = 0;
    uint32_t index = 0;
    for (; index < key.size(); index += 1)
    {
      uint8_t byte = key.data()[index];
      if (byte == ':')
      {
        break;
      }
      if (byte < '0' || byte > '9' || parsedDeploymentID > (UINT64_MAX - uint64_t(byte - '0')) / 10)
      {
        return false;
      }
      parsedDeploymentID = (parsedDeploymentID * 10) + uint64_t(byte - '0');
    }

    if (index == 0 || index >= key.size() || key.data()[index] != ':')
    {
      return false;
    }

    deploymentID = parsedDeploymentID;
    wormholeName.assign(reinterpret_cast<const char *>(key.data() + index + 1), uint64_t(key.size() - index - 1));
    return wormholeName.size() > 0;
  }

  static bool tlsResumptionSnapshotMatchesWormhole(const TlsResumptionSnapshot& snapshot, const Wormhole& wormhole)
  {
    return wormhole.hasTlsResumptionConfig &&
           snapshot.wormholeName.equal(wormhole.name) &&
           snapshot.keyRing.size() > 0;
  }

  static uint8_t tlsResumptionNextEpochPhase(const TlsResumptionSnapshot& snapshot)
  {
    for (const TlsResumptionKeyEpoch& epoch : snapshot.keyRing)
    {
      if (epoch.generation == snapshot.generation)
      {
        return prodigyTlsResumptionEpochPhase(epoch) ^ 0x01u;
      }
    }

    return 0;
  }

  void mintTlsResumptionEpoch(TlsResumptionKeyEpoch& epoch, uint64_t generation, int64_t nowMs, uint8_t phase)
  {
    epoch = TlsResumptionKeyEpoch();
    epoch.generation = generation;
    epoch.role = TlsResumptionKeyRole::acceptOnly;
    Crypto::fillWithSecureRandomBytes(epoch.keyID, sizeof(epoch.keyID));
    Crypto::fillWithSecureRandomBytes(epoch.masterSecret, sizeof(epoch.masterSecret));
    prodigyTlsResumptionForceEpochPhase(epoch, phase);
    const int64_t baseMs = nowMs > 0 ? nowMs : 0;
    epoch.issueUntilMs = 0;
    uint64_t acceptWindowMs = prodigyTlsResumptionTicketLifetimeMs;
    if (UINT64_MAX - acceptWindowMs < prodigyTlsResumptionOverlapMs)
    {
      acceptWindowMs = UINT64_MAX;
    }
    else
    {
      acceptWindowMs += prodigyTlsResumptionOverlapMs;
    }

    if (acceptWindowMs > uint64_t(INT64_MAX - baseMs))
    {
      epoch.acceptUntilMs = INT64_MAX;
    }
    else
    {
      epoch.acceptUntilMs = baseMs + int64_t(acceptWindowMs);
    }
  }

  const TlsResumptionSnapshot *ensureTlsResumptionSnapshotForWormhole(const DeploymentPlan& deploymentPlan, const Wormhole& wormhole, int64_t nowMs)
  {
    if (wormhole.hasTlsResumptionConfig == false || wormhole.name.size() == 0)
    {
      return nullptr;
    }

    if (wormholeSupportsTlsResumption(wormhole) == false)
    {
      return nullptr;
    }

    const uint64_t deploymentID = deploymentPlan.config.deploymentID();
    auto& deploymentState = tlsResumptionStateByDeployment[deploymentID];
    if (auto existing = deploymentState.wormholes.find(wormhole.name); existing != deploymentState.wormholes.end())
    {
      if (tlsResumptionSnapshotMatchesWormhole(existing->second.snapshot, wormhole))
      {
        return &existing->second.snapshot;
      }
    }

    uint64_t generation = mintNextTlsResumptionGeneration();

    TlsResumptionSnapshot snapshot = {};
    snapshot.generation = generation;
    snapshot.wormholeName = wormhole.name;

    TlsResumptionKeyEpoch epoch = {};
    mintTlsResumptionEpoch(epoch, generation, nowMs, 0);
    snapshot.keyRing.push_back(epoch);

    BrainTlsResumptionWormholeState state = {};
    state.snapshot = std::move(snapshot);
    deploymentState.wormholes.insert_or_assign(wormhole.name, std::move(state));
    auto it = deploymentState.wormholes.find(wormhole.name);
    if (it == deploymentState.wormholes.end())
    {
      return nullptr;
    }

    noteMasterAuthorityRuntimeStateChanged();
    return &it->second.snapshot;
  }

  uint64_t mintNextTlsResumptionGeneration(uint64_t floorGeneration = 0)
  {
    if (nextTlsResumptionGeneration <= floorGeneration)
    {
      nextTlsResumptionGeneration = (floorGeneration == UINT64_MAX) ? 1 : floorGeneration + 1;
    }
    if (nextTlsResumptionGeneration == 0)
    {
      nextTlsResumptionGeneration = 1;
    }

    uint64_t generation = nextTlsResumptionGeneration++;
    if (nextTlsResumptionGeneration == 0)
    {
      nextTlsResumptionGeneration = 1;
    }
    return generation;
  }

  BrainTlsResumptionWormholeState *mutableTlsResumptionStateForWormhole(uint64_t deploymentID, const String& wormholeName)
  {
    auto deploymentIt = tlsResumptionStateByDeployment.find(deploymentID);
    if (deploymentIt == tlsResumptionStateByDeployment.end())
    {
      return nullptr;
    }

    auto it = deploymentIt->second.wormholes.find(wormholeName);
    return it == deploymentIt->second.wormholes.end() ? nullptr : &it->second;
  }

  const BrainTlsResumptionWormholeState *tlsResumptionStateForWormhole(uint64_t deploymentID, const String& wormholeName) const
  {
    auto deploymentIt = tlsResumptionStateByDeployment.find(deploymentID);
    if (deploymentIt == tlsResumptionStateByDeployment.end())
    {
      return nullptr;
    }

    auto it = deploymentIt->second.wormholes.find(wormholeName);
    return it == deploymentIt->second.wormholes.end() ? nullptr : &it->second;
  }

  TlsResumptionSnapshot *mutableTlsResumptionSnapshotForWormhole(uint64_t deploymentID, const String& wormholeName)
  {
    BrainTlsResumptionWormholeState *state = mutableTlsResumptionStateForWormhole(deploymentID, wormholeName);
    return state == nullptr ? nullptr : &state->snapshot;
  }

  const TlsResumptionSnapshot *tlsResumptionSnapshotForWormhole(uint64_t deploymentID, const String& wormholeName) const
  {
    const BrainTlsResumptionWormholeState *state = tlsResumptionStateForWormhole(deploymentID, wormholeName);
    return state == nullptr ? nullptr : &state->snapshot;
  }

  void clearTlsResumptionAcksForWormhole(uint64_t deploymentID, const String& wormholeName)
  {
    BrainTlsResumptionWormholeState *state = mutableTlsResumptionStateForWormhole(deploymentID, wormholeName);
    if (state != nullptr)
    {
      state->acksByContainer.clear();
    }
  }

  bool recordTlsResumptionApplyResult(uint128_t containerUUID, const TlsResumptionApplyResult& result)
  {
    auto containerIt = containers.find(containerUUID);
    if (containerIt == containers.end() || containerIt->second == nullptr || result.wormholeName.size() == 0)
    {
      return false;
    }

    ContainerView *container = containerIt->second;
    const uint64_t deploymentID = container->deploymentID;
    BrainTlsResumptionWormholeState *state = mutableTlsResumptionStateForWormhole(deploymentID, result.wormholeName);
    if (state == nullptr)
    {
      return false;
    }

    if (result.generation != state->snapshot.generation)
    {
      return false;
    }

    BrainTlsResumptionAckState ack = {};
    ack.generation = result.generation;
    ack.success = result.success;
    ack.failureReason = result.failureReason;
    state->acksByContainer.insert_or_assign(containerUUID, std::move(ack));
    return true;
  }

  bool recordTlsResumptionApplyAck(uint128_t containerUUID, const TlsResumptionApplyAck& result)
  {
    bool recordedAny = false;
    for (const TlsResumptionApplyResult& resumptionResult : result.results)
    {
      recordedAny = recordTlsResumptionApplyResult(containerUUID, resumptionResult) || recordedAny;
    }

    return recordedAny;
  }

  static bool containerCanServeResumedTlsTraffic(const ContainerView& container)
  {
    return container.state == ContainerState::healthy;
  }

  bool tlsResumptionAckCoverageSatisfied(const DeploymentPlan& deploymentPlan, const Wormhole& wormhole, String *failure = nullptr) const
  {
    if (failure)
    {
      failure->clear();
    }

    if (wormhole.hasTlsResumptionConfig == false || wormhole.name.size() == 0)
    {
      if (failure)
      {
        failure->assign("resumption-enabled wormhole required"_ctv);
      }
      return false;
    }

    const uint64_t deploymentID = deploymentPlan.config.deploymentID();
    const BrainTlsResumptionWormholeState *state = tlsResumptionStateForWormhole(deploymentID, wormhole.name);
    if (state == nullptr)
    {
      if (failure)
      {
        failure->assign("resumption snapshot missing"_ctv);
      }
      return false;
    }
    const TlsResumptionSnapshot& snapshot = state->snapshot;

    auto deploymentIt = deployments.find(deploymentID);
    if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
    {
      if (failure)
      {
        failure->assign("resumption deployment missing"_ctv);
      }
      return false;
    }

    bool sawServingContainer = false;
    for (ContainerView *container : deploymentIt->second->containers)
    {
      if (container == nullptr || containerCanServeResumedTlsTraffic(*container) == false)
      {
        continue;
      }

      sawServingContainer = true;
      auto ackIt = state->acksByContainer.find(container->uuid);
      if (ackIt == state->acksByContainer.end())
      {
        if (failure)
        {
          failure->snprintf<"missing resumption ACK for traffic-serving container {}"_ctv>(String::toHex(container->uuid));
        }
        return false;
      }

      const BrainTlsResumptionAckState& ack = ackIt->second;
      if (ack.generation != snapshot.generation || ack.success == false)
      {
        if (failure)
        {
          failure->snprintf<"resumption ACK not successful for container {}"_ctv>(String::toHex(container->uuid));
        }
        return false;
      }
    }

    if (sawServingContainer == false)
    {
      if (failure)
      {
        failure->assign("no traffic-serving resumption containers"_ctv);
      }
      return false;
    }

    return true;
  }

  static uint64_t containerCredentialBundleGeneration(const ContainerView *container)
  {
    uint64_t generation = 0;
    if (container != nullptr && container->hasCredentialBundle)
    {
      generation = container->credentialBundle.bundleGeneration;
    }
    if (container != nullptr && container->hasPendingCredentialBundle && container->pendingCredentialBundle.bundleGeneration > generation)
    {
      generation = container->pendingCredentialBundle.bundleGeneration;
    }
    return generation;
  }

  bool pushCredentialDeltaToContainer(ContainerView *container, CredentialDelta delta)
  {
    if (container == nullptr)
    {
      return false;
    }
    delta.bundleGeneration = std::max(delta.bundleGeneration, containerCredentialBundleGeneration(container));
    String serializedDelta = {};
    if (ProdigyWire::serializeCredentialDelta(serializedDelta, delta) == false)
    {
      return false;
    }
    if (container->canProxySendToNeuron())
    {
      noteContainerCredentialDeltaPending(container, delta);
    }
    container->proxySend(NeuronTopic::refreshContainerCredentials, container->uuid, serializedDelta);
    return true;
  }

  uint32_t pushCredentialDeltaToLiveContainers(const DeploymentPlan& deploymentPlan, const CredentialDelta& delta)
  {
    uint32_t eligibleContainers = 0;
    auto deploymentIt = deployments.find(deploymentPlan.config.deploymentID());
    if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
    {
      return 0;
    }

    for (ContainerView *container : deploymentIt->second->containers)
    {
      if (container == nullptr)
      {
        continue;
      }

      switch (container->state)
      {
        case ContainerState::scheduled:
        case ContainerState::healthy:
        case ContainerState::crashedRestarting:
          {
            eligibleContainers += pushCredentialDeltaToContainer(container, delta) ? 1 : 0;
            break;
          }
        default:
          break;
      }
    }

    return eligibleContainers;
  }

  uint32_t pushTlsResumptionUpdateToLiveContainers(const DeploymentPlan& deploymentPlan, const TlsResumptionSnapshot *snapshot, const String *removedWormholeName, uint64_t generation, const String& reason)
  {
    CredentialDelta delta = {};
    delta.bundleGeneration = generation;
    if (snapshot != nullptr)
    {
      delta.bundleGeneration = snapshot->generation;
      delta.updatedResumptionSnapshots.push_back(*snapshot);
    }
    if (removedWormholeName != nullptr && removedWormholeName->size() > 0)
    {
      delta.removedResumptionWormholeNames.push_back(*removedWormholeName);
    }
    delta.reason = reason;
    return pushCredentialDeltaToLiveContainers(deploymentPlan, delta);
  }

  static bool deploymentPlanEnablesTlsResumptionWormhole(const DeploymentPlan& deploymentPlan, const String& wormholeName)
  {
    if (wormholeName.size() == 0)
    {
      return false;
    }

    for (const Wormhole& wormhole : deploymentPlan.wormholes)
    {
      if (wormhole.name.equal(wormholeName) &&
          wormhole.hasTlsResumptionConfig)
      {
        return true;
      }
    }

    return false;
  }

  bool removeTlsResumptionStateForWormhole(uint64_t deploymentID, const String& wormholeName, bool noteChanged = true)
  {
    if (wormholeName.size() == 0)
    {
      return false;
    }

    auto deploymentIt = tlsResumptionStateByDeployment.find(deploymentID);
    if (deploymentIt == tlsResumptionStateByDeployment.end())
    {
      return false;
    }

    auto it = deploymentIt->second.wormholes.find(wormholeName);
    if (it == deploymentIt->second.wormholes.end())
    {
      return false;
    }

    deploymentIt->second.wormholes.erase(it);
    if (deploymentIt->second.wormholes.empty())
    {
      tlsResumptionStateByDeployment.erase(deploymentIt);
    }
    if (noteChanged)
    {
      noteMasterAuthorityRuntimeStateChanged();
    }
    return true;
  }

  uint32_t removeTlsResumptionStateForDeployment(uint64_t deploymentID, bool noteChanged = true)
  {
    auto deploymentIt = tlsResumptionStateByDeployment.find(deploymentID);
    if (deploymentIt == tlsResumptionStateByDeployment.end())
    {
      return 0;
    }

    uint32_t removed = uint32_t(deploymentIt->second.wormholes.size());
    tlsResumptionStateByDeployment.erase(deploymentIt);

    if (removed > 0 && noteChanged)
    {
      noteMasterAuthorityRuntimeStateChanged();
    }
    return removed;
  }

  uint32_t removeTlsResumptionStateNotEnabledByPlan(const DeploymentPlan& deploymentPlan, bool pushDelta = true)
  {
    const uint64_t deploymentID = deploymentPlan.config.deploymentID();
    Vector<String> wormholesToRemove = {};
    Vector<uint64_t> generationsToRemove = {};

    auto deploymentIt = tlsResumptionStateByDeployment.find(deploymentID);
    if (deploymentIt == tlsResumptionStateByDeployment.end())
    {
      return 0;
    }

    for (const auto& [wormholeName, state] : deploymentIt->second.wormholes)
    {
      const TlsResumptionSnapshot& snapshot = state.snapshot;
      if (deploymentPlanEnablesTlsResumptionWormhole(deploymentPlan, wormholeName))
      {
        continue;
      }

      wormholesToRemove.push_back(wormholeName);
      generationsToRemove.push_back(snapshot.generation);
    }

    uint32_t removed = 0;
    for (uint32_t index = 0; index < wormholesToRemove.size(); index += 1)
    {
      const String& wormholeName = wormholesToRemove[index];
      if (pushDelta)
      {
        pushTlsResumptionUpdateToLiveContainers(deploymentPlan, nullptr, &wormholeName, generationsToRemove[index], "tls-resumption-policy-disabled-or-removed"_ctv);
      }
      if (removeTlsResumptionStateForWormhole(deploymentID, wormholeName, false))
      {
        removed += 1;
      }
    }

    if (removed > 0)
    {
      noteMasterAuthorityRuntimeStateChanged();
    }
    return removed;
  }

  TlsResumptionSnapshot *beginTlsResumptionAcceptOnlyRollout(const DeploymentPlan& deploymentPlan, const Wormhole& wormhole, int64_t nowMs, bool pushDelta = true, String *failure = nullptr)
  {
    if (failure)
    {
      failure->clear();
    }

    const TlsResumptionSnapshot *ensured = ensureTlsResumptionSnapshotForWormhole(deploymentPlan, wormhole, nowMs);
    if (ensured == nullptr)
    {
      if (failure)
      {
        failure->assign("failed to ensure resumption snapshot"_ctv);
      }
      return nullptr;
    }

    const uint64_t deploymentID = deploymentPlan.config.deploymentID();
    TlsResumptionSnapshot *snapshot = mutableTlsResumptionSnapshotForWormhole(deploymentID, wormhole.name);
    if (snapshot == nullptr)
    {
      if (failure)
      {
        failure->assign("resumption snapshot missing after ensure"_ctv);
      }
      return nullptr;
    }

    for (const TlsResumptionKeyEpoch& epoch : snapshot->keyRing)
    {
      if (epoch.generation == snapshot->generation && epoch.role == TlsResumptionKeyRole::acceptOnly)
      {
        if (pushDelta)
        {
          pushTlsResumptionUpdateToLiveContainers(deploymentPlan, snapshot, nullptr, snapshot->generation, "tls-resumption-accept-only-rollout"_ctv);
        }
        return snapshot;
      }
    }

    uint64_t generation = mintNextTlsResumptionGeneration(snapshot->generation);

    TlsResumptionKeyEpoch epoch = {};
    mintTlsResumptionEpoch(epoch, generation, nowMs, tlsResumptionNextEpochPhase(*snapshot));
    snapshot->generation = generation;
    snapshot->keyRing.push_back(epoch);

    clearTlsResumptionAcksForWormhole(deploymentID, wormhole.name);

    noteMasterAuthorityRuntimeStateChanged();
    if (pushDelta)
    {
      pushTlsResumptionUpdateToLiveContainers(deploymentPlan, snapshot, nullptr, snapshot->generation, "tls-resumption-accept-only-rollout"_ctv);
    }
    return snapshot;
  }

  bool promoteTlsResumptionIssueEpochIfAcked(const DeploymentPlan& deploymentPlan, const Wormhole& wormhole, int64_t nowMs, bool pushDelta = true, String *failure = nullptr)
  {
    if (tlsResumptionAckCoverageSatisfied(deploymentPlan, wormhole, failure) == false)
    {
      return false;
    }

    TlsResumptionSnapshot *snapshot = mutableTlsResumptionSnapshotForWormhole(deploymentPlan.config.deploymentID(), wormhole.name);
    if (snapshot == nullptr)
    {
      if (failure)
      {
        failure->assign("resumption snapshot missing"_ctv);
      }
      return false;
    }

    bool changed = false;
    int64_t issueUntilMs = nowMs;
    if (prodigyTlsResumptionRotationPeriodMs > uint64_t(INT64_MAX - issueUntilMs))
    {
      issueUntilMs = INT64_MAX;
    }
    else
    {
      issueUntilMs += int64_t(prodigyTlsResumptionRotationPeriodMs);
    }

    for (TlsResumptionKeyEpoch& epoch : snapshot->keyRing)
    {
      if (epoch.generation == snapshot->generation)
      {
        if (epoch.role != TlsResumptionKeyRole::issueAndAccept || epoch.issueUntilMs != issueUntilMs)
        {
          epoch.role = TlsResumptionKeyRole::issueAndAccept;
          epoch.issueUntilMs = issueUntilMs;
          changed = true;
        }
      }
      else if (epoch.role == TlsResumptionKeyRole::issueAndAccept)
      {
        epoch.role = TlsResumptionKeyRole::acceptOnly;
        epoch.issueUntilMs = 0;
        changed = true;
      }
    }

    if (changed == false)
    {
      return false;
    }

    noteMasterAuthorityRuntimeStateChanged();
    if (pushDelta)
    {
      pushTlsResumptionUpdateToLiveContainers(deploymentPlan, snapshot, nullptr, snapshot->generation, "tls-resumption-issue-promotion"_ctv);
    }
    return true;
  }

  static bool tlsResumptionIssueWindowExpired(const TlsResumptionSnapshot& snapshot, int64_t nowMs)
  {
    if (nowMs <= 0)
    {
      return false;
    }

    for (const TlsResumptionKeyEpoch& epoch : snapshot.keyRing)
    {
      if (epoch.generation == snapshot.generation &&
          epoch.role == TlsResumptionKeyRole::issueAndAccept &&
          epoch.issueUntilMs > 0 &&
          epoch.issueUntilMs <= nowMs)
      {
        return true;
      }
    }

    return false;
  }

  uint32_t retireExpiredTlsResumptionEpochs(const DeploymentPlan& deploymentPlan, int64_t nowMs, bool pushDelta = true)
  {
    if (nowMs <= 0)
    {
      return 0;
    }

    uint32_t retired = 0;
    const uint64_t deploymentID = deploymentPlan.config.deploymentID();
    for (const Wormhole& wormhole : deploymentPlan.wormholes)
    {
      if (wormhole.hasTlsResumptionConfig == false || wormhole.name.size() == 0)
      {
        continue;
      }

      TlsResumptionSnapshot *snapshot = mutableTlsResumptionSnapshotForWormhole(deploymentID, wormhole.name);
      if (snapshot == nullptr || snapshot->keyRing.empty())
      {
        continue;
      }

      const uint32_t before = uint32_t(snapshot->keyRing.size());
      const uint8_t nextPhase = tlsResumptionNextEpochPhase(*snapshot);
      auto firstExpired = std::remove_if(snapshot->keyRing.begin(), snapshot->keyRing.end(), [&](const TlsResumptionKeyEpoch& epoch) {
        return epoch.acceptUntilMs > 0 && epoch.acceptUntilMs <= nowMs;
      });
      if (firstExpired == snapshot->keyRing.end())
      {
        continue;
      }

      snapshot->keyRing.erase(firstExpired, snapshot->keyRing.end());
      retired += before - uint32_t(snapshot->keyRing.size());
      if (snapshot->keyRing.empty())
      {
        const uint64_t generation = mintNextTlsResumptionGeneration(snapshot->generation);

        TlsResumptionKeyEpoch epoch = {};
        mintTlsResumptionEpoch(epoch, generation, nowMs, nextPhase);
        snapshot->generation = generation;
        snapshot->keyRing.push_back(epoch);
        clearTlsResumptionAcksForWormhole(deploymentID, wormhole.name);
      }

      noteMasterAuthorityRuntimeStateChanged();
      if (pushDelta)
      {
        pushTlsResumptionUpdateToLiveContainers(deploymentPlan, snapshot, nullptr, snapshot->generation, "tls-resumption-expired-epoch-retire"_ctv);
      }
    }

    return retired;
  }

  uint32_t advanceTlsResumptionLifecycleForDeployment(const DeploymentPlan& deploymentPlan, int64_t nowMs, bool allowRotation, bool pushDelta = true)
  {
    if (nowMs <= 0)
    {
      return 0;
    }

    uint32_t advanced = 0;
    const uint64_t deploymentID = deploymentPlan.config.deploymentID();
    if (allowRotation)
    {
      advanced += retireExpiredTlsResumptionEpochs(deploymentPlan, nowMs, pushDelta);
    }

    for (const Wormhole& wormhole : deploymentPlan.wormholes)
    {
      if (wormhole.hasTlsResumptionConfig == false || wormhole.name.size() == 0)
      {
        continue;
      }

      const bool hadSnapshot = tlsResumptionSnapshotForWormhole(deploymentID, wormhole.name) != nullptr;
      const TlsResumptionSnapshot *snapshot = ensureTlsResumptionSnapshotForWormhole(deploymentPlan, wormhole, nowMs);
      if (snapshot == nullptr)
      {
        continue;
      }

      if (hadSnapshot == false)
      {
        advanced += 1;
        if (pushDelta)
        {
          pushTlsResumptionUpdateToLiveContainers(deploymentPlan, snapshot, nullptr, snapshot->generation, "tls-resumption-initial-snapshot"_ctv);
        }
      }

      if (allowRotation && tlsResumptionIssueWindowExpired(*snapshot, nowMs))
      {
        const uint64_t previousGeneration = snapshot->generation;
        String failure = {};
        TlsResumptionSnapshot *next = beginTlsResumptionAcceptOnlyRollout(deploymentPlan, wormhole, nowMs, pushDelta, &failure);
        if (next != nullptr && next->generation != previousGeneration)
        {
          advanced += 1;
        }
      }

      String failure = {};
      if (promoteTlsResumptionIssueEpochIfAcked(deploymentPlan, wormhole, nowMs, pushDelta, &failure))
      {
        advanced += 1;
      }
    }

    return advanced;
  }

  uint32_t advanceAllDeploymentTlsResumptionLifecycles(bool allowRotation, bool pushDelta = true)
  {
    if (weAreMaster == false)
    {
      return 0;
    }

    uint32_t advanced = 0;
    const int64_t nowMs = Time::now<TimeResolution::ms>();
    for (const auto& [deploymentID, deployment] : deployments)
    {
      (void)deploymentID;
      if (deployment == nullptr)
      {
        continue;
      }
      advanced += advanceTlsResumptionLifecycleForDeployment(deployment->plan, nowMs, allowRotation, pushDelta);
    }
    return advanced;
  }

  bool buildTlsResumptionSnapshotsForContainer(const DeploymentPlan& deploymentPlan, const ContainerView& container, CredentialBundle& bundle, uint64_t& bundleGeneration)
  {
    (void)container;
    bool produced = false;
    const int64_t nowMs = Time::now<TimeResolution::ms>();

    for (const Wormhole& wormhole : deploymentPlan.wormholes)
    {
      const TlsResumptionSnapshot *snapshot = ensureTlsResumptionSnapshotForWormhole(deploymentPlan, wormhole, nowMs);
      if (snapshot == nullptr)
      {
        continue;
      }

      bundle.tlsResumptionSnapshots.push_back(*snapshot);
      if (snapshot->generation > bundleGeneration)
      {
        bundleGeneration = snapshot->generation;
      }
      produced = true;
    }

    return produced;
  }

  bool buildCredentialBundleForContainer(const DeploymentPlan& deploymentPlan, const ContainerView& container, CredentialBundle& bundle)
  {
    bundle.tlsIdentities.clear();
    bundle.apiCredentials.clear();
    bundle.tlsResumptionSnapshots.clear();
    bundle.bundleGeneration = 0;

    bool produced = false;
    uint64_t bundleGeneration = 0;

    if (deploymentPlan.hasApiCredentialPolicy)
    {
      const DeploymentApiCredentialPolicy& apiPolicy = deploymentPlan.apiCredentialPolicy;
      if (auto setIt = apiCredentialSetsByApp.find(apiPolicy.applicationID); setIt != apiCredentialSetsByApp.end())
      {
        const ApplicationApiCredentialSet& set = setIt->second;
        for (const String& requiredName : apiPolicy.requiredCredentialNames)
        {
          if (const ApiCredential *credential = findApiCredential(set, requiredName); credential != nullptr)
          {
            if (apiCredentialMayReachContainer(deploymentPlan, *credential))
            {
              bundle.apiCredentials.push_back(*credential);
              produced = true;
            }
          }
        }

        if (set.setGeneration > bundleGeneration)
        {
          bundleGeneration = set.setGeneration;
        }
      }
    }

    if (buildTlsBundleForContainer(deploymentPlan, container, bundle, bundleGeneration))
    {
      produced = true;
    }

    if (buildPublicTlsBundleForContainer(deploymentPlan, bundle, bundleGeneration))
    {
      produced = true;
    }

    if (buildTlsResumptionSnapshotsForContainer(deploymentPlan, container, bundle, bundleGeneration))
    {
      produced = true;
    }

    bundle.bundleGeneration = produced ? bundleGeneration : 0;
    return produced;
  }

  void applyCredentialsToContainerPlan(const DeploymentPlan& deploymentPlan, const ContainerView& container, ContainerPlan& plan) override
  {
    CredentialBundle bundle;
    if (buildCredentialBundleForContainer(deploymentPlan, container, bundle))
    {
      plan.hasCredentialBundle = true;
      plan.credentialBundle = std::move(bundle);
    }
    else
    {
      plan.hasCredentialBundle = false;
      plan.credentialBundle = CredentialBundle();
    }
  }

  bool containerTlsIdentitiesFresh(const DeploymentPlan& deploymentPlan, const ContainerView& container, bool *pending = nullptr, String *failure = nullptr)
  {
    if (pending)
    {
      *pending = false;
    }
    if (failure)
    {
      failure->clear();
    }

    CredentialBundle expected = {};
    if (buildCredentialBundleForContainer(deploymentPlan, container, expected) == false || expected.tlsIdentities.empty())
    {
      return true;
    }

    for (const TlsIdentity& identity : expected.tlsIdentities)
    {
      bool fresh = container.hasCredentialBundle && credentialBundleHasTlsIdentityGeneration(container.credentialBundle, identity.name, identity.generation);
      if (fresh)
      {
        continue;
      }
      if (pending && container.hasPendingCredentialBundle &&
          (container.pendingCredentialBundleSinceMs <= 0 || Time::now<TimeResolution::ms>() - container.pendingCredentialBundleSinceMs < credentialDeltaAckTimeoutMs) &&
          credentialBundleHasTlsIdentityGeneration(container.pendingCredentialBundle, identity.name, identity.generation))
      {
        *pending = true;
      }
      if (failure)
      {
        failure->snprintf<"container {} is missing TLS identity {} generation {itoa}"_ctv>(String::toHex(container.uuid), identity.name, identity.generation);
      }
      return false;
    }

    return true;
  }

  bool tlsIdentityCoverageSatisfied(const DeploymentPlan& deploymentPlan, String *failure = nullptr)
  {
    if (failure)
    {
      failure->clear();
    }
    auto deploymentIt = deployments.find(deploymentPlan.config.deploymentID());
    if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
    {
      if (failure)
      {
        failure->assign("TLS identity deployment missing"_ctv);
      }
      return false;
    }

    bool sawExpected = false;
    for (ContainerView *container : deploymentIt->second->containers)
    {
      if (container == nullptr || container->state != ContainerState::healthy)
      {
        continue;
      }
      CredentialBundle expected = {};
      if (buildCredentialBundleForContainer(deploymentPlan, *container, expected) == false || expected.tlsIdentities.empty())
      {
        continue;
      }
      sawExpected = true;
      if (containerTlsIdentitiesFresh(deploymentPlan, *container, nullptr, failure) == false)
      {
        return false;
      }
    }

    if (sawExpected == false && (deploymentPlan.hasTlsIssuancePolicy || deploymentPlan.publicTLS.empty() == false))
    {
      if (failure)
      {
        failure->assign("no healthy TLS identity containers"_ctv);
      }
      return false;
    }
    return true;
  }

  void summarizeDeploymentTlsIdentityFreshness(const ApplicationDeployment *deployment, DeploymentStatusReport& report)
  {
    if (deployment == nullptr)
    {
      return;
    }
    for (ContainerView *container : deployment->containers)
    {
      if (container == nullptr || container->state != ContainerState::healthy)
      {
        continue;
      }
      CredentialBundle expected = {};
      if (buildCredentialBundleForContainer(deployment->plan, *container, expected) == false || expected.tlsIdentities.empty())
      {
        continue;
      }
      report.nTlsIdentityExpected += 1;
      bool pending = false;
      if (containerTlsIdentitiesFresh(deployment->plan, *container, &pending, nullptr))
      {
        report.nTlsIdentityFresh += 1;
      }
      else
      {
        report.nTlsIdentityStale += 1;
        report.nTlsIdentityPending += pending ? 1 : 0;
      }
    }
  }

  uint32_t retryStaleTlsIdentityDeltas(void)
  {
    uint32_t sent = 0;
    for (const auto& [deploymentID, deployment] : deployments)
    {
      (void)deploymentID;
      if (deployment == nullptr)
      {
        continue;
      }
      for (ContainerView *container : deployment->containers)
      {
        if (container == nullptr)
        {
          continue;
        }
        if (container->state != ContainerState::scheduled && container->state != ContainerState::healthy && container->state != ContainerState::crashedRestarting)
        {
          continue;
        }
        bool pending = false;
        if (containerTlsIdentitiesFresh(deployment->plan, *container, &pending, nullptr) || pending)
        {
          continue;
        }

        CredentialBundle expected = {};
        if (buildCredentialBundleForContainer(deployment->plan, *container, expected) == false || expected.tlsIdentities.empty())
        {
          continue;
        }
        CredentialDelta delta = {};
        delta.bundleGeneration = expected.bundleGeneration;
        delta.updatedTls = std::move(expected.tlsIdentities);
        delta.reason = "tls-identity-stale-retry"_ctv;
        sent += pushCredentialDeltaToContainer(container, delta) ? 1 : 0;
      }
    }
    return sent;
  }

  uint32_t pushPublicTlsIdentityDeltaToLiveContainers(const PublicTlsCertificateState& certificate, const String& reason)
  {
    if (certificate.identity.certPem.size() == 0 || certificate.identity.keyPem.size() == 0)
    {
      return 0;
    }

    auto deploymentIt = deployments.find(certificate.spec.deploymentID);
    if (deploymentIt == deployments.end() || deploymentIt->second == nullptr || publicTlsCertificateMatchesDeployment(deploymentIt->second->plan, certificate) == false)
    {
      return 0;
    }

    CredentialDelta delta = {};
    delta.bundleGeneration = certificate.identity.generation;
    delta.updatedTls.push_back(certificate.identity);
    delta.reason = reason;
    return pushCredentialDeltaToLiveContainers(deploymentIt->second->plan, delta);
  }

  uint32_t pushPrivateTlsIdentityDeltaToLiveContainers(uint16_t applicationID, const String& reason)
  {
    uint32_t sent = 0;
    for (const auto& [deploymentID, deployment] : deployments)
    {
      (void)deploymentID;
      if (deployment == nullptr ||
          deployment->plan.hasTlsIssuancePolicy == false ||
          deployment->plan.tlsIssuancePolicy.applicationID != applicationID)
      {
        continue;
      }

      for (ContainerView *container : deployment->containers)
      {
        if (container == nullptr)
        {
          continue;
        }
        if (container->state != ContainerState::scheduled && container->state != ContainerState::healthy && container->state != ContainerState::crashedRestarting)
        {
          continue;
        }

        CredentialBundle bundle = {};
        uint64_t bundleGeneration = 0;
        if (buildTlsBundleForContainer(deployment->plan, *container, bundle, bundleGeneration) == false || bundle.tlsIdentities.empty())
        {
          continue;
        }

        CredentialDelta delta = {};
        delta.bundleGeneration = bundleGeneration;
        delta.updatedTls = std::move(bundle.tlsIdentities);
        delta.reason = reason;
        sent += pushCredentialDeltaToContainer(container, delta) ? 1 : 0;
      }
    }
    return sent;
  }

  static bool privateTlsAuthorityRenewalDueAt(const PrivateTlsVaultLifecycleState& lifecycle, int64_t nowMs)
  {
    int64_t rootRenewAtMs = privateTlsVaultRenewAtMs(lifecycle, lifecycle.rootNotBeforeMs, lifecycle.rootNotAfterMs, 0xA11CE001ULL);
    int64_t interRenewAtMs = privateTlsVaultRenewAtMs(lifecycle, lifecycle.intermediateNotBeforeMs, lifecycle.intermediateNotAfterMs, 0xA11CE002ULL);
    return (rootRenewAtMs > 0 && rootRenewAtMs <= nowMs) || (interRenewAtMs > 0 && interRenewAtMs <= nowMs);
  }

  static bool privateTlsAuthorityRenewalDue(const PrivateTlsVaultLifecycleState& lifecycle)
  {
    return privateTlsAuthorityRenewalDueAt(lifecycle, lifecycle.nextRenewAtMs);
  }

  uint32_t reapPublicTlsCertbotProcesses(int64_t nowMs)
  {
    uint32_t reaped = 0;
    for (auto it = publicTlsCertbotJobs.begin(); it != publicTlsCertbotJobs.end();)
    {
      PublicTlsCertbotJob& job = it->second;
      int status = 0;
      pid_t result = waitpid(job.pid, &status, WNOHANG);
      int waitErrno = result < 0 ? errno : 0;
      String failure = {};
      if (result == 0)
      {
        if (job.startedAtMs <= 0 || nowMs - job.startedAtMs < publicTlsCertbotTimeoutMs)
        {
          ++it;
          continue;
        }
        kill(job.pid, SIGKILL);
        result = waitpid(job.pid, &status, 0);
        waitErrno = result < 0 ? errno : 0;
        failure.assign("certbot process timed out"_ctv);
      }

      PublicTlsCertificateState *certificate = findPublicTlsCertificateStateByRuntimeKey(it->first);
      if (certificate != nullptr)
      {
        if (failure.size() == 0 && result < 0)
        {
          if (waitErrno == ECHILD && certificate->lastSuccessMs < certificate->lastAttemptMs)
          {
            failure.assign("certbot completed without importing lineage"_ctv);
          }
          else if (waitErrno != ECHILD)
          {
            failure.assign("certbot process was not waitable"_ctv);
          }
        }
        else if (failure.size() == 0 && result >= 0 && (WIFEXITED(status) == false || WEXITSTATUS(status) != 0))
        {
          failure.assign("certbot exited without issuing certificate"_ctv);
        }
        else if (failure.size() == 0 && result >= 0 && certificate->lastSuccessMs < certificate->lastAttemptMs)
        {
          failure.assign("certbot completed without importing lineage"_ctv);
        }
        if (failure.size() > 0)
        {
          noteCertificateFailure(certificate->failureCount, certificate->lastFailure, failure);
        }
        (void)cleanupPublicTlsPendingDNS01Challenges(*certificate);
      }
      releasePublicTlsCertbotLock(job);
      it = publicTlsCertbotJobs.erase(it);
      reaped += 1;
      if (certificate != nullptr)
      {
        noteMasterAuthorityRuntimeStateChanged();
      }
    }
    (void)nowMs;
    return reaped;
  }

  bool recoverPublicTlsCertificateLineage(PublicTlsCertificateState& certificate, const ProdigyCertbotPaths& paths)
  {
    if (certificate.lastAttemptMs <= certificate.lastSuccessMs ||
        (certificate.lastFailure.size() > 0 && certificate.lastFailure.equal("certbot completed without importing lineage"_ctv) == false))
    {
      return false;
    }
    AcmeLineageImportRequest request = {};
    request.clusterUUID = brainConfig.clusterUUID;
    request.applicationID = certificate.spec.applicationID;
    request.deploymentID = certificate.spec.deploymentID;
    request.wormholeName = certificate.spec.wormholeName;
    request.certName = certificate.certbotCertName.size() ? certificate.certbotCertName : certificate.spec.identityName;
    request.renewedDomains = certificate.spec.domains;
    if (certificate.lineagePath.size() == 0)
    {
      prodigyCertbotLineagePath(brainConfig, certificate, paths, certificate.lineagePath);
    }
    request.lineagePath = certificate.lineagePath;

    AcmeLineageImportResponse response = {};
    return importACMELineage(request, response);
  }

  uint32_t advancePublicTlsCertificateLifecycles(int64_t nowMs, const ProdigyCertbotPaths& paths = {})
  {
    uint32_t started = 0;
    (void)reapPublicTlsCertbotProcesses(nowMs);
    for (PublicTlsCertificateState& certificate : masterAuthorityRuntimeState.publicTlsCertificates)
    {
      if (certificate.releasePending)
      {
        (void)cleanupPublicTlsPendingDNS01Challenges(certificate);
        continue;
      }
      if (certificate.identity.certPem.size() > 0 && certificate.nextRenewAtMs > nowMs)
      {
        continue;
      }
      String key = publicTlsCertificateRuntimeKey(certificate);
      if (publicTlsCertbotJobs.find(key) != publicTlsCertbotJobs.end())
      {
        continue;
      }
      if (certificate.lastAttemptMs > certificate.lastSuccessMs && recoverPublicTlsCertificateLineage(certificate, paths))
      {
        continue;
      }
      if (certificateLifecycleBackoffActive(nowMs, certificate.lastAttemptMs, certificate.lastSuccessMs, certificate.failureCount, publicTlsCertificateJitterSeed(certificate)))
      {
        continue;
      }

      ProdigyCertbotCommand command = {};
      String failure = {};
      if (prodigyBuildCertbotCertonlyCommand(brainConfig, certificate, paths, command, &failure) == false)
      {
        certificate.lastAttemptMs = nowMs;
        noteCertificateFailure(certificate.failureCount, certificate.lastFailure, failure);
        noteMasterAuthorityRuntimeStateChanged();
        continue;
      }
      prodigyCertbotLineagePath(brainConfig, certificate, paths, certificate.lineagePath);

      int lockFD = -1;
      bool lockBusy = false;
      if (prodigyAcquireCertbotCertificateLock(brainConfig, certificate, paths, lockFD, &lockBusy, &failure) == false)
      {
        if (lockBusy)
        {
          continue;
        }
        certificate.lastAttemptMs = nowMs;
        noteCertificateFailure(certificate.failureCount, certificate.lastFailure, failure);
        noteMasterAuthorityRuntimeStateChanged();
        continue;
      }

      pid_t pid = -1;
      certificate.lastAttemptMs = nowMs;
      if (prodigySpawnArgv(command.argv, command.env, pid, &failure) == false)
      {
        prodigyReleaseCertbotLockFD(lockFD);
        noteCertificateFailure(certificate.failureCount, certificate.lastFailure, failure);
        noteMasterAuthorityRuntimeStateChanged();
        continue;
      }

      certificate.lastFailure.clear();
      publicTlsCertbotJobs.insert_or_assign(key, PublicTlsCertbotJob {pid, nowMs, lockFD});
      noteMasterAuthorityRuntimeStateChanged();
      started += 1;
    }
    return started;
  }

  uint32_t advancePrivateTlsVaultLifecycles(int64_t nowMs, bool pushDelta = true)
  {
    uint32_t advanced = 0;
    for (PrivateTlsVaultLifecycleState& lifecycle : masterAuthorityRuntimeState.privateTlsVaultLifecycles)
    {
      auto factoryIt = tlsVaultFactoriesByApp.find(lifecycle.applicationID);
      if (factoryIt != tlsVaultFactoriesByApp.end() && refreshPrivateTlsLeafSchedule(factoryIt->second, lifecycle))
      {
        noteMasterAuthorityRuntimeStateChanged();
      }
      if (lifecycle.nextRenewAtMs <= 0 || lifecycle.nextRenewAtMs > nowMs || certificateLifecycleBackoffActive(nowMs, lifecycle.lastAttemptMs, lifecycle.lastSuccessMs, lifecycle.failureCount, privateTlsVaultJitterSeed(lifecycle)))
      {
        continue;
      }

      lifecycle.lastAttemptMs = nowMs;
      if (factoryIt == tlsVaultFactoriesByApp.end())
      {
        String failure = {};
        failure.assign("tls vault factory is missing"_ctv);
        noteCertificateFailure(lifecycle.failureCount, lifecycle.lastFailure, failure);
        noteMasterAuthorityRuntimeStateChanged();
        continue;
      }
      ApplicationTlsVaultFactory factory = factoryIt->second;
      bool rotateAuthority = privateTlsAuthorityRenewalDueAt(lifecycle, nowMs);
      if (rotateAuthority && (lifecycle.mode != ProdigyCertificateLifecycleMode::managed || factory.keySourceMode != 0))
      {
        String failure = {};
        failure.assign("external tls vault authority material requires operator refresh"_ctv);
        noteCertificateFailure(lifecycle.failureCount, lifecycle.lastFailure, failure);
        noteMasterAuthorityRuntimeStateChanged();
        continue;
      }

      factory.updatedAtMs = nowMs;
      if (factory.factoryGeneration < UINT64_MAX)
      {
        factory.factoryGeneration += 1;
      }
      if (rotateAuthority)
      {
        String failure = {};
        if (generateManagedTlsVaultFactoryMaterial(factory, &failure) == false || validateApplicationTlsVaultFactoryMaterial(factory, &failure) == false)
        {
          noteCertificateFailure(lifecycle.failureCount, lifecycle.lastFailure, failure);
          noteMasterAuthorityRuntimeStateChanged();
          continue;
        }
      }
      tlsVaultFactoriesByApp.insert_or_assign(factory.applicationID, factory);
      if (nBrains > 1)
      {
        String serializedFactory = {};
        BitseryEngine::serialize(serializedFactory, factory);
        queueBrainReplication(BrainTopic::replicateTlsVaultFactory, serializedFactory);
      }

      PrivateTlsVaultLifecycleState next = {};
      String failure = {};
      if (buildPrivateTlsVaultLifecycleState(factory, nowMs, next, &failure) == false)
      {
        noteCertificateFailure(lifecycle.failureCount, lifecycle.lastFailure, failure);
        noteMasterAuthorityRuntimeStateChanged();
        continue;
      }
      next.lastAttemptMs = nowMs;
      next.lastSuccessMs = nowMs;
      next.failureCount = 0;
      lifecycle = std::move(next);
      noteMasterAuthorityRuntimeStateChanged();
      if (pushDelta)
      {
        String reason = {};
        if (rotateAuthority)
        {
          reason.assign("tls-vault-authority-renewal"_ctv);
        }
        else
        {
          reason.assign("tls-vault-leaf-renewal"_ctv);
        }
        (void)pushPrivateTlsIdentityDeltaToLiveContainers(factory.applicationID, reason);
      }
      advanced += 1;
    }
    return advanced;
  }

  uint32_t advanceCertificateLifecycles(int64_t nowMs, bool pushDelta = true, const ProdigyCertbotPaths& paths = {})
  {
    uint32_t advanced = advancePublicTlsCertificateLifecycles(nowMs, paths) + advancePrivateTlsVaultLifecycles(nowMs, pushDelta);
    return advanced + (pushDelta ? retryStaleTlsIdentityDeltas() : 0);
  }

  void pushApiCredentialDeltaToLiveContainers(uint16_t applicationID, const ApplicationApiCredentialSet& set, const Vector<String>& updatedNames, const Vector<String>& removedNames, const String& reason)
  {
    if (updatedNames.size() == 0 && removedNames.size() == 0)
    {
      return;
    }

    for (const auto& [deploymentID, deployment] : deployments)
    {
      (void)deploymentID;
      if (deployment == nullptr)
      {
        continue;
      }
      if (deployment->plan.config.applicationID != applicationID)
      {
        continue;
      }
      if (deployment->plan.hasApiCredentialPolicy == false)
      {
        continue;
      }

      const DeploymentApiCredentialPolicy& policy = deployment->plan.apiCredentialPolicy;
      if (policy.refreshPushEnabled == false)
      {
        continue;
      }

      CredentialDelta delta;
      delta.bundleGeneration = set.setGeneration;
      if (reason.size() > 0)
      {
        delta.reason.assign(reason);
      }
      else
      {
        delta.reason.assign("api-credential-set-upsert"_ctv);
      }

      for (const String& requiredName : policy.requiredCredentialNames)
      {
        if (containsCredentialName(updatedNames, requiredName))
        {
          if (const ApiCredential *credential = findApiCredential(set, requiredName); credential != nullptr)
          {
            if (apiCredentialMayReachContainer(deployment->plan, *credential))
            {
              delta.updatedApi.push_back(*credential);
            }
            else if (containsCredentialName(delta.removedApiNames, requiredName) == false)
            {
              delta.removedApiNames.push_back(requiredName);
            }
          }
        }

        if (containsCredentialName(removedNames, requiredName) && containsCredentialName(delta.removedApiNames, requiredName) == false)
        {
          delta.removedApiNames.push_back(requiredName);
        }
      }

      if (delta.updatedApi.size() == 0 && delta.removedApiNames.size() == 0)
      {
        continue;
      }

      for (ContainerView *container : deployment->containers)
      {
        if (container == nullptr)
        {
          continue;
        }

        switch (container->state)
        {
          case ContainerState::scheduled:
          case ContainerState::healthy:
          case ContainerState::crashedRestarting:
            {
              (void)pushCredentialDeltaToContainer(container, delta);
              break;
            }
          default:
            break;
        }
      }
    }
  }

  static void machineLifecycleCompleted(
      void *context,
      ProdigyBrainMachineLifecycleCoordinator::Action action,
      uint128_t uuid,
      const String& cloudID,
      const String& failure)
  {
    Brain& owner = *static_cast<Brain *>(context);
    if (failure.empty() == false)
    {
      basics_log("provider machine lifecycle failed action=%u uuid=%llu cloudID=%.*s error=%.*s\n",
                 unsigned(action),
                 (unsigned long long)uuid,
                 int(cloudID.size()),
                 reinterpret_cast<const char *>(cloudID.data()),
                 int(failure.size()),
                 reinterpret_cast<const char *>(failure.data()));
    }
    if (action != ProdigyBrainMachineLifecycleCoordinator::Action::hardReboot)
    {
      return;
    }

    auto it = owner.machinesByUUID.find(uuid);
    Machine *machine = it == owner.machinesByUUID.end() ? nullptr : it->second;
    if (machine == nullptr || machine->cloudID != cloudID ||
        machine->state != MachineState::hardRebooting)
    {
      return;
    }

    owner.cancelMachineHardRebootWatchdog(machine);
    TimeoutPacket *timeout = new TimeoutPacket();
    timeout->flags = uint64_t(BrainTimeoutFlags::hardRebootedMachine);
    timeout->identifier = machine->uuid;
    timeout->originator = machine;
    timeout->dispatcher = &owner;
    timeout->setTimeoutMs(prodigyBrainHardRebootWatchdogMs);
    RingDispatcher::installMultiplexee(timeout, &owner);
    Ring::queueTimeout(timeout);
    machine->hardRebootWatchdog = timeout;

    // let's also tell neuron and possibly brain to keep trying to reconnect?
    // we likely have to recreate the socket here
    if (owner.isActiveMaster())
    {
      // Keep retry budget for the reboot window, but recycle any active
      // fixed-file slot through normal close completion before reopening.
      owner.armMachineNeuronReconnect(machine, prodigyBrainHardRebootReconnectWindowMs);
    }
  }

  bool elasticAddressReplyStreamIsCurrent(const PendingElasticAddressControlOperation& operation);
  void sendRoutableSubnetRegistrationResponse(Mothership *stream,
                                               const RoutableSubnetRegistration& response);
  void sendRoutableSubnetUnregistrationResponse(Mothership *stream,
                                                 const RoutableSubnetUnregistration& response);
  void sendRoutableSubnetRegistrationResponse(const PendingElasticAddressControlOperation& operation,
                                               const RoutableSubnetRegistration& response);
  void sendRoutableSubnetUnregistrationResponse(const PendingElasticAddressControlOperation& operation,
                                                 const RoutableSubnetUnregistration& response);
  bool commitRoutableSubnetRegistryChange(void);
  bool routableSubnetOperationPending(const String& name, uint128_t uuid = 0) const;
  bool routablePrefixReleasePending(uint128_t uuid) const override;
  bool validatePendingElasticAddressOperations(
      const ProdigyMasterAuthorityRuntimeState& state,
      const BrainConfig *candidateBrainConfig = nullptr) const;
  void captureDurableElasticAddressOperations(void);
  bool configurePendingElasticAddressReleaseFence(const ProdigyMasterAuthorityRuntimeState& state);
  bool quarantinePendingElasticAddressReleasePrefixes(const ProdigyMasterAuthorityRuntimeState& state);
  bool replicatedRuntimeStateCoversPendingElasticAddressOperations(const ProdigyMasterAuthorityRuntimeState& incoming) const;
  void noteMasterAuthorityTransitionSentToPeer(BrainView *peer,
                                               const ProdigyMasterAuthorityRuntimeState& state,
                                               const String& transitionDigest);
  void acknowledgeMasterAuthorityTransition(
      BrainView *peer,
      const ProdigyMasterAuthorityStateTransitionAck& acknowledgement);
  void sendMasterAuthorityTransitionAcknowledgement(BrainView *peer,
                                                     uint64_t generation,
                                                     const String& transitionDigest);
  bool pendingElasticAddressOperationHasMajority(uint64_t operationID, uint64_t transitionGeneration);
  ProdigyPendingElasticAddressAssignment *findPendingElasticAddressAssignment(uint64_t operationID);
  const ProdigyPendingElasticAddressAssignment *findPendingElasticAddressAssignment(uint64_t operationID) const;
  ProdigyPendingElasticAddressRelease *findPendingElasticAddressRelease(uint64_t operationID);
  const ProdigyPendingElasticAddressRelease *findPendingElasticAddressRelease(uint64_t operationID) const;
  bool commitPendingElasticAddressStateChange(bool advanceGeneration = true);
  void reconcilePendingElasticAddressAssignments(void);
  void reconcilePendingElasticAddressReleases(void);
  bool reserveElasticAddressControlOperationIDs(uint32_t count, uint64_t& firstOperationID);
  bool nextElasticAddressControlOperationID(uint64_t& operationID);
  uint32_t pendingElasticAddressLogicalOperationCount(void) const;
  bool elasticAddressSagaFencesRuntimeEnvironment(const ProdigyRuntimeEnvironmentConfig& requested) const;
  bool enqueueElasticAddressAssignment(Mothership *stream,
                                       BrainIaaS& provider,
                                       const RoutableSubnetRegistration& request,
                                       uint128_t machineUUID,
                                       const String& machineCloudID,
                                       const IPPrefix& deliveryPrefix);
  bool enqueueElasticAddressRelease(Mothership *stream,
                                    BrainIaaS& provider,
                                    const RoutableSubnetUnregistration& request,
                                    const DistributableExternalSubnet& prefix);
  void completeElasticAddressAssignment(PendingElasticAddressControlOperation& operation,
                                        ProviderElasticAddressPlan&& plan,
                                        ProviderElasticAddressAssignment&& assignment,
                                        String&& failure);
  void completeElasticAddressCompensation(PendingElasticAddressControlOperation& operation,
                                          String&& failure);
  void completeElasticAddressRelease(PendingElasticAddressControlOperation& operation,
                                     String&& failure);
  static void elasticAddressOperationCompleted(
      void *context,
      uint64_t operationID,
      ProdigyBrainElasticAddressCoordinator::Action action,
      ProviderElasticAddressPlan&& plan,
      ProviderElasticAddressAssignment&& assignment,
      String&& failure);

  void handleRegisterRoutableSubnet(Mothership *stream, uint8_t *args);
  void handleUnregisterRoutableSubnet(Mothership *stream, uint8_t *args);

  static const ApiCredential *dnsOperationCredential(void *context,
                                                     uint16_t applicationID,
                                                     const String& name)
  {
    return static_cast<Brain *>(context)->findDNSCredential(applicationID, name);
  }

  bool deploymentDNSReady(uint64_t deploymentID) const
  {
    for (const RoutableResourceLease& lease : routableResourceLeaseRuntimeState)
    {
      if (lease.kind == RoutableResourceLeaseKind::dnsRecord &&
          lease.owner.deploymentID == deploymentID &&
          (lease.dnsDeletePending || dnsRecordLeaseApplied(lease) == false))
      {
        return false;
      }
    }
    return true;
  }

  bool dnsReconciliationPending(void) const
  {
    for (const RoutableResourceLease& lease : routableResourceLeaseRuntimeState)
    {
      if (lease.kind == RoutableResourceLeaseKind::dnsRecord &&
          (lease.dnsDeletePending || dnsRecordLeaseApplied(lease) == false) &&
          dnsRecordLeaseOperationPending(lease,
                                         lease.dnsDeletePending ?
                                             ProdigyBrainDNSOperationCoordinator::Action::remove :
                                             ProdigyBrainDNSOperationCoordinator::Action::upsert) == false)
      {
        return true;
      }
    }
    return false;
  }

  void armDNSReconciliationRetry(void)
  {
    if (dnsReconcileRetryArmed || weAreMaster == false ||
        RingDispatcher::dispatcher == nullptr || Ring::getRingFD() <= 0)
    {
      return;
    }
    if (dnsReconcileRetryInstalled == false)
    {
      dnsReconcileRetry.flags = uint64_t(BrainTimeoutFlags::dnsReconcileRetry);
      dnsReconcileRetry.dispatcher = this;
      RingDispatcher::installMultiplexee(&dnsReconcileRetry, this);
      dnsReconcileRetryInstalled = true;
    }
    const uint32_t exponent = std::min<uint32_t>(dnsReconcileFailureCount, 6);
    dnsReconcileRetry.setTimeoutMs(std::min<uint64_t>(uint64_t(1000) << exponent, 60'000));
    dnsReconcileFailureCount += dnsReconcileFailureCount < UINT32_MAX ? 1 : 0;
    dnsReconcileRetryArmed = true;
    Ring::queueTimeout(&dnsReconcileRetry);
  }

  void resumeDNSReadyDeployments(void)
  {
    for (auto it = deploymentsWaitingForDNS.begin(); it != deploymentsWaitingForDNS.end();)
    {
      const uint64_t deploymentID = *it;
      if (deploymentDNSReady(deploymentID) == false)
      {
        ++it;
        continue;
      }
      auto deployment = deployments.find(deploymentID);
      it = deploymentsWaitingForDNS.erase(it);
      if (deployment != deployments.end() && deployment->second != nullptr)
      {
        spinApplication(deployment->second);
      }
    }
  }

  void completeDNSOperation(uint64_t owner,
                            ProdigyBrainDNSOperationCoordinator::Action action,
                            bool success,
                            String&& failure)
  {
    auto pendingIt = pendingDNSOperations.find(owner);
    if (pendingIt == pendingDNSOperations.end())
    {
      return;
    }
    PendingDNSOperation pending = std::move(pendingIt->second);
    pendingDNSOperations.erase(pendingIt);
    if (pending.action != action)
    {
      return;
    }

    if (pending.kind == PendingDNSOperationKind::challenge)
    {
      AcmeDNS01ChallengeResponse response;
      response.success = success;
      response.failure = std::move(failure);
      response.recordName.assign(pending.record.name);
      response.provider.assign(pending.record.provider);
      response.zone.assign(pending.record.zone);
      response.ttl = pending.record.ttl;
      PublicTlsCertificateState *certificate = findPublicTlsCertificateStateByRuntimeKey(pending.certificateKey);
      if (response.success && certificate == nullptr)
      {
        response.success = false;
        response.failure.assign("ACME certificate state changed before DNS completion"_ctv);
      }
      if (response.success)
      {
        const bool changed = action == ProdigyBrainDNSOperationCoordinator::Action::cleanupTXT ?
                                 forgetPublicTlsPendingDNS01Challenge(*certificate, pending.record) :
                                 rememberPublicTlsPendingDNS01Challenge(*certificate, pending.record);
        if (changed)
        {
          noteMasterAuthorityRuntimeStateChanged();
        }
        if (action == ProdigyBrainDNSOperationCoordinator::Action::cleanupTXT &&
            certificate->releasePending && certificate->pendingDNS01Challenges.empty())
        {
          for (auto it = masterAuthorityRuntimeState.publicTlsCertificates.begin();
               it != masterAuthorityRuntimeState.publicTlsCertificates.end(); ++it)
          {
            if (publicTlsCertificateRuntimeKey(*it).equals(pending.certificateKey))
            {
              masterAuthorityRuntimeState.publicTlsCertificates.erase(it);
              noteMasterAuthorityRuntimeStateChanged();
              break;
            }
          }
        }
      }
      if (pending.inlineResponse != nullptr)
      {
        *pending.inlineResponse = response;
      }
      if (pending.stream != nullptr && activeMotherships.contains(pending.stream) &&
          pending.stream->connectionIncarnation == pending.streamIncarnation)
      {
        String serializedResponse;
        BitseryEngine::serialize(serializedResponse, response);
        Message::construct(pending.stream->wBuffer, pending.topic, serializedResponse);
        (void)flushActiveMothershipSendBuffer(pending.stream, "dns-operation-complete");
      }
      if (response.success == false && action == ProdigyBrainDNSOperationCoordinator::Action::cleanupTXT)
      {
        armDNSReconciliationRetry();
      }
      else if (response.success)
      {
        reconcileAuthoritativeDNSState();
      }
      return;
    }

    auto current = routableResourceLeaseRuntimeState.end();
    for (auto it = routableResourceLeaseRuntimeState.begin(); it != routableResourceLeaseRuntimeState.end(); ++it)
    {
      if (*it == pending.lease)
      {
        current = it;
        break;
      }
    }
    const bool currentMatched = current != routableResourceLeaseRuntimeState.end();
    bool terminalSuccess = success && currentMatched;
    if (success && currentMatched == false)
    {
      failure.assign("DNS intent changed before operation completion"_ctv);
    }
    if (terminalSuccess)
    {
      if (action == ProdigyBrainDNSOperationCoordinator::Action::upsert && current->dnsDeletePending == false)
      {
        if (dnsRecordLeaseApplied(*current) == false)
        {
          RoutableResourceLease applied;
          ownDNSRecordLease(applied, *current);
          appliedDNSRecordLeases.push_back(std::move(applied));
        }
      }
      else if (action == ProdigyBrainDNSOperationCoordinator::Action::remove && current->dnsDeletePending)
      {
        const RoutableResourceLease addressLease = dnsBindingAddressLease(*current);
        const RoutableResourceLease deleted = *current;
        for (auto applied = appliedDNSRecordLeases.begin(); applied != appliedDNSRecordLeases.end();)
        {
          if (applied->owner == deleted.owner && routableResourceDNSIdentityMatches(*applied, deleted))
          {
            applied = appliedDNSRecordLeases.erase(applied);
          }
          else
          {
            ++applied;
          }
        }
        for (auto it = routableResourceLeaseRuntimeState.begin(); it != routableResourceLeaseRuntimeState.end();)
        {
          if ((it->kind == RoutableResourceLeaseKind::dnsRecord && *it == deleted) ||
              (it->kind == RoutableResourceLeaseKind::wormholeAddress &&
               routableResourceLeaseResourcesIntersect(*it, addressLease) && it->owner == addressLease.owner))
          {
            it = routableResourceLeaseRuntimeState.erase(it);
          }
          else
          {
            ++it;
          }
        }
        noteRoutableResourceLeaseRuntimeStateChanged();
      }
      resumeDNSReadyDeployments();
      reconcileAuthoritativeDNSState();
    }

    if (pending.controlID != 0)
    {
      finishDNSControl(pending.controlID, pending.lease, terminalSuccess, failure);
    }
    if (terminalSuccess == false)
    {
      basics_log("dns operation failed failure=%s\n", failure.c_str());
      armDNSReconciliationRetry();
    }
    else
    {
      bool converged = true;
      for (const RoutableResourceLease& lease : routableResourceLeaseRuntimeState)
      {
        if (lease.kind == RoutableResourceLeaseKind::dnsRecord &&
            (lease.dnsDeletePending || dnsRecordLeaseApplied(lease) == false))
        {
          converged = false;
          break;
        }
      }
      if (converged)
      {
        dnsReconcileFailureCount = 0;
      }
    }
  }

  static void dnsOperationCompleted(void *context,
                                    ProdigyBrainDNSOperationCoordinator::Ticket,
                                    ProdigyBrainDNSOperationCoordinator::Action action,
                                    uint64_t owner,
                                    bool success,
                                    String&& failure)
  {
    static_cast<Brain *>(context)->completeDNSOperation(owner, action, success, std::move(failure));
  }

  bool queueMachineHardReboot(Machine *machine)
  {
    if (iaas == nullptr || machine == nullptr || machine->cloudID.empty())
    {
      basics_log("provider hard reboot rejected: machine identity unavailable\n");
      return false;
    }

    const MachineState priorState = machine->state;
    const uint32_t priorAttempts = machine->hardRebootAttempts;
    const int64_t priorRebootMs = machine->lastHardRebootMs;
    machine->state = MachineState::hardRebooting;
    machine->hardRebootAttempts += 1;
    machine->lastHardRebootMs = Time::now<TimeResolution::ms>();
    if (machineLifecycle.enqueue(*iaas,
                                 ProdigyBrainMachineLifecycleCoordinator::Action::hardReboot,
                                 machine->uuid,
                                 machine->cloudID))
    {
      return true;
    }

    machine->state = priorState;
    machine->hardRebootAttempts = priorAttempts;
    machine->lastHardRebootMs = priorRebootMs;
    basics_log("provider hard reboot queue full uuid=%llu cloudID=%s\n",
               (unsigned long long)machine->uuid,
               machine->cloudID.c_str());
    return false;
  }

  bool queueMachineDestroy(const Machine& machine)
  {
    if (iaas != nullptr && machine.cloudID.empty() == false &&
        machineLifecycle.enqueue(*iaas,
                                 ProdigyBrainMachineLifecycleCoordinator::Action::destroy,
                                 machine.uuid,
                                 machine.cloudID))
    {
      return true;
    }
    basics_log("provider machine destroy queue rejected uuid=%llu cloudID=%.*s\n",
               (unsigned long long)machine.uuid,
               int(machine.cloudID.size()),
               reinterpret_cast<const char *>(machine.cloudID.data()));
    return false;
  }

  Brain()
  {
    mesh = new Mesh();
    machineLifecycle.configureCompletion({this, machineLifecycleCompleted});
    elasticAddressOperations.configureCompletion({this, elasticAddressOperationCompleted});
    dnsOperations.configure({this, dnsOperationCredential},
                            {this, dnsOperationCompleted});
    initializeApplicationIDReservationState();
    initializeApplicationServiceReservationState();
  }

  void configureDNSProviderRuntime(ProdigyDNSProviderRuntime requestedRuntime)
  {
    if (dnsProvider != nullptr)
    {
      dnsProvider->configureRuntime(requestedRuntime);
    }
    dnsOperations.configureDelay(requestedRuntime.delay);
  }

  uint128_t selfBrainUUID(void) const
  {
    if (thisNeuron == nullptr)
    {
      return 0;
    }

    return thisNeuron->uuid;
  }

  static int compareIPAddresses(const IPAddress& lhs, const IPAddress& rhs)
  {
    if (lhs.is6 != rhs.is6)
    {
      return lhs.is6 ? 1 : -1;
    }

    if (lhs.is6)
    {
      return memcmp(lhs.v6, rhs.v6, sizeof(lhs.v6));
    }

    if (lhs.v4 < rhs.v4)
    {
      return -1;
    }

    if (lhs.v4 > rhs.v4)
    {
      return 1;
    }

    return 0;
  }

  void collectLocalBrainCandidateAddresses(Vector<IPAddress>& localAddresses) const
  {
    localAddresses.clear();

    if (thisNeuron == nullptr)
    {
      return;
    }

    Vector<ClusterMachinePeerAddress> candidates;
    String preferredInterface = {};
    preferredInterface.assign(thisNeuron->eth.name);
    prodigyCollectLocalPeerAddressCandidates(preferredInterface, thisNeuron->private4, candidates);

    for (const ClusterMachinePeerAddress& candidate : candidates)
    {
      IPAddress parsedAddress = {};
      if (ClusterMachine::parseIPAddressLiteral(candidate.address, parsedAddress) == false)
      {
        continue;
      }

      bool alreadyPresent = false;
      for (const IPAddress& existing : localAddresses)
      {
        if (existing.equals(parsedAddress))
        {
          alreadyPresent = true;
          break;
        }
      }

      if (alreadyPresent == false)
      {
        localAddresses.push_back(parsedAddress);
      }
    }
  }

  void adoptLocalBrainPeerAddresses(const Vector<ClusterMachinePeerAddress>& candidates)
  {
    localBrainPeerAddresses.clear();
    for (const ClusterMachinePeerAddress& candidate : candidates)
    {
      prodigyAppendUniqueClusterMachinePeerAddress(localBrainPeerAddresses, candidate);
    }

    if (localBrainPeerAddresses.empty())
    {
      return;
    }

    bool currentStillPresent = false;
    for (const ClusterMachinePeerAddress& candidate : localBrainPeerAddresses)
    {
      if (candidate.address.equals(localBrainPeerAddressText))
      {
        currentStillPresent = true;
        break;
      }
    }

    if (currentStillPresent)
    {
      return;
    }

    IPAddress address = {};
    String addressText = {};
    if (ClusterMachine::parseIPAddressLiteral(localBrainPeerAddresses[0].address, address))
    {
      addressText.assign(localBrainPeerAddresses[0].address);
      adoptLocalBrainPeerAddress(address, addressText);
    }
  }

  void refreshLocalBrainPeerAddresses(void)
  {
    if (thisNeuron == nullptr)
    {
      localBrainPeerAddresses.clear();
      return;
    }

    Vector<ClusterMachinePeerAddress> candidates;
    String preferredInterface = {};
    preferredInterface.assign(thisNeuron->eth.name);
    prodigyCollectLocalPeerAddressCandidates(preferredInterface, thisNeuron->private4, candidates);
    if (candidates.empty() == false)
    {
      ClusterTopology topology = {};
      ClusterMachine self = {};
      self.isBrain = true;
      prodigyAssignClusterMachineAddressesFromPeerCandidates(self.addresses, candidates);
      topology.machines.push_back(self);
      prodigyNormalizeClusterTopologyPeerAddresses(topology);
      prodigyCollectClusterMachinePeerAddresses(topology.machines[0], candidates);
    }

    adoptLocalBrainPeerAddresses(candidates);
    if (thisNeuron != nullptr)
    {
      Machine *machine = nullptr;
      if (thisNeuron->uuid != 0)
      {
        if (auto it = machinesByUUID.find(thisNeuron->uuid); it != machinesByUUID.end())
        {
          machine = it->second;
        }
      }

      if (machine == nullptr)
      {
        for (Machine *candidateMachine : machines)
        {
          if (candidateMachine && candidateMachine->isThisMachine)
          {
            machine = candidateMachine;
            break;
          }
        }
      }

      if (machine != nullptr)
      {
        machine->peerAddresses = localBrainPeerAddresses;
        if (machine->privateAddress.size() == 0 && localBrainPeerAddressText.size() > 0)
        {
          machine->privateAddress = localBrainPeerAddressText;
        }
      }
    }
  }

  void adoptLocalMachineHardwareProfile(const MachineHardwareProfile& hardware) override
  {
    Machine *machine = nullptr;
    if (thisNeuron != nullptr && thisNeuron->uuid != 0)
    {
      if (auto it = machinesByUUID.find(thisNeuron->uuid); it != machinesByUUID.end())
      {
        machine = it->second;
      }
    }

    if (machine == nullptr)
    {
      for (Machine *candidateMachine : machines)
      {
        if (candidateMachine && candidateMachine->isThisMachine)
        {
          machine = candidateMachine;
          break;
        }
      }
    }

    if (machine == nullptr)
    {
      return;
    }

    applyMachineHardwareProfile(machine, hardware);
    promoteMachineToHealthyIfReady(machine);
  }

  void replayLocalMachineHardwareProfileIfReady(void)
  {
    if (thisNeuron == nullptr)
    {
      return;
    }

    thisNeuron->ensureDeferredHardwareInventoryProgress();
    if (const MachineHardwareProfile *hardware = thisNeuron->latestHardwareProfileIfReady(); hardware != nullptr)
    {
      adoptLocalMachineHardwareProfile(*hardware);
    }
  }

  bool localBrainAddressMatches(const IPAddress& address) const
  {
    if (address.isNull() || thisNeuron == nullptr)
    {
      return false;
    }

    Vector<IPAddress> localAddresses;
    collectLocalBrainCandidateAddresses(localAddresses);

    for (const IPAddress& localAddress : localAddresses)
    {
      if (localAddress.equals(address))
      {
        return true;
      }
    }

    return false;
  }

  void adoptLocalBrainPeerAddress(const IPAddress& address, const String& addressText)
  {
    if (address.isNull() == false)
    {
      localBrainPeerAddress = address;
    }

    if (addressText.size() > 0)
    {
      localBrainPeerAddressText = addressText;
    }
    else if (localBrainPeerAddress.isNull() == false)
    {
      (void)ClusterMachine::renderIPAddressLiteral(localBrainPeerAddress, localBrainPeerAddressText);
    }

    ClusterMachinePeerAddress candidate = {};
    if (localBrainPeerAddressText.size() > 0)
    {
      candidate.address.assign(localBrainPeerAddressText);
    }
    else if (localBrainPeerAddress.isNull() == false)
    {
      (void)ClusterMachine::renderIPAddressLiteral(localBrainPeerAddress, candidate.address);
    }

    if (candidate.address.size() > 0)
    {
      prodigyAppendUniqueClusterMachinePeerAddress(localBrainPeerAddresses, candidate);
    }
  }

  bool resolveLocalBrainPeerAddressFromIaaS(void)
  {
    if (iaas == nullptr)
    {
      return false;
    }

    IPAddress address = {};
    String addressText = {};
    if (iaas->resolveLocalBrainPeerAddress(address, addressText) == false)
    {
      return false;
    }

    adoptLocalBrainPeerAddress(address, addressText);
    return true;
  }

  void collectLocalBrainPeerSourceCandidates(Vector<ClusterMachinePeerAddress>& localCandidates, bool preferNeuronPrivate4BeforeAmbient = false) const
  {
    localCandidates = localBrainPeerAddresses;
    if (localCandidates.empty() && localBrainPeerAddress.isNull() == false)
    {
      ClusterMachinePeerAddress candidate = {};
      if (localBrainPeerAddressText.size() > 0)
      {
        candidate.address.assign(localBrainPeerAddressText);
      }
      else
      {
        (void)ClusterMachine::renderIPAddressLiteral(localBrainPeerAddress, candidate.address);
      }

      if (candidate.address.size() > 0)
      {
        prodigyAppendUniqueClusterMachinePeerAddress(localCandidates, candidate);
      }
    }

    if (preferNeuronPrivate4BeforeAmbient && localCandidates.empty() && thisNeuron != nullptr && thisNeuron->private4.isNull() == false)
    {
      ClusterMachinePeerAddress candidate = {};
      if (ClusterMachine::renderIPAddressLiteral(thisNeuron->private4, candidate.address))
      {
        prodigyAppendUniqueClusterMachinePeerAddress(localCandidates, candidate);
      }
    }

    if (localCandidates.empty() && thisNeuron != nullptr)
    {
      String preferredInterface = {};
      preferredInterface.assign(thisNeuron->eth.name);
      prodigyCollectLocalPeerAddressCandidates(preferredInterface, thisNeuron->private4, localCandidates);
      if (localCandidates.empty() == false)
      {
        ClusterTopology topology = {};
        ClusterMachine self = {};
        self.isBrain = true;
        prodigyAssignClusterMachineAddressesFromPeerCandidates(self.addresses, localCandidates);
        topology.machines.push_back(self);
        prodigyNormalizeClusterTopologyPeerAddresses(topology);
        prodigyCollectClusterMachinePeerAddresses(topology.machines[0], localCandidates);
      }
    }
  }

  bool shouldWeConnectToBrain(const BrainView *brain) const
  {
    if (brain == nullptr)
    {
      return false;
    }

    Vector<ClusterMachinePeerAddress> localCandidates = {};
    collectLocalBrainPeerSourceCandidates(localCandidates, true);

    Vector<ClusterMachinePeerAddress> peerCandidates = brain->peerAddresses;
    if (peerCandidates.empty())
    {
      if (brain->peerAddressText.size() > 0)
      {
        peerCandidates.push_back(ClusterMachinePeerAddress {brain->peerAddressText, 0});
      }
      else if (brain->peerAddress.isNull() == false)
      {
        String peerAddressText = {};
        if (ClusterMachine::renderIPAddressLiteral(brain->peerAddress, peerAddressText))
        {
          peerCandidates.push_back(ClusterMachinePeerAddress {peerAddressText, 0});
        }
      }
      else if (brain->private4 != 0)
      {
        IPAddress peerAddress = {};
        peerAddress.v4 = brain->private4;
        peerAddress.is6 = false;
        String peerAddressText = {};
        if (ClusterMachine::renderIPAddressLiteral(peerAddress, peerAddressText))
        {
          peerCandidates.push_back(ClusterMachinePeerAddress {peerAddressText, 0});
        }
      }
    }

    for (const ClusterMachinePeerAddress& peerCandidate : peerCandidates)
    {
      IPAddress peerAddress = {};
      if (ClusterMachine::parseIPAddressLiteral(peerCandidate.address, peerAddress) == false)
      {
        continue;
      }

      IPAddress preferredSelfAddress = {};
      if (prodigyResolvePreferredLocalSourceAddress(localCandidates, peerCandidate, preferredSelfAddress))
      {
        int addressCmp = compareIPAddresses(preferredSelfAddress, peerAddress);
        if (addressCmp != 0)
        {
          return addressCmp < 0;
        }
      }

      for (const ClusterMachinePeerAddress& localCandidate : localCandidates)
      {
        IPAddress selfAddress = {};
        if (ClusterMachine::parseIPAddressLiteral(localCandidate.address, selfAddress) == false)
        {
          continue;
        }

        if (selfAddress.is6 != peerAddress.is6)
        {
          continue;
        }

        int addressCmp = compareIPAddresses(selfAddress, peerAddress);
        if (addressCmp != 0)
        {
          return addressCmp < 0;
        }
      }
    }

    IPAddress selfAddress = localBrainPeerAddress;
    if (selfAddress.isNull() && thisNeuron != nullptr && thisNeuron->private4.v4 != 0)
    {
      selfAddress = thisNeuron->private4;
    }

    IPAddress peerAddress = brain->peerAddress;
    if (peerAddress.isNull() && brain->private4 != 0)
    {
      peerAddress = {};
      peerAddress.v4 = brain->private4;
      peerAddress.is6 = false;
    }

    if (selfAddress.isNull() == false && peerAddress.isNull() == false)
    {
      int addressCmp = compareIPAddresses(selfAddress, peerAddress);
      if (addressCmp != 0)
      {
        return addressCmp < 0;
      }
    }

    if (thisNeuron != nullptr && brain->uuid != 0 && thisNeuron->uuid != brain->uuid)
    {
      return thisNeuron->uuid < brain->uuid;
    }

    return false;
  }

  uint128_t getExistingMasterUUID(void) const
  {
    uint128_t existingMasterUUID = 0;

    if (weAreMaster)
    {
      existingMasterUUID = selfBrainUUID();
    }
    else if (noMasterYet == false)
    {
      for (BrainView *bv : brains)
      {
        if (peerRepresentsCurrentMaster(bv))
        {
          existingMasterUUID = bv->uuid;
          break;
        }
      }
    }

    return existingMasterUUID;
  }

  bool peerClaimsCurrentMasterIdentity(const BrainView *peer) const
  {
    if (peer == nullptr || weAreMaster)
    {
      return false;
    }

    return (
        peer->uuid != 0 && peer->existingMasterUUID != 0 && peer->existingMasterUUID == peer->uuid);
  }

  bool peerRepresentsCurrentMaster(const BrainView *peer) const
  {
    if (peer == nullptr)
    {
      return false;
    }

    if (peer->isMasterBrain)
    {
      return true;
    }

    if (weAreMaster || noMasterYet)
    {
      return false;
    }

    return peerClaimsCurrentMasterIdentity(peer);
  }

  bool peerRepresentsCurrentMasterForLiveness(const BrainView *peer) const
  {
    if (peer == nullptr)
    {
      return false;
    }

    if (peer->isMasterBrain)
    {
      return true;
    }

    // Followers can transiently lose the local isMasterBrain bit during reconnect
    // churn even while a peer is still explicitly claiming it is the current master.
    // Keep treating that peer as the authoritative master identity for liveness,
    // registration, and reconnect decisions until a new election resolves it.
    return peerClaimsCurrentMasterIdentity(peer);
  }

  bool peerReconnectOwned(const BrainView *peer) const
  {
    if (peer == nullptr)
    {
      return false;
    }

    return (peer->weConnectToIt || peer->forceConnectorOwnershipUntilMasterAck);
  }

  void queueLocalPeerAddressCandidates(BrainView *brain)
  {
    if (brain == nullptr || brain->canQueueSend() == false)
    {
      return;
    }

    if (localBrainPeerAddresses.empty())
    {
      refreshLocalBrainPeerAddresses();
    }

    if (localBrainPeerAddresses.empty())
    {
      return;
    }

    String serializedCandidates = {};
    BitseryEngine::serialize(serializedCandidates, localBrainPeerAddresses);
    Message::construct(brain->wBuffer, BrainTopic::peerAddressCandidates, serializedCandidates);
    Ring::queueSend(brain);
  }

  bool updateBrainPeerAddressCandidates(BrainView *brain, const Vector<ClusterMachinePeerAddress>& candidates)
  {
    if (brain == nullptr || candidates.empty())
    {
      return false;
    }

    Vector<ClusterMachinePeerAddress> normalizedCandidates;
    for (const ClusterMachinePeerAddress& candidate : candidates)
    {
      prodigyAppendUniqueClusterMachinePeerAddress(normalizedCandidates, candidate);
    }

    if (normalizedCandidates.empty())
    {
      return false;
    }

    if (prodigyClusterMachinePeerAddressesEqual(brain->peerAddresses, normalizedCandidates))
    {
      return false;
    }

    adoptBrainPeerAddresses(brain, normalizedCandidates);
    if (brain->machine != nullptr)
    {
      brain->machine->peerAddresses = brain->peerAddresses;
      if (brain->machine->privateAddress.size() == 0 && brain->peerAddressText.size() > 0)
      {
        brain->machine->privateAddress = brain->peerAddressText;
      }
    }
    else
    {
      synchronizeBrainUUIDToMachine(brain);
    }

    if (weAreMaster == false)
    {
      return true;
    }

    ClusterTopology topology = {};
    if (loadAuthoritativeClusterTopology(topology) == false || topology.machines.empty())
    {
      return true;
    }

    bool updatedTopology = false;
    for (ClusterMachine& clusterMachine : topology.machines)
    {
      if (clusterMachine.isBrain == false)
      {
        continue;
      }

      bool matchesPeer = (brain->uuid != 0 && clusterMachine.uuid != 0 && clusterMachine.uuid == brain->uuid);
      if (matchesPeer == false && brain->machine != nullptr)
      {
        matchesPeer = prodigyClusterMachineMatchesMachineIdentity(clusterMachine, *brain->machine);
      }

      if (matchesPeer == false)
      {
        for (const ClusterMachinePeerAddress& candidate : normalizedCandidates)
        {
          IPAddress candidateAddress = {};
          if (ClusterMachine::parseIPAddressLiteral(candidate.address, candidateAddress) && clusterMachine.peerAddressMatches(candidateAddress, &candidate.address))
          {
            matchesPeer = true;
            break;
          }
        }
      }

      if (matchesPeer == false)
      {
        continue;
      }

      clusterMachine.peerAddresses.clear();
      for (const ClusterMachinePeerAddress& candidate : normalizedCandidates)
      {
        prodigyAppendUniqueClusterMachinePeerAddress(clusterMachine.peerAddresses, candidate);
      }
      prodigyAssignClusterMachineAddressesFromPeerCandidates(clusterMachine.addresses, normalizedCandidates);

      updatedTopology = true;
      break;
    }

    if (updatedTopology == false)
    {
      return true;
    }

    prodigyNormalizeClusterTopologyPeerAddresses(topology);
    topology.version += 1;
    if (persistAuthoritativeClusterTopology(topology) == false)
    {
      return false;
    }

    String serializedTopology = {};
    BitseryEngine::serialize(serializedTopology, topology);
    queueBrainReplication(BrainTopic::replicateClusterTopology, serializedTopology);
    sendNeuronSwitchboardOverlayRoutes();
    return true;
  }

  uint128_t resolveConsistentExistingMasterUUID(void) const
  {
    uint128_t existingMasterUUID = 0;
    bool conflictingExistingMasterUUID = false;

    for (BrainView *brain : brains)
    {
      if (peerEligibleForClusterQuorum(brain) == false)
      {
        continue;
      }

      if (brain->existingMasterUUID == 0)
      {
        continue;
      }

      if (existingMasterUUID == 0)
      {
        existingMasterUUID = brain->existingMasterUUID;
      }
      else if (existingMasterUUID != brain->existingMasterUUID)
      {
        conflictingExistingMasterUUID = true;
        break;
      }
    }

    return conflictingExistingMasterUUID ? uint128_t(0) : existingMasterUUID;
  }

  bool peerHasFreshExistingMasterClaim(BrainView *peer) const
  {
    if (peerEligibleForClusterQuorum(peer) == false)
    {
      return false;
    }

    if (peer->registrationFresh == false)
    {
      return false;
    }

    if (peer->uuid == 0 || peer->boottimens == 0 || peer->existingMasterUUID == 0)
    {
      return false;
    }

    return true;
  }

  uint128_t deriveRegisteredMasterUUID(void) const
  {
    uint128_t masterUUID = 0;
    uint128_t selfUUID = selfBrainUUID();
    if (selfUUID != 0)
    {
      masterUUID = selfUUID;
    }

    for (BrainView *bv : brains)
    {
      if (peerEligibleForClusterQuorum(bv) == false || bv->boottimens == 0 || bv->uuid == 0)
      {
        continue;
      }

      if (masterUUID == 0 || bv->uuid < masterUUID)
      {
        masterUUID = bv->uuid;
      }
    }

    return masterUUID;
  }

  bool activeBrainRegistrationsReadyForMasterElection(void)
  {
    if (selfBrainUUID() == 0 || boottimens == 0)
    {
      return false;
    }

    for (BrainView *bv : brains)
    {
      if (peerEligibleForClusterQuorum(bv) == false)
      {
        continue;
      }

      if (peerSocketActive(bv) == false)
      {
        continue;
      }

      if (bv->uuid == 0 || bv->boottimens == 0)
      {
        return false;
      }
    }

    return true;
  }

  bool resolveFailoverMasterByActivePeerAddressOrder(bool& preferSelf, bool *sawActivePeer = nullptr)
  {
    preferSelf = false;
    if (sawActivePeer != nullptr)
    {
      *sawActivePeer = false;
    }

    if (thisNeuron == nullptr || thisNeuron->private4.isNull())
    {
      return false;
    }

    uint32_t selfPrivate4 = thisNeuron->private4.v4;
    if (selfPrivate4 == 0)
    {
      return false;
    }

    preferSelf = true;
    bool sawComparableActivePeer = false;
    bool sawIncompleteActivePeer = false;
    for (BrainView *bv : brains)
    {
      if (peerEligibleForClusterQuorum(bv) == false)
      {
        continue;
      }

      if (peerSocketActive(bv) == false)
      {
        continue;
      }

      if (sawActivePeer != nullptr)
      {
        *sawActivePeer = true;
      }

      if (bv->private4 == 0)
      {
        basics_log("failoverAddressOrder skip-incomplete peer=%p uuid=%llu connected=%d quarantined=%d isFixed=%d fslot=%d\n",
                   static_cast<void *>(bv),
                   (unsigned long long)bv->uuid,
                   int(bv->connected),
                   int(bv->quarantined),
                   int(bv->isFixedFile),
                   bv->fslot);
        sawIncompleteActivePeer = true;
        continue;
      }

      sawComparableActivePeer = true;
      basics_log("failoverAddressOrder compare selfPrivate4=%u peerPrivate4=%u peerUUID=%llu preferSelfBefore=%d\n",
                 unsigned(selfPrivate4),
                 unsigned(bv->private4),
                 (unsigned long long)bv->uuid,
                 int(preferSelf));
      if (bv->private4 < selfPrivate4)
      {
        preferSelf = false;
      }
    }

    if (sawComparableActivePeer)
    {
      basics_log("failoverAddressOrder resolved selfPrivate4=%u preferSelf=%d incomplete=%d\n",
                 unsigned(selfPrivate4),
                 int(preferSelf),
                 int(sawIncompleteActivePeer));
      return true;
    }

    if (sawIncompleteActivePeer)
    {
      preferSelf = false;
      basics_log("failoverAddressOrder waiting selfPrivate4=%u reason=incomplete-active-peer\n", unsigned(selfPrivate4));
      return false;
    }

    basics_log("failoverAddressOrder selfPrivate4=%u no-active-peers\n", unsigned(selfPrivate4));
    return true;
  }

  bool peerEligibleForClusterQuorum(BrainView *peer) const
  {
    if (peer == nullptr || peer->quarantined)
    {
      return false;
    }

    if (thisNeuron != nullptr)
    {
      if (peer->private4 != 0 && peer->private4 == thisNeuron->private4.v4)
      {
        return false;
      }

      uint128_t selfUUID = selfBrainUUID();
      if (selfUUID != 0 && peer->uuid != 0 && peer->uuid == selfUUID)
      {
        return false;
      }
    }

    return true;
  }

  uint64_t connectFailureLogKey(uint8_t socketKind, uint32_t private4, int result, bool quarantined) const
  {
    uint64_t key = 0;
    key |= (uint64_t(socketKind & 0x03u) << 62);
    key |= (uint64_t(private4) << 30);
    key |= (uint64_t(uint16_t(result)) << 14);
    key |= (quarantined ? (uint64_t(1) << 13) : 0);
    return key;
  }

  bool shouldLogConnectFailure(uint64_t key, uint32_t attemptNumber, uint32_t attemptBudget)
  {
    int64_t nowMs = Time::now<TimeResolution::ms>();
    int64_t& nextLogAtMs = connectFailureNextLogMsByKey[key];

    // Emit immediately on the first attempt for a failure-mode key, then gate repeats.
    if (attemptNumber == 1)
    {
      if (nextLogAtMs == 0 || nowMs >= nextLogAtMs)
      {
        nextLogAtMs = nowMs + connectFailureLogIntervalMs;
        return true;
      }
    }
    else if (attemptNumber == attemptBudget)
    {
      // Keep a periodic terminal-attempt heartbeat while the peer is unreachable.
      if (nextLogAtMs == 0 || nowMs >= nextLogAtMs)
      {
        nextLogAtMs = nowMs + connectFailureLogIntervalMs;
        return true;
      }
    }

    return false;
  }

  void recoverDeploymentsAfterNeuronState(void)
  {
    if (weAreMaster == false || ignited == false)
    {
      return;
    }

    for (const auto& [applicationID, head] : deploymentsByApp)
    {
      (void)applicationID;
      if (head == nullptr)
      {
        continue;
      }
      if (deploymentDNSReady(head->plan.config.deploymentID()) == false)
      {
        deploymentsWaitingForDNS.insert(head->plan.config.deploymentID());
        continue;
      }
      head->recoverAfterReboot();
    }
  }

  template <typename T>
  int loggableSocketFD(T *socket) const
  {
    if (socket == nullptr)
    {
      return -1;
    }

    if (socket->isFixedFile)
    {
      return Ring::getFDFromFixedFileSlot(socket->fslot);
    }

    return socket->fd;
  }

  void logMothershipReceiveBufferHead(const char *stage, Mothership *stream)
  {
    if (stream == nullptr)
    {
      return;
    }

    uint64_t outstanding = stream->rBuffer.outstandingBytes();
    uint32_t peekSize = 0;
    uint8_t sample[16] = {0};
    if (outstanding >= sizeof(uint32_t))
    {
      memcpy(&peekSize, stream->rBuffer.pHead(), sizeof(uint32_t));
    }

    uint64_t sampleCount = (outstanding < sizeof(sample) ? outstanding : sizeof(sample));
    if (sampleCount > 0)
    {
      memcpy(sample, stream->rBuffer.pHead(), sampleCount);
    }

    PRODIGY_DEBUG_LOG(
                 "prodigy mothership %s outstanding=%llu peekSize=%u sampleBytes=%llu sample=%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x stream=%p fixedFD=%d fslot=%d master=%d\n",
                 stage,
                 (unsigned long long)outstanding,
                 unsigned(peekSize),
                 (unsigned long long)sampleCount,
                 unsigned(sample[0]),
                 unsigned(sample[1]),
                 unsigned(sample[2]),
                 unsigned(sample[3]),
                 unsigned(sample[4]),
                 unsigned(sample[5]),
                 unsigned(sample[6]),
                 unsigned(sample[7]),
                 unsigned(sample[8]),
                 unsigned(sample[9]),
                 unsigned(sample[10]),
                 unsigned(sample[11]),
                 unsigned(sample[12]),
                 unsigned(sample[13]),
                 unsigned(sample[14]),
                 unsigned(sample[15]),
                 static_cast<void *>(stream),
                 loggableSocketFD(stream),
                 stream->fslot,
                 int(weAreMaster));
    PRODIGY_DEBUG_FLUSH();
  }

  void acceptHandler(void *socket, int fslot) override
  {
    if (socket == (void *)&brainSocket)
    {
      if (fslot >= 0)
      {
        IPAddress remoteAddress = {};
        String remoteAddressText = {};
        if (prodigySockaddrToIPAddress(reinterpret_cast<struct sockaddr *>(&brain_saddr), remoteAddress, &remoteAddressText) == false)
        {
          basics_log("brain accept unknown sockaddr family=%d fslot=%d\n", int(brain_saddr.ss_family), fslot);
          Ring::queueCloseRaw(fslot);
          brain_saddrlen = sizeof(brain_saddr);
          Ring::queueAccept(&brainSocket, reinterpret_cast<struct sockaddr *>(&brain_saddr), &brain_saddrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
          return;
        }

        BrainView *brain = nullptr;
        brain = findBrainViewByPeerAddress(remoteAddress);

        if (brain == nullptr && remoteAddress.is6 == false)
        {
          brain = findBrainViewByPrivate4(remoteAddress.v4);
        }

        if (brain)
        {
          if (peerSocketActive(brain))
          {
            uint128_t updateSelfPeerKey = updateSelfPeerTrackingKey(brain);
            bool expectedUpdateFollowerReconnect = (weAreMaster && updateSelfState == UpdateSelfState::waitingForFollowerReboots && updateSelfPeerKey != 0 && updateSelfFollowerBootNsByPeerKey.contains(updateSelfPeerKey));
            bool replaceActivePeerWithAcceptedStream = shouldReplaceActivePeerWithAcceptedStream(brain, expectedUpdateFollowerReconnect);
            if (replaceActivePeerWithAcceptedStream)
            {
              PRODIGY_DEBUG_LOG(
                           "prodigy debug brain accept-replace private4=%u reason=%s oldAccepted=%d oldConnected=%d oldQuarantined=%d weConnectToIt=%d oldFd=%d oldFslot=%d newFslot=%d\n",
                           brain->private4,
                           (expectedUpdateFollowerReconnect ? "expected-update-reconnect" : "canonical-accepted-replaces-outbound"),
                           int(brain->currentStreamAccepted),
                           int(brain->connected),
                           int(brain->quarantined),
                           int(brain->weConnectToIt),
                           brain->fd,
                           brain->fslot,
                           fslot);
              PRODIGY_DEBUG_FLUSH();
              if (expectedUpdateFollowerReconnect)
              {
                PRODIGY_DEBUG_LOG(
                             "prodigy updateProdigy follower-accept-replace private4=%u peerKey=%llu oldFslot=%d newFslot=%d\n",
                             brain->private4,
                             (unsigned long long)updateSelfPeerKey,
                             brain->fslot,
                             fslot);
                PRODIGY_DEBUG_FLUSH();
              }
              abandonSocketGeneration(brain);
            }
            else
            {
              // Connector ownership only decides who should initiate. If a known
              // peer has already established a live socket, keep that single
              // stream and drop only true duplicates.
              // Keep a single active accepted stream per peer.
              Ring::queueCloseRaw(fslot);
              brain_saddrlen = sizeof(brain_saddr);
              Ring::queueAccept(&brainSocket, reinterpret_cast<struct sockaddr *>(&brain_saddr), &brain_saddrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
              return;
            }
          }

          // possible it's already completed and is in the CQE queue, so this is the only
          // safe cancellation path before the stale completion drains.
          cancelBrainMissingWaiter(brain, "accept-known");
          cancelBrainReconnectWaiter(brain, "accept-known");

          if (rawStreamIsActive(brain))
          {
            abandonSocketGeneration(brain);
          }

          // A prior queueClose() can already have a tracked close CQE in flight for
          // this BrainView identity. Advance to a fresh transport generation before
          // adopting the replacement accepted slot so that stale close completions
          // from the old generation cannot dispatch against the new stream.
          const uint8_t priorGeneration = brain->ioGeneration;
          brain->bumpIoGeneration();

          // Accepted reconnects must not inherit buffered plaintext/ciphertext
          // or stale peer-verification state from the prior stream generation.
          // Keep the broader BrainView identity/runtime intact and scrub only
          // the transport buffers that can block fresh registration parsing.
          brain->ProdigyTransportTLSStream::reset();
          brain->fslot = fslot;
          brain->isFixedFile = true;
          brain->isNonBlocking = true;
          brain->currentStreamAccepted = true;
          brain->registrationFresh = false;
          brain->noteTransportActivated();
          Ring::publishSocketGeneration(brain);
          PRODIGY_DEBUG_LOG(
                       "prodigy debug brain accept-known private4=%u fd=%d fslot=%d updateState=%u oldConnected=%d oldQuarantined=%d generation=%u priorGeneration=%u transportEpoch=%u\n",
                       brain->private4,
                       brain->fd,
                       brain->fslot,
                       unsigned(updateSelfState),
                       int(brain->connected),
                       int(brain->quarantined),
                       unsigned(brain->ioGeneration),
                       unsigned(priorGeneration),
                       unsigned(brain->transportEpoch));
          PRODIGY_DEBUG_FLUSH();
          queueAcceptedBrainPeerSocketOptions(brain);
          if (ProdigyTransportTLSRuntime::configured() && brain->beginTransportTLS(true) == false)
          {
            queueBrainCloseIfActive(brain, "accept-known-tls-begin-fail");
            brain_saddrlen = sizeof(brain_saddr);
            Ring::queueAccept(&brainSocket, reinterpret_cast<struct sockaddr *>(&brain_saddr), &brain_saddrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
            return;
          }

          if (brain->quarantined)
          {
            brainFound(brain);
          }
          brain->connected = true;
          if (updateSelfState == UpdateSelfState::waitingForFollowerReboots)
          {
            uint128_t peerKey = updateSelfPeerTrackingKey(brain);
            if (peerKey != 0 && updateSelfFollowerBootNsByPeerKey.contains(peerKey))
            {
              updateSelfFollowerReconnectedPeerKeys.insert(peerKey);
            }
          }

          brain->sendRegistration(boottimens, version, getExistingMasterUUID());
          queueLocalPeerAddressCandidates(brain);
          queueUpdateSelfBundleToPeer(brain);
          queueUpdateSelfTransitionToPeer(brain);
          queueUpdateSelfRelinquishToPeer(brain);

          // they will send us a registration too
          Ring::queueRecv(brain);
          PRODIGY_DEBUG_LOG(
                       "prodigy debug brain recv-armed private4=%u fd=%d fslot=%d pendingRecv=%d pendingSend=%d tls=%d negotiated=%d queuedBytes=%llu\n",
                       brain->private4,
                       brain->fd,
                       brain->fslot,
                       int(brain->pendingRecv),
                       int(brain->pendingSend),
                       int(brain->transportTLSEnabled()),
                       int(brain->isTLSNegotiated()),
                       (unsigned long long)brain->queuedSendOutstandingBytes());
          PRODIGY_DEBUG_FLUSH();

          // This is the first post-accept opportunity to arm the server-side
          // TLS receive. Submit now so a rebooted brain does not wait for an
          // unrelated later CQE before it can consume the peer's ClientHello.
          Ring::submitPending();
          refreshBrainPeerHandshakeWatchdog(brain, "accept-known");
        }
        else
        {
          basics_log("brain accept unknown peer address=%s fslot=%d\n", remoteAddressText.c_str(), fslot);
          Ring::queueCloseRaw(fslot); // we could put even better protections in here later.... maybe crypto keys
        }
      }

      brain_saddrlen = sizeof(brain_saddr);
      Ring::queueAccept(&brainSocket, reinterpret_cast<struct sockaddr *>(&brain_saddr), &brain_saddrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
    }
    else if (socket == (void *)&mothershipUnixSocket)
    {
      mothershipUnixAcceptArmed = false;
      PRODIGY_DEBUG_LOG( "prodigy mothership accept transport=unix result=%d master=%d existing=%p listenerPath=%s listenerFD=%d listenerFslot=%d\n",
                   fslot,
                   int(weAreMaster),
                   static_cast<void *>(mothership),
                   mothershipUnixSocketPath.c_str(),
                   mothershipUnixSocket.fd,
                   mothershipUnixSocket.fslot);
      PRODIGY_DEBUG_FLUSH();

      if (fslot >= 0)
      {
        if (weAreMaster == false)
        {
          PRODIGY_DEBUG_LOG( "prodigy mothership accept-close transport=unix reason=follower acceptedFslot=%d path=%s\n",
                       fslot,
                       mothershipUnixSocketPath.c_str());
          PRODIGY_DEBUG_FLUSH();
          Ring::queueCloseRaw(fslot);
        }
        else
        {
          mothership = new Mothership();
          mothership->fslot = fslot;
          mothership->isFixedFile = true;
          mothership->isNonBlocking = true;
          Ring::publishSocketGeneration(mothership);
          if (activateMothershipConnection(mothership) == false)
          {
            delete mothership;
            mothership = nullptr;
            Ring::queueCloseRaw(fslot);
            return;
          }
          const int fixedFD = loggableSocketFD(mothership);
          PRODIGY_DEBUG_LOG( "prodigy mothership accept-adopt transport=unix source=cqe acceptedFslot=%d fixedFD=%d isFixed=%d path=%s\n",
                       fslot,
                       fixedFD,
                       int(mothership->isFixedFile),
                       mothershipUnixSocketPath.c_str());
          PRODIGY_DEBUG_FLUSH();

          RingDispatcher::installMultiplexee(mothership, this);
          queueMothershipReceiveIfNeeded(mothership, "accept-unix-cqe");
        }
      }

      if (weAreMaster)
      {
        queueMothershipUnixAcceptIfNeeded();
      }
    }
  }

  void connectHandler(void *socket, int result) override
  {
    if (brains.contains(static_cast<BrainView *>(socket)))
    {
      BrainView *brain = static_cast<BrainView *>(socket);
      brain->cancelPendingConnect();

      // Non-connector peers only own accepted transports in steady state.
      // Once a peer is healthy again and no longer quarantined, any later
      // connect CQE on the opposite-direction connector is stale fallback
      // work and must not reinitialize the BrainView transport generation.
      if (brain->weConnectToIt == false && brain->currentStreamAccepted == false && brain->quarantined == false)
      {
        basics_log("brain connect ignored non-connector completion private4=%u result=%d fd=%d fslot=%d\n",
                   brain->private4,
                   result,
                   brain->fd,
                   brain->fslot);
        return;
      }

      // Accepted peer ownership can replace an older outbound generation on the
      // same BrainView identity. Ignore any later connect CQEs from that stale
      // outbound generation so we do not re-run client TLS/registration against
      // the accepted stream.
      if (brain->currentStreamAccepted)
      {
        basics_log("brain connect ignored accepted-owned completion private4=%u result=%d fd=%d fslot=%d weConnectToIt=%d\n",
                   brain->private4,
                   result,
                   brain->fd,
                   brain->fslot,
                   int(brain->weConnectToIt));
        return;
      }

      if (result == 0) // connected to brain
      {
        if (Ring::socketIsClosing(brain) || brain->isFixedFile == false || brain->fslot < 0)
        {
          return;
        }

        cancelBrainMissingWaiter(brain, "connect-ok");
        cancelBrainReconnectWaiter(brain, "connect-ok");

        brain->currentStreamAccepted = false;
        brain->connected = true;
        brain->noteTransportActivated();
        brain->registrationFresh = false;
        PRODIGY_DEBUG_LOG(
                     "prodigy debug brain connect-ok private4=%u fd=%d fslot=%d updateState=%u weConnectToIt=%d transportEpoch=%u\n",
                     brain->private4,
                     brain->fd,
                     brain->fslot,
                     unsigned(updateSelfState),
                     int(brain->weConnectToIt),
                     unsigned(brain->transportEpoch));
        PRODIGY_DEBUG_FLUSH();
        if (updateSelfState == UpdateSelfState::waitingForFollowerReboots)
        {
          PRODIGY_DEBUG_LOG( "prodigy updateProdigy peer-connect-ok private4=%u\n", brain->private4);
          PRODIGY_DEBUG_FLUSH();
          uint128_t peerKey = updateSelfPeerTrackingKey(brain);
          if (peerKey != 0 && updateSelfFollowerBootNsByPeerKey.contains(peerKey))
          {
            updateSelfFollowerReconnectedPeerKeys.insert(peerKey);
          }
        }
        brain->connectAttemptSucceded();
        // A successful reconnect is a fresh transport generation. Keep the
        // BrainView identity/reconnect policy but discard prior TLS/BIO and
        // buffered stream state before starting the new handshake.
        brain->ProdigyTransportTLSStream::reset();
        if (ProdigyTransportTLSRuntime::configured() && brain->beginTransportTLS(false) == false)
        {
          if (updateSelfState == UpdateSelfState::waitingForFollowerReboots)
          {
            PRODIGY_DEBUG_LOG( "prodigy updateProdigy peer-connect-tls-fail private4=%u\n", brain->private4);
            PRODIGY_DEBUG_FLUSH();
          }
          queueBrainCloseIfActive(brain, "connect-ok-tls-begin-fail");
          return;
        }
        // reset failure streak on success
        if (brain->machine)
        {
          brain->machine->brainConnectFailStreak = 0;
        }

        if (brain->quarantined)
        {
          brainFound(brain);
        }

        // it might have already registered with us... but that data could be old... it could've rebooted
        brain->sendRegistration(boottimens, version, getExistingMasterUUID());
        queueLocalPeerAddressCandidates(brain);
        queueUpdateSelfBundleToPeer(brain);
        queueUpdateSelfTransitionToPeer(brain);
        queueUpdateSelfRelinquishToPeer(brain);

        // We always need to receive the peer's registration/replication stream after connect.
        Ring::queueRecv(brain);
        refreshBrainPeerHandshakeWatchdog(brain, "connect-ok");
        PRODIGY_DEBUG_LOG(
                     "prodigy debug brain recv-armed private4=%u fd=%d fslot=%d pendingRecv=%d pendingSend=%d tls=%d negotiated=%d queuedBytes=%llu\n",
                     brain->private4,
                     brain->fd,
                     brain->fslot,
                     int(brain->pendingRecv),
                     int(brain->pendingSend),
                     int(brain->transportTLSEnabled()),
                     int(brain->isTLSNegotiated()),
                     (unsigned long long)brain->queuedSendOutstandingBytes());
        PRODIGY_DEBUG_FLUSH();
      }
      else
      {
        brain->connected = false;
        if (updateSelfState == UpdateSelfState::waitingForFollowerReboots)
        {
          PRODIGY_DEBUG_LOG(
                       "prodigy updateProdigy peer-connect-fail private4=%u result=%d attempts=%u budget=%u\n",
                       brain->private4,
                       result,
                       brain->nConnectionAttempts + 1,
                       brain->getAttemptBudget());
          PRODIGY_DEBUG_FLUSH();
        }
        uint32_t attemptNumber = brain->nConnectionAttempts + 1;
        uint32_t attemptBudget = brain->getAttemptBudget();
        uint64_t logKey = connectFailureLogKey(1, brain->private4, result, brain->quarantined);
        if (shouldLogConnectFailure(logKey, attemptNumber, attemptBudget))
        {
          basics_log("brain connect failed stream=%p private4=%u result=%d fslot=%d weConnectToIt=%d quarantined=%d attempt=%u/%u\n",
                     static_cast<void *>(brain), brain->private4, result, brain->fslot, int(brain->weConnectToIt), int(brain->quarantined), attemptNumber, attemptBudget);
        }
        queueBrainCloseIfActive(brain, "connect-fail", result);

        if (brain->connectAttemptFailed())
        {
          if (brain->machine)
          {
            brain->machine->brainConnectFailStreak += 1;
            brain->machine->lastNeuronFailMs = Time::now<TimeResolution::ms>();
          }
          brainMissing(brain);
        }
      }
    }
    else if (neurons.contains(static_cast<NeuronView *>(socket)))
    {
      NeuronView *neuron = static_cast<NeuronView *>(socket);
      neuron->cancelPendingConnect();

      if (result == 0) // connected to neuron
      {
        cancelNeuronReconnectWaiter(neuron, "connect-ok");
        if (Ring::socketIsClosing(neuron) || neuron->isFixedFile == false || neuron->fslot < 0)
        {
          return;
        }

        bool reconnecting = neuron->hadSuccessfulConnection;
        neuron->connected = true;
        neuron->hadSuccessfulConnection = true;
        basics_log("brain neuron connect ok stream=%p uuid=%llu private4=%u fd=%d fslot=%d tlsConfigured=%d\n",
                   static_cast<void *>(neuron),
                   (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                   unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                   neuron->fd,
                   neuron->fslot,
                   int(ProdigyTransportTLSRuntime::configured()));
        PRODIGY_DEBUG_LOG(
                     "brain neuron connect-ok-live stream=%p uuid=%llu private4=%u fd=%d fslot=%d reconnecting=%d tlsConfigured=%d\n",
                     static_cast<void *>(neuron),
                     (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                     unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                     neuron->fd,
                     neuron->fslot,
                     int(reconnecting),
                     int(ProdigyTransportTLSRuntime::configured()));
        PRODIGY_DEBUG_FLUSH();
        neuron->connectAttemptSucceded();
        neuron->rBuffer.clear();
        if (ProdigyTransportTLSRuntime::configured() && neuron->beginTransportTLS(false) == false)
        {
          queueCloseIfActive(neuron);
          return;
        }

        // reset failure streak on success; clear binary update flag
        if (neuron->machine)
        {
          neuron->machine->neuronConnectFailStreak = 0;
          neuron->machine->inBinaryUpdate = false;
        }

        uint64_t pendingBytes = neuron->wBuffer.outstandingBytes();
        if (reconnecting && pendingBytes > 0)
        {
          // Reconnect starts a new stream generation; do not replay buffered payloads
          // from the prior connection because partial delivery state is unknowable.
          PRODIGY_DEBUG_LOG( "brain neuron reconnect drop-buffered uuid=%llu private4=%u bytes=%llu fd=%d fslot=%d hadSuccessfulConnection=%d\n",
                       (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                       unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                       (unsigned long long)pendingBytes,
                       neuron->fd,
                       neuron->fslot,
                       int(neuron->hadSuccessfulConnection));
          PRODIGY_DEBUG_FLUSH();
          neuron->wBuffer.clear();
        }

        const bool requiresNeuronState = ignited && (reconnecting == false || machineNeedsNeuronStateRefresh(neuron->machine));
        Message::construct(neuron->wBuffer, NeuronTopic::registration, requiresNeuronState);
        PRODIGY_DEBUG_LOG(
                     "brain neuron connect-queue-before stream=%p uuid=%llu private4=%u fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d wbytes=%u queued=%llu needsKick=%d\n",
                     static_cast<void *>(neuron),
                     (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                     unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                     neuron->fd,
                     neuron->fslot,
                     int(neuron->pendingSend),
                     int(neuron->pendingRecv),
                     int(neuron->isTLSNegotiated()),
                     int(neuron->tlsPeerVerified),
                     unsigned(neuron->wBuffer.size()),
                     (unsigned long long)neuron->queuedSendOutstandingBytes(),
                     int(neuron->needsTransportTLSSendKick()));
        PRODIGY_DEBUG_FLUSH();
        Ring::queueSend(neuron);
        PRODIGY_DEBUG_LOG(
                     "brain neuron connect-send-submit stream=%p uuid=%llu private4=%u fd=%d fslot=%d pendingSend=%d pendingRecv=%d pendingSendBytes=%u tlsNegotiated=%d peerVerified=%d wbytes=%u queued=%llu needsKick=%d\n",
                     static_cast<void *>(neuron),
                     (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                     unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                     neuron->fd,
                     neuron->fslot,
                     int(neuron->pendingSend),
                     int(neuron->pendingRecv),
                     unsigned(neuron->pendingSendBytes),
                     int(neuron->isTLSNegotiated()),
                     int(neuron->tlsPeerVerified),
                     unsigned(neuron->wBuffer.size()),
                     (unsigned long long)neuron->queuedSendOutstandingBytes(),
                     int(neuron->needsTransportTLSSendKick()));
        PRODIGY_DEBUG_FLUSH();
        basics_log("brain neuron connect arm stream=%p uuid=%llu private4=%u fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d needsSendKick=%d wbytes=%u queued=%llu\n",
                   static_cast<void *>(neuron),
                   (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                   unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                   neuron->fd,
                   neuron->fslot,
                   int(neuron->pendingSend),
                   int(neuron->pendingRecv),
                   int(neuron->isTLSNegotiated()),
                   int(neuron->needsTransportTLSSendKick()),
                   unsigned(neuron->wBuffer.size()),
                   (unsigned long long)neuron->queuedSendOutstandingBytes());

        // the neuron will now send us its state
        Ring::queueRecv(neuron);
        refreshNeuronControlHandshakeWatchdog(neuron, "connect");
        PRODIGY_DEBUG_LOG(
                     "brain neuron connect-recv-submit stream=%p uuid=%llu private4=%u fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d wbytes=%u queued=%llu\n",
                     static_cast<void *>(neuron),
                     (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                     unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                     neuron->fd,
                     neuron->fslot,
                     int(neuron->pendingSend),
                     int(neuron->pendingRecv),
                     int(neuron->isTLSNegotiated()),
                     int(neuron->tlsPeerVerified),
                     unsigned(neuron->wBuffer.size()),
                     (unsigned long long)neuron->queuedSendOutstandingBytes());
        PRODIGY_DEBUG_FLUSH();
        basics_log("brain neuron recv arm stream=%p uuid=%llu private4=%u fd=%d fslot=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d needsSendKick=%d wbytes=%u queued=%llu\n",
                   static_cast<void *>(neuron),
                   (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                   unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                   neuron->fd,
                   neuron->fslot,
                   int(neuron->pendingSend),
                   int(neuron->pendingRecv),
                   int(neuron->isTLSNegotiated()),
                   int(neuron->needsTransportTLSSendKick()),
                   unsigned(neuron->wBuffer.size()),
                   (unsigned long long)neuron->queuedSendOutstandingBytes());

        // The initial neuron-control TLS exchange is queued from inside the connect
        // completion handler. Submit those SQEs immediately so the control channel can
        // begin progressing before unrelated control-plane work re-enters the loop.
        Ring::submitPending();
      }
      else
      {
        uint32_t attemptNumber = neuron->nConnectionAttempts + 1;
        uint32_t attemptBudget = neuron->getAttemptBudget();
        uint32_t machinePrivate4 = (neuron->machine ? neuron->machine->private4 : 0);
        uint64_t logKey = connectFailureLogKey(2, machinePrivate4, result, false);
        if (shouldLogConnectFailure(logKey, attemptNumber, attemptBudget))
        {
          basics_log("neuron connect failed private4=%u result=%d fslot=%d attempt=%u/%u\n",
                     machinePrivate4, result, neuron->fslot, attemptNumber, attemptBudget);
        }
        queueCloseIfActive(neuron);

        if (neuron->connectAttemptFailed())
        {
          if (neuron->machine)
          {
            neuron->machine->neuronConnectFailStreak += 1;
            neuron->machine->lastNeuronFailMs = Time::now<TimeResolution::ms>();
          }
          handleMachineStateChange(neuron->machine, MachineState::missing);
        }
      }
    }
    else if (sshs.contains(static_cast<MachineSSH *>(socket)))
    {
      MachineSSH *ssh = static_cast<MachineSSH *>(socket);
      ssh->cancelPendingConnect();

      if (result == 0) // connected to brain
      {
        if (Ring::socketIsClosing(ssh))
        {
          return;
        }

        ssh->connectAttemptSucceded();
        ssh->execute();
      }
      else
      {
        Machine *sshMachine = nullptr;
        if (ssh->machine && machines.contains(ssh->machine))
        {
          sshMachine = ssh->machine;
        }

        basics_log("ssh connect failed machine=%u result=%d fd=%d fslot=%d fixed=%d\n",
                   (sshMachine ? uint32_t(sshMachine->private4) : 0), result, ssh->fd, ssh->fslot, int(ssh->isFixedFile));
        queueCloseIfActive(ssh);

        if (ssh->connectAttemptFailed())
        {
          // we've failed out on connection tries
          // only master brain

          if (sshMachine)
          {
            handleMachineStateChange(sshMachine, MachineState::unresponsive);
          }
        }
      }
    }
    else
    {
      basics_log("connect handler unmatched socket=%p result=%d\n", socket, result);
    }
  }

  bool shouldReplaceActivePeerWithAcceptedStream(BrainView *brain, bool expectedUpdateFollowerReconnect) const
  {
    if (brain == nullptr)
    {
      return false;
    }

    if (expectedUpdateFollowerReconnect)
    {
      return true;
    }

    if (brain->currentStreamAccepted && brain->connected && brain->quarantined == false)
    {
      return false;
    }

    if (brain->transportTLSEnabled() && (brain->isTLSNegotiated() == false || brain->tlsPeerVerified == false))
    {
      return true;
    }

    // Master-side fallback redials can temporarily connect outward to a peer that
    // canonically owns the connector. When that peer restores its accepted stream,
    // prefer the canonical accepted transport and drop the fallback outbound one.
    return (brain->weConnectToIt == false && brain->currentStreamAccepted == false);
  }

  void brainFound(BrainView *brain)
  {
    // a brain we had quarantined reappeared... either the network restored OR we restarted the neuron program or the machine itself
    cancelBrainLivenessWaiter(brain, "brain-found");
    brain->boottimens = 0; // this will block any new master derivation until after it has registered
    brain->registrationFresh = false;
    brain->quarantined = false;
    brain->weConnectToIt = shouldWeConnectToBrain(brain);
    if (brain->weConnectToIt)
    {
      configureBrainPeerConnectAddress(brain);
    }
  }

  void cancelBrainMissingWaiter(BrainView *brain, const char *reason = nullptr)
  {
    if (brain == nullptr)
    {
      return;
    }

    if (auto it = brainWaiters.find(brain); it != brainWaiters.end())
    {
      TimeoutPacket *packet = it->second;
      packet->flags = uint64_t(BrainTimeoutFlags::canceled);
      brainWaiters.erase(it);
      PRODIGY_DEBUG_LOG(
                   "prodigy debug brain waiter-cancel private4=%u packet=%p reason=%s\n",
                   brain->private4,
                   static_cast<void *>(packet),
                   (reason ? reason : "unspecified"));
      PRODIGY_DEBUG_FLUSH();
      basics_log("brainMissing waiter canceled private4=%u packet=%p reason=%s\n",
                 brain->private4,
                 static_cast<void *>(packet),
                 (reason ? reason : "unspecified"));
    }
  }

  void armBrainMissingWaiterIfAbsent(BrainView *brain, int64_t timeoutMs, const char *reason)
  {
    if (brain == nullptr)
    {
      return;
    }

    if (brainWaiters.contains(brain))
    {
      PRODIGY_DEBUG_LOG(
                   "prodigy debug brain waiter-preserve private4=%u packet=%p reason=%s\n",
                   brain->private4,
                   static_cast<void *>(brainWaiters[brain]),
                   (reason ? reason : "unspecified"));
      PRODIGY_DEBUG_FLUSH();
      basics_log("brainMissing waiter preserve-existing private4=%u reason=%s packet=%p\n",
                 brain->private4,
                 (reason ? reason : "unspecified"),
                 static_cast<void *>(brainWaiters[brain]));
      return;
    }

    TimeoutPacket *timeout = new TimeoutPacket();
    timeout->flags = uint64_t(BrainTimeoutFlags::brainMissing);
    timeout->originator = brain;
    timeout->dispatcher = this;
    timeout->setTimeoutMs(std::max<int64_t>(timeoutMs, 1));

    brainWaiters.insert({brain, timeout});
    PRODIGY_DEBUG_LOG(
                 "prodigy debug brain waiter-arm private4=%u packet=%p reason=%s timeoutMs=%lld\n",
                 brain->private4,
                 static_cast<void *>(timeout),
                 (reason ? reason : "unspecified"),
                 (long long)std::max<int64_t>(timeoutMs, 1));
    PRODIGY_DEBUG_FLUSH();
    basics_log("brainMissing waiter armed private4=%u packet=%p reason=%s timeoutMs=%lld\n",
               brain->private4,
               static_cast<void *>(timeout),
               (reason ? reason : "unspecified"),
               (long long)std::max<int64_t>(timeoutMs, 1));
    Ring::queueTimeout(timeout);
  }

  void cancelBrainReconnectWaiter(BrainView *brain, const char *reason)
  {
    if (brain == nullptr)
    {
      return;
    }

    if (auto it = brainReconnectWaiters.find(brain); it != brainReconnectWaiters.end())
    {
      TimeoutPacket *packet = it->second;
      packet->flags = uint64_t(BrainTimeoutFlags::canceled);
      brainReconnectWaiters.erase(it);
      basics_log("brain reconnect waiter canceled private4=%u packet=%p reason=%s\n",
                 brain->private4,
                 static_cast<void *>(packet),
                 (reason ? reason : "unspecified"));
    }
  }

  void cancelBrainLivenessWaiter(BrainView *brain, const char *reason)
  {
    if (brain == nullptr)
    {
      return;
    }

    if (auto it = brainLivenessWaiters.find(brain); it != brainLivenessWaiters.end())
    {
      TimeoutPacket *packet = it->second;
      packet->flags = uint64_t(BrainTimeoutFlags::canceled);
      brainLivenessWaiters.erase(it);
      basics_log("brain liveness waiter canceled private4=%u packet=%p reason=%s\n",
                 brain->private4,
                 static_cast<void *>(packet),
                 (reason ? reason : "unspecified"));
    }
  }

  void cancelBrainPeerHandshakeWatchdog(BrainView *brain, const char *reason)
  {
    if (brain == nullptr)
    {
      return;
    }

    if (auto it = brainHandshakeWaiters.find(brain); it != brainHandshakeWaiters.end())
    {
      TimeoutPacket *packet = it->second;
      packet->flags = uint64_t(BrainTimeoutFlags::canceled);
      brainHandshakeWaiters.erase(it);
      basics_log("brain peer handshake watchdog canceled private4=%u packet=%p reason=%s\n",
                 brain->private4,
                 static_cast<void *>(packet),
                 (reason ? reason : "unspecified"));
    }
  }

  void cancelAllBrainLivenessWaiters(const char *reason)
  {
    for (auto& [brain, packet] : brainLivenessWaiters)
    {
      if (packet != nullptr)
      {
        packet->flags = uint64_t(BrainTimeoutFlags::canceled);
      }

      basics_log("brain liveness waiter canceled private4=%u packet=%p reason=%s\n",
                 brain ? brain->private4 : 0u,
                 static_cast<void *>(packet),
                 (reason ? reason : "unspecified"));
    }

    brainLivenessWaiters.clear();
  }

  bool brainPeerHandshakeComplete(BrainView *brain)
  {
    if (brain == nullptr || rawStreamIsActive(brain) == false)
    {
      return true;
    }

    if (brain->connected == false)
    {
      return false;
    }

    if (brain->transportTLSEnabled() && (brain->isTLSNegotiated() == false || brain->tlsPeerVerified == false))
    {
      return false;
    }

    return brain->registrationFresh;
  }

  void refreshBrainPeerHandshakeWatchdog(BrainView *brain, const char *reason)
  {
    if (brain == nullptr || brains.contains(brain) == false)
    {
      cancelBrainPeerHandshakeWatchdog(brain, reason);
      return;
    }

    if (brainPeerHandshakeComplete(brain))
    {
      cancelBrainPeerHandshakeWatchdog(brain, reason);
      return;
    }

    cancelBrainPeerHandshakeWatchdog(brain, "refresh");

    TimeoutPacket *timeout = new TimeoutPacket();
    timeout->flags = uint64_t(BrainTimeoutFlags::brainPeerHandshake);
    timeout->originator = brain;
    timeout->identifier = brain->transportEpoch;
    timeout->dispatcher = this;
    timeout->setTimeoutMs(prodigyBrainPeerHandshakeTimeoutMs);
    brainHandshakeWaiters.insert({brain, timeout});
    basics_log("brain peer handshake watchdog armed private4=%u packet=%p reason=%s timeoutMs=%u transportEpoch=%u\n",
               brain->private4,
               static_cast<void *>(timeout),
               (reason ? reason : "unspecified"),
               unsigned(prodigyBrainPeerHandshakeTimeoutMs),
               unsigned(brain->transportEpoch));
    Ring::queueTimeout(timeout);
  }

  int64_t brainPeerReconnectDelayMs(const BrainView *brain) const
  {
    if (brain == nullptr || brain->connectTimeoutMs <= 0)
    {
      return 1;
    }

    return std::max<int64_t>(brain->connectTimeoutMs, 1);
  }

  bool staleDisconnectedFixedFileBrainPeer(BrainView *brain)
  {
    if (brain == nullptr ||
        brain->isFixedFile == false ||
        brain->fslot < 0 ||
        brain->connected ||
        brain->pendingSend ||
        brain->pendingRecv ||
        brain->connectAttemptPending() ||
        Ring::socketIsClosing(brain))
    {
      return false;
    }

    return brain->quarantined ||
           brain->reconnectAfterClose;
  }

  void attemptBrainPeerReconnectNow(BrainView *brain, bool persistentReconnect, const char *reason)
  {
    if (brain == nullptr || brains.contains(brain) == false)
    {
      return;
    }

    if (staleDisconnectedFixedFileBrainPeer(brain))
    {
      basics_log("brain reconnect abandoning stale fixedfile private4=%u reason=%s fd=%d fslot=%d quarantined=%d reconnectAfterClose=%d\n",
                 brain->private4,
                 (reason ? reason : "unspecified"),
                 brain->fd,
                 brain->fslot,
                 int(brain->quarantined),
                 int(brain->reconnectAfterClose));
      abandonSocketGeneration(brain);
    }

    if (rawStreamIsActive(brain) || Ring::socketIsClosing(brain) || brain->connectAttemptPending())
    {
      basics_log("brain reconnect skipped active private4=%u reason=%s active=%d closing=%d pendingConnect=%d\n",
                 brain->private4,
                 (reason ? reason : "unspecified"),
                 int(rawStreamIsActive(brain)),
                 int(Ring::socketIsClosing(brain)),
                 int(brain->connectAttemptPending()));
      return;
    }

    brain->reset();
    brain->recreateSocket();
    configureBrainPeerConnectAddress(brain);

    if (persistentReconnect)
    {
      brain->nConnectionAttempts = 0;
      brain->reconnectAfterClose = true;

      int64_t reconnectWindowMs = int64_t(brain->connectTimeoutMs) * int64_t(brain->nDefaultAttemptsBudget);
      if (reconnectWindowMs < prodigyBrainPeerPersistentReconnectMinMs)
      {
        reconnectWindowMs = prodigyBrainPeerPersistentReconnectMinMs;
      }

      if (brain->connectTimeoutMs > 0)
      {
        brain->attemptForMs(reconnectWindowMs);
      }
      else
      {
        brain->nAttemptsBudget = brain->nDefaultAttemptsBudget;
      }
    }

    if (installBrainPeerSocket(brain))
    {
      brain->attemptConnect();
    }
  }

  void armBrainReconnectWaiterIfAbsent(BrainView *brain, int64_t delayMs, bool persistentReconnect, const char *reason, bool allowCloseInFlight = false)
  {
    if (brain == nullptr)
    {
      return;
    }

    if (staleDisconnectedFixedFileBrainPeer(brain))
    {
      basics_log("brain reconnect waiter abandoning stale fixedfile private4=%u reason=%s fd=%d fslot=%d quarantined=%d reconnectAfterClose=%d\n",
                 brain->private4,
                 (reason ? reason : "unspecified"),
                 brain->fd,
                 brain->fslot,
                 int(brain->quarantined),
                 int(brain->reconnectAfterClose));
      abandonSocketGeneration(brain);
    }

    if (rawStreamIsActive(brain) || (allowCloseInFlight == false && Ring::socketIsClosing(brain)) || brain->connectAttemptPending())
    {
      return;
    }

    if (brainReconnectWaiters.contains(brain))
    {
      basics_log("brain reconnect waiter preserve-existing private4=%u reason=%s packet=%p\n",
                 brain->private4,
                 (reason ? reason : "unspecified"),
                 static_cast<void *>(brainReconnectWaiters[brain]));
      return;
    }

    TimeoutPacket *timeout = new TimeoutPacket();
    timeout->flags = uint64_t(BrainTimeoutFlags::brainPeerReconnect);
    timeout->originator = brain;
    timeout->dispatcher = this;
    timeout->identifier = persistentReconnect ? uint128_t(1) : uint128_t(0);
    timeout->setTimeoutMs(std::max<int64_t>(delayMs, 1));

    brainReconnectWaiters.insert({brain, timeout});
    basics_log("brain reconnect waiter armed private4=%u packet=%p reason=%s timeoutMs=%lld persistent=%d\n",
               brain->private4,
               static_cast<void *>(timeout),
               (reason ? reason : "unspecified"),
               (long long)std::max<int64_t>(delayMs, 1),
               int(persistentReconnect));
    Ring::queueTimeout(timeout);
  }

  void cancelNeuronReconnectWaiter(NeuronView *neuron, const char *reason)
  {
    if (neuron == nullptr)
    {
      return;
    }

    if (auto it = neuronReconnectWaiters.find(neuron); it != neuronReconnectWaiters.end())
    {
      TimeoutPacket *packet = it->second;
      packet->flags = uint64_t(BrainTimeoutFlags::canceled);
      neuronReconnectWaiters.erase(it);
      basics_log("neuron reconnect waiter canceled private4=%u packet=%p reason=%s\n",
                 (neuron->machine ? neuron->machine->private4 : 0u),
                 static_cast<void *>(packet),
                 (reason ? reason : "unspecified"));
    }
  }

  bool neuronControlHandshakeComplete(NeuronView *neuron)
  {
    if (neuron == nullptr || rawStreamIsActive(neuron) == false)
    {
      return true;
    }

    if (neuron->transportTLSEnabled() && (neuron->isTLSNegotiated() == false || neuron->tlsPeerVerified == false))
    {
      return false;
    }

    return ignited == false || brainConfig.datacenterFragment == 0 || machineNeedsNeuronStateRefresh(neuron->machine) == false;
  }

  void cancelNeuronControlHandshakeWatchdog(NeuronView *neuron, const char *reason)
  {
    if (neuron == nullptr)
    {
      return;
    }

    if (auto it = neuronHandshakeWaiters.find(neuron); it != neuronHandshakeWaiters.end())
    {
      TimeoutPacket *packet = it->second;
      packet->flags = uint64_t(BrainTimeoutFlags::canceled);
      neuronHandshakeWaiters.erase(it);
      basics_log("neuron handshake watchdog canceled private4=%u packet=%p reason=%s\n",
                 (neuron->machine ? neuron->machine->private4 : 0u),
                 static_cast<void *>(packet),
                 (reason ? reason : "unspecified"));
    }
  }

  void refreshNeuronControlHandshakeWatchdog(NeuronView *neuron, const char *reason)
  {
    if (neuron == nullptr || weAreMaster == false || neurons.contains(neuron) == false)
    {
      cancelNeuronControlHandshakeWatchdog(neuron, reason);
      return;
    }

    if (neuronControlHandshakeComplete(neuron))
    {
      cancelNeuronControlHandshakeWatchdog(neuron, reason);
      return;
    }

    cancelNeuronControlHandshakeWatchdog(neuron, "refresh");

    TimeoutPacket *timeout = new TimeoutPacket();
    timeout->flags = uint64_t(BrainTimeoutFlags::neuronControlHandshake);
    timeout->originator = neuron;
    timeout->identifier = neuron->machine ? neuron->machine->uuid : 0;
    timeout->dispatcher = this;
    timeout->setTimeoutMs(prodigyBrainNeuronControlHandshakeTimeoutMs);
    neuronHandshakeWaiters.insert({neuron, timeout});
    basics_log("neuron handshake watchdog armed private4=%u packet=%p reason=%s timeoutMs=%u\n",
               (neuron->machine ? neuron->machine->private4 : 0u),
               static_cast<void *>(timeout),
               (reason ? reason : "unspecified"),
               unsigned(prodigyBrainNeuronControlHandshakeTimeoutMs));
    Ring::queueTimeout(timeout);
  }

  int64_t neuronControlReconnectDelayMs(const NeuronView *neuron) const
  {
    if (neuron == nullptr || neuron->connectTimeoutMs <= 0)
    {
      return 1;
    }

    return std::max<int64_t>(neuron->connectTimeoutMs, 1);
  }

  void attemptNeuronControlReconnectNow(NeuronView *neuron, const char *reason)
  {
    if (neuron == nullptr || neurons.contains(neuron) == false)
    {
      return;
    }

    if (weAreMaster == false || neuron->shouldReconnect() == false)
    {
      disarmNeuronControlReconnect(neuron);
      return;
    }

    if (rawStreamIsActive(neuron) || neuron->connectAttemptPending())
    {
      basics_log("neuron reconnect skipped active private4=%u reason=%s active=%d closing=%d pendingConnect=%d\n",
                 (neuron->machine ? neuron->machine->private4 : 0u),
                 (reason ? reason : "unspecified"),
                 int(rawStreamIsActive(neuron)),
                 int(Ring::socketIsClosing(neuron)),
                 int(neuron->connectAttemptPending()));
      return;
    }

    if (Ring::socketIsClosing(neuron))
    {
      basics_log("neuron reconnect deferred close-in-flight private4=%u reason=%s timeoutMs=%lld\n",
                 (neuron->machine ? neuron->machine->private4 : 0u),
                 (reason ? reason : "unspecified"),
                 (long long)neuronControlReconnectDelayMs(neuron));
      armNeuronReconnectWaiterIfAbsent(neuron, neuronControlReconnectDelayMs(neuron), "neuron-reconnect-close-in-flight", true, true);
      return;
    }

    neuron->ProdigyTransportTLSStream::reset();
    neuron->recreateSocket();
    if (installNeuronControlSocket(neuron))
    {
      neuron->attemptConnect();
    }
  }

  void armNeuronReconnectWaiterIfAbsent(NeuronView *neuron, int64_t delayMs, const char *reason, bool allowCloseInFlight = false, bool allowActiveTransport = false)
  {
    if (neuron == nullptr || weAreMaster == false || neuron->shouldReconnect() == false)
    {
      return;
    }

    if ((allowActiveTransport == false && rawStreamIsActive(neuron)) || (allowCloseInFlight == false && Ring::socketIsClosing(neuron)) || neuron->connectAttemptPending())
    {
      return;
    }

    if (neuronReconnectWaiters.contains(neuron))
    {
      basics_log("neuron reconnect waiter preserve-existing private4=%u reason=%s packet=%p\n",
                 (neuron->machine ? neuron->machine->private4 : 0u),
                 (reason ? reason : "unspecified"),
                 static_cast<void *>(neuronReconnectWaiters[neuron]));
      return;
    }

    TimeoutPacket *timeout = new TimeoutPacket();
    timeout->flags = uint64_t(BrainTimeoutFlags::neuronControlReconnect);
    timeout->originator = neuron;
    timeout->dispatcher = this;
    timeout->setTimeoutMs(std::max<int64_t>(delayMs, 1));

    neuronReconnectWaiters.insert({neuron, timeout});
    basics_log("neuron reconnect waiter armed private4=%u packet=%p reason=%s timeoutMs=%lld\n",
               (neuron->machine ? neuron->machine->private4 : 0u),
               static_cast<void *>(timeout),
               (reason ? reason : "unspecified"),
               (long long)std::max<int64_t>(delayMs, 1));
    Ring::queueTimeout(timeout);
  }

  void refreshMasterPeerLivenessWaiter(BrainView *brain, const char *reason)
  {
    if (brain == nullptr || nBrains <= 1 || brainPeerHeartbeatTimeoutMs == 0 || Ring::getRingFD() <= 0)
    {
      return;
    }

    if (peerRepresentsCurrentMasterForLiveness(brain) == false)
    {
      cancelBrainLivenessWaiter(brain, reason);
      return;
    }

    if (rawStreamIsActive(brain) == false || brain->connected == false || (brain->transportTLSEnabled() && (brain->isTLSNegotiated() == false || brain->tlsPeerVerified == false)))
    {
      return;
    }

    cancelBrainLivenessWaiter(brain, reason);

    TimeoutPacket *timeout = new TimeoutPacket();
    timeout->flags = uint64_t(BrainTimeoutFlags::brainPeerLiveness);
    timeout->originator = brain;
    timeout->dispatcher = this;
    timeout->setTimeoutMs(std::max<int64_t>(brainPeerHeartbeatTimeoutMs, 1));

    brainLivenessWaiters.insert({brain, timeout});
    basics_log("brain liveness waiter armed private4=%u packet=%p reason=%s timeoutMs=%lld\n",
               brain->private4,
               static_cast<void *>(timeout),
               (reason ? reason : "unspecified"),
               (long long)std::max<int64_t>(brainPeerHeartbeatTimeoutMs, 1));
    Ring::queueTimeout(timeout);
  }

  float calculateAliveBrainRatio(void)
  {
    uint32_t nBrainsAlive = 1;

    for (BrainView *bv : brains)
    {
      if (bv->quarantined == false)
      {
        nBrainsAlive += 1;
      }
    }

    // nBrains is computed as peers + self during getBrains().
    return (nBrains > 0)
               ? float(nBrainsAlive) / float(nBrains)
               : 0.0f;
  }

  bool maybeDeriveOnMasterMissingAgreement(const char *reason)
  {
    // Local vote must agree as well; then require currently reachable active peers.
    bool everyoneAgrees = isMasterMissing;
    uint32_t nBrainsAlive = 1;

    for (BrainView *peer : brains)
    {
      if (peerEligibleForClusterQuorum(peer) == false)
      {
        continue;
      }
      if (peerSocketActive(peer) == false)
      {
        continue;
      }
      nBrainsAlive += 1;
      if (peer->isMasterMissing == false)
      {
        everyoneAgrees = false;
      }
    }

    if (nBrainsAlive <= 1)
    {
      everyoneAgrees = false;
    }

    basics_log("masterMissing agreement reason=%s everyone=%d alive=%u local=%d\n",
               (reason ? reason : "unspecified"),
               int(everyoneAgrees),
               nBrainsAlive,
               int(isMasterMissing));

    if (everyoneAgrees)
    {
      deriveMasterBrainIf();
      return true;
    }

    return false;
  }

  void driveMasterPeerIdentityConvergence(BrainView *peer, int64_t nowMs)
  {
    if (weAreMaster == false || peer == nullptr)
    {
      return;
    }

    bool peerAcknowledgedCurrentMaster = (peerHasFreshExistingMasterClaim(peer) && peer->existingMasterUUID == selfBrainUUID());
    if (peerAcknowledgedCurrentMaster)
    {
      return;
    }

    if (peerSocketActive(peer))
    {
      if (peer->lastMasterRegistrationAdvertiseMs == 0 || nowMs - peer->lastMasterRegistrationAdvertiseMs >= int64_t(brainPeerHeartbeatIntervalMs))
      {
        peer->sendRegistration(boottimens, version, getExistingMasterUUID());
        peer->lastMasterRegistrationAdvertiseMs = nowMs;
      }
      return;
    }

    peer->weConnectToIt = shouldWeConnectToBrain(peer);
    const bool reconnectAlreadyInFlight = (rawStreamIsActive(peer) || Ring::socketIsClosing(peer) || peer->connectAttemptPending());
    if (reconnectAlreadyInFlight == false)
    {
      if (peer->weConnectToIt)
      {
        armOutboundPeerReconnect(peer);
      }
      else
      {
        armOutboundPeerReconnect(peer, true);
      }
    }
    else if (peer->weConnectToIt == false)
    {
      peer->forceConnectorOwnershipUntilMasterAck = true;
    }
  }

  void runBrainPeerHeartbeatTick(void)
  {
    if (brainPeerHeartbeatIntervalMs == 0 || brainPeerHeartbeatTimeoutMs == 0)
    {
      return;
    }

    int64_t nowMs = Time::now<TimeResolution::ms>();
    int64_t tickLagMs = 0;
    if (lastBrainPeerHeartbeatTickMs > 0 && nowMs > lastBrainPeerHeartbeatTickMs)
    {
      tickLagMs = nowMs - lastBrainPeerHeartbeatTickMs;
    }
    lastBrainPeerHeartbeatTickMs = nowMs;
    const bool localHeartbeatTickLagged = (tickLagMs >= int64_t(brainPeerHeartbeatTimeoutMs));
    for (BrainView *peer : brains)
    {
      auto noteMasterPeerHeartbeatEligibility = [&](uint8_t state, const char *reason) -> void {
        if (peer == nullptr || peerRepresentsCurrentMasterForLiveness(peer) == false || peer->peerHeartbeatEligibilityState == state)
        {
          return;
        }

        peer->peerHeartbeatEligibilityState = state;
        basics_log("brainPeerHeartbeat eligibility private4=%u state=%u reason=%s rawActive=%d connected=%d tls=%d negotiated=%d peerVerified=%d registrationFresh=%d fd=%d fslot=%d transportEpoch=%u lastAckAgoMs=%lld lastRecvAgoMs=%lld\n",
                   peer->private4,
                   unsigned(state),
                   (reason ? reason : "unspecified"),
                   int(rawStreamIsActive(peer)),
                   int(peer->connected),
                   int(peer->transportTLSEnabled()),
                   int(peer->isTLSNegotiated()),
                   int(peer->tlsPeerVerified),
                   int(peer->registrationFresh),
                   peer->fd,
                   peer->fslot,
                   unsigned(peer->transportEpoch),
                   (long long)(peer->lastHeartbeatAckMs > 0 ? (nowMs - peer->lastHeartbeatAckMs) : -1),
                   (long long)(peer->lastReceiveMs > 0 ? (nowMs - peer->lastReceiveMs) : -1));
        PRODIGY_DEBUG_LOG(
                     "prodigy debug brainPeerHeartbeat eligibility private4=%u state=%u reason=%s rawActive=%d connected=%d tls=%d negotiated=%d peerVerified=%d registrationFresh=%d fd=%d fslot=%d transportEpoch=%u lastAckAgoMs=%lld lastRecvAgoMs=%lld\n",
                     peer->private4,
                     unsigned(state),
                     (reason ? reason : "unspecified"),
                     int(rawStreamIsActive(peer)),
                     int(peer->connected),
                     int(peer->transportTLSEnabled()),
                     int(peer->isTLSNegotiated()),
                     int(peer->tlsPeerVerified),
                     int(peer->registrationFresh),
                     peer->fd,
                     peer->fslot,
                     unsigned(peer->transportEpoch),
                     (long long)(peer->lastHeartbeatAckMs > 0 ? (nowMs - peer->lastHeartbeatAckMs) : -1),
                     (long long)(peer->lastReceiveMs > 0 ? (nowMs - peer->lastReceiveMs) : -1));
        PRODIGY_DEBUG_FLUSH();
      };

      if (peer == nullptr || rawStreamIsActive(peer) == false)
      {
        noteMasterPeerHeartbeatEligibility(1, "raw-inactive");
        driveMasterPeerIdentityConvergence(peer, nowMs);
        continue;
      }

      if (peer->connected == false)
      {
        noteMasterPeerHeartbeatEligibility(2, "disconnected");
        driveMasterPeerIdentityConvergence(peer, nowMs);
        continue;
      }

      if (peer->transportTLSEnabled() && (peer->isTLSNegotiated() == false || peer->tlsPeerVerified == false))
      {
        noteMasterPeerHeartbeatEligibility(3, "tls-unready");
        driveMasterPeerIdentityConvergence(peer, nowMs);
        continue;
      }

      noteMasterPeerHeartbeatEligibility(4, "eligible");

      int64_t lastPeerLivenessMs = peer->lastHeartbeatAckMs;
      if (peer->lastReceiveMs > lastPeerLivenessMs)
      {
        lastPeerLivenessMs = peer->lastReceiveMs;
      }

      const bool heartbeatOutstanding = (peer->lastHeartbeatSentNonce != peer->lastHeartbeatAckNonce);
      if (heartbeatOutstanding && peer->lastHeartbeatSendMs > 0 && nowMs - peer->lastHeartbeatSendMs >= int64_t(brainPeerHeartbeatTimeoutMs))
      {
        if (localHeartbeatTickLagged)
        {
          basics_log("brainPeerHeartbeat stale-deferred private4=%u tickLagMs=%lld timeoutMs=%u transportEpoch=%u lastAckNonce=%llu lastSentNonce=%llu\n",
                     peer->private4,
                     (long long)tickLagMs,
                     brainPeerHeartbeatTimeoutMs,
                     unsigned(peer->transportEpoch),
                     (unsigned long long)peer->lastHeartbeatAckNonce,
                     (unsigned long long)peer->lastHeartbeatSentNonce);
          PRODIGY_DEBUG_LOG(
                       "prodigy debug brainPeerHeartbeat stale-deferred private4=%u tickLagMs=%lld timeoutMs=%u transportEpoch=%u lastAckNonce=%llu lastSentNonce=%llu\n",
                       peer->private4,
                       (long long)tickLagMs,
                       brainPeerHeartbeatTimeoutMs,
                       unsigned(peer->transportEpoch),
                       (unsigned long long)peer->lastHeartbeatAckNonce,
                       (unsigned long long)peer->lastHeartbeatSentNonce);
          PRODIGY_DEBUG_FLUSH();
          peer->lastHeartbeatSendMs = nowMs;
          driveMasterPeerIdentityConvergence(peer, nowMs);
          continue;
        }

        peer->confirmedMissingTransportEpoch = peer->transportEpoch;
        basics_log("brainPeerHeartbeat stale private4=%u lastLivenessAgoMs=%lld lastAckAgoMs=%lld timeoutMs=%u transportEpoch=%u lastAckNonce=%llu lastSentNonce=%llu lastReceiveAgoMs=%lld lastSendAgoMs=%lld\n",
                   peer->private4,
                   (long long)(nowMs - lastPeerLivenessMs),
                   (long long)(peer->lastHeartbeatAckMs > 0 ? (nowMs - peer->lastHeartbeatAckMs) : -1),
                   brainPeerHeartbeatTimeoutMs,
                   unsigned(peer->transportEpoch),
                   (unsigned long long)peer->lastHeartbeatAckNonce,
                   (unsigned long long)peer->lastHeartbeatSentNonce,
                   (long long)(peer->lastReceiveMs > 0 ? (nowMs - peer->lastReceiveMs) : -1),
                   (long long)(peer->lastHeartbeatSendMs > 0 ? (nowMs - peer->lastHeartbeatSendMs) : -1));
        PRODIGY_DEBUG_LOG(
                     "prodigy debug brainPeerHeartbeat stale private4=%u lastLivenessAgoMs=%lld lastAckAgoMs=%lld timeoutMs=%u transportEpoch=%u lastAckNonce=%llu lastSentNonce=%llu lastReceiveAgoMs=%lld lastSendAgoMs=%lld\n",
                     peer->private4,
                     (long long)(nowMs - lastPeerLivenessMs),
                     (long long)(peer->lastHeartbeatAckMs > 0 ? (nowMs - peer->lastHeartbeatAckMs) : -1),
                     brainPeerHeartbeatTimeoutMs,
                     unsigned(peer->transportEpoch),
                     (unsigned long long)peer->lastHeartbeatAckNonce,
                     (unsigned long long)peer->lastHeartbeatSentNonce,
                     (long long)(peer->lastReceiveMs > 0 ? (nowMs - peer->lastReceiveMs) : -1),
                     (long long)(peer->lastHeartbeatSendMs > 0 ? (nowMs - peer->lastHeartbeatSendMs) : -1));
        PRODIGY_DEBUG_FLUSH();
        queueBrainCloseIfActive(peer, "peer-heartbeat-timeout");
        brainMissing(peer);
        continue;
      }

      driveMasterPeerIdentityConvergence(peer, nowMs);

      const bool heartbeatDue = (peer->lastHeartbeatSendMs == 0 || nowMs - peer->lastHeartbeatSendMs >= int64_t(brainPeerHeartbeatIntervalMs) || (lastPeerLivenessMs > 0 && nowMs - lastPeerLivenessMs >= int64_t(brainPeerHeartbeatIntervalMs)));
      if (heartbeatOutstanding == false && heartbeatDue)
      {
        peer->sendPeerHeartbeat(nowMs);
      }
    }
  }

  void brainMissing(BrainView *brain)
  {
    const bool peerWasCurrentMaster = peerRepresentsCurrentMasterForLiveness(brain);
    brain->connected = false;
    cancelBrainReconnectWaiter(brain, "brain-missing");
    cancelBrainLivenessWaiter(brain, "brain-missing");
    const bool reconnectAlreadyInFlight = (Ring::socketIsClosing(brain) || brain->connectAttemptPending());
    bool expectedUpdateFollowerReboot = (updateSelfState == UpdateSelfState::waitingForFollowerReboots &&
                                         updateSelfFollowerBootNsByPeerKey.contains(updateSelfPeerTrackingKey(brain)));

    // During coordinated updateProdigy follower reboots, temporary peer loss is expected.
    // Keep the reconnect path armed, but suppress the failure remediation/election
    // side effects until the reboot-registration window completes.

    // we either got here because we failed 3 times in a row trying to connect (or reconnect) to a brain, OR we were never connected to / the connection broke and they never
    // reconnected to us

    bool firstMissingTransition = (brain->quarantined == false);
    brain->weConnectToIt = shouldWeConnectToBrain(brain);
    // On first missing transition, extend outbound reconnect attempts so transient
    // outages can heal without dropping reconnect permanently after the default budget.
    if (brain->weConnectToIt && firstMissingTransition)
    {
      configureBrainPeerConnectAddress(brain);
      brain->nConnectionAttempts = 0;
      brain->reconnectAfterClose = true;

      int64_t recoveryReconnectWindowMs = int64_t(brain->connectTimeoutMs) * int64_t(brain->nDefaultAttemptsBudget);
      if (recoveryReconnectWindowMs < prodigyBrainPeerRecoveryReconnectMinMs)
      {
        recoveryReconnectWindowMs = prodigyBrainPeerRecoveryReconnectMinMs;
      }

      if (brain->connectTimeoutMs > 0)
      {
        brain->attemptForMs(recoveryReconnectWindowMs);
      }
      else
      {
        brain->nAttemptsBudget = brain->nDefaultAttemptsBudget;
      }
    }

    if (expectedUpdateFollowerReboot)
    {
      if (weAreMaster && brain->weConnectToIt)
      {
        armOutboundPeerReconnect(brain);
      }

      co_return;
    }

    // One-time side effects (quarantine transition, majority/election flow) only on first missing transition.
    if (firstMissingTransition)
    {
      brain->quarantined = true;
      brain->registrationFresh = false;
      brain->existingMasterUUID = 0;
      basics_log("brainMissing private4=%u weAreMaster=%d peerWasMaster=%d weConnectToIt=%d\n",
                 brain->private4, int(weAreMaster), int(peerWasCurrentMaster), int(brain->weConnectToIt));

      // Master-side fallback: if a peer link drops, proactively dial it even when
      // canonical connector ownership is the opposite direction. Do not stack a
      // second forced reconnect on top of a close/connect already in flight.
      if (weAreMaster)
      {
        if (reconnectAlreadyInFlight == false)
        {
          if (brain->weConnectToIt)
          {
            armOutboundPeerReconnect(brain);
          }
          else
          {
            armOutboundPeerReconnect(brain, true);
          }
        }
        else if (brain->weConnectToIt == false)
        {
          brain->forceConnectorOwnershipUntilMasterAck = true;
        }
      }

      if (weAreMaster)
      {
        masterQuorumDegraded = true;
        bool retainMaster = shouldRetainMasterControlOnBrainLoss();
        if (retainMaster)
        {
          // Do not evacuate machine containers from a brain-link miss alone.
          // Network partitions can isolate the master from peers without machine failure,
          // and aggressive evacuation here causes destructive split-brain churn.
          // Machine/neuron health paths remain the source of truth for draining.
        }
        else
        {
          // no majority so we definitely forfeit master status
          forfeitMasterStatus();
        }
      }
      else
      {
        if (peerWasCurrentMaster)
        {
          // the master brain is missing
          isMasterMissing = true;
          basics_log("brainMissing detected master private4=%u, starting masterMissing gossip\n", brain->private4);

          for (BrainView *bv : brains)
          {
            if (bv->quarantined == false)
            {
              // tell it the master is lost to us
              // chat with the other peers to see if they agree
              // then we'd select a new master
              // a major utiltiy of this is to test connectivity... it's possible this breaks the connection.. aka this would cascade the failure discovery
              bv->sendMasterMissing();

              // and if they all fail, we'll end up in our if (allQuarantined) bracket below
            }
          }

          // Re-evaluate after publishing our local vote. A reachable peer may
          // already have reported the master missing before our own liveness
          // timeout completed; derivation still requires connected-majority checks.
          maybeDeriveOnMasterMissingAgreement("brain-missing-local-vote");
        }

        if (isMasterMissing) // if master fails first, then the other brain fails, we'd run through here twice, otherwise once
        {
          bool allQuarantined = true;

          for (BrainView *bv : brains)
          {
            if (bv->quarantined == false)
            {
              allQuarantined = false;
              break;
            }
          }

          if (allQuarantined) // we could only be isolated if every brain connection fails.. aka all quarantined.. so this can only run once, one all have failed
          {
            basics_log("brainMissing all peers quarantined; evaluating isolated election nBrains=%u\n", nBrains);

            // In multi-brain clusters, isolated self-election is unsafe and can
            // create split-brain during transient partitions/heal windows.
            // Stay degraded and keep reconnecting until quorum gossip can derive.
            if (nBrains > 1)
            {
              co_return;
            }

            // Single-brain compatibility path.
            resetMasterBrainAssignment();
            basics_log("brainMissing elect-self reason=single-brain-isolation\n");
            selfElectAsMaster("brainMissing:single-brain-isolation");
          }
          else
          {
            // wait on those peers to respond about the missing master.. we would need a majority to elect (or if they all fail and their switches are still alive
            // we'd self elect in the above bracket)
          }
        }
      }
    }
  }

  void closeHandler(void *socket) override
  {
    if (socket == (void *)&brainSocket)
    {
      basics_log("brain listener socket closed private4=%u; rearming\n", thisNeuron->private4.v4);
      RingDispatcher::eraseMultiplexee(&brainSocket);

      brainSocket.recreateSocket();
      brainSocket.setIPVersion(AF_INET6);
      if (uint32_t maxSegmentSize = controlPlaneTCPMaxSegmentSize(AF_INET6); maxSegmentSize > 0)
      {
        (void)prodigySetTCPMaxSegmentSize(brainSocket.fd, maxSegmentSize);
      }
      setsockopt(brainSocket.fd, IPPROTO_IPV6, IPV6_V6ONLY, (const int[]) {0}, sizeof(int));
      brainSocket.setKeepaliveTimeoutSeconds(brainPeerKeepaliveSeconds);
      brainSocket.setSaddr("::"_ctv, uint16_t(ReservedPorts::brain));
      brainSocket.bindThenListen();

      RingDispatcher::installMultiplexee(&brainSocket, this);
      Ring::installFDIntoFixedFileSlot(&brainSocket);
      brain_saddrlen = sizeof(brain_saddr);
      Ring::queueAccept(&brainSocket, reinterpret_cast<struct sockaddr *>(&brain_saddr), &brain_saddrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
      co_return;
    }

    if (brains.contains(static_cast<BrainView *>(socket)))
    {
      BrainView *brain = static_cast<BrainView *>(socket);
      cancelBrainLivenessWaiter(brain, "close");
      cancelBrainPeerHandshakeWatchdog(brain, "close");
      uint128_t updateSelfPeerKey = updateSelfPeerTrackingKey(brain);
      PRODIGY_DEBUG_LOG(
                   "prodigy debug brain close stream=%p private4=%u fd=%d fslot=%d isFixed=%d updateState=%u weConnectToIt=%d forceConnectorOwnership=%d accepted=%d connected=%d pendingSend=%d pendingRecv=%d tls=%d negotiated=%d peerVerified=%d registrationFresh=%d quarantined=%d isMasterBrain=%d existingMasterUUID=%llu noMasterYet=%d weAreMaster=%d transportEpoch=%u queuedCloseEpoch=%u processedCloseEpoch=%u confirmedMissingEpoch=%u queuedBytes=%llu wbytes=%u rbytes=%llu peerKey=%llu\n",
                   static_cast<void *>(brain),
                   brain->private4,
                   brain->fd,
                   brain->fslot,
                   int(brain->isFixedFile),
                   unsigned(updateSelfState),
                   int(brain->weConnectToIt),
                   int(brain->forceConnectorOwnershipUntilMasterAck),
                   int(brain->currentStreamAccepted),
                   int(brain->connected),
                   int(brain->pendingSend),
                   int(brain->pendingRecv),
                   int(brain->transportTLSEnabled()),
                   int(brain->isTLSNegotiated()),
                   int(brain->tlsPeerVerified),
                   int(brain->registrationFresh),
                   int(brain->quarantined),
                   int(brain->isMasterBrain),
                   (unsigned long long)brain->existingMasterUUID,
                   int(noMasterYet),
                   int(weAreMaster),
                   unsigned(brain->transportEpoch),
                   unsigned(brain->queuedCloseTransportEpoch),
                   unsigned(brain->processedCloseTransportEpoch),
                   unsigned(brain->confirmedMissingTransportEpoch),
                   (unsigned long long)brain->queuedSendOutstandingBytes(),
                   uint32_t(brain->wBuffer.outstandingBytes()),
                   (unsigned long long)brain->rBuffer.outstandingBytes(),
                   (unsigned long long)updateSelfPeerKey);
      PRODIGY_DEBUG_FLUSH();
      const bool closeConfirmedMissing = (brain->confirmedMissingTransportEpoch != 0 && brain->confirmedMissingTransportEpoch == brain->transportEpoch);
      const bool closeTargetHasInstalledTransport = (brain->isFixedFile
                                                         ? (brain->fslot >= 0)
                                                         : (brain->fd >= 0));
      const bool closeArrivedOnActiveReplacement = (closeTargetHasInstalledTransport && brain->connected && brain->confirmedMissingTransportEpoch != brain->transportEpoch && brain->queuedCloseTransportEpoch != brain->transportEpoch && (brain->queuedCloseTransportEpoch != 0 || (brain->processedCloseTransportEpoch != 0 && brain->processedCloseTransportEpoch != brain->transportEpoch)));
      const bool staleCloseAfterTransportAdvance = (brain->queuedCloseTransportEpoch != 0 && brain->queuedCloseTransportEpoch != brain->transportEpoch);
      if (closeArrivedOnActiveReplacement)
      {
        basics_log("brain close ignored stale transport private4=%u queuedCloseEpoch=%u transportEpoch=%u weConnectToIt=%d accepted=%d fd=%d fslot=%d\n",
                   brain->private4,
                   unsigned(brain->queuedCloseTransportEpoch),
                   unsigned(brain->transportEpoch),
                   int(brain->weConnectToIt),
                   int(brain->currentStreamAccepted),
                   brain->fd,
                   brain->fslot);
        brain->queuedCloseTransportEpoch = 0;
        co_return;
      }
      if (staleCloseAfterTransportAdvance)
      {
        basics_log("brain close processing inactive advanced transport private4=%u queuedCloseEpoch=%u transportEpoch=%u weConnectToIt=%d accepted=%d fd=%d fslot=%d\n",
                   brain->private4,
                   unsigned(brain->queuedCloseTransportEpoch),
                   unsigned(brain->transportEpoch),
                   int(brain->weConnectToIt),
                   int(brain->currentStreamAccepted),
                   brain->fd,
                   brain->fslot);
        brain->queuedCloseTransportEpoch = 0;
      }
      brain->processedCloseTransportEpoch = brain->transportEpoch;
      brain->confirmedMissingTransportEpoch = 0;
      const bool reconnectOwned = peerReconnectOwned(brain);
      const bool inertDuplicateConnectorClose = (reconnectOwned && brain->reconnectAfterClose && brain->uuid != 0 && brain->queuedCloseTransportEpoch == 0 && rawStreamIsActive(brain) == false && brain->connected == false && brain->currentStreamAccepted == false && brain->connectAttemptPending() == false && brain->pendingSend == false && brain->pendingRecv == false && brain->registrationFresh == false && brain->tlsPeerVerified == false && brain->isTLSNegotiated() == false && brain->queuedSendOutstandingBytes() == 0 && brain->wBuffer.outstandingBytes() == 0 && brain->rBuffer.outstandingBytes() == 0);
      if (updateSelfPeerKey != 0)
      {
        updateSelfBundleIssuedPeerKeys.erase(updateSelfPeerKey);
        // Keep the transition one-shot sticky across the intentional follower
        // reboot close. Reissuing it on reconnect can bounce the fresh process
        // again before its registration lands and the master credits the reboot.
        updateSelfRelinquishIssuedPeerKeys.erase(updateSelfPeerKey);
      }
      brain->connected = false;
      brain->cancelPendingConnect();
      brain->registrationFresh = false;
      // The next accepted/outbound peer stream must not inherit TLS/BIO or
      // buffered send/receive state from the closed socket generation.
      brain->ProdigyTransportTLSStream::reset();
      bool expectedOSUpdateFollowerReboot = (brain->machine != nullptr && brain->machine->state == MachineState::updatingOS && brain->machine->osUpdateCommandIssued);
      bool expectedUpdateFollowerReboot = ((updateSelfState == UpdateSelfState::waitingForFollowerReboots && updateSelfFollowerBootNsByPeerKey.contains(updateSelfPeerTrackingKey(brain))) || expectedOSUpdateFollowerReboot);

      brain->cancelSuspended();
      if (closeConfirmedMissing && expectedOSUpdateFollowerReboot && brain->machine != nullptr && brain->machine->state == MachineState::updatingOS)
      {
        handleMachineStateChange(brain->machine, MachineState::missing);
      }

      if (reconnectOwned)
      {
        if (closeConfirmedMissing)
        {
          basics_log("brain close liveness-confirmed connector deferring missing vote private4=%u transportEpoch=%u\n",
                     brain->private4,
                     unsigned(brain->transportEpoch));
        }

        const bool armConnectorMasterWaiter = (expectedUpdateFollowerReboot == false && peerRepresentsCurrentMasterForLiveness(brain) && nBrains > 1);
        PRODIGY_DEBUG_LOG(
                     "prodigy debug brain close-master-eval private4=%u closeConfirmedMissing=%d expectedUpdateFollowerReboot=%d arm=%d inert=%d reconnectOwned=%d nBrains=%u isMasterBrain=%d existingMasterUUID=%llu uuid=%llu noMasterYet=%d weAreMaster=%d\n",
                     brain->private4,
                     int(closeConfirmedMissing),
                     int(expectedUpdateFollowerReboot),
                     int(armConnectorMasterWaiter),
                     int(inertDuplicateConnectorClose),
                     int(reconnectOwned),
                     nBrains,
                     int(brain->isMasterBrain),
                     (unsigned long long)brain->existingMasterUUID,
                     (unsigned long long)brain->uuid,
                     int(noMasterYet),
                     int(weAreMaster));
        PRODIGY_DEBUG_FLUSH();
        if (armConnectorMasterWaiter == false)
        {
          if (inertDuplicateConnectorClose == false || brainWaiters.contains(brain) == false)
          {
            cancelBrainMissingWaiter(brain, "close-connector-reconnect");
          }
        }
        else
        {
          armBrainMissingWaiterIfAbsent(
              brain,
              brain->nDefaultAttemptsBudget * brain->connectTimeoutMs + prodigyBrainPeerInboundMissingSlackMs,
              "close-connector-master");
        }
        if (inertDuplicateConnectorClose)
        {
          basics_log("brain close ignored inert duplicate connector private4=%u weConnectToIt=%d reconnectAfterClose=%d\n",
                     brain->private4,
                     int(brain->weConnectToIt),
                     int(brain->reconnectAfterClose));
          co_return;
        }

        // this connection might've broken spuriously, or due to a network failure (maybe discovered when we sent a masterMissing message)
        // but regardless try to reconnect, if not we'll then assume and handle the failure
        if (brain->shouldReconnect())
        {
          armBrainReconnectWaiterIfAbsent(
              brain,
              brainPeerReconnectDelayMs(brain),
              false,
              "close-connector-reconnect",
              true);
        }
        else
        {
          // Keep connector-owned peer links persistently re-armed while the cluster
          // runs. A transient partition can outlive the default reconnect budget
          // and otherwise strand the mesh with no active brain links.
          armBrainReconnectWaiterIfAbsent(
              brain,
              brainPeerReconnectDelayMs(brain),
              true,
              "close-connector-persistent-reconnect",
              true);
        }
      }
      else
      {
        if (closeConfirmedMissing)
        {
          basics_log("brain close liveness-confirmed inbound deferring missing vote private4=%u transportEpoch=%u\n",
                     brain->private4,
                     unsigned(brain->transportEpoch));
        }

        const bool shouldProbeCurrentMaster = (expectedUpdateFollowerReboot == false && peerRepresentsCurrentMasterForLiveness(brain) && nBrains > 1 && rawStreamIsActive(brain) == false && brain->connectAttemptPending() == false);
        if (shouldProbeCurrentMaster)
        {
          armOutboundPeerReconnect(brain, true);
        }

        // Wait one full inbound reconnect window plus a small slack so the
        // owner brain has a fair chance to redial before we quarantine it.
        // During coordinated follower reboots we still need this waiter armed;
        // skipping it can strand the master with no recovery path for the
        // rebooted accepted peer.
        if (brainWaiters.contains(brain))
        {
          armBrainMissingWaiterIfAbsent(brain, 0, "close-inbound");
          co_return;
        }
        armBrainMissingWaiterIfAbsent(
            brain,
            brain->nDefaultAttemptsBudget * brain->connectTimeoutMs + prodigyBrainPeerInboundMissingSlackMs,
            "close-inbound");
      }
    }
    else if (neurons.contains(static_cast<NeuronView *>(socket)))
    {
      NeuronView *neuron = static_cast<NeuronView *>(socket);
      const bool duplicateInactiveNeuronClose = (weAreMaster && neuronReconnectWaiters.contains(neuron) && rawStreamIsActive(neuron) == false && neuron->connectAttemptPending() == false && neuron->pendingSend == false && neuron->pendingRecv == false);
      if (duplicateInactiveNeuronClose)
      {
        co_return;
      }

      cancelNeuronControlHandshakeWatchdog(neuron, "close");
      neuron->connected = false;

      neuron->cancelSuspended();
      basics_log("brain neuron close stream=%p uuid=%llu private4=%u reconnect=%d connected=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d fd=%d isFixed=%d fslot=%d queuedBytes=%llu wbytes=%u rbytes=%llu\n",
                 static_cast<void *>(neuron),
                 (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                 unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                 int(neuron->reconnectAfterClose),
                 int(neuron->connected),
                 int(neuron->pendingSend),
                 int(neuron->pendingRecv),
                 int(neuron->isTLSNegotiated()),
                 int(neuron->tlsPeerVerified),
                 neuron->fd,
                 int(neuron->isFixedFile),
                 neuron->fslot,
                 (unsigned long long)neuron->queuedSendOutstandingBytes(),
                 uint32_t(neuron->wBuffer.outstandingBytes()),
                 (unsigned long long)neuron->rBuffer.outstandingBytes());
      PRODIGY_DEBUG_LOG(
                   "brain neuron close-live stream=%p uuid=%llu private4=%u reconnect=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d fd=%d fslot=%d queued=%llu rbytes=%llu\n",
                   static_cast<void *>(neuron),
                   (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                   unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                   int(neuron->reconnectAfterClose),
                   int(neuron->pendingSend),
                   int(neuron->pendingRecv),
                   int(neuron->isTLSNegotiated()),
                   int(neuron->tlsPeerVerified),
                   neuron->fd,
                   neuron->fslot,
                   (unsigned long long)neuron->queuedSendOutstandingBytes(),
                   (unsigned long long)neuron->rBuffer.outstandingBytes());
      PRODIGY_DEBUG_FLUSH();
      neuron->cancelPendingConnect();

      retryScheduledContainerWaitersAfterNeuronClose(neuron->machine);

      if (weAreMaster && neuron->shouldReconnect())
      {
        // A reconnect is a fresh transport generation. If stale send/TLS state
        // survives the prior socket, queueSend() can stay wedged behind a dead
        // pendingSend flag and the first post-reconnect registration/control
        // frames never get re-armed.
        if (rawStreamIsActive(neuron))
        {
          abandonSocketGeneration(neuron);
        }
        else
        {
          neuron->ProdigyTransportTLSStream::reset();
        }
        armNeuronReconnectWaiterIfAbsent(neuron, neuronControlReconnectDelayMs(neuron), "close-neuron-reconnect", true, true);
      }
      else
      {
        cancelNeuronReconnectWaiter(neuron, "close-neuron-disarm");
        disarmNeuronControlReconnect(neuron);
      }
    }
    else if (socket == (void *)&mothershipUnixSocket)
    {
      basics_log("mothership unix listener socket closed weAreMaster=%d path=%s\n", int(weAreMaster), mothershipUnixSocketPath.c_str());
      mothershipUnixAcceptArmed = false;
      RingDispatcher::eraseMultiplexee(&mothershipUnixSocket);

      if (weAreMaster)
      {
        armMothershipUnixListener();
      }
      else
      {
        unlinkMothershipUnixSocketPath("unix-listener-close-follower");
      }
    }
    else if (activeMotherships.contains(static_cast<Mothership *>(socket)))
    {
      Mothership *activeMothership = static_cast<Mothership *>(socket);
      basics_log("mothership stream closed weAreMaster=%d\n", int(weAreMaster));
      clearSpinApplicationMothershipsForStream(activeMothership);
      clearContainerLogRequestsForStream(activeMothership);
      activeMotherships.erase(activeMothership);
      if (mothership == activeMothership)
      {
        mothership = (activeMotherships.empty() ? nullptr : *activeMotherships.begin());
      }
      RingDispatcher::eraseMultiplexee(activeMothership); // it'll reconnect to us
      delete activeMothership;
      if (weAreMaster)
      {
        queueMothershipUnixAcceptIfNeeded();
      }
    }
    else if (closingMotherships.contains(static_cast<Mothership *>(socket)))
    {
      Mothership *closingStream = static_cast<Mothership *>(socket);
      basics_log("mothership retired stream closed weAreMaster=%d closingStreams=%zu\n",
                 int(weAreMaster),
                 size_t(closingMotherships.size()));
      clearSpinApplicationMothershipsForStream(closingStream);
      clearContainerLogRequestsForStream(closingStream);
      RingDispatcher::eraseMultiplexee(closingStream);
      closingMotherships.erase(closingStream);
      delete closingStream;
      if (weAreMaster)
      {
        queueMothershipUnixAcceptIfNeeded();
      }
    }
    else if (sshs.contains(static_cast<MachineSSH *>(socket)))
    {
      MachineSSH *ssh = static_cast<MachineSSH *>(socket);
      ssh->cancelPendingConnect();

      ssh->cancelSuspended();

      if (ssh->shouldReconnect())
      {
        ssh->recreateSocket();
        ssh->attemptConnect();

        // mark as rebooting neuron during SSH restart flow
        if (ssh->machine)
        {
          ssh->machine->state = MachineState::neuronRebooting;
        }
      }
      else
      {
        // failure logic handled in connect handler
        // also possible this succeded and is now being destroyed
        sshs.erase(ssh);
        RingDispatcher::eraseMultiplexee(ssh);
        delete ssh;
      }
    }
  }

  void pollHandler(void *socket, int result) override
  {
    MachineSSH *ssh = static_cast<MachineSSH *>(socket);

    if (result & (POLLHUP | POLLERR))
    {
      Ring::queueClose(ssh);

      // it failed.... so we'd end up trying to reconnect and start again
    }
    else
    {
      ssh->co_consume();
    }
  }

  void queueNeuronStateUploadForMachine(Machine *machine)
  {
    if (machine == nullptr || brainConfig.datacenterFragment == 0 || machine->fragment == 0)
    {
      return;
    }

    machine->reportedDatacenterFragment = 0;
    machine->reportedFragment = 0;
    machine->runtimeReady = false;

    uint32_t headerOffset = Message::appendHeader(machine->neuron.wBuffer, NeuronTopic::stateUpload);

    struct local_container_subnet6 fragment = {};
    fragment.dpfx = brainConfig.datacenterFragment;
    fragment.mpfx[0] = static_cast<uint8_t>((machine->fragment >> 16) & 0xFF);
    fragment.mpfx[1] = static_cast<uint8_t>((machine->fragment >> 8) & 0xFF);
    fragment.mpfx[2] = static_cast<uint8_t>(machine->fragment & 0xFF);

    Message::appendAlignedBuffer<Alignment::one>(machine->neuron.wBuffer, reinterpret_cast<uint8_t *>(&fragment), sizeof(struct local_container_subnet6));

    for (const auto& [deploymentID, containers] : machine->containersByDeploymentID)
    {
      auto deploymentIt = deployments.find(deploymentID);
      if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
      {
        continue;
      }

      ApplicationDeployment *deployment = deploymentIt->second;
      for (ContainerView *container : containers)
      {
        ApplicationConfig replayConfig = deployment->resourceConfigForContainer(container);
        ContainerPlan planToReplay = container->generatePlan(deployment->plan, deployment->nShardGroups, &replayConfig);
        if (planToReplay.isStateful)
        {
          prodigyPopulateDefaultStatefulTopology(planToReplay.statefulTopology, planToReplay.shardGroup, planToReplay.config);
        }
        applyCredentialsToContainerPlan(deployment->plan, *container, planToReplay);

        NeuronContainerBootstrap bootstrap = {};
        bootstrap.plan = std::move(planToReplay);
        bootstrap.metricPolicy = deriveNeuronMetricPolicyForDeployment(deployment->plan);
        String serializedBootstrap = {};
        BitseryEngine::serialize(serializedBootstrap, bootstrap);
        Message::appendValue(machine->neuron.wBuffer, serializedBootstrap);
      }
    }

    Message::finish(machine->neuron.wBuffer, headerOffset);

    if (streamIsActive(&machine->neuron))
    {
      Ring::queueSend(&machine->neuron);
    }
  }

  bool machineNeedsNeuronStateRefresh(const Machine *machine) const
  {
    if (machine == nullptr)
    {
      return false;
    }

    if (machine->state == MachineState::hardRebooting || machine->state == MachineState::neuronRebooting || machine->runtimeReady == false)
    {
      return true;
    }

    return brainConfig.datacenterFragment != 0 && machine->fragment > 0 && (machine->reportedDatacenterFragment != brainConfig.datacenterFragment || machine->reportedFragment != machine->fragment);
  }

  void refreshMachineFragmentAssignmentsIfPossible(void)
  {
    if (brainConfig.datacenterFragment == 0)
    {
      return;
    }

    for (Machine *machine : machines)
    {
      if (machine == nullptr || neuronControlStreamActive(machine) == false)
      {
        continue;
      }

      if (machine->fragment == 0)
      {
        assignMachineFragment(machine);
        continue;
      }

      if (machine->runtimeReady == false || machine->reportedDatacenterFragment != brainConfig.datacenterFragment || machine->reportedFragment != machine->fragment)
      {
        queueNeuronStateUploadForMachine(machine);
      }
    }
  }

  void assignMachineFragment(Machine *machine)
  {
    if (machine == nullptr || brainConfig.datacenterFragment == 0)
    {
      return;
    }

    bool fakeIPv4Mode = false;
#if NAMETAG_PRODIGY_DEV_FAKE_IPV4_ROUTE
    if (const char *mode = getenv("PRODIGY_DEV_FAKE_IPV4_MODE"); mode && mode[0] == '1' && mode[1] == '\0')
    {
      fakeIPv4Mode = true;
    }
#endif

    if (machine->fragment == 0)
    {
      do
      {
        if (fakeIPv4Mode)
        {
          IPAddress preferredAddress = {};
          uint32_t preferred = 0;
          if (prodigyResolveMachinePeerAddress(*machine, preferredAddress))
          {
            preferred = preferredAddress.is6
                            ? uint32_t(preferredAddress.v6[15])
                            : (ntohl(preferredAddress.v4) & 0xFFu);
          }
          else if (machine->private4 != 0)
          {
            preferred = ntohl(machine->private4) & 0xFFu;
          }
          if (preferred == 0)
          {
            preferred = 1;
          }

          machine->fragment = 0;
          for (uint32_t offset = 0; offset < 255; ++offset)
          {
            uint32_t candidate = ((preferred + offset - 1u) % 255u) + 1u;
            if (usedMachineFragments.contains(candidate) == false)
            {
              machine->fragment = candidate;
              break;
            }
          }

          if (machine->fragment == 0)
          {
            machine->fragment = Random::generateNumberWithNBits<24, uint32_t>();
          }
        }
        else
        {
          machine->fragment = Random::generateNumberWithNBits<24, uint32_t>();
        }

      } while (usedMachineFragments.contains(machine->fragment));
    }

    usedMachineFragments.insert(machine->fragment);
    machine->reportedDatacenterFragment = 0;
    machine->reportedFragment = 0;
    machine->runtimeReady = false;

    struct local_container_subnet6 lcsubnet6;
    lcsubnet6.dpfx = brainConfig.datacenterFragment;
    lcsubnet6.mpfx[0] = static_cast<uint8_t>((machine->fragment >> 16) & 0xFF);
    lcsubnet6.mpfx[1] = static_cast<uint8_t>((machine->fragment >> 8) & 0xFF);
    lcsubnet6.mpfx[2] = static_cast<uint8_t>(machine->fragment & 0xFF);

    uint32_t headerOffset = Message::appendHeader(machine->neuron.wBuffer, NeuronTopic::assignFragment);
    Message::appendAlignedBuffer<Alignment::one>(machine->neuron.wBuffer, reinterpret_cast<uint8_t *>(&lcsubnet6), sizeof(struct local_container_subnet6));
    Message::finish(machine->neuron.wBuffer, headerOffset);

    if (streamIsActive(&machine->neuron))
    {
      Ring::queueSend(&machine->neuron);
    }

    sendNeuronSwitchboardOverlayRoutes();
  }

  void relinquishMachineFragment(Machine *machine)
  {
    usedMachineFragments.erase(machine->fragment);
    machine->fragment = 0;
    machine->reportedDatacenterFragment = 0;
    machine->reportedFragment = 0;
    machine->runtimeReady = false;
    sendNeuronSwitchboardOverlayRoutes();
  }

  bool machineReadyForHealthyState(Machine *machine) const
  {
    if (machine == nullptr)
    {
      return false;
    }

    if (neuronControlStreamActive(machine) == false)
    {
      return false;
    }

    // A connected neuron socket alone is not sufficient to host work. Real
    // machines need hardware inventory; isolated test clusters may use the
    // configured synthetic capacity because local runners often expose only
    // loop-backed storage to lsblk.
    bool hasInventoryOrTestCapacity = machine->hardware.inventoryComplete;
    if (hasInventoryOrTestCapacity == false && brainConfig.runtimeEnvironment.test.enabled)
    {
      hasInventoryOrTestCapacity = prodigyMachineReadyResourcesAvailable(*machine);
    }

    if (hasInventoryOrTestCapacity == false || (brainConfig.datacenterFragment != 0 && machine->fragment == 0))
    {
      return false;
    }

    return prodigyMachineReadyResourcesAvailable(*machine);
  }

  bool machineCanEnterHealthyState(Machine *machine) const
  {
    if (machineReadyForHealthyState(machine) == false)
    {
      return false;
    }

    if (machine->state == MachineState::updatingOS || (machine->state == MachineState::hardRebooting && machine->osUpdateCommandIssued))
    {
      const OperatingSystemUpdatePolicy *policy = osUpdatePolicyForMachine(machine);
      return policy != nullptr && machine->osVersionID.equals(policy->targetVersionID) && machine->runtimeReady;
    }

    return machine->state != MachineState::hardRebooting || machine->runtimeReady;
  }

  void promoteMachineToHealthyIfReady(Machine *machine)
  {
    if (machine != nullptr && machine->state != MachineState::healthy && machineCanEnterHealthyState(machine))
    {
      handleMachineStateChange(machine, MachineState::healthy);
    }
  }

  void resumeMachineClaimsIfSchedulingReady(Machine *machine)
  {
    if (machine == nullptr || machine->state != MachineState::healthy || machine->runtimeReady == false || machine->claims.size() == 0)
    {
      return;
    }

    for (auto it = machine->claims.begin(); it != machine->claims.end();)
    {
      Machine::Claim& claim = *it;

      MachineTicket *ticket = claim.ticket;
      ticket->nNow = claim.nFit;
      ticket->shardGroups = claim.shardGroups;
      ticket->placementTopologyEpochs = claim.placementTopologyEpochs;
      ticket->reservedGPUMemoryMBs = claim.reservedGPUMemoryMBs;
      ticket->reservedGPUDevices = claim.reservedGPUDevices;
      ticket->machineNow = machine;

      ticket->coro->co_consume();

      it = machine->claims.erase(it);
    }
  }

  static void ownMachineConfig(const MachineConfig& source, MachineConfig& owned)
  {
    owned = {};
    owned.kind = source.kind;
    owned.slug.assign(source.slug);
    owned.ipxeScriptURL.assign(source.ipxeScriptURL);
    owned.vmImageURI.assign(source.vmImageURI);
    owned.gcpInstanceTemplate.assign(source.gcpInstanceTemplate);
    owned.gcpInstanceTemplateSpot.assign(source.gcpInstanceTemplateSpot);
    owned.nLogicalCores = source.nLogicalCores;
    owned.nMemoryMB = source.nMemoryMB;
    owned.nStorageMB = source.nStorageMB;
    owned.providesHostPublic4 = source.providesHostPublic4;
    owned.providesHostPublic6 = source.providesHostPublic6;
  }

  static void ownDistributableExternalSubnet(const DistributableExternalSubnet& source, DistributableExternalSubnet& owned)
  {
    owned = {};
    owned.uuid = source.uuid;
    owned.name.assign(source.name);
    owned.kind = source.kind;
    owned.subnet = source.subnet;
    owned.deliverySubnet = source.deliverySubnet;
    owned.routing = source.routing;
    owned.usage = source.usage;
    owned.ingressScope = source.ingressScope;
    owned.machineUUID = source.machineUUID;
    owned.providerPool.assign(source.providerPool);
    owned.providerAllocationID.assign(source.providerAllocationID);
    owned.providerAssociationID.assign(source.providerAssociationID);
    owned.releaseOnRemove = source.releaseOnRemove;
  }

  static void ownRuntimeEnvironmentConfig(const ProdigyRuntimeEnvironmentConfig& source, ProdigyRuntimeEnvironmentConfig& owned)
  {
    prodigyOwnRuntimeEnvironmentConfig(source, owned);
    prodigyStripManagedCloudBootstrapCredentials(owned);
  }

  static void ownBrainConfig(const BrainConfig& source, BrainConfig& owned)
  {
    owned = {};
    for (const auto& [slug, machineConfig] : source.configBySlug)
    {
      String ownedSlug = {};
      ownedSlug.assign(slug);
      MachineConfig ownedMachineConfig = {};
      ownMachineConfig(machineConfig, ownedMachineConfig);
      owned.configBySlug.insert_or_assign(std::move(ownedSlug), std::move(ownedMachineConfig));
    }

    owned.clusterUUID = source.clusterUUID;
    owned.datacenterFragment = source.datacenterFragment;
    owned.autoscaleIntervalSeconds = source.autoscaleIntervalSeconds;
    owned.sharedCPUOvercommitPermille = source.sharedCPUOvercommitPermille;
    owned.machineReservedResources = source.machineReservedResources;
    owned.requiredBrainCount = source.requiredBrainCount;
    owned.architecture = source.architecture;
    owned.bootstrapSshUser.assign(source.bootstrapSshUser);
    owned.bootstrapSshKeyPackage = source.bootstrapSshKeyPackage;
    owned.bootstrapSshHostKeyPackage = source.bootstrapSshHostKeyPackage;
    owned.bootstrapSshPrivateKeyPath.assign(source.bootstrapSshPrivateKeyPath);
    owned.remoteProdigyPath.assign(source.remoteProdigyPath);
    owned.controlSocketPath.assign(source.controlSocketPath);
    for (const DistributableExternalSubnet& sourceSubnet : source.distributableExternalSubnets)
    {
      DistributableExternalSubnet ownedSubnet = {};
      ownDistributableExternalSubnet(sourceSubnet, ownedSubnet);
      owned.distributableExternalSubnets.push_back(std::move(ownedSubnet));
    }
    owned.dnsProvider.assign(source.dnsProvider);
    owned.dnsCredential.name.assign(source.dnsCredential.name);
    owned.dnsCredential.provider.assign(source.dnsCredential.provider);
    owned.dnsCredential.generation = source.dnsCredential.generation;
    owned.dnsCredential.expiresAtMs = source.dnsCredential.expiresAtMs;
    owned.dnsCredential.activeFromMs = source.dnsCredential.activeFromMs;
    owned.dnsCredential.sunsetAtMs = source.dnsCredential.sunsetAtMs;
    owned.dnsCredential.material.assign(source.dnsCredential.material);
    for (const auto& [key, value] : source.dnsCredential.metadata)
    {
      String ownedKey, ownedValue;
      ownedKey.assign(key);
      ownedValue.assign(value);
      owned.dnsCredential.metadata.insert_or_assign(std::move(ownedKey), std::move(ownedValue));
    }
    owned.acme.accountEmail.assign(source.acme.accountEmail);
    owned.acme.certbotInstall.assign(source.acme.certbotInstall);
    owned.acme.certbotPath.assign(source.acme.certbotPath);
    owned.acme.certbotVersion.assign(source.acme.certbotVersion);
    owned.acme.termsAgreed = source.acme.termsAgreed;
    owned.vmImageURI.assign(source.vmImageURI);
    owned.osUpdatesEnabled = source.osUpdatesEnabled;
    owned.osUpdatePolicies = source.osUpdatePolicies;
    owned.maxOSDrains = source.maxOSDrains;
    owned.machineUpdateCadenceMins = source.machineUpdateCadenceMins;
    ownRuntimeEnvironmentConfig(source.runtimeEnvironment, owned.runtimeEnvironment);
  }

  bool applyConfiguredMachineCapacity(Machine *machine, const MachineConfig& machineConfig, bool overrideExistingTotals)
  {
    if (machine == nullptr)
    {
      return false;
    }

    uint32_t beforeTotalLogicalCores = machine->totalLogicalCores;
    uint32_t beforeTotalMemoryMB = machine->totalMemoryMB;
    uint32_t beforeTotalStorageMB = machine->totalStorageMB;
    uint32_t beforeOwnedLogicalCores = machine->ownedLogicalCores;
    uint32_t beforeOwnedMemoryMB = machine->ownedMemoryMB;
    uint32_t beforeOwnedStorageMB = machine->ownedStorageMB;
    int32_t beforeAvailableLogicalCores = machine->nLogicalCores_available;
    int32_t beforeAvailableSharedCPUMillis = machine->sharedCPUMillis_available;
    int32_t beforeAvailableMemoryMB = machine->memoryMB_available;
    int32_t beforeAvailableStorageMB = machine->storageMB_available;

    if (overrideExistingTotals)
    {
      if (machineConfig.nLogicalCores > 0)
      {
        machine->totalLogicalCores = machineConfig.nLogicalCores;
      }
      if (machineConfig.nMemoryMB > 0)
      {
        machine->totalMemoryMB = machineConfig.nMemoryMB;
      }
      if (machineConfig.nStorageMB > 0)
      {
        machine->totalStorageMB = machineConfig.nStorageMB;
      }
    }
    else
    {
      if (machine->totalLogicalCores == 0)
      {
        machine->totalLogicalCores = machineConfig.nLogicalCores;
      }
      if (machine->totalMemoryMB == 0)
      {
        machine->totalMemoryMB = machineConfig.nMemoryMB;
      }
      if (machine->totalStorageMB == 0)
      {
        machine->totalStorageMB = machineConfig.nStorageMB;
      }
    }

    ClusterMachineOwnership ownership = {};
    ownership.mode = ClusterMachineOwnershipMode(machine->ownershipMode);
    ownership.nLogicalCoresCap = machine->ownershipLogicalCoresCap;
    ownership.nMemoryMBCap = machine->ownershipMemoryMBCap;
    ownership.nStorageMBCap = machine->ownershipStorageMBCap;
    ownership.nLogicalCoresBasisPoints = machine->ownershipLogicalCoresBasisPoints;
    ownership.nMemoryBasisPoints = machine->ownershipMemoryBasisPoints;
    ownership.nStorageBasisPoints = machine->ownershipStorageBasisPoints;

    uint32_t resolvedOwnedLogicalCores = overrideExistingTotals ? 0 : machine->ownedLogicalCores;
    uint32_t resolvedOwnedMemoryMB = overrideExistingTotals ? 0 : machine->ownedMemoryMB;
    uint32_t resolvedOwnedStorageMB = overrideExistingTotals ? 0 : machine->ownedStorageMB;
    if (resolvedOwnedLogicalCores == 0 || resolvedOwnedMemoryMB == 0 || resolvedOwnedStorageMB == 0)
    {
      (void)clusterMachineResolveOwnedResources(
          ownership,
          machine->totalLogicalCores,
          machine->totalMemoryMB,
          machine->totalStorageMB,
          resolvedOwnedLogicalCores,
          resolvedOwnedMemoryMB,
          resolvedOwnedStorageMB,
          brainConfig.machineReservedResources);
    }

    machine->ownedLogicalCores = resolvedOwnedLogicalCores;
    machine->ownedMemoryMB = resolvedOwnedMemoryMB;
    machine->ownedStorageMB = resolvedOwnedStorageMB;
    machine->isolatedLogicalCoresCommitted = 0;
    machine->sharedCPUMillisCommitted = 0;
    machine->memoryMB_available = int32_t(resolvedOwnedMemoryMB);
    machine->storageMB_available = int32_t(resolvedOwnedStorageMB);
    machine->resetAvailableGPUMemoryMBsFromHardware();
    prodigyRecomputeMachineCPUAvailability(machine, prodigySharedCPUOvercommitPermille(brainConfig.sharedCPUOvercommitPermille));

    for (Machine::Claim& claim : machine->claims)
    {
      if (claim.nFit == 0)
      {
        continue;
      }

      uint32_t reservedIsolatedLogicalCores = claim.reservedIsolatedLogicalCoresTotal ? claim.reservedIsolatedLogicalCoresTotal : (claim.reservedIsolatedLogicalCoresPerInstance * claim.nFit);
      uint32_t reservedSharedCPUMillis = claim.reservedSharedCPUMillisTotal ? claim.reservedSharedCPUMillisTotal : (claim.reservedSharedCPUMillisPerInstance * claim.nFit);
      uint32_t reservedMemoryMB = claim.reservedMemoryMBTotal ? claim.reservedMemoryMBTotal : (claim.reservedMemoryMBPerInstance * claim.nFit);
      uint32_t reservedStorageMB = claim.reservedStorageMBTotal ? claim.reservedStorageMBTotal : (claim.reservedStorageMBPerInstance * claim.nFit);
      machine->isolatedLogicalCoresCommitted += reservedIsolatedLogicalCores;
      machine->sharedCPUMillisCommitted += reservedSharedCPUMillis;
      machine->memoryMB_available -= int32_t(reservedMemoryMB);
      machine->storageMB_available -= int32_t(reservedStorageMB);
      prodigyConsumeAssignedGPUsFromMachineAvailability(machine, claim.reservedGPUMemoryMBs, claim.reservedGPUDevices);
    }

    for (const auto& [deploymentID, indexedContainers] : machine->containersByDeploymentID)
    {
      auto deploymentIt = deployments.find(deploymentID);
      if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
      {
        continue;
      }

      const ApplicationConfig& indexedConfig = deploymentIt->second->plan.config;
      for (ContainerView *container : indexedContainers)
      {
        if (container == nullptr || container->state == ContainerState::destroyed)
        {
          continue;
        }

        prodigyDebitMachineScalarResources(machine, indexedConfig, 1);
        prodigyConsumeAssignedGPUsFromMachineAvailability(machine, container->assignedGPUMemoryMBs, container->assignedGPUDevices);
      }
    }

    prodigyRecomputeMachineCPUAvailability(machine, prodigySharedCPUOvercommitPermille(brainConfig.sharedCPUOvercommitPermille));

    return beforeTotalLogicalCores != machine->totalLogicalCores || beforeTotalMemoryMB != machine->totalMemoryMB || beforeTotalStorageMB != machine->totalStorageMB || beforeOwnedLogicalCores != machine->ownedLogicalCores || beforeOwnedMemoryMB != machine->ownedMemoryMB || beforeOwnedStorageMB != machine->ownedStorageMB || beforeAvailableLogicalCores != machine->nLogicalCores_available || beforeAvailableSharedCPUMillis != machine->sharedCPUMillis_available || beforeAvailableMemoryMB != machine->memoryMB_available || beforeAvailableStorageMB != machine->storageMB_available;
  }

  void loadBrainConfigIf(void)
  {
    if (iaas != nullptr)
    {
      iaas->configureRuntimeEnvironment(brainConfig.runtimeEnvironment);
    }
    for (Machine *machine : machines)
    {
      if (machine == nullptr)
      {
        continue;
      }

      sendNeuronSwitchboardStateSync(machine);
    }

    const bool haveDatacenterFragment = (brainConfig.datacenterFragment != 0);
    for (Machine *machine : machines) // accounts for us
    {
      auto it = brainConfig.configBySlug.find(machine->slug);
      if (it == brainConfig.configBySlug.end())
      {
        continue;
      }

      const MachineConfig& machineConfig = it->second;
      (void)applyConfiguredMachineCapacity(machine, machineConfig, brainConfig.runtimeEnvironment.test.enabled);

      if (haveDatacenterFragment)
      {
        assignMachineFragment(machine);
      }

      promoteMachineToHealthyIfReady(machine);

      if (machine->isThisMachine)
      {
        // Local autoscaling metrics are ingested from neuron/container statistics;
        // no extra metrics service subscriptions are required here.
      }
    }
  }

  virtual bool loadAuthoritativeClusterTopology(ClusterTopology& topology) const
  {
    (void)topology;
    return false;
  }

  virtual bool persistAuthoritativeClusterTopology(const ClusterTopology& topology)
  {
    (void)topology;
    persistLocalRuntimeState();
    return true;
  }

  bool loadOrPersistAuthoritativeClusterTopology(ClusterTopology& topology)
  {
    if (loadAuthoritativeClusterTopology(topology) && topology.machines.empty() == false)
    {
      return true;
    }

    persistLocalRuntimeState();
    return loadAuthoritativeClusterTopology(topology) && topology.machines.empty() == false;
  }

  void applyMachineHardwareProfile(Machine *machine, const MachineHardwareProfile& hardware)
  {
    if (machine == nullptr)
    {
      return;
    }

    bool changed = (machine->hardware != hardware);
    if (changed)
    {
      prodigyApplyHardwareProfileToMachine(*machine, hardware);
    }
    bool configuredCapacityChanged = false;
    if (brainConfig.runtimeEnvironment.test.enabled)
    {
      auto configIt = brainConfig.configBySlug.find(machine->slug);
      if (configIt != brainConfig.configBySlug.end())
      {
        configuredCapacityChanged = applyConfiguredMachineCapacity(machine, configIt->second, true);
      }
    }

    if (changed == false && configuredCapacityChanged == false)
    {
      return;
    }

    persistLocalRuntimeState();

    if (isActiveMaster())
    {
      ClusterTopology topology = {};
      if (loadAuthoritativeClusterTopology(topology) && topology.machines.empty() == false)
      {
        bool updatedTopology = false;
        for (ClusterMachine& clusterMachine : topology.machines)
        {
          if (prodigyClusterMachineMatchesMachineIdentity(clusterMachine, *machine) == false)
          {
            continue;
          }

          prodigyApplyHardwareProfileToClusterMachine(clusterMachine, hardware, brainConfig.machineReservedResources);
          if (brainConfig.runtimeEnvironment.test.enabled)
          {
            auto configIt = brainConfig.configBySlug.find(machine->slug);
            if (configIt != brainConfig.configBySlug.end())
            {
              (void)clusterMachineApplyOwnedResourcesFromConfig(clusterMachine, configIt->second, brainConfig.machineReservedResources);
            }
          }
          updatedTopology = true;
          break;
        }

        if (updatedTopology == false)
        {
          return;
        }

        prodigyStripMachineHardwareCapturesFromClusterTopology(topology);
        topology.version += 1;
        if (persistAuthoritativeClusterTopology(topology) == false)
        {
          return;
        }

        String serializedTopology = {};
        BitseryEngine::serialize(serializedTopology, topology);
        queueBrainReplication(BrainTopic::replicateClusterTopology, serializedTopology);
      }
    }
  }

  static bool resolveClusterMachinePrivate4(const ClusterMachine& clusterMachine, uint32_t& private4)
  {
    return clusterMachine.resolvePrivate4(private4);
  }

  static bool resolveClusterMachinePeerAddress(const ClusterMachine& clusterMachine, IPAddress& address, String& addressText)
  {
    address = {};
    addressText.clear();
    return clusterMachine.resolvePeerAddress(address, &addressText);
  }

  static void resolveClusterMachinePeerAddresses(const ClusterMachine& clusterMachine, Vector<ClusterMachinePeerAddress>& addresses)
  {
    prodigyCollectClusterMachinePeerAddresses(clusterMachine, addresses);
  }

  BrainView *findBrainViewByPrivate4(uint32_t private4) const
  {
    for (BrainView *brain : brains)
    {
      if (brain && brain->private4 == private4 && brain->peerAddress.isNull() && brain->peerAddressText.size() == 0)
      {
        return brain;
      }
    }

    return nullptr;
  }

  BrainView *findBrainViewByUUID(uint128_t uuid) const
  {
    for (BrainView *brain : brains)
    {
      if (brain && brain->uuid == uuid)
      {
        return brain;
      }
    }

    return nullptr;
  }

  BrainView *findBrainViewByUpdateSelfPeerKey(uint128_t peerKey) const
  {
    if (peerKey == 0)
    {
      return nullptr;
    }

    for (BrainView *brain : brains)
    {
      if (brain == nullptr)
      {
        continue;
      }

      if (updateSelfPeerTrackingKey(brain) == peerKey)
      {
        return brain;
      }
    }

    return nullptr;
  }

  BrainView *findBrainViewByPeerAddress(const IPAddress& address) const
  {
    for (BrainView *brain : brains)
    {
      if (brain == nullptr)
      {
        continue;
      }

      if (brain->peerAddress.equals(address))
      {
        return brain;
      }

      for (const ClusterMachinePeerAddress& candidate : brain->peerAddresses)
      {
        IPAddress candidateAddress = {};
        if (ClusterMachine::parseIPAddressLiteral(candidate.address, candidateAddress) && candidateAddress.equals(address))
        {
          return brain;
        }
      }
    }

    return nullptr;
  }

  BrainView *findBrainViewByPeerAddresses(const Vector<ClusterMachinePeerAddress>& addresses) const
  {
    for (const ClusterMachinePeerAddress& candidate : addresses)
    {
      IPAddress address = {};
      if (ClusterMachine::parseIPAddressLiteral(candidate.address, address) == false)
      {
        continue;
      }

      if (BrainView *brain = findBrainViewByPeerAddress(address); brain != nullptr)
      {
        return brain;
      }
    }

    return nullptr;
  }

  static bool machineAddressMatchesLiteral(const String& candidate, const IPAddress& address, const String *addressText = nullptr)
  {
    if (candidate.size() == 0)
    {
      return false;
    }

    if (addressText && candidate.equals(*addressText))
    {
      return true;
    }

    IPAddress parsed = {};
    return ClusterMachine::parseIPAddressLiteral(candidate, parsed) && parsed.equals(address);
  }

  bool machineMatchesPeerAddress(const Machine *machine, const IPAddress& address, const String *addressText = nullptr) const
  {
    if (machine == nullptr || address.isNull())
    {
      return false;
    }

    return prodigyMachinePeerAddressMatches(*machine, address, addressText);
  }

  void adoptBrainPeerAddresses(BrainView *brain, const Vector<ClusterMachinePeerAddress>& addresses)
  {
    if (brain == nullptr)
    {
      return;
    }

    brain->peerAddresses.clear();
    for (const ClusterMachinePeerAddress& candidate : addresses)
    {
      prodigyAppendUniqueClusterMachinePeerAddress(brain->peerAddresses, candidate);
    }

    if (brain->peerAddresses.empty())
    {
      return;
    }

    uint32_t selectedIndex = 0;
    for (uint32_t index = 0; index < brain->peerAddresses.size(); ++index)
    {
      IPAddress peerAddress = {};
      if (ClusterMachine::parseIPAddressLiteral(brain->peerAddresses[index].address, peerAddress))
      {
        selectedIndex = index;
        break;
      }
    }

    brain->peerAddressIndex = selectedIndex;
    IPAddress peerAddress = {};
    if (ClusterMachine::parseIPAddressLiteral(brain->peerAddresses[selectedIndex].address, peerAddress))
    {
      brain->peerAddress = peerAddress;
      brain->peerAddressText = brain->peerAddresses[selectedIndex].address;
    }
  }

  static bool installBrainPeerSocket(BrainView *brain)
  {
    if (brain == nullptr || brain->fd < 0)
    {
      return false;
    }

    if (brain->daddrLen == 0)
    {
      return false;
    }

    if (Ring::bindSourceAddressBeforeFixedFileInstall(brain) == false)
    {
      ::close(brain->fd);
      brain->fd = -1;
      brain->isFixedFile = false;
      return false;
    }

    int slot = Ring::adoptProcessFDIntoFixedFileSlot(brain->fd);
    if (slot < 0)
    {
      ::close(brain->fd);
      brain->fd = -1;
      brain->isFixedFile = false;
      return false;
    }

    brain->fslot = slot;
    brain->isFixedFile = true;
    return true;
  }

  uint32_t controlPlaneTCPMaxSegmentSize(int family) const
  {
    if (brainConfig.runtimeEnvironment.test.enabled == false)
    {
      return 0;
    }

    return prodigyTCPMaxSegmentSizeForMTU(brainConfig.runtimeEnvironment.test.interContainerMTU, family);
  }

  void queueAcceptedBrainPeerSocketOptions(BrainView *brain)
  {
    if (brain == nullptr)
    {
      return;
    }

    Ring::queueSetSockOptRaw(brain, SOL_TCP, TCP_CONGESTION, "dctcp", socklen_t(strlen("dctcp")), "brain accepted peer congestion");
    Ring::queueSetSockOptInt(brain, SOL_SOCKET, SO_KEEPALIVE, 1, "brain accepted peer keepalive");
    Ring::queueSetSockOptInt(brain, SOL_TCP, TCP_KEEPIDLE, int(std::max<uint32_t>(brainPeerKeepaliveSeconds, 1u)), "brain accepted peer keepidle");
    Ring::queueSetSockOptInt(brain, SOL_TCP, TCP_KEEPINTVL, int(std::max<uint32_t>(brainPeerKeepaliveSeconds / 3, 1u)), "brain accepted peer keepintvl");
    Ring::queueSetSockOptInt(brain, SOL_TCP, TCP_KEEPCNT, 3, "brain accepted peer keepcnt");
    // Followers can receive multi-megabyte replicated blobs immediately
    // after accept. Keep the short accepted-peer probe cadence, but lift
    // the in-flight data timeout to the large-payload budget before the
    // first big frame starts arriving.
    Ring::queueSetSockOptInt(
        brain,
        SOL_TCP,
        TCP_USER_TIMEOUT,
        int(brainPeerLargePayloadKeepaliveSeconds * 1000u),
        "brain accepted peer large-payload user-timeout");
    if (uint32_t maxSegmentSize = controlPlaneTCPMaxSegmentSize(brain->peerAddress.is6 ? AF_INET6 : AF_INET); maxSegmentSize > 0)
    {
      Ring::queueSetSockOptInt(brain, SOL_TCP, TCP_MAXSEG, int(maxSegmentSize), "brain accepted peer tcp maxseg");
    }
  }

  void configureBrainPeerConnectAddress(BrainView *brain, bool advanceCandidate = false) const
  {
    if (brain == nullptr)
    {
      return;
    }

    Vector<ClusterMachinePeerAddress> localCandidates = {};
    collectLocalBrainPeerSourceCandidates(localCandidates);

    IPAddress peerAddress = {};
    String peerAddressText = {};
    ClusterMachinePeerAddress selectedPeerCandidate = {};
    if (brain->peerAddresses.empty() == false)
    {
      if (advanceCandidate && brain->peerAddresses.size() > 1)
      {
        brain->peerAddressIndex = (brain->peerAddressIndex + 1) % uint32_t(brain->peerAddresses.size());
      }
      else if (brain->peerAddressIndex >= brain->peerAddresses.size())
      {
        brain->peerAddressIndex = 0;
      }

      if (ClusterMachine::parseIPAddressLiteral(brain->peerAddresses[brain->peerAddressIndex].address, peerAddress))
      {
        peerAddressText.assign(brain->peerAddresses[brain->peerAddressIndex].address);
        selectedPeerCandidate = brain->peerAddresses[brain->peerAddressIndex];
        brain->peerAddress = peerAddress;
        brain->peerAddressText = peerAddressText;
      }
    }

    if (peerAddress.isNull())
    {
      peerAddress = brain->peerAddress;
      peerAddressText = brain->peerAddressText;
    }

    if (peerAddress.isNull())
    {
      if (brain->private4 == 0)
      {
        return;
      }

      peerAddress = {};
      peerAddress.v4 = brain->private4;
      peerAddress.is6 = false;
      brain->peerAddress = peerAddress;
      if (peerAddressText.size() == 0)
      {
        (void)ClusterMachine::renderIPAddressLiteral(peerAddress, peerAddressText);
      }
      brain->peerAddressText = peerAddressText;
    }

    if ((brain->isFixedFile && brain->fslot >= 0) || (brain->isFixedFile == false && brain->fd >= 0 && Ring::socketIsClosing(brain) == false))
    {
      return;
    }

    brain->setIPVersion(peerAddress.is6 ? AF_INET6 : AF_INET);
    brain->setDatacenterCongestion();
    if (uint32_t maxSegmentSize = controlPlaneTCPMaxSegmentSize(peerAddress.is6 ? AF_INET6 : AF_INET); maxSegmentSize > 0)
    {
      (void)prodigySetTCPMaxSegmentSize(brain->fd, maxSegmentSize);
    }
    brain->saddrLen = 0;
    String sourceAddressText = {};
    if (selectedPeerCandidate.address.size() == 0 && peerAddressText.size() > 0)
    {
      selectedPeerCandidate.address.assign(peerAddressText);
    }
    if (selectedPeerCandidate.address.size() > 0)
    {
      IPAddress sourceAddress = {};
      if (prodigyResolvePreferredLocalSourceAddress(localCandidates, selectedPeerCandidate, sourceAddress, &sourceAddressText))
      {
        brain->setSaddr(sourceAddress);
      }
    }
    if (const char *ringVerbose = std::getenv("RING_VERBOSE_LOGS"); ringVerbose && ringVerbose[0] == '1' && ringVerbose[1] == '\0')
    {
      basics_log("configureBrainPeerConnectAddress stream=%p uuid=%llu private4=%u candidateIndex=%u peer=%s source=%s localCandidates=%u peerCandidates=%u\n",
                 static_cast<void *>(brain),
                 (unsigned long long)brain->uuid,
                 unsigned(brain->private4),
                 unsigned(brain->peerAddressIndex),
                 peerAddressText.size() > 0 ? peerAddressText.c_str() : "<unset>",
                 sourceAddressText.size() > 0 ? sourceAddressText.c_str() : "<unset>",
                 unsigned(localCandidates.size()),
                 unsigned(brain->peerAddresses.size()));
    }
    brain->setDaddr(peerAddress, uint16_t(ReservedPorts::brain));
  }

  Machine *findMachineByIdentity(uint128_t uuid, uint32_t private4, const Vector<ClusterMachinePeerAddress> *peerAddresses = nullptr, const IPAddress *peerAddress = nullptr, const String *peerAddressText = nullptr) const
  {
    if (uuid != 0)
    {
      if (auto it = machinesByUUID.find(uuid); it != machinesByUUID.end())
      {
        return it->second;
      }
    }

    if (peerAddresses != nullptr)
    {
      for (const ClusterMachinePeerAddress& candidate : *peerAddresses)
      {
        IPAddress candidateAddress = {};
        if (ClusterMachine::parseIPAddressLiteral(candidate.address, candidateAddress) == false)
        {
          continue;
        }

        for (Machine *machine : machines)
        {
          if (machineMatchesPeerAddress(machine, candidateAddress, &candidate.address))
          {
            return machine;
          }
        }
      }
    }

    if (peerAddress && peerAddress->isNull() == false)
    {
      for (Machine *machine : machines)
      {
        if (machineMatchesPeerAddress(machine, *peerAddress, peerAddressText))
        {
          return machine;
        }
      }
    }

    if (private4 != 0)
    {
      for (Machine *machine : machines)
      {
        if (machine && machine->private4 == private4)
        {
          return machine;
        }
      }
    }

    return nullptr;
  }

  Machine *findMachineByUUID(uint128_t uuid) const
  {
    if (uuid == 0)
    {
      return nullptr;
    }

    if (auto it = machinesByUUID.find(uuid); it != machinesByUUID.end())
    {
      return it->second;
    }

    return nullptr;
  }

  bool clusterTopologyContainsMachineIdentity(const ClusterTopology& topology, const ClusterMachine& clusterMachine) const
  {
    for (const ClusterMachine& existing : topology.machines)
    {
      if (existing.sameIdentityAs(clusterMachine))
      {
        return true;
      }
    }

    return false;
  }

  static bool resolveClusterMachineSchemaKey(const ClusterMachine& clusterMachine, String& schemaKey)
  {
    if (clusterMachine.cloudPresent() && clusterMachine.cloud.schema.size() > 0)
    {
      schemaKey.assign(clusterMachine.cloud.schema);
      return true;
    }

    schemaKey.clear();
    return false;
  }

  void applyBrainViewRuntimeMetadataToMachine(Machine *machine, BrainView *brain)
  {
    if (machine == nullptr || brain == nullptr)
    {
      return;
    }

    machine->brain = brain;
    brain->machine = machine;
    if (brain->kernel.size() > 0)
    {
      machine->kernel = brain->kernel;
    }
    if (brain->osID.size() > 0)
    {
      machine->osID = brain->osID;
    }
    if (brain->osVersionID.size() > 0)
    {
      machine->osVersionID = brain->osVersionID;
    }
    if (brain->boottimens > 0)
    {
      machine->lastUpdatedOSMs = brain->boottimens / 1'000'000;
    }
  }

  void linkBrainViewToMachine(Machine *machine)
  {
    if (machine == nullptr || machine->isBrain == false)
    {
      return;
    }

    for (BrainView *brain : brains)
    {
      if (brain == nullptr)
      {
        continue;
      }

      if ((brain->uuid != 0 && machine->uuid != 0 && brain->uuid == machine->uuid) || machineMatchesPeerAddress(machine, brain->peerAddress, &brain->peerAddressText))
      {
        applyBrainViewRuntimeMetadataToMachine(machine, brain);
        return;
      }

      for (const ClusterMachinePeerAddress& candidate : brain->peerAddresses)
      {
        IPAddress candidateAddress = {};
        if (ClusterMachine::parseIPAddressLiteral(candidate.address, candidateAddress) == false)
        {
          continue;
        }

        if (machineMatchesPeerAddress(machine, candidateAddress, &candidate.address))
        {
          applyBrainViewRuntimeMetadataToMachine(machine, brain);
          return;
        }
      }

      if (machine->private4 != 0 && brain->private4 != 0 && machine->private4 == brain->private4 && brain->peerAddress.isNull() && brain->peerAddressText.size() == 0)
      {
        applyBrainViewRuntimeMetadataToMachine(machine, brain);
        return;
      }
    }
  }

  void synchronizeBrainUUIDToMachine(BrainView *brain)
  {
    if (brain == nullptr || brain->uuid == 0)
    {
      return;
    }

    Machine *machine = brain->machine;
    if (machine == nullptr)
    {
      machine = findMachineByIdentity(0, brain->private4, &brain->peerAddresses,
                                      brain->peerAddress.isNull() ? nullptr : &brain->peerAddress,
                                      brain->peerAddressText.size() > 0 ? &brain->peerAddressText : nullptr);
      if (machine == nullptr)
      {
        return;
      }

      applyBrainViewRuntimeMetadataToMachine(machine, brain);
    }

    if (machine->uuid == brain->uuid)
    {
      return;
    }

    if (machine->cloudID.size() > 0)
    {
      return;
    }

    if (machine->uuid != 0)
    {
      machinesByUUID.erase(machine->uuid);
    }

    machine->uuid = brain->uuid;
    machinesByUUID.insert_or_assign(machine->uuid, machine);
  }

  static uint32_t stableNonzeroRackUUIDForText(const String& text)
  {
    if (text.size() == 0)
    {
      return 0;
    }

    uint64_t hash = 1'469'598'103'934'665'603ULL;
    for (uint64_t i = 0; i < uint64_t(text.size()); i += 1)
    {
      hash ^= uint64_t(uint8_t(text[i]));
      hash *= 1'099'511'628'211ULL;
    }

    uint32_t rackUUID = uint32_t(hash ^ (hash >> 32));
    return rackUUID != 0 ? rackUUID : 1u;
  }

  uint32_t synthesizeTestClusterRackUUID(const ClusterMachine& clusterMachine, uint32_t resolvedPrivate4, const String& resolvedPeerAddressText) const
  {
    if (brainConfig.runtimeEnvironment.test.enabled == false || clusterMachine.rackUUID != 0)
    {
      return clusterMachine.rackUUID;
    }

    if (resolvedPrivate4 != 0)
    {
      return resolvedPrivate4;
    }

    if (uint32_t rackUUID = stableNonzeroRackUUIDForText(resolvedPeerAddressText))
    {
      return rackUUID;
    }

    Vector<ClusterMachinePeerAddress> candidates = {};
    resolveClusterMachinePeerAddresses(clusterMachine, candidates);
    for (const ClusterMachinePeerAddress& candidate : candidates)
    {
      if (uint32_t rackUUID = stableNonzeroRackUUIDForText(candidate.address))
      {
        return rackUUID;
      }
    }

    if (uint32_t rackUUID = stableNonzeroRackUUIDForText(clusterMachine.ssh.address))
    {
      return rackUUID;
    }

    return 1;
  }

  void applyClusterMachineRecord(Machine *machine, const ClusterMachine& clusterMachine, uint32_t resolvedPrivate4, const IPAddress& resolvedPeerAddress, const String& resolvedPeerAddressText)
  {
    if (machine == nullptr)
    {
      return;
    }

    String schema = {};
    (void)resolveClusterMachineSchemaKey(clusterMachine, schema);
    machine->slug = schema;
    machine->lifetime = clusterMachine.lifetime;
    if (clusterMachine.cloudPresent())
    {
      machine->type = clusterMachine.cloud.providerMachineType;
      machine->cloudID = clusterMachine.cloud.cloudID;
    }
    else
    {
      machine->type.clear();
      machine->cloudID.clear();
    }
    machine->topologySource = uint8_t(clusterMachine.source);
    machine->sshAddress = clusterMachine.ssh.address;
    machine->sshPort = clusterMachine.ssh.port > 0 ? clusterMachine.ssh.port : 22;
    machine->sshUser = clusterMachine.ssh.user;
    machine->sshPrivateKeyPath = clusterMachine.ssh.privateKeyPath;
    machine->sshHostPublicKeyOpenSSH = clusterMachine.ssh.hostPublicKeyOpenSSH;
    machine->publicAddress.clear();
    machine->privateAddress.clear();
    if (const ClusterMachineAddress *publicAddress = prodigyFirstClusterMachineAddress(clusterMachine.addresses.publicAddresses); publicAddress != nullptr)
    {
      machine->publicAddress = publicAddress->address;
    }
    if (const ClusterMachineAddress *privateAddress = prodigyFirstClusterMachineAddress(clusterMachine.addresses.privateAddresses); privateAddress != nullptr)
    {
      machine->privateAddress = privateAddress->address;
    }
    prodigyCollectClusterMachinePeerAddresses(clusterMachine, machine->peerAddresses);
    if (machine->privateAddress.size() == 0 && resolvedPeerAddressText.size() > 0)
    {
      machine->privateAddress = resolvedPeerAddressText;
    }
    else if (machine->privateAddress.size() == 0 && resolvedPrivate4 != 0)
    {
      struct in_addr address = {};
      address.s_addr = resolvedPrivate4;
      char buffer[INET_ADDRSTRLEN] = {};
      if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) != nullptr)
      {
        machine->privateAddress.assign(buffer);
      }
    }

    machine->ownershipMode = uint8_t(clusterMachine.ownership.mode);
    machine->ownershipLogicalCoresCap = clusterMachine.ownership.nLogicalCoresCap;
    machine->ownershipMemoryMBCap = clusterMachine.ownership.nMemoryMBCap;
    machine->ownershipStorageMBCap = clusterMachine.ownership.nStorageMBCap;
    machine->ownershipLogicalCoresBasisPoints = clusterMachine.ownership.nLogicalCoresBasisPoints;
    machine->ownershipMemoryBasisPoints = clusterMachine.ownership.nMemoryBasisPoints;
    machine->ownershipStorageBasisPoints = clusterMachine.ownership.nStorageBasisPoints;
    machine->totalLogicalCores = clusterMachine.totalLogicalCores;
    machine->totalMemoryMB = clusterMachine.totalMemoryMB;
    machine->totalStorageMB = clusterMachine.totalStorageMB;
    machine->ownedLogicalCores = clusterMachine.ownedLogicalCores;
    machine->ownedMemoryMB = clusterMachine.ownedMemoryMB;
    machine->ownedStorageMB = clusterMachine.ownedStorageMB;

    bool thisIsMachine = clusterMachineMatchesThisBrain(clusterMachine);
    uint128_t resolvedMachineUUID = clusterMachine.uuid;
    if (resolvedMachineUUID == 0)
    {
      if (thisIsMachine && thisNeuron != nullptr && thisNeuron->uuid != 0 && clusterMachine.cloud.cloudID.size() == 0)
      {
        resolvedMachineUUID = thisNeuron->uuid;
      }
      else if (machine->uuid != 0)
      {
        resolvedMachineUUID = machine->uuid;
      }
    }
    machine->uuid = resolvedMachineUUID;
    uint32_t rackUUID = synthesizeTestClusterRackUUID(clusterMachine, resolvedPrivate4, resolvedPeerAddressText);
    machine->rackUUID = rackUUID != 0 ? rackUUID : 1;
    machine->private4 = resolvedPrivate4;
    machine->gatewayPrivate4 = 0;
    if (clusterMachine.resolvePrivate4Gateway(machine->gatewayPrivate4) == false && thisNeuron != nullptr)
    {
      machine->gatewayPrivate4 = thisNeuron->gateway4.v4;
    }
    machine->creationTimeMs = clusterMachine.creationTimeMs;
    machine->isBrain = clusterMachine.isBrain;
    machine->isThisMachine = thisIsMachine;
    machine->neuron.machine = machine;
    prodigyConfigureMachineNeuronEndpoint(*machine, thisNeuron, &localBrainPeerAddresses);
  }

  bool restoreBrainsFromClusterTopology(const ClusterTopology& topology)
  {
    bool restoredAny = false;

    for (const ClusterMachine& clusterMachine : topology.machines)
    {
      if (clusterMachine.isBrain == false)
      {
        continue;
      }

      IPAddress peerAddress = {};
      String peerAddressText = {};
      bool havePeerAddress = resolveClusterMachinePeerAddress(clusterMachine, peerAddress, peerAddressText);
      Vector<ClusterMachinePeerAddress> peerAddresses;
      resolveClusterMachinePeerAddresses(clusterMachine, peerAddresses);
      uint32_t resolvedPrivate4 = 0;
      (void)resolveClusterMachinePrivate4(clusterMachine, resolvedPrivate4);
      if (clusterMachineMatchesThisBrain(clusterMachine))
      {
        adoptLocalBrainPeerAddresses(peerAddresses);
        if (havePeerAddress)
        {
          adoptLocalBrainPeerAddress(peerAddress, peerAddressText);
        }
        continue;
      }

      BrainView *brain = nullptr;
      if (peerAddresses.empty() == false)
      {
        brain = findBrainViewByPeerAddresses(peerAddresses);
      }
      if (brain == nullptr && havePeerAddress)
      {
        brain = findBrainViewByPeerAddress(peerAddress);
      }
      if (brain == nullptr && clusterMachine.uuid != 0)
      {
        brain = findBrainViewByUUID(clusterMachine.uuid);
      }
      if (brain == nullptr && resolvedPrivate4 != 0)
      {
        brain = findBrainViewByPrivate4(resolvedPrivate4);
      }
      if (brain == nullptr)
      {
        brain = new BrainView();
        brains.insert(brain);
      }

      if (havePeerAddress)
      {
        brain->peerAddress = peerAddress;
        brain->peerAddressText = peerAddressText;
      }
      else
      {
        brain->peerAddress = {};
        brain->peerAddressText.clear();
      }

      adoptBrainPeerAddresses(brain, peerAddresses);

      if (clusterMachine.uuid != 0 || brain->uuid == 0)
      {
        brain->uuid = clusterMachine.uuid;
      }
      brain->private4 = resolvedPrivate4;
      brain->gatewayPrivate4 = 0;
      if (clusterMachine.resolvePrivate4Gateway(brain->gatewayPrivate4) == false && thisNeuron != nullptr)
      {
        brain->gatewayPrivate4 = thisNeuron->gateway4.v4;
      }
      brain->creationTimeMs = clusterMachine.creationTimeMs;
      linkBrainViewToMachine(findMachineByIdentity(clusterMachine.uuid, resolvedPrivate4, &peerAddresses, havePeerAddress ? &peerAddress : nullptr, havePeerAddress ? &peerAddressText : nullptr));
      synchronizeBrainUUIDToMachine(brain);
      restoredAny = true;
    }

    return restoredAny;
  }

  void initializeBrainPeerIfNeeded(BrainView *brain)
  {
    if (brain == nullptr || (brain->private4 == 0 && brain->peerAddress.isNull() && brain->peerAddresses.empty()))
    {
      PRODIGY_DEBUG_LOG(
                   "prodigy brain init-peer-skip reason=missing-identity stream=%p private4=%u fd=%d isFixed=%d fslot=%d\n",
                   static_cast<void *>(brain),
                   unsigned(brain ? brain->private4 : 0),
                   brain ? brain->fd : -1,
                   brain ? int(brain->isFixedFile) : 0,
                   brain ? brain->fslot : -1);
      PRODIGY_DEBUG_FLUSH();
      return;
    }

    // Resume/reconcile paths can rebuild topology in synchronous or test-only contexts
    // before the Ring dispatcher exists. Peer socket bring-up only makes sense once
    // the event loop is actually live.
    if (RingDispatcher::dispatcher == nullptr || Ring::getRingFD() <= 0)
    {
      PRODIGY_DEBUG_LOG(
                   "prodigy brain init-peer-skip reason=ring-inactive private4=%u dispatcher=%p ringFD=%d\n",
                   unsigned(brain->private4),
                   static_cast<void *>(RingDispatcher::dispatcher),
                   Ring::getRingFD());
      PRODIGY_DEBUG_FLUSH();
      return;
    }

    RingDispatcher::installMultiplexee(brain, this);

    bool isDevMode = BrainBase::controlPlaneDevModeEnabled();
    brain->connectTimeoutMs = BrainBase::controlPlaneConnectTimeoutMs(isDevMode);
    brain->nDefaultAttemptsBudget = BrainBase::controlPlaneConnectAttemptsBudget(isDevMode);
    brain->setKeepaliveTimeoutSeconds(brainPeerKeepaliveSeconds);

    if (brain->connected)
    {
      PRODIGY_DEBUG_LOG(
                   "prodigy brain init-peer-skip reason=already-connected private4=%u fd=%d isFixed=%d fslot=%d\n",
                   unsigned(brain->private4),
                   brain->fd,
                   int(brain->isFixedFile),
                   brain->fslot);
      PRODIGY_DEBUG_FLUSH();
      return;
    }

    if (brainWaiters.contains(brain))
    {
      PRODIGY_DEBUG_LOG(
                   "prodigy brain init-peer-skip reason=waiter-active private4=%u fd=%d isFixed=%d fslot=%d\n",
                   unsigned(brain->private4),
                   brain->fd,
                   int(brain->isFixedFile),
                   brain->fslot);
      PRODIGY_DEBUG_FLUSH();
      return;
    }

    if (brain->isFixedFile)
    {
      if (brain->fslot >= 0)
      {
        if (staleDisconnectedFixedFileBrainPeer(brain))
        {
          PRODIGY_DEBUG_LOG(
                       "prodigy brain init-peer-stale-fixedfile private4=%u fd=%d isFixed=%d fslot=%d\n",
                       unsigned(brain->private4),
                       brain->fd,
                       int(brain->isFixedFile),
                       brain->fslot);
          PRODIGY_DEBUG_FLUSH();
          abandonSocketGeneration(brain);
        }
        else
        {
          PRODIGY_DEBUG_LOG(
                       "prodigy brain init-peer-skip reason=fixedfile-present private4=%u fd=%d isFixed=%d fslot=%d\n",
                       unsigned(brain->private4),
                       brain->fd,
                       int(brain->isFixedFile),
                       brain->fslot);
          PRODIGY_DEBUG_FLUSH();
          return;
        }
      }
    }
    else if (brain->fd >= 0)
    {
      PRODIGY_DEBUG_LOG(
                   "prodigy brain init-peer-skip reason=fd-present private4=%u fd=%d isFixed=%d fslot=%d\n",
                   unsigned(brain->private4),
                   brain->fd,
                   int(brain->isFixedFile),
                   brain->fslot);
      PRODIGY_DEBUG_FLUSH();
      return;
    }

    uint32_t connectAttemptTimeMs = BrainBase::machineInitialConnectAttemptTimeMs(
        brain->creationTimeMs,
        brain->connectTimeoutMs,
        brain->nDefaultAttemptsBudget,
        isDevMode);

    if (shouldWeConnectToBrain(brain))
    {
      brain->weConnectToIt = true;
      configureBrainPeerConnectAddress(brain);
      PRODIGY_DEBUG_LOG(
                   "prodigy brain init-peer-connect private4=%u fd=%d isFixed=%d fslot=%d daddrLen=%u\n",
                   unsigned(brain->private4),
                   brain->fd,
                   int(brain->isFixedFile),
                   brain->fslot,
                   unsigned(brain->daddrLen));
      PRODIGY_DEBUG_FLUSH();

      if (installBrainPeerSocket(brain))
      {
        PRODIGY_DEBUG_LOG(
                     "prodigy brain init-peer-connect-arm private4=%u fd=%d isFixed=%d fslot=%d\n",
                     unsigned(brain->private4),
                     brain->fd,
                     int(brain->isFixedFile),
                     brain->fslot);
        PRODIGY_DEBUG_FLUSH();
        brain->attemptConnectForMs(connectAttemptTimeMs);
      }
      else
      {
        PRODIGY_DEBUG_LOG(
                     "prodigy brain init-peer-connect-install-fail private4=%u fd=%d isFixed=%d fslot=%d daddrLen=%u\n",
                     unsigned(brain->private4),
                     brain->fd,
                     int(brain->isFixedFile),
                     brain->fslot,
                     unsigned(brain->daddrLen));
        PRODIGY_DEBUG_FLUSH();
        armBrainReconnectWaiterIfAbsent(
            brain,
            brainPeerReconnectDelayMs(brain),
            true,
            "init-peer-connect-install-fail",
            true);
      }
    }
    else
    {
      brain->weConnectToIt = false;
      PRODIGY_DEBUG_LOG(
                   "prodigy brain init-peer-wait private4=%u fd=%d isFixed=%d fslot=%d\n",
                   unsigned(brain->private4),
                   brain->fd,
                   int(brain->isFixedFile),
                   brain->fslot);
      PRODIGY_DEBUG_FLUSH();

      TimeoutPacket *timeout = new TimeoutPacket();
      timeout->flags = uint64_t(BrainTimeoutFlags::brainMissing);
      timeout->originator = brain;
      timeout->dispatcher = this;
      timeout->setTimeoutMs(connectAttemptTimeMs);

      brainWaiters.insert_or_assign(brain, timeout);
      basics_log("brainMissing waiter armed private4=%u packet=%p reason=init-peer-wait timeoutMs=%lld\n",
                 brain->private4,
                 static_cast<void *>(timeout),
                 (long long)connectAttemptTimeMs);
      Ring::queueTimeout(timeout);
    }
  }

  void initializeAllBrainPeersIfNeeded(void)
  {
    for (BrainView *brain : brains)
    {
      initializeBrainPeerIfNeeded(brain);
    }
  }

  bool normalizeAdoptedClusterMachine(const ClusterMachine& requested, const String& defaultSSHUser, const String& defaultSSHPrivateKeyPath, ClusterMachine& normalized, String& failure) const
  {
    normalized = requested;
    normalized.source = ClusterMachineSource::adopted;
    if (normalized.backing == ClusterMachineBacking::cloud)
    {
      normalized.hasCloud = true;
      String schemaKey = {};
      if (resolveClusterMachineSchemaKey(requested, schemaKey) == false)
      {
        failure.assign("cloud adopted machine requires cloud.schema"_ctv);
        return false;
      }

      auto it = brainConfig.configBySlug.find(schemaKey);
      if (it == brainConfig.configBySlug.end())
      {
        failure.snprintf<"unknown machine schema '{}'"_ctv>(schemaKey);
        return false;
      }

      const MachineConfig& machineConfig = it->second;
      normalized.cloud.schema = schemaKey;
      normalized.kind = machineConfig.kind;
      if (normalized.cloud.providerMachineType.size() == 0)
      {
        failure.assign("cloud adopted machine requires cloud.providerMachineType"_ctv);
        return false;
      }

      if (normalized.cloud.cloudID.size() == 0)
      {
        failure.assign("cloud adopted machine requires cloud.cloudID"_ctv);
        return false;
      }
    }
    else if (normalized.cloudPresent())
    {
      failure.assign("owned adopted machine must not include cloud fields"_ctv);
      return false;
    }

    if (normalized.ssh.user.size() == 0 && defaultSSHUser.size() > 0)
    {
      normalized.ssh.user.assign(defaultSSHUser);
    }

    if (normalized.ssh.privateKeyPath.size() == 0 && defaultSSHPrivateKeyPath.size() > 0)
    {
      normalized.ssh.privateKeyPath.assign(defaultSSHPrivateKeyPath);
    }

    if (normalized.ssh.user.size() == 0)
    {
      failure.assign("adopted machine sshUser required"_ctv);
      return false;
    }

    if (normalized.ssh.privateKeyPath.size() == 0)
    {
      failure.assign("adopted machine sshPrivateKeyPath required"_ctv);
      return false;
    }

    if (normalized.ssh.port == 0)
    {
      normalized.ssh.port = 22;
    }

    if (normalized.ssh.address.size() == 0)
    {
      if (const ClusterMachineAddress *privateAddress = prodigyFirstClusterMachineAddress(normalized.addresses.privateAddresses); privateAddress != nullptr)
      {
        normalized.ssh.address = privateAddress->address;
      }
      else if (const ClusterMachineAddress *publicAddress = prodigyFirstClusterMachineAddress(normalized.addresses.publicAddresses); publicAddress != nullptr)
      {
        normalized.ssh.address = publicAddress->address;
      }
    }

    if (normalized.ssh.address.size() == 0)
    {
      failure.assign("adopted machine sshAddress required"_ctv);
      return false;
    }

    if (normalized.ssh.hostPublicKeyOpenSSH.size() == 0)
    {
      failure.assign("adopted machine ssh.hostPublicKeyOpenSSH required"_ctv);
      return false;
    }

    String label = {};
    normalized.renderIdentityLabel(label);
    PRODIGY_DEBUG_LOG( "prodigy mothership adopted-probe-start machine=%.*s ssh=%.*s:%u user=%.*s\n",
                 int(label.size()),
                 label.c_str(),
                 int(normalized.ssh.address.size()),
                 normalized.ssh.address.c_str(),
                 unsigned(normalized.ssh.port),
                 int(normalized.ssh.user.size()),
                 normalized.ssh.user.c_str());
    PRODIGY_DEBUG_FLUSH();

    ProdigyRemoteMachineResources probedResources = {};
    String probeFailure;
    if (prodigyProbeRemoteMachineResources(normalized, probedResources, &probeFailure) == false)
    {
      failure.snprintf<"failed to probe adopted machine '{}': {}"_ctv>(label, probeFailure);
      return false;
    }
    PRODIGY_DEBUG_LOG( "prodigy mothership adopted-probe-ok machine=%.*s logicalCores=%u memoryMB=%u storageMB=%u peerAddresses=%u\n",
                 int(label.size()),
                 label.c_str(),
                 unsigned(probedResources.totalLogicalCores),
                 unsigned(probedResources.totalMemoryMB),
                 unsigned(probedResources.totalStorageMB),
                 uint32_t(probedResources.peerAddresses.size()));
    PRODIGY_DEBUG_FLUSH();

    if (clusterMachineApplyOwnedResourcesFromTotals(normalized, probedResources.totalLogicalCores, probedResources.totalMemoryMB, probedResources.totalStorageMB, brainConfig.machineReservedResources, &failure) == false)
    {
      return false;
    }

    uint32_t resolvedPrivate4 = 0;
    if (resolveClusterMachinePrivate4(normalized, resolvedPrivate4) == false)
    {
      normalized.peerAddresses.clear();
      for (const ClusterMachinePeerAddress& candidate : probedResources.peerAddresses)
      {
        prodigyAppendUniqueClusterMachinePeerAddress(normalized.peerAddresses, candidate);
      }
      prodigyAssignClusterMachineAddressesFromPeerCandidates(normalized.addresses, probedResources.peerAddresses);
      ClusterTopology candidateTopology = {};
      for (const Machine *machine : machines)
      {
        if (machine == nullptr || machine->isBrain == false)
        {
          continue;
        }

        ClusterMachine existing = {};
        existing.isBrain = machine->isBrain;
        existing.uuid = machine->uuid;
        existing.ssh.address = machine->sshAddress;
        for (const ClusterMachinePeerAddress& candidate : machine->peerAddresses)
        {
          prodigyAppendUniqueClusterMachinePeerAddress(existing.peerAddresses, candidate);
        }
        prodigyAssignClusterMachineAddressesFromPeerCandidates(existing.addresses, machine->peerAddresses);
        String privateGateway = {};
        if (machine->gatewayPrivate4 != 0)
        {
          IPAddress gatewayAddress = {};
          gatewayAddress.v4 = machine->gatewayPrivate4;
          gatewayAddress.is6 = false;
          (void)ClusterMachine::renderIPAddressLiteral(gatewayAddress, privateGateway);
        }
        prodigyAppendUniqueClusterMachineAddress(existing.addresses.privateAddresses, machine->privateAddress, 0, privateGateway);
        prodigyAppendUniqueClusterMachineAddress(existing.addresses.publicAddresses, machine->publicAddress);
        candidateTopology.machines.push_back(existing);
      }

      ClusterMachine candidateSelf = normalized;
      candidateTopology.machines.push_back(candidateSelf);
      prodigyNormalizeClusterTopologyPeerAddresses(candidateTopology);
      if (candidateTopology.machines.empty() == false)
      {
        normalized.addresses = candidateTopology.machines.back().addresses;
      }

      Vector<ClusterMachinePeerAddress> normalizedCandidates = {};
      prodigyCollectClusterMachinePeerAddresses(normalized, normalizedCandidates);
      for (const ClusterMachinePeerAddress& candidate : normalizedCandidates)
      {
        IPAddress parsedAddress = {};
        if (ClusterMachine::parseIPAddressLiteral(candidate.address, parsedAddress) == false)
        {
          continue;
        }

        if (resolvedPrivate4 == 0 && parsedAddress.is6 == false && prodigyClusterMachinePeerAddressIsPrivate(candidate))
        {
          resolvedPrivate4 = parsedAddress.v4;
        }
      }
    }

    if (normalized.addresses.privateAddresses.empty())
    {
      if (resolvedPrivate4 != 0)
      {
        struct in_addr address = {};
        address.s_addr = resolvedPrivate4;
        char buffer[INET_ADDRSTRLEN] = {};
        if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) != nullptr)
        {
          String privateAddress = {};
          privateAddress.assign(buffer);
          prodigyAppendUniqueClusterMachineAddress(normalized.addresses.privateAddresses, privateAddress);
        }
      }
    }

    if (normalized.addresses.privateAddresses.empty() && normalized.addresses.publicAddresses.empty())
    {
      ClusterTopology singletonTopology = {};
      singletonTopology.machines.push_back(normalized);
      prodigyNormalizeClusterTopologyPeerAddresses(singletonTopology);
      normalized.addresses = singletonTopology.machines[0].addresses;
    }

    if (normalized.ssh.address.size() == 0)
    {
      if (const ClusterMachineAddress *privateAddress = prodigyFirstClusterMachineAddress(normalized.addresses.privateAddresses); privateAddress != nullptr)
      {
        normalized.ssh.address = privateAddress->address;
      }
      else if (const ClusterMachineAddress *publicAddress = prodigyFirstClusterMachineAddress(normalized.addresses.publicAddresses); publicAddress != nullptr)
      {
        normalized.ssh.address = publicAddress->address;
      }
    }

    if (normalized.creationTimeMs == 0)
    {
      normalized.creationTimeMs = Time::now<TimeResolution::ms>();
    }

    return true;
  }

  bool clusterMachineMatchesThisBrain(const ClusterMachine& machine) const
  {
    if (thisNeuron == nullptr)
    {
      return false;
    }

    if (machine.uuid != 0 && machine.uuid == thisNeuron->uuid)
    {
      return true;
    }

    bool hadExplicitPeerAddress = false;
    auto explicitAddressMatches = [&](const String& addressText) -> bool {
      if (addressText.size() == 0)
      {
        return false;
      }

      hadExplicitPeerAddress = true;
      IPAddress peerAddress = {};
      return ClusterMachine::parseIPAddressLiteral(addressText, peerAddress) && localBrainAddressMatches(peerAddress);
    };

    for (const ClusterMachineAddress& addressText : machine.addresses.privateAddresses)
    {
      if (explicitAddressMatches(addressText.address))
      {
        return true;
      }
    }

    for (const ClusterMachineAddress& addressText : machine.addresses.publicAddresses)
    {
      if (explicitAddressMatches(addressText.address))
      {
        return true;
      }
    }

    if (explicitAddressMatches(machine.ssh.address))
    {
      return true;
    }

    if (hadExplicitPeerAddress)
    {
      return false;
    }

    IPAddress peerAddress = {};
    String peerAddressText = {};
    return resolveClusterMachinePeerAddress(machine, peerAddress, peerAddressText) && localBrainAddressMatches(peerAddress);
  }

  bool probeCandidateBrainReachability(const ClusterTopology& currentTopology, const ClusterMachine& candidate, AddMachines& response) const
  {
    response.reachabilityProbeAddress.clear();
    response.reachabilityResults.clear();

    if (candidate.isBrain == false)
    {
      return true;
    }

    IPAddress targetAddress = {};
    if (candidate.resolvePeerAddress(targetAddress, &response.reachabilityProbeAddress) == false || response.reachabilityProbeAddress.size() == 0)
    {
      response.failure.assign("candidate brain requires a reachable ipv4 or ipv6 address"_ctv);
      return false;
    }

    Vector<ClusterMachine> sourceBrains;
    for (const ClusterMachine& machine : currentTopology.machines)
    {
      if (machine.isBrain)
      {
        sourceBrains.push_back(machine);
      }
    }

    if (sourceBrains.empty())
    {
      return true;
    }

    return prodigyProbeAddressFromClusterBrains(
        sourceBrains,
        response.reachabilityProbeAddress,
        [this](const ClusterMachine& sourceBrain, const String& targetAddress, BrainReachabilityProbeResult& result, String& failure) -> bool {
          if (clusterMachineMatchesThisBrain(sourceBrain))
          {
            return prodigyProbeReachabilityLocally(targetAddress, result, &failure);
          }

          return prodigyProbeReachabilityOverSSH(sourceBrain, targetAddress, result, &failure);
        },
        response.reachabilityResults,
        response.failure);
  }

  bool restoreMachinesFromClusterTopology(const ClusterTopology& topology)
  {
    bool restoredAny = false;
    bytell_hash_set<Machine *> knownMachines = machines;

    for (const ClusterMachine& clusterMachine : topology.machines)
    {
      uint32_t resolvedPrivate4 = 0;
      (void)resolveClusterMachinePrivate4(clusterMachine, resolvedPrivate4);
      IPAddress resolvedPeerAddress = {};
      String resolvedPeerAddressText = {};
      bool havePeerAddress = resolveClusterMachinePeerAddress(clusterMachine, resolvedPeerAddress, resolvedPeerAddressText);
      Vector<ClusterMachinePeerAddress> resolvedPeerAddresses;
      resolveClusterMachinePeerAddresses(clusterMachine, resolvedPeerAddresses);

      Machine *machine = findMachineByIdentity(clusterMachine.uuid, resolvedPrivate4, &resolvedPeerAddresses, havePeerAddress ? &resolvedPeerAddress : nullptr, havePeerAddress ? &resolvedPeerAddressText : nullptr);
      bool knownMachine = (machine != nullptr) && knownMachines.contains(machine);
      PRODIGY_DEBUG_LOG( "prodigy topology restore-machine begin clusterUUID=%llu resolvedPrivate4=%u isBrain=%d known=%d machine=%p uuidPresent=%d peerCount=%u peer=%s\n",
                   (unsigned long long)clusterMachine.uuid,
                   unsigned(resolvedPrivate4),
                   int(clusterMachine.isBrain),
                   int(knownMachine),
                   machine,
                   int(clusterMachine.uuid != 0),
                   uint32_t(resolvedPeerAddresses.size()),
                   resolvedPeerAddressText.c_str());
      PRODIGY_DEBUG_FLUSH();
      if (machine == nullptr)
      {
        machine = new Machine();
        PRODIGY_DEBUG_LOG( "prodigy topology restore-machine allocated machine=%p\n", machine);
        PRODIGY_DEBUG_FLUSH();
      }

      applyClusterMachineRecord(machine, clusterMachine, resolvedPrivate4, resolvedPeerAddress, resolvedPeerAddressText);
      PRODIGY_DEBUG_LOG( "prodigy topology restore-machine applied machine=%p uuid=%llu private4=%u isBrain=%d isThisMachine=%d slug=%s cloudID=%s\n",
                   machine,
                   (unsigned long long)machine->uuid,
                   unsigned(machine->private4),
                   int(machine->isBrain),
                   int(machine->isThisMachine),
                   machine->slug.c_str(),
                   machine->cloudID.c_str());
      PRODIGY_DEBUG_FLUSH();

      // finishMachineConfig() can arm live neuron-control connects. Register the
      // Machine/NeuronView in the runtime sets first so any immediate connect CQE
      // is recognized as a neuron socket instead of falling through unmatched.
      machines.insert(machine);
      neurons.insert(&machine->neuron);
      if (machine->uuid != 0)
      {
        machinesByUUID.insert_or_assign(machine->uuid, machine);
      }

      if (knownMachine == false)
      {
        PRODIGY_DEBUG_LOG( "prodigy topology restore-machine finish-begin machine=%p uuid=%llu private4=%u\n",
                     machine,
                     (unsigned long long)machine->uuid,
                     unsigned(machine->private4));
        PRODIGY_DEBUG_FLUSH();
        finishMachineConfig(machine);
        PRODIGY_DEBUG_LOG( "prodigy topology restore-machine finish-done machine=%p uuid=%llu private4=%u fd=%d isFixed=%d fslot=%d\n",
                     machine,
                     (unsigned long long)machine->uuid,
                     unsigned(machine->private4),
                     machine->neuron.fd,
                     int(machine->neuron.isFixedFile),
                     machine->neuron.fslot);
        PRODIGY_DEBUG_FLUSH();

        machine->state = BrainBase::machineBootstrapLifecycleState(machine->creationTimeMs);
      }
      else
      {
        PRODIGY_DEBUG_LOG( "prodigy topology restore-machine relink-begin machine=%p uuid=%llu private4=%u\n",
                     machine,
                     (unsigned long long)machine->uuid,
                     unsigned(machine->private4));
        PRODIGY_DEBUG_FLUSH();
        linkBrainViewToMachine(machine);
        PRODIGY_DEBUG_LOG( "prodigy topology restore-machine relink-done machine=%p uuid=%llu private4=%u brain=%p\n",
                     machine,
                     (unsigned long long)machine->uuid,
                     unsigned(machine->private4),
                     machine->brain);
        PRODIGY_DEBUG_FLUSH();
      }

      if (machine->uuid != 0)
      {
        machinesByUUID.insert_or_assign(machine->uuid, machine);
      }
      if (machine->isThisMachine && thisNeuron != nullptr)
      {
        machine->kernel = thisNeuron->kernel;
        machine->osID = thisNeuron->osID;
        machine->osVersionID = thisNeuron->osVersionID;
        machine->lastUpdatedOSMs = thisNeuron->bootTimeMs;
        thisNeuron->ensureDeferredHardwareInventoryProgress();
        // The local neuron can finish deferred inventory before topology
        // restore links it to the runtime Machine. Replay any completed
        // inventory now so created seeds do not lose self hardware state.
        if (const MachineHardwareProfile *hardware = thisNeuron->latestHardwareProfileIfReady(); hardware != nullptr)
        {
          applyMachineHardwareProfile(machine, *hardware);
          promoteMachineToHealthyIfReady(machine);
        }
      }
      PRODIGY_DEBUG_LOG( "prodigy topology restore-machine complete machine=%p uuid=%llu private4=%u\n",
                   machine,
                   (unsigned long long)machine->uuid,
                   unsigned(machine->private4));
      PRODIGY_DEBUG_FLUSH();

      restoredAny = true;
    }

    return restoredAny;
  }

  void noteLocalContainerHealthy(uint128_t containerUUID) override
  {
    PRODIGY_DEBUG_LOG(
                 "brain noteLocalContainerHealthy enter uuid=%llu weAreMaster=%d tracked=%llu\n",
                 (unsigned long long)containerUUID,
                 int(weAreMaster),
                 (unsigned long long)containers.size());
    PRODIGY_DEBUG_FLUSH();

    if (weAreMaster == false)
    {
      BrainView *masterPeer = currentMasterPeer();
      if (masterPeer != nullptr)
      {
        Message::construct(masterPeer->wBuffer, BrainTopic::replicateContainerHealthy, containerUUID);
        Ring::queueSend(masterPeer);
        PRODIGY_DEBUG_LOG(
                     "brain noteLocalContainerHealthy relay uuid=%llu peerPrivate4=%u peerFslot=%d\n",
                     (unsigned long long)containerUUID,
                     unsigned(masterPeer->private4),
                     masterPeer->fslot);
        PRODIGY_DEBUG_FLUSH();
      }
      return;
    }

    basics_log("brain local containerHealthy uuid=%llu containersTracked=%llu\n",
               (unsigned long long)containerUUID,
               (unsigned long long)containers.size());

    if (auto it = containers.find(containerUUID); it != containers.end())
    {
      ContainerView *container = it->second;
      ApplicationDeployment *deployment = nullptr;
      if (auto deploymentIt = deployments.find(container->deploymentID); deploymentIt != deployments.end())
      {
        deployment = deploymentIt->second;
      }

      basics_log("brain local containerHealthy apply uuid=%llu deploymentID=%llu appID=%u machinePrivate4=%u waitingOnContainers=%llu\n",
                 (unsigned long long)containerUUID,
                 (unsigned long long)container->deploymentID,
                 unsigned(ApplicationConfig::extractApplicationID(container->deploymentID)),
                 (container->machine ? unsigned(container->machine->private4) : 0u),
                 (unsigned long long)(deployment ? deployment->waitingOnContainers.size() : 0));

      if (deployment)
      {
        PRODIGY_DEBUG_LOG(
                     "brain noteLocalContainerHealthy apply uuid=%llu deploymentID=%llu appID=%u waitingBefore=%llu stateBefore=%u\n",
                     (unsigned long long)containerUUID,
                     (unsigned long long)container->deploymentID,
                     unsigned(ApplicationConfig::extractApplicationID(container->deploymentID)),
                     (unsigned long long)deployment->waitingOnContainers.size(),
                     unsigned(container->state));
        PRODIGY_DEBUG_FLUSH();
        deployment->containerIsHealthy(container);
        (void)advanceTlsResumptionLifecycleForDeployment(deployment->plan, Time::now<TimeResolution::ms>(), false);
        replicateContainerRuntimeStateToFollowers(container);
        PRODIGY_DEBUG_LOG(
                     "brain noteLocalContainerHealthy done uuid=%llu deploymentID=%llu appID=%u waitingAfter=%llu stateAfter=%u\n",
                     (unsigned long long)containerUUID,
                     (unsigned long long)container->deploymentID,
                     unsigned(ApplicationConfig::extractApplicationID(container->deploymentID)),
                     (unsigned long long)deployment->waitingOnContainers.size(),
                     unsigned(container->state));
        PRODIGY_DEBUG_FLUSH();
      }
      else
      {
        basics_log("brain local containerHealthy missing deployment for uuid=%llu deploymentID=%llu\n",
                   (unsigned long long)containerUUID,
                   (unsigned long long)container->deploymentID);
      }
    }
    else
    {
      basics_log("brain local containerHealthy missing uuid=%llu\n",
                 (unsigned long long)containerUUID);
    }
  }

  void noteLocalContainerRuntimeReady(uint128_t containerUUID) override
  {
    if (weAreMaster == false)
    {
      BrainView *masterPeer = currentMasterPeer();
      if (masterPeer != nullptr)
      {
        Message::construct(masterPeer->wBuffer, BrainTopic::replicateContainerRuntimeReady, containerUUID);
        Ring::queueSend(masterPeer);
      }
      return;
    }

    if (auto it = containers.find(containerUUID); it != containers.end())
    {
      ContainerView *container = it->second;
      if (container == nullptr)
      {
        return;
      }

      if (auto deploymentIt = deployments.find(container->deploymentID); deploymentIt != deployments.end() && deploymentIt->second != nullptr)
      {
        deploymentIt->second->containerIsRuntimeReady(container);
        replicateContainerRuntimeStateToFollowers(container);
      }
    }
  }

  void getMachines(CoroutineStack *coro)
  {
    ClusterTopology topology = {};
    (void)(loadAuthoritativeClusterTopology(topology) && restoreMachinesFromClusterTopology(topology));

    uint32_t suspendIndex = coro->nextSuspendIndex();

    bytell_hash_set<Machine *> knownMachines = machines;
    bytell_hash_map<uint128_t, Machine *> knownByUUID;
    for (Machine *machine : knownMachines)
    {
      if (machine && machine->uuid != 0)
      {
        knownByUUID.insert_or_assign(machine->uuid, machine);
      }
    }

    String inventoryFailure = {};
    iaas->getMachines(coro, thisNeuron->metro, machines, inventoryFailure);

    if (suspendIndex < coro->nextSuspendIndex())
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (inventoryFailure.size() > 0)
    {
      basics_log("machine inventory failed: %s\n", inventoryFailure.c_str());
      co_return;
    }

    Vector<Machine *> duplicateSnapshots;
    auto isGenericBootstrapMachineSnapshot = [](const Machine *machine) -> bool {
      return machine != nullptr && machine->slug.equals("bootstrap"_ctv) && machine->type.size() == 0 && machine->cloudID.size() == 0;
    };

    auto reconcileCanonicalMachineFromSnapshot = [&](Machine *canonical, Machine *candidate) -> void {
      if (canonical == nullptr || candidate == nullptr)
      {
        return;
      }

      auto assignRack = [&](Machine *machine, uint32_t rackUUID) -> void {
        if (machine == nullptr || rackUUID == 0)
        {
          return;
        }

        if (machine->rack != nullptr && machine->rack->uuid == rackUUID)
        {
          machine->rackUUID = rackUUID;
          return;
        }

        if (machine->rack != nullptr)
        {
          Rack *previousRack = machine->rack;
          previousRack->machines.erase(machine);
          if (previousRack->machines.empty())
          {
            racks.erase(previousRack->uuid);
            delete previousRack;
          }
        }

        Rack *rack = nullptr;
        if (auto rackIt = racks.find(rackUUID); rackIt != racks.end())
        {
          rack = rackIt->second;
        }
        else
        {
          rack = new Rack();
          rack->uuid = rackUUID;
          racks.insert_or_assign(rackUUID, rack);
        }

        machine->rackUUID = rackUUID;
        machine->rack = rack;
        rack->machines.insert(machine);
      };

      canonical->isBrain = candidate->isBrain;
      canonical->isThisMachine = candidate->isThisMachine;
      if (candidate->private4 != 0)
      {
        canonical->private4 = candidate->private4;
      }
      if (candidate->gatewayPrivate4 != 0)
      {
        canonical->gatewayPrivate4 = candidate->gatewayPrivate4;
      }
      if (isGenericBootstrapMachineSnapshot(candidate) == false || canonical->slug.size() == 0)
      {
        canonical->slug = candidate->slug;
        canonical->lifetime = candidate->lifetime;
        canonical->type = candidate->type;
        canonical->cloudID = candidate->cloudID;
      }
      if (candidate->sshAddress.size() > 0)
      {
        canonical->sshAddress = candidate->sshAddress;
      }
      if (candidate->sshPort != 0)
      {
        canonical->sshPort = candidate->sshPort;
      }
      if (candidate->sshUser.size() > 0)
      {
        canonical->sshUser = candidate->sshUser;
      }
      if (candidate->sshPrivateKeyPath.size() > 0)
      {
        canonical->sshPrivateKeyPath = candidate->sshPrivateKeyPath;
      }
      if (candidate->sshHostPublicKeyOpenSSH.size() > 0)
      {
        canonical->sshHostPublicKeyOpenSSH = candidate->sshHostPublicKeyOpenSSH;
      }
      if (candidate->publicAddress.size() > 0)
      {
        canonical->publicAddress = candidate->publicAddress;
      }
      if (candidate->privateAddress.size() > 0)
      {
        canonical->privateAddress = candidate->privateAddress;
      }
      if (candidate->peerAddresses.empty() == false)
      {
        canonical->peerAddresses = candidate->peerAddresses;
      }
      if (candidate->creationTimeMs != 0)
      {
        canonical->creationTimeMs = candidate->creationTimeMs;
      }
      canonical->neuron.machine = canonical;
      prodigyConfigureMachineNeuronEndpoint(*canonical, thisNeuron, &localBrainPeerAddresses);

      if (candidate->rackUUID != 0)
      {
        assignRack(canonical, candidate->rackUUID);
      }
    };

    for (Machine *candidate : machines)
    {
      if (knownMachines.contains(candidate))
      {
        continue;
      }

      Machine *canonical = nullptr;
      if (candidate->uuid != 0)
      {
        if (auto known = knownByUUID.find(candidate->uuid); known != knownByUUID.end())
        {
          canonical = known->second;
        }
      }

      if (canonical == nullptr)
      {
        for (Machine *knownMachine : knownMachines)
        {
          if (knownMachine != nullptr && prodigyMachinesShareIdentity(*knownMachine, *candidate))
          {
            canonical = knownMachine;
            break;
          }
        }
      }

      if (canonical != nullptr)
      {
        reconcileCanonicalMachineFromSnapshot(canonical, candidate);
        duplicateSnapshots.push_back(candidate);
        continue;
      }

      if (candidate->uuid != 0)
      {
        knownByUUID.insert_or_assign(candidate->uuid, candidate);
      }
    }

    for (Machine *snapshot : duplicateSnapshots)
    {
      machines.erase(snapshot);
      neurons.erase(&snapshot->neuron);

      if (snapshot->neuron.isFixedFile == false && snapshot->neuron.fd >= 0)
      {
        snapshot->neuron.close();
        snapshot->neuron.fd = -1;
      }

      delete snapshot;
    }

    for (Machine *machine : machines)
    {
      bool knownMachine = knownMachines.contains(machine);
      // finishMachineConfig() may issue live neuron-control connects for new
      // machines. Track the NeuronView before that happens so connect CQEs
      // route through the neuron branch instead of the unmatched fallback.
      neurons.insert(&machine->neuron);
      if (knownMachine == false)
      {
        finishMachineConfig(machine);

        // Freshly created machines are still bootstrapping, not updating their OS.
        machine->state = BrainBase::machineBootstrapLifecycleState(machine->creationTimeMs);
      }
      else
      {
        // Existing machine state comes from live control-plane lifecycle and must
        // survive master handoff; do not reset it on inventory refresh.
      }

      if (machine->uuid != 0)
      {
        machinesByUUID.insert_or_assign(machine->uuid, machine);
      }
    }

    loadBrainConfigIf();

    // Wait one full initial control-plane reconnect window before declaring
    // startup ignited. Freshly created machines can continue bootstrapping
    // after this; ignition just avoids racing the first reconnect budget.
    bool isDevMode = BrainBase::controlPlaneDevModeEnabled();
    brainPeerKeepaliveSeconds = (isDevMode ? prodigyBrainDevPeerKeepaliveSeconds : prodigyBrainPeerKeepaliveSeconds);
    brainPeerHeartbeatIntervalMs = (isDevMode ? prodigyBrainDevPeerHeartbeatIntervalMs : prodigyBrainPeerHeartbeatIntervalMs);
    brainPeerHeartbeatTimeoutMs = (isDevMode ? prodigyBrainDevPeerHeartbeatTimeoutMs : prodigyBrainPeerHeartbeatTimeoutMs);
    ignitionSwitch.flags = uint64_t(BrainTimeoutFlags::ignition);
    ignitionSwitch.setTimeoutMs(BrainBase::controlPlaneIgnitionTimeoutMs(isDevMode));
    ignitionSwitch.dispatcher = this;
    RingDispatcher::installMultiplexee(&ignitionSwitch, this);
    Ring::queueTimeout(&ignitionSwitch);

    brainPeerHeartbeatTicker.flags = uint64_t(BrainTimeoutFlags::brainPeerHeartbeat);
    brainPeerHeartbeatTicker.setTimeoutMs(brainPeerHeartbeatIntervalMs);
    brainPeerHeartbeatTicker.dispatcher = this;
    RingDispatcher::installMultiplexee(&brainPeerHeartbeatTicker, this);
    // Keep peer liveness ticking even when the mesh goes otherwise quiet.
    Ring::queueTimeout(&brainPeerHeartbeatTicker);

    // we could turn this on and off whether we have spot machines or not.... but just simpler to let it run always
    spotDecomissionChecker.flags = uint64_t(BrainTimeoutFlags::spotDecomissionChecker);
    spotDecomissionChecker.setTimeoutMs(prodigyBrainSpotDecommissionCheckIntervalMs); // every 90 seconds, gives us 30 seconds to get a new machine up if need be
    spotDecomissionChecker.dispatcher = this;
    RingDispatcher::installMultiplexee(&spotDecomissionChecker, this);
    Ring::queueTimeout(&spotDecomissionChecker);

    // if the last master brain failed...
    // after the ignition timeout we would autodetect that we can't connect to the neuron of the previous master brain,
    // then we'd try SSH, then we'd try hard rebooting... if that worked it would rejoin the brains, otherwise the machine would be reported for manual intervention
  }

  bool hasHealthyMachines(void) const override
  {
    for (Machine *machine : machines)
    {
      if (prodigyMachineReadyForScheduling(machine))
      {
        return true;
      }
    }
    return false;
  }

  // we only called from afterRing at boot time
  void getBrains(void)
  {
    boottimens = Time::now<TimeResolution::ns>();

    iaas->boot();

    bool isDevMode = BrainBase::controlPlaneDevModeEnabled();

    // Keep brain-to-brain liveness bounded in dev so master failover is testable.
    // Production uses a slightly larger bound to avoid churn from brief transients.
    brainPeerKeepaliveSeconds = (isDevMode ? prodigyBrainDevPeerKeepaliveSeconds : prodigyBrainPeerKeepaliveSeconds);
    brainPeerHeartbeatIntervalMs = (isDevMode ? prodigyBrainDevPeerHeartbeatIntervalMs : prodigyBrainPeerHeartbeatIntervalMs);
    brainPeerHeartbeatTimeoutMs = (isDevMode ? prodigyBrainDevPeerHeartbeatTimeoutMs : prodigyBrainPeerHeartbeatTimeoutMs);

    // Fast-restore brain state from memfd if available
    {
      String brainState;
      int fd = -1;
      if (char *env = getenv("PRODIGY_BRAIN_STATE_FD"); env && env[0] != '\0')
      {
        fd = atoi(env);
      }
      else if (fcntl(4, F_GETFD) != -1)
      {
        fd = 4;
      }

      if (fd >= 0 && fcntl(fd, F_GETFD) != -1 && Memfd::readAll(fd, brainState))
      {
        MemfdBlobHeader header = {};
        const uint8_t *payload = nullptr;
        size_t payloadSize = 0;
        if (parseMemfdBlob(brainState, header, payload, payloadSize) && header.kind == uint16_t(MemfdBlobKind::brainPlans))
        {
          String serializedPlans = {};
          serializedPlans.assign(reinterpret_cast<uint8_t *>(const_cast<uint8_t *>(payload)), payloadSize);
          Vector<DeploymentPlan> plans;
          if (BitseryEngine::deserializeSafe(serializedPlans, plans))
          {
            for (const auto& plan : plans)
            {
              deploymentPlans.insert_or_assign(plan.config.deploymentID(), plan);
            }
          }
        }
      }
    }

    // Connector ownership is derived from transport-address ordering until
    // registration exchanges persistent brain UUIDs, but the
    // listener itself must accept whichever IPv4/IPv6 address peers can route
    // to on this machine.
    brainSocket.setIPVersion(AF_INET6);
    if (uint32_t maxSegmentSize = controlPlaneTCPMaxSegmentSize(AF_INET6); maxSegmentSize > 0)
    {
      (void)prodigySetTCPMaxSegmentSize(brainSocket.fd, maxSegmentSize);
    }
    setsockopt(brainSocket.fd, IPPROTO_IPV6, IPV6_V6ONLY, (const int[]) {0}, sizeof(int));
    brainSocket.setKeepaliveTimeoutSeconds(brainPeerKeepaliveSeconds);
    brainSocket.setSaddr("::"_ctv, uint16_t(ReservedPorts::brain));
    brainSocket.bindThenListen();

    RingDispatcher::installMultiplexee(&brainSocket, this);
    Ring::installFDIntoFixedFileSlot(&brainSocket);
    brain_saddrlen = sizeof(brain_saddr);
    Ring::queueAccept(&brainSocket, reinterpret_cast<struct sockaddr *>(&brain_saddr), &brain_saddrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);

    CoroutineStack *coro = &brainInventoryCoroutine;

    bool selfIsBrain = false;
    ClusterTopology topology = {};
    if (loadAuthoritativeClusterTopology(topology) && topology.machines.empty() == false)
    {
      restoreBrainsFromClusterTopology(topology);

      for (const ClusterMachine& clusterMachine : topology.machines)
      {
        if (clusterMachine.isBrain == false)
        {
          continue;
        }

        if (clusterMachineMatchesThisBrain(clusterMachine))
        {
          selfIsBrain = true;
          Vector<ClusterMachinePeerAddress> peerAddresses;
          resolveClusterMachinePeerAddresses(clusterMachine, peerAddresses);
          adoptLocalBrainPeerAddresses(peerAddresses);
          IPAddress peerAddress = {};
          String peerAddressText = {};
          if (resolveClusterMachinePeerAddress(clusterMachine, peerAddress, peerAddressText))
          {
            adoptLocalBrainPeerAddress(peerAddress, peerAddressText);
          }
          break;
        }
      }

      nBrains = clusterTopologyBrainCount(topology);
      if (selfIsBrain)
      {
        refreshLocalBrainPeerAddresses();
      }
    }
    else
    {
      uint32_t suspendIndex = coro->nextSuspendIndex();

      String inventoryFailure = {};
      iaas->getBrains(coro, thisNeuron->uuid, selfIsBrain, brains, inventoryFailure);

      if (suspendIndex < coro->nextSuspendIndex())
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (inventoryFailure.size() > 0)
      {
        basics_log("brain inventory failed: %s\n", inventoryFailure.c_str());
        co_return;
      }

      nBrains = brains.size(); // every brain must be present and working for the cluster to initiate, but once it does it can run with fewer
      if (selfIsBrain)
      {
        nBrains += 1;
      }
      if (selfIsBrain)
      {
        (void)resolveLocalBrainPeerAddressFromIaaS();
        refreshLocalBrainPeerAddresses();
      }
    }

    for (BrainView *brain : brains)
    {
      initializeBrainPeerIfNeeded(brain);
    }
    // Multi-brain bootstrap self-elects from brain registrations; only the elected master
    // should arm mothership listening.
    if (nBrains == 1)
    {
      basics_log("getBrains elect-self reason=single-brain-bootstrap\n");
      selfElectAsMaster("getBrains:single-brain-bootstrap"); // we are it
    }

    persistLocalRuntimeState();
  }

  void resetMasterBrainAssignment(void)
  {
    noMasterYet = true;
    isMasterMissing = false;
    pendingDesignatedMasterPeerKey = 0;
    cancelAllBrainLivenessWaiters("reset-master");

    for (BrainView *bv : brains)
    {
      bv->isMasterBrain = false;
      bv->isMasterMissing = false;
      bv->forceConnectorOwnershipUntilMasterAck = false;
    }
  }

  virtual bool storeSystemContainerArtifact(const String& sha256, uint64_t bytes, const String& blob, String *failure = nullptr)
  {
    return ContainerStore::systemStore(sha256, bytes, blob, failure);
  }

  virtual bool systemContainerArtifactPresent(const String& sha256, uint64_t bytes)
  {
    String failure = {};
    return ContainerStore::systemVerify(sha256, bytes, nullptr, nullptr, &failure);
  }

  virtual bool loadSystemContainerArtifact(const String& sha256, uint64_t bytes, String& blob, String *failure = nullptr)
  {
    return ContainerStore::systemLoadVerified(sha256, bytes, blob, failure);
  }

  virtual bool startMothershipTunnelProviderRuntime(const MothershipTunnelProviderSpec& spec, const MothershipTunnelGatewayAuth& gatewayAuth, uint128_t& containerUUID, String *failure = nullptr)
  {
    (void)spec;
    (void)gatewayAuth;
    containerUUID = 0;
    if (failure)
    {
      failure->assign("mothership tunnel provider launch hook missing"_ctv);
    }
    return false;
  }

  virtual void stopMothershipTunnelProviderRuntime(uint128_t containerUUID)
  {
    (void)containerUUID;
  }

  static int64_t mothershipTunnelProviderRetryDelayMs(uint32_t failureCount)
  {
    uint32_t shifts = failureCount > 1 ? std::min<uint32_t>(failureCount - 1, 6) : 0;
    return std::min<int64_t>(mothershipTunnelProviderBaseRetryDelayMs << shifts, mothershipTunnelProviderMaxRetryDelayMs);
  }

  template <typename Diagnostic>
  void noteMothershipTunnelProviderPhase(TunnelProviderPhase phase, Diagnostic&& diagnostic)
  {
    mothershipTunnelProviderRuntimeState.phase = phase;
    mothershipTunnelProviderRuntimeState.lastFailure.assign(diagnostic);
  }

  void stopMothershipTunnelProviderLocalInstance(void)
  {
    if (mothershipTunnelProviderRuntimeState.localContainerUUID != 0)
    {
      stopMothershipTunnelProviderRuntime(mothershipTunnelProviderRuntimeState.localContainerUUID);
    }
    mothershipTunnelProviderRuntimeState.localContainerUUID = 0;
  }

  void noteMothershipTunnelProviderControlSession(void)
  {
    if (mothershipConnectivity.kind == MothershipConnectivityKind::tunnelProvider &&
        mothershipTunnelProviderRuntimeState.localContainerUUID != 0)
    {
      mothershipTunnelProviderRuntimeState.phase = TunnelProviderPhase::healthy;
      mothershipTunnelProviderRuntimeState.failureCount = 0;
      mothershipTunnelProviderRuntimeState.nextRetryMs = 0;
      mothershipTunnelProviderRuntimeState.lastHealthyAtMs = Time::now<TimeResolution::ms>();
      mothershipTunnelProviderRuntimeState.lastFailure.clear();
    }
  }

  bool noteMothershipTunnelProviderInstanceFailed(uint128_t containerUUID, const String& report, bool restarted)
  {
    if (mothershipConnectivity.kind != MothershipConnectivityKind::tunnelProvider ||
        mothershipTunnelProviderRuntimeState.localContainerUUID != containerUUID)
    {
      return false;
    }

    if (restarted)
    {
      mothershipTunnelProviderRuntimeState.phase = TunnelProviderPhase::awaitingSession;
      mothershipTunnelProviderRuntimeState.lastFailure.assign("mothership tunnel provider restarted: "_ctv);
    }
    else
    {
      mothershipTunnelProviderRuntimeState.phase = TunnelProviderPhase::backoff;
      mothershipTunnelProviderRuntimeState.failureCount += 1;
      mothershipTunnelProviderRuntimeState.nextRetryMs = Time::now<TimeResolution::ms>() + mothershipTunnelProviderRetryDelayMs(mothershipTunnelProviderRuntimeState.failureCount);
      mothershipTunnelProviderRuntimeState.lastFailure.assign("mothership tunnel provider exited: "_ctv);
    }
    if (report.size() > 0)
    {
      mothershipTunnelProviderRuntimeState.lastFailure.append(report);
    }
    else
    {
      mothershipTunnelProviderRuntimeState.lastFailure.append("unknown"_ctv);
    }
    if (restarted == false)
    {
      mothershipTunnelProviderRuntimeState.localContainerUUID = 0;
      stopMothershipTunnelProviderRuntime(containerUUID);
    }
    return true;
  }

  bool handleUploadedMothershipTunnelProviderContainer(NeuronView *neuron, const ContainerPlan& plan)
  {
    if (plan.system.kind != SystemContainerKind::mothershipTunnelProvider)
    {
      return false;
    }
    if (weAreMaster && neuron != nullptr && neuron->machine != nullptr)
    {
      bool currentLocal = mothershipConnectivity.kind == MothershipConnectivityKind::tunnelProvider &&
                          plan.uuid == mothershipTunnelProviderRuntimeState.localContainerUUID;
      if (currentLocal == false)
      {
        neuron->machine->queueSend(NeuronTopic::killContainer, plan.uuid);
      }
    }
    return true;
  }

  bool applySystemContainerArtifact(const String& sha256, uint64_t bytes, const String& blob, bool replicateToPeers, String *failure = nullptr)
  {
    bool alreadyStored = systemContainerArtifactPresent(sha256, bytes);
    if (alreadyStored == false && storeSystemContainerArtifact(sha256, bytes, blob, failure) == false)
    {
      return false;
    }

    if (replicateToPeers && alreadyStored == false)
    {
      queueBrainSystemContainerArtifactReplication(sha256, bytes, blob);
    }
    reconcileMothershipTunnelProviderRuntimeState();

    if (failure)
    {
      failure->clear();
    }
    return true;
  }

  void capturePresentSystemArtifactRef(SystemContainerArtifactRef& ref)
  {
    ref = {};
    if (mothershipConnectivity.kind != MothershipConnectivityKind::tunnelProvider)
    {
      return;
    }

    const MothershipTunnelProviderSpec& spec = mothershipConnectivity.tunnelProvider;
    if (systemContainerArtifactPresent(spec.artifactSha256, spec.artifactBytes))
    {
      ref.sha256 = spec.artifactSha256;
      ref.bytes = spec.artifactBytes;
    }
  }

  void queueMissingSystemContainerArtifactForPeer(BrainView *peer, const SystemContainerArtifactRef& peerArtifact)
  {
    if (peer == nullptr)
    {
      return;
    }

    const MothershipConnectivity& connectivity = masterAuthorityRuntimeState.mothershipTunnelProviderDesiredState.connectivity;
    if (connectivity.kind != MothershipConnectivityKind::tunnelProvider)
    {
      return;
    }

    const MothershipTunnelProviderSpec& spec = connectivity.tunnelProvider;
    if (peerArtifact.bytes == spec.artifactBytes && peerArtifact.sha256.equal(spec.artifactSha256))
    {
      return;
    }

    String blob = {};
    String failure = {};
    if (loadSystemContainerArtifact(spec.artifactSha256, spec.artifactBytes, blob, &failure))
    {
      (void)queueBrainSystemContainerArtifactReplicationToPeer(peer, spec.artifactSha256, spec.artifactBytes, blob);
    }
  }

  void reconcileMothershipTunnelProviderRuntimeState(void)
  {
    if (mothershipConnectivity.kind != MothershipConnectivityKind::tunnelProvider)
    {
      stopMothershipTunnelProviderLocalInstance();
      mothershipTunnelProviderRuntimeState = {};
      return;
    }

    const MothershipTunnelProviderSpec& spec = mothershipConnectivity.tunnelProvider;
    auto& state = mothershipTunnelProviderRuntimeState;
    auto failStopped = [&](TunnelProviderPhase phase, auto&& failureText) -> void {
      stopMothershipTunnelProviderLocalInstance();
      noteMothershipTunnelProviderPhase(phase, failureText);
    };

    if (isActiveMaster() == false)
    {
      failStopped(TunnelProviderPhase::disabled, "not active master"_ctv);
      return;
    }

    if (mothershipTunnelGatewayAuth.configured() == false)
    {
      failStopped(TunnelProviderPhase::awaitingMaterial, "mothership tunnel gateway auth missing"_ctv);
      return;
    }

    if (state.localContainerUUID != 0)
    {
      if (state.phase == TunnelProviderPhase::healthy &&
          state.lastHealthyAtMs + mothershipTunnelProviderSessionHealthTtlMs < Time::now<TimeResolution::ms>())
      {
        state.phase = TunnelProviderPhase::awaitingSession;
        state.lastFailure.assign("waiting for authenticated tunnel session"_ctv);
      }
      return;
    }

    if (systemContainerArtifactPresent(spec.artifactSha256, spec.artifactBytes) == false)
    {
      failStopped(TunnelProviderPhase::awaitingMaterial, "tunnel provider artifact missing from system store"_ctv);
      return;
    }

    if (state.phase == TunnelProviderPhase::backoff && Time::now<TimeResolution::ms>() < state.nextRetryMs)
    {
      return;
    }

    String launchFailure = {};
    if (mothershipTunnelProviderSpecValid(spec, &launchFailure) == false)
    {
      failStopped(TunnelProviderPhase::awaitingMaterial, launchFailure);
      return;
    }

    uint128_t containerUUID = 0;
    if (startMothershipTunnelProviderRuntime(spec, mothershipTunnelGatewayAuth, containerUUID, &launchFailure) == false)
    {
      if (launchFailure.size() == 0)
      {
        launchFailure.assign("mothership tunnel provider runtime launch failed"_ctv);
      }
      state.failureCount += 1;
      state.nextRetryMs = Time::now<TimeResolution::ms>() + mothershipTunnelProviderRetryDelayMs(state.failureCount);
      failStopped(TunnelProviderPhase::backoff, launchFailure);
      return;
    }
    if (containerUUID == 0)
    {
      state.failureCount += 1;
      state.nextRetryMs = Time::now<TimeResolution::ms>() + mothershipTunnelProviderRetryDelayMs(state.failureCount);
      failStopped(TunnelProviderPhase::backoff, "mothership tunnel provider launch returned empty container uuid"_ctv);
      return;
    }

    state.localContainerUUID = containerUUID;
    state.phase = TunnelProviderPhase::awaitingSession;
    state.nextRetryMs = 0;
    state.lastFailure.assign("waiting for authenticated tunnel session"_ctv);
  }

  bool prepareMothershipTunnelProviderDesiredState(const MothershipTunnelProviderDesiredState& incoming, MothershipTunnelProviderDesiredState& desired, String *failure = nullptr)
  {
    desired = {};
    desired.connectivity = incoming.connectivity;
    mothershipStripMothershipOnlyConnectivityFields(desired.connectivity);
    if (mothershipConnectivityRuntimeConfigValid(desired.connectivity, failure) == false)
    {
      return false;
    }

    if (desired.connectivity.kind == MothershipConnectivityKind::tunnelProvider)
    {
      MothershipTunnelGatewayTLSContext gatewayTLS = {};
      if (gatewayTLS.configure(incoming.gatewayAuth, failure) == false)
      {
        return false;
      }
      desired.gatewayAuth = incoming.gatewayAuth;
    }
    return true;
  }

  void commitMothershipTunnelProviderDesiredState(const MothershipTunnelProviderDesiredState& desired, bool replicateToPeers, bool persistAuthority, String *failure = nullptr)
  {
    bool changed = mothershipConnectivity != desired.connectivity ||
                   (mothershipTunnelGatewayAuth == desired.gatewayAuth) == false;
    mothershipConnectivity = desired.connectivity;
    mothershipTunnelGatewayAuth = desired.gatewayAuth;
    if (changed)
    {
      stopMothershipTunnelProviderLocalInstance();
      mothershipTunnelProviderRuntimeState = {};
    }
    reconcileMothershipTunnelProviderRuntimeState();
    if (persistAuthority && (changed || (masterAuthorityRuntimeState.mothershipTunnelProviderDesiredState == desired) == false))
    {
      noteMasterAuthorityRuntimeStateChanged(replicateToPeers, true);
    }
    if (failure)
    {
      failure->clear();
    }
  }

  void restoreMothershipTunnelProviderDesiredStateFromMasterAuthority(void)
  {
    MothershipTunnelProviderDesiredState desired = {};
    String failure = {};
    if (prepareMothershipTunnelProviderDesiredState(masterAuthorityRuntimeState.mothershipTunnelProviderDesiredState, desired, &failure))
    {
      commitMothershipTunnelProviderDesiredState(desired, false, false);
      return;
    }

    mothershipConnectivity = {};
    mothershipTunnelGatewayAuth = {};
    stopMothershipTunnelProviderLocalInstance();
    mothershipTunnelProviderRuntimeState = {};
    if (failure.size() > 0)
    {
      noteMothershipTunnelProviderPhase(TunnelProviderPhase::awaitingMaterial, failure);
    }
  }

  bool applyMothershipTunnelProviderDesiredState(const MothershipTunnelProviderDesiredState& incoming, bool replicateToPeers, String *failure = nullptr)
  {
    MothershipTunnelProviderDesiredState desired = {};
    if (prepareMothershipTunnelProviderDesiredState(incoming, desired, failure) == false)
    {
      return false;
    }
    commitMothershipTunnelProviderDesiredState(desired, replicateToPeers, true, failure);
    return true;
  }

  bool applyMothershipTunnelProviderConfigureRequest(const MothershipTunnelProviderConfigureRequest& request, bool replicateToPeers, String *failure = nullptr)
  {
    MothershipTunnelProviderDesiredState desired = {};
    if (prepareMothershipTunnelProviderDesiredState(request.desired, desired, failure) == false)
    {
      return false;
    }

    if (desired.connectivity.kind == MothershipConnectivityKind::tunnelProvider)
    {
      const MothershipTunnelProviderSpec& spec = desired.connectivity.tunnelProvider;
      for (BrainView *brain : brains)
      {
        if (replicateToPeers && brain != nullptr && brain->connected && brain->version < ProdigyBinaryVersion)
        {
          if (failure)
          {
            failure->assign("mothership tunnel provider requires current brain peer binary"_ctv);
          }
          return false;
        }
      }
      bool alreadyStored = systemContainerArtifactPresent(spec.artifactSha256, spec.artifactBytes);
      if (alreadyStored == false && request.artifactBlob.size() == 0)
      {
        if (failure)
        {
          failure->assign("mothership tunnel provider artifact missing"_ctv);
        }
        return false;
      }
      if (alreadyStored == false && storeSystemContainerArtifact(spec.artifactSha256, spec.artifactBytes, request.artifactBlob, failure) == false)
      {
        return false;
      }
      commitMothershipTunnelProviderDesiredState(desired, false, true, failure);
      if (replicateToPeers)
      {
        if (alreadyStored == false)
        {
          queueBrainSystemContainerArtifactReplication(spec.artifactSha256, spec.artifactBytes, request.artifactBlob);
        }
        queueMasterAuthorityRuntimeStateReplication();
      }
      if (failure)
      {
        failure->clear();
      }
      return true;
    }

    commitMothershipTunnelProviderDesiredState(desired, replicateToPeers, true, failure);
    return true;
  }

  void configureMothershipUnixSocketPath(String& mothershipSocketPath)
  {
    resolveProdigyControlSocketPathFromProcess(mothershipSocketPath);
  }

  bool mothershipUnixSocketPathHasLiveListener(const String& socketPath) const
  {
    if (socketPath.size() == 0)
    {
      return false;
    }

    String ownedSocketPath = socketPath;

    struct stat st = {};
    if (::stat(ownedSocketPath.c_str(), &st) != 0 || S_ISSOCK(st.st_mode) == false)
    {
      return false;
    }

    int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
      // Fail safe: if we cannot probe, do not tear down a path that may belong
      // to an active master listener.
      return true;
    }

    struct sockaddr_un address = {};
    address.sun_family = AF_UNIX;
    std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", ownedSocketPath.c_str());
    socklen_t addressLen = socklen_t(sizeof(address.sun_family) + std::strlen(address.sun_path));

    bool listenerLive = (::connect(fd, reinterpret_cast<struct sockaddr *>(&address), addressLen) == 0);
    if (listenerLive == false)
    {
      listenerLive = (errno != ECONNREFUSED);
    }

    ::close(fd);
    return listenerLive;
  }

  void clearMothershipUnixSocketPathOwnership(void)
  {
    mothershipUnixSocketPathInodeRecorded = false;
    mothershipUnixSocketPathDevice = 0;
    mothershipUnixSocketPathInode = 0;
  }

  bool recordMothershipUnixSocketPathOwnership(void)
  {
    if (mothershipUnixSocketPath.size() == 0)
    {
      return false;
    }

    struct stat pathStat = {};
    if (::stat(mothershipUnixSocketPath.c_str(), &pathStat) != 0 || S_ISSOCK(pathStat.st_mode) == false)
    {
      return false;
    }

    mothershipUnixSocketPathInodeRecorded = true;
    mothershipUnixSocketPathDevice = pathStat.st_dev;
    mothershipUnixSocketPathInode = pathStat.st_ino;
    return true;
  }

  bool mothershipUnixSocketPathOwnedByLocalListener(void)
  {
    if (mothershipUnixSocketPath.size() == 0 || mothershipUnixSocketPathInodeRecorded == false)
    {
      return false;
    }

    struct stat pathStat = {};
    if (::stat(mothershipUnixSocketPath.c_str(), &pathStat) != 0 || S_ISSOCK(pathStat.st_mode) == false)
    {
      return false;
    }

    return pathStat.st_dev == mothershipUnixSocketPathDevice && pathStat.st_ino == mothershipUnixSocketPathInode;
  }

  bool armMothershipUnixListener(bool replaceLiveListener = false)
  {
    mothershipUnixAcceptArmed = false;
    clearMothershipUnixSocketPathOwnership();
    mothershipUnixSocket.recreateSocket();
    mothershipUnixSocket.isFixedFile = false;
    mothershipUnixSocket.pendingSend = false;
    mothershipUnixSocket.pendingSendBytes = 0;
    mothershipUnixSocket.pendingRecv = false;

    configureMothershipUnixSocketPath(mothershipUnixSocketPath);
    if (mothershipUnixSocketPath.size() == 0)
    {
      basics_log("armMothershipUnixListener missing socket path\n");
      return false;
    }
    struct sockaddr_un pathLimitProbe = {};
    if (mothershipUnixSocketPath.size() >= sizeof(pathLimitProbe.sun_path))
    {
      PRODIGY_DEBUG_LOG(
                   "prodigy mothership listen-failed transport=unix reason=path-too-long pathBytes=%zu maxBytes=%zu path=%s\n",
                   size_t(mothershipUnixSocketPath.size()),
                   sizeof(pathLimitProbe.sun_path) - 1,
                   mothershipUnixSocketPath.c_str());
      PRODIGY_DEBUG_FLUSH();
      return false;
    }

    mothershipUnixSocket.setSocketPath(mothershipUnixSocketPath.c_str());
    mothershipUnixSocket.saddr_storage = mothershipUnixSocket.daddr_storage;
    mothershipUnixSocket.saddrLen = mothershipUnixSocket.daddrLen;

    constexpr uint32_t bindRetryLimit = 50;
    bool listenerBound = false;
    for (uint32_t attempt = 1; attempt <= bindRetryLimit; attempt++)
    {
      if (::bind(mothershipUnixSocket.fd, mothershipUnixSocket.saddr<struct sockaddr>(), mothershipUnixSocket.saddrLen) == 0)
      {
        listenerBound = true;
        break;
      }

      int err = errno;
      if (err == EADDRINUSE)
      {
        if (mothershipUnixSocketPathHasLiveListener(mothershipUnixSocketPath))
        {
          if (replaceLiveListener == false)
          {
            basics_log("armMothershipUnixListener live listener already owns path=%s; deferring election\n",
                       mothershipUnixSocketPath.c_str());
            ::close(mothershipUnixSocket.fd);
            mothershipUnixSocket.fd = -1;
            return false;
          }

          basics_log("armMothershipUnixListener replacing live listener path=%s\n",
                     mothershipUnixSocketPath.c_str());
        }

        unlinkMothershipUnixSocketPath("arm-mothership-unix-listener-rebind", false);
        if (attempt == bindRetryLimit)
        {
          basics_log("armMothershipUnixListener bind busy after retries path=%s; deferring election\n",
                     mothershipUnixSocketPath.c_str());
          ::close(mothershipUnixSocket.fd);
          mothershipUnixSocket.fd = -1;
          return false;
        }

        usleep(20'000);
        continue;
      }

      basics_log("armMothershipUnixListener bind failed path=%s errno=%d(%s)\n",
                 mothershipUnixSocketPath.c_str(),
                 err,
                 strerror(err));
      ::close(mothershipUnixSocket.fd);
      mothershipUnixSocket.fd = -1;
      return false;
    }

    if (listenerBound == false)
    {
      return false;
    }

    if (recordMothershipUnixSocketPathOwnership() == false)
    {
      basics_log("armMothershipUnixListener ownership record failed path=%s\n",
                 mothershipUnixSocketPath.c_str());
      ::unlink(mothershipUnixSocketPath.c_str());
      ::close(mothershipUnixSocket.fd);
      mothershipUnixSocket.fd = -1;
      return false;
    }

    if (::listen(mothershipUnixSocket.fd, SOMAXCONN) != 0)
    {
      basics_log("armMothershipUnixListener listen failed path=%s errno=%d(%s)\n",
                 mothershipUnixSocketPath.c_str(),
                 errno,
                 strerror(errno));
      clearMothershipUnixSocketPathOwnership();
      ::close(mothershipUnixSocket.fd);
      mothershipUnixSocket.fd = -1;
      return false;
    }

    RingDispatcher::installMultiplexee(&mothershipUnixSocket, this);
    Ring::installFDIntoFixedFileSlot(&mothershipUnixSocket);
    if (Ring::socketIsClosing(&mothershipUnixSocket) == false)
    {
      Ring::queueAccept(&mothershipUnixSocket, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
      mothershipUnixAcceptArmed = true;
      basics_log("armMothershipUnixListener queued initial accept path=%s isFixed=%d fd=%d fslot=%d weAreMaster=%d\n",
                 mothershipUnixSocketPath.c_str(),
                 int(mothershipUnixSocket.isFixedFile),
                 mothershipUnixSocket.fd,
                 mothershipUnixSocket.fslot,
                 int(weAreMaster));
      PRODIGY_DEBUG_LOG( "prodigy mothership listen-arm transport=unix path=%s listenerFD=%d listenerFslot=%d master=%d phase=initial\n",
                   mothershipUnixSocketPath.c_str(),
                   mothershipUnixSocket.fd,
                   mothershipUnixSocket.fslot,
                   int(weAreMaster));
      PRODIGY_DEBUG_FLUSH();
    }

    return true;
  }

  void unlinkMothershipUnixSocketPath(const char *reason, bool requireLocalOwnership = true)
  {
    if (mothershipUnixSocketPath.size() == 0)
    {
      return;
    }

    bool locallyOwned = mothershipUnixSocketPathOwnedByLocalListener();
    if (requireLocalOwnership && locallyOwned == false)
    {
      basics_log("mothership unix socket path unlink skipped reason=%s path=%s ownership=not-local\n",
                 reason ? reason : "unspecified",
                 mothershipUnixSocketPath.c_str());
      return;
    }

    int rc = ::unlink(mothershipUnixSocketPath.c_str());
    if (rc == 0 || errno == ENOENT)
    {
      clearMothershipUnixSocketPathOwnership();
      basics_log("mothership unix socket path unlinked reason=%s path=%s\n",
                 reason ? reason : "unspecified",
                 mothershipUnixSocketPath.c_str());
    }
    else
    {
      basics_log("mothership unix socket path unlink failed reason=%s path=%s errno=%d(%s)\n",
                 reason ? reason : "unspecified",
                 mothershipUnixSocketPath.c_str(),
                 errno,
                 strerror(errno));
    }
  }

protected:

  virtual bool installNeuronControlSocketFromBrain(NeuronView *neuron)
  {
    return installNeuronControlSocket(neuron);
  }

  virtual void awaitSelfElectionMachineInventoryIfNeeded(CoroutineStack *coro, uint32_t suspendIndex)
  {
    if (coro && suspendIndex < coro->nextSuspendIndex())
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }

  virtual bool reconcileManagedMachineSchemasOnSelfElection(String *failure)
  {
    return reconcileManagedMachineSchemas(failure);
  }

public:

  void advanceMasterAuthorityEpoch(void)
  {
    masterAuthorityEpoch += 1;
    if (masterAuthorityEpoch == 0)
    {
      masterAuthorityEpoch = 1;
    }
  }

  void forfeitMasterStatus(void)
  {
    basics_log("forfeitMasterStatus weAreMaster=%d\n", int(weAreMaster));
    advanceMasterAuthorityEpoch();
    weAreMaster = false;
    masterAuthorityReplicationByPeer.clear();
    (void)configurePendingElasticAddressReleaseFence(masterAuthorityRuntimeState);
    noMasterYet = true;
    reconcileMothershipTunnelProviderRuntimeState();
    mothershipUnixAcceptArmed = false;

    unlinkMothershipUnixSocketPath("forfeit-master");

    // Relinquishing master also relinquishes any active mothership control stream.
    if (activeMotherships.empty() == false)
    {
      Vector<Mothership *> activeStreams = {};
      activeStreams.reserve(activeMotherships.size());
      for (Mothership *stream : activeMotherships)
      {
        activeStreams.push_back(stream);
      }

      for (Mothership *stream : activeStreams)
      {
        queueCloseIfActive(stream);
      }
    }

    if (mothershipUnixSocket.isFixedFile)
    {
      if (mothershipUnixSocket.fslot >= 0 && Ring::socketIsClosing(&mothershipUnixSocket) == false)
      {
        RingDispatcher::eraseMultiplexee(&mothershipUnixSocket);
        abandonSocketGeneration(&mothershipUnixSocket);
      }
    }
    else if (mothershipUnixSocket.fd >= 0 && Ring::socketIsClosing(&mothershipUnixSocket) == false)
    {
      RingDispatcher::eraseMultiplexee(&mothershipUnixSocket);
      abandonSocketGeneration(&mothershipUnixSocket);
    }
    // Only the active master may hold neuron control sockets.
    for (NeuronView *nv : neurons)
    {
      cancelNeuronControlHandshakeWatchdog(nv, "forfeit-master");
      disarmNeuronControlReconnect(nv);
      nv->connected = false;
      if (nv->isFixedFile)
      {
        if (nv->fslot >= 0 && Ring::socketIsClosing(nv) == false)
        {
          Ring::queueClose(nv);
        }
      }
      else if (nv->fd >= 0 && Ring::socketIsClosing(nv) == false)
      {
        Ring::queueClose(nv);
      }
    }

    for (BrainView *bv : brains)
    {
      bv->forceConnectorOwnershipUntilMasterAck = false;
    }
  }

  bool selfElectAsMaster(const char *reason = "unspecified", bool replaceLiveMothershipListener = false)
  {
    basics_log("selfElectAsMaster begin weAreMaster=%d reason=%s\n", int(weAreMaster), reason);
    if (weAreMaster)
    {
      return true;
    }

    advanceMasterAuthorityEpoch();

    // Promotion must flip master ownership before listener arm so any immediate
    // close CQE races on mothership control-listener re-arm through closeHandler.
    weAreMaster = true;
    masterAuthorityReplicationByPeer.clear();
    cancelAllBrainLivenessWaiters("self-elect");

    if (armMothershipUnixListener(replaceLiveMothershipListener) == false)
    {
      weAreMaster = false;
      return false;
    }

    noMasterYet = false;
    pendingDesignatedMasterPeerKey = 0;
    masterQuorumDegraded = false;
    hasCompletedInitialMasterElection = true;
    reconcileMothershipTunnelProviderRuntimeState();
    noteMasterAuthorityRuntimeStateChanged();
    refreshAllDeploymentWormholeQuicCidState(false);
    basics_log("selfElectAsMaster complete\n");

    // During handover/updateProdigy or bootstrap, followers may not yet have
    // acknowledged the new master identity. Keep any live peer stream intact long
    // enough to push the new registration across it. Only force an outbound
    // reconnect when there is no usable peer stream to carry that registration.
    for (BrainView *bv : brains)
    {
      if (bv == nullptr || bv->quarantined)
      {
        continue;
      }

      bool peerAcknowledgedMaster = (peerHasFreshExistingMasterClaim(bv) && bv->existingMasterUUID == selfBrainUUID());
      if (peerAcknowledgedMaster == false)
      {
        if (peerSocketActive(bv))
        {
          bv->sendRegistration(boottimens, version, getExistingMasterUUID());
          continue;
        }

        armOutboundPeerReconnect(bv, true);
        continue;
      }

      if (bv->weConnectToIt && peerSocketActive(bv) == false)
      {
        armOutboundPeerReconnect(bv);
      }
    }

    // Broadcast our selected-master identity immediately so peers converge on this master.
    for (BrainView *bv : brains)
    {
      if (bv->quarantined)
      {
        continue;
      }
      bv->sendRegistration(boottimens, version, getExistingMasterUUID());
    }

    // Existing peer links and canonical connector ownership are sufficient here.

    CoroutineStack *coro = &brainInventoryCoroutine;

    uint32_t suspendIndex = coro->nextSuspendIndex();

    getMachines(coro);

    awaitSelfElectionMachineInventoryIfNeeded(coro, suspendIndex);

    // Re-arm neuron control-plane sockets after machine inventory is known.
    // This must run after getMachines() because followers may not have
    // populated neuron socket state before becoming master.
    for (Machine *machine : machines)
    {
      NeuronView *nv = &machine->neuron;

      neurons.insert(nv);
      RingDispatcher::installMultiplexee(nv, this);
      nv->nConnectionAttempts = 0;
      nv->nAttemptsBudget = 0;
      nv->reconnectAfterClose = true;
      PRODIGY_DEBUG_LOG(
                   "prodigy debug neuron-control-rearm-entry source=self-elect uuid=%llu private4=%u armed=%d connected=%d closing=%d pendingConnect=%d pendingSend=%d pendingRecv=%d fd=%d fslot=%d\n",
                   (unsigned long long)machine->uuid,
                   unsigned(machine->private4),
                   int(neuronControlSocketArmed(machine)),
                   int(nv->connected),
                   int(Ring::socketIsClosing(nv)),
                   int(nv->connectAttemptPending()),
                   int(nv->pendingSend),
                   int(nv->pendingRecv),
                   nv->fd,
                   nv->fslot);
      PRODIGY_DEBUG_FLUSH();

      bool reconnectArmedByClose = Ring::socketIsClosing(nv);
      if (reconnectArmedByClose == false)
      {
        if (neuronControlSocketArmed(machine))
        {
          // Restored/master-inherited fixed slots are only reusable if the
          // transport is actually live or still progressing. Preserving a
          // disconnected fixed slot strands the master queueing control
          // traffic into a dead neuron stream.
          if (neuronControlStreamActive(machine) || nv->pendingSend || nv->pendingRecv || nv->connectAttemptPending())
          {
            PRODIGY_DEBUG_LOG(
                         "prodigy debug neuron-control-rearm-preserve source=self-elect uuid=%llu private4=%u connected=%d closing=%d pendingConnect=%d pendingSend=%d pendingRecv=%d fd=%d fslot=%d\n",
                         (unsigned long long)machine->uuid,
                         unsigned(machine->private4),
                         int(nv->connected),
                         int(Ring::socketIsClosing(nv)),
                         int(nv->connectAttemptPending()),
                         int(nv->pendingSend),
                         int(nv->pendingRecv),
                         nv->fd,
                         nv->fslot);
            PRODIGY_DEBUG_FLUSH();
            continue;
          }

          abandonSocketGeneration(nv);
        }
      }

      if (reconnectArmedByClose == false)
      {
        nv->recreateSocket();
        if (installNeuronControlSocketFromBrain(nv))
        {
          nv->attemptForMs(BrainBase::machineInitialConnectAttemptTimeMs(
              machine->creationTimeMs,
              nv->connectTimeoutMs,
              nv->nDefaultAttemptsBudget));
          nv->attemptConnect();
          PRODIGY_DEBUG_LOG(
                       "prodigy debug neuron-control-connect-submit source=self-elect uuid=%llu private4=%u fd=%d fslot=%d pendingConnect=%d pendingSend=%d pendingRecv=%d daddrLen=%u\n",
                       (unsigned long long)machine->uuid,
                       unsigned(machine->private4),
                       nv->fd,
                       nv->fslot,
                       int(nv->connectAttemptPending()),
                       int(nv->pendingSend),
                       int(nv->pendingRecv),
                       unsigned(nv->daddrLen));
          PRODIGY_DEBUG_FLUSH();
        }
      }
    }

    for (const auto& [deploymentID, plan] : deploymentPlans)
    {
      ApplicationDeployment *deployment = new ApplicationDeployment(); // as neurons register and upload their state, these deployments will be populated
      deployment->plan = plan;
      deployment->restorePersistedStatefulWorkerTopologyUpgradeOperation();
      deployment->restorePersistedDeferredStatefulScaleIntent();

      deployments.insert_or_assign(plan.config.deploymentID(), deployment);

      if (auto it = deploymentsByApp.find(plan.config.applicationID); it != deploymentsByApp.end())
      {
        ApplicationDeployment *other = it->second;

        if (other->plan.config.versionID < deployment->plan.config.versionID)
        {
          // replace
          deploymentsByApp.insert_or_assign(plan.config.applicationID, deployment);
          deployment->previous = other;
          other->next = deployment;
        }
      }
      else
      {
        deploymentsByApp.insert_or_assign(plan.config.applicationID, deployment);
      }
      applyPendingReplicatedContainerRuntimeStates(plan.config.deploymentID());
    }

    // Deployment recovery still waits for healthy machine state transitions, but
    // interrupted addMachines journaling can resume immediately on promotion.
    deploymentPlans.clear();
    resumePendingAddMachinesOperations();
    reconcilePendingElasticAddressAssignments();
    reconcilePendingElasticAddressReleases();
    appliedDNSRecordLeases.clear();
    reconcileAuthoritativeDNSState();
    if (ignited)
    {
      refreshMachineFragmentAssignmentsIfPossible();
    }
    String managedSchemaReconcileFailure = {};
    if (reconcileManagedMachineSchemasOnSelfElection(&managedSchemaReconcileFailure) == false)
    {
      basics_log("selfElectAsMaster managed machine schema reconcile failed reason=%s\n",
                 managedSchemaReconcileFailure.c_str());
    }
    recoverDeploymentsAfterNeuronState();

    return true;
  }

  void electBrainToMaster(BrainView *brain)
  {
    if (brain == nullptr)
    {
      return;
    }

    if (weAreMaster)
    {
      forfeitMasterStatus();
    }
    else
    {
      // Peer-master convergence must hard-stop any stale local ownership too.
      // Followers never hold commander or neuron control sockets.
      unlinkMothershipUnixSocketPath("elect-peer-master");
      queueCloseIfActive(&mothershipUnixSocket);
      if (activeMotherships.empty() == false)
      {
        Vector<Mothership *> activeStreams = {};
        activeStreams.reserve(activeMotherships.size());
        for (Mothership *stream : activeMotherships)
        {
          activeStreams.push_back(stream);
        }

        for (Mothership *stream : activeStreams)
        {
          queueCloseIfActive(stream);
        }
      }

      for (NeuronView *nv : neurons)
      {
        disarmNeuronControlReconnect(nv);
        nv->connected = false;
        queueCloseIfActive(nv);
      }
    }

    noMasterYet = false;
    pendingDesignatedMasterPeerKey = 0;
    brain->isMasterBrain = true;
    hasCompletedInitialMasterElection = true;
    reconcileMothershipTunnelProviderRuntimeState();
    String masterUUIDText = {};
    masterUUIDText.snprintf<"{itoa}"_ctv>(brain->uuid);
    basics_log("electBrainToMaster uuid=%s\n", masterUUIDText.c_str());

    refreshMasterAuthorityRuntimeStateFromLiveFields();
    persistLocalRuntimeState();
    refreshMasterPeerLivenessWaiter(brain, "elect-master");
  }

  void deriveMasterBrain(bool allowExistingMasterClaims = true)
  {
    // Initial master is cluster-derived, not mothership-selected.

    // when we first seed a datacenter, we'll seed the first machine first brain first. provide it subnets. let it become operational.
    // at this stage it's effectively a single-brain cluster (nBrainsExpected == 1). we can then instruct it to create the next 2 brains...
    // and then tell it to add them to its pool (this add function would be handy for our test environment to just "add" hardware we manually add, not cloud hardware we spin)
    // we can virtualize the API interacting functions... and create a subclassed Brain object for production vs ProdigyDev (using our LAN, for now)

    // it's possible we were master.. then lost connectivity.. then reconnected... only to discover that a master was voted in..
    // in that case we need to just recognize that as master..

    if (noMasterYet)
    {
      uint32_t nRegisteredBrains = 1; // include self
      for (BrainView *bv : brains)
      {
        if (peerEligibleForClusterQuorum(bv) && bv->boottimens > 0)
        {
          nRegisteredBrains += 1;
        }
      }

      // Initial bootstrap requires full registration across the fixed brain set.
      // After the first successful election, failover can proceed with majority.
      const uint32_t requiredRegisteredBrains =
          hasCompletedInitialMasterElection ? (uint32_t(nBrains / 2) + 1) : nBrains;
      basics_log("deriveMasterBrain gate hasInitial=%d nBrains=%u nRegistered=%u required=%u\n",
                 int(hasCompletedInitialMasterElection), nBrains, nRegisteredBrains, requiredRegisteredBrains);
      if (nRegisteredBrains < requiredRegisteredBrains)
      {
        return;
      }

      if (hasCompletedInitialMasterElection && allowExistingMasterClaims == false)
      {
        bool preferSelfByAddressOrder = false;
        bool sawActivePeer = false;
        if (resolveFailoverMasterByActivePeerAddressOrder(preferSelfByAddressOrder, &sawActivePeer))
        {
          if (preferSelfByAddressOrder)
          {
            basics_log("deriveMasterBrain elect-self reason=active-peer-address-order\n");
            selfElectAsMaster("deriveMasterBrain:active-peer-address-order", true);
          }
          else
          {
            basics_log("deriveMasterBrain waiting for lower-address active peer to self-elect\n");
          }

          return;
        }

        if (sawActivePeer)
        {
          basics_log("deriveMasterBrain waiting for active peer identity convergence\n");
          return;
        }
      }

      if (activeBrainRegistrationsReadyForMasterElection() == false)
      {
        basics_log("deriveMasterBrain waiting for active peer registrations\n");
        return;
      }

      uint128_t existingMasterUUID = 0;
      if (allowExistingMasterClaims)
      {
        existingMasterUUID = resolveConsistentExistingMasterUUID();
      }

      for (BrainView *brain : brains)
      {
        brain->existingMasterUUID = 0; // clear all of these
      }

      bool adoptedExistingMaster = false;
      if (existingMasterUUID > 0) // peers report a consistent existing master
      {
        if (existingMasterUUID == selfBrainUUID())
        {
          // If a live quorum reports us as master, keep ownership.
          basics_log("deriveMasterBrain elect-self reason=consistent-existing-master\n");
          selfElectAsMaster("deriveMasterBrain:consistent-existing-master");
          adoptedExistingMaster = true;
        }
        else
        {
          if (BrainView *brain = findBrainViewByUUID(existingMasterUUID); brain != nullptr)
          {
            // Never adopt a missing/stale master candidate.
            if (brain->quarantined == false && brain->boottimens > 0)
            {
              electBrainToMaster(brain);
              adoptedExistingMaster = true;
            }
          }
        }
      }

      if (adoptedExistingMaster == false) // we need to derive one
      {
        if (hasCompletedInitialMasterElection)
        {
          bool preferSelfByAddressOrder = false;
          bool sawActivePeer = false;
          if (resolveFailoverMasterByActivePeerAddressOrder(preferSelfByAddressOrder, &sawActivePeer))
          {
            if (preferSelfByAddressOrder)
            {
              basics_log("deriveMasterBrain elect-self reason=active-peer-address-order\n");
              selfElectAsMaster("deriveMasterBrain:active-peer-address-order", allowExistingMasterClaims == false);
            }
            else
            {
              basics_log("deriveMasterBrain waiting for lower-address active peer to self-elect\n");
            }

            return;
          }

          if (sawActivePeer)
          {
            basics_log("deriveMasterBrain waiting for active peer identity convergence\n");
            return;
          }
        }

        uint128_t derivedMasterUUID = deriveRegisteredMasterUUID();
        {
          String derivedMasterUUIDText = {};
          String selfUUIDText = {};
          derivedMasterUUIDText.snprintf<"{itoa}"_ctv>(derivedMasterUUID);
          selfUUIDText.snprintf<"{itoa}"_ctv>(selfBrainUUID());
          basics_log("deriveMasterBrain fallback derivedUUID=%s selfUUID=%s\n",
                     derivedMasterUUIDText.c_str(),
                     selfUUIDText.c_str());
        }
        if (derivedMasterUUID == 0 || derivedMasterUUID == selfBrainUUID())
        {
          basics_log("deriveMasterBrain elect-self reason=derived-master-uuid\n");
          selfElectAsMaster("deriveMasterBrain:derived-master-uuid");
        }
        else if (BrainView *master = findBrainViewByUUID(derivedMasterUUID); master != nullptr)
        {
          electBrainToMaster(master);
        }
      }
    }

    persistLocalRuntimeState();
  }

  void deriveMasterBrainIf(void)
  {
    float aliveRatio = calculateAliveBrainRatio();
    bool connectedMajority = hasConnectedBrainMajority();
    basics_log("deriveMasterBrainIf isMasterMissing=%d aliveRatio=%.3f connectedMajority=%d\n",
               int(isMasterMissing), aliveRatio, int(connectedMajority));
    resetMasterBrainAssignment(); // either we now have no brain, or we derive a new one

    if (aliveRatio > 0.5f && connectedMajority)
    {
      // an outright majority of machines are alive and they all voted the master is missing

      // so derive a new master
      deriveMasterBrain(false);
    }
    else
    {
      // everyone alive agrees (might be no-one)
      // but to move forward we'd need to at least make sure those machines are really dead, not isolated

      // it's possible the master spuriously regained network here and reconnected??? that would've triggered brainFound()
      // even if, deriveMasterBrain will still rederive the correct master or fail if it hasn't registered yet

      // our switch can't be dead because we're only in here because someone responded

      bool reachableSwitchMajority = false;
      checkMetroReachabilityForMasterFailover(connectedMajority, reachableSwitchMajority);
      if (reachableSwitchMajority && connectedMajority)
      {
        // now counting alive (at least 1 other machine besdies us) + reachable, we have a majority
        deriveMasterBrain(false);
      }
      else
      {
        // we don't have a majority so no brain right now... (this could only happen if we ever upgraded to 5 brains from 3, otherwise we'd
        // always have 1 other brain alive, making 2 alive brains, to even be in this message handler)
      }
    }
  }

  virtual void checkMetroReachabilityForMasterFailover(bool& connectedMajority, bool& reachableSwitchMajority)
  {
    std::unique_ptr<MetroNetworkMonitor> monitor = std::make_unique<MetroNetworkMonitor>();
    monitor->check(thisNeuron->private4.v4, thisNeuron->gateway4.v4, brains);
    co_await monitor->suspend();

    connectedMajority = hasConnectedBrainMajority();
    reachableSwitchMajority = (monitor->ratioOfReachableSwitches() > 0.5f);
  }

  static bool selectScaleOutMachineConfig(const bytell_hash_map<String, MachineConfig>& configBySlug, const ApplicationConfig& config, uint32_t nMore, String& selectedSlug, const MachineConfig *& selectedConfig)
  {
    selectedSlug.clear();
    selectedConfig = nullptr;

    if (nMore == 0)
    {
      return false;
    }

    auto divideAndRoundUp = [](uint64_t numerator, uint32_t denominator, uint32_t& result) -> bool {
      if (denominator == 0)
      {
        return false;
      }

      uint64_t quotient = (numerator + denominator - 1) / denominator;
      if (quotient == 0 || quotient > UINT32_MAX)
      {
        return false;
      }

      result = uint32_t(quotient);
      return true;
    };

    auto lexicalLess = [](const String& a, const String& b) -> bool {
      uint64_t limit = std::min(a.size(), b.size());
      int comparison = memcmp(a.data(), b.data(), limit);
      if (comparison != 0)
      {
        return comparison < 0;
      }

      return a.size() < b.size();
    };

    uint16_t overcommitPermille = prodigySharedCPUOvercommitMinPermille;
    if (thisBrain != nullptr)
    {
      overcommitPermille = prodigySharedCPUOvercommitPermille(thisBrain->brainConfig.sharedCPUOvercommitPermille);
    }

    uint64_t requiredCPUUnits = applicationUsesSharedCPUs(config)
                                    ? (uint64_t(nMore) * uint64_t(applicationRequestedCPUMillis(config)))
                                    : (uint64_t(nMore) * uint64_t(config.nLogicalCores));
    uint64_t requiredMemoryMB = uint64_t(nMore) * config.totalMemoryMB();
    uint64_t requiredStorageMB = uint64_t(nMore) * config.totalStorageMB();

    uint32_t bestMachineCount = UINT32_MAX;
    uint64_t bestWasteCores = UINT64_MAX;
    uint64_t bestWasteMemoryMB = UINT64_MAX;
    uint64_t bestWasteStorageMB = UINT64_MAX;

    for (const auto& [candidateSlug, candidateConfig] : configBySlug)
    {
      if (config.architecture != MachineCpuArchitecture::unknown)
      {
        if (candidateConfig.cpu.architecture == MachineCpuArchitecture::unknown || candidateConfig.cpu.architecture != config.architecture)
        {
          continue;
        }
      }

      if (config.requiredIsaFeatures.empty() == false)
      {
        if (candidateConfig.cpu.authoritative() == false || prodigyIsaFeaturesMeetRequirements(candidateConfig.cpu.isaFeatures, config.requiredIsaFeatures) == false)
        {
          continue;
        }
      }

      uint32_t nByCores;
      uint32_t nByMemory;
      uint32_t nByStorage;

      uint64_t candidateCPUCapacity = applicationUsesSharedCPUs(config)
                                          ? (uint64_t(candidateConfig.nLogicalCores) * uint64_t(overcommitPermille))
                                          : uint64_t(candidateConfig.nLogicalCores);

      if (divideAndRoundUp(requiredCPUUnits, candidateCPUCapacity, nByCores) == false || divideAndRoundUp(requiredMemoryMB, candidateConfig.nMemoryMB, nByMemory) == false || divideAndRoundUp(requiredStorageMB, candidateConfig.nStorageMB, nByStorage) == false)
      {
        continue;
      }

      uint32_t machineCount = nByCores;
      if (nByMemory > machineCount)
      {
        machineCount = nByMemory;
      }
      if (nByStorage > machineCount)
      {
        machineCount = nByStorage;
      }

      uint64_t wasteCores = (uint64_t(machineCount) * candidateCPUCapacity) - requiredCPUUnits;
      uint64_t wasteMemoryMB = (uint64_t(machineCount) * candidateConfig.nMemoryMB) - requiredMemoryMB;
      uint64_t wasteStorageMB = (uint64_t(machineCount) * candidateConfig.nStorageMB) - requiredStorageMB;

      bool takeCandidate = false;
      if (selectedConfig == nullptr)
      {
        takeCandidate = true;
      }
      else if (machineCount < bestMachineCount)
      {
        takeCandidate = true;
      }
      else if (machineCount == bestMachineCount)
      {
        if (wasteCores < bestWasteCores)
        {
          takeCandidate = true;
        }
        else if (wasteCores == bestWasteCores)
        {
          if (wasteMemoryMB < bestWasteMemoryMB)
          {
            takeCandidate = true;
          }
          else if (wasteMemoryMB == bestWasteMemoryMB)
          {
            if (wasteStorageMB < bestWasteStorageMB)
            {
              takeCandidate = true;
            }
            else if (wasteStorageMB == bestWasteStorageMB && lexicalLess(candidateSlug, selectedSlug))
            {
              takeCandidate = true;
            }
          }
        }
      }

      if (takeCandidate)
      {
        selectedSlug = candidateSlug;
        selectedConfig = &candidateConfig;
        bestMachineCount = machineCount;
        bestWasteCores = wasteCores;
        bestWasteMemoryMB = wasteMemoryMB;
        bestWasteStorageMB = wasteStorageMB;
      }
    }

    return selectedConfig != nullptr;
  }

  void requestMachines(MachineTicket *ticket, ApplicationDeployment *deployment, ApplicationLifetime lifetime, uint32_t nMore) override
  {
    const ApplicationConfig& config = deployment->plan.config;

  retry: // there will be new MachineState::deploying machines now

    for (Machine *machine : machines)
    {
      if (machine->state == MachineState::deploying)
      {
        switch (lifetime)
        {
          case ApplicationLifetime::base:
          case ApplicationLifetime::canary:
            {
              if (machine->lifetime == MachineLifetime::spot)
              {
                continue;
              }
              break;
            }
          case ApplicationLifetime::surge:
            {
              if (machine->lifetime != MachineLifetime::spot)
              {
                continue;
              }
              break;
            }
        }

        // we need to log claims on machines otherwise it's impossible to know from one invocation of requestMachines to the next
        // how many of the resources of previously requested machines are spoken for, and thus would have to spin up new machines for
        // each invocation

        uint32_t nFit = deployment->nFitOnMachineClaim(ticket, machine, nMore);

        if (nFit > 0)
        {
          nMore -= nFit;

          if (nMore == 0)
          {
            break;
          }
        }
      }
    }

    if (nMore > 0) // we still need more machines
    {
      MachineLifetime machineLifetime;

      switch (lifetime)
      {
        case ApplicationLifetime::base:
          {
            // predictReservedCapacity30Days();
            [[fallthrough]];
          }
        case ApplicationLifetime::canary:
          {
            machineLifetime = MachineLifetime::ondemand;
            break;
          }
        case ApplicationLifetime::surge:
          {
            machineLifetime = MachineLifetime::spot;
            break;
          }
      }

      String slug;
      const MachineConfig *machineConfig = nullptr;
      uint32_t nMoreMachines = 0;
      uint64_t provisioningOperationID = 0;
      ProdigyPendingAutonomousProvisioningOperation *pendingOperation =
          findPendingAutonomousProvisioningOperation(config.deploymentID(), lifetime);

      if (pendingOperation != nullptr)
      {
        auto configIt = brainConfig.configBySlug.find(pendingOperation->machineSchema);
        if (configIt == brainConfig.configBySlug.end() || pendingOperation->count == 0)
        {
          basics_log("requestMachines failure reason=pending-operation-machine-config-missing applicationID=%u deploymentID=%llu lifetime=%u operationID=%llu schema=%.*s\n",
                     unsigned(config.applicationID),
                     (unsigned long long)config.deploymentID(),
                     unsigned(lifetime),
                     (unsigned long long)pendingOperation->operationID,
                     int(pendingOperation->machineSchema.size()),
                     reinterpret_cast<const char *>(pendingOperation->machineSchema.data()));
          co_return;
        }
        slug.assign(pendingOperation->machineSchema);
        machineConfig = &configIt->second;
        nMoreMachines = pendingOperation->count;
        provisioningOperationID = pendingOperation->operationID;
      }
      else if (selectScaleOutMachineConfig(brainConfig.configBySlug, config, nMore, slug, machineConfig) == false)
      {
        basics_log("requestMachines failure reason=no-matching-machine-config applicationID=%u deploymentID=%llu lifetime=%u requested=%u\n",
                   unsigned(config.applicationID), (unsigned long long)config.deploymentID(),
                   unsigned(lifetime), unsigned(nMore));
        co_return;
      }

      if (pendingOperation == nullptr)
      {
        auto divideAndRoundUp = [=](uint64_t numerator, uint64_t denominator) -> uint32_t {
          return uint32_t((numerator + denominator - 1) / denominator);
        };
        uint16_t overcommitPermille = prodigySharedCPUOvercommitPermille(brainConfig.sharedCPUOvercommitPermille);
        uint64_t requiredCPUUnits = applicationUsesSharedCPUs(config)
                                        ? (uint64_t(nMore) * uint64_t(applicationRequestedCPUMillis(config)))
                                        : (uint64_t(nMore) * uint64_t(config.nLogicalCores));
        uint64_t machineCPUCapacity = applicationUsesSharedCPUs(config)
                                          ? (uint64_t(machineConfig->nLogicalCores) * uint64_t(overcommitPermille))
                                          : uint64_t(machineConfig->nLogicalCores);
        uint32_t nByCores = divideAndRoundUp(requiredCPUUnits, machineCPUCapacity);
        uint32_t nByMemory = divideAndRoundUp(uint64_t(nMore) * config.totalMemoryMB(), machineConfig->nMemoryMB);
        uint32_t nByStorage = divideAndRoundUp(uint64_t(nMore) * config.totalStorageMB(), machineConfig->nStorageMB);
        nMoreMachines = std::max(nByCores, std::max(nByMemory, nByStorage));
        if (journalAutonomousProvisioningOperation(config.deploymentID(), lifetime,
                                                   slug, nMoreMachines,
                                                   provisioningOperationID) == false)
        {
          basics_log("requestMachines failure reason=provisioning-operation-persist-failed applicationID=%u deploymentID=%llu lifetime=%u requested=%u\n",
                     unsigned(config.applicationID),
                     (unsigned long long)config.deploymentID(),
                     unsigned(lifetime), unsigned(nMoreMachines));
          co_return;
        }
      }

      CoroutineStack *coro = new CoroutineStack();

      String error;

      uint32_t suspendIndex = coro->nextSuspendIndex();
      const uint64_t machineCountBeforeProvisioning = machines.size();

      iaas->configureProvisioningClusterUUID(brainConfig.clusterUUID);
      iaas->configureProvisioningOperationID(provisioningOperationID);
      iaas->spinMachines(coro, machineLifetime, *machineConfig, nMoreMachines, machines, error);

      if (suspendIndex < coro->nextSuspendIndex())
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }

      delete coro;

      if (iaas->provisioningOperationSettled() == false)
      {
        co_return;
      }
      if (settleAutonomousProvisioningOperation(provisioningOperationID) == false)
      {
        basics_log("requestMachines failure reason=provisioning-operation-settlement-persist-failed applicationID=%u deploymentID=%llu lifetime=%u operationID=%llu\n",
                   unsigned(config.applicationID),
                   (unsigned long long)config.deploymentID(),
                   unsigned(lifetime),
                   (unsigned long long)provisioningOperationID);
        co_return;
      }
      if (machines.size() <= machineCountBeforeProvisioning)
      {
        co_return;
      }
      goto retry;
    }
  }

  void decommissionMachine(Machine *machine)
  {
    basics_log("decommissionMachine uuid=%llu private4=%u state=%u isBrain=%d cloudID=%s containers=%llu\n",
               (unsigned long long)(machine ? machine->uuid : 0),
               unsigned(machine ? machine->private4 : 0u),
               unsigned(machine ? machine->state : MachineState::unknown),
               int(machine ? machine->isBrain : false),
               (machine ? machine->cloudID.c_str() : ""),
               (unsigned long long)(machine ? machine->containersByDeploymentID.size() : 0u));

    cancelMachineSoftWatchdog(machine);
    cancelMachineHardRebootWatchdog(machine);
    cancelOSUpdateCommandWatchdog(machine);

    evacuateFailedMachineContainers(machine);

    // if we need another machine, the deployments will request it

    if (machine->state == MachineState::hardwareFailure)
    {
      // destroy it
      (void)queueMachineDestroy(*machine);
    }

    if (machine->fragment > 0)
    {
      relinquishMachineFragment(machine);
    }

    machines.erase(machine);
    machinesByUUID.erase(machine->uuid);
    neurons.erase(&machine->neuron);
    cancelNeuronReconnectWaiter(&machine->neuron, "decommission-machine");

    for (MachineSSH *ssh : sshs)
    {
      if (ssh && ssh->machine == machine)
      {
        ssh->machine = nullptr;
      }
    }

    if (machine->brain)
    {
      machine->brain->machine = nullptr;
    }
    machine->brain = nullptr;
    machine->neuron.machine = nullptr;

    RingDispatcher::eraseMultiplexee(&machine->neuron);
    // Remove the Machine* mapping used for timeout originator routing
    RingDispatcher::eraseMultiplexee(machine);

    /// we have to close the socket.
    /// This object is deleted immediately, so close by raw slot/fd instead of
    /// pointer-based queueClose() callback dispatch.
    if (machine->neuron.isFixedFile)
    {
      if (machine->neuron.fslot >= 0)
      {
        Ring::queueCloseRaw(machine->neuron.fslot);
        machine->neuron.fslot = -1;
      }
    }
    else if (machine->neuron.fd >= 0)
    {
      machine->neuron.close();
      machine->neuron.fd = -1;
    }
    machine->neuron.isFixedFile = false;

    Rack *rack = machine->rack;
    rack->machines.erase(machine);

    if (rack->machines.size() == 0) // destroy rack too
    {
      racks.erase(rack->uuid);
      delete rack;
    }

    delete machine;
  }

  void checkForSpotTerminations(void)
  {
    if (spotDecommissionCheckActive)
    {
      co_return;
    }
    spotDecommissionCheckActive = true;
    struct ActiveCheck final
    {
      bool& active;
      ~ActiveCheck()
      {
        active = false;
      }
    } activeCheck {spotDecommissionCheckActive};

    CoroutineStack *coro = &spotDecommissionCheckCoroutine;

    Vector<String> decommissionedIDs;

    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          iaas->checkForSpotTerminations(coro, decommissionedIDs);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }

    if (decommissionedIDs.size() > 0)
    {
      for (const String& id : decommissionedIDs)
      {
        Machine *machine = nullptr;
        for (const auto& pair : machinesByUUID)
        {
          if (pair.second && pair.second->cloudID == id)
          {
            machine = pair.second;
            break;
          }
        }

        if (machine == nullptr)
        {
          uint128_t uuid = String::numberFromHexString<uint128_t>(id);

          if (auto it = machinesByUUID.find(uuid); it != machinesByUUID.end())
          {
            machine = it->second;
          }
        }

        if (machine)
        {
          machine->state = MachineState::decommissioning;
          decommissionMachine(machine);
        }
      }
    }

    refreshAllDeploymentWormholeQuicCidState(true);
    (void)advanceAllDeploymentTlsResumptionLifecycles(true);
    const int64_t nowMs = Time::now<TimeResolution::ms>();
    (void)advanceCertificateLifecycles(nowMs);
    (void)pruneExpiredTaskExecutionRecords(nowMs);
    spotDecomissionChecker.setTimeoutMs(prodigyBrainSpotDecommissionCheckIntervalMs);
    Ring::queueTimeout(&spotDecomissionChecker);
  }

  // Initiate drain on a single machine by asking every deployment with
  // containers on it to evacuate (kill/move) those containers. When the
  // last container departs, container lifecycle events will trigger
  // isMachineDrained(machine), which in turn performs the next step
  // (triggering the OS update when state==updatingOS).
  void drainMachine(Machine *machine)
  {
    // we could be draining for multiple reasons, so machine->state set before this

    for (const auto& [deploymentID, containers] : machine->containersByDeploymentID)
    {
      (void)containers;
      if (auto deployment = deployments.find(deploymentID); deployment != deployments.end() && deployment->second)
      {
        deployment->second->drainMachine(machine, false);
      }
    }
  }

  void evacuateFailedMachineContainers(Machine *machine)
  {
    if (machine == nullptr)
    {
      return;
    }

    basics_log("evacuateFailedMachineContainers missingPrivate4=%u trackedContainers=%llu\n",
               machine->private4,
               (unsigned long long)containers.size());

    // Containers may still reference an equivalent Machine object through an older
    // snapshot. Drain every machine object that still resolves to the same machine
    // identity so failover does not strand deployment bins on duplicate objects.
    bytell_hash_set<Machine *> drainTargets;
    drainTargets.insert(machine);

    for (const auto& [containerUUID, container] : containers)
    {
      (void)containerUUID;
      if (container && container->machine && prodigyMachinesShareIdentity(*container->machine, *machine))
      {
        drainTargets.insert(container->machine);
      }
    }

    basics_log("evacuateFailedMachineContainers missingPrivate4=%u drainTargets=%llu\n",
               machine->private4,
               (unsigned long long)drainTargets.size());

    for (Machine *target : drainTargets)
    {
      if (target == nullptr || target->containersByDeploymentID.size() == 0)
      {
        if (target)
        {
          basics_log("evacuateFailedMachineContainers targetPrivate4=%u deploymentBins=0\n", target->private4);
        }
        continue;
      }

      basics_log("evacuateFailedMachineContainers targetPrivate4=%u deploymentBins=%llu\n",
                 target->private4,
                 (unsigned long long)target->containersByDeploymentID.size());

      for (const auto& [deploymentID, containersOnMachine] : target->containersByDeploymentID)
      {
        (void)containersOnMachine;
        if (auto it = deployments.find(deploymentID); it != deployments.end() && it->second)
        {
          it->second->drainMachine(target, true);
        }
      }

      target->containersByDeploymentID.clear();
    }
  }

  void retryScheduledContainerWaitersAfterNeuronClose(Machine *machine)
  {
    if (machine == nullptr || weAreMaster == false)
    {
      return;
    }

    Vector<ApplicationDeployment *> affectedDeployments;
    for (const auto& [deploymentID, deployment] : deployments)
    {
      (void)deploymentID;
      if (deployment && deployment->plan.isStateful == false)
      {
        affectedDeployments.push_back(deployment);
      }
    }

    for (ApplicationDeployment *deployment : affectedDeployments)
    {
      deployment->drainMachine(machine, true, true);
    }
  }

  uint32_t normalizedMaxOSDrains(void) const
  {
    return brainConfig.maxOSDrains > 0 ? brainConfig.maxOSDrains : 1;
  }

  uint32_t normalizedMachineUpdateCadenceMins(void) const
  {
    return brainConfig.machineUpdateCadenceMins > 0 ? brainConfig.machineUpdateCadenceMins : 15;
  }

  int64_t normalizedMachineUpdateCadenceMs(void) const
  {
    const char *devMode = std::getenv("PRODIGY_DEV_MODE");
    const char *devCadenceMs = std::getenv("PRODIGY_DEV_OS_UPDATE_CADENCE_MS");
    if (devMode != nullptr && devMode[0] != '\0' && devMode[0] != '0' && devCadenceMs != nullptr && devCadenceMs[0] != '\0')
    {
      errno = 0;
      char *end = nullptr;
      unsigned long long value = std::strtoull(devCadenceMs, &end, 10);
      if (errno == 0 && end != devCadenceMs && *end == '\0' && value > 0 && value <= uint64_t(INT64_MAX))
      {
        return int64_t(value);
      }
    }

    return int64_t(normalizedMachineUpdateCadenceMins()) * 60 * 1000;
  }

  int64_t normalizedOSUpdateCommandRebootDeadlineMs(void) const
  {
    const char *devMode = std::getenv("PRODIGY_DEV_MODE");
    const char *devDeadlineMs = std::getenv("PRODIGY_DEV_OS_UPDATE_COMMAND_REBOOT_DEADLINE_MS");
    if (devMode != nullptr && devMode[0] != '\0' && devMode[0] != '0' && devDeadlineMs != nullptr && devDeadlineMs[0] != '\0')
    {
      errno = 0;
      char *end = nullptr;
      unsigned long long value = std::strtoull(devDeadlineMs, &end, 10);
      if (errno == 0 && end != devDeadlineMs && *end == '\0' && value > 0 && value <= uint64_t(INT64_MAX))
      {
        return int64_t(value);
      }
    }

    return prodigyBrainOSUpdateCommandRebootDeadlineMs;
  }

  bool machineIsVMForMaintenance(const Machine *machine) const
  {
    if (machine == nullptr)
    {
      return false;
    }

    auto configIt = brainConfig.configBySlug.find(machine->slug);
    if (configIt != brainConfig.configBySlug.end())
    {
      return configIt->second.kind == MachineConfig::MachineKind::vm;
    }

    return machine->cloudID.size() > 0 || machine->currentImageURI.size() > 0;
  }

  const OperatingSystemUpdatePolicy *osUpdatePolicyForMachine(const Machine *machine) const
  {
    if (machine == nullptr || machine->osID.size() == 0)
    {
      return nullptr;
    }

    for (const OperatingSystemUpdatePolicy& policy : brainConfig.osUpdatePolicies)
    {
      if (policy.osID.size() > 0 && policy.targetVersionID.size() > 0 && policy.command.size() > 0 && machine->osID.equals(policy.osID))
      {
        return &policy;
      }
    }

    return nullptr;
  }

  OperatingSystemUpdatePolicy *mutableOSUpdatePolicyForMachine(const Machine *machine)
  {
    if (machine == nullptr || machine->osID.size() == 0)
    {
      return nullptr;
    }

    for (OperatingSystemUpdatePolicy& policy : brainConfig.osUpdatePolicies)
    {
      if (policy.osID.size() > 0 && policy.targetVersionID.size() > 0 && policy.command.size() > 0 && machine->osID.equals(policy.osID))
      {
        return &policy;
      }
    }

    return nullptr;
  }

  bool machineEligibleForOSUpdate(Machine *machine) const
  {
    const OperatingSystemUpdatePolicy *policy = osUpdatePolicyForMachine(machine);
    if (machine == nullptr || policy == nullptr || machine->uuid == 0 || machine->state != MachineState::healthy || machine->osVersionID.size() == 0 || machine->osVersionID.equals(policy->targetVersionID) || neuronControlStreamActive(machine) == false)
    {
      return false;
    }

    if (machineIsVMForMaintenance(machine) && policy->includeVMs == false)
    {
      return false;
    }

    return true;
  }

  bool osUpdatePolicyCoverageComplete(void) const
  {
    if (brainConfig.osUpdatesEnabled == false || brainConfig.osUpdatePolicies.empty())
    {
      return false;
    }

    for (Machine *machine : machines)
    {
      if (machine == nullptr)
      {
        continue;
      }

      if (machine->uuid == 0 || machine->osID.size() == 0 || osUpdatePolicyForMachine(machine) == nullptr)
      {
        return false;
      }
    }

    return true;
  }

  bool hasPendingVMReimage(void) const
  {
    if (masterAuthorityRuntimeState.pendingAddMachinesOperations.empty() == false)
    {
      return true;
    }

    ClusterTopology topology = {};
    if (loadAuthoritativeClusterTopology(topology) == false)
    {
      return false;
    }

    for (const ClusterMachine& machine : topology.machines)
    {
      if (machine.source != ClusterMachineSource::created || machine.backing != ClusterMachineBacking::cloud || machine.kind != MachineConfig::MachineKind::vm || machine.cloud.schema.size() == 0)
      {
        continue;
      }

      const ProdigyManagedMachineSchema *managedSchema =
          prodigyFindManagedMachineSchema(masterAuthorityRuntimeState.machineSchemas, machine.cloud.schema);
      if (managedSchema == nullptr || managedSchema->kind != MachineConfig::MachineKind::vm || managedSchema->vmImageURI.size() == 0)
      {
        continue;
      }

      if (machine.vmImageURI.equals(managedSchema->vmImageURI) == false)
      {
        return true;
      }
    }

    return false;
  }

  uint32_t countActiveOSDrains(void) const
  {
    uint32_t count = 0;
    for (Machine *machine : machines)
    {
      if (machine == nullptr)
      {
        continue;
      }

      if (machine->state == MachineState::updatingOS || (machine->state == MachineState::hardRebooting && machine->osUpdateCommandIssued && osUpdatePolicyForMachine(machine) != nullptr))
      {
        count += 1;
      }
    }

    return count;
  }

  void refreshOperatingSystemUpdateQueue(void)
  {
    operatingSystemUpdateOrder.clear();
    for (Machine *machine : machines)
    {
      if (machineEligibleForOSUpdate(machine))
      {
        operatingSystemUpdateOrder.push_back(machine);
      }
    }

    std::sort(operatingSystemUpdateOrder.begin(), operatingSystemUpdateOrder.end(), [](const Machine *lhs, const Machine *rhs) -> bool {
      if (lhs->isThisMachine != rhs->isThisMachine)
      {
        return rhs->isThisMachine;
      }

      if (lhs->lastUpdatedOSMs != rhs->lastUpdatedOSMs)
      {
        return lhs->lastUpdatedOSMs < rhs->lastUpdatedOSMs;
      }

      return lhs->uuid < rhs->uuid;
    });
  }

  Machine *nextOperatingSystemUpdateCandidate(void)
  {
    while (operatingSystemUpdateOrder.empty() == false)
    {
      Machine *machine = operatingSystemUpdateOrder.front();
      operatingSystemUpdateOrder.erase(operatingSystemUpdateOrder.begin());
      if (machineEligibleForOSUpdate(machine))
      {
        return machine;
      }
    }

    return nullptr;
  }

  bool machineAtOSUpdateTargetVersion(Machine *machine) const
  {
    const OperatingSystemUpdatePolicy *policy = osUpdatePolicyForMachine(machine);
    return (
        machine != nullptr && policy != nullptr && machine->osVersionID.size() > 0 && machine->osVersionID.equals(policy->targetVersionID));
  }

  BrainView *selectOSUpdateMasterHandoffPeer(Machine *machine)
  {
    if (machine == nullptr || machine->isThisMachine == false || weAreMaster == false || nBrains <= 1)
    {
      return nullptr;
    }

    BrainView *selected = nullptr;
    uint128_t selectedPeerKey = 0;
    for (BrainView *peer : brains)
    {
      if (peer == nullptr || peer->quarantined || peer->registrationFresh == false || peer->uuid == 0 || peer->boottimens == 0 || peerSocketActive(peer) == false || peer->machine == nullptr || peer->machine == machine || peer->machine->state != MachineState::healthy || peer->machine->runtimeReady == false || machineAtOSUpdateTargetVersion(peer->machine) == false)
      {
        continue;
      }

      uint128_t peerKey = updateSelfPeerTrackingKey(peer);
      if (peerKey == 0)
      {
        continue;
      }

      if (selected == nullptr || peerKey < selectedPeerKey)
      {
        selected = peer;
        selectedPeerKey = peerKey;
      }
    }

    return selected;
  }

  bool handoffMasterBeforeLocalOSUpdate(Machine *machine)
  {
    BrainView *target = selectOSUpdateMasterHandoffPeer(machine);
    if (target == nullptr)
    {
      basics_log("os update local master defer uuid=%llu private4=%u reason=no-updated-brain-handoff-target\n",
                 (unsigned long long)(machine ? machine->uuid : 0),
                 unsigned(machine ? machine->private4 : 0));
      return false;
    }

    uint128_t targetPeerKey = updateSelfPeerTrackingKey(target);
    uint32_t relayedPeers = 0;
    for (BrainView *peer : brains)
    {
      if (peer == nullptr || peer->quarantined || peerSocketActive(peer) == false)
      {
        continue;
      }

      Message::construct(peer->wBuffer, BrainTopic::relinquishMasterStatus, uint8_t(1), targetPeerKey);
      Ring::queueSend(peer);
      relayedPeers += 1;
    }

    if (relayedPeers == 0)
    {
      return false;
    }

    basics_log("os update local master handoff uuid=%llu private4=%u targetUUID=%llu targetPrivate4=%u relayedPeers=%u\n",
               (unsigned long long)(machine ? machine->uuid : 0),
               unsigned(machine ? machine->private4 : 0),
               (unsigned long long)target->uuid,
               unsigned(target->private4),
               relayedPeers);
    electBrainToMaster(target);
    noteMasterAuthorityRuntimeStateChanged(false, true);
    return true;
  }

  void queueMachineOSUpdate(Machine *machine)
  {
    OperatingSystemUpdatePolicy *policy = mutableOSUpdatePolicyForMachine(machine);
    if (machine == nullptr || policy == nullptr || machine->osUpdateCommandIssued || neuronControlStreamActive(machine) == false)
    {
      return;
    }

    Message::construct(
        machine->neuron.wBuffer,
        NeuronTopic::updateOS,
        policy->osID,
        policy->targetVersionID,
        policy->command);
    machine->state = MachineState::updatingOS;
    machine->osUpdateCommandIssued = true;
    persistLocalRuntimeState();
    armOSUpdateCommandWatchdog(machine);
    PRODIGY_DEBUG_LOG(
                 "os update command queued uuid=%llu private4=%u osID=%s targetVersionID=%s\n",
                 (unsigned long long)machine->uuid,
                 unsigned(machine->private4),
                 policy->osID.c_str(),
                 policy->targetVersionID.c_str());
    PRODIGY_DEBUG_FLUSH();
    basics_log("os update command queued uuid=%llu private4=%u osID=%s targetVersionID=%s\n",
               (unsigned long long)machine->uuid,
               unsigned(machine->private4),
               policy->osID.c_str(),
               policy->targetVersionID.c_str());
    Ring::queueSend(&machine->neuron);
  }

  bool beginMachineOSUpdate(Machine *machine)
  {
    if (machineEligibleForOSUpdate(machine) == false)
    {
      return false;
    }

    if (machine->isThisMachine && weAreMaster && nBrains > 1)
    {
      return handoffMasterBeforeLocalOSUpdate(machine);
    }

    machine->state = MachineState::updatingOS;
    machine->osUpdateCommandIssued = false;
    lastOperatingSystemUpdateStartMs = Time::now<TimeResolution::ms>();
    drainMachine(machine);
    isMachineDrained(machine);
    return true;
  }

  bool runMachineUpdateCadenceTick(void)
  {
    if (weAreMaster == false || ignited == false || osUpdatePolicyCoverageComplete() == false || hasPendingVMReimage() || countActiveOSDrains() >= normalizedMaxOSDrains())
    {
      return false;
    }

    refreshOperatingSystemUpdateQueue();
    for (;;)
    {
      Machine *machine = nextOperatingSystemUpdateCandidate();
      if (machine == nullptr)
      {
        return false;
      }

      if (beginMachineOSUpdate(machine))
      {
        return true;
      }
    }
  }

  // Called opportunistically after container lifecycle events (destroy/failed)
  // to check whether the machine is now empty. If we were draining for an OS
  // update, this queues the explicit Neuron update command.
  void isMachineDrained(Machine *machine)
  {
    if (machine->containersByDeploymentID.size() == 0)
    {
      switch (machine->state)
      {
        case MachineState::updatingOS:
          {
            queueMachineOSUpdate(machine);

            break;
          }
        case MachineState::decommissioning:
          {
            (void)queueMachineDestroy(*machine);
            break;
          }
        default:
          break;
      }
    }
  }

  void scheduleNextOperatingSystemUpdate(void)
  {
    armMachineUpdateTimerIfNeeded();
  }

  bool isActiveMaster(void) const
  {
    return weAreMaster;
  }

  bool shouldReconnectNeuronControl(NeuronView *neuron) const
  {
    return (weAreMaster && neuron != nullptr && const_cast<NeuronView *>(neuron)->shouldReconnect());
  }

  bool canControlNeurons(void) const override
  {
    return weAreMaster;
  }

protected:

  void armMachineNeuronControl(Machine *machine) override
  {
    if (machine == nullptr)
    {
      return;
    }

    neurons.insert(&machine->neuron);
    if (weAreMaster == false)
    {
      disarmNeuronControlReconnect(&machine->neuron);
      machine->neuron.connected = false;
      queueCloseIfActive(&machine->neuron);
      basics_log("brain armMachineNeuronControl skip-follower uuid=%llu private4=%u privateAddress=%s fd=%d isFixed=%d fslot=%d\n",
                 (unsigned long long)machine->uuid,
                 unsigned(machine->private4),
                 machine->privateAddress.c_str(),
                 machine->neuron.fd,
                 int(machine->neuron.isFixedFile),
                 machine->neuron.fslot);
      return;
    }

    basics_log("brain armMachineNeuronControl uuid=%llu private4=%u privateAddress=%s isThisMachine=%d fd=%d isFixed=%d fslot=%d\n",
               (unsigned long long)machine->uuid,
               unsigned(machine->private4),
               machine->privateAddress.c_str(),
               int(machine->isThisMachine),
               machine->neuron.fd,
               int(machine->neuron.isFixedFile),
               machine->neuron.fslot);

    NeuronView *neuron = &machine->neuron;
    PRODIGY_DEBUG_LOG(
                 "prodigy debug neuron-control-rearm-entry source=brain-arm uuid=%llu private4=%u armed=%d connected=%d closing=%d pendingConnect=%d pendingSend=%d pendingRecv=%d fd=%d fslot=%d\n",
                 (unsigned long long)machine->uuid,
                 unsigned(machine->private4),
                 int(neuronControlSocketArmed(machine)),
                 int(neuron->connected),
                 int(Ring::socketIsClosing(neuron)),
                 int(neuron->connectAttemptPending()),
                 int(neuron->pendingSend),
                 int(neuron->pendingRecv),
                 neuron->fd,
                 neuron->fslot);
    PRODIGY_DEBUG_FLUSH();
    if (neuronControlSocketArmed(machine))
    {
      if (Ring::socketIsClosing(neuron) || neuronControlStreamActive(machine) || neuron->pendingSend || neuron->pendingRecv || neuron->connectAttemptPending())
      {
        PRODIGY_DEBUG_LOG(
                     "prodigy debug neuron-control-rearm-preserve source=brain-arm uuid=%llu private4=%u connected=%d closing=%d pendingConnect=%d pendingSend=%d pendingRecv=%d fd=%d fslot=%d\n",
                     (unsigned long long)machine->uuid,
                     unsigned(machine->private4),
                     int(neuron->connected),
                     int(Ring::socketIsClosing(neuron)),
                     int(neuron->connectAttemptPending()),
                     int(neuron->pendingSend),
                     int(neuron->pendingRecv),
                     neuron->fd,
                     neuron->fslot);
        PRODIGY_DEBUG_FLUSH();
        basics_log("brain armMachineNeuronControl preserve-active uuid=%llu private4=%u connected=%d closing=%d pendingSend=%d pendingRecv=%d fd=%d isFixed=%d fslot=%d\n",
                   (unsigned long long)machine->uuid,
                   unsigned(machine->private4),
                   int(neuron->connected),
                   int(Ring::socketIsClosing(neuron)),
                   int(neuron->pendingSend),
                   int(neuron->pendingRecv),
                   neuron->fd,
                   int(neuron->isFixedFile),
                   neuron->fslot);
        return;
      }

      abandonSocketGeneration(neuron);
    }

    PRODIGY_DEBUG_LOG(
                 "prodigy debug neuron-control-rearm-recreate source=brain-arm uuid=%llu private4=%u pendingConnect=%d pendingSend=%d pendingRecv=%d fd=%d fslot=%d\n",
                 (unsigned long long)machine->uuid,
                 unsigned(machine->private4),
                 int(neuron->connectAttemptPending()),
                 int(neuron->pendingSend),
                 int(neuron->pendingRecv),
                 neuron->fd,
                 neuron->fslot);
    PRODIGY_DEBUG_FLUSH();
    BrainBase::armMachineNeuronControl(machine);
  }

public:

  void onDrainCompleteForOSUpdate(Machine *machine)
  {
    if (machine != nullptr)
    {
      machine->osUpdateCommandIssued = false;
      cancelOSUpdateCommandWatchdog(machine);
    }
  }

  void armMachineUpdateTimerIfNeeded(void)
  {
    if (brainConfig.osUpdatesEnabled || brainConfig.osUpdatePolicies.empty() == false)
    {
      PRODIGY_DEBUG_LOG(
                   "os update scheduler arm-enter master=%d ignited=%d enabled=%d policies=%u coverage=%d activeDrains=%u armed=%d pendingVMReimage=%d\n",
                   int(weAreMaster),
                   int(ignited),
                   int(brainConfig.osUpdatesEnabled),
                   unsigned(brainConfig.osUpdatePolicies.size()),
                   int(osUpdatePolicyCoverageComplete()),
                   unsigned(countActiveOSDrains()),
                   int(osUpdateTimerArmed),
                   int(hasPendingVMReimage()));
      PRODIGY_DEBUG_FLUSH();
      basics_log("os update scheduler arm-enter master=%d ignited=%d enabled=%d policies=%u coverage=%d activeDrains=%u armed=%d pendingVMReimage=%d\n",
                 int(weAreMaster),
                 int(ignited),
                 int(brainConfig.osUpdatesEnabled),
                 unsigned(brainConfig.osUpdatePolicies.size()),
                 int(osUpdatePolicyCoverageComplete()),
                 unsigned(countActiveOSDrains()),
                 int(osUpdateTimerArmed),
                 int(hasPendingVMReimage()));
    }

    if (weAreMaster == false || ignited == false || osUpdatePolicyCoverageComplete() == false || hasPendingVMReimage() || countActiveOSDrains() >= normalizedMaxOSDrains())
    {
      return;
    }

    refreshOperatingSystemUpdateQueue();
    basics_log("os update scheduler arm-check enabled=%d policies=%u activeDrains=%u candidates=%u armed=%d lastStartMs=%lld cadenceMs=%lld\n",
               int(brainConfig.osUpdatesEnabled),
               unsigned(brainConfig.osUpdatePolicies.size()),
               unsigned(countActiveOSDrains()),
               unsigned(operatingSystemUpdateOrder.size()),
               int(osUpdateTimerArmed),
               (long long)lastOperatingSystemUpdateStartMs,
               (long long)normalizedMachineUpdateCadenceMs());
    if (operatingSystemUpdateOrder.empty())
    {
      return;
    }

    int64_t nowMs = Time::now<TimeResolution::ms>();
    int64_t cadenceMs = normalizedMachineUpdateCadenceMs();
    int64_t elapsedMs = lastOperatingSystemUpdateStartMs > 0 ? nowMs - lastOperatingSystemUpdateStartMs : cadenceMs;
    if (lastOperatingSystemUpdateStartMs == 0 || elapsedMs >= cadenceMs)
    {
      bool started = runMachineUpdateCadenceTick();
      if (started)
      {
        basics_log("os update scheduler started candidate immediately cadenceMs=%lld\n", (long long)cadenceMs);
        return;
      }
    }

    if (osUpdateTimerArmed)
    {
      return;
    }

    osUpdateTimer.flags = uint64_t(BrainTimeoutFlags::updateOSWakeup);
    osUpdateTimer.dispatcher = this;
    if (osUpdateTimerInstalled == false)
    {
      RingDispatcher::installMultiplexee(&osUpdateTimer, this);
      osUpdateTimerInstalled = true;
    }

    int64_t delayMs = cadenceMs;
    if (lastOperatingSystemUpdateStartMs > 0)
    {
      delayMs = cadenceMs - elapsedMs;
      if (delayMs < 1)
      {
        delayMs = 1;
      }
    }

    osUpdateTimer.setTimeoutMs(delayMs);
    Ring::queueTimeout(&osUpdateTimer);
    osUpdateTimerArmed = true;
  }

  void cancelMachineSoftWatchdog(Machine *machine)
  {
    if (machine == nullptr)
    {
      return;
    }

    if (machines.contains(machine) == false)
    {
      return;
    }

    if (machine->softWatchdog)
    {
      TimeoutPacket *watchdog = machine->softWatchdog;
      machine->softWatchdog = nullptr;

      RingDispatcher::eraseMultiplexee(watchdog);
      watchdog->flags = uint64_t(BrainTimeoutFlags::canceled);
      Ring::queueCancelTimeout(watchdog);
    }
  }

  void cancelMachineHardRebootWatchdog(Machine *machine)
  {
    if (machine == nullptr)
    {
      return;
    }

    if (machines.contains(machine) == false)
    {
      return;
    }

    if (machine->hardRebootWatchdog)
    {
      TimeoutPacket *watchdog = machine->hardRebootWatchdog;
      machine->hardRebootWatchdog = nullptr;

      RingDispatcher::eraseMultiplexee(watchdog);
      watchdog->flags = uint64_t(BrainTimeoutFlags::canceled);
      Ring::queueCancelTimeout(watchdog);
    }
  }

  void cancelOSUpdateCommandWatchdog(Machine *machine)
  {
    if (machine == nullptr)
    {
      return;
    }

    if (machines.contains(machine) == false)
    {
      return;
    }

    if (machine->osUpdateCommandWatchdog)
    {
      TimeoutPacket *watchdog = machine->osUpdateCommandWatchdog;
      machine->osUpdateCommandWatchdog = nullptr;

      RingDispatcher::eraseMultiplexee(watchdog);
      watchdog->flags = uint64_t(BrainTimeoutFlags::canceled);
      Ring::queueCancelTimeout(watchdog);
    }
  }

  void armOSUpdateCommandWatchdog(Machine *machine)
  {
    if (machine == nullptr || machines.contains(machine) == false)
    {
      return;
    }

    cancelOSUpdateCommandWatchdog(machine);

    TimeoutPacket *timeout = new TimeoutPacket();
    timeout->flags = uint64_t(BrainTimeoutFlags::osUpdateCommandDeadline);
    timeout->identifier = machine->uuid;
    timeout->originator = machine;
    timeout->dispatcher = this;
    timeout->setTimeoutMs(normalizedOSUpdateCommandRebootDeadlineMs());
    RingDispatcher::installMultiplexee(timeout, this);
    Ring::queueTimeout(timeout);
    machine->osUpdateCommandWatchdog = timeout;
  }

  void failOSUpdateCommandDeadline(Machine *machine)
  {
    if (machine == nullptr || machines.contains(machine) == false)
    {
      return;
    }

    PRODIGY_DEBUG_LOG(
                 "os update command deadline uuid=%llu private4=%u state=%u targetKnown=%d\n",
                 (unsigned long long)machine->uuid,
                 unsigned(machine->private4),
                 unsigned(machine->state),
                 int(osUpdatePolicyForMachine(machine) != nullptr));
    PRODIGY_DEBUG_FLUSH();
    basics_log("os update command deadline uuid=%llu private4=%u state=%u targetKnown=%d\n",
               (unsigned long long)machine->uuid,
               unsigned(machine->private4),
               unsigned(machine->state),
               int(osUpdatePolicyForMachine(machine) != nullptr));

    machine->osUpdateCommandIssued = false;
    iaas->reportHardwareFailure(machine->uuid, "OS update command did not reboot before deadline"_ctv);
    if (machine->state != MachineState::hardwareFailure && machine->state != MachineState::decommissioning)
    {
      handleMachineStateChange(machine, MachineState::hardwareFailure);
      decommissionMachine(machine);
    }
    armMachineUpdateTimerIfNeeded();
  }

  void dispatchTimeout(TimeoutPacket *packet) override
  {
    switch (BrainTimeoutFlags(packet->flags))
    {
      case BrainTimeoutFlags::canceled:
        {
          RingDispatcher::eraseMultiplexee(packet);
          delete packet;
          break;
        }
      case BrainTimeoutFlags::dnsReconcileRetry:
        {
          dnsReconcileRetryArmed = false;
          reconcileAuthoritativeDNSState();
          if (dnsReconciliationPending())
          {
            armDNSReconciliationRetry();
          }
          break;
        }
      case BrainTimeoutFlags::ignition:
        {
          ignited = true;

          // at this point we've either connected to every neuron and gotten an upload of its state,
          // or we can assume the neuron is missing... and appropriate action would already be in progress

          for (Machine *machine : machines)
          {
            // consider the machine registered if we've received neuron registration metadata
            if ((machine->lastUpdatedOSMs > 0 || machine->kernel.size() > 0) && prodigyMachineHardwareInventoryReady(machine->hardware))
            {
              if (machine->fragment == 0)
              {
                assignMachineFragment(machine);
              }

              promoteMachineToHealthyIfReady(machine);
            }
            // else we'll be triaging it already
          }

          refreshMachineFragmentAssignmentsIfPossible();

          // Recover only deployments whose authoritative DNS intent has
          // completed for the exact current lease snapshot.
          recoverDeploymentsAfterNeuronState();

          armMachineUpdateTimerIfNeeded();

          if (weAreMaster)
          {
            TimeoutPacket *recovery = new TimeoutPacket();
            recovery->flags = uint64_t(BrainTimeoutFlags::postIgnitionRecovery);
            recovery->dispatcher = this;
            recovery->setTimeoutMs(prodigyBrainPostIgnitionRecoveryTimeoutMs);
            RingDispatcher::installMultiplexee(recovery, this);
            Ring::queueTimeout(recovery);
          }

          break;
        }
      case BrainTimeoutFlags::brainPeerHeartbeat:
        {
          runBrainPeerHeartbeatTick();
          expireContainerLogRequests();
          brainPeerHeartbeatTicker.setTimeoutMs(brainPeerHeartbeatIntervalMs);
          Ring::queueTimeout(&brainPeerHeartbeatTicker);
          break;
        }
      case BrainTimeoutFlags::brainPeerReconnect:
        {
          BrainView *brain = (BrainView *)packet->originator;
          bool persistentReconnect = (packet->identifier != 0);
          if (auto it = brainReconnectWaiters.find(brain); it != brainReconnectWaiters.end())
          {
            if (it->second != packet)
            {
              basics_log("brain reconnect timeout ignored stale packet private4=%u active=%p stale=%p\n",
                         brain ? brain->private4 : 0u,
                         static_cast<void *>(it->second),
                         static_cast<void *>(packet));
              delete packet;
              break;
            }

            brainReconnectWaiters.erase(it);
          }
          else
          {
            basics_log("brain reconnect timeout ignored untracked packet private4=%u packet=%p\n",
                       brain ? brain->private4 : 0u,
                       static_cast<void *>(packet));
            delete packet;
            break;
          }

          delete packet;
          attemptBrainPeerReconnectNow(brain, persistentReconnect, "reconnect-timeout");
          break;
        }
      case BrainTimeoutFlags::brainPeerHandshake:
        {
          BrainView *brain = (BrainView *)packet->originator;
          uint128_t transportEpoch = packet->identifier;
          if (auto it = brainHandshakeWaiters.find(brain); it != brainHandshakeWaiters.end())
          {
            if (it->second != packet)
            {
              basics_log("brain peer handshake timeout ignored stale packet private4=%u active=%p stale=%p\n",
                         brain ? brain->private4 : 0u,
                         static_cast<void *>(it->second),
                         static_cast<void *>(packet));
              delete packet;
              break;
            }

            brainHandshakeWaiters.erase(it);
          }
          else
          {
            basics_log("brain peer handshake timeout ignored untracked packet private4=%u packet=%p\n",
                       brain ? brain->private4 : 0u,
                       static_cast<void *>(packet));
            delete packet;
            break;
          }

          delete packet;

          if (brain == nullptr || brains.contains(brain) == false || brainPeerHandshakeComplete(brain) || transportEpoch != uint128_t(brain->transportEpoch))
          {
            break;
          }

          basics_log("brain peer handshake timeout closing private4=%u active=%d closing=%d connected=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d registrationFresh=%d transportEpoch=%u\n",
                     brain->private4,
                     int(rawStreamIsActive(brain)),
                     int(Ring::socketIsClosing(brain)),
                     int(brain->connected),
                     int(brain->pendingSend),
                     int(brain->pendingRecv),
                     int(brain->isTLSNegotiated()),
                     int(brain->tlsPeerVerified),
                     int(brain->registrationFresh),
                     unsigned(brain->transportEpoch));

          if (rawStreamIsActive(brain))
          {
            queueBrainCloseIfActive(brain, "brain-peer-handshake-timeout");
          }
          else if (peerReconnectOwned(brain) && Ring::socketIsClosing(brain) == false)
          {
            attemptBrainPeerReconnectNow(brain, true, "brain-peer-handshake-timeout");
          }

          break;
        }
      case BrainTimeoutFlags::neuronControlReconnect:
        {
          NeuronView *neuron = (NeuronView *)packet->originator;
          if (auto it = neuronReconnectWaiters.find(neuron); it != neuronReconnectWaiters.end())
          {
            if (it->second != packet)
            {
              basics_log("neuron reconnect timeout ignored stale packet private4=%u active=%p stale=%p\n",
                         (neuron && neuron->machine ? neuron->machine->private4 : 0u),
                         static_cast<void *>(it->second),
                         static_cast<void *>(packet));
              delete packet;
              break;
            }

            neuronReconnectWaiters.erase(it);
          }
          else
          {
            basics_log("neuron reconnect timeout ignored untracked packet private4=%u packet=%p\n",
                       (neuron && neuron->machine ? neuron->machine->private4 : 0u),
                       static_cast<void *>(packet));
            delete packet;
            break;
          }

          delete packet;
          attemptNeuronControlReconnectNow(neuron, "neuron-reconnect-timeout");
          break;
        }
      case BrainTimeoutFlags::neuronControlHandshake:
        {
          NeuronView *neuron = (NeuronView *)packet->originator;
          if (auto it = neuronHandshakeWaiters.find(neuron); it != neuronHandshakeWaiters.end())
          {
            if (it->second != packet)
            {
              basics_log("neuron handshake timeout ignored stale packet private4=%u active=%p stale=%p\n",
                         (neuron && neuron->machine ? neuron->machine->private4 : 0u),
                         static_cast<void *>(it->second),
                         static_cast<void *>(packet));
              delete packet;
              break;
            }

            neuronHandshakeWaiters.erase(it);
          }
          else
          {
            basics_log("neuron handshake timeout ignored untracked packet private4=%u packet=%p\n",
                       (neuron && neuron->machine ? neuron->machine->private4 : 0u),
                       static_cast<void *>(packet));
            delete packet;
            break;
          }

          delete packet;

          if (neuron == nullptr || neurons.contains(neuron) == false || weAreMaster == false || neuronControlHandshakeComplete(neuron))
          {
            break;
          }

          if (neuron->machine)
          {
            neuron->machine->lastNeuronFailMs = Time::now<TimeResolution::ms>();
            neuron->machine->neuronConnectFailStreak += 1;
          }

          basics_log("neuron handshake timeout closing private4=%u active=%d closing=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d runtimeReady=%d state=%u\n",
                     (neuron->machine ? neuron->machine->private4 : 0u),
                     int(rawStreamIsActive(neuron)),
                     int(Ring::socketIsClosing(neuron)),
                     int(neuron->pendingSend),
                     int(neuron->pendingRecv),
                     int(neuron->isTLSNegotiated()),
                     int(neuron->tlsPeerVerified),
                     int(neuron->machine ? neuron->machine->runtimeReady : false),
                     unsigned(neuron->machine ? uint32_t(neuron->machine->state) : 0u));

          if (rawStreamIsActive(neuron))
          {
            queueCloseIfActive(neuron);
          }
          else
          {
            attemptNeuronControlReconnectNow(neuron, "neuron-handshake-timeout");
          }

          break;
        }
      case BrainTimeoutFlags::brainPeerLiveness:
        {
          BrainView *brain = (BrainView *)packet->originator;
          if (auto it = brainLivenessWaiters.find(brain); it != brainLivenessWaiters.end())
          {
            if (it->second != packet)
            {
              basics_log("brain liveness timeout ignored stale packet private4=%u active=%p stale=%p\n",
                         brain ? brain->private4 : 0u,
                         static_cast<void *>(it->second),
                         static_cast<void *>(packet));
              delete packet;
              break;
            }

            brainLivenessWaiters.erase(it);
          }
          else
          {
            basics_log("brain liveness timeout ignored untracked packet private4=%u packet=%p\n",
                       brain ? brain->private4 : 0u,
                       static_cast<void *>(packet));
            delete packet;
            break;
          }

          delete packet;

          if (brain == nullptr || brains.contains(brain) == false || peerRepresentsCurrentMasterForLiveness(brain) == false)
          {
            break;
          }

          brain->confirmedMissingTransportEpoch = brain->transportEpoch;
          basics_log("brain liveness timeout current-master private4=%u transportEpoch=%u active=%d closing=%d\n",
                     brain->private4,
                     unsigned(brain->transportEpoch),
                     int(rawStreamIsActive(brain)),
                     int(Ring::socketIsClosing(brain)));
          if (rawStreamIsActive(brain))
          {
            queueBrainCloseIfActive(brain, "peer-liveness-timeout");
          }
          else if (Ring::socketIsClosing(brain) == false)
          {
            brainMissing(brain);
          }

          break;
        }
      case BrainTimeoutFlags::brainMissing:
        {
          BrainView *brain = (BrainView *)packet->originator;
          if (auto it = brainWaiters.find(brain); it != brainWaiters.end())
          {
            if (it->second != packet)
            {
              basics_log("brainMissing timeout ignored stale packet private4=%u active=%p stale=%p\n",
                         brain ? brain->private4 : 0u,
                         static_cast<void *>(it->second),
                         static_cast<void *>(packet));
              delete packet;
              break;
            }

            brainWaiters.erase(it);
          }
          else
          {
            basics_log("brainMissing timeout ignored untracked packet private4=%u packet=%p\n",
                       brain ? brain->private4 : 0u,
                       static_cast<void *>(packet));
            delete packet;
            break;
          }
          PRODIGY_DEBUG_LOG(
                       "prodigy debug brain waiter-fire private4=%u packet=%p\n",
                       brain ? brain->private4 : 0u,
                       static_cast<void *>(packet));
          PRODIGY_DEBUG_FLUSH();
          delete packet;

          brainMissing(brain);

          break;
        }
      case BrainTimeoutFlags::updateOSWakeup:
        {
          osUpdateTimerArmed = false;
          (void)runMachineUpdateCadenceTick();
          armMachineUpdateTimerIfNeeded();
          break;
        }
      case BrainTimeoutFlags::osUpdateCommandDeadline:
        {
          Machine *machine = nullptr;
          if (packet->identifier > 0)
          {
            if (auto it = machinesByUUID.find(packet->identifier); it != machinesByUUID.end())
            {
              machine = it->second;
            }
          }
          else if (packet->originator != nullptr)
          {
            Machine *candidate = (Machine *)packet->originator;
            if (machines.contains(candidate))
            {
              machine = candidate;
            }
          }

          if (machine == nullptr || machine->osUpdateCommandWatchdog != packet)
          {
            RingDispatcher::eraseMultiplexee(packet);
            delete packet;
            break;
          }

          machine->osUpdateCommandWatchdog = nullptr;
          RingDispatcher::eraseMultiplexee(packet);
          delete packet;

          if (machine->osUpdateCommandIssued)
          {
            failOSUpdateCommandDeadline(machine);
          }
          break;
        }
      case BrainTimeoutFlags::hardRebootedMachine:
        {
          Machine *machine = nullptr;
          if (packet->identifier > 0)
          {
            if (auto it = machinesByUUID.find(packet->identifier); it != machinesByUUID.end())
            {
              machine = it->second;
            }
          }
          else if (packet->originator != nullptr)
          {
            Machine *candidate = (Machine *)packet->originator;
            if (machines.contains(candidate))
            {
              machine = candidate;
            }
          }

          // A machine may have already been decommissioned before this timeout fires.
          // Drop stale reboot watchdog packets instead of dereferencing dead pointers.
          if (machine == nullptr || machine->hardRebootWatchdog != packet)
          {
            RingDispatcher::eraseMultiplexee(packet);
            delete packet;
            break;
          }

          machine->hardRebootWatchdog = nullptr;

          if (machine->state == MachineState::healthy) // did we reconnect to the neuron or brain?
          {
          }
          else
          {
            iaas->reportHardwareFailure(machine->uuid, ""_ctv);
            // we probably also want to text ourselves but... maybe we build a mothership app?

            // if it's not a reserved machine... can we just destroy it or?
            // Treat a hard-reboot timeout as a terminal host failure so deployments drain and reschedule.
            if (machine->state != MachineState::hardwareFailure && machine->state != MachineState::decommissioning)
            {
              handleMachineStateChange(machine, MachineState::hardwareFailure);
              decommissionMachine(machine);
            }
          }

          RingDispatcher::eraseMultiplexee(packet);
          delete packet;

          break;
        }
      case BrainTimeoutFlags::softEscalationCheck:
        {
          // If the machine isn't healthy yet after a soft SSH restart, escalate to unresponsive
          Machine *machine = nullptr;
          if (packet->identifier > 0)
          {
            if (auto it = machinesByUUID.find(packet->identifier); it != machinesByUUID.end())
            {
              machine = it->second;
            }
          }
          else if (packet->originator != nullptr)
          {
            Machine *candidate = (Machine *)packet->originator;
            if (machines.contains(candidate))
            {
              machine = candidate;
            }
          }

          if (machine == nullptr || machine->softWatchdog != packet)
          {
            RingDispatcher::eraseMultiplexee(packet);
            delete packet;
            break;
          }

          machine->softWatchdog = nullptr;

          RingDispatcher::eraseMultiplexee(packet);
          delete packet;

          if (machine && machine->state != MachineState::healthy && machine->state != MachineState::neuronRebooting)
          {
            basics_log("machine soft escalation timeout uuid=%llu private4=%u state=%u creationTimeMs=%lld\n",
                       (unsigned long long)machine->uuid,
                       unsigned(machine->private4),
                       unsigned(machine->state),
                       (long long)machine->creationTimeMs);
            // move to medium escalation
            handleMachineStateChange(machine, MachineState::unresponsive);
          }
          break;
        }
      case BrainTimeoutFlags::transitionStuck:
        {
          Machine *machine = (Machine *)packet->originator;
          RingDispatcher::eraseMultiplexee(packet);
          delete packet;

          if (machine && machine->state != MachineState::healthy)
          {
            // If still in a supposed update, consider it stuck and escalate
            if (machine->inBinaryUpdate || machine->state == MachineState::neuronRebooting)
            {
              machine->inBinaryUpdate = false;
              handleMachineStateChange(machine, MachineState::unresponsive);
            }
          }

          break;
        }
      case BrainTimeoutFlags::performHardReboot:
        {
          Machine *machine = (Machine *)packet->originator;
          RingDispatcher::eraseMultiplexee(packet);
          delete packet;

          if (machine)
          {
            (void)queueMachineHardReboot(machine);
          }

          break;
        }
      case BrainTimeoutFlags::postIgnitionRecovery:
        {
          recoverDeploymentsAfterNeuronState();

          RingDispatcher::eraseMultiplexee(packet);
          delete packet;
          break;
        }
      case BrainTimeoutFlags::spotDecomissionChecker:
        {
          reconcilePendingElasticAddressAssignments();
          reconcilePendingElasticAddressReleases();
          checkForSpotTerminations();
          break;
        }
      default:
        break;
    }
  }

  void timeoutHandler(TimeoutPacket *packet, int result) override
  {
    if (packet->dispatcher)
    {
      packet->dispatcher->dispatchTimeout(packet);
    }
  }

  void timeoutMultishotHandler(TimeoutPacket *packet, int result) override
  {
    timeoutHandler(packet, result);
  }

  template <typename T>
  bool rawStreamIsActive(T *stream)
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

    // Reconnect/bootstrap can briefly keep a live direct-fd stream around
    // until the fixed-file replacement is installed.
    return (stream->fd >= 0);
  }

  template <typename T>
  bool streamIsActive(T *stream)
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
  void queueCloseIfActive(T *stream)
  {
    if (rawStreamIsActive(stream) == false || Ring::socketIsClosing(stream))
    {
      return;
    }

    Ring::queueClose(stream);
  }

  void queueBrainCloseIfActive(BrainView *brain, const char *reason, int result = 0)
  {
    if (brain == nullptr)
    {
      return;
    }

    const bool active = rawStreamIsActive(brain);
    basics_log("brain queueClose reason=%s private4=%u result=%d active=%d weConnectToIt=%d accepted=%d connected=%d pendingSend=%d pendingRecv=%d tls=%d negotiated=%d peerVerified=%d registrationFresh=%d quarantined=%d fd=%d fslot=%d queuedBytes=%llu wbytes=%u rbytes=%llu\n",
               (reason ? reason : "unspecified"),
               brain->private4,
               result,
               int(active),
               int(brain->weConnectToIt),
               int(brain->currentStreamAccepted),
               int(brain->connected),
               int(brain->pendingSend),
               int(brain->pendingRecv),
               int(brain->transportTLSEnabled()),
               int(brain->isTLSNegotiated()),
               int(brain->tlsPeerVerified),
               int(brain->registrationFresh),
               int(brain->quarantined),
               brain->fd,
               brain->fslot,
               (unsigned long long)brain->queuedSendOutstandingBytes(),
               uint32_t(brain->wBuffer.outstandingBytes()),
               (unsigned long long)brain->rBuffer.outstandingBytes());

    if (active == false)
    {
      return;
    }

    brain->noteCloseQueuedForCurrentTransport();
    Ring::queueClose(brain);
  }

  template <typename T>
  void abandonSocketGeneration(T *stream)
  {
    if (stream == nullptr || Ring::socketIsClosing(stream))
    {
      return;
    }

    if (stream->isFixedFile && stream->fslot >= 0)
    {
      if (RingDispatcher::dispatcher != nullptr && Ring::getRingFD() > 0)
      {
        Ring::queueCancelAll(stream);
        Ring::queueCloseRaw(stream->fslot);
      }

      stream->fslot = -1;
      stream->isFixedFile = false;
    }
    else if (stream->fd >= 0)
    {
      ::close(stream->fd);
      stream->fd = -1;
      stream->isFixedFile = false;
    }

    if constexpr (requires (T *value) { value->reset(); })
    {
      // A reconnect/accepted replacement must discard the full prior stream
      // generation, not just the raw fd. Leaving TLS/BIO/encrypted-buffer
      // state behind lets the next handshake consume stale allocator-backed
      // state on a fresh socket generation.
      stream->reset();
    }
    else
    {
      stream->pendingSend = false;
      stream->pendingRecv = false;
      stream->pendingSendBytes = 0;
      stream->bumpIoGeneration();

      if constexpr (requires (T *value) { value->connected; })
      {
        stream->connected = false;
      }

      if constexpr (requires (T *value) { value->rBuffer.clear(); })
      {
        stream->rBuffer.clear();
      }

      if constexpr (requires (T *value) { value->clearQueuedSendBytes(); })
      {
        stream->clearQueuedSendBytes();
      }

      if constexpr (requires (T *value) { value->tlsPeerVerified = false; value->tlsPeerUUID = 0; })
      {
        stream->tlsPeerVerified = false;
        stream->tlsPeerUUID = 0;
      }
    }
  }

  bool verifyBrainTransportTLSPeer(BrainView *brain)
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
      basics_log("brain transport tls missing peer uuid fd=%d fslot=%d\n", brain->fd, brain->fslot);
      return false;
    }

    if (brain->uuid != 0 && brain->uuid != peerUUID)
    {
      basics_log("brain transport tls uuid mismatch expected=%llu actual=%llu fd=%d fslot=%d\n",
                 (unsigned long long)brain->uuid,
                 (unsigned long long)peerUUID,
                 brain->fd,
                 brain->fslot);
      return false;
    }

    if (brain->machine && brain->machine->uuid != 0 && brain->machine->uuid != peerUUID)
    {
      basics_log("brain transport tls machine uuid mismatch expected=%llu actual=%llu fd=%d fslot=%d\n",
                 (unsigned long long)brain->machine->uuid,
                 (unsigned long long)peerUUID,
                 brain->fd,
                 brain->fslot);
      return false;
    }

    if (brain->uuid == 0)
    {
      brain->uuid = peerUUID;
    }

    brain->tlsPeerUUID = peerUUID;
    brain->tlsPeerVerified = true;
    basics_log("brain transport tls peer verified fd=%d fslot=%d\n", brain->fd, brain->fslot);
    return true;
  }

  bool verifyNeuronTransportTLSPeer(NeuronView *neuron)
  {
    if (neuron == nullptr || neuron->transportTLSEnabled() == false || neuron->tlsPeerVerified)
    {
      return true;
    }

    if (neuron->isTLSNegotiated() == false)
    {
      return true;
    }

    Machine *machine = neuron->machine;
    uint128_t peerUUID = 0;
    if (ProdigyTransportTLSRuntime::extractPeerUUID(neuron->ssl, peerUUID) == false)
    {
      basics_log("neuron transport tls missing peer uuid fd=%d fslot=%d\n", neuron->fd, neuron->fslot);
      PRODIGY_DEBUG_LOG(
                   "brain neuron tls-verify missing-peer-uuid fd=%d fslot=%d private4=%u machineUUID=%llu tlsNegotiated=%d\n",
                   neuron->fd,
                   neuron->fslot,
                   unsigned(machine ? machine->private4 : 0u),
                   (unsigned long long)(machine ? machine->uuid : 0),
                   int(neuron->isTLSNegotiated()));
      PRODIGY_DEBUG_FLUSH();
      return false;
    }

    if (machine && machine->uuid != 0 && machine->uuid != peerUUID)
    {
      basics_log("neuron transport tls uuid mismatch expected=%llu actual=%llu fd=%d fslot=%d\n",
                 (unsigned long long)machine->uuid,
                 (unsigned long long)peerUUID,
                 neuron->fd,
                 neuron->fslot);
      PRODIGY_DEBUG_LOG(
                   "brain neuron tls-verify uuid-mismatch expected=%llu actual=%llu private4=%u fd=%d fslot=%d\n",
                   (unsigned long long)machine->uuid,
                   (unsigned long long)peerUUID,
                   unsigned(machine->private4),
                   neuron->fd,
                   neuron->fslot);
      PRODIGY_DEBUG_FLUSH();
      return false;
    }

    if (machine && machine->uuid == 0)
    {
      machine->uuid = peerUUID;
      machinesByUUID.insert_or_assign(machine->uuid, machine);
    }

    neuron->tlsPeerUUID = peerUUID;
    neuron->tlsPeerVerified = true;
#if PRODIGY_DEBUG
    basics_log("brain neuron transport tls peer verified fd=%d fslot=%d peerUUID=%llu machineUUID=%llu private4=%u cloudID=%s state=%u inventoryComplete=%d\n",
               neuron->fd,
               neuron->fslot,
               (unsigned long long)peerUUID,
               (unsigned long long)(machine ? machine->uuid : 0),
               unsigned(machine ? machine->private4 : 0u),
               (machine ? machine->cloudID.c_str() : ""),
               unsigned(machine ? uint32_t(machine->state) : 0u),
               int(machine ? machine->hardware.inventoryComplete : 0));
#else
    basics_log("brain neuron transport tls peer verified fd=%d fslot=%d\n", neuron->fd, neuron->fslot);
#endif
    PRODIGY_DEBUG_LOG(
                 "brain neuron tls-verify ok peerUUID=%llu machineUUID=%llu private4=%u fd=%d fslot=%d state=%u inventoryComplete=%d\n",
                 (unsigned long long)peerUUID,
                 (unsigned long long)(machine ? machine->uuid : 0),
                 unsigned(machine ? machine->private4 : 0u),
                 neuron->fd,
                 neuron->fslot,
                 unsigned(machine ? uint32_t(machine->state) : 0u),
                 int(machine ? machine->hardware.inventoryComplete : 0));
    PRODIGY_DEBUG_FLUSH();
    return true;
  }

  void retireClosingMothershipStreamIfNeeded(Mothership *stream, const char *reason = nullptr)
  {
    if (stream == nullptr || activeMotherships.contains(stream) == false)
    {
      return;
    }

    if (Ring::socketIsClosing(stream) == false)
    {
      return;
    }

    closingMotherships.insert(stream);
    activeMotherships.erase(stream);
    if (mothership == stream)
    {
      mothership = (activeMotherships.empty() ? nullptr : *activeMotherships.begin());
    }
    PRODIGY_DEBUG_LOG( "prodigy mothership retire-closing reason=%s stream=%p closingStreams=%zu master=%d\n",
                 (reason ? reason : "unknown"),
                 static_cast<void *>(stream),
                 size_t(closingMotherships.size()),
                 int(weAreMaster));
    PRODIGY_DEBUG_FLUSH();
    if (weAreMaster)
    {
      queueMothershipUnixAcceptIfNeeded();
    }
  }

  void destroyIdleMothershipStreamNow(Mothership *stream, const char *reason = nullptr)
  {
    if (stream == nullptr || Ring::socketIsClosing(stream))
    {
      return;
    }

    PRODIGY_DEBUG_LOG( "prodigy mothership destroy-idle reason=%s stream=%p fd=%d fslot=%d master=%d\n",
                 (reason ? reason : "unknown"),
                 static_cast<void *>(stream),
                 stream->fd,
                 stream->fslot,
                 int(weAreMaster));
    PRODIGY_DEBUG_FLUSH();

    stream->closeAfterSendDrain = false;

    if (RingDispatcher::dispatcher != nullptr && Ring::getRingFD() > 0 && rawStreamIsActive(stream))
    {
      if (stream->isFixedFile && stream->fslot >= 0)
      {
        Ring::queueCancelAll(stream);
      }

      // Even a fully drained commander client must stay alive until the close
      // completion lands. Deleting it after a raw slot close lets stale CQEs
      // race with allocator reuse of the same object address.
      Ring::queueClose(stream);
      retireClosingMothershipStreamIfNeeded(stream, reason);
      return;
    }

    clearSpinApplicationMothershipsForStream(stream);
    clearContainerLogRequestsForStream(stream);
    closingMotherships.erase(stream);

    activeMotherships.erase(stream);
    if (stream == mothership)
    {
      mothership = (activeMotherships.empty() ? nullptr : *activeMotherships.begin());
    }

    if (stream->isFixedFile && stream->fslot >= 0)
    {
      stream->fslot = -1;
      stream->isFixedFile = false;
    }
    else if (stream->fd >= 0)
    {
      ::close(stream->fd);
      stream->fd = -1;
      stream->isFixedFile = false;
    }

    stream->TCPStream::reset();
    stream->CoroutineStack::reset();

    RingDispatcher::eraseMultiplexee(stream);
    delete stream;

    if (weAreMaster)
    {
      queueMothershipUnixAcceptIfNeeded();
    }
  }

  void queueCloseIfActive(Mothership *stream, const char *reason = nullptr)
  {
    if (streamIsActive(stream) == false || Ring::socketIsClosing(stream))
    {
      return;
    }

    stream->closeAfterSendDrain = false;
    Ring::queueClose(stream);
    if (stream->pendingSend == false && stream->wBuffer.outstandingBytes() == 0)
    {
      retireClosingMothershipStreamIfNeeded(stream, reason);
    }
  }

  void closeMothershipAfterSendDrainIfNeeded(Mothership *stream, const char *reason = nullptr)
  {
    if (stream == nullptr || stream->closeAfterSendDrain == false)
    {
      return;
    }

    if (stream->pendingSend || stream->wBuffer.outstandingBytes() > 0)
    {
      return;
    }

    stream->closeAfterSendDrain = false;
    if (streamIsActive(stream) && Ring::socketIsClosing(stream) == false)
    {
      Ring::queueClose(stream);
    }

    retireClosingMothershipStreamIfNeeded(stream, reason);
  }

  void queueCloseAfterSendDrain(Mothership *stream)
  {
    if (stream == nullptr)
    {
      return;
    }

    stream->closeAfterSendDrain = true;
    closeMothershipAfterSendDrainIfNeeded(stream, "send-drain-immediate");
  }

  Mothership *spinApplicationMothershipFor(ApplicationDeployment *deployment)
  {
    if (deployment == nullptr)
    {
      return nullptr;
    }

    auto it = spinApplicationMotherships.find(deployment->plan.config.deploymentID());
    if (it == spinApplicationMotherships.end())
    {
      return nullptr;
    }

    Mothership *stream = it->second;
    if (streamIsActive(stream) == false || Ring::socketIsClosing(stream))
    {
      spinApplicationMotherships.erase(it);
      return nullptr;
    }

    return stream;
  }

  void bindSpinApplicationMothership(ApplicationDeployment *deployment, Mothership *stream)
  {
    if (deployment == nullptr)
    {
      return;
    }

    uint64_t deploymentID = deployment->plan.config.deploymentID();
    if (deploymentID == 0)
    {
      return;
    }

    if (stream == nullptr || streamIsActive(stream) == false || Ring::socketIsClosing(stream))
    {
      spinApplicationMotherships.erase(deploymentID);
      return;
    }

    spinApplicationMotherships.insert_or_assign(deploymentID, stream);
  }

  void clearSpinApplicationMothership(ApplicationDeployment *deployment)
  {
    if (deployment == nullptr)
    {
      return;
    }

    uint64_t deploymentID = deployment->plan.config.deploymentID();
    if (deploymentID == 0)
    {
      return;
    }

    spinApplicationMotherships.erase(deploymentID);
  }

  void clearSpinApplicationMothershipsForStream(Mothership *stream)
  {
    if (stream == nullptr)
    {
      return;
    }

    for (auto it = spinApplicationMotherships.begin(); it != spinApplicationMotherships.end();)
    {
      if (it->second == stream)
      {
        it = spinApplicationMotherships.erase(it);
      }
      else
      {
        ++it;
      }
    }
  }

  // The unix Mothership control stream now uses the same fixed-file recv/send
  // path as the TCP listener. There is no direct-fd compatibility pump.
  void queueMothershipReceiveIfNeeded(Mothership *stream, const char *reason)
  {
    if (stream == nullptr)
    {
      return;
    }

    if (Ring::socketIsClosing(stream) || streamIsActive(stream) == false)
    {
      PRODIGY_DEBUG_LOG( "prodigy mothership recv-rearm-skip reason=%s active=%d closing=%d stream=%p fd=%d fslot=%d\n",
                   (reason ? reason : "unknown"),
                   int(streamIsActive(stream)),
                   int(Ring::socketIsClosing(stream)),
                   static_cast<void *>(stream),
                   stream->fd,
                   stream->fslot);
      PRODIGY_DEBUG_FLUSH();
      return;
    }

    PRODIGY_DEBUG_LOG( "prodigy mothership recv-arm reason=%s stream=%p fd=%d fslot=%d isFixed=%d pendingRecv=%d pendingSend=%d\n",
                 (reason ? reason : "unknown"),
                 static_cast<void *>(stream),
                 loggableSocketFD(stream),
                 stream->fslot,
                 int(stream->isFixedFile),
                 int(stream->pendingRecv),
                 int(stream->pendingSend));
    PRODIGY_DEBUG_FLUSH();
    Ring::queueRecv(stream);
    PRODIGY_DEBUG_LOG( "prodigy mothership recv-submit reason=%s pendingRecv=%d stream=%p fixedFD=%d fslot=%d rbytes=%zu remaining=%llu\n",
                 (reason ? reason : "unknown"),
                 int(stream->pendingRecv),
                 static_cast<void *>(stream),
                 loggableSocketFD(stream),
                 stream->fslot,
                 size_t(stream->rBuffer.size()),
                 (unsigned long long)stream->rBuffer.remainingCapacity());
    PRODIGY_DEBUG_FLUSH();
  }

  bool flushActiveMothershipSendBuffer(Mothership *stream, const char *reason)
  {
    if (stream == nullptr)
    {
      return false;
    }

    if (stream->wBuffer.size() == 0)
    {
#if PRODIGY_DEBUG
      PRODIGY_DEBUG_LOG( "prodigy mothership send-skip reason=%s wbytes=0 active=%d stream=%p fd=%d fslot=%d\n",
                   (reason ? reason : "unknown"),
                   int(streamIsActive(stream)),
                   static_cast<void *>(stream),
                   stream->fd,
                   stream->fslot);
      PRODIGY_DEBUG_FLUSH();
#endif
      return true;
    }

    if (streamIsActive(stream) == false || Ring::socketIsClosing(stream))
    {
#if PRODIGY_DEBUG
      PRODIGY_DEBUG_LOG( "prodigy mothership send-skip reason=%s wbytes=%zu active=%d closing=%d stream=%p fd=%d fslot=%d\n",
                   (reason ? reason : "unknown"),
                   size_t(stream->wBuffer.size()),
                   int(streamIsActive(stream)),
                   int(Ring::socketIsClosing(stream)),
                   static_cast<void *>(stream),
                   stream->fd,
                   stream->fslot);
      PRODIGY_DEBUG_FLUSH();
#endif
      return false;
    }

#if PRODIGY_DEBUG
    PRODIGY_DEBUG_LOG( "prodigy mothership send-queue reason=%s wbytes=%zu stream=%p fd=%d fslot=%d pendingSend=%d\n",
                 (reason ? reason : "unknown"),
                 size_t(stream->wBuffer.size()),
                 static_cast<void *>(stream),
                 stream->fd,
                 stream->fslot,
                 int(stream->pendingSend));
    PRODIGY_DEBUG_FLUSH();
#endif
    Ring::queueSend(stream);
#if PRODIGY_DEBUG
    PRODIGY_DEBUG_LOG( "prodigy mothership send-submit reason=%s pendingSend=%d pendingSendBytes=%u wbytes=%zu active=%d stream=%p fixedFD=%d fslot=%d\n",
                 (reason ? reason : "unknown"),
                 int(stream->pendingSend),
                 unsigned(stream->pendingSendBytes),
                 size_t(stream->wBuffer.size()),
                 int(streamIsActive(stream)),
                 static_cast<void *>(stream),
                 loggableSocketFD(stream),
                 stream->fslot);
    PRODIGY_DEBUG_FLUSH();
#endif
    return true;
  }

  bool processMothershipReceivedBytes(Mothership *stream, int result, const char *source)
  {
    if (stream == nullptr || result <= 0)
    {
      return false;
    }

    const uint64_t remaining = stream->rBuffer.remainingCapacity();
    if (uint64_t(result) > remaining)
    {
      basics_log("mothership recv overflow result=%d remaining=%llu fd=%d fslot=%d weAreMaster=%d source=%s\n",
                 result,
                 (unsigned long long)remaining,
                 stream->fd,
                 stream->fslot,
                 int(weAreMaster),
                 (source ? source : "unknown"));
      stream->rBuffer.clear();
      if (weAreMaster)
      {
        queueMothershipUnixAcceptIfNeeded();
      }
      queueCloseIfActive(stream);
      return false;
    }

    stream->rBuffer.advance(result);
    logMothershipReceiveBufferHead("recv-parse-head", stream);
    bool parseFailed = false;
    stream->extractMessages<Message>([&](Message *message) -> void {
      size_t wBefore = size_t(stream->wBuffer.size());
      PRODIGY_DEBUG_LOG( "prodigy mothership dispatch-begin source=%s topic=%s(%u) size=%u wBefore=%zu stream=%p fd=%d fslot=%d\n",
                   (source ? source : "unknown"),
                   prodigyMothershipTopicName(MothershipTopic(message->topic)),
                   unsigned(message->topic),
                   unsigned(message->size),
                   wBefore,
                   static_cast<void *>(stream),
                   stream->fd,
                   stream->fslot);
      PRODIGY_DEBUG_FLUSH();

      mothershipHandler(stream, message);
      size_t wAfter = size_t(stream->wBuffer.size());
      PRODIGY_DEBUG_LOG( "prodigy mothership dispatch-end source=%s topic=%s(%u) size=%u wAfter=%zu delta=%lld active=%d pendingSend=%d pendingRecv=%d\n",
                   (source ? source : "unknown"),
                   prodigyMothershipTopicName(MothershipTopic(message->topic)),
                   unsigned(message->topic),
                   unsigned(message->size),
                   wAfter,
                   static_cast<long long>(wAfter) - static_cast<long long>(wBefore),
                   int(streamIsActive(stream)),
                   int(stream->pendingSend),
                   int(stream->pendingRecv));
      PRODIGY_DEBUG_FLUSH();
    },
                                     true, UINT32_MAX, 16, ProdigyWire::maxControlFrameBytes, parseFailed);

    if (parseFailed)
    {
      uint64_t outstanding = stream->rBuffer.outstandingBytes();
      uint32_t peekSize = 0;
      if (outstanding >= sizeof(uint32_t))
      {
        memcpy(&peekSize, stream->rBuffer.pHead(), sizeof(uint32_t));
      }

      basics_log("mothership recv parse failure outstanding=%llu peekSize=%u fd=%d fslot=%d weAreMaster=%d source=%s\n",
                 (unsigned long long)outstanding,
                 unsigned(peekSize),
                 stream->fd,
                 stream->fslot,
                 int(weAreMaster),
                 (source ? source : "unknown"));
      logMothershipReceiveBufferHead("recv-parse-failure", stream);
      stream->rBuffer.clear();
      if (weAreMaster)
      {
        queueMothershipUnixAcceptIfNeeded();
      }
      queueCloseIfActive(stream);
      return false;
    }

    if (stream->wBuffer.size() > 0)
    {
      return flushActiveMothershipSendBuffer(stream, source);
    }

    PRODIGY_DEBUG_LOG( "prodigy mothership send-skip reason=%s wbytes=%zu active=%d stream=%p fd=%d fslot=%d\n",
                 (source ? source : "unknown"),
                 size_t(stream->wBuffer.size()),
                 int(streamIsActive(stream)),
                 static_cast<void *>(stream),
                 stream->fd,
                 stream->fslot);
    PRODIGY_DEBUG_FLUSH();
    return streamIsActive(stream);
  }

  void queueMothershipUnixAcceptIfNeeded(void)
  {
    if (weAreMaster == false)
    {
      return;
    }

    if (mothershipUnixAcceptArmed)
    {
      return;
    }

    if (Ring::socketIsClosing(&mothershipUnixSocket))
    {
      return;
    }

    bool listenerActive = false;
    if (mothershipUnixSocket.isFixedFile)
    {
      listenerActive = (mothershipUnixSocket.fslot >= 0);
    }
    else
    {
      listenerActive = (mothershipUnixSocket.fd >= 0);
    }

    if (listenerActive == false)
    {
      return;
    }

    Ring::queueAccept(&mothershipUnixSocket, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
    mothershipUnixAcceptArmed = true;
    PRODIGY_DEBUG_LOG( "prodigy mothership listen-arm transport=unix path=%s listenerFD=%d listenerFslot=%d master=%d\n",
                 mothershipUnixSocketPath.c_str(),
                 mothershipUnixSocket.fd,
                 mothershipUnixSocket.fslot,
                 int(weAreMaster));
    PRODIGY_DEBUG_FLUSH();
  }

  Mothership *activeMothershipFromSocket(void *socket)
  {
    if (socket == nullptr)
    {
      return nullptr;
    }

    Mothership *stream = static_cast<Mothership *>(socket);
    if (activeMotherships.contains(stream))
    {
      return stream;
    }

    return nullptr;
  }

  bool activateMothershipConnection(Mothership *stream)
  {
    if (stream == nullptr || activeMotherships.contains(stream) ||
        lastMothershipConnectionIncarnation == UINT64_MAX)
    {
      return false;
    }
    stream->connectionIncarnation = ++lastMothershipConnectionIncarnation;
    activeMotherships.insert(stream);
    return true;
  }

  void recvHandler(void *socket, int result) override
  {
    Mothership *activeMothership = activeMothershipFromSocket(socket);
    if (brains.contains(static_cast<BrainView *>(socket)))
    {
      BrainView *brain = static_cast<BrainView *>(socket);
      if (brain->pendingRecv == false)
      {
        // Ignore stale/duplicate recv completions from prior socket generations.
        return;
      }
      brain->pendingRecv = false;

      if (result > 0)
      {
        PRODIGY_DEBUG_LOG(
                     "prodigy debug brain recv-result private4=%u result=%d fd=%d fslot=%d tls=%d negotiated=%d peerVerified=%d pendingSend=%d pendingRecv=%d queuedBytes=%llu rbytes=%llu\n",
                     brain->private4,
                     result,
                     brain->fd,
                     brain->fslot,
                     int(brain->transportTLSEnabled()),
                     int(brain->isTLSNegotiated()),
                     int(brain->tlsPeerVerified),
                     int(brain->pendingSend),
                     int(brain->pendingRecv),
                     (unsigned long long)brain->queuedSendOutstandingBytes(),
                     (unsigned long long)brain->rBuffer.outstandingBytes());
        PRODIGY_DEBUG_FLUSH();
        const uint64_t remaining = brain->rBuffer.remainingCapacity();
        if (uint64_t(result) > remaining)
        {
          basics_log("brain recv overflow private4=%u result=%d remaining=%llu fd=%d fslot=%d\n",
                     brain->private4,
                     result,
                     (unsigned long long)remaining,
                     brain->fd,
                     brain->fslot);
          brain->rBuffer.clear();
          queueBrainCloseIfActive(brain, "recv-overflow", result);
          return;
        }

        if (brain->transportTLSEnabled())
        {
          if (brain->decryptTransportTLS(uint32_t(result)) == false || verifyBrainTransportTLSPeer(brain) == false)
          {
            brain->rBuffer.clear();
            queueBrainCloseIfActive(brain, "recv-decrypt-or-peer-verify-fail", result);
            return;
          }
        }
        else
        {
          brain->rBuffer.advance(result);
        }

        brain->notePeerMessageReceived();

        bool parseFailed = false;
        brain->extractMessages<Message>([&](Message *message) -> void {
          brainHandler(brain, message);
        },
                                        true, UINT32_MAX, 16, ProdigyWire::maxControlFrameBytes, parseFailed);
        if (parseFailed)
        {
          uint64_t outstanding = brain->rBuffer.outstandingBytes();
          uint32_t peekSize = 0;
          if (outstanding >= sizeof(uint32_t))
          {
            memcpy(&peekSize, brain->rBuffer.pHead(), sizeof(uint32_t));
          }

          basics_log("brain recv parse failure private4=%u outstanding=%llu peekSize=%u fd=%d fslot=%d\n",
                     brain->private4,
                     (unsigned long long)outstanding,
                     unsigned(peekSize),
                     brain->fd,
                     brain->fslot);
          brain->rBuffer.clear();
          queueBrainCloseIfActive(brain, "recv-parse-fail", result);
          return;
        }

        if (brainPeerHandshakeComplete(brain))
        {
          cancelBrainPeerHandshakeWatchdog(brain, "recv");
        }
        const bool rawActiveAfterDispatch = rawStreamIsActive(brain);
        const bool streamActiveAfterDispatch = streamIsActive(brain);
        const bool closingAfterDispatch = Ring::socketIsClosing(brain);
        if (streamActiveAfterDispatch && brain->transportTLSEnabled() && brain->needsTransportTLSSendKick())
        {
          Ring::queueSend(brain);
        }
        else if (brain->wBuffer.size() > 0 && streamActiveAfterDispatch)
        {
          Ring::queueSend(brain);
        }

        if (streamActiveAfterDispatch)
        {
          Ring::queueRecv(brain);
          if (brain->pendingRecv == false)
          {
            basics_log("brain recv rearm failed private4=%u result=%d rawActive=%d streamActive=%d closing=%d connected=%d weConnectToIt=%d accepted=%d fd=%d fslot=%d pendingSend=%d pendingRecv=%d tls=%d negotiated=%d peerVerified=%d queuedBytes=%llu wbytes=%u rbytes=%llu\n",
                       brain->private4,
                       result,
                       int(rawActiveAfterDispatch),
                       int(streamActiveAfterDispatch),
                       int(closingAfterDispatch),
                       int(brain->connected),
                       int(brain->weConnectToIt),
                       int(brain->currentStreamAccepted),
                       brain->fd,
                       brain->fslot,
                       int(brain->pendingSend),
                       int(brain->pendingRecv),
                       int(brain->transportTLSEnabled()),
                       int(brain->isTLSNegotiated()),
                       int(brain->tlsPeerVerified),
                       (unsigned long long)brain->queuedSendOutstandingBytes(),
                       uint32_t(brain->wBuffer.outstandingBytes()),
                       (unsigned long long)brain->rBuffer.outstandingBytes());
          }
        }
        else
        {
          basics_log("brain recv rearm skipped private4=%u result=%d rawActive=%d streamActive=%d closing=%d connected=%d weConnectToIt=%d accepted=%d fd=%d fslot=%d pendingSend=%d pendingRecv=%d tls=%d negotiated=%d peerVerified=%d queuedBytes=%llu wbytes=%u rbytes=%llu\n",
                     brain->private4,
                     result,
                     int(rawActiveAfterDispatch),
                     int(streamActiveAfterDispatch),
                     int(closingAfterDispatch),
                     int(brain->connected),
                     int(brain->weConnectToIt),
                     int(brain->currentStreamAccepted),
                     brain->fd,
                     brain->fslot,
                     int(brain->pendingSend),
                     int(brain->pendingRecv),
                     int(brain->transportTLSEnabled()),
                     int(brain->isTLSNegotiated()),
                     int(brain->tlsPeerVerified),
                     (unsigned long long)brain->queuedSendOutstandingBytes(),
                     uint32_t(brain->wBuffer.outstandingBytes()),
                     (unsigned long long)brain->rBuffer.outstandingBytes());
        }
      }
      else
      {
        basics_log("brain recv failed stream=%p private4=%u result=%d isFixed=%d fslot=%d fd=%d weConnectToIt=%d accepted=%d connected=%d pendingSend=%d pendingRecv=%d tls=%d negotiated=%d peerVerified=%d registrationFresh=%d quarantined=%d queuedBytes=%llu wbytes=%u rbytes=%llu updateState=%u\n",
                   static_cast<void *>(brain),
                   brain->private4,
                   result,
                   int(brain->isFixedFile),
                   brain->fslot,
                   brain->fd,
                   int(brain->weConnectToIt),
                   int(brain->currentStreamAccepted),
                   int(brain->connected),
                   int(brain->pendingSend),
                   int(brain->pendingRecv),
                   int(brain->transportTLSEnabled()),
                   int(brain->isTLSNegotiated()),
                   int(brain->tlsPeerVerified),
                   int(brain->registrationFresh),
                   int(brain->quarantined),
                   (unsigned long long)brain->queuedSendOutstandingBytes(),
                   uint32_t(brain->wBuffer.outstandingBytes()),
                   (unsigned long long)brain->rBuffer.outstandingBytes(),
                   unsigned(updateSelfState));
        queueBrainCloseIfActive(brain, "recv-fail", result);
        // try to reconnect... then when that fails...
      }
    }
    else if (neurons.contains(static_cast<NeuronView *>(socket)))
    {
      NeuronView *neuron = static_cast<NeuronView *>(socket);
      if (neuron->pendingRecv == false)
      {
        // Ignore stale/duplicate recv completions from prior socket generations.
        return;
      }

      neuron->pendingRecv = false;

      if (result > 0)
      {
        basics_log("brain neuron recv result uuid=%llu private4=%u result=%d fd=%d fslot=%d tlsNegotiated=%d peerVerified=%d pendingSend=%d pendingRecv=%d wbytes=%u queued=%llu rbytes=%llu\n",
                   (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                   unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                   result,
                   neuron->fd,
                   neuron->fslot,
                   int(neuron->isTLSNegotiated()),
                   int(neuron->tlsPeerVerified),
                   int(neuron->pendingSend),
                   int(neuron->pendingRecv),
                   unsigned(neuron->wBuffer.size()),
                   (unsigned long long)neuron->queuedSendOutstandingBytes(),
                   (unsigned long long)neuron->rBuffer.outstandingBytes());
        const uint64_t remaining = neuron->rBuffer.remainingCapacity();
        if (uint64_t(result) > remaining)
        {
          basics_log("neuron recv overflow private4=%u result=%d remaining=%llu fd=%d fslot=%d\n",
                     (neuron->machine ? neuron->machine->private4 : 0u),
                     result,
                     (unsigned long long)remaining,
                     neuron->fd,
                     neuron->fslot);
          neuron->rBuffer.clear();
          queueCloseIfActive(neuron);
          return;
        }

        if (neuron->transportTLSEnabled())
        {
          if (neuron->decryptTransportTLS(uint32_t(result)) == false || verifyNeuronTransportTLSPeer(neuron) == false)
          {
            PRODIGY_DEBUG_LOG(
                         "brain neuron recv-close tls-or-verify uuid=%llu private4=%u result=%d tlsNegotiated=%d peerVerified=%d fd=%d fslot=%d rbytes=%llu queued=%llu\n",
                         (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                         unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                         result,
                         int(neuron->isTLSNegotiated()),
                         int(neuron->tlsPeerVerified),
                         neuron->fd,
                         neuron->fslot,
                         (unsigned long long)neuron->rBuffer.outstandingBytes(),
                         (unsigned long long)neuron->queuedSendOutstandingBytes());
            PRODIGY_DEBUG_FLUSH();
            neuron->rBuffer.clear();
            queueCloseIfActive(neuron);
            return;
          }
        }
        else
        {
          neuron->rBuffer.advance(result);
        }

        bool parseFailed = false;
        neuron->extractMessages<Message>([&](Message *message) -> void {
          if (ProdigyIngressValidation::validateNeuronPayloadForBrain(message->topic, message->args, message->terminal()) == false)
          {
            basics_log("brain neuron recv invalid payload uuid=%llu private4=%u topic=%u fd=%d fslot=%d\n",
                       (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                       unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                       unsigned(message->topic),
                       neuron->fd,
                       neuron->fslot);
            neuron->rBuffer.clear();
            queueCloseIfActive(neuron);
            return;
          }

#if PRODIGY_DEBUG
          if (message->topic == uint16_t(NeuronTopic::registration) || message->topic == uint16_t(NeuronTopic::machineHardwareProfile))
          {
            basics_log("brain neuron recv-dispatch topic=%u uuid=%llu private4=%u cloudID=%s state=%u inventoryComplete=%d bytes=%u fd=%d fslot=%d\n",
                       unsigned(message->topic),
                       (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                       unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                       (neuron->machine ? neuron->machine->cloudID.c_str() : ""),
                       unsigned(neuron->machine ? uint32_t(neuron->machine->state) : 0u),
                       int(neuron->machine ? neuron->machine->hardware.inventoryComplete : 0),
                       unsigned(message->size),
                       neuron->fd,
                       neuron->fslot);
          }
#endif
          neuronHandler(neuron, message);
        },
                                         true, UINT32_MAX, 16, ProdigyWire::maxControlFrameBytes, parseFailed);
        if (parseFailed)
        {
          uint64_t outstanding = neuron->rBuffer.outstandingBytes();
          uint32_t peekSize = 0;
          uint8_t sample[8] = {0};
          if (outstanding >= sizeof(uint32_t))
          {
            memcpy(&peekSize, neuron->rBuffer.pHead(), sizeof(uint32_t));
          }
          uint64_t sampleCount = (outstanding < sizeof(sample) ? outstanding : sizeof(sample));
          if (sampleCount > 0)
          {
            memcpy(sample, neuron->rBuffer.pHead(), sampleCount);
          }

          basics_log("neuron recv parse failure private4=%u outstanding=%llu peekSize=%u fd=%d fslot=%d sample=%02x %02x %02x %02x %02x %02x %02x %02x\n",
                     (neuron->machine ? neuron->machine->private4 : 0u),
                     (unsigned long long)outstanding,
                     unsigned(peekSize),
                     neuron->fd,
                     neuron->fslot,
                     unsigned(sample[0]),
                     unsigned(sample[1]),
                     unsigned(sample[2]),
                     unsigned(sample[3]),
                     unsigned(sample[4]),
                     unsigned(sample[5]),
                     unsigned(sample[6]),
                     unsigned(sample[7]));
          neuron->rBuffer.clear();
          queueCloseIfActive(neuron);
          return;
        }

#if PRODIGY_DEBUG
        {
          uint64_t outstanding = neuron->rBuffer.outstandingBytes();
          if (outstanding > 0)
          {
            uint32_t peekSize = 0;
            uint16_t peekTopic = 0;
            uint8_t peekHeader = 0;
            uint8_t peekPadding = 0;
            uint8_t sample[8] = {0};
            if (outstanding >= sizeof(uint32_t))
            {
              memcpy(&peekSize, neuron->rBuffer.pHead(), sizeof(uint32_t));
            }
            if (outstanding >= sizeof(Message))
            {
              Message *peek = reinterpret_cast<Message *>(neuron->rBuffer.pHead());
              peekTopic = peek->topic;
              peekHeader = peek->headerSize;
              peekPadding = peek->padding;
            }
            uint64_t sampleCount = (outstanding < sizeof(sample) ? outstanding : sizeof(sample));
            if (sampleCount > 0)
            {
              memcpy(sample, neuron->rBuffer.pHead(), sampleCount);
            }

            basics_log("brain neuron recv-partial uuid=%llu private4=%u cloudID=%s outstanding=%llu peekSize=%u peekTopic=%u peekHeader=%u peekPadding=%u fd=%d fslot=%d sample=%02x %02x %02x %02x %02x %02x %02x %02x\n",
                       (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                       unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                       (neuron->machine ? neuron->machine->cloudID.c_str() : ""),
                       (unsigned long long)outstanding,
                       unsigned(peekSize),
                       unsigned(peekTopic),
                       unsigned(peekHeader),
                       unsigned(peekPadding),
                       neuron->fd,
                       neuron->fslot,
                       unsigned(sample[0]),
                       unsigned(sample[1]),
                       unsigned(sample[2]),
                       unsigned(sample[3]),
                       unsigned(sample[4]),
                       unsigned(sample[5]),
                       unsigned(sample[6]),
                       unsigned(sample[7]));
          }
        }
#endif

        if (streamIsActive(neuron) && neuron->transportTLSEnabled() && neuron->needsTransportTLSSendKick())
        {
          Ring::queueSend(neuron);
        }
        else if (neuron->wBuffer.size() > 0 && streamIsActive(neuron))
        {
          Ring::queueSend(neuron);
        }

        if (streamIsActive(neuron))
        {
          Ring::queueRecv(neuron);
        }
      }
      else
      {
        basics_log("neuron recv failed stream=%p uuid=%llu private4=%u result=%d isFixed=%d fslot=%d fd=%d connected=%d reconnect=%d pendingSend=%d pendingRecv=%d tlsNegotiated=%d peerVerified=%d queuedBytes=%llu wbytes=%u rbytes=%llu machineState=%d\n",
                   static_cast<void *>(neuron),
                   (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                   unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                   result,
                   int(neuron->isFixedFile),
                   neuron->fslot,
                   neuron->fd,
                   int(neuron->connected),
                   int(neuron->reconnectAfterClose),
                   int(neuron->pendingSend),
                   int(neuron->pendingRecv),
                   int(neuron->isTLSNegotiated()),
                   int(neuron->tlsPeerVerified),
                   (unsigned long long)neuron->queuedSendOutstandingBytes(),
                   uint32_t(neuron->wBuffer.outstandingBytes()),
                   (unsigned long long)neuron->rBuffer.outstandingBytes(),
                   (neuron->machine ? int(neuron->machine->state) : -1));
        queueCloseIfActive(neuron);
        // try to reconnect... then when that fails...
      }
    }
    else if (activeMothership != nullptr)
    {
      if (activeMothership->pendingRecv == false)
      {
        // Ignore stale/duplicate recv completions from prior socket generations.
        return;
      }
      activeMothership->pendingRecv = false;
      PRODIGY_DEBUG_LOG( "prodigy mothership recv-complete result=%d stream=%p fd=%d fslot=%d isFixed=%d rbytes=%zu wbytes=%zu master=%d\n",
                   result,
                   static_cast<void *>(activeMothership),
                   activeMothership->fd,
                   activeMothership->fslot,
                   int(activeMothership->isFixedFile),
                   size_t(activeMothership->rBuffer.size()),
                   size_t(activeMothership->wBuffer.size()),
                   int(weAreMaster));
      PRODIGY_DEBUG_FLUSH();

      if (result > 0)
      {
        if (processMothershipReceivedBytes(activeMothership, result, "io_uring-recv") == false)
        {
          return;
        }

        queueMothershipReceiveIfNeeded(activeMothership, "post-dispatch");
      }
      else
      {
        const bool closeCompletion = (result == -9 || result == -125);
        if (closeCompletion == false)
        {
          basics_log("mothership stream recv closed result=%d weAreMaster=%d\n", result, int(weAreMaster));
        }
        PRODIGY_DEBUG_LOG( "prodigy mothership recv-close result=%d closeCompletion=%d stream=%p fd=%d fslot=%d master=%d\n",
                     result,
                     int(closeCompletion),
                     static_cast<void *>(activeMothership),
                     activeMothership->fd,
                     activeMothership->fslot,
                     int(weAreMaster));
        PRODIGY_DEBUG_FLUSH();
        if (weAreMaster && closeCompletion == false)
        {
          queueMothershipUnixAcceptIfNeeded();
        }
        if (activeMothership->pendingSend == false && activeMothership->pendingRecv == false && activeMothership->wBuffer.outstandingBytes() == 0)
        {
          // Local one-shot commander clients hit EOF immediately after
          // consuming the response. Retire the drained stream into the
          // normal close-completion lifecycle so stale CQEs cannot outlive
          // the object and collide with allocator reuse.
          destroyIdleMothershipStreamNow(activeMothership, "recv-eof-drained");
        }
        else
        {
          queueCloseIfActive(activeMothership);
        }
      }
    }
  }

  template <typename T>
  void sendHandler(T *stream, int result)
  {
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
        basics_log("brain send overflow stream=%p result=%d outstanding=%llu fd=%d fslot=%d\n",
                   stream,
                   result,
                   (unsigned long long)outstanding,
                   stream->fd,
                   stream->fslot);
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

      if (queueAnotherSend)
      {
        if (streamIsActive(stream))
        {
          Ring::queueSend(stream);
        }
        else
        {
          // We still have buffered bytes, but the socket dropped out of active
          // state between submissions/completions. Force close/reconnect so
          // connectHandler can re-register and flush pending bytes.
          queueCloseIfActive(stream);
        }
      }
    }
    else
    {
      stream->noteSendCompleted();
      // Do not carry partial stream bytes across reconnect boundaries.
      // A failed send may leave the buffer starting mid-frame; replaying that
      // tail on a new socket can desynchronize framing and corrupt parsing.
      stream->clearQueuedSendBytes();
      queueCloseIfActive(stream);
    }
  }

  void sendHandler(void *socket, int result) override
  {
    Mothership *activeMothership = activeMothershipFromSocket(socket);
    if (result <= 0 && activeMothership != nullptr && weAreMaster)
    {
      queueMothershipUnixAcceptIfNeeded();
    }

    if (brains.contains(static_cast<BrainView *>(socket)))
    {
      BrainView *brain = static_cast<BrainView *>(socket);
      PRODIGY_DEBUG_LOG(
                   "prodigy debug brain send-result private4=%u result=%d fd=%d fslot=%d pendingSend=%d pendingRecv=%d tls=%d negotiated=%d peerVerified=%d queuedBytes=%llu wbytes=%u\n",
                   brain->private4,
                   result,
                   brain->fd,
                   brain->fslot,
                   int(brain->pendingSend),
                   int(brain->pendingRecv),
                   int(brain->transportTLSEnabled()),
                   int(brain->isTLSNegotiated()),
                   int(brain->tlsPeerVerified),
                   (unsigned long long)brain->queuedSendOutstandingBytes(),
                   uint32_t(brain->wBuffer.outstandingBytes()));
      PRODIGY_DEBUG_FLUSH();
      if (result <= 0)
      {
        basics_log("brain send failed stream=%p private4=%u result=%d isFixed=%d fslot=%d fd=%d updateProdigyState=%u\n",
                   static_cast<void *>(brain), brain->private4, result, int(brain->isFixedFile), brain->fslot, brain->fd, uint32_t(updateSelfState));
      }
      sendHandler(brain, result);
      if (result > 0)
      {
        queueUpdateSelfBundleToPeer(brain);
        queueUpdateSelfTransitionToPeer(brain);
        queueUpdateSelfRelinquishToPeer(brain);
      }
    }
    else if (neurons.contains(static_cast<NeuronView *>(socket)))
    {
      NeuronView *neuron = static_cast<NeuronView *>(socket);
      uint32_t bytesBefore = neuron->wBuffer.size();
      if (result <= 0)
      {
        if (neuron->pendingSend)
        {
          neuron->wBuffer.noteSendCompleted();
        }
        neuron->pendingSend = false;
        neuron->pendingSendBytes = 0;
        // Failed send completions can leave a partial frame at head.
        // Drop buffered bytes before reconnect so framing stays valid.
        neuron->wBuffer.clear();
        basics_log("neuron send failed private4=%u result=%d isFixed=%d fslot=%d fd=%d machineState=%d wbytes=%u\n",
                   (neuron->machine ? neuron->machine->private4 : 0u),
                   result,
                   int(neuron->isFixedFile),
                   neuron->fslot,
                   neuron->fd,
                   (neuron->machine ? int(neuron->machine->state) : -1),
                   unsigned(bytesBefore));
        queueCloseIfActive(neuron);
        return;
      }
      sendHandler(neuron, result);
      basics_log("neuron send complete private4=%u result=%d bytesBefore=%u bytesAfter=%u active=%d pendingSend=%d\n",
                 (neuron->machine ? neuron->machine->private4 : 0u),
                 result,
                 unsigned(bytesBefore),
                 unsigned(neuron->wBuffer.size()),
                 int(streamIsActive(neuron)),
                 int(neuron->pendingSend));
    }
    else if (activeMothership != nullptr)
    {
      size_t bytesBefore = size_t(activeMothership->wBuffer.size());
      uint32_t submittedBytes = activeMothership->pendingSendBytes;
      bool pendingSendBefore = activeMothership->pendingSend;
      sendHandler(activeMothership, result);
      bool updateAckDrained = updateSelfTransitionAfterMothershipAck && result > 0 && activeMothership->pendingSend == false && activeMothership->wBuffer.outstandingBytes() == 0;
      PRODIGY_DEBUG_LOG( "prodigy mothership send-complete result=%d submittedBytes=%u bytesBefore=%zu bytesAfter=%zu stream=%p fixedFD=%d fslot=%d active=%d pendingSendBefore=%d pendingSendAfter=%d pendingSendBytesAfter=%u\n",
                   result,
                   unsigned(submittedBytes),
                   bytesBefore,
                   size_t(activeMothership->wBuffer.size()),
                   static_cast<void *>(activeMothership),
                   loggableSocketFD(activeMothership),
                   activeMothership->fslot,
                   int(streamIsActive(activeMothership)),
                   int(pendingSendBefore),
                   int(activeMothership->pendingSend),
                   unsigned(activeMothership->pendingSendBytes));
      PRODIGY_DEBUG_FLUSH();
      if (updateAckDrained)
      {
        transitionLocalUpdateToNewBundle();
        return;
      }
      if (updateSelfTransitionAfterMothershipAck && result <= 0)
      {
        basics_log("updateProdigy aborting local transition because mothership ack send failed result=%d\n", result);
        updateSelfTransitionAfterMothershipAck = false;
        resetUpdateSelfState();
        noteMasterAuthorityRuntimeStateChanged();
      }
      closeMothershipAfterSendDrainIfNeeded(activeMothership, "send-complete-drained");
      if (Ring::socketIsClosing(activeMothership) && activeMothership->pendingSend == false && activeMothership->wBuffer.outstandingBytes() == 0)
      {
        retireClosingMothershipStreamIfNeeded(activeMothership, "send-complete-drained");
      }
    }
  }

  void handleMachineStateChange(Machine *machine, MachineState newState)
  {
    if (machine == nullptr)
    {
      co_return;
    }

    if (machines.contains(machine) == false)
    {
      co_return;
    }

    // it's possible to fail through multiple pathways, but we atomize the states enough that if the state
    // is already equal to the new desired state, the action is already being taken
    if (newState == machine->state)
    {
      co_return;
    }

    MachineState oldState = machine->state;
    basics_log("machine state change uuid=%llu private4=%u cloudID=%s old=%u new=%u isBrain=%d creationTimeMs=%lld lastUpdatedOSMs=%lld\n",
               (unsigned long long)machine->uuid,
               unsigned(machine->private4),
               machine->cloudID.c_str(),
               unsigned(oldState),
               unsigned(newState),
               int(machine->isBrain),
               (long long)machine->creationTimeMs,
               (long long)machine->lastUpdatedOSMs);
    machine->state = newState;

    switch (newState)
    {
      case MachineState::healthy:
        {
          // clear transient flags and counters when returning to healthy
          machine->inBinaryUpdate = false;
          machine->neuronConnectFailStreak = 0;
          machine->brainConnectFailStreak = 0;
          cancelMachineSoftWatchdog(machine);
          cancelMachineHardRebootWatchdog(machine);
          cancelOSUpdateCommandWatchdog(machine);

          resumeMachineClaimsIfSchedulingReady(machine);

          switch (oldState)
          {
            case MachineState::deploying:
              {
                if (machine->lifetime == MachineLifetime::reserved || machine->lifetime == MachineLifetime::owned)
                {
                  Vector<Machine *> donorMachines;

                  for (Machine *machine : machines) // gather so we can sort
                  {
                    if (machine->state != MachineState::healthy)
                    {
                      continue;
                    }

                    if (machine->lifetime == MachineLifetime::ondemand)
                    {
                      donorMachines.push_back(machine);
                    }
                  }

                  // sort by most available cores first... aka least busy
                  sorter(donorMachines, [&](const Machine *machine) -> int64_t {
                    return machine->nLogicalCores_available;
                  });

                  for (Machine *donor : donorMachines)
                  {
                    for (auto& [deploymentID, containersOfDeployment] : donor->containersByDeploymentID)
                    {
                      auto deploymentIt = deployments.find(deploymentID);
                      if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
                      {
                        continue;
                      }

                      ApplicationDeployment *deployment = deploymentIt->second;
                      DeploymentPlan& plan = deployment->plan;

                      uint32_t budget = containersOfDeployment.size(); // optimistically move them all

                      // stateful budget (which is only rack budget) considered later
                      if (plan.isStateful == false)
                      {
                        budget = ApplicationDeployment::clampBudgetByRackAndMachine(deployment, machine, budget);
                      }

                      if (uint32_t nFit = ApplicationDeployment::nFitOnMachine(deployment, machine, budget); nFit > 0)
                      {
                        for (auto it = containersOfDeployment.begin(); it != containersOfDeployment.end() && nFit > 0;)
                        {
                          ContainerView *container = *it;

                          switch (container->state)
                          {
                            case ContainerState::planned:
                              {
                                if (donor->rack != machine->rack)
                                {
                                  if (plan.isStateful)
                                  {
                                    if (deployment->racksByShardGroup[container->shardGroup].contains(machine->rack))
                                    {
                                      break;
                                    }

                                    deployment->racksByShardGroup[container->shardGroup].erase(donor->rack);
                                    deployment->racksByShardGroup[container->shardGroup].insert(machine->rack);
                                  }

                                  deployment->countPerRack[donor->rack] -= 1;
                                  deployment->countPerRack[machine->rack] += 1;
                                }

                                nFit -= 1;

                                prodigyDebitMachineScalarResources(machine, plan.config, 1);

                                deployment->countPerMachine[donor] -= 1;
                                deployment->countPerMachine[machine] += 1;

                                if (container->state == ContainerState::planned)
                                {
                                  prodigyCreditMachineScalarResources(donor, plan.config, 1);

                                  WorkBase *work = container->plannedWork->getBase();
                                  donor->removeContainerIndexEntry(container->deploymentID, container);

                                  work->machine = machine;
                                  work->container->machine = machine;
                                  machine->upsertContainerIndexEntry(container->deploymentID, container);

                                  if (work->lifecycle == LifecycleOp::updateInPlace)
                                  {
                                    work->lifecycle = LifecycleOp::construct;
                                    std::get_if<StatefulWork>(container->plannedWork)->data = DataStrategy::seeding;

                                    deployment->toSchedule.erase(container->plannedWork);

                                    DeploymentWork *dwork = deployment->planStatefulDestruction(work->oldContainer);

                                    work->oldContainer = nullptr;

                                    deployment->scheduleConstructionDestruction(container->plannedWork, dwork);
                                  }

                                  // delete us from containersByDeploymentID
                                  it = containersOfDeployment.erase(it);
                                  continue;
                                }
                                else
                                {
                                  container->state = ContainerState::aboutToDestroy;
                                  deployment->handleContainerStateChange(container, true);

                                  if (plan.isStateful)
                                  {
                                    DeploymentWork *dwork = deployment->planStatefulDestruction(container);
                                    DeploymentWork *cwork = deployment->planStatefulConstruction(machine, container->shardGroup, DataStrategy::seeding);

                                    deployment->scheduleConstructionDestruction(cwork, dwork);
                                  }
                                  else
                                  {
                                    DeploymentWork *dwork = deployment->planStatelessDestruction(container);
                                    DeploymentWork *cwork = deployment->planStatelessConstruction(machine, container->lifetime);

                                    deployment->scheduleConstructionDestruction(cwork, dwork);
                                  }
                                }

                                break;
                              }
                            case ContainerState::scheduled:
                            case ContainerState::crashedRestarting:
                            case ContainerState::healthy:
                              {
                                bool skipLiveMove = false;
                                if (plan.isStateful)
                                {
                                  skipLiveMove = (container->state != ContainerState::healthy);
                                }
                                else
                                {
                                  skipLiveMove =
                                      (deployment->statelessCompactionDonorIsQuiescent() == false) || (ApplicationDeployment::statelessCompactionContainerIsEligible(container) == false);
                                }

                                if (skipLiveMove)
                                {
                                  basics_log(
                                      "machine healthy donor-skip deploymentID=%llu appID=%u uuid=%llu state=%u donorPrivate4=%u targetPrivate4=%u deploymentState=%u waiting=%llu toSchedule=%llu\n",
                                      (unsigned long long)deployment->plan.config.deploymentID(),
                                      unsigned(deployment->plan.config.applicationID),
                                      (unsigned long long)container->uuid,
                                      unsigned(container->state),
                                      unsigned(donor->private4),
                                      unsigned(machine->private4),
                                      unsigned(deployment->state),
                                      (unsigned long long)deployment->waitingOnContainers.size(),
                                      (unsigned long long)deployment->toSchedule.size());
                                  break;
                                }

                                if (donor->rack != machine->rack)
                                {
                                  if (plan.isStateful)
                                  {
                                    if (deployment->racksByShardGroup[container->shardGroup].contains(machine->rack))
                                    {
                                      break;
                                    }

                                    deployment->racksByShardGroup[container->shardGroup].erase(donor->rack);
                                    deployment->racksByShardGroup[container->shardGroup].insert(machine->rack);
                                  }

                                  deployment->countPerRack[donor->rack] -= 1;
                                  deployment->countPerRack[machine->rack] += 1;
                                }

                                nFit -= 1;

                                prodigyDebitMachineScalarResources(machine, plan.config, 1);

                                deployment->countPerMachine[donor] -= 1;
                                deployment->countPerMachine[machine] += 1;
                                container->state = ContainerState::aboutToDestroy;
                                deployment->handleContainerStateChange(container, true);

                                if (plan.isStateful)
                                {
                                  DeploymentWork *dwork = deployment->planStatefulDestruction(container);
                                  DeploymentWork *cwork = deployment->planStatefulConstruction(machine, container->shardGroup, DataStrategy::seeding);

                                  deployment->scheduleConstructionDestruction(cwork, dwork);
                                }
                                else
                                {
                                  DeploymentWork *dwork = deployment->planStatelessDestruction(container);
                                  DeploymentWork *cwork = deployment->planStatelessConstruction(machine, container->lifetime);

                                  deployment->scheduleConstructionDestruction(cwork, dwork);
                                }

                                break;
                              }
                            case ContainerState::aboutToDestroy: // destruction already planned
                            case ContainerState::destroying: // destruction already scheduled
                            case ContainerState::destroyed: // not possible here
                            case ContainerState::none:
                              {
                                break;
                              }

                              it++;
                          }
                        }
                      }
                    }

                    // deployments will schedule containers onto on-demand and reserved with the same affinity... so it's possible
                    // even if we move all containers off an on-demand machine, that by the time all the containers have been destroyed
                    // that some other deployment has scheduled a container onto it... and thus it's not empty... and thus we can't destroy it

                    // if we marked a machine as don't schedule to this... it's possible we need that capacity and then we'd end up scheduling
                    // another on-demand... that works though but only if we fully unschedule it

                    bool containersDrained = true;

                    for (const auto& [deploymentID, containers] : donor->containersByDeploymentID)
                    {
                      for (ContainerView *container : containers)
                      {
                        switch (container->state)
                        {
                          case ContainerState::scheduled:
                          case ContainerState::crashedRestarting:
                          case ContainerState::healthy:
                            {
                              containersDrained = false;
                              goto jumpout;
                            }
                          default:
                            break;
                        }
                      }
                    }
                  jumpout:

                    // nothing else will be scheduled to this machine now... and it will be decomissioned once the final container is destroyed off
                    if (containersDrained)
                    {
                      handleMachineStateChange(donor, MachineState::decommissioning);
                    }
                  }
                }

                break;
              }
            case MachineState::updatingOS:
              {
                // Returned healthy after an OS update.
                onDrainCompleteForOSUpdate(machine);
                armMachineUpdateTimerIfNeeded();
                break;
              }
            case MachineState::hardRebooting:
              {
                if (machine->osUpdateCommandIssued)
                {
                  onDrainCompleteForOSUpdate(machine);
                  armMachineUpdateTimerIfNeeded();
                }
                break;
              }
            default:
              break;
          }

          if (isActiveMaster())
          {
            for (const auto& [applicationID, head] : deploymentsByApp)
            {
              (void)applicationID;
              if (head && !head->plan.isStateful)
              {
                head->recoverAfterReboot();
              }
            }
          }

          break;
        }
      case MachineState::missing:
        {
          // by the time we get here, we could've already progressed past this stage and be on SSH or hard rebooting or even reported it failed..
          // so check that state first, then return if

          bool handledExpectedOSUpdateReboot = false;
          switch (oldState)
          {
            case MachineState::deploying:
              {
                // we just created a machine but the neuron never came alive

                break;
              }
            case MachineState::neuronRebooting:
              {
                // should only take microseconds(?) for the neuron to become available again
                // if a brain, maybe 100ms for the brain socket to been accepting (after the neuron gathers its metadata and sees it's a brain)
                // then, if a brain and it connects to us, maybe another 100ms until it gathers all machines and connects to us
                // so either way this should always be captured witin the 750ms reconnect time

                // so not sure what we'd do in this situation though... might require manual intervention
                break;
              }
            case MachineState::healthy:
              {
                // it was healthy, now it's vanished

                break;
              }
            case MachineState::updatingOS:
              {
                basics_log("machine os update reboot wait uuid=%llu private4=%u watchdogMs=%u reconnectWindowMs=%u\n",
                           (unsigned long long)machine->uuid,
                           unsigned(machine->private4),
                           unsigned(prodigyBrainOSUpdateRebootWatchdogMs),
                           unsigned(prodigyBrainOSUpdateReconnectWindowMs));
                cancelOSUpdateCommandWatchdog(machine);
                machine->state = MachineState::hardRebooting;
                machine->lastHardRebootMs = Time::now<TimeResolution::ms>();
                cancelMachineSoftWatchdog(machine);
                cancelMachineHardRebootWatchdog(machine);

                if (isActiveMaster())
                {
                  armMachineNeuronReconnect(machine, prodigyBrainOSUpdateReconnectWindowMs);
                }

                if (machine->brain)
                {
                  armOutboundPeerReconnect(machine->brain);
                }

                TimeoutPacket *timeout = new TimeoutPacket();
                timeout->flags = uint64_t(BrainTimeoutFlags::hardRebootedMachine);
                timeout->identifier = machine->uuid;
                timeout->originator = machine;
                timeout->dispatcher = this;
                timeout->setTimeoutMs(prodigyBrainOSUpdateRebootWatchdogMs);
                RingDispatcher::installMultiplexee(timeout, this);
                Ring::queueTimeout(timeout);
                machine->hardRebootWatchdog = timeout;
                handledExpectedOSUpdateReboot = true;
                break;
              }
            default:
              break;
          }

          if (handledExpectedOSUpdateReboot)
          {
            break;
          }

          // If we transitioned here during a binary update, give it space (state will be neuronRebooting)
          if (machine->inBinaryUpdate)
          {
            machine->state = MachineState::neuronRebooting;
            break;
          }

          // Missing host should release placement immediately so stateless/service
          // workloads can move without waiting for remediation escalation timeouts.
          evacuateFailedMachineContainers(machine);

          // even if the machine responded to pings, our next action would be to try
          // to SSH in and restart the neuron so there's no point of pinging, the SSH
          // TCP connection serves the same purpose, and has 0 risk of packets being dropped.

          // Budget: try SSH restart up to 2 times, then escalate to unresponsive
          if (machine->sshRestartAttempts >= 2)
          {
            machine->state = MachineState::unresponsive; // medium escalation
            co_return;
          }

          MachineSSH *ssh = new MachineSSH();
          sshs.insert(ssh);
          ssh->machine = machine;
          ssh->bootstrapSshKeyPackage = &brainConfig.bootstrapSshKeyPackage;
          ssh->bootstrapSshPrivateKeyPath = &brainConfig.bootstrapSshPrivateKeyPath;
          RingDispatcher::installMultiplexee(ssh, this);

          // isn't the point just to see if we can connect to SSH... and then if we can restart the neuron?
          // i guess this collapses both functions into one

          // as long as we can garauntee none of the captured context can be destroyed before
          // this lambda fires, then we're fine
          IPAddress sshAddress = {};
          uint16_t sshPort = 0;
          if (prodigyResolveMachineSSHSocketAddress(*machine, sshAddress, sshPort) == false)
          {
            sshs.erase(ssh);
            delete ssh;
            co_return;
          }

          ssh->setIPVersion(sshAddress.is6 ? AF_INET6 : AF_INET);
          ssh->setDatacenterCongestion();
          ssh->setDaddr(sshAddress, sshPort);
          ssh->machine = machine;

          bool isDevMode = BrainBase::controlPlaneDevModeEnabled();
          ssh->connectTimeoutMs = BrainBase::controlPlaneConnectTimeoutMs(isDevMode);
          ssh->nDefaultAttemptsBudget = BrainBase::controlPlaneConnectAttemptsBudget(isDevMode);
          uint32_t sshConnectAttemptTimeMs = BrainBase::machineInitialConnectAttemptTimeMs(
              machine->creationTimeMs,
              ssh->connectTimeoutMs,
              ssh->nDefaultAttemptsBudget);
          ssh->attemptForMs(sshConnectAttemptTimeMs);

          // technically it's possible that the network randomly broke then healed, so SSH succeeded.. then we restarted the neuron for no reason... but that'll never happen

          uint128_t sshMachineUUID = machine->uuid;
          ssh->registerAction(SSHAction::restartProdigy, [this, ssh, sshMachineUUID](void) -> void {
            Machine *targetMachine = nullptr;
            if (auto machineIt = machinesByUUID.find(sshMachineUUID); machineIt != machinesByUUID.end())
            {
              targetMachine = machineIt->second;
            }

            // if the TCP connection succeded, every stage of restartProdigy will succeed
            // and then we'll be here
            // but if the TCP connection failed, then not
            // but if the SSH TCP connection failed, then we'd go straight to machine missing

            if (targetMachine && isActiveMaster())
            {
              armMachineNeuronReconnect(targetMachine, BrainBase::machineInitialConnectAttemptTimeMs(
                                                           targetMachine->creationTimeMs,
                                                           targetMachine->neuron.connectTimeoutMs,
                                                           targetMachine->neuron.nDefaultAttemptsBudget));
            }

            if (targetMachine && targetMachine->brain)
            {
              armOutboundPeerReconnect(targetMachine->brain);
            }

            ssh->reconnectAfterClose = false;
            Ring::queueClose(ssh);
          });

          machine->sshRestartAttempts += 1;
          machine->lastSshAttemptMs = Time::now<TimeResolution::ms>();
          ssh->attemptConnect();

          // Arm a short watchdog to escalate if the SSH restart does not restore health
          cancelMachineSoftWatchdog(machine);
          machine->softWatchdog = new TimeoutPacket();
          machine->softWatchdog->flags = uint64_t(BrainTimeoutFlags::softEscalationCheck);
          machine->softWatchdog->identifier = machine->uuid;
          machine->softWatchdog->originator = machine;
          machine->softWatchdog->dispatcher = this;
          // Freshly bootstrapped machines can legitimately take much longer than 1s
          // before neuron/brain control sockets accept. Keep the SSH-restart escalation
          // path creation-aware so a brand-new machine is not hard-rebooted immediately.
          uint32_t softEscalationTimeoutMs = BrainBase::machineBootstrapSoftEscalationTimeoutMs(
              machine->creationTimeMs,
              machine->neuron.connectTimeoutMs,
              machine->neuron.nDefaultAttemptsBudget);
          machine->softWatchdog->setTimeoutMs(softEscalationTimeoutMs);
          basics_log("machine missing remediation uuid=%llu private4=%u sshWindowMs=%u softTimeoutMs=%u creationTimeMs=%lld sshRestartAttempts=%u\n",
                     (unsigned long long)machine->uuid,
                     unsigned(machine->private4),
                     sshConnectAttemptTimeMs,
                     softEscalationTimeoutMs,
                     (long long)machine->creationTimeMs,
                     unsigned(machine->sshRestartAttempts));
          RingDispatcher::installMultiplexee(machine->softWatchdog, this);
          Ring::queueTimeout(machine->softWatchdog);

          break;
        }
      case MachineState::unresponsive:
        {
          // SSH was unable to connect; escalate to IaaS hard reboot.
          basics_log("machine hard reboot escalation uuid=%llu private4=%u hardRebootAttempts=%u creationTimeMs=%lld\n",
                     (unsigned long long)machine->uuid,
                     unsigned(machine->private4),
                     unsigned(machine->hardRebootAttempts + 1),
                     (long long)machine->creationTimeMs);
          (void)queueMachineHardReboot(machine);

          break;
        }
      case MachineState::hardRebooting:
        {

          break;
        }
      case MachineState::hardwareFailure:
        {
          break;
        }
      case MachineState::decommissioning:
        {
          // once the final container has been destroyed, transition into actual destruction of the machine

          break;
        }
      case MachineState::updatingOS:
        {
          // definitely share this, especially so they know the last time it was updated
          // or we'd share the state then after share the timestamp and new kernel version
          break;
        }
      // never shared as updates
      case MachineState::neuronRebooting: // no reason to share this
      case MachineState::unknown: // this is the base state of a machine more than 7 minutes old
      default:
        break;
    }
  }

  virtual void transitionToNewBundle(void)
  {
    // should we serialize and save all the container data?
    String failure = {};
    String stagedBundlePath = prodigyStagedBundlePath();
    if (prodigyInstallBundleToRoot(stagedBundlePath, "/root/prodigy"_ctv, &failure) == false)
    {
      basics_log("transitionToNewBundle install failed: %s\n", failure.c_str());
      _exit(EXIT_FAILURE);
    }

    ProdigyInstallRootPaths installPaths = {};
    prodigyBuildInstallRootPaths("/root/prodigy"_ctv, installPaths);
    String libraryDirectoryText = {};
    libraryDirectoryText.assign(installPaths.libraryDirectory);
    (void)setenv("LD_LIBRARY_PATH", libraryDirectoryText.c_str(), 1);
    String prepareFailure = {};
    if (prepareForBundleExec(prepareFailure) == false)
    {
      basics_log("transitionToNewBundle prepare failed: %s\n", prepareFailure.c_str());
      _exit(EXIT_FAILURE);
    }
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

    String binaryPathText = {};
    binaryPathText.assign(installPaths.binaryPath);
    Vector<char *> argv = {};
    if (buildLaunchArgumentsForExec(binaryPathText, argv))
    {
      execv(binaryPathText.c_str(), argv.data());
    }

    execl(binaryPathText.c_str(), binaryPathText.c_str(), (char *)NULL);
    _exit(EXIT_FAILURE);
  }

  void transitionLocalUpdateToNewBundle(void)
  {
    updateSelfTransitionAfterMothershipAck = false;
    boottimens = Time::now<TimeResolution::ns>();
    forfeitMasterStatus();
    resetUpdateSelfState();
    noteMasterAuthorityRuntimeStateChanged();
    transitionToNewBundle();
  }

  void resetUpdateSelfState(bool clearBundleBlob = true)
  {
    updateSelfState = UpdateSelfState::idle;
    updateSelfExpectedEchos = 0;
    updateSelfBundleEchos = 0;
    updateSelfRelinquishEchos = 0;
    updateSelfPlannedMasterPeerKey = 0;
    updateSelfUseStagedBundleOnly = false;
    if (clearBundleBlob)
    {
      updateSelfBundleBlob.clear();
    }
    updateSelfBundleIssuedPeerKeys.clear();
    updateSelfBundleEchoPeerKeys.clear();
    updateSelfRelinquishEchoPeerKeys.clear();
    updateSelfFollowerBootNsByPeerKey.clear();
    updateSelfFollowerReconnectedPeerKeys.clear();
    updateSelfFollowerRebootedPeerKeys.clear();
    updateSelfTransitionIssuedPeerKeys.clear();
    updateSelfRelinquishIssuedPeerKeys.clear();
  }

  bool devSharedStagedBundleEnabled(void) const
  {
    if (const char *sharedStageEnv = getenv("PRODIGY_DEV_SHARED_STAGE_BUNDLE");
        sharedStageEnv && sharedStageEnv[0] == '1' && sharedStageEnv[1] == '\0')
    {
      return true;
    }

    return false;
  }

  bool peerSocketActive(BrainView *bv)
  {
    if (bv == nullptr)
    {
      return false;
    }
    if (bv->connected == false)
    {
      return false;
    }
    if (Ring::socketIsClosing(bv))
    {
      return false;
    }
    if (bv->isFixedFile == false)
    {
      // fd/fslot are a union; negative slot means no active descriptor.
      if (bv->fslot < 0)
      {
        return false;
      }

      basics_log("peerSocketActive expected fixed-file peer=%p private4=%u fd=%d fslot=%d\n",
                 bv, bv->private4, bv->fd, bv->fslot);
      std::abort();
    }
    return (bv->fslot >= 0);
  }

  bool hasConnectedBrainMajority(void)
  {
    uint32_t connectedBrains = 1; // include self
    for (BrainView *peer : brains)
    {
      if (peerEligibleForClusterQuorum(peer) == false)
      {
        continue;
      }
      if (peerSocketActive(peer) == false)
      {
        continue;
      }
      connectedBrains += 1;
    }

    return (connectedBrains > (nBrains / 2));
  }

  bool shouldRetainMasterControlOnBrainLoss(void)
  {
    return hasConnectedBrainMajority();
  }

  void armOutboundPeerReconnect(BrainView *bv, bool forceConnectorOwnership = false)
  {
    if (bv == nullptr)
    {
      return;
    }
    if (bv->weConnectToIt == false && forceConnectorOwnership == false)
    {
      return;
    }
    if (forceConnectorOwnership)
    {
      bv->forceConnectorOwnershipUntilMasterAck = true;
    }
    cancelBrainMissingWaiter(bv, forceConnectorOwnership ? "arm-outbound-force" : "arm-outbound");
    const uint32_t preservedAttemptsBudget = bv->nAttemptsBudget;
    const int64_t preservedAttemptDeadlineMs = bv->attemptDeadlineMs;
    const bool preserveReconnectPolicy = (preservedAttemptsBudget > 0 || preservedAttemptDeadlineMs > 0);
    const bool hadActivePeerSocket = peerSocketActive(bv);
    const bool hadRawActiveStream = rawStreamIsActive(bv);
    bv->connected = false;
    bv->nConnectionAttempts = 0;
    bv->reconnectAfterClose = true;

    bool reconnectArmedByClose = Ring::socketIsClosing(bv);
    if (reconnectArmedByClose == false && hadActivePeerSocket)
    {
      queueBrainCloseIfActive(bv, forceConnectorOwnership ? "arm-outbound-force" : "arm-outbound");
      reconnectArmedByClose = Ring::socketIsClosing(bv);
    }

    const bool shouldGracefullyCloseLiveRawTransport = (reconnectArmedByClose == false && hadRawActiveStream && (bv->currentStreamAccepted || bv->tlsPeerVerified || bv->isTLSNegotiated() || bv->registrationFresh || bv->pendingSend || bv->pendingRecv));
    if (shouldGracefullyCloseLiveRawTransport)
    {
      queueBrainCloseIfActive(bv, forceConnectorOwnership ? "arm-outbound-force" : "arm-outbound");
      reconnectArmedByClose = Ring::socketIsClosing(bv);
    }

    if (reconnectArmedByClose == false && hadRawActiveStream)
    {
      PRODIGY_DEBUG_LOG(
                   "prodigy debug brain reconnect-abandon private4=%u reason=%s accepted=%d connected=%d quarantined=%d fd=%d fslot=%d\n",
                   bv->private4,
                   (forceConnectorOwnership ? "arm-outbound-force" : "arm-outbound"),
                   int(bv->currentStreamAccepted),
                   int(bv->connected),
                   int(bv->quarantined),
                   bv->fd,
                   bv->fslot);
      PRODIGY_DEBUG_FLUSH();
      abandonSocketGeneration(bv);
    }

    if (preserveReconnectPolicy)
    {
      bv->nAttemptsBudget = preservedAttemptsBudget;
      bv->attemptDeadlineMs = preservedAttemptDeadlineMs;
    }
    else
    {
      bv->nAttemptsBudget = 0;
      bv->attemptDeadlineMs = 0;
    }

    if (reconnectArmedByClose == false)
    {
      bv->currentStreamAccepted = false;
      bv->recreateSocket();
      configureBrainPeerConnectAddress(bv);
      if (installBrainPeerSocket(bv))
      {
        bv->attemptConnect();
      }
    }
  }

  void armMachineNeuronReconnect(Machine *machine, int64_t reconnectWindowMs)
  {
    if (machine == nullptr)
    {
      return;
    }

    NeuronView *neuron = &machine->neuron;
    neuron->nConnectionAttempts = 0;
    neuron->reconnectAfterClose = true;
    neuron->attemptForMs(reconnectWindowMs);

    bool reconnectArmedByClose = Ring::socketIsClosing(neuron);
    if (reconnectArmedByClose == false)
    {
      if (neuronControlSocketArmed(machine))
      {
        queueCloseIfActive(neuron);
        reconnectArmedByClose = Ring::socketIsClosing(neuron);
      }
    }

    if (reconnectArmedByClose == false)
    {
      neuron->recreateSocket();
      if (installNeuronControlSocket(neuron))
      {
        neuron->attemptConnect();
      }
    }
  }

  void queueUpdateSelfBundleToPeer(BrainView *bv)
  {
    if (updateSelfState != UpdateSelfState::waitingForBundleEchos)
    {
      return;
    }
    if (bv == nullptr)
    {
      return;
    }
    if (updateSelfUseStagedBundleOnly == false && updateSelfBundleBlob.size() == 0)
    {
      return;
    }
    uint128_t peerKey = updateSelfPeerTrackingKey(bv);
    if (peerKey != 0 && updateSelfBundleEchoPeerKeys.contains(peerKey))
    {
      return;
    }
    if (peerKey != 0 && updateSelfBundleIssuedPeerKeys.contains(peerKey))
    {
      return;
    }
    if (bv->pendingSend)
    {
      return;
    }
    if (peerSocketActive(bv) == false)
    {
      PRODIGY_DEBUG_LOG(
                   "prodigy updateProdigy bundle-peer-unavailable private4=%u quarantined=%d isFixed=%d fslot=%d fd=%d\n",
                   bv->private4, int(bv->quarantined), int(bv->isFixedFile), bv->fslot, bv->fd);
      PRODIGY_DEBUG_FLUSH();
      if (bv->weConnectToIt)
      {
        armOutboundPeerReconnect(bv);
      }
      return;
    }

    if (updateSelfUseStagedBundleOnly)
    {
      // Explicit dev fast path: brains share one writable /root staging area, so
      // /root/prodigy.bundle.new.tar.zst is already staged locally on every brain process.
      Message::construct(bv->wBuffer, BrainTopic::updateBundle, "__staged__"_ctv);
      PRODIGY_DEBUG_LOG( "prodigy updateProdigy bundle-staged-send private4=%u\n", bv->private4);
      PRODIGY_DEBUG_FLUSH();
    }
    else
    {
      const uint64_t bundleSendHeadroom = 256_KB;
      // Large updateProdigy payloads can exceed the normal peer keepalive/user-timeout window.
      queueBrainPeerLargePayloadKeepalive(bv);
      bv->wBuffer.reserve(bv->wBuffer.size() + updateSelfBundleBlob.size() + bundleSendHeadroom);
      Message::construct(bv->wBuffer, BrainTopic::updateBundle, updateSelfBundleBlob);
      PRODIGY_DEBUG_LOG( "prodigy updateProdigy bundle-send private4=%u bytes=%u\n", bv->private4, uint32_t(updateSelfBundleBlob.size()));
      PRODIGY_DEBUG_FLUSH();
    }
    if (peerKey != 0)
    {
      updateSelfBundleIssuedPeerKeys.insert(peerKey);
    }
    Ring::queueSend(bv);
  }

  void queueUpdateSelfBundleToPendingPeers(void)
  {
    if (updateSelfState != UpdateSelfState::waitingForBundleEchos)
    {
      return;
    }

    for (BrainView *bv : brains)
    {
      queueUpdateSelfBundleToPeer(bv);
    }
  }

  bool updateSelfPeerStreamDrained(BrainView *bv)
  {
    if (bv == nullptr)
    {
      return false;
    }
    if (peerSocketActive(bv) == false)
    {
      return false;
    }
    return (bv->pendingSend == false);
  }

  void queueUpdateSelfTransitionToPeer(BrainView *bv)
  {
    if (updateSelfState != UpdateSelfState::waitingForFollowerReboots)
    {
      return;
    }
    if (bv == nullptr)
    {
      return;
    }

    uint128_t peerKey = updateSelfPeerTrackingKey(bv);
    if (peerKey == 0)
    {
      return;
    }
    if (updateSelfFollowerBootNsByPeerKey.contains(peerKey) == false)
    {
      return;
    }
    if (updateSelfFollowerRebootedPeerKeys.contains(peerKey))
    {
      return;
    }
    if (updateSelfTransitionIssuedPeerKeys.contains(peerKey))
    {
      return;
    }
    if (updateSelfPeerStreamDrained(bv) == false)
    {
      return;
    }

    updateSelfTransitionIssuedPeerKeys.insert(peerKey);
    PRODIGY_DEBUG_LOG( "prodigy updateProdigy follower-transition-send private4=%u peerKey=%llu\n",
                 bv->private4,
                 (unsigned long long)peerKey);
    PRODIGY_DEBUG_FLUSH();
    PRODIGY_DEBUG_LOG(
                 "prodigy updateProdigy follower-transition-construct private4=%u peerKey=%llu pendingSend=%d wbytes=%u tls=%d negotiated=%d\n",
                 bv->private4,
                 (unsigned long long)peerKey,
                 int(bv->pendingSend),
                 uint32_t(bv->wBuffer.outstandingBytes()),
                 int(bv->transportTLSEnabled()),
                 int(bv->isTLSNegotiated()));
    PRODIGY_DEBUG_FLUSH();
    Message::construct(bv->wBuffer, BrainTopic::transitionToNewBundle, uint8_t(1));
    PRODIGY_DEBUG_LOG(
                 "prodigy updateProdigy follower-transition-queued-message private4=%u peerKey=%llu wbytes=%u\n",
                 bv->private4,
                 (unsigned long long)peerKey,
                 uint32_t(bv->wBuffer.outstandingBytes()));
    PRODIGY_DEBUG_FLUSH();
    Ring::queueSend(bv);
    PRODIGY_DEBUG_LOG(
                 "prodigy updateProdigy follower-transition-queue-send private4=%u peerKey=%llu pendingSend=%d queuedBytes=%llu\n",
                 bv->private4,
                 (unsigned long long)peerKey,
                 int(bv->pendingSend),
                 (unsigned long long)bv->queuedSendOutstandingBytes());
    PRODIGY_DEBUG_FLUSH();
  }

  void queueUpdateSelfRelinquishToPeer(BrainView *bv)
  {
    if (updateSelfState != UpdateSelfState::waitingForRelinquishEchos)
    {
      return;
    }
    if (bv == nullptr)
    {
      return;
    }

    uint128_t peerKey = updateSelfPeerTrackingKey(bv);
    if (peerKey == 0)
    {
      return;
    }
    if (updateSelfFollowerRebootedPeerKeys.contains(peerKey) == false)
    {
      return;
    }
    if (updateSelfRelinquishEchoPeerKeys.contains(peerKey))
    {
      return;
    }
    if (updateSelfRelinquishIssuedPeerKeys.contains(peerKey))
    {
      return;
    }
    if (updateSelfPeerStreamDrained(bv) == false)
    {
      return;
    }

    updateSelfRelinquishIssuedPeerKeys.insert(peerKey);
    Message::construct(bv->wBuffer, BrainTopic::relinquishMasterStatus, uint8_t(1), updateSelfPlannedMasterPeerKey);
    Ring::queueSend(bv);
  }

  void beginUpdateSelfBundle(uint32_t expectedPeerEchos)
  {
    bool useStagedBundleOnly = updateSelfUseStagedBundleOnly;
    resetUpdateSelfState(false);
    updateSelfUseStagedBundleOnly = useStagedBundleOnly;
    // We're collecting echos from other brains that they received and saved the new bundle.
    updateSelfState = UpdateSelfState::waitingForBundleEchos;
    updateSelfExpectedEchos = expectedPeerEchos;

    PRODIGY_DEBUG_LOG(
                 "prodigy updateProdigy begin expectedPeerEchos=%u stagedOnly=%d bundleBytes=%zu nowMs=%lld\n",
                 expectedPeerEchos,
                 int(updateSelfUseStagedBundleOnly),
                 size_t(updateSelfBundleBlob.size()),
                 (long long)Time::now<TimeResolution::ms>());
    PRODIGY_DEBUG_FLUSH();
    noteMasterAuthorityRuntimeStateChanged();

    if (expectedPeerEchos == 0)
    {
      if (updateSelfTransitionAfterMothershipAck)
      {
        return;
      }
      transitionLocalUpdateToNewBundle();
      return;
    }

    queueUpdateSelfBundleToPendingPeers();
  }

  void maybeRelinquishMasterForUpdateSelf(void)
  {
    if (updateSelfState != UpdateSelfState::waitingForFollowerReboots)
    {
      return;
    }
    if (updateSelfFollowerRebootedPeerKeys.size() < updateSelfExpectedEchos)
    {
      return;
    }

    // Ask peers to derive the next master before we restart ourselves.
    updateSelfState = UpdateSelfState::waitingForRelinquishEchos;
    updateSelfRelinquishEchos = 0;
    updateSelfRelinquishEchoPeerKeys.clear();
    updateSelfRelinquishIssuedPeerKeys.clear();
    updateSelfPlannedMasterPeerKey = 0;
    for (BrainView *bv : brains)
    {
      if (bv == nullptr)
      {
        continue;
      }

      uint128_t peerKey = updateSelfPeerTrackingKey(bv);
      if (updateSelfFollowerRebootedPeerKeys.contains(peerKey) == false)
      {
        continue;
      }

      if (updateSelfPlannedMasterPeerKey == 0 || peerKey < updateSelfPlannedMasterPeerKey)
      {
        updateSelfPlannedMasterPeerKey = peerKey;
      }
    }
    if (updateSelfPlannedMasterPeerKey == 0)
    {
      return;
    }
    String nextMasterPeerKeyText = {};
    nextMasterPeerKeyText.snprintf<"{itoa}"_ctv>(updateSelfPlannedMasterPeerKey);
    PRODIGY_DEBUG_LOG(
                 "prodigy updateProdigy relinquish-begin peers=%u nextMasterPeerKey=%s nowMs=%lld\n",
                 updateSelfExpectedEchos,
                 nextMasterPeerKeyText.c_str(),
                 (long long)Time::now<TimeResolution::ms>());
    PRODIGY_DEBUG_FLUSH();
    noteMasterAuthorityRuntimeStateChanged();

    for (BrainView *bv : brains)
    {
      queueUpdateSelfRelinquishToPeer(bv);
    }
  }

  void maybeTransitionFollowersForUpdateSelf(void)
  {
    if (updateSelfState != UpdateSelfState::waitingForBundleEchos)
    {
      return;
    }
    if (updateSelfBundleEchos < updateSelfExpectedEchos)
    {
      return;
    }

    updateSelfState = UpdateSelfState::waitingForFollowerReboots;
    updateSelfFollowerBootNsByPeerKey.clear();
    updateSelfFollowerRebootedPeerKeys.clear();
    updateSelfTransitionIssuedPeerKeys.clear();
    updateSelfBundleBlob.clear();
    noteMasterAuthorityRuntimeStateChanged();

    // Followers should transition first so master handoff/restart happens last.
    PRODIGY_DEBUG_LOG(
                 "prodigy updateProdigy follower-transition-begin peers=%u nowMs=%lld\n",
                 updateSelfExpectedEchos,
                 (long long)Time::now<TimeResolution::ms>());
    PRODIGY_DEBUG_FLUSH();
    for (BrainView *bv : brains)
    {
      if (peerSocketActive(bv) == false)
      {
        continue;
      }

      uint128_t peerKey = updateSelfPeerTrackingKey(bv);
      if (peerKey != 0)
      {
        updateSelfFollowerBootNsByPeerKey.insert_or_assign(peerKey, bv->boottimens);
      }

      queueUpdateSelfTransitionToPeer(bv);
    }
  }

  void noteUpdateSelfFollowerReboot(BrainView *bv, const char *source, int64_t previousBootNs = 0)
  {
    if (updateSelfState != UpdateSelfState::waitingForFollowerReboots)
    {
      return;
    }
    if (bv == nullptr)
    {
      return;
    }

    uint128_t peerKey = updateSelfPeerTrackingKey(bv);
    if (peerKey == 0)
    {
      return;
    }
    if (updateSelfFollowerBootNsByPeerKey.contains(peerKey) == false)
    {
      return;
    }
    if (updateSelfFollowerRebootedPeerKeys.contains(peerKey))
    {
      return;
    }

    updateSelfFollowerReconnectedPeerKeys.erase(peerKey);
    updateSelfFollowerRebootedPeerKeys.insert(peerKey);

    String rebootedUUIDText = {};
    rebootedUUIDText.snprintf<"{itoa}"_ctv>(bv->uuid);
    PRODIGY_DEBUG_LOG(
                 "prodigy updateProdigy follower-reboot source=%s uuid=%s private4=%u %u/%u oldBootNs=%ld newBootNs=%ld nowMs=%lld\n",
                 (source ? source : "unknown"),
                 rebootedUUIDText.c_str(),
                 bv->private4,
                 uint32_t(updateSelfFollowerRebootedPeerKeys.size()),
                 updateSelfExpectedEchos,
                 (long)previousBootNs,
                 (long)bv->boottimens,
                 (long long)Time::now<TimeResolution::ms>());
    PRODIGY_DEBUG_FLUSH();
    noteMasterAuthorityRuntimeStateChanged();

    maybeRelinquishMasterForUpdateSelf();
  }

  void onUpdateSelfPeerRegistration(BrainView *bv)
  {
    if (updateSelfState != UpdateSelfState::waitingForFollowerReboots)
    {
      return;
    }
    if (bv == nullptr)
    {
      return;
    }

    uint128_t peerKey = updateSelfPeerTrackingKey(bv);
    auto it = updateSelfFollowerBootNsByPeerKey.find(peerKey);
    PRODIGY_DEBUG_LOG(
                 "prodigy updateProdigy follower-registration private4=%u tracked=%d oldBootNs=%ld newBootNs=%ld\n",
                 bv->private4,
                 int(it != updateSelfFollowerBootNsByPeerKey.end()),
                 (long)(it != updateSelfFollowerBootNsByPeerKey.end() ? it->second : 0),
                 (long)bv->boottimens);
    PRODIGY_DEBUG_FLUSH();

    if (it != updateSelfFollowerBootNsByPeerKey.end())
    {
      int64_t previousBootNs = it->second;
      bool sawReconnect = updateSelfFollowerReconnectedPeerKeys.contains(peerKey);
      if ((bv->boottimens > 0 && bv->boottimens != previousBootNs) || sawReconnect)
      {
        noteUpdateSelfFollowerReboot(bv, sawReconnect ? "registration-reconnect" : "registration", previousBootNs);
      }
    }
  }

  void onUpdateSelfBundleEcho(BrainView *bv)
  {
    if (updateSelfState != UpdateSelfState::waitingForBundleEchos)
    {
      return;
    }
    if (bv == nullptr)
    {
      return;
    }

    uint128_t peerKey = updateSelfPeerTrackingKey(bv);
    if (peerKey != 0 && updateSelfBundleEchoPeerKeys.contains(peerKey) == false && updateSelfBundleEchos < updateSelfExpectedEchos)
    {
      updateSelfBundleEchoPeerKeys.insert(peerKey);
      updateSelfBundleEchos += 1;
      noteMasterAuthorityRuntimeStateChanged();
    }

    PRODIGY_DEBUG_LOG(
                 "prodigy updateProdigy bundle-echo %u/%u nowMs=%lld\n",
                 updateSelfBundleEchos,
                 updateSelfExpectedEchos,
                 (long long)Time::now<TimeResolution::ms>());
    PRODIGY_DEBUG_FLUSH();
    maybeTransitionFollowersForUpdateSelf();
  }

  void onUpdateSelfRelinquishEcho(BrainView *bv)
  {
    if (updateSelfState != UpdateSelfState::waitingForRelinquishEchos)
    {
      return;
    }
    if (bv == nullptr)
    {
      return;
    }

    uint128_t peerKey = updateSelfPeerTrackingKey(bv);
    if (peerKey != 0 && updateSelfRelinquishEchoPeerKeys.contains(peerKey) == false && updateSelfRelinquishEchos < updateSelfExpectedEchos)
    {
      updateSelfRelinquishEchoPeerKeys.insert(peerKey);
      updateSelfRelinquishEchos += 1;
      noteMasterAuthorityRuntimeStateChanged();
    }

    PRODIGY_DEBUG_LOG(
                 "prodigy updateProdigy relinquish-echo %u/%u nowMs=%lld\n",
                 updateSelfRelinquishEchos,
                 updateSelfExpectedEchos,
                 (long long)Time::now<TimeResolution::ms>());
    PRODIGY_DEBUG_FLUSH();
    if (updateSelfRelinquishEchos < updateSelfExpectedEchos)
    {
      return;
    }

    // Once every peer has acknowledged relinquish, we can safely restart ourselves.
    if (updateSelfPlannedMasterPeerKey > 0)
    {
      pendingDesignatedMasterPeerKey = updateSelfPlannedMasterPeerKey;
    }
    boottimens = Time::now<TimeResolution::ns>();
    forfeitMasterStatus();
    resetUpdateSelfState();
    noteMasterAuthorityRuntimeStateChanged();
    transitionToNewBundle();
  }

  BrainView *currentMasterPeer(void)
  {
    for (BrainView *peer : brains)
    {
      if (peer == nullptr)
      {
        continue;
      }

      if (peerRepresentsCurrentMasterForLiveness(peer) == false)
      {
        continue;
      }

      if (peerSocketActive(peer) == false)
      {
        continue;
      }

      return peer;
    }

    return nullptr;
  }

  void replicateMetricSampleToFollowers(BrainView *excludePeer, uint64_t deploymentID, uint128_t containerUUID, int64_t sampleTimeMs, uint64_t metricKey, uint64_t metricValue)
  {
    if (nBrains <= 1)
    {
      return;
    }

    for (BrainView *peer : brains)
    {
      if (peer == nullptr || peer == excludePeer || peer->quarantined)
      {
        continue;
      }

      if (peerSocketActive(peer) == false)
      {
        continue;
      }

      Message::construct(peer->wBuffer, BrainTopic::replicateMetricsAppend, deploymentID, containerUUID, sampleTimeMs, metricKey, metricValue);
      Ring::queueSend(peer);
    }
  }

  void forwardMetricSampleToMaster(uint64_t deploymentID, uint128_t containerUUID, int64_t sampleTimeMs, uint64_t metricKey, uint64_t metricValue)
  {
    if (weAreMaster)
    {
      replicateMetricSampleToFollowers(nullptr, deploymentID, containerUUID, sampleTimeMs, metricKey, metricValue);
      return;
    }

    BrainView *masterPeer = currentMasterPeer();
    if (masterPeer == nullptr)
    {
      return;
    }

    uint32_t headerOffset = Message::appendHeader(masterPeer->wBuffer, BrainTopic::replicateMetricsAppend);
    Message::append(masterPeer->wBuffer, deploymentID);
    Message::append(masterPeer->wBuffer, containerUUID);
    Message::append(masterPeer->wBuffer, sampleTimeMs);
    Message::append(masterPeer->wBuffer, metricKey);
    Message::append(masterPeer->wBuffer, metricValue);
    Message::finish(masterPeer->wBuffer, headerOffset);
    Ring::queueSend(masterPeer);
  }

  void brainHandler(BrainView *bv, Message *message)
  {
    uint8_t *args = message->args;
    if (bv != nullptr)
    {
      bv->notePeerMessageReceived();
    }

    switch (BrainTopic(message->topic))
    {
#if 0
      case BrainTopic::reconcileMetrics:
      {
         // follower -> master: lastKnownMs(8)
         if (!isActiveMaster()) break;
         int64_t lastMs = 0;
         Message::extractArg<ArgumentNature::fixed>(args, lastMs);
         // Send metrics newer than lastMs in chunks
         const Vector<Measurement> &feed = metrics.all;
         const size_t maxPerChunk = 256; // keep messages moderate
         size_t start = 0;
         // find first index > lastMs
         while (start < feed.size() && feed[start].ms <= lastMs) ++start;
         for (size_t i = start; i < feed.size(); )
         {
            uint32_t h = Message::appendHeader(bv->wBuffer, BrainTopic::replicateMetricsAppend);
            uint16_t n = 0; size_t j = i;
            // reserve count field placeholder written above
            // Append up to maxPerChunk measurements
            Message::append(bv->wBuffer, uint16_t(0)); // placeholder; will overwrite after building
            size_t countPos = bv->wBuffer.size() - sizeof(uint16_t);
            for (; j < feed.size() && n < maxPerChunk; ++j, ++n)
            {
               const Measurement &m = feed[j];
               Message::append(bv->wBuffer, m.ms);
               Message::append(bv->wBuffer, m.deploymentID);
               Message::append(bv->wBuffer, m.containerUUID);
               Message::append(bv->wBuffer, m.metricKey);
               Message::append(bv->wBuffer, m.value);
            }
            // backpatch count
            memcpy(bv->wBuffer.data() + countPos, &n, sizeof(uint16_t));
            Message::finish(bv->wBuffer, h);
            Ring::queueSend(bv);
            i = j;
         }
         break;
      }
      case BrainTopic::replicateMetricsAppend:
      {
         // master -> follower: count(2), then {ms(8) dep(8) uuid(16) key(4) value(float)} * count
         uint16_t n = 0; Message::extractArg<ArgumentNature::fixed>(args, n);
         Vector<Measurement> batch; batch.reserve(n);
         for (uint16_t i = 0; i < n; ++i)
         {
            int64_t ms; uint64_t dep; uint128_t uuid; uint32_t key; float v;
            Message::extractArg<ArgumentNature::fixed>(args, ms);
            Message::extractArg<ArgumentNature::fixed>(args, dep);
            Message::extractArg<ArgumentNature::fixed>(args, uuid);
            Message::extractArg<ArgumentNature::fixed>(args, key);
            Message::extractArg<ArgumentNature::fixed>(args, v);
            metrics.record(dep, uuid, key, ms, v);
            batch.push_back(Measurement{ms, dep, uuid, key, v});
         }
         // If we're master and this came from a follower, fan-out to other peers (exclude sender)
         if (isActiveMaster())
         {
            for (BrainView *peer : brains)
            {
               if (peer == bv) continue;
               uint32_t h = Message::appendHeader(peer->wBuffer, BrainTopic::replicateMetricsAppend);
               uint16_t nout = (uint16_t)batch.size();
               Message::append(peer->wBuffer, nout);
               for (const auto &m : batch)
               {
                  Message::append(peer->wBuffer, m.ms);
                  Message::append(peer->wBuffer, m.deploymentID);
                  Message::append(peer->wBuffer, m.containerUUID);
                  Message::append(peer->wBuffer, m.metricKey);
                  Message::append(peer->wBuffer, m.value);
               }
               Message::finish(peer->wBuffer, h);
               Ring::queueSend(peer);
            }
         }
         break;
      }
      case BrainTopic::reconcileTd:
      {
         // follower -> master: lastMinuteEndMs(8)
         if (!isActiveMaster()) break;
         int64_t lastMinute = 0;
         Message::extractArg<ArgumentNature::fixed>(args, lastMinute);
         const Vector<TDMinute> &feed = tdminutes.all;
         const size_t maxPerChunk = 128;
         size_t start = 0;
         while (start < feed.size() && feed[start].minuteEndMs <= lastMinute) ++start;
         for (size_t i = start; i < feed.size(); )
         {
            uint32_t h = Message::appendHeader(bv->wBuffer, BrainTopic::replicateTdAppend);
            uint16_t n = 0; size_t j = i;
            Message::append(bv->wBuffer, uint16_t(0));
            size_t countPos = bv->wBuffer.size() - sizeof(uint16_t);
            for (; j < feed.size() && n < maxPerChunk; ++j, ++n)
            {
               const TDMinute &r = feed[j];
               Message::append(bv->wBuffer, r.minuteEndMs);
               Message::append(bv->wBuffer, r.deploymentID);
               Message::append(bv->wBuffer, r.containerUUID);
               Message::append(bv->wBuffer, r.metricKey);
               metrics::TDigestCodec::append(bv->wBuffer, r.digest);
            }
            memcpy(bv->wBuffer.data() + countPos, &n, sizeof(uint16_t));
            Message::finish(bv->wBuffer, h);
            Ring::queueSend(bv);
            i = j;
         }
         // Also stream any group-minute records newer than lastMinute (best-effort); reuse same reconcileTd? Keep group sync via recompute path on follower.
         break;
      }
      case BrainTopic::replicateTdAppend:
      {
         // master -> follower: count(2), then {minuteEnd(8) dep(8) uuid(16) key(4) digest} * count
         uint16_t n = 0; Message::extractArg<ArgumentNature::fixed>(args, n);
         Vector<TDMinute> batch; batch.reserve(n);
         for (uint16_t i = 0; i < n; ++i)
         {
            int64_t minuteEnd; uint64_t dep; uint128_t uuid; uint32_t key;
            Message::extractArg<ArgumentNature::fixed>(args, minuteEnd);
            Message::extractArg<ArgumentNature::fixed>(args, dep);
            Message::extractArg<ArgumentNature::fixed>(args, uuid);
            Message::extractArg<ArgumentNature::fixed>(args, key);
            metrics::TDigest d(200.0);
            bool ok = metrics::TDigestCodec::extract(args, message->terminal(), d);
            if (!ok) break;
            tdminutes.upsert(dep, uuid, key, minuteEnd, d);
            if (minuteEnd > tdLastMinuteApplied) tdLastMinuteApplied = minuteEnd;
            recomputeGroupMinute(dep, key, minuteEnd);
            batch.push_back(TDMinute{minuteEnd, dep, uuid, key, d});
         }
         // If we're master and this came from a follower, fan-out to other peers (exclude sender)
         if (isActiveMaster())
         {
            for (BrainView *peer : brains)
            {
               if (peer == bv) continue;
               uint32_t h = Message::appendHeader(peer->wBuffer, BrainTopic::replicateTdAppend);
               uint16_t nout = (uint16_t)batch.size();
               Message::append(peer->wBuffer, nout);
               for (const auto &r : batch)
               {
                  Message::append(peer->wBuffer, r.minuteEndMs);
                  Message::append(peer->wBuffer, r.deploymentID);
                  Message::append(peer->wBuffer, r.containerUUID);
                  Message::append(peer->wBuffer, r.metricKey);
                  metrics::TDigestCodec::append(peer->wBuffer, r.digest);
               }
               Message::finish(peer->wBuffer, h);
               Ring::queueSend(peer);
            }
         }
         break;
      }
#endif
      case BrainTopic::replicateMetricsAppend:
        {
          // follower -> master: deploymentID(8) containerUUID(16) sampleTimeMs(8) metricKey(8) metricValue(8)
          uint64_t deploymentID = 0;
          uint128_t containerUUID = 0;
          int64_t sampleTimeMs = 0;
          uint64_t metricKey = 0;
          uint64_t metricValue = 0;

          Message::extractArg<ArgumentNature::fixed>(args, deploymentID);
          Message::extractArg<ArgumentNature::fixed>(args, containerUUID);
          Message::extractArg<ArgumentNature::fixed>(args, sampleTimeMs);
          Message::extractArg<ArgumentNature::fixed>(args, metricKey);
          Message::extractArg<ArgumentNature::fixed>(args, metricValue);

          recordContainerMetric(deploymentID, containerUUID, metricKey, sampleTimeMs, static_cast<double>(metricValue));
          if (auto containerIt = containers.find(containerUUID); containerIt != containers.end())
          {
            if (containerIt->second->deploymentID == deploymentID && containerIt->second->applyStatefulTopologyCutoverMetric(metricKey, metricValue))
            {
              if (auto deploymentIt = deployments.find(deploymentID); deploymentIt != deployments.end() && deploymentIt->second)
              {
                deploymentIt->second->containerStatefulTopologyCutoverBarrierUpdated(containerIt->second);
              }
            }
          }
          if (weAreMaster && bv != nullptr)
          {
            replicateMetricSampleToFollowers(bv, deploymentID, containerUUID, sampleTimeMs, metricKey, metricValue);
          }
          break;
        }
      case BrainTopic::replicateContainerHealthy:
        {
          uint128_t containerUUID = 0;
          Message::extractArg<ArgumentNature::fixed>(args, containerUUID);
          if (weAreMaster)
          {
            noteLocalContainerHealthy(containerUUID);
          }
          break;
        }
      case BrainTopic::replicateContainerRuntimeReady:
        {
          uint128_t containerUUID = 0;
          Message::extractArg<ArgumentNature::fixed>(args, containerUUID);
          if (weAreMaster)
          {
            noteLocalContainerRuntimeReady(containerUUID);
          }
          break;
        }
      case BrainTopic::replicateContainerRuntimeState:
        {
          String serialized;
          Message::extractToStringView(args, serialized);

          BrainReplicatedContainerRuntimeState state = {};
          if (BitseryEngine::deserializeSafe(serialized, state))
          {
            applyReplicatedContainerRuntimeState(state);
          }
          break;
        }
      case BrainTopic::replicateMetricsSnapshot:
        {
          String serialized;
          Message::extractToStringView(args, serialized);

          Vector<ProdigyMetricSample> samples;
          if (BitseryEngine::deserializeSafe(serialized, samples))
          {
            metrics.importSamples(samples);
            persistLocalRuntimeState();
          }
          break;
        }
      // this is for adding new deployments
      case BrainTopic::replicateDeployment:
        {
          if (message->payloadSize() == 8) // echo
          {
            // deploymentID(8)

            uint64_t deploymentID;
            Message::extractArg<ArgumentNature::fixed>(args, deploymentID);

            if (auto it = deployments.find(deploymentID); it != deployments.end())
            {
              ApplicationDeployment *deployment = it->second;
              uint128_t peerKey = updateSelfPeerTrackingKey(bv);
              const bool requiresBlobEcho = (deployment->plan.config.containerBlobBytes > 0);

              if (requiresBlobEcho && peerKey != 0 && deployment->brainBlobQueuedPeerKeys.contains(peerKey) == false)
              {
                String serializedPlan = {};
                BitseryEngine::serialize(serializedPlan, deployment->plan);
                if (queueBrainDeploymentReplicationFromStoreToPeer(
                        bv,
                        serializedPlan,
                        deploymentID,
                        deployment->plan.config.containerBlobBytes))
                {
                  deployment->brainBlobQueuedPeerKeys.insert(peerKey);
                  std::fprintf(
                      stderr,
                      "prodigy replicateDeployment stage-blob private4=%u deploymentID=%llu peerKey=%llu blobBytes=%llu\n",
                      bv->private4,
                      (unsigned long long)deploymentID,
                      (unsigned long long)peerKey,
                      (unsigned long long)deployment->plan.config.containerBlobBytes);
                  PRODIGY_DEBUG_FLUSH();
                }
                else
                {
                  basics_log(
                      "replicateDeployment stage-blob failed private4=%u deploymentID=%llu peerKey=%llu blobBytes=%llu\n",
                      bv->private4,
                      (unsigned long long)deploymentID,
                      (unsigned long long)peerKey,
                      (unsigned long long)deployment->plan.config.containerBlobBytes);
                }

                break;
              }

              if (requiresBlobEcho && peerKey != 0)
              {
                if (deployment->brainBlobEchoPeerKeys.contains(peerKey))
                {
                  break;
                }

                deployment->brainBlobEchoPeerKeys.insert(peerKey);
              }

              deployment->brainEchos += 1;

              if (deployment->brainEchos == 2 && deployment->state == DeploymentState::none) // what if a brain dies during this??? then when it comes back online and gets replicated the deployments it will echo back to us
              {
                spinApplication(deployment);
              }
            }
          }
          else
          {
            // plan{4} containerBlob{4}

            String serializedPlan;
            Message::extractToStringView(args, serializedPlan);

            DeploymentPlan plan;
            BitseryEngine::deserialize(serializedPlan, plan);

            deploymentPlans.insert_or_assign(plan.config.deploymentID(), plan);
            applyReplicatedDeploymentPlanLiveState(plan);
            applyPendingReplicatedContainerRuntimeStates(plan.config.deploymentID());

            String containerBlob;
            Message::extractToStringView(args, containerBlob);

            if (containerBlob.size() > 0)
            {
              String storeFailure = {};
              if (ContainerStore::store(
                      plan.config.deploymentID(),
                      containerBlob,
                      nullptr,
                      nullptr,
                      &plan.config.containerBlobSHA256,
                      &plan.config.containerBlobBytes,
                      &storeFailure) == false)
              {
                basics_log(
                    "replicateDeployment blob store failed deploymentID=%llu reason=%s\n",
                    (unsigned long long)plan.config.deploymentID(),
                    (storeFailure.size() > 0 ? storeFailure.c_str() : "unknown"));
              }
            }
            // else this replication carried only metadata (e.g. no-op image reuse path)

            Message::construct(bv->wBuffer, BrainTopic::replicateDeployment, plan.config.deploymentID());
            persistLocalRuntimeState();
          }

          break;
        }
      case BrainTopic::replicateSystemContainerArtifact:
        {
          String sha256;
          uint64_t bytes = 0;
          String blob;
          Message::extractToStringView(args, sha256);
          Message::extractArg<ArgumentNature::fixed>(args, bytes);
          Message::extractToStringView(args, blob);

          String storeFailure = {};
          if (applySystemContainerArtifact(sha256, bytes, blob, false, &storeFailure) == false)
          {
            basics_log(
                "replicateSystemContainerArtifact store failed sha256=%s bytes=%llu reason=%s\n",
                sha256.c_str(),
                (unsigned long long)bytes,
                (storeFailure.size() > 0 ? storeFailure.c_str() : "unknown"));
          }

          break;
        }
      // we're done with this.... either it failed and we're erasing it... or we replaced it and fully transitioned to the new deployment
      case BrainTopic::cullDeployment:
        {
          // deploymentID(8)
          uint64_t deploymentID;
          Message::extractArg<ArgumentNature::fixed>(args, deploymentID);

          deploymentPlans.erase(deploymentID);
          releaseRoutableResourceLeasesForDeployment(deploymentID);
          if (removeTlsResumptionStateForDeployment(deploymentID, false) > 0)
          {
            refreshMasterAuthorityRuntimeStateFromLiveFields();
          }
          ContainerStore::destroy(deploymentID);
          persistLocalRuntimeState();

          break;
        }
      case BrainTopic::reconcileState:
        {
          uint8_t *args = message->args;

          // check what they have and send back culls and replications

          String serializedRequest = {};
          Message::extractToStringView(args, serializedRequest);
          BrainReconcileStateRequest request = {};
          if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
          {
            break;
          }

          bytell_hash_set<uint64_t> deploymentIDs;
          for (uint64_t deploymentID : request.deploymentIDs)
          {
            deploymentIDs.insert(deploymentID);
          }

          uint64_t before = bv->wBuffer.size();

          ClusterTopology authoritativeTopology = {};
          if (loadOrPersistAuthoritativeClusterTopology(authoritativeTopology))
          {
            String serializedTopology;
            BitseryEngine::serialize(serializedTopology, authoritativeTopology);
            Message::construct(bv->wBuffer, BrainTopic::replicateClusterTopology, serializedTopology);
          }

          bool abortedDeploymentReplication = false;
          for (const auto& [deploymentID, deployment] : deployments)
          {
            if (deploymentIDs.contains(deploymentID))
            {
              deploymentIDs.erase(deploymentID);
            }
            else
            {
              String serializedPlan;
              BitseryEngine::serialize(serializedPlan, deployment->plan);
              if (queueBrainDeploymentReplicationFromStoreToPeer(
                      bv,
                      serializedPlan,
                      deployment->plan.config.deploymentID(),
                      deployment->plan.config.containerBlobBytes) == false)
              {
                abortedDeploymentReplication = true;
                break;
              }
            }
          }

          if (abortedDeploymentReplication)
          {
            break;
          }

          for (uint64_t deploymentID : deploymentIDs) // all of these are culls
          {
            Message::construct(bv->wBuffer, BrainTopic::cullDeployment, deploymentID);
          }
          refreshMasterAuthorityRuntimeStateFromLiveFields();
          queueMissingSystemContainerArtifactForPeer(bv, request.systemArtifact);
          for (const auto& [applicationName, applicationID] : reservedApplicationIDsByName)
          {
            Message::construct(bv->wBuffer, BrainTopic::replicateApplicationIDReservation, applicationID, applicationName);
          }
          for (const auto& [service, identity] : reservedApplicationServicesByID)
          {
            (void)service;
            String serializedIdentity;
            BitseryEngine::serialize(serializedIdentity, identity);
            Message::construct(bv->wBuffer, BrainTopic::replicateApplicationServiceReservation, serializedIdentity);
          }
          for (const auto& [applicationID, factory] : tlsVaultFactoriesByApp)
          {
            (void)applicationID;
            String serializedFactory;
            BitseryEngine::serialize(serializedFactory, factory);
            Message::construct(bv->wBuffer, BrainTopic::replicateTlsVaultFactory, serializedFactory);
          }
          for (const auto& [applicationID, set] : apiCredentialSetsByApp)
          {
            (void)applicationID;
            String serializedSet;
            BitseryEngine::serialize(serializedSet, set);
            Message::construct(bv->wBuffer, BrainTopic::replicateApiCredentialSet, serializedSet);
          }
          {
            String serializedRuntimeState;
            ProdigyMasterAuthorityStateTransition transition;
            transition.runtimeState = masterAuthorityRuntimeState;
            transition.runtimeState.updateSelf = {};
            ownBrainConfig(brainConfig, transition.brainConfig);
            BitseryEngine::serialize(serializedRuntimeState, transition);
            String transitionDigest;
            if (prodigyComputeSHA256Hex(serializedRuntimeState, transitionDigest) == false)
            {
              break;
            }
            noteMasterAuthorityTransitionSentToPeer(bv,
                                                    transition.runtimeState,
                                                    transitionDigest);
            Message::construct(bv->wBuffer, BrainTopic::replicateMasterAuthorityState, serializedRuntimeState);
          }
          {
            Vector<ProdigyMetricSample> metricSamples;
            metrics.exportSamples(metricSamples);
            if (metricSamples.empty() == false)
            {
              String serializedMetricSamples;
              BitseryEngine::serialize(serializedMetricSamples, metricSamples);
              Message::construct(bv->wBuffer, BrainTopic::replicateMetricsSnapshot, serializedMetricSamples);
            }
          }

          if (bv->wBuffer.size() > before && peerSocketActive(bv))
          {
            Ring::queueSend(bv);
          }

          break;
        }
      case BrainTopic::registration:
        {
          uint8_t *args = message->args;

          // uuid(16) boottimens(8) version(8) existingMasterUUID(16) kernel{4} osID{4} osVersionID{4}
          Message::extractArg<ArgumentNature::fixed>(args, bv->uuid);
          Message::extractArg<ArgumentNature::fixed>(args, bv->boottimens);
          Message::extractArg<ArgumentNature::fixed>(args, bv->version);
          Message::extractArg<ArgumentNature::fixed>(args, bv->existingMasterUUID);
          Message::extractToString(args, bv->kernel);
          Message::extractToString(args, bv->osID);
          Message::extractToString(args, bv->osVersionID);
          bv->registrationFresh = true;
          if (bv->machine != nullptr)
          {
            bv->machine->kernel = bv->kernel;
            bv->machine->osID = bv->osID;
            bv->machine->osVersionID = bv->osVersionID;
            bv->machine->lastUpdatedOSMs = bv->boottimens / 1'000'000;
          }
          PRODIGY_DEBUG_LOG(
                       "prodigy debug brain registration private4=%u uuid=%llu boottimens=%ld existingMasterUUID=%llu osID=%s osVersionID=%s updateState=%u\n",
                       bv->private4,
                       (unsigned long long)bv->uuid,
                       (long)bv->boottimens,
                       (unsigned long long)bv->existingMasterUUID,
                       bv->osID.c_str(),
                       bv->osVersionID.c_str(),
                       unsigned(updateSelfState));
          PRODIGY_DEBUG_FLUSH();
          if (updateSelfState == UpdateSelfState::waitingForFollowerReboots ||
              updateSelfState == UpdateSelfState::waitingForRelinquishEchos)
          {
            uint128_t peerKey = updateSelfPeerTrackingKey(bv);
            PRODIGY_DEBUG_LOG(
                         "prodigy updateProdigy registration-recv private4=%u peerKey=%llu boottimens=%ld state=%u\n",
                         bv->private4,
                         (unsigned long long)peerKey,
                         (long)bv->boottimens,
                         unsigned(updateSelfState));
            PRODIGY_DEBUG_FLUSH();
          }
          synchronizeBrainUUIDToMachine(bv);
          refreshBrainPeerHandshakeWatchdog(bv, "registration");
          if (isActiveMaster() && bv->machine != nullptr)
          {
            promoteMachineToHealthyIfReady(bv->machine);
            armMachineUpdateTimerIfNeeded();
          }
          onUpdateSelfPeerRegistration(bv);

          if (weAreMaster && bv->existingMasterUUID == selfBrainUUID())
          {
            bv->forceConnectorOwnershipUntilMasterAck = false;
          }

          if (weAreMaster && bv->existingMasterUUID == selfBrainUUID())
          {
            bool conflictingMasterClaims = false;
            for (BrainView *peer : brains)
            {
              if (peerHasFreshExistingMasterClaim(peer) == false)
              {
                continue;
              }
              if (peer->existingMasterUUID == selfBrainUUID())
              {
                continue;
              }
              conflictingMasterClaims = true;
              break;
            }

            if (conflictingMasterClaims == false)
            {
              masterQuorumDegraded = false;
            }
          }

          // If we are currently master but a majority of peers consistently report a different
          // existing master, relinquish and follow that majority to avoid split-brain on heal.
          if (weAreMaster && peerHasFreshExistingMasterClaim(bv) && bv->existingMasterUUID != selfBrainUUID())
          {
            uint32_t majority = uint32_t(nBrains / 2) + 1;
            bytell_hash_map<uint128_t, uint32_t> votesByMasterUUID;

            for (BrainView *peer : brains)
            {
              if (peerSocketActive(peer) == false)
              {
                continue;
              }
              if (peerHasFreshExistingMasterClaim(peer) == false)
              {
                continue;
              }
              if (peer->existingMasterUUID == selfBrainUUID())
              {
                continue;
              }

              votesByMasterUUID[peer->existingMasterUUID] += 1;
            }

            uint128_t candidateMasterUUID = 0;
            uint32_t candidateVotes = 0;
            for (const auto& [uuid, votes] : votesByMasterUUID)
            {
              if (votes > candidateVotes)
              {
                candidateMasterUUID = uuid;
                candidateVotes = votes;
              }
            }

            BrainView *candidateMasterBrain = findBrainViewByUUID(candidateMasterUUID);

            bool candidateMasterActive = (candidateMasterBrain != nullptr &&
                                          peerSocketActive(candidateMasterBrain) &&
                                          peerHasFreshExistingMasterClaim(candidateMasterBrain) &&
                                          candidateMasterBrain->existingMasterUUID == candidateMasterUUID);
            bool connectedMajority = hasConnectedBrainMajority();
            bool overrideByMajority = (candidateMasterUUID > 0 &&
                                       candidateVotes >= majority &&
                                       candidateMasterActive &&
                                       connectedMajority);
            bool overrideByDegradedRejoin = (candidateMasterUUID > 0 &&
                                             candidateVotes > 0 &&
                                             candidateMasterActive &&
                                             connectedMajority &&
                                             masterQuorumDegraded);

            if (overrideByMajority || overrideByDegradedRejoin)
            {
              String oldMasterUUIDText = {};
              String newMasterUUIDText = {};
              oldMasterUUIDText.snprintf<"{itoa}"_ctv>(selfBrainUUID());
              newMasterUUIDText.snprintf<"{itoa}"_ctv>(candidateMasterUUID);
              basics_log("registration master override old=%s new=%s votes=%u majority=%u degraded=%d mode=%s\n",
                         oldMasterUUIDText.c_str(),
                         newMasterUUIDText.c_str(),
                         candidateVotes,
                         majority,
                         int(masterQuorumDegraded),
                         overrideByMajority ? "majority" : "degraded-rejoin");

              forfeitMasterStatus();
              resetMasterBrainAssignment();

              for (BrainView *peer : brains)
              {
                if (peer->uuid == candidateMasterUUID)
                {
                  electBrainToMaster(peer);
                  break;
                }
              }
            }
            else
            {
              // Reconciliation requires quorum-majority reports from currently active peers.
              // Never relinquish master from stale/degraded claims.
            }
          }

          if (weAreMaster && bv->existingMasterUUID != selfBrainUUID())
          {
            // Followers can still have a live stream to us while lacking an explicit
            // current-master claim. Push our master identity immediately so liveness
            // and failover logic do not wait for a later reconnect cycle.
            bv->sendRegistration(boottimens, version, getExistingMasterUUID());
          }

          if (noMasterYet && weAreMaster == false && pendingDesignatedMasterPeerKey > 0)
          {
            uint128_t registrationPeerKey = updateSelfPeerTrackingKey(bv);
            uint128_t selfPeerKey = updateSelfLocalPeerTrackingKey();
            if (selfPeerKey > 0 && pendingDesignatedMasterPeerKey == selfPeerKey)
            {
              String pendingPeerKeyText = {};
              pendingPeerKeyText.snprintf<"{itoa}"_ctv>(pendingDesignatedMasterPeerKey);
              basics_log("registration elect-self reason=pending-designated-master peerKey=%s\n",
                         pendingPeerKeyText.c_str());
              (void)selfElectAsMaster("registration:pending-designated-master", true);
            }
            else if (registrationPeerKey == pendingDesignatedMasterPeerKey && bv->quarantined == false)
            {
              electBrainToMaster(bv);
            }
          }

          if (noMasterYet && weAreMaster == false && bv->existingMasterUUID > 0 && bv->existingMasterUUID != selfBrainUUID())
          {
            uint128_t registrationPeerKey = updateSelfPeerTrackingKey(bv);
            if (pendingDesignatedMasterPeerKey > 0 && registrationPeerKey != pendingDesignatedMasterPeerKey)
            {
              String claimUUIDText = {};
              String pendingPeerKeyText = {};
              String fromUUIDText = {};
              claimUUIDText.snprintf<"{itoa}"_ctv>(bv->existingMasterUUID);
              pendingPeerKeyText.snprintf<"{itoa}"_ctv>(pendingDesignatedMasterPeerKey);
              fromUUIDText.snprintf<"{itoa}"_ctv>(bv->uuid);
              basics_log("registration deferring non-designated master claim claim=%s pendingPeerKey=%s from=%s\n",
                         claimUUIDText.c_str(), pendingPeerKeyText.c_str(), fromUUIDText.c_str());
            }
            else
            {
              if (BrainView *peer = findBrainViewByUUID(bv->existingMasterUUID); peer != nullptr)
              {
                electBrainToMaster(peer);
              }
            }
          }

          if (noMasterYet)
          {
            if (pendingDesignatedMasterPeerKey == 0)
            {
              deriveMasterBrain();
            }
            else
            {
              String pendingPeerKeyText = {};
              String fromUUIDText = {};
              String claimUUIDText = {};
              pendingPeerKeyText.snprintf<"{itoa}"_ctv>(pendingDesignatedMasterPeerKey);
              fromUUIDText.snprintf<"{itoa}"_ctv>(bv->uuid);
              claimUUIDText.snprintf<"{itoa}"_ctv>(bv->existingMasterUUID);
              basics_log("registration waiting designated master peerKey=%s from=%s claim=%s\n",
                         pendingPeerKeyText.c_str(), fromUUIDText.c_str(), claimUUIDText.c_str());
            }

            if (!noMasterYet && !weAreMaster) // aka we just now have a master and it's not us
            {
              for (BrainView *bv : brains)
              {
                if (peerRepresentsCurrentMaster(bv))
                {
                  // send the deployments we have
                  // the master will respond with any to cull and any we don't have yet

                  BrainReconcileStateRequest request = {};
                  for (const auto& [deploymentID, plan] : deploymentPlans)
                  {
                    request.deploymentIDs.push_back(plan.config.deploymentID());
                  }
                  capturePresentSystemArtifactRef(request.systemArtifact);

                  String serializedRequest = {};
                  BitseryEngine::serialize(serializedRequest, request);
                  Message::construct(bv->wBuffer, BrainTopic::reconcileState, serializedRequest);
                }
              }
            }
          }

          // late-join reconciliation: if we are master and peer has an older bundle, push and transition it now
          if (!noMasterYet && weAreMaster && bv->version < version)
          {
            if (peerSocketActive(bv))
            {
              bv->wBuffer.reserve(bv->wBuffer.size() + 512_KB);
              String prodigyBundlePath = {};
              prodigyResolveInstalledBundlePathForRoot("/root/prodigy"_ctv, prodigyBundlePath);
              uint32_t headerOffset = Message::appendHeader(bv->wBuffer, BrainTopic::updateBundle);
              Message::appendFile(bv->wBuffer, prodigyBundlePath);
              Message::finish(bv->wBuffer, headerOffset);
              Message::construct(bv->wBuffer, BrainTopic::transitionToNewBundle);
              Ring::queueSend(bv);
            }
          }

          refreshMasterPeerLivenessWaiter(bv, "registration");
          break;
        }
      case BrainTopic::peerAddressCandidates:
        {
          String serialized;
          Message::extractToStringView(args, serialized);

          Vector<ClusterMachinePeerAddress> candidates;
          if (BitseryEngine::deserializeSafe(serialized, candidates))
          {
            (void)updateBrainPeerAddressCandidates(bv, candidates);
          }

          break;
        }
      case BrainTopic::masterMissing:
        {
          if (message->isEcho()) // they're eliciting our state but also saying their state is true
          {
            bv->isMasterMissing = true;
            basics_log("masterMissing echo from=%u localIsMasterMissing=%d\n", bv->private4, int(isMasterMissing));
            bv->respondMasterMissing(isMasterMissing);
            maybeDeriveOnMasterMissingAgreement("echo");
          }
          else
          {
            // they're sending their state
            // and we would only elicit if we thought the master was missing
            uint8_t *args = message->args;
            Message::extractArg<ArgumentNature::fixed>(args, bv->isMasterMissing);
            basics_log("masterMissing response from=%u value=%d\n", bv->private4, int(bv->isMasterMissing));
            maybeDeriveOnMasterMissingAgreement("response");
          }

          break;
        }
      case BrainTopic::peerHeartbeat:
        {
          uint8_t *args = message->args;
          bool isResponse = false;
          uint64_t heartbeatNonce = 0;
          if (Message::extractArg<ArgumentNature::fixed>(args, isResponse) == false)
          {
            break;
          }
          if (Message::extractArg<ArgumentNature::fixed>(args, heartbeatNonce) == false)
          {
            break;
          }

          if (isResponse)
          {
            bv->notePeerHeartbeatAck(heartbeatNonce);
            refreshMasterPeerLivenessWaiter(bv, "peer-heartbeat-ack");
          }
          else
          {
            bv->respondPeerHeartbeat(heartbeatNonce);
          }
          break;
        }
      case BrainTopic::updateBundle:
        {
          if (message->isEcho())
          {
            onUpdateSelfBundleEcho(bv);
          }
          else
          {
            // bundleBlob{4}

            String newBundle;
            Message::extractToStringView(args, newBundle);

            if (newBundle == "__staged__"_ctv && devSharedStagedBundleEnabled())
            {
              PRODIGY_DEBUG_LOG( "prodigy updateProdigy bundle-staged-recv from=%u\n", bv->private4);
              PRODIGY_DEBUG_FLUSH();
            }
            else
            {
              PRODIGY_DEBUG_LOG( "prodigy updateProdigy bundle-recv from=%u bytes=%u\n", bv->private4, uint32_t(newBundle.size()));
              PRODIGY_DEBUG_FLUSH();
              Filesystem::openWriteAtClose(-1, prodigyStagedBundlePath(), newBundle);
            }

            if (peerSocketActive(bv))
            {
              Message::construct(bv->wBuffer, BrainTopic::updateBundle); // this signals that we got the message
              Ring::queueSend(bv);
            }
          }

          break;
        }
      case BrainTopic::transitionToNewBundle:
        {
          PRODIGY_DEBUG_LOG(
                       "prodigy updateProdigy transition-recv private4=%u master=%d\n",
                       thisNeuron->private4.v4,
                       int(weAreMaster));
          PRODIGY_DEBUG_FLUSH();
          if (weAreMaster == false)
          {
            transitionToNewBundle();
          }

          break;
        }
      case BrainTopic::relinquishMasterStatus:
        {
          if (message->isEcho())
          {
            onUpdateSelfRelinquishEcho(bv);
          }
          else
          {
            uint8_t commandMarker = 0;
            uint128_t designatedMasterPeerKey = 0;
            if (args < message->terminal())
            {
              Message::extractArg<ArgumentNature::fixed>(args, commandMarker);
              (void)commandMarker;
            }
            if ((args + sizeof(uint128_t)) <= message->terminal())
            {
              Message::extractArg<ArgumentNature::fixed>(args, designatedMasterPeerKey);
            }

            resetMasterBrainAssignment();
            pendingDesignatedMasterPeerKey = designatedMasterPeerKey;
            {
              String designatedPeerKeyText = {};
              designatedPeerKeyText.snprintf<"{itoa}"_ctv>(designatedMasterPeerKey);
              basics_log("relinquishMasterStatus designatedMasterPeerKey=%s\n",
                         designatedPeerKeyText.c_str());
            }

            bool electedDesignatedMaster = false;
            bool designatedMasterKnown = false;
            uint128_t selfPeerKey = updateSelfLocalPeerTrackingKey();
            if (designatedMasterPeerKey > 0 && designatedMasterPeerKey == selfPeerKey)
            {
              designatedMasterKnown = true;
              basics_log("relinquishMasterStatus elect-self reason=designated-master\n");
              electedDesignatedMaster = selfElectAsMaster("relinquishMasterStatus:designated-master", true);
            }
            else if (designatedMasterPeerKey > 0)
            {
              if (BrainView *peer = findBrainViewByUpdateSelfPeerKey(designatedMasterPeerKey); peer != nullptr)
              {
                designatedMasterKnown = true;
                if (peer->quarantined == false)
                {
                  electBrainToMaster(peer);
                  electedDesignatedMaster = true;
                }
              }
            }

            if (electedDesignatedMaster == false)
            {
              if (designatedMasterPeerKey > 0 && designatedMasterKnown)
              {
                String designatedPeerKeyText = {};
                designatedPeerKeyText.snprintf<"{itoa}"_ctv>(designatedMasterPeerKey);
                basics_log("relinquishMasterStatus waiting designated peerKey=%s (currently unavailable)\n",
                           designatedPeerKeyText.c_str());
              }
              else
              {
                pendingDesignatedMasterPeerKey = 0;
                deriveMasterBrain();
              }
            }

            if (peerSocketActive(bv))
            {
              Message::construct(bv->wBuffer, BrainTopic::relinquishMasterStatus);
              Ring::queueSend(bv);
            }

            noteMasterAuthorityRuntimeStateChanged(false, true);
          }

          break;
        }
      case BrainTopic::replicateBrainConfig:
        {
          // Brain configuration is inseparable from its versioned master-authority
          // state; reject the retired split payload instead of admitting a state
          // that cannot be authenticated, persisted, and acknowledged atomically.
          break;
        }
      case BrainTopic::replicateClusterTopology:
        {
          String serialized;
          Message::extractToStringView(args, serialized);

          ClusterTopology incomingTopology = {};
          if (BitseryEngine::deserializeSafe(serialized, incomingTopology) == false)
          {
            break;
          }

          prodigyStripMachineHardwareCapturesFromClusterTopology(incomingTopology);

          ClusterTopology existingTopology = {};
          if (loadAuthoritativeClusterTopology(existingTopology) && existingTopology.machines.empty() == false && existingTopology.version >= incomingTopology.version)
          {
            break;
          }

          restoreBrainsFromClusterTopology(incomingTopology);
          restoreMachinesFromClusterTopology(incomingTopology);
          nBrains = clusterTopologyBrainCount(incomingTopology);
          initializeAllBrainPeersIfNeeded();
          persistAuthoritativeClusterTopology(incomingTopology);
          break;
        }
      case BrainTopic::replicateApplicationIDReservation:
        {
          // applicationID(2) applicationName{4}
          uint16_t applicationID = 0;
          Message::extractArg<ArgumentNature::fixed>(args, applicationID);

          String applicationName;
          Message::extractToString(args, applicationName);

          String reserveFailure;
          if (reserveApplicationIDMapping(applicationName, applicationID, &reserveFailure) == false)
          {
            basics_log("replicateApplicationIDReservation reject appID=%u name=%s reason=%s\n",
                       unsigned(applicationID),
                       applicationName.c_str(),
                       reserveFailure.c_str());
          }
          else
          {
            persistLocalRuntimeState();
          }

          break;
        }
      case BrainTopic::replicateApplicationServiceReservation:
        {
          // identity{4}
          String serializedIdentity;
          Message::extractToStringView(args, serializedIdentity);

          ApplicationServiceIdentity identity;
          if (BitseryEngine::deserializeSafe(serializedIdentity, identity) == false)
          {
            break;
          }

          String reserveFailure;
          if (reserveApplicationServiceMapping(identity, &reserveFailure) == false)
          {
            basics_log("replicateApplicationServiceReservation reject appID=%u service=%s reason=%s\n",
                       unsigned(identity.applicationID),
                       identity.serviceName.c_str(),
                       reserveFailure.c_str());
          }
          else
          {
            persistLocalRuntimeState();
          }

          break;
        }
      case BrainTopic::replicateTlsVaultFactory:
        {
          // factory{4}
          String serializedFactory;
          Message::extractToStringView(args, serializedFactory);

          ApplicationTlsVaultFactory incoming;
          if (BitseryEngine::deserializeSafe(serializedFactory, incoming) == false)
          {
            break;
          }

          const ApplicationTlsVaultFactory *existing = nullptr;
          if (auto it = tlsVaultFactoriesByApp.find(incoming.applicationID); it != tlsVaultFactoriesByApp.end())
          {
            existing = &it->second;
          }

          if (shouldAcceptTlsFactoryReplication(incoming, existing))
          {
            String validationFailure;
            if (validateApplicationTlsVaultFactoryMaterial(incoming, &validationFailure))
            {
              tlsVaultFactoriesByApp.insert_or_assign(incoming.applicationID, incoming);
              persistLocalRuntimeState();
            }
            else
            {
              basics_log("replicateTlsVaultFactory reject appID=%u reason=%s\n",
                         unsigned(incoming.applicationID),
                         validationFailure.c_str());
            }
          }

          break;
        }
      case BrainTopic::replicateApiCredentialSet:
        {
          // set{4}
          String serializedSet;
          Message::extractToStringView(args, serializedSet);

          ApplicationApiCredentialSet incoming;
          if (BitseryEngine::deserializeSafe(serializedSet, incoming) == false)
          {
            break;
          }

          const ApplicationApiCredentialSet *existing = nullptr;
          if (auto it = apiCredentialSetsByApp.find(incoming.applicationID); it != apiCredentialSetsByApp.end())
          {
            existing = &it->second;
          }

          if (shouldAcceptApiCredentialSetReplication(incoming, existing))
          {
            apiCredentialSetsByApp.insert_or_assign(incoming.applicationID, incoming);
            persistLocalRuntimeState();
          }

          break;
        }
      case BrainTopic::replicateMasterAuthorityState:
        {
          String serialized;
          Message::extractToStringView(args, serialized);

          if (weAreMaster)
          {
            ProdigyMasterAuthorityStateTransitionAck acknowledgement = {};
            if (BitseryEngine::deserializeSafe(serialized, acknowledgement))
            {
              acknowledgeMasterAuthorityTransition(bv, acknowledgement);
            }
            break;
          }

          if (peerCanReplicateMasterAuthorityState(bv) == false)
          {
            break;
          }

          ProdigyMasterAuthorityStateTransition incoming = {};
          if (BitseryEngine::deserializeSafe(serialized, incoming) &&
              incoming.version == ProdigyMasterAuthorityStateTransition::currentVersion &&
              validatePendingElasticAddressOperations(incoming.runtimeState,
                                                      &incoming.brainConfig))
          {
            String transitionDigest;
            const bool applied = applyReplicatedMasterAuthorityTransition(incoming, true);
            if (applied &&
                (incoming.runtimeState.pendingElasticAddressAssignments.empty() == false ||
                 incoming.runtimeState.pendingElasticAddressReleases.empty() == false) &&
                replicatedRuntimeStateCoversPendingElasticAddressOperations(incoming.runtimeState) &&
                prodigyComputeSHA256Hex(serialized, transitionDigest))
            {
              sendMasterAuthorityTransitionAcknowledgement(
                  bv,
                  incoming.runtimeState.generation,
                  transitionDigest);
            }
          }

          break;
        }
      default:
        break;
    }
  }

  void spinApplication(ApplicationDeployment *deployment)
  {
    if (deployment != nullptr && prodigyDebugDeployHeapEnabled())
    {
      const ProdigyDeployHeapMetrics heap = prodigyReadDeployHeapMetrics();
      PRODIGY_DEBUG_LOG(
                   "prodigy debug spinApplication-begin deploymentID=%llu appID=%u stateful=%d deployments=%zu apps=%zu brains=%zu heapUsed=%llu heapMapped=%llu heapFree=%llu\n",
                   (unsigned long long)deployment->plan.config.deploymentID(),
                   unsigned(deployment->plan.config.applicationID),
                   int(deployment->plan.isStateful),
                   size_t(deployments.size()),
                   size_t(deploymentsByApp.size()),
                   size_t(brains.size()) + 1,
                   (unsigned long long)heap.used,
                   (unsigned long long)heap.mapped,
                   (unsigned long long)heap.free);
      PRODIGY_DEBUG_FLUSH();
    }

    ApplicationDeployment *previous = nullptr;

    if (deployment->plan.config.type == ApplicationType::task)
    {
      deployments.insert_or_assign(deployment->plan.config.deploymentID(), deployment);
      deployment->deploy();
      persistLocalRuntimeState();
      return;
    }

    if (auto it = deploymentsByApp.find(deployment->plan.config.applicationID); it != deploymentsByApp.end())
    {
      previous = it->second;
    }

    deploymentsByApp.insert_or_assign(deployment->plan.config.applicationID, deployment);
    deployments.insert_or_assign(deployment->plan.config.deploymentID(), deployment);
    deployment->restorePersistedStatefulWorkerTopologyUpgradeOperation();
    deployment->restorePersistedDeferredStatefulScaleIntent();

    if (previous == nullptr)
    {
      deployment->deploy();
    }
    else
    {
      switch (previous->state)
      {
        case DeploymentState::none: // they rapid fire sent another before we could begin work on this
        case DeploymentState::waitingToDeploy:

          {
            if (previous->previous == nullptr)
            {
              previous->next = deployment;
              deployment->previous = previous;
              deployment->state = DeploymentState::waitingToDeploy;
              break;
            }

            deployment->previous = previous->previous;
            previous->previous->next = deployment;

            if (auto it = deployments.find(previous->plan.config.deploymentID()); it != deployments.end() && it->second == previous)
            {
              deployments.erase(it);
            }

            releaseRoutableResourceLeasesForDeployment(previous->plan.config.deploymentID());
            delete previous;

            break;
          }
        case DeploymentState::canaries:
        case DeploymentState::deploying:
          {
            // still transitioning from n-2 deployment to n-1 deployment
            // once it finishes deploying, it will automatically transition
            // to this new one

            previous->next = deployment;
            deployment->previous = previous;

            deployment->state = DeploymentState::waitingToDeploy;

            // first of all we should NEVER be doing this... but if it ever did happen let's just gracefully
            // let each deployment complete then move forward

            // if we let it run to completion we're just going to destroy them all anyway.... but it's possible
            // if we stopped a stateful transition... that we'd have some n-2 and some n-1 and that is wouldn't be
            // possible to spin our entire n cluster from this disjoint basis

            break;
          }
        case DeploymentState::running:
          {
            previous->next = deployment;
            deployment->previous = previous;

            if (previous->nSuspended > 0) // they're in the middle of processing something... wait and they'll deploy us after
            {
              deployment->state = DeploymentState::waitingToDeploy;
            }
            else
            {
              previous->rollForward();
            }

            break;
          }
        case DeploymentState::failed:
          {
            // this happens if canaries fail....
            // otherwise should never happen?

            if (previous->previous)
            {
              deployment->previous = previous->previous;
            }

            // just delete this for now but maybe in the future we'd want to store failed results?
            delete previous;
            deployment->deploy();

            break;
          }
        case DeploymentState::decommissioning:
          break; // not possible
      }
    }

    persistLocalRuntimeState();

    if (deployment != nullptr && prodigyDebugDeployHeapEnabled())
    {
      const ProdigyDeployHeapMetrics heap = prodigyReadDeployHeapMetrics();
      PRODIGY_DEBUG_LOG(
                   "prodigy debug spinApplication-end deploymentID=%llu appID=%u state=%u deployments=%zu apps=%zu heapUsed=%llu heapMapped=%llu heapFree=%llu\n",
                   (unsigned long long)deployment->plan.config.deploymentID(),
                   unsigned(deployment->plan.config.applicationID),
                   unsigned(deployment->state),
                   size_t(deployments.size()),
                   size_t(deploymentsByApp.size()),
                   (unsigned long long)heap.used,
                   (unsigned long long)heap.mapped,
                   (unsigned long long)heap.free);
      PRODIGY_DEBUG_FLUSH();
    }
  }

  void respinApplication(ApplicationDeployment *deployment) override
  {
    if (deployment == nullptr)
    {
      return;
    }

    String serializedPlan;
    BitseryEngine::serialize(serializedPlan, deployment->plan);

    if (nBrains > 1)
    {
      queueBrainDeploymentReplication(serializedPlan, ""_ctv);

      String containerBlob;
      ContainerStore::get(deployment->plan.config.deploymentID(), containerBlob);

      if (containerBlob.size() > 0)
      {
        queueBrainDeploymentReplication(serializedPlan, containerBlob);
      }
    }

    // Apply the respin locally on the active master; replication keeps followers in sync.
    spinApplication(deployment);
  }

  void pushSpinApplicationProgressToMothership(ApplicationDeployment *deployment, StringType auto&& message)
  {
    Mothership *stream = spinApplicationMothershipFor(deployment);
    if (stream != nullptr)
    {
      Message::construct(
          stream->wBuffer,
          MothershipTopic::spinApplication,
          uint8_t(SpinApplicationResponseCode::progress),
          message);
      (void)flushActiveMothershipSendBuffer(stream, "spin-application-progress");
    }
  }

  void spinApplicationFailed(ApplicationDeployment *deployment, StringType auto&& message)
  {
    Mothership *stream = spinApplicationMothershipFor(deployment);
    if (stream != nullptr)
    {
      Message::construct(
          stream->wBuffer,
          MothershipTopic::spinApplication,
          uint8_t(SpinApplicationResponseCode::failed),
          message);
      (void)flushActiveMothershipSendBuffer(stream, "spin-application-failed");
    }

    clearSpinApplicationMothership(deployment);
  }

  uint32_t nextTaskAttemptNumber(const DeploymentPlan& plan) override
  {
    if (auto it = masterAuthorityRuntimeState.taskExecutions.find(plan.config.deploymentID()); it != masterAuthorityRuntimeState.taskExecutions.end())
    {
      return it->second.currentAttemptNumber + 1;
    }

    return 1;
  }

  void noteTaskAttemptAssigned(const DeploymentPlan& plan, const ContainerView& container) override
  {
    auto it = masterAuthorityRuntimeState.taskExecutions.find(plan.config.deploymentID());
    if (it == masterAuthorityRuntimeState.taskExecutions.end())
    {
      return;
    }

    TaskExecutionRecord& record = it->second;
    const int64_t nowMs = Time::now<TimeResolution::ms>();
    String ignored = {};
    if (taskExecutionTransition(record, TaskExecutionState::assigned, nowMs, &ignored) == false)
    {
      return;
    }
    (void)taskExecutionTransition(record, TaskExecutionState::running, nowMs, &ignored);
    record.currentAttemptNumber = container.taskAttemptNumber;
    record.attemptsStarted += 1;
    noteMasterAuthorityRuntimeStateChanged();
  }

  void noteTaskAttemptTerminal(ApplicationDeployment *deployment, ContainerView *container, const TaskTermination& termination) override
  {
    if (deployment == nullptr || container == nullptr)
    {
      return;
    }

    auto recordIt = masterAuthorityRuntimeState.taskExecutions.find(deployment->plan.config.deploymentID());
    if (recordIt == masterAuthorityRuntimeState.taskExecutions.end())
    {
      return;
    }

    const int64_t nowMs = Time::now<TimeResolution::ms>();
    TaskAttemptRecord attempt = {};
    attempt.attemptNumber = container->taskAttemptNumber;
    attempt.containerUUID = container->uuid;
    attempt.machinePrivate4 = container->machine ? container->machine->private4 : 0;
    attempt.state = termination.succeeded() ? TaskExecutionState::succeeded : (termination.kind == TaskTerminationKind::cancelled ? TaskExecutionState::cancelled : (termination.kind == TaskTerminationKind::lost ? TaskExecutionState::lost : TaskExecutionState::failed));
    attempt.acceptedAtMs = container->createdAtMs;
    attempt.assignedAtMs = container->createdAtMs;
    attempt.startedAtMs = container->createdAtMs;
    attempt.completedAtMs = nowMs;
    attempt.termination = termination;
    attempt.noRelaunchTombstone = true;

    String transitionFailure = {};
    if (taskExecutionCommitAttempt(recordIt->second, attempt, nowMs, &transitionFailure) == false)
    {
      basics_log("task terminal commit rejected deploymentID=%llu attempt=%u reason=%s\n",
                 (unsigned long long)deployment->plan.config.deploymentID(),
                 unsigned(attempt.attemptNumber),
                 transitionFailure.c_str());
      return;
    }

    if (container->machine)
    {
      container->machine->queueSend(NeuronTopic::taskAttemptTerminalAck, deployment->plan.config.deploymentID(), container->taskAttemptNumber);
    }
    deployment->taskAttemptContainerDone(container);
    noteMasterAuthorityRuntimeStateChanged();

    if (recordIt->second.state == TaskExecutionState::retrying)
    {
      pushSpinApplicationProgressToMothership(deployment, "task attempt failed; retrying"_ctv);
      deployment->state = DeploymentState::deploying;
      deployment->stateChangedAtMs = nowMs;
      deployment->architect(nullptr, false, false, false);
      deployment->schedule(nullptr);
      return;
    }

    spinApplicationFin(deployment);
    const uint64_t deploymentID = deployment->plan.config.deploymentID();
    releaseRoutableResourceLeasesForDeployment(deploymentID);
    ContainerStore::destroy(deploymentID);
    deploymentPlans.erase(deploymentID);
    deployments.erase(deploymentID);
    delete deployment;
    persistLocalRuntimeState();
  }

  void spinApplicationFin(ApplicationDeployment *deployment) override
  {
    Mothership *stream = spinApplicationMothershipFor(deployment);
    if (stream != nullptr)
    {
      if (deployment != nullptr && deployment->plan.config.type == ApplicationType::task)
      {
        String serializedRecord = {};
        if (auto it = masterAuthorityRuntimeState.taskExecutions.find(deployment->plan.config.deploymentID()); it != masterAuthorityRuntimeState.taskExecutions.end())
        {
          BitseryEngine::serialize(serializedRecord, it->second);
        }
        Message::construct(
            stream->wBuffer,
            MothershipTopic::spinApplication,
            uint8_t(SpinApplicationResponseCode::finished),
            serializedRecord);
      }
      else
      {
        Message::construct(
            stream->wBuffer,
            MothershipTopic::spinApplication,
            uint8_t(SpinApplicationResponseCode::finished));
      }
      (void)flushActiveMothershipSendBuffer(stream, "spin-application-fin");
    }

    clearSpinApplicationMothership(deployment);
  }

  class ManagedAddMachinesWork {
  public:

    ManagedAddMachinesWork()
        : requiredBrainCount(0)
    {}

    Vector<CreateMachinesInstruction> createdMachines;
    uint32_t requiredBrainCount;

    bool empty(void) const
    {
      return createdMachines.empty() && requiredBrainCount == 0;
    }
  };

  static bool managedMachineSchemaMatchesClusterMachine(const ClusterMachine& machine, const ProdigyManagedMachineSchema& managedSchema)
  {
    return machine.source == ClusterMachineSource::created && machine.backing == ClusterMachineBacking::cloud && machine.kind == managedSchema.kind && machine.cloudPresent() && machine.lifetime == managedSchema.lifetime && machine.cloud.schema.equals(managedSchema.schema) && machine.cloud.providerMachineType.equals(managedSchema.providerMachineType) && (managedSchema.kind != MachineConfig::MachineKind::vm || managedSchema.vmImageURI.size() == 0 || machine.vmImageURI.equals(managedSchema.vmImageURI));
  }

  static bool managedCreatedClusterMachineRemovalPriority(const ClusterMachine *lhs, const ClusterMachine *rhs)
  {
    if ((lhs->isBrain == false) != (rhs->isBrain == false))
    {
      return lhs->isBrain == false;
    }

    if (lhs->creationTimeMs != rhs->creationTimeMs)
    {
      return lhs->creationTimeMs > rhs->creationTimeMs;
    }

    return std::lexicographical_compare(
        lhs->cloud.schema.data(),
        lhs->cloud.schema.data() + lhs->cloud.schema.size(),
        rhs->cloud.schema.data(),
        rhs->cloud.schema.data() + rhs->cloud.schema.size());
  }

  bool buildManagedMachineSchemaRequest(const ClusterTopology& topology, AddMachines& request, ManagedAddMachinesWork& work, String *failure = nullptr)
  {
    request = {};
    work = ManagedAddMachinesWork();
    if (failure)
    {
      failure->clear();
    }

    request.clusterUUID = brainConfig.clusterUUID;
    request.architecture = brainConfig.architecture;
    request.bootstrapSshUser = brainConfig.bootstrapSshUser;
    request.bootstrapSshKeyPackage = brainConfig.bootstrapSshKeyPackage;
    request.bootstrapSshHostKeyPackage = brainConfig.bootstrapSshHostKeyPackage;
    request.bootstrapSshPrivateKeyPath = brainConfig.bootstrapSshPrivateKeyPath;
    request.remoteProdigyPath = brainConfig.remoteProdigyPath;
    request.controlSocketPath = brainConfig.controlSocketPath;
    work.requiredBrainCount = brainConfig.requiredBrainCount;

    auto removedMachineAlreadyCounted = [&](const ClusterMachine& machine) -> bool {
      for (const ClusterMachine& removedMachine : request.removedMachines)
      {
        if (removedMachine.sameIdentityAs(machine))
        {
          return true;
        }
      }

      return false;
    };

    for (const ClusterMachine& existingMachine : topology.machines)
    {
      if (existingMachine.source != ClusterMachineSource::created)
      {
        continue;
      }

      bool wanted = false;
      for (const ProdigyManagedMachineSchema& managedSchema : masterAuthorityRuntimeState.machineSchemas)
      {
        if (managedMachineSchemaMatchesClusterMachine(existingMachine, managedSchema))
        {
          wanted = true;
          break;
        }
      }

      if (wanted == false)
      {
        request.removedMachines.push_back(existingMachine);
      }
    }

    for (const ProdigyManagedMachineSchema& managedSchema : masterAuthorityRuntimeState.machineSchemas)
    {
      Vector<const ClusterMachine *> matches = {};
      for (const ClusterMachine& existingMachine : topology.machines)
      {
        if (removedMachineAlreadyCounted(existingMachine))
        {
          continue;
        }

        if (managedMachineSchemaMatchesClusterMachine(existingMachine, managedSchema))
        {
          matches.push_back(&existingMachine);
        }
      }

      if (matches.size() <= managedSchema.budget)
      {
        continue;
      }

      std::sort(matches.begin(), matches.end(), managedCreatedClusterMachineRemovalPriority);
      uint32_t nRemove = uint32_t(matches.size()) - managedSchema.budget;
      for (uint32_t index = 0; index < nRemove; ++index)
      {
        request.removedMachines.push_back(*matches[index]);
      }
    }

    uint32_t finalBrainCount = clusterTopologyBrainCount(topology);
    for (const ClusterMachine& removedMachine : request.removedMachines)
    {
      if (removedMachine.isBrain)
      {
        finalBrainCount -= 1;
      }
    }

    uint32_t remainingBrains = (brainConfig.requiredBrainCount > finalBrainCount)
                                   ? (brainConfig.requiredBrainCount - finalBrainCount)
                                   : 0;

    if (remainingBrains > 0)
    {
      uint32_t brainsNeedingSlots = remainingBrains;
      for (const ProdigyManagedMachineSchema& managedSchema : masterAuthorityRuntimeState.machineSchemas)
      {
        uint32_t existingCount = 0;
        Vector<const ClusterMachine *> replaceableMachines = {};
        for (const ClusterMachine& existingMachine : topology.machines)
        {
          if (removedMachineAlreadyCounted(existingMachine))
          {
            continue;
          }

          if (managedMachineSchemaMatchesClusterMachine(existingMachine, managedSchema) == false)
          {
            continue;
          }

          existingCount += 1;
          if (existingMachine.isBrain == false)
          {
            replaceableMachines.push_back(&existingMachine);
          }
        }

        uint32_t freeSlots = (managedSchema.budget > existingCount)
                                 ? (managedSchema.budget - existingCount)
                                 : 0;

        if (brainsNeedingSlots <= freeSlots)
        {
          brainsNeedingSlots = 0;
          break;
        }

        brainsNeedingSlots -= freeSlots;
        if (replaceableMachines.empty())
        {
          continue;
        }

        std::sort(replaceableMachines.begin(), replaceableMachines.end(), managedCreatedClusterMachineRemovalPriority);
        uint32_t nReplace = std::min<uint32_t>(uint32_t(replaceableMachines.size()), brainsNeedingSlots);
        for (uint32_t index = 0; index < nReplace; ++index)
        {
          request.removedMachines.push_back(*replaceableMachines[index]);
        }

        brainsNeedingSlots -= nReplace;
        if (brainsNeedingSlots == 0)
        {
          break;
        }
      }
    }

    for (const ProdigyManagedMachineSchema& managedSchema : masterAuthorityRuntimeState.machineSchemas)
    {
      uint32_t existingCount = 0;
      for (const ClusterMachine& existingMachine : topology.machines)
      {
        if (removedMachineAlreadyCounted(existingMachine))
        {
          continue;
        }

        if (managedMachineSchemaMatchesClusterMachine(existingMachine, managedSchema))
        {
          existingCount += 1;
        }
      }

      if (existingCount >= managedSchema.budget)
      {
        continue;
      }

      uint32_t createCount = managedSchema.budget - existingCount;
      if (createCount == 0)
      {
        continue;
      }

      auto appendInstruction = [&](uint32_t instructionCount, bool isBrainMachine) -> void {
        if (instructionCount == 0)
        {
          return;
        }

        CreateMachinesInstruction instruction = {};
        instruction.kind = managedSchema.kind;
        instruction.lifetime = managedSchema.lifetime;
        instruction.backing = ClusterMachineBacking::cloud;
        instruction.cloud.schema = managedSchema.schema;
        instruction.cloud.providerMachineType = managedSchema.providerMachineType;
        instruction.count = instructionCount;
        instruction.isBrain = isBrainMachine;
        instruction.region = managedSchema.region;
        instruction.zone = managedSchema.zone;
        work.createdMachines.push_back(std::move(instruction));
      };

      uint32_t brainCreateCount = std::min(createCount, remainingBrains);
      appendInstruction(brainCreateCount, true);
      appendInstruction(createCount - brainCreateCount, false);
      remainingBrains -= brainCreateCount;
    }

    if (remainingBrains > 0)
    {
      if (failure)
      {
        failure->assign("cluster machineSchemas cannot satisfy nBrains");
      }
      request = {};
      work = ManagedAddMachinesWork();
      return false;
    }

    return true;
  }

  bool reconcileManagedMachineSchemas(
      String *failure = nullptr,
      ProdigyTimingAttribution *timingAttribution = nullptr,
      ClusterTopology *reconciledTopology = nullptr)
  {
    if (failure)
    {
      failure->clear();
    }
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
    if (timingAttribution != nullptr)
    {
      *timingAttribution = {};
    }
#else
    (void)timingAttribution;
#endif
    auto loadReconciledTopologyOutput = [&](const String& topologyFailure) -> bool {
      if (reconciledTopology == nullptr)
      {
        return true;
      }

      *reconciledTopology = {};
      if (loadOrPersistAuthoritativeClusterTopology(*reconciledTopology))
      {
        return true;
      }

      if (failure)
      {
        failure->assign(topologyFailure);
      }

      return false;
    };

    PRODIGY_DEBUG_LOG( "prodigy managedSchemas-reconcile-begin master=%d schemas=%u\n",
                 int(weAreMaster),
                 uint32_t(masterAuthorityRuntimeState.machineSchemas.size()));
    PRODIGY_DEBUG_FLUSH();
    if (weAreMaster == false)
    {
      return loadReconciledTopologyOutput("authoritative cluster topology unavailable after machine schema reconcile"_ctv);
    }

    if (masterAuthorityRuntimeState.machineSchemas.empty())
    {
      return loadReconciledTopologyOutput("authoritative cluster topology unavailable after machine schema reconcile"_ctv);
    }

    ClusterTopology currentTopology = {};
    if (loadOrPersistAuthoritativeClusterTopology(currentTopology) == false)
    {
      if (failure)
      {
        failure->assign("authoritative cluster topology unavailable"_ctv);
      }
      return false;
    }

    AddMachines request = {};
    ManagedAddMachinesWork work = ManagedAddMachinesWork();
    if (buildManagedMachineSchemaRequest(currentTopology, request, work, failure) == false)
    {
      return false;
    }

    PRODIGY_DEBUG_LOG( "prodigy managedSchemas-reconcile-built adopted=%u ready=%u removed=%u created=%u requiredBrains=%u topologyMachines=%u\n",
                 uint32_t(request.adoptedMachines.size()),
                 uint32_t(request.readyMachines.size()),
                 uint32_t(request.removedMachines.size()),
                 uint32_t(work.createdMachines.size()),
                 unsigned(work.requiredBrainCount),
                 uint32_t(currentTopology.machines.size()));
    PRODIGY_DEBUG_FLUSH();

    if (work.createdMachines.empty() && request.removedMachines.empty())
    {
      PRODIGY_DEBUG_LOG( "prodigy managedSchemas-reconcile-noop topologyMachines=%u\n",
                   uint32_t(currentTopology.machines.size()));
      PRODIGY_DEBUG_FLUSH();
      if (reconciledTopology != nullptr)
      {
        *reconciledTopology = currentTopology;
      }
      return true;
    }

    AddMachines response = {};
    PRODIGY_DEBUG_LOG( "prodigy managedSchemas-reconcile-dispatch created=%u removed=%u\n",
                 uint32_t(work.createdMachines.size()),
                 uint32_t(request.removedMachines.size()));
    PRODIGY_DEBUG_FLUSH();
    addMachines(nullptr, std::move(request), std::move(work), &response);
    PRODIGY_DEBUG_LOG( "prodigy managedSchemas-reconcile-result success=%d failureBytes=%zu hasTopology=%d topologyMachines=%u\n",
                 int(response.success),
                 size_t(response.failure.size()),
                 int(response.hasTopology),
                 (response.hasTopology ? uint32_t(response.topology.machines.size()) : 0u));
    PRODIGY_DEBUG_FLUSH();
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
    if (timingAttribution != nullptr && response.hasTimingAttribution)
    {
      *timingAttribution = response.timingAttribution;
    }
#endif
    if (response.success == false)
    {
      if (failure)
      {
        *failure = response.failure;
      }
      return false;
    }

    if (reconciledTopology != nullptr)
    {
      if (response.hasTopology)
      {
        *reconciledTopology = std::move(response.topology);
      }
      else
      {
        *reconciledTopology = std::move(currentTopology);
      }
    }

    return true;
  }

  void addMachines(Mothership *mothership, AddMachines request, ManagedAddMachinesWork managedWork = ManagedAddMachinesWork(), AddMachines *capturedResponse = nullptr)
  {
    AddMachines response = {};
    response.success = false;
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
    uint64_t addMachinesStartNs = Time::now<TimeResolution::ns>();
    uint64_t addMachinesProviderWaitNs = 0;
#endif
    PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-begin adopted=%u ready=%u removed=%u created=%u requiredBrains=%u stream=%p fd=%d fslot=%d master=%d\n",
                 uint32_t(request.adoptedMachines.size()),
                 uint32_t(request.readyMachines.size()),
                 uint32_t(request.removedMachines.size()),
                 uint32_t(managedWork.createdMachines.size()),
                 unsigned(managedWork.requiredBrainCount),
                 static_cast<void *>(mothership),
                 (mothership ? mothership->fd : -1),
                 (mothership ? mothership->fslot : -1),
                 int(weAreMaster));
    PRODIGY_DEBUG_FLUSH();

    const bool readOnlyTopologyRequest = request.adoptedMachines.empty() && request.readyMachines.empty() && request.removedMachines.empty() && managedWork.createdMachines.empty();
    ClusterTopology currentTopology = {};
    if (mothership != nullptr && managedWork.empty() == false)
    {
      response.failure.assign("addMachines only supports adopted/ready/removed machines"_ctv);
    }
    else if (loadOrPersistAuthoritativeClusterTopology(currentTopology) == false)
    {
      response.failure.assign("authoritative cluster topology unavailable"_ctv);
    }
    else
    {
      ClusterTopology targetTopology = currentTopology;
      uint32_t addedBrainCount = 0;
      uint64_t pendingAddMachinesOperationID = 0;
      Vector<ClusterMachine> machinesToBootstrap;
      Vector<ClusterMachine> startedMachines;
      Vector<ClusterMachine> streamedBootstrapQueuedMachines;
      std::vector<Machine *> createdProvisionedSnapshots;
      Vector<ClusterMachine> removedMachinesToDecommission;
      bool requireSynchronousBootstrap = (capturedResponse != nullptr && mothership == nullptr);
      bool bootstrapCanSuspend = (canSuspendRemoteBootstrap() && requireSynchronousBootstrap == false);
      bool incrementalCreatedBootstrapUsesBlocking = requireSynchronousBootstrap && iaas->supportsIncrementalProvisioningCallbacks();
      bool incrementalCreatedBootstrapUsesCoordinator = bootstrapCanSuspend && iaas->supportsIncrementalProvisioningCallbacks();
      bool incrementalCreatedBootstrapSupported = incrementalCreatedBootstrapUsesBlocking || incrementalCreatedBootstrapUsesCoordinator;
      ProdigyRemoteBootstrapCoordinator bootstrapCoordinator = {};
      ProdigyRemoteBootstrapBundleApprovalCache bootstrapBundleApprovalCache = {};
      PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-bootstrap-mode sync=%d canSuspend=%d providerIncremental=%d blocking=%d coordinator=%d supported=%d capturedResponse=%p\n",
                   int(requireSynchronousBootstrap),
                   int(bootstrapCanSuspend),
                   int(iaas->supportsIncrementalProvisioningCallbacks()),
                   int(incrementalCreatedBootstrapUsesBlocking),
                   int(incrementalCreatedBootstrapUsesCoordinator),
                   int(incrementalCreatedBootstrapSupported),
                   static_cast<void *>(capturedResponse));
      PRODIGY_DEBUG_FLUSH();

      auto cleanupProvisionedSnapshots = [&](bool destroyProviderMachines) -> void {
        for (Machine *snapshot : createdProvisionedSnapshots)
        {
          if (destroyProviderMachines)
          {
            (void)queueMachineDestroy(*snapshot);
          }

          prodigyDestroyMachineSnapshot(snapshot);
        }

        createdProvisionedSnapshots.clear();
      };

      auto startedBootstrapContainsMachine = [&](const ClusterMachine& machine) -> bool {
        return prodigyFindClusterMachineByIdentity(startedMachines, machine) != nullptr;
      };

      auto bootstrapQueueContainsMachine = [&](const ClusterMachine& machine) -> bool {
        return prodigyFindClusterMachineByIdentity(machinesToBootstrap, machine) != nullptr;
      };

      auto streamedBootstrapQueueContainsMachine = [&](const ClusterMachine& machine) -> bool {
        return prodigyFindClusterMachineByIdentity(streamedBootstrapQueuedMachines, machine) != nullptr;
      };

      class AddMachinesProvisioningProgressSink final : public BrainIaaSMachineProvisioningProgressSink {
      private:

        Brain *owner = nullptr;
        Mothership *mothership = nullptr;
        const AddMachines *request = nullptr;
        const CreateMachinesInstruction *instruction = nullptr;
        const MachineConfig *machineConfig = nullptr;
        ClusterTopology *targetTopology = nullptr;
        Vector<ClusterMachine> *machinesToBootstrap = nullptr;
        Vector<ClusterMachine> *startedMachines = nullptr;
        Vector<ClusterMachine> *streamedBootstrapQueuedMachines = nullptr;
        uint32_t *addedBrainCount = nullptr;
        uint64_t *pendingOperationID = nullptr;
        ProdigyRemoteBootstrapCoordinator *bootstrapCoordinator = nullptr;
        ProdigyRemoteBootstrapBundleApprovalCache *bootstrapBundleApprovalCache = nullptr;
        String *failure = nullptr;
        bool incrementalCreatedBootstrapBlocking = false;
        bool incrementalCreatedBootstrapCoordinator = false;

      public:

        AddMachinesProvisioningProgressSink(Brain *brain, Mothership *stream)
            : owner(brain),
              mothership(stream)
        {}

        void configureIncrementalCreatedBootstrap(
            const AddMachines *activeRequest,
            const CreateMachinesInstruction *activeInstruction,
            const MachineConfig *activeMachineConfig,
            ClusterTopology *activeTargetTopology,
            Vector<ClusterMachine> *activeMachinesToBootstrap,
            Vector<ClusterMachine> *activeStartedMachines,
            Vector<ClusterMachine> *activeStreamedBootstrapQueuedMachines,
            uint32_t *activeAddedBrainCount,
            uint64_t *activePendingOperationID,
            ProdigyRemoteBootstrapCoordinator *activeBootstrapCoordinator,
            ProdigyRemoteBootstrapBundleApprovalCache *activeBootstrapBundleApprovalCache,
            String *activeFailure,
            bool blockingEnabled,
            bool coordinatorEnabled)
        {
          request = activeRequest;
          instruction = activeInstruction;
          machineConfig = activeMachineConfig;
          targetTopology = activeTargetTopology;
          machinesToBootstrap = activeMachinesToBootstrap;
          startedMachines = activeStartedMachines;
          streamedBootstrapQueuedMachines = activeStreamedBootstrapQueuedMachines;
          addedBrainCount = activeAddedBrainCount;
          pendingOperationID = activePendingOperationID;
          bootstrapCoordinator = activeBootstrapCoordinator;
          bootstrapBundleApprovalCache = activeBootstrapBundleApprovalCache;
          failure = activeFailure;
          incrementalCreatedBootstrapBlocking = blockingEnabled;
          incrementalCreatedBootstrapCoordinator = coordinatorEnabled;
        }

        void clearIncrementalCreatedBootstrap(void)
        {
          request = nullptr;
          instruction = nullptr;
          machineConfig = nullptr;
          targetTopology = nullptr;
          machinesToBootstrap = nullptr;
          startedMachines = nullptr;
          streamedBootstrapQueuedMachines = nullptr;
          addedBrainCount = nullptr;
          pendingOperationID = nullptr;
          bootstrapCoordinator = nullptr;
          bootstrapBundleApprovalCache = nullptr;
          failure = nullptr;
          incrementalCreatedBootstrapBlocking = false;
          incrementalCreatedBootstrapCoordinator = false;
        }

        void reportMachineProvisioningAccepted(const String& cloudID) override
        {
          if ((incrementalCreatedBootstrapBlocking == false && incrementalCreatedBootstrapCoordinator == false) || owner == nullptr || request == nullptr || instruction == nullptr || machineConfig == nullptr || targetTopology == nullptr || pendingOperationID == nullptr || *pendingOperationID == 0 || failure == nullptr || failure->size() > 0 || cloudID.size() == 0)
          {
#if PRODIGY_DEBUG
            basics_log("addMachines incremental accepted-skip cloudID=%.*s blocking=%d coordinator=%d owner=%p request=%p instruction=%p machineConfig=%p targetTopology=%p pendingOpPtr=%p pendingOp=%llu failureBytes=%llu\n",
                       int(cloudID.size()),
                       reinterpret_cast<const char *>(cloudID.data()),
                       int(incrementalCreatedBootstrapBlocking),
                       int(incrementalCreatedBootstrapCoordinator),
                       static_cast<void *>(owner),
                       static_cast<const void *>(request),
                       static_cast<const void *>(instruction),
                       static_cast<const void *>(machineConfig),
                       static_cast<void *>(targetTopology),
                       static_cast<void *>(pendingOperationID),
                       (unsigned long long)((pendingOperationID != nullptr) ? *pendingOperationID : 0ULL),
                       (unsigned long long)(failure != nullptr ? failure->size() : 0ULL));
#endif
            return;
          }

#if PRODIGY_DEBUG
          basics_log("addMachines incremental accepted cloudID=%.*s op=%llu mode=%s\n",
                     int(cloudID.size()),
                     reinterpret_cast<const char *>(cloudID.data()),
                     (unsigned long long)*pendingOperationID,
                     incrementalCreatedBootstrapCoordinator ? "coordinator" : "blocking");
#endif

          ClusterMachine createdMachine = {};
          prodigyPopulateCreatedClusterMachineFromAcceptance(
              createdMachine,
              cloudID,
              *instruction,
              *machineConfig,
              request->bootstrapSshUser,
              request->bootstrapSshPrivateKeyPath,
              request->bootstrapSshHostKeyPackage.publicKeyOpenSSH,
              owner->brainConfig.machineReservedResources);
          bool inserted = false;
          if (prodigyUpsertClusterMachineByIdentity(targetTopology->machines, createdMachine, &inserted))
          {
            if (inserted && createdMachine.isBrain && addedBrainCount != nullptr)
            {
              *addedBrainCount += 1;
            }
          }

          (void)owner->upsertPendingAddMachinesOperationMachine(*pendingOperationID, createdMachine, false);
        }

        void reportMachineProvisioned(const Machine& machine) override
        {
          if ((incrementalCreatedBootstrapBlocking == false && incrementalCreatedBootstrapCoordinator == false) || owner == nullptr || request == nullptr || instruction == nullptr || machineConfig == nullptr || targetTopology == nullptr || machinesToBootstrap == nullptr || startedMachines == nullptr || pendingOperationID == nullptr || *pendingOperationID == 0 || failure == nullptr || failure->size() > 0 || machine.cloudID.size() == 0)
          {
#if PRODIGY_DEBUG
            basics_log("addMachines incremental provisioned-skip cloudID=%.*s blocking=%d coordinator=%d owner=%p request=%p instruction=%p machineConfig=%p targetTopology=%p machinesToBootstrap=%p startedMachines=%p pendingOpPtr=%p pendingOp=%llu failureBytes=%llu cloudIDBytes=%llu\n",
                       int(machine.cloudID.size()),
                       reinterpret_cast<const char *>(machine.cloudID.data()),
                       int(incrementalCreatedBootstrapBlocking),
                       int(incrementalCreatedBootstrapCoordinator),
                       static_cast<void *>(owner),
                       static_cast<const void *>(request),
                       static_cast<const void *>(instruction),
                       static_cast<const void *>(machineConfig),
                       static_cast<void *>(targetTopology),
                       static_cast<void *>(machinesToBootstrap),
                       static_cast<void *>(startedMachines),
                       static_cast<void *>(pendingOperationID),
                       (unsigned long long)((pendingOperationID != nullptr) ? *pendingOperationID : 0ULL),
                       (unsigned long long)(failure != nullptr ? failure->size() : 0ULL),
                       (unsigned long long)machine.cloudID.size());
#endif
            return;
          }

          ClusterMachine createdMachine = {};
          prodigyPopulateCreatedClusterMachineFromAcceptance(
              createdMachine,
              machine.cloudID,
              *instruction,
              *machineConfig,
              request->bootstrapSshUser,
              request->bootstrapSshPrivateKeyPath,
              request->bootstrapSshHostKeyPackage.publicKeyOpenSSH,
              owner->brainConfig.machineReservedResources);
          prodigyRefreshCreatedClusterMachineFromSnapshot(
              createdMachine,
              const_cast<Machine *>(&machine),
              request->bootstrapSshUser,
              request->bootstrapSshPrivateKeyPath,
              request->bootstrapSshHostKeyPackage.publicKeyOpenSSH,
              owner->brainConfig.machineReservedResources);

          bool inserted = false;
          if (prodigyUpsertClusterMachineByIdentity(targetTopology->machines, createdMachine, &inserted))
          {
            prodigyNormalizeClusterTopologyPeerAddresses(*targetTopology);
            if (inserted && createdMachine.isBrain && addedBrainCount != nullptr)
            {
              *addedBrainCount += 1;
            }
          }

#if PRODIGY_DEBUG
          basics_log("addMachines incremental provisioned cloudID=%s op=%llu ssh=%s:%u mode=%s targetMachines=%u queued=%u started=%u streamed=%u inserted=%d owned=%u/%u/%u\n",
                     createdMachine.cloud.cloudID.c_str(),
                     (unsigned long long)*pendingOperationID,
                     createdMachine.ssh.address.c_str(),
                     unsigned(createdMachine.ssh.port),
                     incrementalCreatedBootstrapCoordinator ? "coordinator" : "blocking",
                     uint32_t(targetTopology->machines.size()),
                     uint32_t(machinesToBootstrap->size()),
                     uint32_t(startedMachines->size()),
                     uint32_t(streamedBootstrapQueuedMachines != nullptr ? streamedBootstrapQueuedMachines->size() : 0u),
                     int(inserted),
                     createdMachine.ownedLogicalCores,
                     createdMachine.ownedMemoryMB,
                     createdMachine.ownedStorageMB);
#endif

          (void)owner->upsertPendingAddMachinesOperationMachine(*pendingOperationID, createdMachine, true);
          if (prodigyFindClusterMachineByIdentity(*startedMachines, createdMachine) != nullptr)
          {
            (void)owner->erasePendingAddMachinesOperationBootstrapMachine(*pendingOperationID, createdMachine);
            prodigyEraseClusterMachineByIdentity(*machinesToBootstrap, createdMachine);
            return;
          }

          if (prodigyFindClusterMachineByIdentity(*machinesToBootstrap, createdMachine) == nullptr)
          {
            machinesToBootstrap->push_back(createdMachine);
          }

          if (incrementalCreatedBootstrapCoordinator)
          {
            if (streamedBootstrapQueuedMachines != nullptr && prodigyFindClusterMachineByIdentity(*streamedBootstrapQueuedMachines, createdMachine) != nullptr)
            {
              return;
            }

            String bootstrapFailure = {};
            if (bootstrapCoordinator != nullptr && bootstrapBundleApprovalCache != nullptr && owner->queueClusterMachineBootstrapAsync(*bootstrapCoordinator, *bootstrapBundleApprovalCache, createdMachine, *request, *targetTopology, bootstrapFailure))
            {
#if PRODIGY_DEBUG
              basics_log("addMachines incremental bootstrap-queued cloudID=%s op=%llu ssh=%s:%u mode=coordinator pendingTasks=%u openSockets=%u streamed=%u queued=%u started=%u\n",
                         createdMachine.cloud.cloudID.c_str(),
                         (unsigned long long)*pendingOperationID,
                         createdMachine.ssh.address.c_str(),
                         unsigned(createdMachine.ssh.port),
                         unsigned(bootstrapCoordinator != nullptr ? bootstrapCoordinator->pendingTasks : 0u),
                         unsigned(bootstrapCoordinator != nullptr ? bootstrapCoordinator->openSockets : 0u),
                         uint32_t(streamedBootstrapQueuedMachines != nullptr ? streamedBootstrapQueuedMachines->size() : 0u),
                         uint32_t(machinesToBootstrap->size()),
                         uint32_t(startedMachines->size()));
#endif
              if (streamedBootstrapQueuedMachines != nullptr)
              {
                streamedBootstrapQueuedMachines->push_back(createdMachine);
              }

              return;
            }

            failure->assign(bootstrapFailure.size() > 0 ? bootstrapFailure : "failed to queue streamed cluster bootstrap"_ctv);
            return;
          }

          String bootstrapFailure = {};
#if PRODIGY_DEBUG
          basics_log("addMachines incremental bootstrap-start cloudID=%s op=%llu ssh=%s:%u mode=blocking targetMachines=%u queued=%u started=%u\n",
                     createdMachine.cloud.cloudID.c_str(),
                     (unsigned long long)*pendingOperationID,
                     createdMachine.ssh.address.c_str(),
                     unsigned(createdMachine.ssh.port),
                     uint32_t(targetTopology->machines.size()),
                     uint32_t(machinesToBootstrap->size()),
                     uint32_t(startedMachines->size()));
#endif
          if (owner->bootstrapClusterMachineBlocking(createdMachine, *request, *targetTopology, bootstrapFailure, bootstrapBundleApprovalCache))
          {
#if PRODIGY_DEBUG
            basics_log("addMachines incremental bootstrap-ok cloudID=%s op=%llu ssh=%s:%u mode=blocking queued=%u started=%u\n",
                       createdMachine.cloud.cloudID.c_str(),
                       (unsigned long long)*pendingOperationID,
                       createdMachine.ssh.address.c_str(),
                       unsigned(createdMachine.ssh.port),
                       uint32_t(machinesToBootstrap->size()),
                       uint32_t(startedMachines->size() + 1));
#endif
            startedMachines->push_back(createdMachine);
            prodigyEraseClusterMachineByIdentity(*machinesToBootstrap, createdMachine);
            (void)owner->erasePendingAddMachinesOperationBootstrapMachine(*pendingOperationID, createdMachine);
            return;
          }

#if PRODIGY_DEBUG
          basics_log("addMachines incremental bootstrap-failed cloudID=%s op=%llu ssh=%s:%u mode=blocking failure=%s\n",
                     createdMachine.cloud.cloudID.c_str(),
                     (unsigned long long)*pendingOperationID,
                     createdMachine.ssh.address.c_str(),
                     unsigned(createdMachine.ssh.port),
                     bootstrapFailure.c_str());
#endif
          owner->stopClusterMachineBootstrap(createdMachine);
          failure->assign(bootstrapFailure);
        }

        void reportMachineProvisioningProgress(const Vector<MachineProvisioningProgress>& progress) override
        {
          if (owner == nullptr || mothership == nullptr || progress.empty())
          {
            return;
          }

          if (Ring::socketIsClosing(mothership))
          {
            return;
          }

          if ((mothership->isFixedFile && mothership->fslot < 0) || (mothership->isFixedFile == false && mothership->fd < 0))
          {
            return;
          }

          AddMachines response = {};
          response.isProgress = true;
          response.provisioningProgress = progress;

          String serializedResponse = {};
          BitseryEngine::serialize(serializedResponse, response);

          String framedResponse = {};
          Message::construct(framedResponse, MothershipTopic::addMachines, serializedResponse);
          PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-progress entries=%u serializedBytes=%zu stream=%p fd=%d fslot=%d\n",
                       uint32_t(progress.size()),
                       size_t(framedResponse.size()),
                       static_cast<void *>(mothership),
                       mothership->fd,
                       mothership->fslot);
          PRODIGY_DEBUG_FLUSH();
          mothership->wBuffer.append(framedResponse);
          (void)owner->flushActiveMothershipSendBuffer(mothership, "addmachines-progress");
        }
      };

      AddMachinesProvisioningProgressSink provisioningProgressSink(this, mothership);

      for (const ClusterMachine& requestedMachine : request.adoptedMachines)
      {
        String requestedLabel = {};
        requestedMachine.renderIdentityLabel(requestedLabel);
        PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-adopted-normalize-start machine=%.*s\n",
                     int(requestedLabel.size()),
                     requestedLabel.c_str());
        PRODIGY_DEBUG_FLUSH();

        ClusterMachine normalizedMachine = {};
        if (normalizeAdoptedClusterMachine(requestedMachine, request.bootstrapSshUser, request.bootstrapSshPrivateKeyPath, normalizedMachine, response.failure) == false)
        {
          break;
        }
        String normalizedLabel = {};
        normalizedMachine.renderIdentityLabel(normalizedLabel);
        PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-adopted-normalize-ok machine=%.*s ssh=%.*s:%u privateAddresses=%u publicAddresses=%u\n",
                     int(normalizedLabel.size()),
                     normalizedLabel.c_str(),
                     int(normalizedMachine.ssh.address.size()),
                     normalizedMachine.ssh.address.c_str(),
                     unsigned(normalizedMachine.ssh.port),
                     uint32_t(normalizedMachine.addresses.privateAddresses.size()),
                     uint32_t(normalizedMachine.addresses.publicAddresses.size()));
        PRODIGY_DEBUG_FLUSH();

        if (clusterTopologyContainsMachineIdentity(targetTopology, normalizedMachine))
        {
          String label = {};
          normalizedMachine.renderIdentityLabel(label);
          response.failure.snprintf<"adopted machine '{}' conflicts with existing topology"_ctv>(label);
          break;
        }

        if (probeCandidateBrainReachability(currentTopology, normalizedMachine, response) == false)
        {
          break;
        }
        PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-adopted-reachability-ok machine=%.*s probeAddress=%.*s results=%u\n",
                     int(normalizedLabel.size()),
                     normalizedLabel.c_str(),
                     int(response.reachabilityProbeAddress.size()),
                     response.reachabilityProbeAddress.c_str(),
                     uint32_t(response.reachabilityResults.size()));
        PRODIGY_DEBUG_FLUSH();

        ClusterTopology candidateTopology = targetTopology;
        candidateTopology.machines.push_back(normalizedMachine);
        prodigyNormalizeClusterTopologyPeerAddresses(candidateTopology);
        normalizedMachine = candidateTopology.machines.back();

        targetTopology = std::move(candidateTopology);
        machinesToBootstrap.push_back(normalizedMachine);
        if (normalizedMachine.isBrain)
        {
          addedBrainCount += 1;
        }
      }

      if (response.failure.size() == 0)
      {
        for (const ClusterMachine& removedMachine : request.removedMachines)
        {
          bool removedAny = false;
          auto it = std::remove_if(targetTopology.machines.begin(), targetTopology.machines.end(), [&](const ClusterMachine& existingMachine) {
            if (existingMachine.sameIdentityAs(removedMachine) == false)
            {
              return false;
            }

            removedAny = true;
            return true;
          });

          if (removedAny)
          {
            targetTopology.machines.erase(it, targetTopology.machines.end());
            removedMachinesToDecommission.push_back(removedMachine);
          }
        }
      }

      if (response.failure.size() == 0)
      {
        for (const ClusterMachine& requestedMachine : request.readyMachines)
        {
          ClusterMachine readyMachine = requestedMachine;
          readyMachine.isBrain = requestedMachine.isBrain;
          if (clusterTopologyContainsMachineIdentity(targetTopology, readyMachine))
          {
            continue;
          }

          ClusterTopology candidateTopology = targetTopology;
          candidateTopology.machines.push_back(readyMachine);
          prodigyNormalizeClusterTopologyPeerAddresses(candidateTopology);
          readyMachine = candidateTopology.machines.back();

          targetTopology = std::move(candidateTopology);
          if (readyMachine.isBrain)
          {
            addedBrainCount += 1;
          }
        }
      }

      if (response.failure.size() == 0)
      {
        for (const CreateMachinesInstruction& instruction : managedWork.createdMachines)
        {
          if (instruction.backing != ClusterMachineBacking::cloud)
          {
            response.failure.assign("created machine instruction currently requires backing=cloud"_ctv);
            break;
          }

          if (instruction.cloud.schema.size() == 0)
          {
            response.failure.assign("created machine instruction requires cloud.schema"_ctv);
            break;
          }

          if (instruction.count == 0)
          {
            response.failure.assign("created machine instruction count required"_ctv);
            break;
          }

          if (instruction.lifetime == MachineLifetime::owned)
          {
            response.failure.assign("created machine instruction lifetime 'owned' is invalid for provider-created machines"_ctv);
            break;
          }

          String schemaKey = {};
          schemaKey.assign(instruction.cloud.schema);

          auto configIt = brainConfig.configBySlug.find(schemaKey);
          if (configIt == brainConfig.configBySlug.end())
          {
            response.failure.snprintf<"unknown machine schema '{}'"_ctv>(schemaKey);
            break;
          }

          const MachineConfig& machineConfig = configIt->second;
          if (instruction.kind != machineConfig.kind)
          {
            response.failure.snprintf<"created machine kind mismatch for schema '{}'"_ctv>(schemaKey);
            break;
          }

          if (iaas->supports(machineConfig.kind) == false)
          {
            response.failure.snprintf<"current runtime environment does not support machine kind for schema '{}'"_ctv>(schemaKey);
            break;
          }

          if (iaas->supportsAutoProvision() == false)
          {
            response.failure.assign("current runtime environment does not support automatic machine provisioning"_ctv);
            break;
          }

          if (incrementalCreatedBootstrapSupported && pendingAddMachinesOperationID == 0)
          {
            pendingAddMachinesOperationID = journalAddMachinesOperation(request, targetTopology, machinesToBootstrap);
          }

          iaas->configureBootstrapSSHAccess(request.bootstrapSshUser, request.bootstrapSshKeyPackage, request.bootstrapSshHostKeyPackage, request.bootstrapSshPrivateKeyPath);
          iaas->configureProvisioningProgressSink(&provisioningProgressSink);
          provisioningProgressSink.configureIncrementalCreatedBootstrap(
              &request,
              &instruction,
              &machineConfig,
              &targetTopology,
              &machinesToBootstrap,
              &startedMachines,
              &streamedBootstrapQueuedMachines,
              &addedBrainCount,
              &pendingAddMachinesOperationID,
              &bootstrapCoordinator,
              &bootstrapBundleApprovalCache,
              &response.failure,
              incrementalCreatedBootstrapUsesBlocking,
              incrementalCreatedBootstrapUsesCoordinator);

          CoroutineStack *coro = new CoroutineStack();
          bytell_hash_set<Machine *> createdSnapshots;
          String providerError;

          PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-spinMachines-start schema=%.*s requested=%u isBrain=%d lifetime=%u\n",
                       int(schemaKey.size()),
                       schemaKey.c_str(),
                       unsigned(instruction.count),
                       int(instruction.isBrain),
                       unsigned(instruction.lifetime));
          PRODIGY_DEBUG_FLUSH();

          iaas->configureProvisioningClusterUUID(brainConfig.clusterUUID);
          iaas->configureProvisioningOperationID(pendingAddMachinesOperationID);
          uint32_t suspendIndex = coro->nextSuspendIndex();
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
          uint64_t providerWaitStartNs = Time::now<TimeResolution::ns>();
#endif
          iaas->spinMachines(coro, instruction.lifetime, machineConfig, instruction.count, instruction.isBrain, createdSnapshots, providerError);
          if (suspendIndex < coro->nextSuspendIndex())
          {
            co_await coro->suspendAtIndex(suspendIndex);
          }
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
          addMachinesProviderWaitNs += (Time::now<TimeResolution::ns>() - providerWaitStartNs);
#endif
          iaas->configureProvisioningProgressSink(nullptr);
          provisioningProgressSink.clearIncrementalCreatedBootstrap();
          delete coro;

          if (createdSnapshots.size() != instruction.count)
          {
            if (providerError.size() > 0)
            {
              response.failure = providerError;
            }
            else
            {
              response.failure.snprintf<"provider returned {itoa} created machines but {itoa} were requested"_ctv>(createdSnapshots.size(), instruction.count);
            }

            for (Machine *snapshot : createdSnapshots)
            {
              (void)queueMachineDestroy(*snapshot);
              prodigyDestroyMachineSnapshot(snapshot);
            }
            break;
          }

          std::vector<Machine *> orderedSnapshots;
          orderedSnapshots.reserve(createdSnapshots.size());
          for (Machine *snapshot : createdSnapshots)
          {
            orderedSnapshots.push_back(snapshot);
            createdProvisionedSnapshots.push_back(snapshot);
          }

          std::sort(orderedSnapshots.begin(), orderedSnapshots.end(), [&](Machine *lhs, Machine *rhs) {
            return prodigyMachineIdentityComesBefore(*lhs, *rhs);
          });

          Vector<ClusterMachine> createdMachines = {};
          for (uint32_t index = 0; index < orderedSnapshots.size(); ++index)
          {
            Machine *snapshot = orderedSnapshots[index];
            ClusterMachine createdMachine = {};
            prodigyPopulateCreatedClusterMachineFromSnapshot(createdMachine, snapshot, instruction, machineConfig, request.bootstrapSshUser, request.bootstrapSshPrivateKeyPath, request.bootstrapSshHostKeyPackage.publicKeyOpenSSH, brainConfig.machineReservedResources);

            bool duplicateCreatedIdentity = false;
            for (const ClusterMachine& pendingCreatedMachine : createdMachines)
            {
              if (pendingCreatedMachine.sameIdentityAs(createdMachine))
              {
                duplicateCreatedIdentity = true;
                break;
              }
            }

            if (duplicateCreatedIdentity)
            {
              String label = {};
              createdMachine.renderIdentityLabel(label);
              response.failure.snprintf<"created machine '{}' conflicts with existing created machine"_ctv>(label);
              break;
            }

            createdMachines.push_back(createdMachine);
          }

          if (response.failure.size() == 0 && createdMachines.empty() == false)
          {
            for (const ClusterMachine& createdMachine : createdMachines)
            {
              bool inserted = false;
              if (prodigyUpsertClusterMachineByIdentity(targetTopology.machines, createdMachine, &inserted))
              {
                if (inserted && createdMachine.isBrain)
                {
                  addedBrainCount += 1;
                }
              }
            }

            prodigyNormalizeClusterTopologyPeerAddresses(targetTopology);
            for (const ClusterMachine& createdMachine : createdMachines)
            {
              const ClusterMachine *normalizedMachine = prodigyFindClusterMachineByIdentity(targetTopology.machines, createdMachine);
              if (normalizedMachine == nullptr)
              {
                continue;
              }

              if (startedBootstrapContainsMachine(*normalizedMachine) == false && bootstrapQueueContainsMachine(*normalizedMachine) == false)
              {
                machinesToBootstrap.push_back(*normalizedMachine);
              }

              if (pendingAddMachinesOperationID > 0)
              {
                (void)upsertPendingAddMachinesOperationMachine(
                    pendingAddMachinesOperationID,
                    *normalizedMachine,
                    bootstrapQueueContainsMachine(*normalizedMachine));
              }
            }
          }

#if PRODIGY_DEBUG
          PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-spinMachines-done schema=%.*s requested=%u snapshots=%zu createdMachines=%u started=%u queued=%u streamedQueued=%u providerErrorBytes=%zu pendingOperationID=%llu\n",
                       int(schemaKey.size()),
                       schemaKey.c_str(),
                       unsigned(instruction.count),
                       orderedSnapshots.size(),
                       uint32_t(createdMachines.size()),
                       uint32_t(startedMachines.size()),
                       uint32_t(machinesToBootstrap.size()),
                       uint32_t(streamedBootstrapQueuedMachines.size()),
                       size_t(providerError.size()),
                       (unsigned long long)pendingAddMachinesOperationID);
          PRODIGY_DEBUG_FLUSH();
#endif

          if (response.failure.size() > 0)
          {
            break;
          }
        }
      }

      if (response.failure.size() == 0 && readOnlyTopologyRequest)
      {
        response.success = true;
        response.hasTopology = true;
        response.topology = currentTopology;
      }

      if (response.failure.size() == 0 && readOnlyTopologyRequest == false)
      {
        uint32_t finalBrainCount = clusterTopologyBrainCount(targetTopology);
        if (managedWork.requiredBrainCount > 0 && finalBrainCount < managedWork.requiredBrainCount)
        {
          response.failure.snprintf<"final brain count {itoa} is below requiredBrainCount {itoa}"_ctv>(finalBrainCount, managedWork.requiredBrainCount);
        }

        if (response.failure.size() > 0)
        {
          goto addmachines_finalize;
        }

        if (addedBrainCount > 0 && clusterTopologyBrainCountSatisfiesQuorum(finalBrainCount) == false)
        {
          response.failure.snprintf<"adding brain machines requires final brain count to be odd and >= 3 (got {itoa})"_ctv>(finalBrainCount);
        }
      }

      if (readOnlyTopologyRequest == false)
      {
        if (response.failure.size() == 0 && pendingAddMachinesOperationID == 0)
        {
          pendingAddMachinesOperationID = journalAddMachinesOperation(request, targetTopology, machinesToBootstrap);
        }

        auto rollbackBootstrapped = [this](const ClusterMachine& clusterMachine) -> void {
          stopClusterMachineBootstrap(clusterMachine);
        };

        // Internal managed-schema reconciliation captures an immediate response and cannot
        // suspend out while follower bootstrap is still in flight.
        if (canSuspendRemoteBootstrap() == false || requireSynchronousBootstrap)
        {
#if PRODIGY_DEBUG
          PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-bootstrap-phase mode=blocking started=%u queued=%u streamedQueued=%u pendingOperationID=%llu\n",
                       uint32_t(startedMachines.size()),
                       uint32_t(machinesToBootstrap.size()),
                       uint32_t(streamedBootstrapQueuedMachines.size()),
                       (unsigned long long)pendingAddMachinesOperationID);
          PRODIGY_DEBUG_FLUSH();
#endif
          if (response.failure.size() == 0 && prodigyBootstrapItemsConcurrently<ClusterMachine>(
                                                  machinesToBootstrap,
                                                  [this, &request, &targetTopology, &bootstrapBundleApprovalCache](const ClusterMachine& clusterMachine, String& failure) -> bool {
                                                    return bootstrapClusterMachineBlocking(clusterMachine, request, targetTopology, failure, &bootstrapBundleApprovalCache);
                                                  },
                                                  rollbackBootstrapped,
                                                  &startedMachines,
                                                  response.failure) == false)
          {
            startedMachines.clear();
          }
        }
        else
        {
#if PRODIGY_DEBUG
          PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-bootstrap-phase mode=coordinator started=%u queued=%u streamedQueued=%u pendingOperationID=%llu\n",
                       uint32_t(startedMachines.size()),
                       uint32_t(machinesToBootstrap.size()),
                       uint32_t(streamedBootstrapQueuedMachines.size()),
                       (unsigned long long)pendingAddMachinesOperationID);
          PRODIGY_DEBUG_FLUSH();
#endif
          if (response.failure.size() == 0)
          {
            for (const ClusterMachine& clusterMachine : machinesToBootstrap)
            {
              if (streamedBootstrapQueueContainsMachine(clusterMachine))
              {
                continue;
              }

              if (queueClusterMachineBootstrapAsync(
                      bootstrapCoordinator,
                      bootstrapBundleApprovalCache,
                      clusterMachine,
                      request,
                      targetTopology,
                      response.failure) == false)
              {
                break;
              }

              streamedBootstrapQueuedMachines.push_back(clusterMachine);
            }
          }

          if (bootstrapCoordinator.pendingTasks > 0 || bootstrapCoordinator.openSockets > 0)
          {
            uint32_t suspendIndex = bootstrapCoordinator.nextSuspendIndex();
            bootstrapCoordinator.awaitCompletion();
            if (suspendIndex < bootstrapCoordinator.nextSuspendIndex())
            {
              co_await bootstrapCoordinator.suspendAtIndex(suspendIndex);
            }
          }

          Vector<ClusterMachine> bootstrappedMachines = {};
          String bootstrapFailure = {};
          bool bootstrapSucceeded = bootstrapCoordinator.finalize(&bootstrappedMachines, rollbackBootstrapped, bootstrapFailure);
          if (response.failure.size() == 0)
          {
            if (bootstrapSucceeded == false)
            {
              startedMachines.clear();
              response.failure = bootstrapFailure;
            }
            else
            {
              startedMachines = std::move(bootstrappedMachines);
            }
          }
          else
          {
            if (bootstrapSucceeded)
            {
              for (const ClusterMachine& clusterMachine : bootstrappedMachines)
              {
                rollbackBootstrapped(clusterMachine);
              }
            }
            startedMachines.clear();
          }
        }
      }

      if (response.failure.size() == 0 && readOnlyTopologyRequest == false)
      {
        PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-post-bootstrap started=%u targetMachines=%u currentVersion=%u\n",
                     uint32_t(startedMachines.size()),
                     uint32_t(targetTopology.machines.size()),
                     uint32_t(currentTopology.version));
        PRODIGY_DEBUG_FLUSH();
        targetTopology.version = currentTopology.version + 1;

        PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-restore-brains version=%u brains=%u\n",
                     uint32_t(targetTopology.version),
                     uint32_t(clusterTopologyBrainCount(targetTopology)));
        PRODIGY_DEBUG_FLUSH();
        restoreBrainsFromClusterTopology(targetTopology);
        PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-restore-machines version=%u machines=%u\n",
                     uint32_t(targetTopology.version),
                     uint32_t(targetTopology.machines.size()));
        PRODIGY_DEBUG_FLUSH();
        restoreMachinesFromClusterTopology(targetTopology);
        nBrains = clusterTopologyBrainCount(targetTopology);
        PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-init-peers nBrains=%u\n", uint32_t(nBrains));
        PRODIGY_DEBUG_FLUSH();
        initializeAllBrainPeersIfNeeded();

        PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-persist-topology version=%u machines=%u\n",
                     uint32_t(targetTopology.version),
                     uint32_t(targetTopology.machines.size()));
        PRODIGY_DEBUG_FLUSH();
        if (persistAuthoritativeClusterTopology(targetTopology) == false)
        {
          response.failure.assign("failed to persist authoritative cluster topology"_ctv);
        }
        else
        {
          PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-replicate-topology version=%u machines=%u\n",
                       uint32_t(targetTopology.version),
                       uint32_t(targetTopology.machines.size()));
          PRODIGY_DEBUG_FLUSH();
          String serializedTopology;
          BitseryEngine::serialize(serializedTopology, targetTopology);
          queueBrainReplication(BrainTopic::replicateClusterTopology, serializedTopology);

          response.success = true;
          response.hasTopology = true;
          response.topology = targetTopology;
          if (pendingAddMachinesOperationID > 0)
          {
            PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-clear-pending operationID=%llu\n",
                         (unsigned long long)pendingAddMachinesOperationID);
            PRODIGY_DEBUG_FLUSH();
            (void)erasePendingAddMachinesOperation(pendingAddMachinesOperationID);
            pendingAddMachinesOperationID = 0;
          }
        }
      }

    addmachines_finalize:
      if (response.failure.size() > 0)
      {
        PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-failure bytes=%zu text=%.*s\n",
                     size_t(response.failure.size()),
                     int(response.failure.size()),
                     response.failure.c_str());
        PRODIGY_DEBUG_FLUSH();
        for (const ClusterMachine& clusterMachine : startedMachines)
        {
          stopClusterMachineBootstrap(clusterMachine);
        }

        cleanupProvisionedSnapshots(true);
        if (pendingAddMachinesOperationID > 0)
        {
          (void)erasePendingAddMachinesOperation(pendingAddMachinesOperationID);
        }
      }
      else
      {
        cleanupProvisionedSnapshots(false);
      }
      if (response.success)
      {
        for (const ClusterMachine& removedMachine : removedMachinesToDecommission)
        {
          IPAddress peerAddress = {};
          String peerAddressText = {};
          bool havePeerAddress = removedMachine.resolvePeerAddress(peerAddress, &peerAddressText);
          uint32_t resolvedPrivate4 = 0;
          (void)removedMachine.resolvePrivate4(resolvedPrivate4);
          Vector<ClusterMachinePeerAddress> removedMachinePeerAddresses = {};
          prodigyCollectClusterMachinePeerAddresses(removedMachine, removedMachinePeerAddresses);

          Machine *machine = findMachineByIdentity(
              removedMachine.uuid,
              resolvedPrivate4,
              &removedMachinePeerAddresses,
              havePeerAddress ? &peerAddress : nullptr,
              havePeerAddress ? &peerAddressText : nullptr);
          if (machine == nullptr)
          {
            stopClusterMachineBootstrap(removedMachine);
            continue;
          }

          if (thisNeuron != nullptr && machine->uuid == thisNeuron->uuid)
          {
            continue;
          }

          decommissionMachine(machine);
        }
      }
    }

    if (response.success && managedWork.empty() && readOnlyTopologyRequest == false && weAreMaster)
    {
      String managedFailure = {};
      ClusterTopology managedTopology = {};
      if (reconcileManagedMachineSchemas(&managedFailure, nullptr, &managedTopology) == false)
      {
        response.success = false;
        response.hasTopology = false;
        response.topology = {};
        response.failure = managedFailure;
      }
      else
      {
        response.hasTopology = true;
        response.topology = std::move(managedTopology);
      }
    }
    if (response.success && readOnlyTopologyRequest == false)
    {
      armMachineUpdateTimerIfNeeded();
    }

#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
    response.hasTimingAttribution = true;
    prodigyFinalizeTimingAttribution(Time::now<TimeResolution::ns>() - addMachinesStartNs, addMachinesProviderWaitNs, response.timingAttribution);
#endif
    bool streamActive = streamIsActive(mothership);
    if (streamActive)
    {
      String serializedResponse;
      BitseryEngine::serialize(serializedResponse, response);
      PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-end success=%d failureBytes=%zu hasTopology=%d topologyMachines=%u serializedBytes=%zu stream=%p fd=%d fslot=%d\n",
                   int(response.success),
                   size_t(response.failure.size()),
                   int(response.hasTopology),
                   (response.hasTopology ? uint32_t(response.topology.machines.size()) : 0u),
                   size_t(serializedResponse.size()),
                   static_cast<void *>(mothership),
                   mothership->fd,
                   mothership->fslot);
      PRODIGY_DEBUG_FLUSH();
      Message::construct(mothership->wBuffer, MothershipTopic::addMachines, serializedResponse);
      bool sendOkay = flushActiveMothershipSendBuffer(mothership, "addmachines-final");
      if (sendOkay)
      {
        PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-finished stream=%p fd=%d fslot=%d closing=1\n",
                     static_cast<void *>(mothership),
                     mothership->fd,
                     mothership->fslot);
        PRODIGY_DEBUG_FLUSH();
        queueCloseAfterSendDrain(mothership);
      }
    }

    if (capturedResponse != nullptr)
    {
      if (streamActive)
      {
        *capturedResponse = response;
      }
      else
      {
        *capturedResponse = std::move(response);
      }
    }
  }

  void mothershipHandler(Mothership *mothership, Message *message)
  {
    uint8_t *args = message->args;
    PRODIGY_DEBUG_LOG( "prodigy mothership handler topic=%s(%u) size=%u stream=%p fd=%d fslot=%d wbytes=%zu rbytes=%zu master=%d\n",
                 prodigyMothershipTopicName(MothershipTopic(message->topic)),
                 unsigned(message->topic),
                 unsigned(message->size),
                 static_cast<void *>(mothership),
                 (mothership ? mothership->fd : -1),
                 (mothership ? mothership->fslot : -1),
                 (mothership ? size_t(mothership->wBuffer.size()) : size_t(0)),
                 (mothership ? size_t(mothership->rBuffer.size()) : size_t(0)),
                 int(weAreMaster));
    PRODIGY_DEBUG_FLUSH();

    // Only the active master may serve mothership control-plane traffic.
    // Followers close opportunistic connections immediately.
    if (weAreMaster == false)
    {
      PRODIGY_DEBUG_LOG( "prodigy mothership handler-reject reason=not-master topic=%s(%u) stream=%p\n",
                   prodigyMothershipTopicName(MothershipTopic(message->topic)),
                   unsigned(message->topic),
                   static_cast<void *>(mothership));
      PRODIGY_DEBUG_FLUSH();
      queueCloseIfActive(mothership);
      return;
    }

    replayLocalMachineHardwareProfileIfReady();

    switch (MothershipTopic(message->topic))
    {
      case MothershipTopic::configure: // this must be the first thing done, before anything else... we could even reject deployments
        {
          // config{4}

          String serialized;
          Message::extractToStringView(args, serialized);

          BrainConfig deserializedConfig = {};
          BitseryEngine::deserialize(serialized, deserializedConfig);
          BrainConfig incomingConfig = {};
          ownBrainConfig(deserializedConfig, incomingConfig);
          uint16_t previousSharedCPUOvercommitPermille = brainConfig.sharedCPUOvercommitPermille;
          PRODIGY_DEBUG_LOG( "prodigy mothership configure-request clusterUUID=%llu datacenter=%u autoscale=%u requiredBrains=%u nMachineConfigs=%u nSubnets=%u runtimeConfigured=%d vmImage=%d\n",
                       (unsigned long long)incomingConfig.clusterUUID,
                       unsigned(incomingConfig.datacenterFragment),
                       unsigned(incomingConfig.autoscaleIntervalSeconds),
                       unsigned(incomingConfig.requiredBrainCount),
                       uint32_t(incomingConfig.configBySlug.size()),
                       uint32_t(incomingConfig.distributableExternalSubnets.size()),
                       int(incomingConfig.runtimeEnvironment.configured()),
                       int(incomingConfig.vmImageURI.size() > 0));
          PRODIGY_DEBUG_FLUSH();

          String ownershipFailure = {};
          if (claimLocalClusterOwnership(incomingConfig.clusterUUID, &ownershipFailure) == false)
          {
            PRODIGY_DEBUG_LOG( "prodigy mothership configure-reject clusterUUID=%llu reason=%s\n",
                         (unsigned long long)incomingConfig.clusterUUID,
                         ownershipFailure.c_str());
            PRODIGY_DEBUG_FLUSH();
            queueCloseIfActive(mothership, "configure-owner-mismatch");
            break;
          }

          if (incomingConfig.runtimeEnvironment.configured() &&
              elasticAddressSagaFencesRuntimeEnvironment(incomingConfig.runtimeEnvironment))
          {
            queueCloseIfActive(mothership, "configure-provider-fenced-by-elastic-saga");
            break;
          }

          BrainConfig previousConfig;
          ownBrainConfig(brainConfig, previousConfig);
          ProdigyMasterAuthorityRuntimeState previousMasterAuthorityState =
              masterAuthorityRuntimeState;
          const bool previousMasterAuthorityDurable = masterAuthorityRuntimeStateDurable;
          const uint64_t previousDurableMasterAuthorityGeneration =
              durableMasterAuthorityRuntimeStateGeneration;
          if (incomingConfig.clusterUUID != 0)
          {
            brainConfig.clusterUUID = incomingConfig.clusterUUID;
          }

          if (incomingConfig.datacenterFragment != 0)
          {
            brainConfig.datacenterFragment = incomingConfig.datacenterFragment;
          }

          if (incomingConfig.autoscaleIntervalSeconds != 0)
          {
            brainConfig.autoscaleIntervalSeconds = incomingConfig.autoscaleIntervalSeconds;
          }

          if (incomingConfig.sharedCPUOvercommitPermille >= prodigySharedCPUOvercommitMinPermille && incomingConfig.sharedCPUOvercommitPermille <= prodigySharedCPUOvercommitMaxPermille)
          {
            brainConfig.sharedCPUOvercommitPermille = incomingConfig.sharedCPUOvercommitPermille;
          }

          brainConfig.machineReservedResources = incomingConfig.machineReservedResources;
          brainConfig.requiredBrainCount = incomingConfig.requiredBrainCount;
          brainConfig.architecture = incomingConfig.architecture;
          brainConfig.bootstrapSshUser = incomingConfig.bootstrapSshUser;
          brainConfig.bootstrapSshKeyPackage = incomingConfig.bootstrapSshKeyPackage;
          brainConfig.bootstrapSshHostKeyPackage = incomingConfig.bootstrapSshHostKeyPackage;
          brainConfig.bootstrapSshPrivateKeyPath = incomingConfig.bootstrapSshPrivateKeyPath;
          brainConfig.remoteProdigyPath = incomingConfig.remoteProdigyPath;
          brainConfig.controlSocketPath = incomingConfig.controlSocketPath;

          for (const auto& [slug, machineConfig] : incomingConfig.configBySlug)
          {
            brainConfig.configBySlug.insert_or_assign(slug, machineConfig);
          }

          if (incomingConfig.distributableExternalSubnets.empty() == false)
          {
            brainConfig.distributableExternalSubnets = incomingConfig.distributableExternalSubnets;
          }

          if (incomingConfig.dnsProvider.size() > 0)
          {
            brainConfig.dnsProvider = incomingConfig.dnsProvider;
          }

          if (incomingConfig.dnsCredential.name.size() > 0)
          {
            brainConfig.dnsCredential = incomingConfig.dnsCredential;
          }

          if (incomingConfig.acme.configured())
          {
            brainConfig.acme = incomingConfig.acme;
          }

          if (incomingConfig.vmImageURI.size() > 0)
          {
            brainConfig.vmImageURI = incomingConfig.vmImageURI;
          }

          brainConfig.osUpdatesEnabled = incomingConfig.osUpdatesEnabled;
          brainConfig.osUpdatePolicies = incomingConfig.osUpdatePolicies;
          brainConfig.maxOSDrains = incomingConfig.maxOSDrains > 0 ? incomingConfig.maxOSDrains : 1;
          brainConfig.machineUpdateCadenceMins = incomingConfig.machineUpdateCadenceMins > 0
                                                     ? incomingConfig.machineUpdateCadenceMins
                                                     : 15;

          if (incomingConfig.runtimeEnvironment.configured())
          {
            ownRuntimeEnvironmentConfig(incomingConfig.runtimeEnvironment, brainConfig.runtimeEnvironment);
            if (uint32_t maxSegmentSize = controlPlaneTCPMaxSegmentSize(AF_INET6); maxSegmentSize > 0)
            {
              if (brainSocket.isFixedFile && brainSocket.fslot >= 0)
              {
                Ring::queueSetSockOptInt(&brainSocket, SOL_TCP, TCP_MAXSEG, int(maxSegmentSize), "brain listener tcp maxseg refresh");
              }
              else
              {
                (void)prodigySetTCPMaxSegmentSize(brainSocket.fd, maxSegmentSize);
              }
            }

            for (BrainView *peer : brains)
            {
              if (peer == nullptr)
              {
                continue;
              }

              uint32_t maxSegmentSize = controlPlaneTCPMaxSegmentSize(peer->peerAddress.is6 ? AF_INET6 : AF_INET);
              if (peer->isFixedFile && peer->fslot >= 0 && maxSegmentSize > 0)
              {
                Ring::queueSetSockOptInt(peer, SOL_TCP, TCP_MAXSEG, int(maxSegmentSize), "brain peer tcp maxseg refresh");
              }
              else if (peer->fd >= 0 && maxSegmentSize > 0)
              {
                (void)prodigySetTCPMaxSegmentSize(peer->fd, maxSegmentSize);
              }
            }

            for (Machine *machine : machines)
            {
              if (machine == nullptr)
              {
                continue;
              }

              prodigyConfigureMachineNeuronEndpoint(*machine, thisNeuron, &localBrainPeerAddresses);
              IPAddress peerAddress = {};
              if (prodigyResolveMachinePeerAddress(*machine, peerAddress) == false)
              {
                continue;
              }

              uint32_t maxSegmentSize = controlPlaneTCPMaxSegmentSize(peerAddress.is6 ? AF_INET6 : AF_INET);
              if (machine->neuron.isFixedFile && machine->neuron.fslot >= 0 && maxSegmentSize > 0)
              {
                Ring::queueSetSockOptInt(&machine->neuron, SOL_TCP, TCP_MAXSEG, int(maxSegmentSize), "neuron control tcp maxseg refresh");
              }
            }
          }

          (void)quarantinePendingElasticAddressReleasePrefixes(masterAuthorityRuntimeState);
          if (commitMasterAuthorityStateChange() == false)
          {
            brainConfig = std::move(previousConfig);
            masterAuthorityRuntimeState = std::move(previousMasterAuthorityState);
            masterAuthorityRuntimeStateDurable = previousMasterAuthorityDurable;
            durableMasterAuthorityRuntimeStateGeneration =
                previousDurableMasterAuthorityGeneration;
            (void)configurePendingElasticAddressReleaseFence(masterAuthorityRuntimeState);
            queueCloseIfActive(mothership, "configure-master-authority-persist-failed");
            break;
          }

          loadBrainConfigIf();
          refreshMachineFragmentAssignmentsIfPossible();
          armMachineUpdateTimerIfNeeded();

          if (noMasterYet)
          {
            deriveMasterBrain();
          }

          String serializedBrainConfig;
          BitseryEngine::serialize(serializedBrainConfig, brainConfig);

          PRODIGY_DEBUG_LOG( "prodigy mothership configure-response clusterUUID=%llu datacenter=%u autoscale=%u nMachineConfigs=%u nSubnets=%u bytes=%zu noMasterYet=%d master=%d osUpdatesEnabled=%d osUpdatePolicies=%u maxOSDrains=%u cadenceMins=%u\n",
                       (unsigned long long)brainConfig.clusterUUID,
                       unsigned(brainConfig.datacenterFragment),
                       unsigned(brainConfig.autoscaleIntervalSeconds),
                       uint32_t(brainConfig.configBySlug.size()),
                       uint32_t(brainConfig.distributableExternalSubnets.size()),
                       size_t(serializedBrainConfig.size()),
                       int(noMasterYet),
                       int(weAreMaster),
                       int(brainConfig.osUpdatesEnabled),
                       unsigned(brainConfig.osUpdatePolicies.size()),
                       unsigned(brainConfig.maxOSDrains),
                       unsigned(brainConfig.machineUpdateCadenceMins));
          PRODIGY_DEBUG_FLUSH();
          basics_log("configure sharedCPUOvercommitPermille=%u previous=%u\n",
                     unsigned(brainConfig.sharedCPUOvercommitPermille),
                     unsigned(previousSharedCPUOvercommitPermille));
          Message::construct(mothership->wBuffer, MothershipTopic::configure, serializedBrainConfig);

          break;
        }
      case MothershipTopic::configureMothershipTunnelProvider:
        {
          String serialized;
          Message::extractToStringView(args, serialized);

          MothershipResponse response = {};
          MothershipTunnelProviderConfigureRequest incoming = {};
          if (BitseryEngine::deserializeSafe(serialized, incoming))
          {
            response.success = applyMothershipTunnelProviderConfigureRequest(incoming, true, &response.failure);
          }
          else
          {
            response.failure.assign("invalid mothership tunnel provider payload"_ctv);
          }

          String serializedResponse;
          BitseryEngine::serialize(serializedResponse, response);
          Message::construct(mothership->wBuffer, MothershipTopic::configureMothershipTunnelProvider, serializedResponse);
          break;
        }
      case MothershipTopic::upsertMachineSchemas:
        {
          String serializedRequest = {};
          Message::extractToStringView(args, serializedRequest);

          UpsertMachineSchemas request = {};
          UpsertMachineSchemas response = {};
          if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
          {
            response.failure.assign("invalid upsertMachineSchemas payload"_ctv);
          }
          else if (request.patches.empty())
          {
            response.failure.assign("upsertMachineSchemas requires at least one schema patch"_ctv);
          }
          else
          {
            Vector<ProdigyManagedMachineSchema> previousSchemas = masterAuthorityRuntimeState.machineSchemas;
            response.upserted = uint32_t(request.patches.size());
            for (const ProdigyManagedMachineSchemaPatch& patch : request.patches)
            {
              bool created = false;
              if (prodigyUpsertManagedMachineSchema(masterAuthorityRuntimeState.machineSchemas, patch, &created, &response.failure) == false)
              {
                break;
              }

              if (created)
              {
                response.created += 1;
              }
            }

            if (response.failure.size() == 0)
            {
              syncManagedMachineSchemaConfigs(previousSchemas, masterAuthorityRuntimeState.machineSchemas);
              noteMasterAuthorityRuntimeStateChanged();

              String reconcileFailure = {};
              ClusterTopology reconciledTopology = {};
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
              ProdigyTimingAttribution reconcileTiming = {};
              if (reconcileManagedMachineSchemas(&reconcileFailure, &reconcileTiming, &reconciledTopology) == false)
#else
              if (reconcileManagedMachineSchemas(&reconcileFailure, nullptr, &reconciledTopology) == false)
#endif
              {
                PRODIGY_DEBUG_LOG( "prodigy mothership upsertMachineSchemas-reconcile-failure bytes=%zu text=%.*s\n",
                             size_t(reconcileFailure.size()),
                             int(reconcileFailure.size()),
                             reconcileFailure.c_str());
                PRODIGY_DEBUG_FLUSH();
                response.failure = reconcileFailure;
              }
              else
              {
                response.hasTopology = true;
                response.topology = std::move(reconciledTopology);
              }

              response.success = (response.failure.size() == 0);
              if (response.success)
              {
                armMachineUpdateTimerIfNeeded();
              }
#if PRODIGY_ENABLE_CREATE_TIMING_ATTRIBUTION
              response.hasTimingAttribution = true;
              response.timingAttribution = reconcileTiming;
#endif
            }
          }

          String serializedResponse = {};
          BitseryEngine::serialize(serializedResponse, response);
          Message::construct(mothership->wBuffer, MothershipTopic::upsertMachineSchemas, serializedResponse);
          break;
        }
      case MothershipTopic::deltaMachineBudget:
        {
          String serializedRequest = {};
          Message::extractToStringView(args, serializedRequest);

          DeltaMachineBudget request = {};
          DeltaMachineBudget response = {};
          if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
          {
            response.failure.assign("invalid deltaMachineBudget payload"_ctv);
          }
          else
          {
            response.schema = request.schema;
            if (prodigyDeltaManagedMachineBudget(masterAuthorityRuntimeState.machineSchemas, request.schema, request.delta, &response.budget, &response.failure) == false)
            {
              response.success = false;
            }
            else
            {
              noteMasterAuthorityRuntimeStateChanged();

              String reconcileFailure = {};
              ClusterTopology reconciledTopology = {};
              if (reconcileManagedMachineSchemas(&reconcileFailure, nullptr, &reconciledTopology) == false)
              {
                response.failure = reconcileFailure;
              }
              else
              {
                response.hasTopology = true;
                response.topology = std::move(reconciledTopology);
              }

              response.success = (response.failure.size() == 0);
            }
          }

          String serializedResponse = {};
          BitseryEngine::serialize(serializedResponse, response);
          Message::construct(mothership->wBuffer, MothershipTopic::deltaMachineBudget, serializedResponse);
          break;
        }
      case MothershipTopic::deleteMachineSchema:
        {
          String serializedRequest = {};
          Message::extractToStringView(args, serializedRequest);

          DeleteMachineSchema request = {};
          DeleteMachineSchema response = {};
          if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
          {
            response.failure.assign("invalid deleteMachineSchema payload"_ctv);
          }
          else
          {
            response.schema = request.schema;
            Vector<ProdigyManagedMachineSchema> previousSchemas = masterAuthorityRuntimeState.machineSchemas;
            if (prodigyDeleteManagedMachineSchema(masterAuthorityRuntimeState.machineSchemas, request.schema, &response.removed, &response.failure) == false)
            {
              response.success = false;
            }
            else
            {
              if (response.removed)
              {
                syncManagedMachineSchemaConfigs(previousSchemas, masterAuthorityRuntimeState.machineSchemas);
                noteMasterAuthorityRuntimeStateChanged();

                String reconcileFailure = {};
                ClusterTopology reconciledTopology = {};
                if (reconcileManagedMachineSchemas(&reconcileFailure, nullptr, &reconciledTopology) == false)
                {
                  response.failure = reconcileFailure;
                }
                else
                {
                  response.hasTopology = true;
                  response.topology = std::move(reconciledTopology);
                }
              }
              else if (loadOrPersistAuthoritativeClusterTopology(response.topology))
              {
                response.hasTopology = true;
              }
              else
              {
                response.failure.assign("authoritative cluster topology unavailable"_ctv);
              }

              response.success = (response.failure.size() == 0);
            }
          }

          String serializedResponse = {};
          BitseryEngine::serialize(serializedResponse, response);
          Message::construct(mothership->wBuffer, MothershipTopic::deleteMachineSchema, serializedResponse);
          break;
        }
      case MothershipTopic::addMachines:
        {
          String serializedRequest;
          Message::extractToStringView(args, serializedRequest);

          AddMachines request = {};
          if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
          {
            AddMachines response = {};
            response.success = false;
            response.failure.assign("invalid addMachines payload"_ctv);
            PRODIGY_DEBUG_LOG( "prodigy mothership addMachines-request invalid-payload bytes=%zu\n", size_t(serializedRequest.size()));
            PRODIGY_DEBUG_FLUSH();

            String serializedResponse;
            BitseryEngine::serialize(serializedResponse, response);
            Message::construct(mothership->wBuffer, MothershipTopic::addMachines, serializedResponse);
            (void)flushActiveMothershipSendBuffer(mothership, "addmachines-invalid");
            break;
          }

          addMachines(mothership, std::move(request));
          break;
        }
      case MothershipTopic::registerRoutableSubnet:
        {
          handleRegisterRoutableSubnet(mothership, args);
          break;
        }
      case MothershipTopic::unregisterRoutableSubnet:
        {
          handleUnregisterRoutableSubnet(mothership, args);
          break;
        }
      case MothershipTopic::pullRoutableSubnets:
        {
          RoutableSubnetRegistryReport response = {};
          response.subnets = brainConfig.distributableExternalSubnets;
          response.success = true;

          String serializedResponse;
          BitseryEngine::serialize(serializedResponse, response);
          Message::construct(mothership->wBuffer, MothershipTopic::pullRoutableSubnets, serializedResponse);
          break;
        }
      case MothershipTopic::pullRoutableResourceLeases:
        {
          RoutableResourceLeaseReport response = {};
          response.leases = routableResourceLeaseRuntimeState;
          response.success = true;

          String serializedResponse;
          BitseryEngine::serialize(serializedResponse, response);
          Message::construct(mothership->wBuffer, MothershipTopic::pullRoutableResourceLeases, serializedResponse);
          break;
        }
      case MothershipTopic::upsertDNSBinding:
      case MothershipTopic::deleteDNSBinding:
        {
          String serializedRequest;
          Message::extractToStringView(args, serializedRequest);

          RoutableResourceLeaseReport request = {};
          RoutableResourceLeaseReport response = {};
          bool accepted = false;
          if (BitseryEngine::deserializeSafe(serializedRequest, request) == false || request.leases.size() != 1)
          {
            response.failure.assign("DNS binding request requires one lease"_ctv);
          }
          else if (MothershipTopic(message->topic) == MothershipTopic::upsertDNSBinding)
          {
            accepted = upsertDNSBindingLease(request.leases[0], response, mothership);
          }
          else
          {
            accepted = deleteDNSBindingLease(request.leases[0], response, mothership);
          }

          if (accepted == false || response.success)
          {
            String serializedResponse;
            BitseryEngine::serialize(serializedResponse, response);
            Message::construct(mothership->wBuffer, MothershipTopic(message->topic), serializedResponse);
          }
          break;
        }
      case MothershipTopic::presentACMEDNS01Challenge:
      case MothershipTopic::cleanupACMEDNS01Challenge:
        {
          String serializedRequest;
          Message::extractToStringView(args, serializedRequest);

          AcmeDNS01ChallengeRequest request = {};
          AcmeDNS01ChallengeResponse response = {};
          bool accepted = false;
          if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
          {
            response.failure.assign("invalid ACME DNS-01 request payload"_ctv);
          }
          else
          {
            accepted = applyACMEDNS01Challenge(request,
                                               MothershipTopic(message->topic) == MothershipTopic::cleanupACMEDNS01Challenge,
                                               response,
                                               mothership);
          }

          if (accepted == false)
          {
            String serializedResponse;
            BitseryEngine::serialize(serializedResponse, response);
            Message::construct(mothership->wBuffer, MothershipTopic(message->topic), serializedResponse);
          }
          break;
        }
      case MothershipTopic::importACMELineage:
        {
          String serializedRequest;
          Message::extractToStringView(args, serializedRequest);

          AcmeLineageImportRequest request = {};
          AcmeLineageImportResponse response = {};
          if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
          {
            response.failure.assign("invalid ACME lineage import request payload"_ctv);
          }
          else
          {
            (void)importACMELineage(request, response);
          }

          String serializedResponse;
          BitseryEngine::serialize(serializedResponse, response);
          Message::construct(mothership->wBuffer, MothershipTopic::importACMELineage, serializedResponse);
          break;
        }
      case MothershipTopic::pullDNSBindings:
        {
          RoutableResourceLeaseReport response = {};
          for (const RoutableResourceLease& lease : routableResourceLeaseRuntimeState)
          {
            if (lease.kind == RoutableResourceLeaseKind::dnsRecord)
            {
              response.leases.push_back(lease);
            }
          }
          response.success = true;

          String serializedResponse;
          BitseryEngine::serialize(serializedResponse, response);
          Message::construct(mothership->wBuffer, MothershipTopic::pullDNSBindings, serializedResponse);
          break;
        }
      case MothershipTopic::teardownDNSBindings:
        {
          RoutableResourceLeaseReport response = {};
          const bool accepted = teardownDNSBindingLeases(response, mothership);

          if (accepted == false)
          {
            String serializedResponse;
            BitseryEngine::serialize(serializedResponse, response);
            Message::construct(mothership->wBuffer, MothershipTopic::teardownDNSBindings, serializedResponse);
          }
          break;
        }
      case MothershipTopic::pullClusterReport:
        {
          ClusterStatusReport report {};
          report.hasTopology = loadOrPersistAuthoritativeClusterTopology(report.topology);
          report.nMachines = machines.size();
          report.mothershipConnectivity.kind.assign(mothershipConnectivityKindName(mothershipConnectivity.kind));
          if (mothershipConnectivity.kind == MothershipConnectivityKind::tunnelProvider)
          {
            reconcileMothershipTunnelProviderRuntimeState();
            report.mothershipConnectivity.tunnelProviderPhase = mothershipTunnelProviderRuntimeState.phase;
            report.mothershipConnectivity.lastFailure.assign(mothershipTunnelProviderRuntimeState.lastFailure);
          }
          int64_t nowMs = Time::now<TimeResolution::ms>();
          BrainView *masterPeer = currentMasterPeer();
          const char *clusterProviderName = nullptr;
          switch (brainConfig.runtimeEnvironment.kind)
          {
            case ProdigyEnvironmentKind::gcp:
            case ProdigyEnvironmentKind::aws:
            case ProdigyEnvironmentKind::azure:
            case ProdigyEnvironmentKind::vultr:
              {
                clusterProviderName = prodigyEnvironmentKindName(brainConfig.runtimeEnvironment.kind);
                break;
              }
            default:
              {
                break;
              }
          }

          auto machineStateName = [](MachineState state) -> const char * {
            switch (state)
            {
              case MachineState::deploying:
                return "deploying";
              case MachineState::unknown:
                return "unknown";
              case MachineState::healthy:
                return "healthy";
              case MachineState::missing:
                return "missing";
              case MachineState::unresponsive:
                return "unresponsive";
              case MachineState::neuronRebooting:
                return "neuronRebooting";
              case MachineState::hardRebooting:
                return "hardRebooting";
              case MachineState::updatingOS:
                return "updatingOS";
              case MachineState::hardwareFailure:
                return "hardwareFailure";
              case MachineState::unreachable:
                return "unreachable";
              case MachineState::decommissioning:
                return "decommissioning";
            }

            return "unknown";
          };

          auto machineSourceName = [&](const Machine *machine) -> const char * {
            if (machine == nullptr)
            {
              return "unknown";
            }

            if (machine->isThisMachine && machine->cloudID.size() == 0 && brainConfig.runtimeEnvironment.kind == ProdigyEnvironmentKind::dev)
            {
              return "local";
            }

            switch (ClusterMachineSource(machine->topologySource))
            {
              case ClusterMachineSource::adopted:
                return "adopted";
              case ClusterMachineSource::created:
                return "created";
            }

            return "unknown";
          };

          auto machineLifetimeName = [](MachineLifetime lifetime) -> const char * {
            switch (lifetime)
            {
              case MachineLifetime::owned:
                return "owned";
              case MachineLifetime::reserved:
                return "reserved";
              case MachineLifetime::ondemand:
                return "ondemand";
              case MachineLifetime::spot:
                return "spot";
            }

            return "unknown";
          };

          auto updateSelfStateName = [](UpdateSelfState state) -> const char * {
            switch (state)
            {
              case UpdateSelfState::idle:
                return "idle";
              case UpdateSelfState::waitingForBundleEchos:
                return "waitingForBundleEchos";
              case UpdateSelfState::waitingForFollowerReboots:
                return "waitingForFollowerReboots";
              case UpdateSelfState::waitingForRelinquishEchos:
                return "waitingForRelinquishEchos";
            }

            return "idle";
          };

          auto resolveApplicationName = [&](uint16_t applicationID, String& applicationName) -> void {
            applicationName.clear();

            if (auto it = reservedApplicationNamesByID.find(applicationID); it != reservedApplicationNamesByID.end())
            {
              applicationName.assign(it->second);
              return;
            }

            applicationName.assign(MeshRegistry::applicationNameMappings[applicationID]);
          };

          auto sortAndDedupeTextList = [](Vector<String>& values) -> void {
            std::sort(values.begin(), values.end(), [](const String& lhs, const String& rhs) -> bool {
              size_t common = std::min(lhs.size(), rhs.size());
              int cmp = memcmp(lhs.data(), rhs.data(), common);
              if (cmp != 0)
              {
                return cmp < 0;
              }

              return lhs.size() < rhs.size();
            });
            values.erase(std::unique(values.begin(), values.end(), [](const String& lhs, const String& rhs) -> bool {
                           return lhs.size() == rhs.size() && memcmp(lhs.data(), rhs.data(), lhs.size()) == 0;
                         }),
                         values.end());
          };

          auto resolveMachineUpdateStage = [&](Machine *machine) -> const char * {
            if (machine == nullptr)
            {
              return "idle";
            }

            if (machine->isBrain)
            {
              if (machine->isThisMachine && isActiveMaster())
              {
                return updateSelfStateName(updateSelfState);
              }

              if (machine->brain != nullptr)
              {
                switch (updateSelfState)
                {
                  case UpdateSelfState::waitingForBundleEchos:
                    {
                      return updateSelfBundleEchoPeerKeys.contains(updateSelfPeerTrackingKey(machine->brain)) ? "bundleEchoed" : "waitingForBundle";
                    }
                  case UpdateSelfState::waitingForFollowerReboots:
                    {
                      return updateSelfFollowerRebootedPeerKeys.contains(updateSelfPeerTrackingKey(machine->brain)) ? "rebooted" : "waitingForReboot";
                    }
                  case UpdateSelfState::waitingForRelinquishEchos:
                    {
                      return updateSelfRelinquishEchoPeerKeys.contains(updateSelfPeerTrackingKey(machine->brain)) ? "relinquishEchoed" : "waitingForRelinquishEcho";
                    }
                  case UpdateSelfState::idle:
                    {
                      break;
                    }
                }
              }
            }

            if (machine->state == MachineState::neuronRebooting || machine->state == MachineState::hardRebooting)
            {
              return "rebooting";
            }

            if (machine->inBinaryUpdate)
            {
              return "updating";
            }

            return "idle";
          };

          String localInstalledBundleSHA256 = {};
          {
            String installedBundlePath = {};
            prodigyResolveInstalledBundlePathForRoot("/root/prodigy"_ctv, installedBundlePath);
            if (prodigyFileReadable(installedBundlePath))
            {
              String digestFailure = {};
              (void)prodigyComputeFileSHA256Hex(installedBundlePath, localInstalledBundleSHA256, &digestFailure);
            }
          }

          String stagedBundleSHA256 = {};
          {
            String stagedBundlePath = prodigyStagedBundlePath();
            if (prodigyFileReadable(stagedBundlePath))
            {
              String digestFailure = {};
              (void)prodigyComputeFileSHA256Hex(stagedBundlePath, stagedBundleSHA256, &digestFailure);
            }
          }

          for (Machine *machine : machines)
          {
            if (machine->lifetime == MachineLifetime::spot)
            {
              report.nSpotMachines += 1;
            }

            MachineStatusReport& mreport = report.machineReports.emplace_back();
            mreport.state.assign(machineStateName(machine->state));
            mreport.isBrain = machine->isBrain;
            mreport.controlPlaneReachable = neuronControlStreamActive(machine);
            mreport.runtimeReady = machine->runtimeReady && mreport.controlPlaneReachable;
            mreport.currentMaster = machine->isBrain && ((machine->isThisMachine && isActiveMaster()) || (machine->brain != nullptr && machine->brain == masterPeer));
            mreport.decommissioning = (machine->state == MachineState::decommissioning);
            mreport.rebooting = (machine->state == MachineState::neuronRebooting || machine->state == MachineState::hardRebooting);
            mreport.updatingOS = (machine->state == MachineState::updatingOS);
            mreport.hardwareFailure = (machine->state == MachineState::hardwareFailure || machine->hardwareFailureReport.size() > 0);
            mreport.bootTimeMs = machine->lastUpdatedOSMs;
            if (machine->lastUpdatedOSMs > 0 && machine->lastUpdatedOSMs <= nowMs)
            {
              mreport.uptimeMs = nowMs - machine->lastUpdatedOSMs;
            }
            if (machine->uuid != 0)
            {
              mreport.machineUUID.assignItoh(machine->uuid);
            }
            mreport.source.assign(machineSourceName(machine));
            mreport.backing.assign(clusterMachineBackingName(machine->cloudID.size() > 0 ? ClusterMachineBacking::cloud : ClusterMachineBacking::owned));
            mreport.lifetime.assign(machineLifetimeName(machine->lifetime));
            if (machine->cloudID.size() > 0 && clusterProviderName != nullptr && clusterProviderName[0] != '\0')
            {
              mreport.provider.assign(clusterProviderName);
            }
            mreport.region.assign(machine->region);
            mreport.zone.assign(machine->zone);
            mreport.rackUUID = machine->rackUUID;
            if (machine->cloudID.size() > 0 || machine->slug.size() > 0 || machine->type.size() > 0)
            {
              mreport.hasCloud = true;
              mreport.cloud.schema.assign(machine->slug);
              mreport.cloud.providerMachineType.assign(machine->type);
              mreport.cloud.cloudID.assign(machine->cloudID);
            }
            String resolvedSSHAddress = {};
            if (prodigyResolveMachineSSHAddress(*machine, resolvedSSHAddress))
            {
              mreport.ssh.address = resolvedSSHAddress;
            }
            mreport.ssh.port = machine->sshPort > 0 ? machine->sshPort : 22;
            mreport.ssh.user.assign(machine->sshUser);
            mreport.ssh.privateKeyPath.assign(machine->sshPrivateKeyPath);
            mreport.ssh.hostPublicKeyOpenSSH.assign(machine->sshHostPublicKeyOpenSSH);
            prodigyAssignClusterMachineAddressesFromPeerCandidates(mreport.addresses, machine->peerAddresses);
            prodigyAppendUniqueClusterMachineAddress(mreport.addresses.publicAddresses, machine->publicAddress);
            String privateGateway = {};
            if (machine->gatewayPrivate4 != 0)
            {
              IPAddress gatewayAddress = {};
              gatewayAddress.v4 = machine->gatewayPrivate4;
              gatewayAddress.is6 = false;
              (void)ClusterMachine::renderIPAddressLiteral(gatewayAddress, privateGateway);
            }
            prodigyAppendUniqueClusterMachineAddress(mreport.addresses.privateAddresses, machine->privateAddress, 0, privateGateway);
            mreport.totalLogicalCores = machine->totalLogicalCores;
            mreport.totalMemoryMB = machine->totalMemoryMB;
            mreport.totalStorageMB = machine->totalStorageMB;
            mreport.ownedLogicalCores = machine->ownedLogicalCores;
            mreport.ownedMemoryMB = machine->ownedMemoryMB;
            mreport.ownedStorageMB = machine->ownedStorageMB;
            for (const Machine::Claim& claim : machine->claims)
            {
              if (claim.nFit == 0)
              {
                continue;
              }

              mreport.reservedContainers += claim.nFit;
              mreport.reservedIsolatedLogicalCores += claim.reservedIsolatedLogicalCoresTotal ? claim.reservedIsolatedLogicalCoresTotal : (claim.reservedIsolatedLogicalCoresPerInstance * claim.nFit);
              mreport.reservedSharedCPUMillis += claim.reservedSharedCPUMillisTotal ? claim.reservedSharedCPUMillisTotal : (claim.reservedSharedCPUMillisPerInstance * claim.nFit);
              mreport.reservedMemoryMB += claim.reservedMemoryMBTotal ? claim.reservedMemoryMBTotal : (claim.reservedMemoryMBPerInstance * claim.nFit);
              mreport.reservedStorageMB += claim.reservedStorageMBTotal ? claim.reservedStorageMBTotal : (claim.reservedStorageMBPerInstance * claim.nFit);
            }

            for (const auto& [deploymentID, indexedContainers] : machine->containersByDeploymentID)
            {
              auto deploymentIt = deployments.find(deploymentID);
              if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
              {
                continue;
              }

              ApplicationDeployment *deployment = deploymentIt->second;
              const ApplicationConfig& config = deployment->plan.config;

              String deploymentIDText = {};
              deploymentIDText.snprintf<"{itoa}"_ctv>(deploymentID);
              mreport.deploymentIDs.push_back(deploymentIDText);

              String applicationName = {};
              resolveApplicationName(ApplicationConfig::extractApplicationID(deploymentID), applicationName);
              if (applicationName.size() > 0)
              {
                mreport.applicationNames.push_back(applicationName);
              }

              for (ContainerView *container : indexedContainers)
              {
                if (container == nullptr || container->state == ContainerState::destroyed)
                {
                  continue;
                }

                if (container->uuid != 0)
                {
                  String containerUUIDText = {};
                  containerUUIDText.assignItoh(container->uuid);
                  mreport.deployedContainers.push_back(containerUUIDText);
                }

                if (deployment->plan.isStateful)
                {
                  String shardGroupText = {};
                  shardGroupText.snprintf<"{itoa}"_ctv>(container->shardGroup);
                  mreport.shardGroups.push_back(shardGroupText);
                }

                mreport.activeContainers += 1;
                mreport.activeIsolatedLogicalCores += applicationRequiredIsolatedCores(config);
                if (applicationUsesSharedCPUs(config))
                {
                  mreport.activeSharedCPUMillis += applicationRequestedCPUMillis(config);
                }
                mreport.activeMemoryMB += config.totalMemoryMB();
                mreport.activeStorageMB += config.totalStorageMB();
              }
            }

            sortAndDedupeTextList(mreport.deployedContainers);
            sortAndDedupeTextList(mreport.applicationNames);
            sortAndDedupeTextList(mreport.deploymentIDs);
            sortAndDedupeTextList(mreport.shardGroups);

            if (machine->isThisMachine)
            {
              mreport.approvedBundleSHA256.assign(localInstalledBundleSHA256);
            }
            if (machine->isThisMachine && version > 0)
            {
              mreport.runningProdigyVersion.snprintf<"{itoa}"_ctv>(version);
            }
            else if (machine->brain != nullptr && machine->brain->version > 0)
            {
              mreport.runningProdigyVersion.snprintf<"{itoa}"_ctv>(machine->brain->version);
            }
            mreport.updateStage.assign(resolveMachineUpdateStage(machine));
            if (machine->isBrain && stagedBundleSHA256.size() > 0)
            {
              mreport.stagedBundleSHA256.assign(stagedBundleSHA256);
            }
            mreport.hardware = machine->hardware;
          }

          uint32_t nApplications;

          report.nApplications = deploymentsByApp.size();

          for (const auto& [applicationID, deployment] : deploymentsByApp)
          {
            ApplicationStatusReport& areport = report.applicationReports.emplace_back();
            areport.applicationID = applicationID;
            if (auto byID = reservedApplicationNamesByID.find(applicationID); byID != reservedApplicationNamesByID.end())
            {
              areport.applicationName = byID->second;
            }

            ApplicationDeployment *workingDeployment = deployment;

            do
            {
              DeploymentStatusReport deploymentReport = workingDeployment->generateReport();
              summarizeDeploymentTlsIdentityFreshness(workingDeployment, deploymentReport);
              areport.deploymentReports.push_back(std::move(deploymentReport));
              workingDeployment = workingDeployment->previous;

            } while (workingDeployment);
          }

          prodigyPrepareClusterStatusReportForTransport(report);

          String serializedReport;
          BitseryEngine::serialize(serializedReport, report);

          basics_log("mothershipHandler pullClusterReport nMachines=%u nApps=%u bytes=%u\n", report.nMachines, report.nApplications, uint32_t(serializedReport.size()));
          PRODIGY_DEBUG_LOG( "prodigy mothership pullClusterReport-response nMachines=%u nApps=%u bytes=%zu\n",
                       report.nMachines,
                       report.nApplications,
                       size_t(serializedReport.size()));
          PRODIGY_DEBUG_FLUSH();
          Message::construct(mothership->wBuffer, MothershipTopic::pullClusterReport, serializedReport);
          {
            uint8_t sample[16] = {0};
            size_t sampleCount = (mothership->wBuffer.size() < sizeof(sample) ? size_t(mothership->wBuffer.size()) : sizeof(sample));
            if (sampleCount > 0)
            {
              memcpy(sample, mothership->wBuffer.data(), sampleCount);
            }
            PRODIGY_DEBUG_LOG(
                         "prodigy mothership pullClusterReport-frame bytes=%zu sampleBytes=%zu sample=%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                         size_t(mothership->wBuffer.size()),
                         sampleCount,
                         unsigned(sample[0]),
                         unsigned(sample[1]),
                         unsigned(sample[2]),
                         unsigned(sample[3]),
                         unsigned(sample[4]),
                         unsigned(sample[5]),
                         unsigned(sample[6]),
                         unsigned(sample[7]),
                         unsigned(sample[8]),
                         unsigned(sample[9]),
                         unsigned(sample[10]),
                         unsigned(sample[11]),
                         unsigned(sample[12]),
                         unsigned(sample[13]),
                         unsigned(sample[14]),
                         unsigned(sample[15]));
            PRODIGY_DEBUG_FLUSH();
          }
          break;
        }
      case MothershipTopic::pullApplicationReport:
        {
          // applicationID(2)
          uint16_t applicationID;
          Message::extractArg<ArgumentNature::fixed>(args, applicationID);

          const auto debugPullApplicationReportMetrics = [&]() -> std::tuple<uint64_t, uint64_t, uint64_t> {
#if USE_MIMALLOC == 0
            struct mallinfo2 info = mallinfo2();
            return {
                uint64_t(info.uordblks),
                uint64_t(info.hblkhd),
                uint64_t(info.fordblks)};
#else
            return {0, 0, 0};
#endif
          };

          uint64_t chainCount = 0;
          uint64_t totalContainers = 0;
          uint64_t totalWaitingOnContainers = 0;
          uint64_t totalScheduledWork = 0;
          uint64_t totalFailureReports = 0;
          uint64_t currentContainers = 0;
          uint64_t currentWaitingOnContainers = 0;
          uint64_t currentScheduledWork = 0;
          uint64_t serializedBytes = 0;

          if (auto it = deploymentsByApp.find(applicationID); it != deploymentsByApp.end())
          {
            for (ApplicationDeployment *workingDeployment = it->second; workingDeployment; workingDeployment = workingDeployment->previous)
            {
              ++chainCount;
              const uint64_t containersCount = workingDeployment->containers.size();
              const uint64_t waitingCount = workingDeployment->waitingOnContainers.size();
              const uint64_t scheduledCount = workingDeployment->toSchedule.size();

              totalContainers += containersCount;
              totalWaitingOnContainers += waitingCount;
              totalScheduledWork += scheduledCount;
              totalFailureReports += workingDeployment->failureReports.size();

              if (chainCount == 1)
              {
                currentContainers = containersCount;
                currentWaitingOnContainers = waitingCount;
                currentScheduledWork = scheduledCount;
              }
            }
          }

          const auto [heapUsedBefore, heapMappedBefore, heapFreeBefore] = debugPullApplicationReportMetrics();

          {
            ApplicationStatusReport report {};
            report.applicationID = applicationID;
            if (auto byID = reservedApplicationNamesByID.find(applicationID); byID != reservedApplicationNamesByID.end())
            {
              report.applicationName = byID->second;
            }

            if (auto it = deploymentsByApp.find(applicationID); it != deploymentsByApp.end())
            {
              ApplicationDeployment *workingDeployment = it->second;

              do
              {
                DeploymentStatusReport deploymentReport = workingDeployment->generateReport();
                summarizeDeploymentTlsIdentityFreshness(workingDeployment, deploymentReport);
                report.deploymentReports.push_back(std::move(deploymentReport));
                workingDeployment = workingDeployment->previous;

              } while (workingDeployment);
            }

            String serializedReport;
            BitseryEngine::serialize(serializedReport, report);
            serializedBytes = serializedReport.size();

            Message::construct(mothership->wBuffer, MothershipTopic::pullApplicationReport, serializedReport);
          }

          const auto [heapUsedAfter, heapMappedAfter, heapFreeAfter] = debugPullApplicationReportMetrics();
          static uint64_t debugPullApplicationReportCount = 0;
          ++debugPullApplicationReportCount;

          if (debugPullApplicationReportCount <= 8 || (debugPullApplicationReportCount % 8) == 0 || heapUsedAfter > (1024ull * 1024ull * 1024ull) || heapMappedAfter > (1024ull * 1024ull * 1024ull))
          {
            PRODIGY_DEBUG_LOG(
                         "prodigy debug pullApplicationReport-stats count=%llu appID=%u chain=%llu currentContainers=%llu currentWaiting=%llu currentSchedule=%llu totalContainers=%llu totalWaiting=%llu totalSchedule=%llu failureReports=%llu serializedBytes=%llu wbytes=%u heapUsedBefore=%llu heapMappedBefore=%llu heapFreeBefore=%llu heapUsedAfter=%llu heapMappedAfter=%llu heapFreeAfter=%llu\n",
                         (unsigned long long)debugPullApplicationReportCount,
                         unsigned(applicationID),
                         (unsigned long long)chainCount,
                         (unsigned long long)currentContainers,
                         (unsigned long long)currentWaitingOnContainers,
                         (unsigned long long)currentScheduledWork,
                         (unsigned long long)totalContainers,
                         (unsigned long long)totalWaitingOnContainers,
                         (unsigned long long)totalScheduledWork,
                         (unsigned long long)totalFailureReports,
                         (unsigned long long)serializedBytes,
                         unsigned(mothership ? mothership->wBuffer.outstandingBytes() : 0u),
                         (unsigned long long)heapUsedBefore,
                         (unsigned long long)heapMappedBefore,
                         (unsigned long long)heapFreeBefore,
                         (unsigned long long)heapUsedAfter,
                         (unsigned long long)heapMappedAfter,
                         (unsigned long long)heapFreeAfter);
            PRODIGY_DEBUG_FLUSH();
          }

          break;
          ;
        }
      case MothershipTopic::pullTaskReport:
        {
          uint64_t deploymentID = 0;
          Message::extractArg<ArgumentNature::fixed>(args, deploymentID);

          bool found = false;
          String serializedRecord = {};
          const int64_t nowMs = Time::now<TimeResolution::ms>();
          auto recordIt = masterAuthorityRuntimeState.taskExecutions.find(deploymentID);
          if (recordIt != masterAuthorityRuntimeState.taskExecutions.end())
          {
            if (recordIt->second.expired(nowMs))
            {
              masterAuthorityRuntimeState.taskExecutions.erase(recordIt);
              noteMasterAuthorityRuntimeStateChanged();
            }
            else
            {
              found = true;
              BitseryEngine::serialize(serializedRecord, recordIt->second);
            }
          }

          Message::construct(mothership->wBuffer, MothershipTopic::pullTaskReport, found, serializedRecord);
          break;
        }
      case MothershipTopic::pullContainerLogs:
        {
          String serialized = {};
          Message::extractToStringView(args, serialized);
          ContainerLogsOperation operation = {};
          if (serialized.size() > containerLogsMaximumWireBytes ||
              BitseryEngine::deserializeSafe(serialized, operation) == false)
          {
            operation.failure.assign("container log request payload is invalid"_ctv);
            serialized.clear();
            BitseryEngine::serialize(serialized, operation);
            Message::construct(mothership->wBuffer, MothershipTopic::pullContainerLogs, serialized);
            break;
          }
          beginContainerLogRequest(mothership, std::move(operation));
          break;
        }
      case MothershipTopic::updateProdigy:
        {
          // bundleBlob{4}

          String newBundle;
          Message::extractToStringView(args, newBundle);

          MothershipResponse response = {};
          int written = Filesystem::openWriteAtClose(-1, prodigyStagedBundlePath(), newBundle);
          if (written < 0 || uint64_t(written) != newBundle.size())
          {
            response.failure.snprintf<"failed to stage update bundle bytes={itoa} expected={itoa}"_ctv>(
                int64_t(written),
                uint64_t(newBundle.size()));
          }

          uint32_t expectedPeerEchos = 0;
          if (response.failure.size() == 0)
          {
            response.success = true;

            // Persist payload for retries in distributed mode by default.
            // The staged fast path is only safe when every brain shares one writable
            // /root staging area, so it is opt-in via PRODIGY_DEV_SHARED_STAGE_BUNDLE=1.
            updateSelfUseStagedBundleOnly = devSharedStagedBundleEnabled();
            if (updateSelfUseStagedBundleOnly)
            {
              updateSelfBundleBlob.clear();
            }
            else
            {
              updateSelfBundleBlob.assign(newBundle);
            }

            for (BrainView *bv : brains)
            {
              if (peerSocketActive(bv))
              {
                expectedPeerEchos += 1;
              }
            }
          }

          String serializedResponse = {};
          BitseryEngine::serialize(serializedResponse, response);
          Message::construct(mothership->wBuffer, MothershipTopic::updateProdigy, serializedResponse);
          if (response.success == false)
          {
            break;
          }

          updateSelfTransitionAfterMothershipAck = expectedPeerEchos == 0 && streamIsActive(mothership);

          // now wait for the echos
          beginUpdateSelfBundle(expectedPeerEchos);

          break;
        }
      case MothershipTopic::reserveApplicationID:
        {
          // request{4}
          String serializedRequest;
          Message::extractToStringView(args, serializedRequest);

          ApplicationIDReserveRequest request;
          ApplicationIDReserveResponse response;
          response.success = false;

          if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
          {
            response.failure.assign("invalid request payload"_ctv);
          }
          else if (isValidReservedApplicationName(request.applicationName) == false)
          {
            response.failure.assign("applicationName invalid"_ctv);
          }
          else
          {
            response.applicationName = request.applicationName;

            if (auto byName = reservedApplicationIDsByName.find(request.applicationName); byName != reservedApplicationIDsByName.end())
            {
              response.applicationID = byName->second;
              if (request.requestedApplicationID != 0 && request.requestedApplicationID != response.applicationID)
              {
                response.failure.assign("applicationName already reserved with different applicationID"_ctv);
              }
              else
              {
                response.success = true;
                response.created = false;
              }
            }
            else
            {
              if (request.createIfMissing == false)
              {
                response.failure.assign("applicationName not reserved"_ctv);
              }
              else
              {
                uint16_t assignedApplicationID = 0;
                if (request.requestedApplicationID != 0)
                {
                  assignedApplicationID = request.requestedApplicationID;
                }
                else
                {
                  assignedApplicationID = takeNextReservableApplicationID();
                  if (assignedApplicationID == 0)
                  {
                    response.failure.assign("applicationID allocation exhausted"_ctv);
                  }
                }

                if (assignedApplicationID != 0)
                {
                  String reserveFailure;
                  if (reserveApplicationIDMapping(request.applicationName, assignedApplicationID, &reserveFailure) == false)
                  {
                    response.failure = reserveFailure;
                  }
                  else
                  {
                    if (nBrains > 1)
                    {
                      queueBrainReplication(BrainTopic::replicateApplicationIDReservation, assignedApplicationID, request.applicationName);
                    }

                    response.applicationID = assignedApplicationID;
                    response.success = true;
                    response.created = true;
                    persistLocalRuntimeState();
                  }
                }
              }
            }
          }

          String serializedResponse;
          BitseryEngine::serialize(serializedResponse, response);
          Message::construct(mothership->wBuffer, MothershipTopic::reserveApplicationID, serializedResponse);
          break;
        }
      case MothershipTopic::reserveServiceID:
        {
          // request{4}
          String serializedRequest;
          Message::extractToStringView(args, serializedRequest);

          ApplicationServiceReserveRequest request;
          ApplicationServiceReserveResponse response;
          response.success = false;

          if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
          {
            response.failure.assign("invalid request payload"_ctv);
          }
          else if (request.serviceName.size() == 0)
          {
            response.failure.assign("serviceName required"_ctv);
          }
          else
          {
            uint16_t applicationID = request.applicationID;
            if (applicationID == 0 && request.applicationName.size() > 0)
            {
              if (resolveReservedApplicationID(request.applicationName, applicationID) == false)
              {
                response.failure.assign("applicationName not reserved"_ctv);
              }
            }

            if (response.failure.size() == 0)
            {
              if (applicationID == 0)
              {
                response.failure.assign("applicationID required"_ctv);
              }
              else if (isApplicationIDReserved(applicationID) == false)
              {
                response.failure.assign("applicationID not reserved"_ctv);
              }
              else
              {
                response.applicationID = applicationID;
                if (auto byID = reservedApplicationNamesByID.find(applicationID); byID != reservedApplicationNamesByID.end())
                {
                  response.applicationName = byID->second;
                }
                else
                {
                  response.applicationName = request.applicationName;
                }
                response.serviceName = request.serviceName;

                ApplicationServiceIdentity existing;
                if (resolveReservedApplicationService(applicationID, request.serviceName, existing))
                {
                  if (request.requestedServiceSlot != 0 && request.requestedServiceSlot != existing.serviceSlot)
                  {
                    response.failure.assign("serviceName already reserved with different serviceSlot"_ctv);
                  }
                  else if (request.kind != ApplicationServiceIdentity::Kind::unspecified && request.kind != existing.kind)
                  {
                    response.failure.assign("serviceName already reserved with different kind"_ctv);
                  }
                  else
                  {
                    response.service = materializeReservedService(existing);
                    response.serviceSlot = existing.serviceSlot;
                    response.kind = existing.kind;
                    response.success = true;
                    response.created = false;
                  }
                }
                else if (request.createIfMissing == false)
                {
                  response.failure.assign("serviceName not reserved"_ctv);
                }
                else
                {
                  ApplicationServiceIdentity identity;
                  identity.applicationID = applicationID;
                  identity.serviceName = request.serviceName;
                  identity.kind = request.kind;

                  if (request.kind == ApplicationServiceIdentity::Kind::unspecified)
                  {
                    response.failure.assign("service kind required to create service"_ctv);
                  }
                  else if (request.requestedServiceSlot != 0)
                  {
                    identity.serviceSlot = request.requestedServiceSlot;
                  }
                  else
                  {
                    identity.serviceSlot = takeNextReservableServiceSlot(applicationID);
                    if (identity.serviceSlot == 0)
                    {
                      response.failure.assign("serviceSlot allocation exhausted"_ctv);
                    }
                  }

                  if (response.failure.size() == 0)
                  {
                    String reserveFailure;
                    if (reserveApplicationServiceMapping(identity, &reserveFailure) == false)
                    {
                      response.failure = reserveFailure;
                    }
                    else
                    {
                      if (nBrains > 1)
                      {
                        String serializedIdentity;
                        BitseryEngine::serialize(serializedIdentity, identity);
                        queueBrainReplication(BrainTopic::replicateApplicationServiceReservation, serializedIdentity);
                      }

                      response.service = materializeReservedService(identity);
                      response.serviceSlot = identity.serviceSlot;
                      response.kind = identity.kind;
                      response.success = true;
                      response.created = true;
                      persistLocalRuntimeState();
                    }
                  }
                }
              }
            }
          }

          String serializedResponse;
          BitseryEngine::serialize(serializedResponse, response);
          Message::construct(mothership->wBuffer, MothershipTopic::reserveServiceID, serializedResponse);
          break;
        }
      case MothershipTopic::upsertTlsVaultFactory:
        {
          // request{4}
          String serializedRequest;
          Message::extractToStringView(args, serializedRequest);

          TlsVaultFactoryUpsertRequest request;
          TlsVaultFactoryUpsertResponse response;
          response.success = false;
          response.applicationID = 0;

          if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
          {
            response.failure.assign("invalid request payload"_ctv);
          }
          else if (request.applicationID == 0)
          {
            response.failure.assign("applicationID required"_ctv);
          }
          else if (request.mode > 1)
          {
            response.failure.assign("mode invalid"_ctv);
          }
          else
          {
            response.applicationID = request.applicationID;

            bool created = false;
            ApplicationTlsVaultFactory factory;
            if (auto it = tlsVaultFactoriesByApp.find(request.applicationID); it != tlsVaultFactoriesByApp.end())
            {
              factory = it->second;
            }
            else
            {
              created = true;
              factory.applicationID = request.applicationID;
              factory.factoryGeneration = 0;
              factory.createdAtMs = Time::now<TimeResolution::ms>();
            }

            factory.updatedAtMs = Time::now<TimeResolution::ms>();
            factory.keySourceMode = request.mode;
            factory.scheme = request.scheme;
            if (request.defaultLeafValidityDays > 0)
            {
              factory.defaultLeafValidityDays = request.defaultLeafValidityDays;
            }
            if (request.mode == 0)
            {
              X509 *rootCert = nullptr;
              EVP_PKEY *rootKey = nullptr;
              X509 *interCert = nullptr;
              EVP_PKEY *interKey = nullptr;

              CryptoScheme scheme = (request.scheme == uint8_t(CryptoScheme::ed25519)) ? CryptoScheme::ed25519 : CryptoScheme::p256;
              VaultCertificateRequest rootRequest = {};
              rootRequest.type = CertificateType::root;
              rootRequest.scheme = scheme;
              generateCertificateAndKeys(rootRequest, nullptr, nullptr, rootCert, rootKey);

              VaultCertificateRequest intermediateRequest = {};
              intermediateRequest.type = CertificateType::intermediary;
              intermediateRequest.scheme = scheme;
              generateCertificateAndKeys(intermediateRequest, rootCert, rootKey, interCert, interKey);

              bool ok = VaultPem::x509ToPem(rootCert, factory.rootCertPem) && VaultPem::privateKeyToPem(rootKey, factory.rootKeyPem) && VaultPem::x509ToPem(interCert, factory.intermediateCertPem) && VaultPem::privateKeyToPem(interKey, factory.intermediateKeyPem);

              if (ok == false)
              {
                response.failure.assign("failed to generate PEM payloads"_ctv);
              }
              else
              {
                response.generatedRootCertPem = factory.rootCertPem;
                response.generatedRootKeyPem = factory.rootKeyPem;
                response.generatedIntermediateCertPem = factory.intermediateCertPem;
                response.generatedIntermediateKeyPem = factory.intermediateKeyPem;
              }

              if (rootCert)
              {
                X509_free(rootCert);
              }
              if (rootKey)
              {
                EVP_PKEY_free(rootKey);
              }
              if (interCert)
              {
                X509_free(interCert);
              }
              if (interKey)
              {
                EVP_PKEY_free(interKey);
              }
            }
            else
            {
              if (request.importRootCertPem.size() == 0 ||
                  request.importRootKeyPem.size() == 0 ||
                  request.importIntermediateCertPem.size() == 0 ||
                  request.importIntermediateKeyPem.size() == 0)
              {
                response.failure.assign("import mode requires root/intermediate cert+key"_ctv);
              }
              else
              {
                factory.rootCertPem = request.importRootCertPem;
                factory.rootKeyPem = request.importRootKeyPem;
                factory.intermediateCertPem = request.importIntermediateCertPem;
                factory.intermediateKeyPem = request.importIntermediateKeyPem;
              }
            }

            if (response.failure.size() == 0)
            {
              String validationFailure;
              if (validateApplicationTlsVaultFactoryMaterial(factory, &validationFailure) == false)
              {
                response.failure = validationFailure;
              }
            }

            if (response.failure.size() == 0)
            {
              factory.factoryGeneration += 1;
              if (upsertPrivateTlsVaultLifecycleState(factory, factory.updatedAtMs, &response.failure) == false)
              {
                factory.factoryGeneration -= 1;
              }
            }

            if (response.failure.size() == 0)
            {
              tlsVaultFactoriesByApp.insert_or_assign(request.applicationID, factory);

              response.success = true;
              response.created = created;
              response.mode = factory.keySourceMode;
              response.factoryGeneration = factory.factoryGeneration;
              response.effectiveLeafValidityDays = factory.defaultLeafValidityDays;

              if (nBrains > 1)
              {
                String serializedFactory;
                BitseryEngine::serialize(serializedFactory, factory);
                queueBrainReplication(BrainTopic::replicateTlsVaultFactory, serializedFactory);
              }

              noteMasterAuthorityRuntimeStateChanged();
              (void)pushPrivateTlsIdentityDeltaToLiveContainers(request.applicationID, "tls-vault-factory-upsert"_ctv);
            }
          }

          String serializedResponse;
          BitseryEngine::serialize(serializedResponse, response);
          Message::construct(mothership->wBuffer, MothershipTopic::upsertTlsVaultFactory, serializedResponse);
          break;
        }
      case MothershipTopic::upsertApiCredentialSet:
        {
          // request{4}
          String serializedRequest;
          Message::extractToStringView(args, serializedRequest);

          ApiCredentialSetUpsertRequest request;
          ApiCredentialSetUpsertResponse response;
          response.success = false;
          response.applicationID = 0;

          if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
          {
            response.failure.assign("invalid request payload"_ctv);
          }
          else if (request.applicationID == 0)
          {
            response.failure.assign("applicationID required"_ctv);
          }
          else
          {
            response.applicationID = request.applicationID;

            ApplicationApiCredentialSet set;
            bool created = false;
            if (auto it = apiCredentialSetsByApp.find(request.applicationID); it != apiCredentialSetsByApp.end())
            {
              set = it->second;
            }
            else
            {
              created = true;
              set.applicationID = request.applicationID;
              set.createdAtMs = Time::now<TimeResolution::ms>();
              set.setGeneration = 0;
            }

            uint64_t nextSetGeneration = set.setGeneration + 1;
            bytell_hash_map<String, ApiCredential> merged;
            for (ApiCredential& existing : set.credentials)
            {
              merged.insert_or_assign(existing.name, existing);
            }

            bool invalidName = false;
            for (ApiCredential credential : request.upsertCredentials)
            {
              if (credential.name.size() == 0)
              {
                invalidName = true;
                break;
              }
              if (credential.generation == 0)
              {
                credential.generation = nextSetGeneration;
              }

              merged.insert_or_assign(credential.name, credential);
              response.updatedNames.push_back(credential.name);
            }

            if (invalidName)
            {
              response.failure.assign("credential name must not be empty"_ctv);
            }
            else
            {
              for (const String& name : request.removeCredentialNames)
              {
                if (name.size() == 0)
                {
                  continue;
                }
                if (merged.find(name) != merged.end())
                {
                  merged.erase(name);
                  response.removedNames.push_back(name);
                }
              }

              set.credentials.clear();
              for (const auto& [name, credential] : merged)
              {
                (void)name;
                set.credentials.push_back(credential);
              }

              set.setGeneration = nextSetGeneration;
              set.updatedAtMs = Time::now<TimeResolution::ms>();
              apiCredentialSetsByApp.insert_or_assign(request.applicationID, set);

              response.setGeneration = set.setGeneration;
              response.success = true;
              (void)created;

              if (nBrains > 1)
              {
                String serializedSet;
                BitseryEngine::serialize(serializedSet, set);
                queueBrainReplication(BrainTopic::replicateApiCredentialSet, serializedSet);
              }

              persistLocalRuntimeState();

              pushApiCredentialDeltaToLiveContainers(request.applicationID, set, response.updatedNames, response.removedNames, request.reason);
            }
          }

          String serializedResponse;
          BitseryEngine::serialize(serializedResponse, response);
          Message::construct(mothership->wBuffer, MothershipTopic::upsertApiCredentialSet, serializedResponse);
          break;
        }
      case MothershipTopic::mintClientTlsIdentity:
        {
          // request{4}
          String serializedRequest;
          Message::extractToStringView(args, serializedRequest);

          ClientTlsMintRequest request;
          ClientTlsMintResponse response;
          response.success = false;
          response.applicationID = 0;

          if (BitseryEngine::deserializeSafe(serializedRequest, request) == false)
          {
            response.failure.assign("invalid request payload"_ctv);
          }
          else if (request.applicationID == 0)
          {
            response.failure.assign("applicationID required"_ctv);
          }
          else if (request.name.size() == 0)
          {
            response.failure.assign("name required"_ctv);
          }
          else
          {
            response.applicationID = request.applicationID;
            response.name = request.name;

            auto factoryIt = tlsVaultFactoriesByApp.find(request.applicationID);
            if (factoryIt == tlsVaultFactoriesByApp.end())
            {
              response.failure.assign("no pre-existing vault factory for applicationID"_ctv);
            }
            else
            {
              const ApplicationTlsVaultFactory& factory = factoryIt->second;
              X509 *interCert = VaultPem::x509FromPem(factory.intermediateCertPem);
              EVP_PKEY *interKey = VaultPem::privateKeyFromPem(factory.intermediateKeyPem);
              if (interCert == nullptr || interKey == nullptr)
              {
                response.failure.assign("stored intermediate material is invalid"_ctv);
                if (interCert)
                {
                  X509_free(interCert);
                }
                if (interKey)
                {
                  EVP_PKEY_free(interKey);
                }
              }
              else
              {
                CryptoScheme scheme = (request.scheme == uint8_t(CryptoScheme::ed25519)) ? CryptoScheme::ed25519 : CryptoScheme::p256;
                X509 *clientCert = nullptr;
                EVP_PKEY *clientKey = nullptr;
                VaultCertificateRequest clientRequest = {};
                clientRequest.type = CertificateType::client;
                clientRequest.scheme = scheme;
                clientRequest.subjectCommonName = request.subjectCommonName.size() > 0 ? request.subjectCommonName : request.name;
                clientRequest.enableClientAuth = true;
                generateCertificateAndKeys(clientRequest, interCert, interKey, clientCert, clientKey);

                if (clientCert == nullptr || clientKey == nullptr || brainAddCertificateSubjectAltNames(clientCert, request.dnsSans, request.ipSans) == false)
                {
                  response.failure.assign("failed to mint client tls identity"_ctv);
                }
                else
                {
                  uint32_t validityDays = request.validityDays > 0 ? request.validityDays : factory.defaultLeafValidityDays;
                  if (validityDays == 0)
                  {
                    validityDays = 15;
                  }
                  X509_gmtime_adj(X509_getm_notBefore(clientCert), 0);
                  X509_time_adj_ex(X509_getm_notAfter(clientCert), int(validityDays), 0, nullptr);
                  (void)X509_sign(clientCert, interKey, (scheme == CryptoScheme::ed25519) ? nullptr : EVP_sha256());

                  bool ok = VaultPem::x509ToPem(clientCert, response.certPem) && VaultPem::privateKeyToPem(clientKey, response.keyPem);
                  if (ok)
                  {
                    response.chainPem = factory.intermediateCertPem;
                    response.chainPem.append(factory.rootCertPem);
                    response.generation = nextMintedClientTlsGeneration++;
                    response.issuerFactoryGeneration = factory.factoryGeneration;
                    response.notBeforeMs = Time::now<TimeResolution::ms>();
                    response.notAfterMs = response.notBeforeMs + int64_t(validityDays) * 24 * 60 * 60 * 1000;
                    response.success = true;
                    noteMasterAuthorityRuntimeStateChanged();
                  }
                  else
                  {
                    response.failure.assign("failed to mint or encode client cert"_ctv);
                  }
                }

                if (clientCert)
                {
                  X509_free(clientCert);
                }
                if (clientKey)
                {
                  EVP_PKEY_free(clientKey);
                }
                if (interCert)
                {
                  X509_free(interCert);
                }
                if (interKey)
                {
                  EVP_PKEY_free(interKey);
                }
              }
            }
          }

          String serializedResponse;
          BitseryEngine::serialize(serializedResponse, response);
          Message::construct(mothership->wBuffer, MothershipTopic::mintClientTlsIdentity, serializedResponse);
          break;
        }
      case MothershipTopic::measureApplication:
        {
          // plan{4}

          String serializedPlan;
          Message::extractToStringView(args, serializedPlan);

          ApplicationDeployment *deployment = new ApplicationDeployment();

          BitseryEngine::deserialize(serializedPlan, deployment->plan);

          if (auto it = deploymentsByApp.find(deployment->plan.config.applicationID); it != deploymentsByApp.end())
          {
            deployment->previous = it->second;
          }

          // we could schedule this many
          bool resolved = true;
          for (Wormhole& wormhole : deployment->plan.wormholes)
          {
            if (wormhole.hasDNSConfig && wormhole.dns.bindingName.size() > 0)
            {
              String failure = {};
              if (resolveDeploymentWormholeDNSBinding(deployment->plan, wormhole, failure) == false)
              {
                basics_log("measureApplication DNS binding failed: %s\n", failure.c_str());
                resolved = false;
                break;
              }
            }
          }
          uint32_t nFit = resolved ? deployment->measure() : 0;

          if (nFit == 0 && deployment->plan.whiteholes.empty() == false)
          {
            basics_log(
                "measureApplication whitehole-fit-zero deploymentID=%llu targetBase=%u targetSurge=%u whiteholes=%u machines=%u\n",
                (unsigned long long)deployment->plan.config.deploymentID(),
                unsigned(deployment->nTargetBase),
                unsigned(deployment->nTargetSurge),
                unsigned(deployment->plan.whiteholes.size()),
                unsigned(machines.size()));

            for (Machine *machine : machines)
            {
              if (machine == nullptr)
              {
                continue;
              }

              String machineUUIDText = {};
              machineUUIDText.assignItoh(machine->uuid);
              basics_log(
                  "measureApplication machine uuid=%s state=%d isBrain=%d isThisMachine=%d slug=%s private4=%u avail=%d/%d/%d rack=%u\n",
                  machineUUIDText.c_str(),
                  int(machine->state),
                  int(machine->isBrain),
                  int(machine->isThisMachine),
                  machine->slug.c_str(),
                  unsigned(machine->private4),
                  int(machine->nLogicalCores_available),
                  int(machine->memoryMB_available),
                  int(machine->storageMB_available),
                  unsigned(machine->rackUUID));
            }
          }

          // we would schedule these many
          uint32_t nBase = deployment->nTargetBase;
          uint32_t nSurge = deployment->nTargetSurge;

          // nBase(4) nSurge(4) nFit(4)
          Message::construct(mothership->wBuffer, MothershipTopic::measureApplication, nBase, nSurge, nFit);

          delete deployment;

          break;
        }
      case MothershipTopic::spinApplication:
        {
          // applicationID(2) plan{4} containerBlob{4}
          uint16_t applicationID;
          Message::extractArg<ArgumentNature::fixed>(args, applicationID);

          if (unlikely(applicationID == 0))
          {
            return;
          }

          String serializedPlan;
          Message::extractToStringView(args, serializedPlan);

          if (unlikely(serializedPlan.size() == 0))
          {
            return;
          }

          ApplicationDeployment *deployment = new ApplicationDeployment();

          BitseryEngine::deserialize(serializedPlan, deployment->plan);
          auto rejectInvalidPlan = [&](const String& reason) {
            String message = reason.size() ? reason : String("invalid plan: unspecified admission failure"_ctv);
            basics_log("spinApplication invalidPlan: %s\n", message.c_str());
            Message::construct(
                mothership->wBuffer,
                MothershipTopic::spinApplication,
                uint8_t(SpinApplicationResponseCode::invalidPlan),
                message);
            delete deployment;
          };
          auto rejectInvalidPlanFailure = [&](const String& failure, const String& fallback) {
            const String& detail = failure.size() > 0 ? failure : fallback;
            String reason;
            reason.snprintf<"invalid plan: {}"_ctv>(detail);
            rejectInvalidPlan(reason);
          };

          if (deployment->plan.config.applicationID != applicationID)
          {
            rejectInvalidPlan("invalid plan: config.applicationID mismatches envelope"_ctv);
            return;
          }
          if (isApplicationIDReserved(applicationID) == false)
          {
            rejectInvalidPlan("invalid plan: applicationID not reserved"_ctv);
            return;
          }
          String identityFailure;
          if (validateDeploymentApplicationIdentity(deployment->plan, identityFailure) == false)
          {
            rejectInvalidPlan(identityFailure);
            return;
          }
          String taskPlanFailure = {};
          if (validateTaskDeploymentPlan(deployment->plan, taskPlanFailure) == false)
          {
            rejectInvalidPlan(taskPlanFailure);
            return;
          }

          if (deployment->plan.isStateful && deployment->plan.canaryCount > 0)
          {
            rejectInvalidPlan("invalid plan: stateful canaries are not supported; use stateful blue-green topology rollout"_ctv);
            return;
          }

          if (deployment->plan.hasTlsIssuancePolicy)
          {
            const DeploymentTlsIssuancePolicy& tlsPolicy = deployment->plan.tlsIssuancePolicy;
            if (tlsPolicy.applicationID == 0)
            {
              rejectInvalidPlan("invalid tls policy: applicationID missing"_ctv);
              return;
            }
            if (tlsPolicy.applicationID != deployment->plan.config.applicationID)
            {
              rejectInvalidPlan("invalid tls policy: applicationID mismatch"_ctv);
              return;
            }
            if (tlsVaultFactoriesByApp.find(tlsPolicy.applicationID) == tlsVaultFactoriesByApp.end())
            {
              rejectInvalidPlan("invalid tls policy: referenced vault factory does not exist"_ctv);
              return;
            }
          }

          if (deployment->plan.hasApiCredentialPolicy)
          {
            const DeploymentApiCredentialPolicy& apiPolicy = deployment->plan.apiCredentialPolicy;
            if (apiPolicy.applicationID == 0)
            {
              rejectInvalidPlan("invalid api credential policy: applicationID missing"_ctv);
              return;
            }
            if (apiPolicy.applicationID != deployment->plan.config.applicationID)
            {
              rejectInvalidPlan("invalid api credential policy: applicationID mismatch"_ctv);
              return;
            }

            auto setIt = apiCredentialSetsByApp.find(apiPolicy.applicationID);
            if (setIt == apiCredentialSetsByApp.end())
            {
              rejectInvalidPlan("invalid api credential policy: credential set does not exist"_ctv);
              return;
            }

            const ApplicationApiCredentialSet& set = setIt->second;
            for (const String& requiredName : apiPolicy.requiredCredentialNames)
            {
              bool found = false;
              for (const ApiCredential& credential : set.credentials)
              {
                if (credential.name.equals(requiredName))
                {
                  found = true;
                  break;
                }
              }

              if (found == false)
              {
                String reason;
                reason.snprintf<"invalid api credential policy: required key '{}' is not registered"_ctv>(requiredName);
                rejectInvalidPlan(reason);
                return;
              }
            }
          }

          for (const Wormhole& wormhole : deployment->plan.wormholes)
          {
            if (wormhole.source != ExternalAddressSource::distributableSubnet && wormhole.source != ExternalAddressSource::registeredRoutablePrefix)
            {
              rejectInvalidPlan("invalid plan: wormholes currently require source == distributableSubnet or registeredRoutablePrefix"_ctv);
              return;
            }
            if (wormhole.hasDNSConfig && wormhole.source != ExternalAddressSource::registeredRoutablePrefix && wormhole.dns.bindingName.size() == 0)
            {
              rejectInvalidPlan("invalid plan: wormhole DNS requires source=registeredRoutablePrefix"_ctv);
              return;
            }
          }

          for (Wormhole& wormhole : deployment->plan.wormholes)
          {
            if (wormhole.isQuic && wormhole.layer4 != IPPROTO_UDP)
            {
              rejectInvalidPlan("invalid plan: wormhole.isQuic requires layer4 == UDP"_ctv);
              return;
            }

            if (wormhole.hasDNSConfig && wormhole.dns.bindingName.size() > 0)
            {
              String dnsBindingFailure = {};
              if (resolveDeploymentWormholeDNSBinding(deployment->plan, wormhole, dnsBindingFailure) == false)
              {
                rejectInvalidPlanFailure(dnsBindingFailure, "wormhole DNS binding resolution failed without detail"_ctv);
                return;
              }
            }

            if (wormhole.source == ExternalAddressSource::registeredRoutablePrefix)
            {
              String resolveFailure = {};
              RoutableResourceLeaseOwner owner = deploymentRoutableResourceLeaseOwner(deployment->plan);
              if (resolveWormholeRegisteredRoutablePrefix(brainConfig.distributableExternalSubnets, wormhole, &resolveFailure, &routableResourceLeaseRuntimeState, &owner) == false)
              {
                rejectInvalidPlanFailure(resolveFailure, "wormhole routable prefix resolution failed without detail"_ctv);
                return;
              }
              if (wormhole.hasDNSConfig)
              {
                String dnsFailure = {};
                if (validateDeploymentWormholeDNSConfig(deployment->plan, wormhole, dnsFailure) == false)
                {
                  rejectInvalidPlanFailure(dnsFailure, "wormhole DNS validation failed without detail"_ctv);
                  return;
                }
              }

              continue;
            }

            bool foundMatchingSubnet = false;
            for (const DistributableExternalSubnet& subnet : brainConfig.distributableExternalSubnets)
            {
              if (distributableExternalSubnetContainsAddress(subnet, wormhole.externalAddress) && distributableExternalSubnetAllowsWormholes(subnet))
              {
                foundMatchingSubnet = true;
                break;
              }
            }

            if (foundMatchingSubnet == false)
            {
              if (wormhole.externalAddress.is6)
              {
                rejectInvalidPlan("invalid plan: wormhole externalAddress is not within a registered distributable ipv6 subnet usable for wormholes"_ctv);
              }
              else
              {
                rejectInvalidPlan("invalid plan: wormhole externalAddress is not within a registered distributable ipv4 subnet usable for wormholes"_ctv);
              }

              return;
            }
          }

          String wormholeLeaseFailure = {};
          if (reserveDeploymentWormholeAddressLeases(deployment->plan, wormholeLeaseFailure, false) == false)
          {
            rejectInvalidPlanFailure(wormholeLeaseFailure, "wormhole lease preflight failed without detail"_ctv);
            return;
          }

          for (const WormholePublicTLSConfig& publicTLS : deployment->plan.publicTLS)
          {
            PublicTlsCertificateSpec ignoredSpec = {};
            String ignoredCertName = {};
            String publicTLSFailure = {};
            if (buildPublicTlsCertificateSpecForDeployment(deployment->plan, publicTLS, ignoredSpec, ignoredCertName, publicTLSFailure) == false)
            {
              rejectInvalidPlanFailure(publicTLSFailure, "public TLS preflight failed without detail"_ctv);
              return;
            }
          }

          (void)prepareDeploymentPlanWormholeQuicCidState(deployment->plan, Time::now<TimeResolution::ms>());

          for (Whitehole& whitehole : deployment->plan.whiteholes)
          {
            whitehole.hasAddress = false;
            whitehole.address = {};
            whitehole.sourcePort = 0;
            whitehole.bindingNonce = 0;

            if (whitehole.source == ExternalAddressSource::hostPublicAddress)
            {
              continue;
            }

            if (whitehole.source == ExternalAddressSource::registeredRoutablePrefix)
            {
              if (findWhiteholeRoutablePrefixForFamily(
                      brainConfig,
                      whitehole.family) == nullptr)
              {
                if (whitehole.family == ExternalAddressFamily::ipv6)
                {
                  rejectInvalidPlan("invalid plan: no registered routable ipv6 prefix usable for whiteholes"_ctv);
                }
                else
                {
                  rejectInvalidPlan("invalid plan: no registered routable ipv4 prefix usable for whiteholes"_ctv);
                }

                return;
              }

              continue;
            }

            if (whitehole.source != ExternalAddressSource::hostPublicAddress)
            {
              rejectInvalidPlan("invalid plan: whiteholes currently require source == hostPublicAddress or registeredRoutablePrefix"_ctv);
              return;
            }
          }

          // they might just reisuse the application with the same deployment ID again if it fails
          if (auto it = failedDeployments.find(deployment->plan.config.deploymentID()); it != failedDeployments.end())
          {
            failedDeployments.erase(it);
          }

          String containerBlob;
          Message::extractToStringView(args, containerBlob);

          String trustedContainerBlobSHA256 = {};
          uint64_t trustedContainerBlobBytes = containerBlob.size();
          String digestFailure = {};
          if (prodigyComputeSHA256Hex(containerBlob, trustedContainerBlobSHA256, &digestFailure) == false)
          {
            rejectInvalidPlanFailure(digestFailure, "container blob sha256 computation failed without detail"_ctv);
            return;
          }

          String taskFingerprint = {};
          if (deployment->plan.config.type == ApplicationType::task)
          {
            DeploymentPlan fingerprintPlan = deployment->plan;
            fingerprintPlan.config.containerBlobSHA256 = trustedContainerBlobSHA256;
            fingerprintPlan.config.containerBlobBytes = trustedContainerBlobBytes;
            String fingerprintFailure = {};
            if (computeTaskExecutionFingerprint(fingerprintPlan, taskFingerprint, &fingerprintFailure) == false)
            {
              rejectInvalidPlanFailure(fingerprintFailure, "task fingerprint computation failed without detail"_ctv);
              return;
            }

            const uint64_t executionID = fingerprintPlan.config.deploymentID();
            const int64_t nowMs = Time::now<TimeResolution::ms>();
            auto existingTaskIt = masterAuthorityRuntimeState.taskExecutions.find(executionID);
            if (existingTaskIt != masterAuthorityRuntimeState.taskExecutions.end() && existingTaskIt->second.expired(nowMs))
            {
              masterAuthorityRuntimeState.taskExecutions.erase(existingTaskIt);
              noteMasterAuthorityRuntimeStateChanged();
              existingTaskIt = masterAuthorityRuntimeState.taskExecutions.end();
            }
            if (existingTaskIt != masterAuthorityRuntimeState.taskExecutions.end())
            {
              TaskExecutionRecord& existing = existingTaskIt->second;
              if (existing.fingerprint != taskFingerprint)
              {
                rejectInvalidPlan("invalid plan: task deploymentID already exists with a different immutable task specification"_ctv);
                return;
              }

              Mothership *stream = mothership;
              Message::construct(stream->wBuffer, MothershipTopic::spinApplication, uint8_t(SpinApplicationResponseCode::okay));
              if (existing.terminal())
              {
                String serializedRecord = {};
                BitseryEngine::serialize(serializedRecord, existing);
                Message::construct(stream->wBuffer, MothershipTopic::spinApplication, uint8_t(SpinApplicationResponseCode::finished), serializedRecord);
              }
              else if (auto liveIt = deployments.find(executionID); liveIt != deployments.end() && liveIt->second != nullptr)
              {
                bindSpinApplicationMothership(liveIt->second, stream);
                String progress = {};
                progress.snprintf<"attached to existing task execution state={} attempt={}"_ctv>(String(prodigyTaskExecutionStateName(existing.state)), existing.currentAttemptNumber);
                pushSpinApplicationProgressToMothership(liveIt->second, progress);
              }
              else
              {
                String progress = {};
                progress.snprintf<"attached to existing task execution state={} attempt={}"_ctv>(String(prodigyTaskExecutionStateName(existing.state)), existing.currentAttemptNumber);
                Message::construct(stream->wBuffer, MothershipTopic::spinApplication, uint8_t(SpinApplicationResponseCode::progress), progress);
              }
              delete deployment;
              return;
            }

            deployment->plan = std::move(fingerprintPlan);
          }

          String expectedContainerBlobSHA256 = trustedContainerBlobSHA256;
          uint64_t expectedContainerBlobBytes = trustedContainerBlobBytes;
          String containerStoreFailure = {};
          if (ContainerStore::store(
                  deployment->plan.config.deploymentID(),
                  containerBlob,
                  &trustedContainerBlobSHA256,
                  &trustedContainerBlobBytes,
                  &expectedContainerBlobSHA256,
                  &expectedContainerBlobBytes,
                  &containerStoreFailure) == false)
          {
            String reason = {};
            reason.assign("invalid container blob: "_ctv);
            if (containerStoreFailure.size() > 0)
            {
              reason.append(containerStoreFailure);
            }
            else
            {
              reason.append("blob store rejected the payload"_ctv);
            }
            rejectInvalidPlan(reason);
            return;
          }

          deployment->plan.config.containerBlobSHA256 = trustedContainerBlobSHA256;
          deployment->plan.config.containerBlobBytes = trustedContainerBlobBytes;
          if (deployment->plan.config.type == ApplicationType::task)
          {
            TaskExecutionRecord record = {};
            record.executionID = deployment->plan.config.deploymentID();
            record.applicationID = deployment->plan.config.applicationID;
            record.versionID = deployment->plan.config.versionID;
            record.policy = deployment->plan.config.taskExecutionPolicy;
            record.state = TaskExecutionState::accepted;
            record.fingerprint = taskFingerprint;
            record.acceptedAtMs = Time::now<TimeResolution::ms>();
            record.updatedAtMs = record.acceptedAtMs;
            masterAuthorityRuntimeState.taskExecutions.insert_or_assign(record.executionID, record);
            noteMasterAuthorityRuntimeStateChanged();
          }
          if (reserveDeploymentWormholeAddressLeases(deployment->plan, wormholeLeaseFailure, true) == false)
          {
            rejectInvalidPlanFailure(wormholeLeaseFailure, "wormhole lease commit failed without detail"_ctv);
            return;
          }
          String publicTLSFailure = {};
          if (reconcilePublicTlsCertificateStatesForDeployment(deployment->plan, publicTLSFailure) == false)
          {
            rejectInvalidPlanFailure(publicTLSFailure, "public TLS reconcile failed without detail"_ctv);
            return;
          }

          (void)advanceCertificateLifecycles(Time::now<TimeResolution::ms>());

          String trustedSerializedPlan = {};
          BitseryEngine::serialize(trustedSerializedPlan, deployment->plan);
          deployments.insert_or_assign(deployment->plan.config.deploymentID(), deployment);
          bindSpinApplicationMothership(deployment, mothership);

          // Initial deploy replication must carry the validated image with the
          // plan. A metadata-only frame can leave an already-master peer with a
          // reserved app name but no live deployment chain to report.
          if (nBrains > 1)
          {
            queueBrainDeploymentReplication(trustedSerializedPlan, containerBlob);
          }

          Message::construct(mothership->wBuffer, MothershipTopic::spinApplication, uint8_t(SpinApplicationResponseCode::okay));

          // The deploy CLI waits for the initial okay/invalidPlan frame before it starts
          // consuming streamed progress on the same topic.
          if (deploymentDNSReady(deployment->plan.config.deploymentID()))
          {
            spinApplication(deployment);
          }
          else
          {
            deploymentsWaitingForDNS.insert(deployment->plan.config.deploymentID());
            pushSpinApplicationProgressToMothership(deployment, "waiting for authoritative DNS reconciliation"_ctv);
          }

          break;
        }
      // this is very dangerous so we might not even want this code to be active
      // case MothershipTopic::destroyApplication:
      // {
      // 	// appID(2)

      // 	uint16_t applicationID;
      // 	Message::extractArg<ArgumentNature::fixed>(args, applicationID);

      // 	if (unlikely(applicationID == 0)) return;

      // 	if (auto it = deploymentsByApp.find(applicationID); it != deploymentsByApp.end()) // if that application even exists
      // 	{
      // 		// we need to tell it to destroy every instance....
      // 		ApplicationDeployment *deployment = it->second;

      // 		deployment->destroy();

      // 		String empty;
      // 		queueBrainReplication(NeuronTopic::replicateDeployment, applicationID, empty);
      // 	}

      // 	// we could either create a new destroy application replication command or we could unwind it here and issue culls for each existing deployment?

      // 	break;
      // }
      default:
        break;
    }
  }

  void neuronHandler(NeuronView *neuron, Message *message)
  {
    uint8_t *args = message->args;
    uint8_t *terminal = message->terminal();

    switch (NeuronTopic(message->topic))
    {
        // given that the brain state upon connection is what matters (either new brain looking to feed on the neuron's data or operating brain ready to configure the neuron)
        // the brain should first express it's state, then the neuron responds in kind

        // brain sends
        // NeuronTopic::registration requiresState(1)

        // if requiresState == true
        // neuron sends... serialized containers + its fragments
        // NeuronTopic::stateUpload containers{4} fragment(4)

        // neuron always sends back
        // NeuronTopic::registration bootTimeMs(8) kernel{4} osID{4} osVersionID{4} haveData(1)

      // if haveData == false
      // brain sends back
      // NeuronTopic::stateUpload containers{4} fragment(4)

      // maybe we should send it our registration... saying that we just became master and don't have data?
      case NeuronTopic::registration:
        {
          // bootTimeMs(8) kernel{4} osID{4} osVersionID{4} haveData(1)
          uint8_t *args = message->args;

          Machine *machine = neuron->machine;
          const bool needsStateRefresh = machineNeedsNeuronStateRefresh(machine);

          Message::extractArg<ArgumentNature::fixed>(args, machine->lastUpdatedOSMs);
          Message::extractToString(args, machine->kernel);
          Message::extractToString(args, machine->osID);
          Message::extractToString(args, machine->osVersionID);
          basics_log("brain neuron registration os uuid=%llu private4=%u osID=%s osVersionID=%s bootTimeMs=%lld\n",
                     (unsigned long long)machine->uuid,
                     unsigned(machine->private4),
                     machine->osID.c_str(),
                     machine->osVersionID.c_str(),
                     (long long)machine->lastUpdatedOSMs);

          bool haveData;
          Message::extractArg<ArgumentNature::fixed>(args, haveData);

          if (haveData == false || needsStateRefresh) // either 1) first time the neuron is connecting or 2) neuron crashed or 3) neuron was updated or 4) OS updated
          {
            if (ignited)
            {
              if (brainConfig.datacenterFragment == 0)
              {
                break;
              }

              if (machine->fragment > 0)
              {
                queueNeuronStateUploadForMachine(machine);
              }
              else // neuron yet to ever be configured, assign fragment now
              {
                assignMachineFragment(machine);
              }
            }
            // else main brain hasn't reached ignition yet. we need to wait for that otherwise we won't have gathered all
            // networking data from every machine, thus can't assign any
          }
          // else maybe some transitory connection breakage

          bool readyAfterRegistration = machineReadyForHealthyState(machine);
#if PRODIGY_DEBUG
          basics_log("brain neuron registration ready-check uuid=%llu private4=%u haveData=%d ready=%d inventoryComplete=%d total=%u/%u/%u owned=%u/%u/%u fd=%d fslot=%d\n",
                     (unsigned long long)(machine ? machine->uuid : 0),
                     unsigned(machine ? machine->private4 : 0u),
                     int(haveData),
                     int(readyAfterRegistration),
                     int(machine ? machine->hardware.inventoryComplete : 0),
                     unsigned(machine ? machine->totalLogicalCores : 0u),
                     unsigned(machine ? machine->totalMemoryMB : 0u),
                     unsigned(machine ? machine->totalStorageMB : 0u),
                     unsigned(machine ? machine->ownedLogicalCores : 0u),
                     unsigned(machine ? machine->ownedMemoryMB : 0u),
                     unsigned(machine ? machine->ownedStorageMB : 0u),
                     neuron->fd,
                     neuron->fslot);
#endif
          if (readyAfterRegistration)
          {
            promoteMachineToHealthyIfReady(machine);
          }

          refreshNeuronControlHandshakeWatchdog(neuron, "registration");
          sendNeuronSwitchboardStateSync(machine);
          recoverDeploymentsAfterNeuronState();
          armMachineUpdateTimerIfNeeded();

          break;
        }
      case NeuronTopic::machineHardwareProfile:
        {
          String serialized = {};
          Message::extractToStringView(args, serialized);

#if PRODIGY_DEBUG
          basics_log("brain neuron machineHardwareProfile begin uuid=%llu private4=%u cloudID=%s bytes=%llu fd=%d fslot=%d state=%u inventoryComplete=%d\n",
                     (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                     unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                     (neuron->machine ? neuron->machine->cloudID.c_str() : ""),
                     (unsigned long long)serialized.size(),
                     neuron->fd,
                     neuron->fslot,
                     unsigned(neuron->machine ? uint32_t(neuron->machine->state) : 0u),
                     int(neuron->machine ? neuron->machine->hardware.inventoryComplete : 0));
#endif
          MachineHardwareProfile hardware = {};
          if (BitseryEngine::deserializeSafe(serialized, hardware) == false)
          {
            basics_log("brain neuron machineHardwareProfile deserialize failed uuid=%llu private4=%u bytes=%llu fd=%d fslot=%d\n",
                       (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                       unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                       (unsigned long long)serialized.size(),
                       neuron->fd,
                       neuron->fslot);
            queueCloseIfActive(neuron);
            break;
          }

          if (hardware.inventoryComplete == false)
          {
            basics_log("brain neuron machineHardwareProfile incomplete uuid=%llu private4=%u bytes=%llu fd=%d fslot=%d\n",
                       (unsigned long long)(neuron->machine ? neuron->machine->uuid : 0),
                       unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                       (unsigned long long)serialized.size(),
                       neuron->fd,
                       neuron->fslot);
            queueCloseIfActive(neuron);
            break;
          }

          Machine *machine = neuron->machine;
          bool readyBeforeHardware = machineReadyForHealthyState(machine);
          applyMachineHardwareProfile(machine, hardware);

#if PRODIGY_DEBUG
          bool readyAfterHardware = machineReadyForHealthyState(machine);
          basics_log("brain neuron machineHardwareProfile ok uuid=%llu private4=%u bytes=%llu inventoryComplete=%d logicalCores=%u memoryMB=%u disks=%llu nics=%llu failure=%s readyBefore=%d readyAfter=%d totals=%u/%u/%u owned=%u/%u/%u fd=%d fslot=%d\n",
                     (unsigned long long)(machine ? machine->uuid : 0),
                     unsigned(machine ? machine->private4 : 0u),
                     (unsigned long long)serialized.size(),
                     int(hardware.inventoryComplete),
                     hardware.cpu.logicalCores,
                     hardware.memory.totalMB,
                     (unsigned long long)hardware.disks.size(),
                     (unsigned long long)hardware.network.nics.size(),
                     hardware.inventoryFailure.c_str(),
                     int(readyBeforeHardware),
                     int(readyAfterHardware),
                     unsigned(machine ? machine->totalLogicalCores : 0u),
                     unsigned(machine ? machine->totalMemoryMB : 0u),
                     unsigned(machine ? machine->totalStorageMB : 0u),
                     unsigned(machine ? machine->ownedLogicalCores : 0u),
                     unsigned(machine ? machine->ownedMemoryMB : 0u),
                     unsigned(machine ? machine->ownedStorageMB : 0u),
                     neuron->fd,
                     neuron->fslot);
#endif

          promoteMachineToHealthyIfReady(machine);
          refreshNeuronControlHandshakeWatchdog(neuron, "machine-hardware");

          break;
        }
      case NeuronTopic::pullContainerLogs:
        {
          String serialized = {};
          Message::extractToStringView(args, serialized);
          ContainerLogsOperation operation = {};
          if (serialized.size() <= containerLogsMaximumWireBytes &&
              BitseryEngine::deserializeSafe(serialized, operation))
          {
            noteContainerLogResponse(neuron, operation);
          }
          break;
        }
      case NeuronTopic::stateUpload:
        {
          // fragment(4) [containerPlan{4} + runtimeCores(2) + runtimeMemMB(4) + runtimeStorMB(4)]...

          struct local_container_subnet6 fragment;
          Message::extractBytes<Alignment::one>(args, (uint8_t *)&fragment, sizeof(struct local_container_subnet6));

          uint32_t reportedFragment = (static_cast<uint32_t>(fragment.mpfx[0]) << 16) |
                                      (static_cast<uint32_t>(fragment.mpfx[1]) << 8) |
                                      static_cast<uint32_t>(fragment.mpfx[2]);
          neuron->machine->reportedDatacenterFragment = fragment.dpfx;
          neuron->machine->reportedFragment = reportedFragment;
          if (neuron->machine->fragment == 0 && fragment.dpfx != 0 && reportedFragment > 0)
          {
            neuron->machine->fragment = reportedFragment;
          }
          else if (reportedFragment > 0 && neuron->machine->fragment > 0 && reportedFragment != neuron->machine->fragment)
          {
            basics_log("brain stateUpload fragment mismatch private4=%u assigned=%u reported=%u\n",
                       unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                       unsigned(neuron->machine->fragment),
                       unsigned(reportedFragment));
          }

          uint8_t *terminal = message->terminal();
          bool malformedStateUpload = false;
          bytell_hash_set<uint128_t> reportedMachineContainerUUIDs = {};
#if PRODIGY_DEBUG
          const uint64_t indexedBefore = neuron->machine ? neuron->machine->containersByDeploymentID.size() : 0u;
#endif
          while (args < terminal)
          {
            String buffer;
            Message::extractToStringView(args, buffer);
            if (buffer.data() > terminal || buffer.size() > uint64_t(terminal - buffer.data()))
            {
              malformedStateUpload = true;
              break;
            }

            ContainerPlan plan;
            if (BitseryEngine::deserializeSafe(buffer, plan) == false)
            {
              malformedStateUpload = true;
              break;
            }

            reportedMachineContainerUUIDs.insert(plan.uuid);
            if (handleUploadedMothershipTunnelProviderContainer(neuron, plan))
            {
              continue;
            }
            ContainerView *container = nullptr;
            if (auto existing = containers.find(plan.uuid); existing != containers.end())
            {
              container = existing->second;
            }
            else
            {
              container = new ContainerView();
            }

            uint64_t previousDeploymentID = container->deploymentID;
            uint32_t previousShardGroup = container->shardGroup;
            Machine *previousMachine = container->machine;
            ContainerState previousState = container->state;
            bool previousRuntimeReady = container->runtimeReady;
            ContainerState uploadedState = plan.state;
            uint128_t previousPairingAddress = container->pairingAddress();
            bool replayActivePeerPairings = false;

            if (previousState == ContainerState::healthy && uploadedState == ContainerState::healthy)
            {
              for (const auto& [service, advertisement] : container->advertisements)
              {
                auto updatedAdvertisement = plan.advertisements.find(service);
                if (updatedAdvertisement != plan.advertisements.end() &&
                    updatedAdvertisement->second.port != advertisement.port)
                {
                  replayActivePeerPairings = true;
                  break;
                }
              }
            }

            if (previousMachine)
            {
              previousMachine->removeContainerIndexEntry(previousDeploymentID, container);
            }

            if (previousDeploymentID > 0)
            {
              if (auto prevDeployment = deployments.find(previousDeploymentID); prevDeployment != deployments.end() && prevDeployment->second)
              {
                prevDeployment->second->containers.erase(container);
                if (prevDeployment->second->plan.isStateful)
                {
                  while (prevDeployment->second->containersByShardGroup.eraseEntry(previousShardGroup, container))
                  {
                  }
                }
              }
            }

            container->subscriptions.clear();
            container->advertisements.clear();
            container->advertisingOnPorts.clear();

            container->uuid = plan.uuid;
            container->deploymentID = plan.config.deploymentID();
            container->applicationID = plan.config.applicationID;
            container->lifetime = plan.lifetime;
            container->state = uploadedState;
            container->runtimeReady = plan.runtimeReady;
            if (container->runtimeReady == false)
            {
              container->clearStatefulTopologyCutoverBarrier();
            }
            container->machine = neuron->machine;
            container->createdAtMs = plan.createdAtMs;
            container->taskAttemptNumber = plan.taskAttemptNumber;
            // Neuron state upload currently transmits the serialized container plan.
            // Seed runtime usage from plan resources; live stats update these later.
            container->runtime_nLogicalCores = static_cast<uint16_t>(applicationSharedCPUCoreHint(plan.config));
            container->runtime_memoryMB = plan.config.totalMemoryMB();
            container->runtime_storageMB = plan.config.totalStorageMB();
            container->addresses = plan.addresses; // directly assigned interface addresses; currently just container-network IPv6
            container->wormholes = plan.wormholes;
            container->whiteholes = plan.whiteholes;
            container->networkAccess = plan.networkAccess;
            container->assignedGPUMemoryMBs = plan.assignedGPUMemoryMBs;
            container->assignedGPUDevices = plan.assignedGPUDevices;
            container->fragment = plan.fragment;
            container->setMeshAddress(container_network_subnet6, brainConfig.datacenterFragment, neuron->machine->fragment, container->fragment);
            container->isStateful = plan.isStateful;
            container->shardGroup = plan.shardGroup;
            container->explicitStatefulMeshRoles = plan.statefulMeshRoles;
            container->explicitStatefulTopology = plan.statefulTopology;
            container->subscriptions = plan.subscriptions;
            container->advertisements = plan.advertisements;
            noteContainerCredentialBundleApplied(container, plan.hasCredentialBundle ? &plan.credentialBundle : nullptr);
            if (previousState == ContainerState::healthy &&
                uploadedState == ContainerState::healthy &&
                previousPairingAddress != container->pairingAddress())
            {
              replayActivePeerPairings = true;
            }

            auto deploymentIt = deployments.find(container->deploymentID);
            if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
            {
              continue;
            }
            ApplicationDeployment *deployment = deploymentIt->second;
            container->remainingSubscriberCapacity = deployment->plan.minimumSubscriberCapacity;

            for (const auto& [service, subscription] : container->subscriptions)
            {
              if (serviceBlueprintActiveAtContainerState(subscription, uploadedState))
              {
                mesh->logSubscription(container, subscription.service, subscription.nature);
              }
            }

            for (const auto& [service, advertisement] : container->advertisements)
            {
              if (serviceBlueprintActiveAtContainerState(advertisement, uploadedState))
              {
                mesh->logAdvertisement(container, advertisement.service);
              }
              container->advertisingOnPorts.insert(advertisement.port);
            }

            for (const auto& [secret, pairings] : plan.advertisementPairings)
            {
              for (const AdvertisementPairing& pairing : pairings)
              {
                mesh->logAdvertisementPairing(pairing.secret, container, pairing);

                // we could also just pull the stress right now.... and then calculate capacity exactly...
                // but this is a decent estimate to right now... then we don't have to add that extra logic path complexity
                // but if it really mattered in the future we could do that
                container->remainingSubscriberCapacity -= 1;
              }
            }

            for (const auto& [secret, pairings] : plan.subscriptionPairings)
            {
              for (const SubscriptionPairing& pairing : pairings)
              {
                mesh->logSubscriptionPairing(pairing.secret, container, pairing);
              }
            }

            containers.insert_or_assign(container->uuid, container);
            container->machine->upsertContainerIndexEntry(container->deploymentID, container);
            deployment->containers.insert(container);

            if (deployment->plan.isStateful)
            {
              deployment->containersByShardGroup.insert(container->shardGroup, container);
            }

            if (uploadedState == ContainerState::healthy && previousState != ContainerState::healthy)
            {
              container->state = previousState;
              deployment->containerIsHealthy(container);
            }

            bool appliedRuntimeReady = false;
            if (container->runtimeReady && previousRuntimeReady == false)
            {
              deployment->containerIsRuntimeReady(container);
              appliedRuntimeReady = true;
            }

            if (replayActivePeerPairings && appliedRuntimeReady == false)
            {
              container->replayActivePairingsToSelf();
              container->replayActivePairingsToPeers();
            }
          }

          if (malformedStateUpload)
          {
            basics_log("brain stateUpload malformed plan payload from private4=%u\n",
                       (neuron->machine ? unsigned(neuron->machine->private4) : 0u));
            neuron->rBuffer.clear();
            if (streamIsActive(neuron))
            {
              Ring::queueClose(neuron);
            }
            break;
          }

          Vector<ContainerView *> staleMachineContainerPointers;
          bytell_hash_set<uint128_t> staleMachineContainerUUIDs = {};
          for (const auto& [deploymentID, machineContainers] : neuron->machine->containersByDeploymentID)
          {
            (void)deploymentID;
            for (ContainerView *container : machineContainers)
            {
              if (container == nullptr)
              {
                continue;
              }

              if (reportedMachineContainerUUIDs.find(container->uuid) != reportedMachineContainerUUIDs.end())
              {
                continue;
              }

              if (staleMachineContainerUUIDs.find(container->uuid) == staleMachineContainerUUIDs.end())
              {
                staleMachineContainerUUIDs.insert(container->uuid);
                staleMachineContainerPointers.push_back(container);
              }
            }
          }

          for (ContainerView *stale : staleMachineContainerPointers)
          {
            if (stale == nullptr)
            {
              continue;
            }

            neuron->machine->removeContainerIndexEntry(stale->deploymentID, stale);
            if (auto deployment = deployments.find(stale->deploymentID); deployment != deployments.end() && deployment->second)
            {
              deployment->second->containers.erase(stale);
              if (deployment->second->plan.isStateful)
              {
                while (deployment->second->containersByShardGroup.eraseEntry(stale->shardGroup, stale))
                {
                }
              }
            }

            if (auto canonical = containers.find(stale->uuid); canonical != containers.end() && canonical->second == stale)
            {
              containers.erase(stale->uuid);
            }

            delete stale;
          }

#if PRODIGY_DEBUG
          basics_log("brain stateUpload applied private4=%u reported=%llu stale=%llu indexedBefore=%llu indexedAfter=%llu canonicalContainers=%llu malformed=%d\n",
                     unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                     (unsigned long long)reportedMachineContainerUUIDs.size(),
                     (unsigned long long)staleMachineContainerPointers.size(),
                     (unsigned long long)indexedBefore,
                     (unsigned long long)(neuron->machine ? neuron->machine->containersByDeploymentID.size() : 0u),
                     (unsigned long long)containers.size(),
                     int(malformedStateUpload));
#endif

          neuron->machine->runtimeReady =
              neuron->machine->fragment > 0 && neuron->machine->reportedDatacenterFragment != 0 && (brainConfig.datacenterFragment == 0 || neuron->machine->reportedDatacenterFragment == brainConfig.datacenterFragment) && neuron->machine->reportedFragment == neuron->machine->fragment;
          promoteMachineToHealthyIfReady(neuron->machine);
          refreshNeuronControlHandshakeWatchdog(neuron, "state-upload");
          resumeMachineClaimsIfSchedulingReady(neuron->machine);
          sendNeuronSwitchboardStateSync(neuron->machine);
          recoverDeploymentsAfterNeuronState();

          break;
        }
      case NeuronTopic::hardwareFailure:
        {
          // report{4}
          uint8_t *args = message->args;

          Machine *machine = neuron->machine;

          Message::extractToString(args, machine->hardwareFailureReport);

          iaas->reportHardwareFailure(machine->uuid, machine->hardwareFailureReport);

          // update machine state before we call machineFailed
          handleMachineStateChange(machine, MachineState::hardwareFailure);

          decommissionMachine(machine);

          break;
        }
      case NeuronTopic::containerHealthy:
        {
          // containerUUID(16)

          uint128_t containerUUID;
          Message::extractArg<ArgumentNature::fixed>(args, containerUUID);
#if PRODIGY_DEBUG
          basics_log("brain neuronHandler containerHealthy private4=%u uuid=%llu master=%d tracked=%llu\n",
                     unsigned(neuron->machine ? neuron->machine->private4 : 0u),
                     (unsigned long long)containerUUID,
                     int(weAreMaster),
                     (unsigned long long)containers.size());
#endif
          noteLocalContainerHealthy(containerUUID);

          break;
        }
      case NeuronTopic::containerRuntimeReady:
        {
          uint128_t containerUUID = 0;
          Message::extractArg<ArgumentNature::fixed>(args, containerUUID);
          noteLocalContainerRuntimeReady(containerUUID);
          break;
        }
      case NeuronTopic::containerStatistics:
        {
          // deploymentID(8) containerUUID(16) sampleTimeMs(8) [metricKey(8) metricValue(8)]...
          uint64_t deploymentID = 0;
          uint128_t containerUUID = 0;
          int64_t sampleTimeMs = 0;

          Message::extractArg<ArgumentNature::fixed>(args, deploymentID);
          Message::extractArg<ArgumentNature::fixed>(args, containerUUID);
          Message::extractArg<ArgumentNature::fixed>(args, sampleTimeMs);

          auto containerIt = containers.find(containerUUID);
          if (containerIt == containers.end())
          {
            break;
          }
          if (containerIt->second->deploymentID != deploymentID)
          {
            break;
          }
          if (deployments.contains(deploymentID) == false)
          {
            break;
          }

          int64_t nowMs = Time::now<TimeResolution::ms>();
          if (sampleTimeMs <= 0 || sampleTimeMs > nowMs + 10'000 || sampleTimeMs < nowMs - BrainBase::metricRetentionMs)
          {
            sampleTimeMs = nowMs;
          }

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

            recordContainerMetric(deploymentID, containerUUID, metricKey, sampleTimeMs, static_cast<double>(metricValue));
            forwardMetricSampleToMaster(deploymentID, containerUUID, sampleTimeMs, metricKey, metricValue);

            if (containerIt->second->applyStatefulTopologyCutoverMetric(metricKey, metricValue))
            {
              if (auto deploymentIt = deployments.find(deploymentID); deploymentIt != deployments.end() && deploymentIt->second)
              {
                deploymentIt->second->containerStatefulTopologyCutoverBarrierUpdated(containerIt->second);
              }
            }
          }

          break;
        }
      case NeuronTopic::refreshContainerCredentials:
        {
          // containerUUID(16)
          uint128_t containerUUID = 0;
          Message::extractArg<ArgumentNature::fixed>(args, containerUUID);
          if (args < message->terminal())
          {
            String serializedAck = {};
            Message::extractToStringView(args, serializedAck);
            CredentialApplyAck credentialAck = {};
            TlsResumptionApplyAck resumptionAck = {};
            bool genericAck = ProdigyWire::deserializeCredentialApplyAck(serializedAck, credentialAck);
            if (genericAck == false && ProdigyWire::deserializeTlsResumptionApplyAck(serializedAck, resumptionAck) == false)
            {
              basics_log("brain refreshContainerCredentialsAckInvalid uuid=%llu bytes=%llu\n",
                         (unsigned long long)containerUUID,
                         (unsigned long long)serializedAck.size());
              queueCloseIfActive(neuron);
              break;
            }

            const int64_t nowMs = Time::now<TimeResolution::ms>();
            if (genericAck)
            {
              (void)noteContainerCredentialApplyAck(containerUUID, credentialAck);
              resumptionAck.results = std::move(credentialAck.resumptionResults);
            }
            else
            {
              (void)noteContainerCredentialRefreshAck(containerUUID);
            }
            (void)recordTlsResumptionApplyAck(containerUUID, resumptionAck);
            if (genericAck)
            {
              for (const TlsIdentityApplyResult& tlsResult : credentialAck.tlsResults)
              {
                basics_log("brain refreshContainerCredentialsTlsAck uuid=%llu identity=%.*s generation=%llu success=%u\n",
                           (unsigned long long)containerUUID,
                           int(tlsResult.identityName.size()),
                           reinterpret_cast<const char *>(tlsResult.identityName.data()),
                           (unsigned long long)tlsResult.generation,
                           unsigned(tlsResult.success));
              }
            }
            for (const TlsResumptionApplyResult& resumptionResult : resumptionAck.results)
            {
              basics_log("brain refreshContainerCredentialsAck uuid=%llu wormhole=%.*s generation=%llu success=%u\n",
                         (unsigned long long)containerUUID,
                         int(resumptionResult.wormholeName.size()),
                         reinterpret_cast<const char *>(resumptionResult.wormholeName.data()),
                         (unsigned long long)resumptionResult.generation,
                         unsigned(resumptionResult.success));
            }

            if (auto containerIt = containers.find(containerUUID); containerIt != containers.end() && containerIt->second != nullptr)
            {
              if (auto deploymentIt = deployments.find(containerIt->second->deploymentID); deploymentIt != deployments.end() && deploymentIt->second != nullptr)
              {
                (void)advanceTlsResumptionLifecycleForDeployment(deploymentIt->second->plan, nowMs, false);
              }
            }
          }
          else
          {
            (void)noteContainerCredentialRefreshAck(containerUUID);
            basics_log("brain refreshContainerCredentialsAck uuid=%llu\n",
                       (unsigned long long)containerUUID);
          }
          break;
        }
      case NeuronTopic::killContainer: // echo-ing back after killing a container
        {
          // containerUUID(16)

          uint128_t containerUUID;
          Message::extractArg<ArgumentNature::fixed>(args, containerUUID);

          // if a canary failed and we rolled back a deployment to previous, it's possible
          // we would've issued canary kills and then destroyed the deployment before we get a reply
          if (auto it = containers.find(containerUUID); it != containers.end())
          {
            ContainerView *container = it->second;

            Machine *machine = container->machine;

            PRODIGY_DEBUG_LOG( "brain killContainerAck begin uuid=%llu deploymentID=%llu appID=%u machinePrivate4=%u state=%u waiting=%llu containers=%llu\n",
                         (unsigned long long)containerUUID,
                         (unsigned long long)container->deploymentID,
                         unsigned(container->applicationID),
                         machine ? unsigned(machine->private4) : 0u,
                         unsigned(container->state),
                         (unsigned long long)((deployments.contains(container->deploymentID) && deployments[container->deploymentID]) ? deployments[container->deploymentID]->waitingOnContainers.size() : 0ull),
                         (unsigned long long)((deployments.contains(container->deploymentID) && deployments[container->deploymentID]) ? deployments[container->deploymentID]->containers.size() : 0ull));
            PRODIGY_DEBUG_FLUSH();

            uint64_t waiterDeploymentID = container->destructionWaiterDeploymentID;
            auto deploymentIt = deployments.find(waiterDeploymentID ? waiterDeploymentID : container->deploymentID);
            if (deploymentIt == deployments.end() || deploymentIt->second == nullptr)
            {
              break;
            }

            ApplicationDeployment *deployment = deploymentIt->second;
            container->destructionWaiterDeploymentID = 0;
            PRODIGY_DEBUG_LOG( "brain killContainerAck destroy-call uuid=%llu deploymentID=%llu waitingBefore=%llu containersBefore=%llu\n",
                         (unsigned long long)containerUUID,
                         (unsigned long long)container->deploymentID,
                         (unsigned long long)deployment->waitingOnContainers.size(),
                         (unsigned long long)deployment->containers.size());
            PRODIGY_DEBUG_FLUSH();
            uint64_t destroyedDeploymentID = container->deploymentID;
            deployment->containerDestroyed(container);
            PRODIGY_DEBUG_LOG( "brain killContainerAck destroy-done uuid=%llu deploymentID=%llu waitingAfter=%llu containersAfter=%llu\n",
                         (unsigned long long)containerUUID,
                         (unsigned long long)destroyedDeploymentID,
                         (unsigned long long)deployment->waitingOnContainers.size(),
                         (unsigned long long)deployment->containers.size());
            PRODIGY_DEBUG_FLUSH();

            isMachineDrained(machine);
            PRODIGY_DEBUG_LOG( "brain killContainerAck drain-done uuid=%llu machinePrivate4=%u\n",
                         (unsigned long long)containerUUID,
                         machine ? unsigned(machine->private4) : 0u);
            PRODIGY_DEBUG_FLUSH();
          }
          break;
        }
      case NeuronTopic::taskAttemptTerminal:
        {
          uint64_t deploymentID = 0;
          uint32_t attemptNumber = 0;
          uint128_t containerUUID = 0;
          Message::extractArg<ArgumentNature::fixed>(args, deploymentID);
          Message::extractArg<ArgumentNature::fixed>(args, attemptNumber);
          Message::extractArg<ArgumentNature::fixed>(args, containerUUID);
          String serialized = {};
          Message::extractToStringView(args, serialized);
          TaskTermination termination = {};
          if (BitseryEngine::deserializeSafe(serialized, termination) == false)
          {
            break;
          }

          auto containerIt = containers.find(containerUUID);
          if (containerIt == containers.end() || containerIt->second == nullptr)
          {
            auto recordIt = masterAuthorityRuntimeState.taskExecutions.find(deploymentID);
            if (neuron->machine &&
                recordIt != masterAuthorityRuntimeState.taskExecutions.end() &&
                (recordIt->second.terminal() || recordIt->second.currentAttemptNumber > attemptNumber))
            {
              neuron->machine->queueSend(NeuronTopic::taskAttemptTerminalAck, deploymentID, attemptNumber);
            }
            break;
          }
          ContainerView *container = containerIt->second;
          if (container->deploymentID != deploymentID || container->taskAttemptNumber != attemptNumber || container->uuid != containerUUID)
          {
            break;
          }
          if (auto deploymentIt = deployments.find(container->deploymentID); deploymentIt != deployments.end() && deploymentIt->second != nullptr && deploymentIt->second->plan.config.type == ApplicationType::task)
          {
            noteTaskAttemptTerminal(deploymentIt->second, container, termination);
          }

          break;
        }
      case NeuronTopic::containerFailed:
        {
          // containerUUID(16) approxTimeMs(8) signal(4) report{4} restarted(1)

          uint128_t containerUUID;
          Message::extractArg<ArgumentNature::fixed>(args, containerUUID);

          int64_t approxTimeMs;
          Message::extractArg<ArgumentNature::fixed>(args, approxTimeMs);

          int signal;
          Message::extractArg<ArgumentNature::fixed>(args, signal);

          String report;
          Message::extractToStringView(args, report);

          bool restarted;
          Message::extractArg<ArgumentNature::fixed>(args, restarted);

          if (noteMothershipTunnelProviderInstanceFailed(containerUUID, report, restarted))
          {
            break;
          }

          if (auto it = containers.find(containerUUID); it != containers.end())
          {
            ContainerView *container = it->second;

            Machine *machine = container->machine;

            ApplicationDeployment *deployment = nullptr;
            if (auto deploymentIt = deployments.find(container->deploymentID); deploymentIt != deployments.end())
            {
              deployment = deploymentIt->second;
            }

            // is it possible we'd ever destroy an application and orphan the containers? no right?
            uint16_t applicationID = ApplicationConfig::extractApplicationID(container->deploymentID);
            if (deployment == nullptr)
            {
              auto deploymentIt = deploymentsByApp.find(applicationID);
              if (deploymentIt != deploymentsByApp.end())
              {
                deployment = deploymentIt->second;
              }
            }

            if (deployment == nullptr)
            {
              break;
            }

            deployment->containerFailed(container, approxTimeMs, signal, report, restarted);

            if (restarted == false)
            {
              isMachineDrained(machine);
            }
          }

          break;
        }
      case NeuronTopic::requestContainerBlob:
        {
          // deploymentID(8)

          uint64_t deploymentID;
          Message::extractArg<ArgumentNature::fixed>(args, deploymentID);

          String containerBlobPath = ContainerStore::pathForContainerImage(deploymentID);
          PRODIGY_DEBUG_LOG( "brain requestContainerBlob deploymentID=%llu machinePrivate4=%u path=%s readable=%d\n",
                       (unsigned long long)deploymentID,
                       (neuron->machine ? unsigned(neuron->machine->private4) : 0u),
                       containerBlobPath.c_str(),
                       int(prodigyFileReadable(containerBlobPath)));
          PRODIGY_DEBUG_FLUSH();

          uint32_t headerOffset = Message::appendHeader(neuron->wBuffer, NeuronTopic::requestContainerBlob);
          Message::append(neuron->wBuffer, deploymentID);
          Message::appendFile(neuron->wBuffer, containerBlobPath);
          Message::finish(neuron->wBuffer, headerOffset);

          Ring::queueSend(neuron);

          break;
        }
      case NeuronTopic::spotTerminationImminent:
        {
          // spot machine preemption imminent; immediately drain all containers
          Machine *machine = neuron->machine;
          if (machine)
          {
            machine->state = MachineState::decommissioning;
            decommissionMachine(machine);
          }

          break;
        }
      case NeuronTopic::ping:
        {
          break;
        }

      default:
        break;
    }
  }
};

#include <prodigy/brain/routable.subnet.control.h>
#include <prodigy/brain/deployments.h>
