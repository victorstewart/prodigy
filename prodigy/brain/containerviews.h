#pragma once

class DeploymentWork;

class ContainerView : public MeshNode, public Stream, public CoroutineStack, public SocketBase {
public:

  ApplicationLifetime lifetime;
  ContainerState state = ContainerState::none;

  uint128_t uuid;
  Machine *machine;
  uint64_t deploymentID;
  int64_t createdAtMs;
  uint32_t taskAttemptNumber = 0;
  Vector<IPPrefix> addresses;
  Vector<Wormhole> wormholes;
  Vector<Whitehole> whiteholes;
  Vector<uint32_t> assignedGPUMemoryMBs;
  Vector<AssignedGPUDevice> assignedGPUDevices;
  uint8_t fragment;

  uint32_t nCrashes;

  DeploymentWork *plannedWork = nullptr;
  uint64_t destructionWaiterDeploymentID = 0;
  bool suppressStartupPairingNotifications = false;
  bool runtimeReady = false;
  bool hasCredentialBundle = false;
  bool hasPendingCredentialBundle = false;
  int64_t pendingCredentialBundleSinceMs = 0;
  CredentialBundle credentialBundle;
  CredentialBundle pendingCredentialBundle;
  String credentialRefreshFailure;
  bool statefulTopologyCutoverReady = false;
  uint32_t statefulTopologyCutoverSourceEpoch = 0;
  uint32_t statefulTopologyCutoverTargetEpoch = 0;

  bool isStateful = false;
  uint32_t shardGroup = 0; // only for stateful
  StatefulMeshRoles explicitStatefulMeshRoles = {};
  StatefulTopology explicitStatefulTopology = {};

  // Runtime resource assignments tracked on the brain
  uint16_t runtime_nLogicalCores = 0;
  uint32_t runtime_memoryMB = 0;
  uint32_t runtime_storageMB = 0;

  bytell_hash_set<uint16_t> advertisingOnPorts;

  uint32_t generateContainerID(void)
  {
    // 3 machines bytes
    // 1 container byte

    uint32_t containerID = 0;

    uint8_t *head = reinterpret_cast<uint8_t *>(&containerID);
    memcpy(head, &machine->fragment, 3);
    memcpy(head + 3, &fragment, 1);

    return containerID;
  }

  bool canProxySendToNeuron(void) const
  {
    if (machine == nullptr)
    {
      return false;
    }

    NeuronView *neuron = &machine->neuron;
    if (Ring::socketIsClosing(neuron))
    {
      return false;
    }

    if (neuron->isFixedFile)
    {
      return neuron->fslot >= 0;
    }

    return neuron->fd >= 0;
  }

  // these are sent out through the brain's connection to the neuron on that machine
  template <typename... Args>
  void proxySend(NeuronTopic topic, Args&&...args)
  {
    if (canProxySendToNeuron() == false)
    {
      return;
    }

    machine->queueSend(topic, std::forward<Args>(args)...);
  }

  void proxySendPairingPayload(NeuronTopic topic, const String& payload)
  {
    if (canProxySendToNeuron() == false)
    {
      return;
    }

    uint32_t payloadBytes = uint32_t(payload.size());
    if (uint64_t(payloadBytes) != payload.size())
    {
      return;
    }

    uint32_t headerOffset = Message::appendHeader(machine->neuron.wBuffer, topic);
    Message::append(machine->neuron.wBuffer, uuid);
    if (payloadBytes > 0)
    {
      Message::append<Alignment::one>(machine->neuron.wBuffer, payload.data(), payloadBytes);
    }
    Message::finish(machine->neuron.wBuffer, headerOffset);
    Ring::queueSend(&machine->neuron);
  }

  void advertisementPairing(uint128_t secret, uint128_t address, uint64_t service, uint16_t applicationID, bool activate) override
  {
    if (suppressStartupPairingNotifications)
    {
      return;
    }

    String payload;
    if (ProdigyWire::serializeAdvertisementPairingPayload(payload, secret, address, service, applicationID, activate))
    {
      proxySendPairingPayload(NeuronTopic::advertisementPairing, payload);
    }
  }

  void subscriptionPairing(uint128_t secret, uint128_t address, uint64_t service, uint16_t port, uint16_t applicationID, bool activate) override
  {
    if (suppressStartupPairingNotifications)
    {
      return;
    }

    if (activate == false)
    {
      std::fprintf(stderr,
                   "containerview subscriptionPairing uuid=%llu appID=%u service=%llu port=%u activate=%d state=%u runtimeReady=%d\n",
                   (unsigned long long)uuid,
                   unsigned(this->applicationID),
                   (unsigned long long)service,
                   unsigned(port),
                   int(activate),
                   unsigned(state),
                   int(runtimeReady));
      std::fflush(stderr);
    }

    String payload;
    if (ProdigyWire::serializeSubscriptionPairingPayload(payload, secret, address, service, port, applicationID, activate))
    {
      proxySendPairingPayload(NeuronTopic::subscriptionPairing, payload);
    }
  }

  uint128_t pairingAddress(void) const override
  {
    if (addresses.size() > 0)
    {
      uint128_t address = 0;
      memcpy(&address, addresses[0].network.v6, 16);
      return address;
    }

    return meshAddress;
  }

  uint16_t getRandomAdvertisementPort(void)
  {
    uint16_t port;

    do
    {
      port = Random::generateNumberWithNBits<16, uint16_t>();

    } while (port < 1024 || advertisingOnPorts.contains(port));

    return port;
  }

  uint32_t countSubscribers(void)
  {
    uint32_t count = 0;

    for (const auto& [key, subset] : advertisingTo)
    {
      count += subset.size();
    }

    return count;
  }

  bool readyForPairingNotifications(void) const override
  {
    return runtimeReady && state != ContainerState::destroyed && state != ContainerState::destroying && state != ContainerState::aboutToDestroy;
  }

  bool readyForSubscriptionPairingNotifications(void) const override
  {
    return runtimeReady || (state == ContainerState::healthy && canProxySendToNeuron());
  }

  void clearStatefulTopologyCutoverBarrier(void)
  {
    statefulTopologyCutoverReady = false;
    statefulTopologyCutoverSourceEpoch = 0;
    statefulTopologyCutoverTargetEpoch = 0;
  }

  bool hasStatefulTopologyCutoverBarrier(uint32_t sourceEpoch, uint32_t targetEpoch) const
  {
    return (statefulTopologyCutoverReady && statefulTopologyCutoverSourceEpoch == sourceEpoch && statefulTopologyCutoverTargetEpoch == targetEpoch);
  }

  bool applyStatefulTopologyCutoverMetric(uint64_t metricKey, uint64_t metricValue)
  {
    if (metricKey == ProdigyMetrics::runtimeStatefulTopologyCutoverReadyKey())
    {
      bool ready = (metricValue != 0);
      if (ready == false)
      {
        clearStatefulTopologyCutoverBarrier();
        return true;
      }

      statefulTopologyCutoverReady = true;
      return true;
    }

    if (metricKey == ProdigyMetrics::runtimeStatefulTopologyCutoverSourceEpochKey())
    {
      statefulTopologyCutoverSourceEpoch = uint32_t(metricValue);
      return true;
    }

    if (metricKey == ProdigyMetrics::runtimeStatefulTopologyCutoverTargetEpochKey())
    {
      statefulTopologyCutoverTargetEpoch = uint32_t(metricValue);
      return true;
    }

    return false;
  }

  void reconcileMeshAgainstState(bool notifySelf) // called during ContainerState changes
  {
    for (const auto& [service, subscription] : subscriptions)
    {
      if (subscription.startAt == state)
      {
        thisBrain->mesh->subscribe(service, this, subscription.nature, notifySelf);
      }
      else if (subscription.stopAt == state)
      {
        thisBrain->mesh->stopSubscription(service, this, subscription.nature, notifySelf);
      }
    }

    for (const auto& [service, advertisement] : advertisements)
    {
      if (advertisement.startAt == state)
      {
        thisBrain->mesh->advertise(service, this, advertisement.port, notifySelf);
      }
      else if (advertisement.stopAt == state)
      {
        thisBrain->mesh->stopAdvertisement(service, this, notifySelf);
      }
    }
  }

  void replayActivePairingsToSelf(void)
  {
    if (runtimeReady == false || thisBrain == nullptr || thisBrain->mesh == nullptr)
    {
      return;
    }

    for (const auto& [service, advertisers] : subscribedTo)
    {
      for (MeshNode *advertiserNode : advertisers)
      {
        ContainerView *advertiser = static_cast<ContainerView *>(advertiserNode);
        if (advertiser == nullptr || advertiser->runtimeReady == false)
        {
          continue;
        }

        auto advertisementIt = advertiser->advertisements.find(service);
        if (advertisementIt == advertiser->advertisements.end())
        {
          continue;
        }

        uint128_t secret = thisBrain->mesh->pairingSecretFor(advertiser, this, service);
        if (secret == 0)
        {
          continue;
        }

        subscriptionPairing(secret, advertiser->pairingAddress(), service, advertisementIt->second.port, advertiser->applicationID, true);
      }
    }

    for (const auto& [service, subscribers] : advertisingTo)
    {
      auto advertisementIt = advertisements.find(service);
      if (advertisementIt == advertisements.end())
      {
        continue;
      }

      for (MeshNode *subscriberNode : subscribers)
      {
        ContainerView *subscriber = static_cast<ContainerView *>(subscriberNode);
        if (subscriber == nullptr)
        {
          continue;
        }

        uint128_t secret = thisBrain->mesh->pairingSecretFor(this, subscriber, service);
        if (secret == 0)
        {
          continue;
        }

        advertisementPairing(secret, subscriber->pairingAddress(), service, subscriber->applicationID, true);
      }
    }
  }

  void replayActivePairingsToPeers(void)
  {
    if (runtimeReady == false || thisBrain == nullptr || thisBrain->mesh == nullptr)
    {
      return;
    }

    for (const auto& [service, subscribers] : advertisingTo)
    {
      auto advertisementIt = advertisements.find(service);
      if (advertisementIt == advertisements.end())
      {
        continue;
      }

      for (MeshNode *subscriberNode : subscribers)
      {
        ContainerView *subscriber = static_cast<ContainerView *>(subscriberNode);
        if (subscriber == nullptr || subscriber->readyForSubscriptionPairingNotifications() == false)
        {
          continue;
        }

        uint128_t secret = thisBrain->mesh->pairingSecretFor(this, subscriber, service);
        if (secret == 0)
        {
          continue;
        }

        subscriber->subscriptionPairing(secret, pairingAddress(), service, advertisementIt->second.port, applicationID, true);
      }
    }
  }

  void deactivateActivePeerSubscriptionsForRestart(void)
  {
    if (runtimeReady == false || thisBrain == nullptr || thisBrain->mesh == nullptr)
    {
      return;
    }

    for (const auto& [service, subscribers] : advertisingTo)
    {
      auto advertisementIt = advertisements.find(service);
      if (advertisementIt == advertisements.end())
      {
        continue;
      }

      for (MeshNode *subscriberNode : subscribers)
      {
        ContainerView *subscriber = static_cast<ContainerView *>(subscriberNode);
        if (subscriber == nullptr || subscriber->readyForSubscriptionPairingNotifications() == false)
        {
          continue;
        }

        uint128_t secret = thisBrain->mesh->pairingSecretFor(this, subscriber, service);
        if (secret == 0)
        {
          continue;
        }

        subscriber->subscriptionPairing(secret, pairingAddress(), service, advertisementIt->second.port, applicationID, false);
      }
    }
  }

  void replayRuntimeReadyPairings(void)
  {
    replayActivePairingsToSelf();
    replayActivePairingsToPeers();
  }

  StatefulMeshRoles effectiveStatefulMeshRoles(const DeploymentPlan& dplan) const
  {
    if (prodigyStatefulMeshRolesConfigured(explicitStatefulMeshRoles))
    {
      return explicitStatefulMeshRoles;
    }

    return StatefulMeshRoles::forShardGroup(dplan.stateful, dplan.config.applicationID, shardGroup);
  }

  StatefulTopology effectiveStatefulTopology(const DeploymentPlan& dplan, const ApplicationConfig *configOverride = nullptr) const
  {
    StatefulTopology topology = explicitStatefulTopology;
    prodigyPopulateDefaultStatefulTopology(topology, shardGroup, (configOverride ? *configOverride : dplan.config));
    return topology;
  }

  ContainerPlan generatePlan(const DeploymentPlan& dplan, uint32_t deploymentShardGroups = 0, const ApplicationConfig *configOverride = nullptr)
  {
    ContainerPlan plan;

    plan.uuid = uuid;
    plan.config = (configOverride ? *configOverride : dplan.config);
    plan.subscriptions = subscriptions;
    plan.advertisements = advertisements;
    plan.requiresDatacenterUniqueTag = dplan.requiresDatacenterUniqueTag;
    plan.runtimeReady = runtimeReady;

    for (const auto& [service, advertisers] : subscribedTo)
    {
      for (MeshNode *advertiser : advertisers)
      {
        if (advertiser == nullptr || advertiser->readyForPairingNotifications() == false)
        {
          continue;
        }

        auto advertisementIt = advertiser->advertisements.find(service);
        if (advertisementIt == advertiser->advertisements.end())
        {
          continue;
        }

        plan.subscriptionPairings.emplace(service, thisBrain->mesh->pairingSecretFor(advertiser, this, service), advertiser->pairingAddress(), service, advertisementIt->second.port);
      }
    }

    for (const auto& [service, subscribers] : advertisingTo)
    {
      for (MeshNode *subscriber : subscribers)
      {
        if (subscriber == nullptr)
        {
          continue;
        }

        plan.advertisementPairings.emplace(service, thisBrain->mesh->pairingSecretFor(this, subscriber, service), subscriber->pairingAddress(), service);
      }
    }

    if (dplan.config.type == ApplicationType::task || lifetime == ApplicationLifetime::canary)
    {
      plan.restartOnFailure = false;
    }
    else
    {
      // plan.restartOnFailure = dplan.restartOnFailure; // basically every container should restart on failure
      plan.restartOnFailure = true;
    }

    plan.fragment = fragment;
    plan.wormholes = wormholes;
    plan.whiteholes = whiteholes;
    plan.useHostNetworkNamespace = dplan.useHostNetworkNamespace;
    plan.addresses = addresses;
    plan.assignedGPUMemoryMBs = assignedGPUMemoryMBs;
    plan.assignedGPUDevices = assignedGPUDevices;

    plan.isStateful = isStateful;
    if (plan.isStateful)
    {
      plan.statefulMeshRoles = effectiveStatefulMeshRoles(dplan);
      auto pruneRole = [&](uint64_t& service) -> void {
        if (service == 0)
        {
          return;
        }

        if (plan.advertisements.find(service) != plan.advertisements.end() ||
            plan.subscriptions.find(service) != plan.subscriptions.end())
        {
          return;
        }

        service = 0;
      };

      pruneRole(plan.statefulMeshRoles.client);
      pruneRole(plan.statefulMeshRoles.sibling);
      pruneRole(plan.statefulMeshRoles.cousin);
      pruneRole(plan.statefulMeshRoles.seeding);
      pruneRole(plan.statefulMeshRoles.sharding);
      pruneRole(plan.statefulMeshRoles.topologyBridge);
      plan.statefulTopology = effectiveStatefulTopology(dplan, &plan.config);
    }

    plan.lifetime = lifetime;
    plan.state = state;
    plan.createdAtMs = createdAtMs;
    plan.taskAttemptNumber = taskAttemptNumber;
    plan.shardGroup = shardGroup;
    plan.nShardGroups = (plan.isStateful ? deploymentShardGroups : 0);
    plan.hasCredentialBundle = hasCredentialBundle;
    plan.credentialBundle = credentialBundle;

    return plan;
  }
};
