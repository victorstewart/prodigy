// Included after the shared fixtures; overrides only the storage boundary.
class AsyncTopologyBrain : public ResumableAddMachinesBrain {
public:
  ClusterTopology heldTopology;
  PersistenceCompletion heldCompletion;
  void persistAuthoritativeClusterTopologyAsync(ClusterTopology topology, PersistenceCompletion completion) override
  {
    heldTopology = std::move(topology); heldCompletion = std::move(completion);
  }
  void finishTopologyReceipt(bool durable)
  {
    if (durable) authoritativeTopology = heldTopology;
    auto completion = std::move(heldCompletion);
    if (completion) completion(durable);
  }
};

static void testAsyncTopologyCallers(TestSuite& suite)
{
  for (int result = 0; result < 3; ++result)
  {
    ScopedRing ring;
    AsyncTopologyBrain brain; NoopBrainIaaS iaas;
    brain.iaas = &iaas; brain.noMasterYet = false; brain.nBrains = 1;
    brain.brainConfig.clusterUUID = 0x5a01;
    ClusterMachine original = makeRackUpdateMachine(0x5a02, 1);
    brain.authoritativeTopology.version = 7;
    brain.authoritativeTopology.machines.push_back(original);
    AddMachines request;
    request.clusterUUID = brain.brainConfig.clusterUUID;
    auto update = original; update.rackUUID = 2;
    request.adoptedMachines.push_back(update);
    bool replied = false; AddMachines response;
    brain.addMachines(nullptr, request, {}, nullptr, [&](AddMachines value) {
      replied = true; response = std::move(value);
    });
    suite.expect(bool(brain.heldCompletion) && !replied && brain.authoritativeTopology.machines[0].rackUUID == 1,
                 "addmachines_waits_for_topology_receipt_before_response");
    if (result == 2) ++brain.masterAuthorityEpoch;
    brain.finishTopologyReceipt(result != 0);
    suite.expect(result == 2 ? !replied : replied && response.success == (result == 1),
                 "addmachines_topology_success_failure_stale_receipt");
    // Restoration allocates runtime views; leave their destruction to Brain.
  }
  for (int result = 0; result < 3; ++result)
  {
    ScopedRing ring;
    AsyncTopologyBrain brain; BrainView sender;
    ClusterTopology candidate; candidate.version = 5;
    candidate.machines.push_back(makeRackUpdateMachine(0x5a03, 2));
    String payload, frame; BitseryEngine::serialize(payload, candidate);
    brain.brainHandler(&sender, buildBrainMessage(frame, BrainTopic::replicateClusterTopology, payload));
    suite.expect(brain.machines.empty() && bool(brain.heldCompletion),
                 "replicated_topology_does_not_expose_membership_before_receipt");
    if (result == 2) ++brain.masterAuthorityEpoch;
    brain.finishTopologyReceipt(result != 0);
    suite.expect(brain.machines.empty() == (result != 1),
                 "replicated_topology_publishes_only_durable_current_membership");
  }
  for (MothershipTopic topic : {MothershipTopic::upsertMachineSchemas, MothershipTopic::deltaMachineBudget,
                                MothershipTopic::deleteMachineSchema})
  for (bool durable : {false, true})
  {
    ScopedAsyncMothershipRing ring;
    ScopedSocketPair sockets;
    ResumableAddMachinesBrain brain; NoopBrainIaaS iaas; Mothership stream;
    brain.iaas = &iaas; brain.weAreMaster = true; brain.noMasterYet = false;
    brain.authoritativeTopology.version = 9;
    brain.authoritativeTopology.machines.push_back(makeRackUpdateMachine(0x5a04, 1));
    if (suite.require(sockets.create(suite, "schema_async_socket_pair"),
                      "schema_async_socket_pair_required") == false) return;
    stream.isFixedFile = false; stream.fd = sockets.takeLeft();
    if (suite.require(brain.activateMothershipConnection(&stream),
                      "schema_async_activates_mothership") == false) return;
    RingDispatcher::installMultiplexee(&stream, &brain);
    ProdigyManagedMachineSchemaPatch patch;
    patch.schema = "async-schema"_ctv;
    patch.hasKind = true; patch.kind = MachineConfig::MachineKind::vm;
    patch.hasLifetime = true; patch.lifetime = MachineLifetime::ondemand;
    patch.hasProviderMachineType = true; patch.providerMachineType = "c7i.large"_ctv;
    patch.hasRegion = true; patch.region = "us-east-1"_ctv;
    patch.hasZone = true; patch.zone = "us-east-1a"_ctv;
    patch.hasBudget = true; patch.budget = 0;
    if (topic != MothershipTopic::upsertMachineSchemas)
    {
      bool created = false; String failure;
      suite.expect(prodigyUpsertManagedMachineSchema(brain.masterAuthorityRuntimeState.machineSchemas, patch,
                                                    &created, &failure), "schema_async_fixture_seed");
    }
    String payload, frame;
    if (topic == MothershipTopic::upsertMachineSchemas)
    {
      UpsertMachineSchemas request; request.patches.push_back(patch); BitseryEngine::serialize(payload, request);
    }
    else if (topic == MothershipTopic::deltaMachineBudget)
    {
      DeltaMachineBudget request; request.schema = patch.schema; request.delta = -1; BitseryEngine::serialize(payload, request);
    }
    else
    {
      DeleteMachineSchema request; request.schema = patch.schema; BitseryEngine::serialize(payload, request);
    }
    brain.holdRuntimePersistence = true;
    brain.mothershipHandler(&stream, buildMothershipMessage(frame, topic, payload));
    suite.expect(stream.wBuffer.empty() && brain.pendingRuntimePersistence.size() == 1,
                 "schema_mutation_no_reply_before_durable_receipt");
    brain.finishRuntimePersistence(durable);
    bool success = false, decoded = false;
    if (topic == MothershipTopic::upsertMachineSchemas)
    { UpsertMachineSchemas response; decoded = extractAsyncRequestResponse(stream.wBuffer, topic, response); success = response.success; }
    else if (topic == MothershipTopic::deltaMachineBudget)
    { DeltaMachineBudget response; decoded = extractAsyncRequestResponse(stream.wBuffer, topic, response); success = response.success; }
    else
    { DeleteMachineSchema response; decoded = extractAsyncRequestResponse(stream.wBuffer, topic, response); success = response.success; }
    suite.expect(decoded && success == durable, "schema_mutation_response_follows_receipt");
    RingDispatcher::eraseMultiplexee(&stream);
    brain.activeMotherships.erase(&stream);
    brain.closingMotherships.erase(&stream);
    if (stream.fd >= 0) { ::close(stream.fd); stream.fd = -1; }
  }
}
