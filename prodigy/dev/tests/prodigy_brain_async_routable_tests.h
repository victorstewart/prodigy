// Included by prodigy_brain_replication_credentials_unit.cpp after its shared fixtures.

static void testAsyncElasticRoutablePersistenceGates(TestSuite& suite)
{
  Neuron localBrain = {};
  localBrain.uuid = uint128_t(0x8a11);
  NeuronBase *previousNeuron = thisNeuron;
  thisNeuron = &localBrain;
  ScopedRing ring;
  auto registerRequest = [](TestBrain& brain, Mothership& mothership, String& buffer,
                            const String& name) {
    (void)sendElasticPrefixRegistration(brain, mothership, buffer, name);
  };
  auto unregisterRequest = [](TestBrain& brain, Mothership& mothership, const String& name) {
    RoutableSubnetUnregistration request;
    request.name.assign(name);
    String serialized;
    BitseryEngine::serialize(serialized, request);
    String buffer;
    Message *message = buildMothershipMessage(buffer, MothershipTopic::unregisterRoutableSubnet,
                                              serialized);
    brain.mothershipHandler(&mothership, message);
  };
  auto addReleasePrefix = [](TestBrain& brain, const Machine& machine, uint128_t uuid,
                             const String& name) {
    DistributableExternalSubnet prefix = makeElasticAuditPrefix(uuid, name);
    prefix.machineUUID = machine.uuid;
    brain.brainConfig.distributableExternalSubnets.push_back(std::move(prefix));
  };
  auto finishDurableCallbacks = [](TestBrain& brain) {
    for (uint32_t attempts = 0; attempts < 8 && brain.pendingRuntimePersistence.empty() == false;
         ++attempts)
    {
      brain.finishRuntimePersistence(true);
    }
  };

  {
    TestBrain brain;
    Mothership mothership;
    ElasticPrefixBrainIaaS iaas;
    Machine machine;
    configureElasticPrefixTarget(brain, mothership, iaas, machine, 11, uint128_t(0x8101),
                                 "cloud-async-assignment-success"_ctv);
    brain.holdRuntimePersistence = true;
    String buffer;
    registerRequest(brain, mothership, buffer, "elastic-async-assignment-success"_ctv);
    suite.expect(iaas.assignCalls == 0 && mothership.wBuffer.empty() &&
                     brain.pendingRuntimePersistence.size() == 1,
                 "elastic_assignment_waits_for_durable_intent_before_provider_or_reply");
    brain.finishRuntimePersistence(true);
    suite.expect(iaas.assignCalls == 0 && mothership.wBuffer.empty() &&
                     brain.pendingRuntimePersistence.size() == 1,
                 "elastic_assignment_plan_waits_for_its_durable_receipt");
    brain.finishRuntimePersistence(true);
    suite.expect(iaas.assignCalls == 0 && mothership.wBuffer.empty() &&
                     brain.pendingRuntimePersistence.size() == 1,
                 "elastic_assignment_attempt_waits_for_its_durable_receipt");
    brain.finishRuntimePersistence(true);
    suite.expect(iaas.assignCalls == 1 && mothership.wBuffer.empty() &&
                     !brain.pendingRuntimePersistence.empty(),
                 "elastic_assignment_provider_result_waits_for_durable_completion");
    finishDurableCallbacks(brain);
    RoutableSubnetRegistration response;
    suite.expect(iaas.assignCalls == 1 &&
                     extractRoutableSubnetRegistrationResponse(mothership.wBuffer, response) &&
                     response.success && response.created,
                 "elastic_assignment_runs_provider_and_success_reply_after_durable_intent");
    brain.activeMotherships.erase(&mothership);
  }

  {
    TestBrain brain;
    Mothership mothership;
    ElasticPrefixBrainIaaS iaas;
    Machine machine;
    configureElasticPrefixTarget(brain, mothership, iaas, machine, 13, uint128_t(0x8201),
                                 "cloud-async-assignment-failure"_ctv);
    brain.holdRuntimePersistence = true;
    String buffer;
    registerRequest(brain, mothership, buffer, "elastic-async-assignment-failure"_ctv);
    brain.finishRuntimePersistence(false);
    RoutableSubnetRegistration response;
    suite.expect(iaas.assignCalls == 0 && brain.pendingElasticAddressControlOperations.empty() &&
                     brain.masterAuthorityRuntimeState.pendingElasticAddressAssignments.empty() &&
                     extractRoutableSubnetRegistrationResponse(mothership.wBuffer, response) &&
                     response.success == false,
                 "elastic_assignment_persistence_failure_skips_provider_and_replies_failure");
    brain.activeMotherships.erase(&mothership);
  }

  {
    TestBrain brain;
    Mothership mothership;
    ElasticPrefixBrainIaaS iaas;
    Machine machine;
    configureElasticPrefixTarget(brain, mothership, iaas, machine, 15, uint128_t(0x8301),
                                 "cloud-async-assignment-stale"_ctv);
    brain.holdRuntimePersistence = true;
    String buffer;
    registerRequest(brain, mothership, buffer, "elastic-async-assignment-stale"_ctv);
    brain.activeMotherships.erase(&mothership);
    machine.neuron.connected = false;
    machine.neuron.fslot = -1;
    ++brain.masterAuthorityEpoch;
    brain.finishRuntimePersistence(true);
    suite.expect(iaas.assignCalls == 0 && brain.pendingElasticAddressControlOperations.empty() &&
                     mothership.wBuffer.empty(),
                 "elastic_assignment_stale_persistence_completion_has_no_provider_effect_or_reply");
    brain.activeMotherships.erase(&mothership);
  }

  {
    TestBrain brain;
    Mothership mothership;
    ElasticPrefixBrainIaaS iaas;
    Machine machine;
    configureElasticPrefixTarget(brain, mothership, iaas, machine, 17, uint128_t(0x8401),
                                 "cloud-async-release-success"_ctv);
    addReleasePrefix(brain, machine, uint128_t(0x8402), "elastic-async-release-success"_ctv);
    brain.holdRuntimePersistence = true;
    unregisterRequest(brain, mothership, "elastic-async-release-success"_ctv);
    suite.expect(iaas.releaseCalls == 0 && mothership.wBuffer.empty() &&
                     brain.pendingRuntimePersistence.size() == 1,
                 "elastic_release_waits_for_durable_intent_before_provider_or_reply");
    brain.finishRuntimePersistence(true);
    suite.expect(iaas.releaseCalls == 0 && mothership.wBuffer.empty() &&
                     brain.pendingRuntimePersistence.size() == 1,
                 "elastic_release_attempt_waits_for_its_durable_receipt");
    brain.finishRuntimePersistence(true);
    suite.expect(iaas.releaseCalls == 1 && mothership.wBuffer.empty() &&
                     !brain.pendingRuntimePersistence.empty(),
                 "elastic_release_provider_result_waits_for_durable_completion");
    finishDurableCallbacks(brain);
    RoutableSubnetUnregistration response;
    suite.expect(iaas.releaseCalls == 1 &&
                     extractRoutableSubnetUnregistrationResponse(mothership.wBuffer, response) &&
                     response.success && response.removed,
                 "elastic_release_runs_provider_and_success_reply_after_durable_intent");
    brain.activeMotherships.erase(&mothership);
  }

  {
    TestBrain brain;
    Mothership mothership;
    ElasticPrefixBrainIaaS iaas;
    Machine machine;
    configureElasticPrefixTarget(brain, mothership, iaas, machine, 19, uint128_t(0x8501),
                                 "cloud-async-release-failure"_ctv);
    addReleasePrefix(brain, machine, uint128_t(0x8502), "elastic-async-release-failure"_ctv);
    brain.holdRuntimePersistence = true;
    unregisterRequest(brain, mothership, "elastic-async-release-failure"_ctv);
    brain.finishRuntimePersistence(false);
    suite.expect(iaas.releaseCalls == 0 && brain.pendingElasticAddressControlOperations.size() == 1 &&
                     brain.masterAuthorityRuntimeState.pendingElasticAddressReleases.size() == 1 &&
                     mothership.wBuffer.empty(),
                 "elastic_release_persistence_failure_retains_intent_without_provider_or_reply");
    brain.activeMotherships.erase(&mothership);
  }

  {
    TestBrain brain;
    Mothership mothership;
    ElasticPrefixBrainIaaS iaas;
    Machine machine;
    configureElasticPrefixTarget(brain, mothership, iaas, machine, 21, uint128_t(0x8601),
                                 "cloud-async-release-stale"_ctv);
    addReleasePrefix(brain, machine, uint128_t(0x8602), "elastic-async-release-stale"_ctv);
    brain.holdRuntimePersistence = true;
    unregisterRequest(brain, mothership, "elastic-async-release-stale"_ctv);
    ++brain.masterAuthorityEpoch;
    brain.finishRuntimePersistence(true);
    suite.expect(iaas.releaseCalls == 0 && mothership.wBuffer.empty(),
                 "elastic_release_stale_persistence_completion_has_no_provider_effect_or_reply");
    brain.activeMotherships.erase(&mothership);
  }
  thisNeuron = previousNeuron;
}

static void testAsyncStaticRoutableRegistryPersistenceGates(TestSuite& suite)
{
  ScopedRing ring;
  auto makeRequest = [](const String& name) {
    RoutableSubnetRegistration request;
    request.subnet.name.assign(name);
    request.subnet.subnet = IPPrefix("2001:db8:901::1", true, 128);
    request.subnet.usage = ExternalSubnetUsage::wormholes;
    request.subnet.ingressScope = RoutableIngressScope::singleMachine;
    return request;
  };
  auto submit = [](TestBrain& brain, Mothership& mothership,
                   const RoutableSubnetRegistration& request, String& buffer) {
    String serialized;
    BitseryEngine::serialize(serialized, request);
    Message *message = buildMothershipMessage(buffer, MothershipTopic::registerRoutableSubnet, serialized);
    brain.mothershipHandler(&mothership, message);
  };
  {
    TestBrain brain;
    Mothership mothership;
    Machine machine;
    brain.weAreMaster = true;
    brain.noMasterYet = false;
    mothership.isFixedFile = true;
    mothership.fslot = 23;
    (void)brain.activateMothershipConnection(&mothership);
    machine.uuid = uint128_t(0x901);
    brain.machines.insert(&machine);
    brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
    brain.holdRuntimePersistence = true;
    String buffer;
    submit(brain, mothership, makeRequest("async-static-success"_ctv), buffer);
    suite.expect(mothership.wBuffer.empty() && brain.pendingRuntimePersistence.size() == 1,
                 "static_routable_registry_waits_for_durable_commit_before_reply");
    brain.finishRuntimePersistence(true);
    RoutableSubnetRegistration response;
    suite.expect(extractRoutableSubnetRegistrationResponse(mothership.wBuffer, response) && response.success,
                 "static_routable_registry_replies_success_after_durable_commit");
    brain.activeMotherships.erase(&mothership);
  }
  {
    TestBrain brain;
    Mothership mothership;
    Machine machine;
    brain.weAreMaster = true;
    brain.noMasterYet = false;
    mothership.isFixedFile = true;
    mothership.fslot = 24;
    (void)brain.activateMothershipConnection(&mothership);
    machine.uuid = uint128_t(0x902);
    brain.machines.insert(&machine);
    brain.machinesByUUID.insert_or_assign(machine.uuid, &machine);
    brain.holdRuntimePersistence = true;
    String buffer;
    submit(brain, mothership, makeRequest("async-static-failure"_ctv), buffer);
    brain.finishRuntimePersistence(false);
    RoutableSubnetRegistration response;
    suite.expect(brain.brainConfig.distributableExternalSubnets.empty() &&
                     extractRoutableSubnetRegistrationResponse(mothership.wBuffer, response) && !response.success,
                 "static_routable_registry_restores_snapshot_after_persistence_failure");
    brain.activeMotherships.erase(&mothership);
  }
}
