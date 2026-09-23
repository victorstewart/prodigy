// Included after TestBrain and the TLS resumption fixture helpers.
static void testAsyncTlsLifecyclePersistenceGate(TestSuite& suite)
{
  ScopedRing ring;
  auto setup = [&](TestBrain& brain, Machine& machine, ApplicationDeployment& deployment,
                   ContainerView& container, uint16_t app) -> DeploymentPlan {
    brain.weAreMaster = true; brain.nBrains = 1;
    DeploymentPlan plan = makeDeploymentPlan(app, 991);
    plan.wormholes.push_back(makeTlsResumptionTestWormhole()); deployment.plan = plan;
    machine.uuid = app; container.uuid = uint128_t(app) + 1; container.machine = &machine;
    machine.neuron.isFixedFile = true;
    machine.neuron.fslot = 14;
    container.deploymentID = plan.config.deploymentID(); container.state = ContainerState::healthy;
    deployment.containers.insert(&container); brain.deployments.insert_or_assign(plan.config.deploymentID(), &deployment);
    brain.containers.insert_or_assign(container.uuid, &container); return plan;
  };
  auto cleanup = [](TestBrain& brain, Machine& machine, ApplicationDeployment& deployment, ContainerView& container, const DeploymentPlan& plan) {
    brain.containers.erase(container.uuid); brain.deployments.erase(plan.config.deploymentID()); deployment.containers.erase(&container);
    if (!machine.neuron.isFixedFile && machine.neuron.fd >= 0) { ::close(machine.neuron.fd); machine.neuron.fd = -1; }
  };
  auto seed = [&](TestBrain& brain, const DeploymentPlan& plan, String& failure) {
    brain.holdRuntimePersistence = false;
    TlsResumptionSnapshot *snapshot = brain.beginTlsResumptionAcceptOnlyRollout(plan, plan.wormholes[0], 1'700'200'000'000, false, &failure);
    suite.expect(snapshot && brain.masterAuthorityRuntimeStateDurable, "tls_lifecycle_seed_is_durable_before_held_receipt");
    return snapshot;
  };
  {
    Machine machine; ApplicationDeployment deployment; ContainerView container; TestBrain brain;
    DeploymentPlan plan = setup(brain, machine, deployment, container, 60'201); String failure = {};
    brain.holdRuntimePersistence = true;
    TlsResumptionSnapshot *initial = brain.beginTlsResumptionAcceptOnlyRollout(plan, plan.wormholes[0], 1'700'200'001'000, true, &failure);
    TlsResumptionSnapshot *repeat = brain.beginTlsResumptionAcceptOnlyRollout(plan, plan.wormholes[0], 1'700'200'001'001, true, &failure);
    suite.expect(initial && repeat && machine.neuron.wBuffer.empty() && !brain.pendingRuntimePersistence.empty(),
                 "tls_accept_only_initial_and_repeat_hold_neuron_publication");
    while (!brain.pendingRuntimePersistence.empty()) brain.finishRuntimePersistence(true);
    suite.expect(!machine.neuron.wBuffer.empty(), "tls_accept_only_receipt_publishes_to_live_neuron");
    cleanup(brain, machine, deployment, container, plan);
  }
  for (int result = 0; result < 3; ++result)
  {
    Machine machine; ApplicationDeployment deployment; ContainerView container; TestBrain brain;
    DeploymentPlan plan = setup(brain, machine, deployment, container, uint16_t(60'210 + result)); String failure = {};
    TlsResumptionSnapshot *snapshot = seed(brain, plan, failure);
    if (snapshot) (void)brain.recordTlsResumptionApplyAck(container.uuid, makeTlsResumptionAck(plan.wormholes[0].name, snapshot->generation));
    machine.neuron.wBuffer.clear(); brain.holdRuntimePersistence = true;
    const bool changed = brain.promoteTlsResumptionIssueEpochIfAcked(plan, plan.wormholes[0], 1'700'200'002'000, true, &failure);
    suite.expect(changed && machine.neuron.wBuffer.empty() && brain.pendingRuntimePersistence.size() == 1,
                 "tls_promotion_holds_live_neuron_delta_until_receipt");
    if (result == 2) ++brain.masterAuthorityEpoch;
    brain.finishRuntimePersistence(result == 1);
    suite.expect(machine.neuron.wBuffer.empty() == (result != 1), "tls_promotion_failure_or_stale_receipt_has_no_neuron_delta");
    cleanup(brain, machine, deployment, container, plan);
  }
  for (int result = 0; result < 3; ++result)
  {
    Machine machine; ApplicationDeployment deployment; ContainerView container; TestBrain brain;
    DeploymentPlan plan = setup(brain, machine, deployment, container, uint16_t(60'220 + result)); String failure = {};
    TlsResumptionSnapshot *first = seed(brain, plan, failure);
    TlsResumptionSnapshot *second = brain.beginTlsResumptionAcceptOnlyRollout(plan, plan.wormholes[0], 1'700'200'003'000, false, &failure);
    if (first && second) (void)setTlsResumptionEpochAcceptUntilMs(second, first->generation, 1'700'200'003'100);
    machine.neuron.wBuffer.clear(); brain.holdRuntimePersistence = true;
    const uint32_t retired = brain.retireExpiredTlsResumptionEpochs(plan, 1'700'200'003'101, true);
    suite.expect(retired == 1 && machine.neuron.wBuffer.empty() && brain.pendingRuntimePersistence.size() == 1,
                 "tls_retire_holds_live_neuron_delta_until_receipt");
    if (result == 2) ++brain.masterAuthorityEpoch;
    brain.finishRuntimePersistence(result == 1);
    suite.expect(machine.neuron.wBuffer.empty() == (result != 1), "tls_retire_failure_or_stale_receipt_has_no_neuron_delta");
    cleanup(brain, machine, deployment, container, plan);
  }
  for (int result = 0; result < 3; ++result)
  {
    Machine machine; ApplicationDeployment deployment; ContainerView container; TestBrain brain;
    DeploymentPlan enabled = setup(brain, machine, deployment, container, uint16_t(60'230 + result)); String failure = {};
    (void)seed(brain, enabled, failure); DeploymentPlan disabled = enabled; disabled.wormholes.clear();
    machine.neuron.wBuffer.clear(); brain.holdRuntimePersistence = true;
    const uint32_t removed = brain.removeTlsResumptionStateNotEnabledByPlan(disabled, true);
    suite.expect(removed == 1 && machine.neuron.wBuffer.empty() && brain.pendingRuntimePersistence.size() == 1,
                 "tls_remove_holds_live_neuron_removal_until_receipt");
    if (result == 2) ++brain.masterAuthorityEpoch;
    brain.finishRuntimePersistence(result == 1);
    suite.expect(machine.neuron.wBuffer.empty() == (result != 1), "tls_remove_failure_or_stale_receipt_has_no_neuron_removal");
    cleanup(brain, machine, deployment, container, enabled);
  }
}
