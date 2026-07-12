#include <networking/includes.h>
#include <prodigy/brain/elastic.address.operations.h>
#include <cstdio>

class TestSuite
{
public:

  uint32_t failed = 0;

  void expect(bool condition, const char *name)
  {
    if (condition == false)
    {
      std::fprintf(stderr, "FAIL: %s\n", name);
      ++failed;
    }
  }
};

class DeferredElasticIaaS final : public BrainIaaS
{
public:

  bool supportsTransactionalElasticAddresses(void) const override
  {
    return true;
  }

  bool validateProviderElasticAddressPlan(const ProviderElasticAddressPlan& plan,
                                          const ProviderElasticAddressRequest& request,
                                          uint128_t transactionNonce) const override
  {
    return plan.opaque == "prepared-plan"_ctv && request.cloudID.empty() == false &&
           transactionNonce != 0;
  }

  CoroutineStack *pending = nullptr;
  Vector<ProdigyBrainElasticAddressCoordinator::Action> started;
  Vector<String> cloudIDs;
  Vector<String> requestedAddresses;
  Vector<String> providerPools;
  Vector<String> allocationIDs;
  Vector<String> associationIDs;
  Vector<ProviderElasticAddressAssignment> assignments;
  Vector<String> failures;
  Vector<uint32_t> delegateIDs;
  uint32_t batchDepth = 0;
  uint32_t beginBatchCalls = 0;
  uint32_t endBatchCalls = 0;
  uint32_t delegateID = 1;
  bool reconfigurationPending = false;

  bool beginElasticAddressOperationBatch(void) override
  {
    ++batchDepth;
    ++beginBatchCalls;
    return true;
  }

  void endElasticAddressOperationBatch(void) override
  {
    --batchDepth;
    ++endBatchCalls;
    if (batchDepth == 0 && reconfigurationPending)
    {
      delegateID = 2;
      reconfigurationPending = false;
    }
  }

  void requestReconfiguration(void)
  {
    reconfigurationPending = true;
    if (batchDepth == 0)
    {
      delegateID = 2;
      reconfigurationPending = false;
    }
  }

  void boot(void) override
  {}

  void spinMachines(CoroutineStack *, MachineLifetime, const MachineConfig&, uint32_t, bytell_hash_set<Machine *>&, String& error) override
  {
    error.clear();
  }

  void getMachines(CoroutineStack *, const String&, bytell_hash_set<Machine *>&, String& failure) override
  {
    failure.clear();
  }

  void getBrains(CoroutineStack *, uint128_t, bool& selfIsBrain, bytell_hash_set<BrainView *>&, String& failure) override
  {
    selfIsBrain = false;
    failure.clear();
  }

  void hardRebootMachine(CoroutineStack *, const String&, String& failure) override
  {
    failure.clear();
  }

  void reportHardwareFailure(uint128_t, const String&) override
  {}

  void checkForSpotTerminations(CoroutineStack *, Vector<String>&) override
  {}

  void destroyMachine(CoroutineStack *, const String&, String& failure) override
  {
    failure.clear();
  }

  uint32_t supportedMachineKindsMask(void) const override
  {
    return 0;
  }

  void prepareProviderElasticAddress(CoroutineStack *coro,
                                     const ProviderElasticAddressRequest& request,
                                     uint128_t transactionNonce,
                                     ProviderElasticAddressPlan& plan,
                                     String& failure) override
  {
    (void)transactionNonce;
    uint32_t resultIndex = started.size();
    started.push_back(ProdigyBrainElasticAddressCoordinator::Action::prepareAssignment);
    delegateIDs.push_back(delegateID);
    pending = coro;
    co_await coro->suspend();
    pending = nullptr;
    cloudIDs.emplace_back().assign(request.cloudID);
    requestedAddresses.emplace_back().assign(request.requestedAddress);
    providerPools.emplace_back().assign(request.providerPool);
    plan.opaque.assign("prepared-plan"_ctv);
    if (resultIndex < failures.size())
    {
      failure = std::move(failures[resultIndex]);
    }
  }

  void applyProviderElasticAddress(CoroutineStack *coro,
                                   const ProviderElasticAddressPlan& plan,
                                   ProviderElasticAddressAssignment& assignment,
                                   String& failure) override
  {
    (void)plan;
    uint32_t resultIndex = started.size();
    started.push_back(ProdigyBrainElasticAddressCoordinator::Action::applyAssignment);
    pending = coro;
    co_await coro->suspend();
    pending = nullptr;
    if (resultIndex < assignments.size())
    {
      assignment = std::move(assignments[resultIndex]);
    }
    if (resultIndex < failures.size())
    {
      failure = std::move(failures[resultIndex]);
    }
  }

  void compensateProviderElasticAddress(CoroutineStack *coro,
                                        const ProviderElasticAddressPlan& plan,
                                        String& failure) override
  {
    (void)plan;
    uint32_t resultIndex = started.size();
    started.push_back(ProdigyBrainElasticAddressCoordinator::Action::compensateAssignment);
    pending = coro;
    co_await coro->suspend();
    pending = nullptr;
    if (resultIndex < failures.size())
    {
      failure = std::move(failures[resultIndex]);
    }
  }

  void releaseProviderElasticAddress(CoroutineStack *coro,
                                     const ProviderElasticAddressRelease& release,
                                     String& failure) override
  {
    uint32_t resultIndex = started.size();
    started.push_back(ProdigyBrainElasticAddressCoordinator::Action::release);
    delegateIDs.push_back(delegateID);
    pending = coro;
    co_await coro->suspend();
    pending = nullptr;
    allocationIDs.emplace_back().assign(release.allocationID);
    associationIDs.emplace_back().assign(release.associationID);
    if (resultIndex < failures.size())
    {
      failure = std::move(failures[resultIndex]);
    }
  }

  bool complete(void)
  {
    if (pending == nullptr)
    {
      return false;
    }
    CoroutineStack *stack = pending;
    stack->co_consume();
    return true;
  }
};

class CompletionRecorder
{
public:

  Vector<uint64_t> operationIDs;
  Vector<ProdigyBrainElasticAddressCoordinator::Action> actions;
  Vector<ProviderElasticAddressPlan> plans;
  Vector<ProviderElasticAddressAssignment> assignments;
  Vector<String> failures;

  static void completed(void *context,
                        uint64_t operationID,
                        ProdigyBrainElasticAddressCoordinator::Action action,
                        ProviderElasticAddressPlan&& plan,
                        ProviderElasticAddressAssignment&& assignment,
                        String&& failure)
  {
    CompletionRecorder& recorder = *static_cast<CompletionRecorder *>(context);
    recorder.operationIDs.push_back(operationID);
    recorder.actions.push_back(action);
    recorder.plans.push_back(std::move(plan));
    recorder.assignments.push_back(std::move(assignment));
    recorder.failures.push_back(std::move(failure));
  }
};

static ProviderElasticAddressRequest makeAssignRequest(const String& cloudID)
{
  ProviderElasticAddressRequest request;
  request.cloudID.assign(cloudID);
  request.family = ExternalAddressFamily::ipv4;
  request.intent = ElasticPrefixIntent::anyOrCreate;
  return request;
}

static void testOwnedSerializedOperations(TestSuite& suite)
{
  DeferredElasticIaaS provider;
  CompletionRecorder recorder;
  ProdigyBrainElasticAddressCoordinator operations(
      {&recorder, CompletionRecorder::completed});

  ProviderElasticAddressAssignment assignment;
  assignment.allocationID.assign("allocation-result"_ctv);
  assignment.associationID.assign("association-result"_ctv);
  assignment.releaseOnRemove = true;
  provider.assignments.push_back(std::move(assignment));
  provider.assignments.emplace_back();
  String firstFailure;
  firstFailure.assign("assign failed after partial provider result"_ctv);
  provider.failures.push_back(std::move(firstFailure));
  provider.failures.emplace_back();

  uint8_t cloudBuffer[] = "cloud-original";
  uint8_t addressBuffer[] = "203.0.113.9";
  uint8_t poolBuffer[] = "pool-original";
  ProviderElasticAddressRequest request;
  request.cloudID = String(cloudBuffer, sizeof(cloudBuffer) - 1, Copy::no);
  request.family = ExternalAddressFamily::ipv4;
  request.intent = ElasticPrefixIntent::anyOrCreate;
  request.requestedAddress = String(addressBuffer, sizeof(addressBuffer) - 1, Copy::no);
  request.providerPool = String(poolBuffer, sizeof(poolBuffer) - 1, Copy::no);
  suite.expect(operations.enqueue(provider, 41, request, 141),
               "brain_elastic_accepts_assignment");
  memset(cloudBuffer, 'x', sizeof(cloudBuffer) - 1);
  memset(addressBuffer, 'x', sizeof(addressBuffer) - 1);
  memset(poolBuffer, 'x', sizeof(poolBuffer) - 1);

  {
    ProviderElasticAddressRelease release;
    release.transactionNonce = 142;
    release.kind = RoutablePrefixKind::elastic;
    release.allocationID.assign("release-allocation"_ctv);
    release.associationID.assign("release-association"_ctv);
    release.releaseOnRemove = true;
    suite.expect(operations.enqueue(provider, 42, release),
                 "brain_elastic_queues_release_while_assignment_suspended");
    release.allocationID.assign("mutated"_ctv);
    release.associationID.clear();
  }

  suite.expect(provider.started.size() == 1 && operations.queuedOperations() == 1,
               "brain_elastic_serializes_provider_calls");
  suite.expect(provider.complete() && provider.started.size() == 2 &&
                   recorder.operationIDs.size() == 1,
               "brain_elastic_failure_completion_pumps_next_operation");
  suite.expect(provider.cloudIDs.size() == 1 && provider.cloudIDs[0] == "cloud-original"_ctv &&
                   provider.requestedAddresses[0] == "203.0.113.9"_ctv &&
                   provider.providerPools[0] == "pool-original"_ctv,
               "brain_elastic_materializes_assignment_string_views");
  suite.expect(recorder.operationIDs[0] == 41 &&
                   recorder.actions[0] == ProdigyBrainElasticAddressCoordinator::Action::prepareAssignment &&
                   recorder.plans[0].opaque == "prepared-plan"_ctv &&
                   recorder.failures[0] == "assign failed after partial provider result"_ctv,
               "brain_elastic_delivers_moved_assignment_and_failure");

  suite.expect(provider.complete() && operations.hasActiveOperation() == false &&
                   operations.queuedOperations() == 0,
               "brain_elastic_drains_owned_coroutine");
  suite.expect(provider.allocationIDs.size() == 1 &&
                   provider.allocationIDs[0] == "release-allocation"_ctv &&
                   provider.associationIDs[0] == "release-association"_ctv &&
                   recorder.operationIDs[1] == 42 &&
                   recorder.actions[1] == ProdigyBrainElasticAddressCoordinator::Action::release &&
                   recorder.assignments[1].allocationID.empty() && recorder.failures[1].empty(),
               "brain_elastic_owns_and_delivers_release_in_fifo_order");
}

static void testValidationAndProviderAffinity(TestSuite& suite)
{
  DeferredElasticIaaS provider;
  DeferredElasticIaaS otherProvider;
  ProdigyBrainElasticAddressCoordinator operations;
  ProviderElasticAddressRequest invalid;
  suite.expect(operations.enqueue(provider, 0, invalid, 1) == false,
               "brain_elastic_rejects_zero_operation_id");
  suite.expect(operations.enqueue(provider, 1, invalid, 1) == false,
               "brain_elastic_rejects_empty_assignment_identity");

  ProviderElasticAddressRequest request = makeAssignRequest("cloud-a"_ctv);
  request.family = static_cast<ExternalAddressFamily>(255);
  suite.expect(operations.enqueue(provider, 1, request, 1) == false,
               "brain_elastic_rejects_invalid_address_family");
  request.family = ExternalAddressFamily::ipv4;
  request.intent = static_cast<ElasticPrefixIntent>(255);
  suite.expect(operations.enqueue(provider, 1, request, 1) == false,
               "brain_elastic_rejects_invalid_prefix_intent");
  request.intent = ElasticPrefixIntent::anyOrCreate;
  suite.expect(operations.enqueue(provider, 1, request, 1),
               "brain_elastic_accepts_first_monotonic_operation");
  suite.expect(operations.enqueue(provider, 1, request, 1) == false,
               "brain_elastic_rejects_reused_operation_id");
  suite.expect(operations.enqueue(otherProvider, 2, request, 2) == false,
               "brain_elastic_rejects_provider_change_while_active");
  suite.expect(operations.enqueue(provider, 2, request, 2),
               "brain_elastic_provider_rejection_does_not_consume_operation_id");
  suite.expect(operations.enqueue(provider, 1, request, 1) == false,
               "brain_elastic_rejects_out_of_order_operation_id");
  while (provider.complete())
  {}

  ProviderElasticAddressRelease invalidRelease;
  invalidRelease.transactionNonce = 3;
  invalidRelease.kind = RoutablePrefixKind::BGP;
  suite.expect(operations.enqueue(provider, 3, invalidRelease) == false,
               "brain_elastic_rejects_non_elastic_release");
}

static void testQueueBound(TestSuite& suite)
{
  DeferredElasticIaaS provider;
  ProdigyBrainElasticAddressCoordinator operations;
  ProviderElasticAddressRequest request = makeAssignRequest("active"_ctv);
  suite.expect(operations.enqueue(provider, 1, request, 1),
               "brain_elastic_queue_bound_accepts_active_operation");
  bool accepted = true;
  for (uint32_t index = 0; index < ProdigyBrainElasticAddressCoordinator::maximumQueuedOperations; ++index)
  {
    String cloudID;
    cloudID.snprintf<"queued-{itoa}"_ctv>(index);
    request.cloudID.assign(cloudID);
    accepted = accepted && operations.enqueue(provider, uint64_t(index) + 2, request,
                                               uint128_t(index) + 2);
  }
  suite.expect(accepted && operations.queuedOperations() ==
                               ProdigyBrainElasticAddressCoordinator::maximumQueuedOperations,
               "brain_elastic_queue_accepts_exact_bounded_capacity");
  suite.expect(operations.enqueue(provider,
                                  ProdigyBrainElasticAddressCoordinator::maximumQueuedOperations + 2,
                                  request,
                                  ProdigyBrainElasticAddressCoordinator::maximumQueuedOperations + 2) == false,
               "brain_elastic_queue_rejects_overflow");
  while (provider.complete())
  {}
  suite.expect(operations.hasActiveOperation() == false,
               "brain_elastic_queue_bound_fixture_drains");
}

class CompensationQueue
{
public:

  ProdigyBrainElasticAddressCoordinator *operations = nullptr;
  DeferredElasticIaaS *provider = nullptr;

  static void completed(void *context,
                        uint64_t operationID,
                        ProdigyBrainElasticAddressCoordinator::Action action,
                        ProviderElasticAddressPlan&& plan,
                        ProviderElasticAddressAssignment&& assignment,
                        String&& failure)
  {
    (void)assignment;
    (void)plan;
    (void)failure;
    CompensationQueue& queue = *static_cast<CompensationQueue *>(context);
    if (operationID == 1 && action == ProdigyBrainElasticAddressCoordinator::Action::prepareAssignment)
    {
      ProviderElasticAddressRelease release;
      release.transactionNonce = 3;
      release.allocationID.assign("cleanup-allocation"_ctv);
      release.associationID.assign("cleanup-association"_ctv);
      release.releaseOnRemove = true;
      (void)queue.operations->enqueue(*queue.provider, 3, release);
    }
  }
};

static void testBatchPinsProviderAcrossQueuedAndCompensationOperations(TestSuite& suite)
{
  DeferredElasticIaaS provider;
  ProdigyBrainElasticAddressCoordinator operations;
  CompensationQueue completion {&operations, &provider};
  operations.configureCompletion({&completion, CompensationQueue::completed});

  ProviderElasticAddressRequest request = makeAssignRequest("cloud-a"_ctv);
  suite.expect(operations.enqueue(provider, 1, request, 1),
               "brain_elastic_batch_accepts_suspended_assignment");
  request.cloudID.assign("cloud-b"_ctv);
  suite.expect(operations.enqueue(provider, 2, request, 2),
               "brain_elastic_batch_queues_second_assignment");
  provider.requestReconfiguration();
  suite.expect(provider.delegateID == 1 && provider.batchDepth == 1,
               "brain_elastic_batch_defers_provider_reconfiguration");

  suite.expect(provider.complete() && provider.started.size() == 2,
               "brain_elastic_batch_pumps_queued_assignment");
  suite.expect(provider.complete() && provider.started.size() == 3,
               "brain_elastic_batch_pumps_completion_enqueued_cleanup");
  suite.expect(provider.complete() && operations.hasActiveOperation() == false,
               "brain_elastic_batch_drains_cleanup");
  suite.expect(provider.delegateIDs.size() == 3 && provider.delegateIDs[0] == 1 &&
                   provider.delegateIDs[1] == 1 && provider.delegateIDs[2] == 1,
               "brain_elastic_batch_pins_all_operations_to_original_delegate");
  suite.expect(provider.beginBatchCalls == 1 && provider.endBatchCalls == 1 &&
                   provider.batchDepth == 0 && provider.delegateID == 2,
               "brain_elastic_batch_applies_reconfiguration_after_drain");
}

int main(void)
{
  TestSuite suite;
  testOwnedSerializedOperations(suite);
  testValidationAndProviderAffinity(suite);
  testQueueBound(suite);
  testBatchPinsProviderAcrossQueuedAndCompensationOperations(suite);
  return suite.failed == 0 ? 0 : 1;
}
