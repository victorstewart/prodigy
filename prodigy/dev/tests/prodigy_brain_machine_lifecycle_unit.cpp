#include <networking/includes.h>
#include <prodigy/brain/machine.lifecycle.h>
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

class DeferredLifecycleIaaS final : public BrainIaaS
{
public:

  CoroutineStack *pending = nullptr;
  Vector<String> started;
  Vector<String> completed;
  Vector<uint8_t> actions;
  String nextFailure;

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

  void run(CoroutineStack *coro, uint8_t action, const String& cloudID, String& failure)
  {
    String ownedCloudID = cloudID;
    started.push_back(ownedCloudID);
    actions.push_back(action);
    pending = coro;
    co_await coro->suspend();
    pending = nullptr;
    completed.push_back(std::move(ownedCloudID));
    failure = nextFailure;
    nextFailure.clear();
  }

  void hardRebootMachine(CoroutineStack *coro, const String& cloudID, String& failure) override
  {
    run(coro, 0, cloudID, failure);
  }

  void reportHardwareFailure(uint128_t, const String&) override
  {}

  void checkForSpotTerminations(CoroutineStack *, Vector<String>&) override
  {}

  void destroyMachine(CoroutineStack *coro, const String& cloudID, String& failure) override
  {
    run(coro, 1, cloudID, failure);
  }

  uint32_t supportedMachineKindsMask(void) const override
  {
    return 0;
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

  Vector<ProdigyBrainMachineLifecycleCoordinator::Action> actions;
  Vector<uint128_t> uuids;
  Vector<String> cloudIDs;
  Vector<String> failures;

  static void completed(void *context,
                        ProdigyBrainMachineLifecycleCoordinator::Action action,
                        uint128_t uuid,
                        const String& cloudID,
                        const String& failure)
  {
    CompletionRecorder& recorder = *static_cast<CompletionRecorder *>(context);
    recorder.actions.push_back(action);
    recorder.uuids.push_back(uuid);
    recorder.cloudIDs.push_back(cloudID);
    recorder.failures.push_back(failure);
  }
};

static void testSerializedOwnedIdentity(TestSuite& suite)
{
  DeferredLifecycleIaaS provider;
  CompletionRecorder recorder;
  ProdigyBrainMachineLifecycleCoordinator coordinator(
      {&recorder, CompletionRecorder::completed});

  String first;
  first.append("cloud-a"_ctv);
  suite.expect(coordinator.enqueue(provider,
                                   ProdigyBrainMachineLifecycleCoordinator::Action::destroy,
                                   11,
                                   first),
               "brain_lifecycle_accepts_first_destroy");
  first.clear();
  first.append("mutated"_ctv);
  suite.expect(coordinator.enqueue(provider,
                                   ProdigyBrainMachineLifecycleCoordinator::Action::hardReboot,
                                   12,
                                   "cloud-b"_ctv),
               "brain_lifecycle_queues_second_operation_while_first_suspended");
  suite.expect(provider.started.size() == 1 && provider.started[0] == "cloud-a"_ctv &&
                   coordinator.queuedOperations() == 1,
               "brain_lifecycle_owns_identity_and_serializes_provider_calls");

  provider.nextFailure.assign("destroy failed"_ctv);
  suite.expect(provider.complete() && provider.started.size() == 2 &&
                   provider.started[1] == "cloud-b"_ctv && recorder.cloudIDs.size() == 1,
               "brain_lifecycle_completion_starts_next_queued_operation");
  suite.expect(provider.complete() && coordinator.hasActiveOperation() == false &&
                   coordinator.queuedOperations() == 0,
               "brain_lifecycle_drains_and_retires_owned_coroutine");
  suite.expect(recorder.cloudIDs.size() == 2 && recorder.cloudIDs[0] == "cloud-a"_ctv &&
                   recorder.cloudIDs[1] == "cloud-b"_ctv &&
                   recorder.uuids[0] == 11 && recorder.uuids[1] == 12 &&
                   recorder.failures[0] == "destroy failed"_ctv && recorder.failures[1].empty(),
               "brain_lifecycle_reports_exact_owned_results_in_fifo_order");
}

static void testQueueBound(TestSuite& suite)
{
  DeferredLifecycleIaaS provider;
  ProdigyBrainMachineLifecycleCoordinator coordinator;
  suite.expect(coordinator.enqueue(provider,
                                   ProdigyBrainMachineLifecycleCoordinator::Action::destroy,
                                   1,
                                   "active"_ctv),
               "brain_lifecycle_queue_bound_accepts_active_operation");
  bool accepted = true;
  for (uint32_t index = 0; index < ProdigyBrainMachineLifecycleCoordinator::maximumQueuedOperations; ++index)
  {
    String cloudID;
    cloudID.snprintf<"queued-{itoa}"_ctv>(index);
    accepted = accepted && coordinator.enqueue(provider,
                                                ProdigyBrainMachineLifecycleCoordinator::Action::destroy,
                                                index + 2,
                                                cloudID);
  }
  suite.expect(accepted && coordinator.queuedOperations() ==
                               ProdigyBrainMachineLifecycleCoordinator::maximumQueuedOperations,
               "brain_lifecycle_queue_accepts_exact_bounded_capacity");
  suite.expect(coordinator.enqueue(provider,
                                   ProdigyBrainMachineLifecycleCoordinator::Action::destroy,
                                   999,
                                   "overflow"_ctv) == false,
               "brain_lifecycle_queue_rejects_overflow");
  while (provider.complete())
  {}
  suite.expect(coordinator.hasActiveOperation() == false,
               "brain_lifecycle_queue_bound_fixture_drains");
}

int main(void)
{
  TestSuite suite;
  testSerializedOwnedIdentity(suite);
  testQueueBound(suite);
  return suite.failed == 0 ? 0 : 1;
}
