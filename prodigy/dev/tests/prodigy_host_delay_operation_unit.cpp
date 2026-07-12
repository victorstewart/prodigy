#include <networking/includes.h>
#include <prodigy/host.delay.operation.h>

class TestSuite
{
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    basics_log("%s: %s\n", condition ? "PASS" : "FAIL", name);
    failed += condition ? 0 : 1;
  }
};

class FakeRing
{
public:

  using Operation = ProdigyHostDelayOperation;

  TimeoutPacket *packet = nullptr;
  uint64_t delayUs = 0;
  uint32_t queues = 0;
  uint32_t cancellations = 0;
  bool completeInline = false;
  bool completeCancellationInline = false;

  static void queue(void *context, TimeoutPacket *packet)
  {
    FakeRing& ring = *static_cast<FakeRing *>(context);
    ring.packet = packet;
    ring.delayUs = uint64_t(packet->timeout.tv_sec) * 1'000'000 +
                   uint64_t(packet->timeout.tv_nsec) / 1000;
    ring.queues += 1;
    if (ring.completeInline)
    {
      ring.expire();
    }
  }

  static void cancel(void *context, TimeoutPacket *packet)
  {
    FakeRing& ring = *static_cast<FakeRing *>(context);
    if (ring.packet != packet)
    {
      return;
    }
    ring.cancellations += 1;
    if (ring.completeCancellationInline)
    {
      ring.expire();
    }
  }

  Operation::Submission submission(void)
  {
    return {this, queue, cancel};
  }

  void expire(void)
  {
    TimeoutPacket *const completed = packet;
    packet = nullptr;
    completed->dispatcher->dispatchTimeout(completed);
  }
};

class CountingStack : public CoroutineStack
{
public:

  uint32_t wakes = 0;

  void co_consume(void) override
  {
    wakes += 1;
  }
};

class DestroyingStack final : public CountingStack
{
public:

  ProdigyHostDelayOperation **operation = nullptr;

  void co_consume(void) override
  {
    wakes += 1;
    delete *operation;
    *operation = nullptr;
  }
};

static void testZeroAndInlineCompletion(TestSuite& suite)
{
  CountingStack concreteStack;
  ProdigyHostDelayOperation concrete(concreteStack);
  suite.expect(concrete.scheduleUs(0) && concrete.hasCompleted() &&
                   !concrete.mustSuspend() && concreteStack.wakes == 0,
               "host_delay_concrete_zero_completes_without_ring");

  FakeRing zeroRing;
  CountingStack zeroStack;
  ProdigyHostDelayOperation zero(zeroRing.submission(), zeroStack);
  suite.expect(zero.scheduleUs(0) && zero.hasCompleted() &&
                   !zero.mustSuspend() && zeroRing.queues == 0 && zeroStack.wakes == 0,
               "host_delay_zero_completes_without_ring");
  suite.expect(zero.takeCompletion() && !zero.hasCompleted(),
               "host_delay_zero_completion_is_consumable_once");

  FakeRing inlineRing;
  inlineRing.completeInline = true;
  CountingStack inlineStack;
  ProdigyHostDelayOperation inlineDelay(inlineRing.submission(), inlineStack);
  suite.expect(inlineDelay.scheduleUs(17) && inlineDelay.hasCompleted() &&
                   !inlineDelay.mustSuspend() && inlineRing.delayUs == 17 &&
                   inlineRing.queues == 1 && inlineStack.wakes == 0,
               "host_delay_inline_ring_completion_never_suspends");
}

static void testDeferredExactOnce(TestSuite& suite)
{
  FakeRing ring;
  CountingStack stack;
  ProdigyHostDelayOperation operation(ring.submission(), stack);

  suite.expect(operation.scheduleUs(2'500) && operation.mustSuspend() &&
                   ring.delayUs == 2'500,
               "host_delay_deferred_completion_arms_wake");
  TimeoutPacket stale;
  ring.packet->dispatcher->dispatchTimeout(&stale);
  suite.expect(!operation.hasCompleted() && stack.wakes == 0,
               "host_delay_deferred_completion_rejects_stale_packet");
  ring.expire();
  suite.expect(operation.hasCompleted() && stack.wakes == 1 &&
                   !operation.mustSuspend(),
               "host_delay_deferred_completion_wakes_exactly_once");
  suite.expect(operation.takeCompletion() && !operation.takeCompletion(),
               "host_delay_deferred_completion_is_consumable_once");
}

static void testAbandonAndDestruction(TestSuite& suite)
{
  FakeRing abandonedRing;
  abandonedRing.completeCancellationInline = true;
  CountingStack abandonedStack;
  {
    ProdigyHostDelayOperation operation(abandonedRing.submission(), abandonedStack);
    operation.scheduleUs(1);
    operation.mustSuspend();
    operation.abandon();
    suite.expect(abandonedRing.cancellations == 1 && abandonedRing.packet == nullptr &&
                     abandonedStack.wakes == 0 && !operation.hasCompleted() &&
                     !operation.mustSuspend(),
                 "host_delay_abandon_disarms_before_inline_cancel_ack");
  }
  suite.expect(abandonedRing.cancellations == 1,
               "host_delay_abandon_prevents_destructor_recancel");

  FakeRing destroyedRing;
  CountingStack destroyedStack;
  {
    ProdigyHostDelayOperation operation(destroyedRing.submission(), destroyedStack);
    operation.scheduleUs(1);
    operation.mustSuspend();
  }
  suite.expect(destroyedRing.cancellations == 1 && destroyedRing.packet != nullptr &&
                   destroyedStack.wakes == 0,
               "host_delay_destructor_retains_completion_until_cancel_ack");
  destroyedRing.expire();
  suite.expect(destroyedRing.packet == nullptr && destroyedStack.wakes == 0,
               "host_delay_deferred_cancel_ack_retires_without_wake");
}

static void testCallbackMayDestroyOperation(TestSuite& suite)
{
  FakeRing ring;
  DestroyingStack stack;
  ProdigyHostDelayOperation *operation =
      new ProdigyHostDelayOperation(ring.submission(), stack);
  stack.operation = &operation;
  operation->scheduleUs(1);
  operation->mustSuspend();

  ring.expire();
  suite.expect(operation == nullptr && stack.wakes == 1 && ring.cancellations == 0,
               "host_delay_callback_may_destroy_operation_during_wake");
}

static void testRejectsOverlappingSchedule(TestSuite& suite)
{
  FakeRing ring;
  CountingStack stack;
  ProdigyHostDelayOperation operation(ring.submission(), stack);
  suite.expect(operation.scheduleUs(1) && !operation.scheduleUs(2) && ring.queues == 1,
               "host_delay_rejects_overlapping_schedule");
  operation.abandon();
  ring.expire();
}

int main(void)
{
  TestSuite suite;
  testZeroAndInlineCompletion(suite);
  testDeferredExactOnce(suite);
  testAbandonAndDestruction(suite);
  testCallbackMayDestroyOperation(suite);
  testRejectsOverlappingSchedule(suite);
  return suite.failed == 0 ? 0 : 1;
}
