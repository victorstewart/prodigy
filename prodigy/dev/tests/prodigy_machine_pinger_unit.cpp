#include <cerrno>
#include <cstdint>
#include <cstdlib>

class MachineBase {
public:

  uint32_t private4 = 0;
};

#include <pinger.h>
#include <services/debug.h>

class TestSuite {
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    basics_log("%s: %s\n", condition ? "PASS" : "FAIL", name);
    failed += condition ? 0 : 1;
  }
};

class FakeRing {
public:

  TimeoutPacket *packet = nullptr;
  uint32_t queues = 0;
  uint32_t cancellations = 0;

  static void queue(void *context, TimeoutPacket *packet)
  {
    FakeRing& ring = *static_cast<FakeRing *>(context);
    ring.packet = packet;
    ring.queues += 1;
  }

  static void cancel(void *context, TimeoutPacket *packet)
  {
    FakeRing& ring = *static_cast<FakeRing *>(context);
    if (ring.packet == packet)
    {
      ring.cancellations += 1;
    }
  }

  MachinePingerTimer::Submission submission(void)
  {
    return {this, queue, cancel};
  }

  void complete(int result)
  {
    TimeoutPacket *completed = packet;
    if (result != -ETIME)
    {
      packet = nullptr;
    }
    static_cast<RingInterface *>(completed->originator)->timeoutHandler(completed, result);
  }
};

struct TimerOutcome {

  uint32_t ticks = 0;
  uint32_t failures = 0;
  int lastFailure = 0;
};

static void recordTick(void *context)
{
  static_cast<TimerOutcome *>(context)->ticks += 1;
}

static void recordFailure(void *context, int result)
{
  TimerOutcome& outcome = *static_cast<TimerOutcome *>(context);
  outcome.failures += 1;
  outcome.lastFailure = result;
}

static void testSerializedCancelAndRestart(TestSuite& suite)
{
  FakeRing ring;
  TimerOutcome outcome;
  MachinePingerTimer timer(
      ring.submission(),
      &outcome,
      recordTick,
      recordFailure,
      250);

  timer.start();
  timer.start();
  suite.expect(ring.queues == 1, "machine_pinger_first_work_arms_once");

  ring.complete(-ETIME);
  ring.complete(-ETIME);
  suite.expect(outcome.ticks == 2, "machine_pinger_normal_multishot_ticks_advance");
  suite.expect(ring.queues == 1, "machine_pinger_normal_multishot_ticks_do_not_rearm");

  timer.stop();
  timer.stop();
  suite.expect(timer.isCancelling(), "machine_pinger_last_work_enters_cancelling");
  suite.expect(ring.cancellations == 1, "machine_pinger_last_work_cancels_once");

  timer.start();
  ring.complete(-ETIME);
  suite.expect(ring.queues == 1, "machine_pinger_restart_waits_for_cancel_terminal");
  suite.expect(outcome.ticks == 2, "machine_pinger_cancelling_tick_is_ignored");

  ring.complete(-ECANCELED);
  suite.expect(ring.queues == 2, "machine_pinger_cancel_terminal_arms_one_replacement");
  suite.expect(timer.isCancelling() == false, "machine_pinger_replacement_is_armed");

  timer.stop();
  ring.complete(-ECANCELED);
  suite.expect(timer.isIdle(), "machine_pinger_terminal_cancel_reaches_idle");
}

static void testUnexpectedTerminalFailsClosed(TestSuite& suite)
{
  FakeRing ring;
  TimerOutcome outcome;
  MachinePingerTimer timer(
      ring.submission(),
      &outcome,
      recordTick,
      recordFailure,
      250);

  timer.start();
  ring.complete(-EINVAL);

  suite.expect(timer.isIdle(), "machine_pinger_unexpected_terminal_reaches_idle");
  suite.expect(ring.queues == 1, "machine_pinger_unexpected_terminal_does_not_rearm");
  suite.expect(outcome.ticks == 0, "machine_pinger_unexpected_terminal_is_not_a_tick");
  suite.expect(
      outcome.failures == 1 && outcome.lastFailure == -EINVAL,
      "machine_pinger_unexpected_terminal_reports_exact_error");
}

static void testDestructionKeepsCompletionAlive(TestSuite& suite)
{
  FakeRing ring;
  TimerOutcome outcome;
  auto *timer = new MachinePingerTimer(
      ring.submission(),
      &outcome,
      recordTick,
      recordFailure,
      250);

  timer->start();
  delete timer;

  suite.expect(ring.cancellations == 1, "machine_pinger_destruction_cancels_live_multishot");
  suite.expect(ring.packet != nullptr, "machine_pinger_completion_outlives_owner");
  ring.complete(-ECANCELED);
  suite.expect(ring.packet == nullptr, "machine_pinger_orphan_completion_is_terminally_reclaimed");
  suite.expect(outcome.ticks == 0, "machine_pinger_orphan_completion_never_calls_owner");
  suite.expect(outcome.failures == 0, "machine_pinger_orphan_completion_never_reports_to_owner");
}

static void testDestructionDoesNotRecancel(TestSuite& suite)
{
  FakeRing ring;
  TimerOutcome outcome;
  auto *timer = new MachinePingerTimer(
      ring.submission(),
      &outcome,
      recordTick,
      recordFailure,
      250);

  timer->start();
  timer->stop();
  delete timer;

  suite.expect(ring.cancellations == 1, "machine_pinger_pending_cancel_is_not_duplicated");
  ring.complete(-ECANCELED);
  suite.expect(ring.packet == nullptr, "machine_pinger_pending_cancel_reclaims_orphan");
  suite.expect(outcome.failures == 0, "machine_pinger_pending_cancel_never_reports_to_owner");
}

int main(void)
{
  TestSuite suite;

  testSerializedCancelAndRestart(suite);
  testUnexpectedTerminalFailsClosed(suite);
  testDestructionKeepsCompletionAlive(suite);
  testDestructionDoesNotRecancel(suite);

  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
