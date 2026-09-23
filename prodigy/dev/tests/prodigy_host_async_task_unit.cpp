#include <prodigy/host.async.task.h>

#include <cstdio>

class TestSuite
{
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    if (!condition)
    {
      std::fprintf(stderr, "FAIL: %s\n", name);
      ++failed;
    }
  }
};

class DestructionProbe final
{
private:

  uint32_t *count;

public:

  explicit DestructionProbe(uint32_t& requestedCount)
      : count(&requestedCount)
  {}

  ~DestructionProbe()
  {
    ++*count;
  }
};

// This owns a normal C++ coroutine handle directly.  It lets the completion
// adapter tests destroy a suspended awaiter before its producer replies.
class CompletionFrame final
{
public:
  struct promise_type;
  using Handle = std::coroutine_handle<promise_type>;

  struct promise_type final
  {
    CompletionFrame get_return_object() { return CompletionFrame(Handle::from_promise(*this)); }
    std::suspend_always initial_suspend() noexcept { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }
    void return_void() noexcept {}
    void unhandled_exception() { std::abort(); }
  };

private:
  Handle handle = {};

  explicit CompletionFrame(Handle requested) : handle(requested) {}

public:
  CompletionFrame(CompletionFrame&& other) noexcept : handle(std::exchange(other.handle, {})) {}
  CompletionFrame(const CompletionFrame&) = delete;
  ~CompletionFrame() { destroy(); }

  void resume() { handle.resume(); }
  bool done() const { return handle.done(); }
  void destroy()
  {
    if (handle) { handle.destroy(); handle = {}; }
  }
};

static CompletionFrame awaitHostCompletion(
    std::function<void(std::function<void(uint32_t)>)> start,
    uint32_t& value, bool& completed, uint32_t& destructed)
{
  DestructionProbe probe(destructed);
  value = co_await ProdigyHostCompletion<uint32_t>(std::move(start));
  completed = true;
}

static ProdigyHostTask<bool> nestedLeaf(CoroutineStack *stack,
                                        bool suspendDuringCleanup,
                                        uint32_t& destructed,
                                        uint32_t& resumed)
{
  DestructionProbe probe(destructed);
  co_await ProdigyHostSuspend(*stack);
  ++resumed;
  if (suspendDuringCleanup)
  {
    co_await ProdigyHostSuspend(*stack);
    ++resumed;
  }
  co_return true;
}

static ProdigyHostTask<bool> nestedParent(CoroutineStack *stack,
                                          bool suspendDuringCleanup,
                                          uint32_t& destructed,
                                          uint32_t& resumed)
{
  DestructionProbe probe(destructed);
  co_return co_await nestedLeaf(stack, suspendDuringCleanup, destructed, resumed);
}

class Root final
{
public:

  CoroutineStack stack;
  uint32_t destructed = 0;
  uint32_t resumed = 0;
  bool complete = false;
  bool result = false;

  void run(bool suspendDuringCleanup)
  {
    result = co_await nestedParent(&stack, suspendDuringCleanup, destructed, resumed);
    complete = true;
  }
};

int main(void)
{
  TestSuite suite;
  {
    uint32_t value = 0, destructed = 0;
    bool completed = false;
    CompletionFrame frame = awaitHostCompletion(
        [](auto receipt) { receipt(7); }, value, completed, destructed);
    frame.resume();
    suite.expect(frame.done() && completed && value == 7 && destructed == 1,
                 "host_completion_inline_receipt_completes_without_suspending");
  }
  {
    std::function<void(uint32_t)> receipt;
    uint32_t value = 0, destructed = 0;
    bool completed = false;
    CompletionFrame frame = awaitHostCompletion(
        [&receipt](auto callback) { receipt = std::move(callback); }, value, completed, destructed);
    frame.resume();
    suite.expect(!frame.done() && !completed && bool(receipt),
                 "host_completion_deferred_receipt_suspends_owned_frame");
    receipt(11);
    suite.expect(frame.done() && completed && value == 11 && destructed == 1,
                 "host_completion_deferred_receipt_resumes_owned_frame_once");
    receipt(12);
    suite.expect(value == 11 && destructed == 1,
                 "host_completion_duplicate_receipt_is_ignored");
  }
  {
    std::function<void(uint32_t)> receipt;
    uint32_t value = 0, destructed = 0;
    bool completed = false;
    CompletionFrame frame = awaitHostCompletion(
        [&receipt](auto callback) { receipt = std::move(callback); }, value, completed, destructed);
    frame.resume();
    suite.expect(!frame.done() && bool(receipt),
                 "host_completion_destroyed_frame_suspends_before_cancellation");
    frame.destroy();
    receipt(19);
    suite.expect(!completed && value == 0 && destructed == 1,
                 "host_completion_late_receipt_after_destroyed_frame_is_inert");
  }
  {
    Root root;
    root.run(false);
    suite.expect(!root.complete && root.stack.suspended.size() == 1,
                 "host_task_nested_leaf_suspends_through_bridge");
    root.stack.co_consume();
    suite.expect(root.complete && root.result && root.resumed == 1 &&
                     root.destructed == 2 && root.stack.suspended.empty(),
                 "host_task_nested_normal_completion_destroys_each_frame_once");
  }
  {
    Root root;
    root.run(true);
    suite.expect(!root.complete && root.stack.suspended.size() == 1,
                 "host_task_cancel_fixture_suspends");
    root.stack.cancelSuspended();
    suite.expect(root.complete && root.result && root.resumed == 2 &&
                     root.destructed == 2 && root.stack.suspended.empty(),
                 "host_task_cancel_unwinds_chain_without_stranding_cleanup");
    root.stack.cancelSuspended();
    suite.expect(root.destructed == 2,
                 "host_task_repeated_cancel_does_not_double_destroy");
  }
  return suite.failed == 0 ? 0 : 1;
}
