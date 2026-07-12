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
