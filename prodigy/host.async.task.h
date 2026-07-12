#pragma once

#include <coroutine>
#include <cstdlib>
#include <optional>
#include <utility>

#include <networking/includes.h>
#include <types/types.containers.h>
#include <networking/coroutinestack.h>

class ProdigyHostSuspend final
{
private:

  CoroutineStack *stack;
  inline static thread_local Vector<CoroutineStack *> cancelingStacks;

  static bool canceling(CoroutineStack *stack)
  {
    for (CoroutineStack *candidate : cancelingStacks)
    {
      if (candidate == stack)
      {
        return true;
      }
    }
    return false;
  }

  class Bridge final
  {
  public:

    class promise_type;
    using Handle = std::coroutine_handle<promise_type>;

    class promise_type final
    {
    public:

      CoroutineStack *stack;
      std::coroutine_handle<> leaf;
      bool dispatched = false;

      promise_type(CoroutineStack *requestedStack, std::coroutine_handle<> requestedLeaf)
          : stack(requestedStack),
            leaf(requestedLeaf)
      {}

      ~promise_type()
      {
        if (dispatched || !leaf)
        {
          return;
        }
        const bool alreadyCanceling = canceling(stack);
        if (!alreadyCanceling)
        {
          cancelingStacks.push_back(stack);
        }
        leaf.resume();
        if (!alreadyCanceling)
        {
          cancelingStacks.pop_back();
        }
      }

      Bridge get_return_object(void)
      {
        return Bridge(Handle::from_promise(*this));
      }

      class InitialSuspend final
      {
      private:

        promise_type *promise;

      public:

        explicit InitialSuspend(promise_type& requestedPromise)
            : promise(&requestedPromise)
        {}

        bool await_ready(void) const noexcept
        {
          return false;
        }

        bool await_suspend(Handle) const noexcept
        {
          return true;
        }

        void await_resume(void) const noexcept
        {
          promise->dispatched = true;
        }
      };

      InitialSuspend initial_suspend(void) noexcept
      {
        return InitialSuspend(*this);
      }

      std::suspend_never final_suspend(void) const noexcept
      {
        return {};
      }

      void return_void(void) const noexcept
      {}

      void unhandled_exception(void)
      {
        std::abort();
      }
    };

  private:

    Handle handle;

    explicit Bridge(Handle requested)
        : handle(requested)
    {}

  public:

    Bridge(Bridge&& other) noexcept
        : handle(std::exchange(other.handle, {}))
    {}

    ~Bridge()
    {
      if (handle)
      {
        handle.destroy();
      }
    }

    std::coroutine_handle<> release(void)
    {
      return std::exchange(handle, {});
    }
  };

  static Bridge bridge(CoroutineStack *stack, std::coroutine_handle<> leaf)
  {
    (void)stack;
    leaf.resume();
    co_return;
  }

public:

  explicit ProdigyHostSuspend(CoroutineStack& requestedStack)
      : stack(&requestedStack)
  {}

  bool await_ready(void) const noexcept
  {
    return canceling(stack);
  }

  bool await_suspend(std::coroutine_handle<> handle) const
  {
    Bridge suspension = bridge(stack, handle);
    std::coroutine_handle<> bridgeHandle = suspension.release();
    if (stack->overrideIndex != -1)
    {
      stack->suspended.insert(stack->suspended.begin() + stack->overrideIndex, bridgeHandle);
      stack->overrideIndex = -1;
    }
    else
    {
      stack->suspended.push_back(bridgeHandle);
    }
    ++stack->suspensionGeneration;
    return true;
  }

  void await_resume(void) const noexcept
  {}
};

template <typename Value>
class ProdigyHostTask final
{
public:

  class promise_type;
  using Handle = std::coroutine_handle<promise_type>;

  class promise_type final
  {
  private:

    std::optional<Value> value;
    std::coroutine_handle<> continuation = std::noop_coroutine();

  public:

    ProdigyHostTask get_return_object(void)
    {
      return ProdigyHostTask(Handle::from_promise(*this));
    }

    std::suspend_always initial_suspend(void) const noexcept
    {
      return {};
    }

    class FinalAwaiter final
    {
    public:

      bool await_ready(void) const noexcept
      {
        return false;
      }

      std::coroutine_handle<> await_suspend(Handle handle) const noexcept
      {
        return handle.promise().continuation;
      }

      void await_resume(void) const noexcept
      {}
    };

    FinalAwaiter final_suspend(void) const noexcept
    {
      return {};
    }

    template <typename Returned>
    void return_value(Returned&& returned)
    {
      value.emplace(std::forward<Returned>(returned));
    }

    void unhandled_exception(void)
    {
      std::abort();
    }

    friend class ProdigyHostTask;
  };

private:

  Handle handle;

  explicit ProdigyHostTask(Handle requestedHandle)
      : handle(requestedHandle)
  {}

public:

  ProdigyHostTask(ProdigyHostTask&& other) noexcept
      : handle(std::exchange(other.handle, {}))
  {}

  ~ProdigyHostTask()
  {
    if (handle)
    {
      handle.destroy();
    }
  }

  ProdigyHostTask(const ProdigyHostTask&) = delete;
  ProdigyHostTask& operator=(const ProdigyHostTask&) = delete;
  ProdigyHostTask& operator=(ProdigyHostTask&&) = delete;

  bool await_ready(void) const noexcept
  {
    return handle.done();
  }

  Handle await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    handle.promise().continuation = continuation;
    return handle;
  }

  Value await_resume(void)
  {
    return std::move(*handle.promise().value);
  }
};
