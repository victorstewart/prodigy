#pragma once

#include <prodigy/child.process.signal.h>
#include <prodigy/host.async.task.h>

#include <networking/multiplexer.h>
#include <networking/stream.h>
#include <networking/ring.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>

class ProdigyCommandCapture final
{
public:

   using Clock = std::chrono::steady_clock;
   constexpr static size_t maximumOutputBytes = 1024 * 1024;
   constexpr static std::chrono::seconds timeout = std::chrono::seconds(30);

private:

   class Operation;

   class State final : public RingMultiplexer,
                       public TimeoutDispatcher,
                       public WaitableProcess
   {
   private:

      friend class Operation;

      Operation *owner;
      CoroutineStack *stack;
      String output;
      String diagnostic;
      String failure;
      pid_t pid = -1;
      int descriptors[2] = {-1, -1};
      Ring::RawPollTicket polls[2] = {Ring::invalidRawPollTicket, Ring::invalidRawPollTicket};
      TimeoutPacket deadline;
      bool waitPending = false;
      bool deadlinePending = false;
      bool deadlineCancellationRequested = false;
      bool terminating = false;
      bool complete = false;
      bool successful = false;
      bool notified = false;
      bool wakeArmed = false;
      bool installed = false;

      static void trimTrailingAsciiWhitespace(String& value)
      {
         while (!value.empty())
         {
            const uint8_t byte = value[value.size() - 1];
            if (byte != ' ' && byte != '\n' && byte != '\r' && byte != '\t')
            {
               break;
            }
            value.resize(value.size() - 1);
         }
      }

      void closeDescriptor(uint32_t channel)
      {
         if (descriptors[channel] >= 0)
         {
            ::close(descriptors[channel]);
            descriptors[channel] = -1;
         }
      }

      void terminate(void)
      {
         if (terminating || pid <= 0)
         {
            return;
         }
         terminating = true;
         output.clear();
         diagnostic.clear();
         (void)::kill(-pid, SIGKILL);
         (void)::kill(pid, SIGKILL);
      }

      void fail(StringType auto&& reason)
      {
         if (failure.empty())
         {
            failure.assign(reason);
         }
         terminate();
      }

      bool drain(uint32_t channel)
      {
         uint8_t buffer[4096];
         String& captured = channel == 0 ? output : diagnostic;
         for (;;)
         {
            const ssize_t bytes = ::read(descriptors[channel], buffer, sizeof(buffer));
            if (bytes > 0)
            {
               if (terminating)
               {
                  continue;
               }
               if (output.size() + diagnostic.size() + uint64_t(bytes) > maximumOutputBytes)
               {
                  fail("credential command output exceeds 1 MiB"_ctv);
                  continue;
               }
               captured.append(buffer, uint64_t(bytes));
               continue;
            }
            if (bytes == 0)
            {
               return true;
            }
            if (errno == EINTR)
            {
               continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
               return false;
            }
            fail("credential command output read failed"_ctv);
            return true;
         }
      }

      bool arm(uint32_t channel)
      {
         polls[channel] = Ring::queueRawFDPoll(
             this, channel + 1, descriptors[channel], POLLIN | POLLHUP | POLLERR);
         if (polls[channel] != Ring::invalidRawPollTicket)
         {
            return true;
         }
         closeDescriptor(channel);
         fail("credential command output poll failed"_ctv);
         return false;
      }

      void cancelPoll(uint32_t channel)
      {
         if (polls[channel] != Ring::invalidRawPollTicket)
         {
            (void)Ring::cancelRawFDPoll(polls[channel]);
         }
      }

      void finishIfReady(void)
      {
         if (!complete && (waitPending || descriptors[0] >= 0 || descriptors[1] >= 0))
         {
            return;
         }
         if (!complete)
         {
            trimTrailingAsciiWhitespace(output);
            trimTrailingAsciiWhitespace(diagnostic);
            successful = failure.empty() && infop.si_code == CLD_EXITED && infop.si_status == 0;
            if (!successful)
            {
               output.clear();
               if (failure.empty())
               {
                  if (!diagnostic.empty())
                  {
                     failure = std::move(diagnostic);
                  }
                  else if (infop.si_code == CLD_EXITED)
                  {
                     failure.snprintf<"command exited with status {itoa}"_ctv>(uint32_t(infop.si_status));
                  }
                  else
                  {
                     failure.assign("command failed"_ctv);
                  }
               }
            }
            diagnostic.clear();
            complete = true;
            if (deadlinePending && !deadlineCancellationRequested)
            {
               deadlineCancellationRequested = true;
               Ring::queueCancelTimeout(&deadline);
            }
         }

         if (deadlinePending || notified)
         {
            return;
         }
         notified = true;
         if (owner != nullptr)
         {
            ownerCompleted();
         }
         destroyIfDetached();
      }

      void ownerCompleted(void);

      void destroyIfDetached(void)
      {
         if (owner == nullptr && !waitPending &&
             polls[0] == Ring::invalidRawPollTicket &&
             polls[1] == Ring::invalidRawPollTicket && !deadlinePending)
         {
            delete this;
         }
      }

      ~State()
      {
         closeDescriptor(0);
         closeDescriptor(1);
         if (installed)
         {
            RingDispatcher::eraseMultiplexee(this);
         }
      }

   public:

      State(Operation& requestedOwner, CoroutineStack& requestedStack)
          : owner(&requestedOwner),
            stack(&requestedStack)
      {}

      bool start(const String& command, Clock::time_point requestedDeadline)
      {
         String ownedCommand;
         ownedCommand.assign(command);
         ownedCommand.addNullTerminator();
         if (command.empty())
         {
            failure.assign("credential command required"_ctv);
            complete = true;
            return true;
         }
         if (Ring::getRingFD() <= 0 || prodigyEnsureSigchldDefaultWaitable() == false)
         {
            failure.assign("credential command Ring runtime unavailable"_ctv);
            complete = true;
            return true;
         }

         const Clock::time_point now = Clock::now();
         requestedDeadline = std::min(requestedDeadline, now + timeout);
         if (now >= requestedDeadline)
         {
            failure.assign("credential command deadline exceeded"_ctv);
            complete = true;
            return true;
         }

         int pipes[2][2] = {{-1, -1}, {-1, -1}};
         if (::pipe2(pipes[0], O_CLOEXEC) != 0 || ::pipe2(pipes[1], O_CLOEXEC) != 0)
         {
            for (auto& pipe : pipes)
            {
               if (pipe[0] >= 0) ::close(pipe[0]);
               if (pipe[1] >= 0) ::close(pipe[1]);
            }
            failure.assign("failed to create credential command pipe"_ctv);
            complete = true;
            return true;
         }
         for (auto& pipe : pipes)
         {
            const int flags = ::fcntl(pipe[0], F_GETFL, 0);
            if (flags < 0 || ::fcntl(pipe[0], F_SETFL, flags | O_NONBLOCK) < 0)
            {
               for (auto& cleanup : pipes)
               {
                  ::close(cleanup[0]);
                  ::close(cleanup[1]);
               }
               failure.assign("failed to configure credential command pipe"_ctv);
               complete = true;
               return true;
            }
         }

         pid = ::fork();
         if (pid == 0)
         {
            (void)::setpgid(0, 0);
            ::close(pipes[0][0]);
            ::close(pipes[1][0]);
            if (::dup2(pipes[0][1], STDOUT_FILENO) < 0 ||
                ::dup2(pipes[1][1], STDERR_FILENO) < 0)
            {
               _exit(127);
            }
            if (pipes[0][1] != STDOUT_FILENO && pipes[0][1] != STDERR_FILENO) ::close(pipes[0][1]);
            if (pipes[1][1] != STDOUT_FILENO && pipes[1][1] != STDERR_FILENO) ::close(pipes[1][1]);
            ::execl("/bin/sh", "sh", "-c", ownedCommand.c_str(), static_cast<char *>(nullptr));
            _exit(127);
         }

         ::close(pipes[0][1]);
         ::close(pipes[1][1]);
         if (pid < 0)
         {
            ::close(pipes[0][0]);
            ::close(pipes[1][0]);
            failure.assign("failed to spawn credential command"_ctv);
            complete = true;
            return true;
         }

         (void)::setpgid(pid, pid);
         descriptors[0] = pipes[0][0];
         descriptors[1] = pipes[1][0];
         RingDispatcher::installMultiplexee(this, this);
         installed = true;
         waitPending = true;
         Ring::queueWaitid(this, P_PID, id_t(pid));
         (void)arm(0);
         (void)arm(1);
         const uint64_t deadlineUs = std::max<uint64_t>(
             1, uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(requestedDeadline - now).count()));
         deadline.setTimeoutUs(deadlineUs);
         deadline.dispatcher = this;
         deadlinePending = true;
         Ring::queueTimeout(&deadline);
         finishIfReady();
         return true;
      }

      bool mustSuspend(void)
      {
         if (complete)
         {
            return false;
         }
         wakeArmed = true;
         return true;
      }

      bool hasResult(void) const
      {
         return complete;
      }

      bool take(String& captured, String *detail)
      {
         captured = std::move(output);
         if (detail != nullptr)
         {
            *detail = std::move(failure);
         }
         return successful;
      }

      void detach(void)
      {
         owner = nullptr;
         stack = nullptr;
         wakeArmed = false;
         if (!complete)
         {
            fail("credential command canceled"_ctv);
            cancelPoll(0);
            cancelPoll(1);
            if (deadlinePending && !deadlineCancellationRequested)
            {
               deadlineCancellationRequested = true;
               Ring::queueCancelTimeout(&deadline);
            }
         }
         destroyIfDetached();
      }

      void rawFDPollHandler(void *pollOwner,
                            uint64_t generation,
                            uint64_t ticket,
                            int result) override
      {
         if (pollOwner != this || generation < 1 || generation > 2)
         {
            return;
         }
         const uint32_t channel = uint32_t(generation - 1);
         if (polls[channel] != ticket)
         {
            return;
         }
         polls[channel] = Ring::invalidRawPollTicket;
         const bool eof = result < 0 || drain(channel);
         if (eof || terminating)
         {
            closeDescriptor(channel);
         }
         else
         {
            (void)arm(channel);
         }
         finishIfReady();
         destroyIfDetached();
      }

      void waitidHandler(void *waiter) override
      {
         if (waiter != this || !waitPending)
         {
            return;
         }
         waitPending = false;
         (void)::kill(-pid, SIGKILL);
         pid = -1;
         finishIfReady();
         destroyIfDetached();
      }

      void dispatchTimeout(TimeoutPacket *packet) override
      {
         if (packet != &deadline || !deadlinePending)
         {
            return;
         }
         deadlinePending = false;
         if (!deadlineCancellationRequested && !complete)
         {
            fail("credential command deadline exceeded"_ctv);
         }
         finishIfReady();
         destroyIfDetached();
      }
   };

   class Operation final
   {
   private:

      State *state;
      CoroutineStack *stack;

      void completed(void)
      {
         if (stack != nullptr && state->wakeArmed)
         {
            state->wakeArmed = false;
            stack->co_consume();
         }
      }

      friend class State;

   public:

      explicit Operation(CoroutineStack& requestedStack)
          : state(new State(*this, requestedStack)),
            stack(&requestedStack)
      {}

      ~Operation()
      {
         if (state != nullptr)
         {
            state->detach();
         }
      }

      bool start(const String& command, Clock::time_point deadline)
      {
         return state->start(command, deadline);
      }

      bool mustSuspend(void)
      {
         return state->mustSuspend();
      }

      bool hasResult(void) const
      {
         return state->hasResult();
      }

      bool take(String& output, String *failure)
      {
         return state->take(output, failure);
      }
   };

public:

   static ProdigyHostTask<bool> run(CoroutineStack *coro,
                                    const String& command,
                                    String& output,
                                    Clock::time_point deadline = Clock::time_point::max(),
                                    String *failure = nullptr)
   {
      output.clear();
      if (failure != nullptr)
      {
         failure->clear();
      }
      if (coro == nullptr)
      {
         if (failure != nullptr)
         {
            failure->assign("credential command coroutine required"_ctv);
         }
         co_return false;
      }

      Operation operation(*coro);
      if (!operation.start(command, deadline))
      {
         if (failure != nullptr)
         {
            failure->assign("credential command submission failed"_ctv);
         }
         co_return false;
      }
      if (operation.mustSuspend())
      {
         co_await ProdigyHostSuspend(*coro);
      }
      if (!operation.hasResult())
      {
         if (failure != nullptr)
         {
            failure->assign("credential command canceled"_ctv);
         }
         co_return false;
      }
      co_return operation.take(output, failure);
   }
};

inline void ProdigyCommandCapture::State::ownerCompleted(void)
{
   owner->completed();
}
