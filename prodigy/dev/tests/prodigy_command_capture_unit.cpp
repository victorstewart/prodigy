#include <networking/includes.h>
#include <networking/multiplexer.h>
#include <networking/stream.h>
#include <networking/ring.h>
#include <prodigy/command.capture.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

class TestSuite
{
public:

   uint32_t failed = 0;

   void expect(bool condition, const char *name)
   {
      basics_log("%s: %s\n", condition ? "PASS" : "FAIL", name);
      failed += condition ? 0 : 1;
   }
};

class CommandRun final
{
public:

   CoroutineStack stack;
   bool complete = false;
   bool result = false;

   void start(const String& command,
              String& output,
              ProdigyCommandCapture::Clock::time_point deadline,
              String *failure)
   {
      result = co_await ProdigyCommandCapture::run(&stack, command, output, deadline, failure);
      complete = true;
      Ring::exit = true;
   }
};

class CommandCaptureHarness final
{
private:

   RingDispatcher dispatcher;

public:

   CommandCaptureHarness()
   {
      Ring::interfacer = &dispatcher;
      Ring::lifecycler = &dispatcher;
      Ring::exit = false;
      Ring::shuttingDown = false;
      Ring::createRing(128, 256, 8, 4, -1, -1, 8);
   }

   ~CommandCaptureHarness()
   {
      Ring::shutdownForExec();
      Ring::interfacer = nullptr;
      Ring::lifecycler = nullptr;
      Ring::exit = false;
      Ring::shuttingDown = false;
   }

   bool run(const String& command,
            String& output,
            ProdigyCommandCapture::Clock::time_point deadline,
            String *failure)
   {
      Ring::exit = false;
      CommandRun operation;
      operation.start(command, output, deadline, failure);
      if (!operation.complete)
      {
         Ring::start();
      }
      return operation.complete && operation.result;
   }

   bool cancel(const String& command, String& output, String& failure)
   {
      class Cancellation final : public TimeoutDispatcher
      {
      public:

         CommandRun *operation = nullptr;
         TimeoutPacket timer;

         void dispatchTimeout(TimeoutPacket *packet) override
         {
            if (packet == &timer && operation != nullptr)
            {
               operation->stack.cancelSuspended();
            }
         }
      } cancellation;

      Ring::exit = false;
      CommandRun operation;
      operation.start(command,
                      output,
                      ProdigyCommandCapture::Clock::now() + std::chrono::seconds(10),
                      &failure);
      cancellation.operation = &operation;
      cancellation.timer.setTimeoutMs(100);
      cancellation.timer.dispatcher = &cancellation;
      Ring::queueTimeout(&cancellation.timer);
      Ring::start();
      return operation.complete && !operation.result;
   }
};

static pid_t readPid(const char *path)
{
   int fd = ::open(path, O_RDONLY | O_CLOEXEC);
   if (fd < 0)
   {
      return -1;
   }
   char text[32] = {};
   ssize_t bytes = ::read(fd, text, sizeof(text) - 1);
   ::close(fd);
   return bytes > 0 ? pid_t(std::strtol(text, nullptr, 10)) : -1;
}

static bool processGoneOrZombie(pid_t pid)
{
   if (pid <= 0)
   {
      return false;
   }
   if (::kill(pid, 0) < 0 && errno == ESRCH)
   {
      return true;
   }

   String path = {};
   path.snprintf<"/proc/{itoa}/stat"_ctv>(uint64_t(pid));
   int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
   if (fd < 0)
   {
      return errno == ENOENT;
   }
   char stat[256] = {};
   ssize_t bytes = ::read(fd, stat, sizeof(stat) - 1);
   ::close(fd);
   if (bytes <= 0)
   {
      return false;
   }
   for (ssize_t index = bytes - 3; index >= 0; --index)
   {
      if (stat[index] == ')' && stat[index + 1] == ' ')
      {
         return stat[index + 2] == 'Z';
      }
   }
   return false;
}

int main(void)
{
   TestSuite suite = {};
   CommandCaptureHarness capture;
   String output = {};
   String failure = {};

   suite.expect(capture.run("printf 'token\\n'"_ctv, output,
                            ProdigyCommandCapture::Clock::now() + std::chrono::seconds(2),
                            &failure) &&
                    output == "token"_ctv && failure.empty(),
                "command_capture_success_and_trim");

   suite.expect(capture.run("printf warning >&2; printf token"_ctv, output,
                            ProdigyCommandCapture::Clock::now() + std::chrono::seconds(2),
                            &failure) &&
                    output == "token"_ctv && failure.empty(),
                "command_capture_keeps_successful_stderr_out_of_material");

   suite.expect(capture.run("printf broken >&2; exit 7"_ctv, output,
                            ProdigyCommandCapture::Clock::now() + std::chrono::seconds(2),
                            &failure) == false &&
                    output.empty() && failure == "broken"_ctv,
                "command_capture_nonzero_exit_is_transactional_and_preserves_detail");

   suite.expect(capture.run("printf secret-token; exit 7"_ctv, output,
                            ProdigyCommandCapture::Clock::now() + std::chrono::seconds(2),
                            &failure) == false &&
                    output.empty() && failure == "command exited with status 7"_ctv,
                "command_capture_never_discloses_failed_credential_stdout");

   suite.expect(capture.run("head -c 1048577 /dev/zero | tr '\\0' x"_ctv, output,
                            ProdigyCommandCapture::Clock::now() + std::chrono::seconds(5),
                            &failure) == false &&
                    output.empty() && failure == "credential command output exceeds 1 MiB"_ctv,
                "command_capture_enforces_output_cap");

   char pidPath[] = "/tmp/prodigy-command-capture-XXXXXX";
   int pidFile = ::mkstemp(pidPath);
   suite.expect(pidFile >= 0, "command_capture_timeout_pid_file");
   if (pidFile >= 0)
   {
      ::close(pidFile);
      String command = {};
      command.snprintf<"sleep 60 & child=$!; printf '%s' \"$child\" > {}; wait"_ctv>(String(pidPath));
      auto started = ProdigyCommandCapture::Clock::now();
      bool captured = capture.run(
          command,
          output,
          started + std::chrono::milliseconds(300),
          &failure);
      auto elapsed = ProdigyCommandCapture::Clock::now() - started;
      pid_t descendant = readPid(pidPath);
      suite.expect(captured == false && output.empty() &&
                       failure == "credential command deadline exceeded"_ctv &&
                       elapsed < std::chrono::seconds(2),
                   "command_capture_deadline_kills_hung_command");
      suite.expect(processGoneOrZombie(descendant),
                   "command_capture_deadline_kills_descendant_process_group");
      ::unlink(pidPath);
   }

   auto leaderStarted = ProdigyCommandCapture::Clock::now();
   suite.expect(capture.run(
                    "sleep 60 & printf '%s' \"$!\""_ctv,
                    output,
                    leaderStarted + std::chrono::seconds(2),
                    &failure) &&
                    ProdigyCommandCapture::Clock::now() - leaderStarted < std::chrono::seconds(2),
                "command_capture_reaps_successful_leader_without_waiting_for_descendant_pipe");
   pid_t successfulDescendant = pid_t(std::strtol(output.c_str(), nullptr, 10));
   suite.expect(processGoneOrZombie(successfulDescendant),
                "command_capture_success_kills_lingering_descendant_process_group");

   struct sigaction previousSigchld = {};
   struct sigaction noChildWait = {};
   sigemptyset(&noChildWait.sa_mask);
   noChildWait.sa_handler = SIG_DFL;
   noChildWait.sa_flags = SA_NOCLDWAIT;
   bool sigchldConfigured = ::sigaction(SIGCHLD, &noChildWait, &previousSigchld) == 0;
   suite.expect(sigchldConfigured &&
                    capture.run(
                        "printf repaired"_ctv,
                        output,
                        ProdigyCommandCapture::Clock::now() + std::chrono::seconds(2),
                        &failure) &&
                    output == "repaired"_ctv,
                "command_capture_repairs_nonwaitable_sigchld_policy");
   if (sigchldConfigured)
   {
      ::sigaction(SIGCHLD, &previousSigchld, nullptr);
   }

   suite.expect(capture.cancel("sleep 60"_ctv, output, failure) &&
                    output.empty() && failure == "credential command canceled"_ctv,
                "command_capture_coroutine_cancellation_kills_without_blocking_ring");
   suite.expect(capture.run("printf after-cancel"_ctv,
                            output,
                            ProdigyCommandCapture::Clock::now() + std::chrono::seconds(2),
                            &failure) && output == "after-cancel"_ctv,
                "command_capture_ring_remains_usable_after_cancellation_cleanup");

   return suite.failed == 0 ? 0 : 1;
}
