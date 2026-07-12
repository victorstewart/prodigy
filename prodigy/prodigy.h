#pragma once

#include <limits.h>

#include <networking/includes.h>
#include <services/prodigy.h>
#include <prodigy/types.h>

#include <prodigy/child.process.signal.h>
#include <prodigy/enums/datacenter.h>

#include <prodigy/neuron/neuron.h>
#include <prodigy/brain/base.h>
/*

1) monitor hardware failures
   * cache
   * memory
   * disk drives (would only be the non-operating system disk) https://manpages.ubuntu.com/manpages/xenial/man8/smartd.8.html
   * NICs (if this fails we won't be able to tell anyone anyway)
   * what about CPU cores failing?

   stop all the running processes and report the error if we can? otherwise another machine will report us missing?

   Uncorrected memory errors – that is data corruption – are reported using a machine check exception and handled directly by the kernel, for example by killing the affected process or shutting down the system down.

   we observe DRAM error rates that are orders of magnitude higher than previously reported, with 25,000 to 70,000 errors per billion device hours per Mbit and more than 8% of DIMMs affected by errors per year.

   In many production environments, including ours, a single un- correctable error is considered serious enough to replace the dual in-line memory module (DIMM) that caused it.
*/

// listen for SIGUSR1 for hardware failures
// read the /run/hardwarefailure.txt file to get the error, send it through the provider support/escalation path, then poweroff machine,

template <typename NeuronType, typename BrainType, typename HostControlNetworkType>
class Prodigy : public RingMultiplexer {
private:

  TimeoutPacket shutdownTimer;
  TimeoutPacket startupTimer;

  std::unique_ptr<HostControlNetworkType> hostControlNetwork;
  std::unique_ptr<CoroutineStack> startupCoroutine;
  NeuronType *neuron = nullptr;
  // the only way master brain is relinquished, is either by choice when we 1) update the operating system or 2) update this program, or by force when 3) the machine fails

  static void exitTraceHandler(int status, void *)
  {
    void *frames[32];
    int nFrames = backtrace(frames, 32);
    std::fprintf(stderr, "prodigy exit-trace pid=%d status=%d frames=%d\n", int(getpid()), status, nFrames);
    for (int i = 0; i < nFrames; ++i)
    {
      std::fprintf(stderr, "prodigy exit-trace frame[%d]=%p\n", i, frames[i]);
    }
    std::fflush(stderr);
  }

  void beforeRing(void)
  {
    Ring::signals[0] = SIGINT;
    Ring::signals[1] = SIGUSR1;
    Ring::signals[2] = SIGTERM;
  }

  void afterRing(void)
  {
    // Enter the Ring dispatch loop before boot so migrated provider work can suspend safely.
    startupTimer.setTimeoutUs(1);
    startupTimer.dispatcher = nullptr;
    startupTimer.originator = this;
    Ring::queueTimeout(&startupTimer);
  }

  void finishRuntimeStartup(void)
  {
    std::fprintf(stderr, "prodigy afterRing neuronIsBrain=%d private4=%u\n", int(neuron->isBrain), ntohl(neuron->private4.v4));

    if (neuron->isBrain)
    {
      BrainType *brain = new BrainType(*hostControlNetwork);
      thisBrain = brain;

      brain->getBrains();
    }
  }

  void bootRuntime(void)
  {
    if (uint32_t suspendIndex = startupCoroutine->nextSuspendIndex(); startupCoroutine->didSuspend([&](void) -> void {
          neuron->boot(startupCoroutine.get());
        }))
    {
      co_await startupCoroutine->suspendAtIndex(suspendIndex);
    }
    finishRuntimeStartup();
  }

  void startRuntime(void)
  {
    if (hostControlNetwork == nullptr)
    {
      hostControlNetwork = std::make_unique<HostControlNetworkType>();
    }
    if (hostControlNetwork->ready() == false)
    {
      std::fprintf(stderr, "prodigy host control network initialization failed\n");
      std::abort();
    }
    neuron = new NeuronType(*hostControlNetwork);
    thisNeuron = neuron;
    startupCoroutine = std::make_unique<CoroutineStack>();
    bootRuntime();
  }

  void queueShutdown(void)
  {
    shutdownTimer.setTimeoutMs(1000);
    shutdownTimer.dispatcher = nullptr;
    shutdownTimer.originator = this; // route back to this Prodigy instance through RingDispatcher
    Ring::queueTimeout(&shutdownTimer);
  }

  void timeoutHandler(TimeoutPacket *packet, int result)
  {
    (void)result;
    if (packet == &startupTimer)
    {
      startRuntime();
    }
    else if (packet == &shutdownTimer)
    {
      beginShutdown();
    }
  }

  bool signalHandler(const struct signalfd_siginfo& sigInfo)
  {
    switch (sigInfo.ssi_signo)
    {
      case SIGINT:
      case SIGTERM:
        {
          beginShutdown();
          return false;
        }
      case SIGUSR1:
        {
          if (neuron == nullptr)
          {
            return true;
          }
          neuron->hardwareFailureOccured();
          return false;
        }
      default:
        return true;
    }
  }

  void beginShutdown(void)
  {
    Guardian::signalHandler(SIGINT, NULL, NULL);
  }

public:

  void prepare(int argc, char *argv[])
  {
    RingDispatcher::installMultiplexer(this);
    // Also register this Prodigy instance for timeout routing
    RingDispatcher::installMultiplexee(this, this);
    BrainBase::captureLaunchArguments(argc, argv);
    if (const char *crashReportPath = std::getenv("PRODIGY_CRASH_REPORT_PATH"); crashReportPath && crashReportPath[0])
    {
      Guardian::crashReportPath.assign(crashReportPath);
    }
    if (const char *exitTrace = std::getenv("PRODIGY_EXIT_TRACE"); exitTrace && exitTrace[0] == '1')
    {
      (void)on_exit(exitTraceHandler, nullptr);
    }

    uint32_t sqeCount = 128;
    uint32_t cqeCount = 128;
    uint32_t nFixedFiles = 8192;
    uint32_t nReservedFixedFiles = 2048;

    Ring::createRing(sqeCount, cqeCount, nFixedFiles, nReservedFixedFiles, -1, -1, 0);
    prodigyEnsureSigchldDefaultWaitable();
  }

  void start(void)
  {
    Ring::start();
  }
};
