#include <networking/includes.h>
#include <services/debug.h>
#include <services/bitsery.h>
#include <services/crypto.h>
#include <services/filesystem.h>
#include <networking/time.h>
#include <networking/ip.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/pool.h>
#include <networking/ring.h>
#include <prodigy/neuron.hub.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <unistd.h>

class TaskProbeContainer final : public NeuronHubDispatch, public TimeoutDispatcher {
private:

  std::unique_ptr<NeuronHub> neuronHub;
  TimeoutPacket exitTick = {};
  String result;
  int exitCode = 0;
  uint32_t ticks = 0;
  bool published = false;

  static int envInt(const char *name, int fallback)
  {
    const char *value = getenv(name);
    return (value && value[0]) ? atoi(value) : fallback;
  }

  void armExitTick(void)
  {
    exitTick.clear();
    exitTick.dispatcher = this;
    exitTick.setTimeoutMs(25);
    Ring::queueTimeout(&exitTick);
  }

  void publishOnce(void)
  {
    if (published || neuronHub == nullptr)
    {
      return;
    }
    published = true;

    int succeedOnAttempt = envInt("PRODIGY_TASK_PROBE_SUCCEED_ON_ATTEMPT", 0);
    exitCode = envInt("PRODIGY_TASK_PROBE_EXIT_CODE", 0);
    if (succeedOnAttempt > 0 && neuronHub->parameters.taskAttemptNumber < uint32_t(succeedOnAttempt))
    {
      exitCode = envInt("PRODIGY_TASK_PROBE_RETRY_EXIT_CODE", 42);
    }

    if (const char *envResult = getenv("PRODIGY_TASK_PROBE_RESULT"); envResult && envResult[0])
    {
      result.assign(envResult);
    }
    else
    {
      result.snprintf<"deployment={itoa} attempt={itoa} exit={itoa}"_ctv>(
          neuronHub->parameters.deploymentID,
          uint64_t(neuronHub->parameters.taskAttemptNumber),
          uint64_t(exitCode));
    }

    if (neuronHub->publishTaskResult(result) == false)
    {
      exitCode = 111;
    }
    armExitTick();
  }

public:

  void beginShutdown(void) override
  {
    _exit(130);
  }

  void endOfDynamicArgs(void) override
  {
    publishOnce();
  }

  void dispatchTimeout(TimeoutPacket *packet) override
  {
    if (packet != &exitTick)
    {
      return;
    }
    if (neuronHub == nullptr ||
        (neuronHub->neuron.pendingSend == false && neuronHub->neuron.wBuffer.outstandingBytes() == 0) ||
        ++ticks > 200)
    {
      _exit(exitCode);
    }
    armExitTick();
  }

  void run(int argc, char *argv[])
  {
    Ring::createRing(64, 128, 512, 128, -1, -1, 0);
    neuronHub = std::make_unique<NeuronHub>(this);
    neuronHub->fillFromMainArgs(argc, argv);
    neuronHub->afterRing();
    publishOnce();
    Ring::start();
  }
};

int main(int argc, char *argv[])
{
  TaskProbeContainer container;
  container.run(argc, argv);
  return 111;
}
