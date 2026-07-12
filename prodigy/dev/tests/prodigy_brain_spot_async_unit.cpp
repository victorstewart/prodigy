#include <networking/includes.h>
#include <prodigy/brain/brain.h>
#include <prodigy/iaas/dev/dev.h>

class SpotTestBrain final : public Brain {
public:

  ~SpotTestBrain()
  {
    delete mesh;
    mesh = nullptr;
  }

  void armMachineNeuronControl(Machine *) override {}
  void pushSpinApplicationProgressToMothership(ApplicationDeployment *, const String&) override {}
  void spinApplicationFailed(ApplicationDeployment *, const String&) override {}
  bool persistLocalRuntimeState(void) override { return true; }
};

class DeferredSpotIaaS final : public DevBrainIaaS {
public:

  CoroutineStack *pending = nullptr;
  bool completed = false;

  void checkForSpotTerminations(CoroutineStack *coro, Vector<String>&) override
  {
    pending = coro;
    co_await coro->suspend();
    completed = true;
  }

  void complete(void)
  {
    pending->co_consume();
  }
};

int main(void)
{
  Ring::createRing(8, 8, 32, 32, -1, -1, 0);
  int failed = 0;
  {
    SpotTestBrain brain = {};
    DeferredSpotIaaS iaas = {};
    brain.iaas = &iaas;

    brain.checkForSpotTerminations();
    failed += !(brain.spotDecommissionCheckActive &&
                brain.spotDecommissionCheckCoroutine.hasSuspendedCoroutines() &&
                iaas.pending == &brain.spotDecommissionCheckCoroutine);
    iaas.complete();
    failed += !(iaas.completed && brain.spotDecommissionCheckActive == false &&
                brain.spotDecommissionCheckCoroutine.hasSuspendedCoroutines() == false);
    Ring::shutdownForExec();
  }
  return failed == 0 ? 0 : 1;
}
