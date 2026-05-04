#include <pinger.h>
#include <assert.h>

#pragma once

class MetroNetworkMonitor : public PingSubscriber, public CoroutineStack {
private:

  MachinePinger pinger;

  MachineBase ourSwitch;
  Vector<MachineBase> otherSwitches;

  uint32_t nOtherBrains = 0;
  uint32_t nReachableBrains = 0;
  bool ourSwitchPonged = false;

  uint32_t waitingOnN = 0;

  void machineReachabilitySettled(void)
  {
    if (--waitingOnN == 0)
    {
      this->co_consume();
    }
  }

public:

  void check(uint32_t ourPrivate4, uint32_t gatewayPrivate4, const bytell_hash_set<BrainView *>& brains)
  {
    // Configure pinger with our source address
    pinger.configure(this, ourPrivate4);

    nOtherBrains = brains.size();
    nReachableBrains = 0;
    ourSwitchPonged = false;
    waitingOnN = nOtherBrains + 1;

    ourSwitch.private4 = gatewayPrivate4;
    pinger.pingMachineN(&ourSwitch, 3);

    otherSwitches.clear();
    otherSwitches.reserve(nOtherBrains);
    for (BrainView *bv : brains)
    {
      MachineBase& other = otherSwitches.emplace_back();
      assert(bv->gatewayPrivate4 != 0 && "BrainView gatewayPrivate4 must not be 0");
      other.private4 = bv->gatewayPrivate4;
      pinger.pingMachineN(&other, 3);
    }
  }

  bool ourSwitchIsReachable(void)
  {
    return ourSwitchPonged;
  }

  float ratioOfReachableSwitches(void)
  {
    if (nOtherBrains == 0)
    {
      return 0.0f;
    }
    return float(nReachableBrains) / float(nOtherBrains);
  }

  void machinePingable(MachineBase *machine)
  {
    if (machine == &ourSwitch)
    {
      ourSwitchPonged = true;
    }
    else
    {
      nReachableBrains += 1;
    }

    machineReachabilitySettled();
  }

  void machineUnpingable(MachineBase *machine)
  {
    machineReachabilitySettled();
  }
};
