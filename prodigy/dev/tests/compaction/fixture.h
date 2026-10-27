#pragma once

// Test-only bounded constructive-compaction experiment.  This deliberately
// plans from existing Brain objects but never creates DeploymentWork or
// schedules a coroutine.  Its caller must use disposable test-owned objects:
// concentration checks temporarily apply speculative counts to those objects.
#include <prodigy/prodigy.h>
#include <prodigy/brain/brain.h>

#include <algorithm>
#include <functional>

namespace prodigy::test::compaction {

constexpr uint32_t maxMoves = 3;
constexpr uint32_t maxExpandedNodes = 2048;
constexpr size_t maxMachines = 3;
constexpr size_t maxContainers = 6;

struct Limits {
  uint32_t maxMoves = 3;
  uint32_t maxNodes = 2048;
};

struct Move {
  ContainerView *container = nullptr;
  Machine *from = nullptr;
  Machine *to = nullptr;
};

struct Result {
  bool admitted = false;
  bool exhausted = false;
  bool unsupported = false;
  uint32_t expandedNodes = 0;
  Vector<Move> moves = {};
  Machine *targetMachine = nullptr;
};

// The fixture must be supplied by a unit test.  It owns the in-memory
// Brain/Machine/Rack/Deployment objects and restores them after the call.
// GPU requests are deliberately unsupported. `targetCanFit` must call
// ApplicationDeployment::nFitOnMachine(target, machine, 1, delta), preserving
// the production resource, slot, routing, and compatibility decision.
struct Inputs {
  ApplicationDeployment *target = nullptr;
  Vector<Machine *> machines = {};
  Vector<ApplicationDeployment *> donorDeployments = {};
  std::function<bool(Machine *, const MachineResourcesDelta&)> targetCanFit;
};

struct State {
  bytell_hash_map<Machine *, MachineResourcesDelta> deltas = {};
  bytell_hash_map<Machine *, uint32_t> incomingSlots = {};
  bytell_hash_map<ApplicationDeployment *, bytell_hash_map<Machine *, int32_t>> machineCountDeltas = {};
  bytell_hash_map<ApplicationDeployment *, bytell_hash_map<Rack *, int32_t>> rackCountDeltas = {};
  bytell_hash_set<ContainerView *> moved = {};
  Vector<Move> moves = {};
};

template <typename K, typename V>
static inline V countOrZero(const bytell_hash_map<K, V>& counts, const K& key)
{
  const auto found = counts.find(key);
  return found == counts.end() ? V {} : found->second;
}

static inline uint32_t speculativeConcentrationBudget(
    ApplicationDeployment *owner, Machine *machine, const State& state)
{
  // Reuse the production concentration owner; do not reproduce its ratio
  // arithmetic.  The mutation is scoped to this call and only valid for a
  // disposable fixture.
  if (owner == nullptr || machine == nullptr || machine->rack == nullptr)
  {
    return 0;
  }
  int32_t machineDelta = 0;
  if (auto ownerIt = state.machineCountDeltas.find(owner);
      ownerIt != state.machineCountDeltas.end())
  {
    machineDelta = countOrZero(ownerIt->second, machine);
  }
  int32_t rackDelta = 0;
  if (auto ownerIt = state.rackCountDeltas.find(owner);
      ownerIt != state.rackCountDeltas.end())
  {
    rackDelta = countOrZero(ownerIt->second, machine->rack);
  }
  uint32_t oldMachine = owner->countPerMachine.getIf(machine);
  uint32_t oldRack = owner->countPerRack.getIf(machine->rack);
  const bool hadMachine = owner->countPerMachine.contains(machine);
  const bool hadRack = owner->countPerRack.contains(machine->rack);
  owner->countPerMachine.insert_or_assign(machine,
      uint32_t(std::max<int64_t>(0, int64_t(oldMachine) + machineDelta)));
  owner->countPerRack.insert_or_assign(machine->rack,
      uint32_t(std::max<int64_t>(0, int64_t(oldRack) + rackDelta)));
  uint32_t budget = ApplicationDeployment::clampBudgetByRackAndMachine(owner, machine, 1);
  if (hadMachine) owner->countPerMachine.insert_or_assign(machine, oldMachine);
  else owner->countPerMachine.erase(machine);
  if (hadRack) owner->countPerRack.insert_or_assign(machine->rack, oldRack);
  else owner->countPerRack.erase(machine->rack);
  return budget;
}

static inline bool canMoveConstructively(
    const Inputs& inputs, ApplicationDeployment *owner,
    ContainerView *container,
    Machine *destination,
    const State& state)
{
  if (owner == nullptr || container == nullptr || destination == nullptr ||
      container->machine == nullptr || container->machine == destination ||
      owner->plan.moveConstructively == false ||
      owner->statelessCompactionDonorIsQuiescent() == false ||
      ApplicationDeployment::statelessCompactionContainerIsEligible(container) == false ||
      owner->plan.isStateful || owner->plan.stateless.moveableDuringCompaction == false ||
      applicationRequiredWholeGPUs(owner->plan.config) != 0 ||
      container->assignedGPUMemoryMBs.empty() == false ||
      container->assignedGPUDevices.empty() == false ||
      prodigyMachineReadyForScheduling(container->machine) == false ||
      prodigyMachineReadyForScheduling(destination) == false ||
      ApplicationDeployment::machineSatisfiesExternalPlacementForDeployment(owner, destination) == false ||
      (destination->lifetime == MachineLifetime::spot && container->lifetime != ApplicationLifetime::surge) ||
      (inputs.target != nullptr && inputs.target->previous != nullptr &&
       owner->plan.config.deploymentID() == inputs.target->previous->plan.config.deploymentID()) ||
      state.moved.contains(container))
  {
    return false;
  }

  if (destination->availableContainerSlotsForScheduling() <= countOrZero(state.incomingSlots, destination) ||
      speculativeConcentrationBudget(owner, destination, state) == 0)
  {
    return false;
  }
  // Constructive means destination fit is checked before source resources are
  // returned. GPU placement is rejected above because this experiment does not
  // reserve destination GPU hardware indexes.
  const auto found = state.deltas.find(destination);
  const MachineResourcesDelta noDelta = {};
  const MachineResourcesDelta& destinationDelta =
      (found == state.deltas.end()) ? noDelta : found->second;
  return ApplicationDeployment::nFitOnMachine(owner, destination, 1,
                                               destinationDelta) == 1;
}

static inline void applyConstructiveMove(
    ApplicationDeployment *owner, const Move& move, State& state)
{
  // This changes only the speculative delta.  The destination debit is made
  // before the source credit, matching production constructive ordering.
  prodigyApplyPlannedMachineScalarDelta(state.deltas[move.to], owner->plan.config, 1);
  prodigyApplyPlannedMachineScalarDelta(state.deltas[move.from], owner->plan.config, -1);
  state.incomingSlots[move.to] += 1;
  state.machineCountDeltas[owner][move.from] -= 1;
  state.machineCountDeltas[owner][move.to] += 1;
  state.rackCountDeltas[owner][move.from->rack] -= 1;
  state.rackCountDeltas[owner][move.to->rack] += 1;
  state.moved.insert(move.container);
  state.moves.push_back(move);
}

static inline bool targetFits(const Inputs& inputs, const State& state, Machine **fittingMachine = nullptr)
{
  if (inputs.target == nullptr || inputs.targetCanFit == nullptr ||
      applicationRequiredWholeGPUs(inputs.target->plan.config) != 0)
  {
    return false;
  }
  for (Machine *machine : inputs.machines)
  {
    if (machine == nullptr || prodigyMachineReadyForScheduling(machine) == false ||
        machine->lifetime == MachineLifetime::spot ||
        machine->availableContainerSlotsForScheduling() <= countOrZero(state.incomingSlots, machine) ||
        ApplicationDeployment::machineSatisfiesExternalPlacementForDeployment(inputs.target, machine) == false)
    {
      continue;
    }
    const auto found = state.deltas.find(machine);
    const MachineResourcesDelta noDelta = {};
    if (speculativeConcentrationBudget(inputs.target, machine, state) > 0 &&
        inputs.targetCanFit(machine, found == state.deltas.end() ? noDelta : found->second))
    {
      if (fittingMachine)
      {
        *fittingMachine = machine;
      }
      return true;
    }
  }
  return false;
}

// Bounded DFS.  There is intentionally no production extraction or work
// scheduling here: it provides a compact oracle for a test-only experiment.
static inline Result search(const Inputs& inputs, Limits limits = {})
{
  Result result = {};
  // This experiment admits one pending stateless base instance. It does not
  // model stateful placement or GPU reservations.
  if (inputs.target == nullptr || inputs.target->plan.isStateful ||
      applicationRequiredWholeGPUs(inputs.target->plan.config) != 0 ||
      inputs.machines.size() > maxMachines || inputs.donorDeployments.size() > maxContainers)
  {
    result.unsupported = true;
    return result;
  }
  size_t containers = 0;
  for (ApplicationDeployment *owner : inputs.donorDeployments)
  {
    if (owner) containers += owner->containers.size();
  }
  if (containers > maxContainers)
  {
    result.unsupported = true;
    return result;
  }
  limits.maxMoves = std::min(limits.maxMoves, maxMoves);
  limits.maxNodes = std::min(limits.maxNodes, maxExpandedNodes);
  if (limits.maxNodes == 0)
  {
    result.exhausted = true;
    return result;
  }
  for (uint32_t depth = 0; depth <= limits.maxMoves; ++depth)
  {
    State initial = {};
    std::function<bool(const State&)> visit = [&](const State& state) {
      if (result.expandedNodes >= limits.maxNodes)
      {
        result.exhausted = true;
        return false;
      }
      result.expandedNodes += 1;
      Machine *targetMachine = nullptr;
      if (targetFits(inputs, state, &targetMachine))
      {
        result.admitted = true;
        result.moves = state.moves;
        result.targetMachine = targetMachine;
        return true;
      }
      if (state.moves.size() == depth)
      {
        return false;
      }
      for (ApplicationDeployment *owner : inputs.donorDeployments)
      {
        if (owner == nullptr || owner->statelessCompactionDonorIsQuiescent() == false)
        {
          continue;
        }
        for (ContainerView *container : owner->containers)
        {
          for (Machine *destination : inputs.machines)
          {
            if (canMoveConstructively(inputs, owner, container, destination, state) == false)
            {
              continue;
            }
            State next = state;
            applyConstructiveMove(owner, Move {container, container->machine, destination}, next);
            if (visit(next))
            {
              return true;
            }
            if (result.exhausted) return false;
          }
        }
      }
      return false;
    };
    if (visit(initial) || result.exhausted)
    {
      break;
    }
  }
  return result;
}

// Baseline is intentionally delegated to the existing one-hop compact path by
// the caller (with `planCompactionWork=false`); doing so preserves all current
// concentration accounting and avoids a second planner implementation here.

} // namespace prodigy::test::compaction
