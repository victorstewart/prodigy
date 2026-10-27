#include "fixture.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <vector>

namespace prodigy::test::compaction {

class TestBrain final : public BrainBase {
public:
  void respinApplication(ApplicationDeployment *) override {}
  void pushSpinApplicationProgressToMothership(ApplicationDeployment *, const String&) override {}
  void spinApplicationFailed(ApplicationDeployment *, const String&) override {}
  void spinApplicationFin(ApplicationDeployment *) override {}
  void requestMachines(MachineTicket *, ApplicationDeployment *, ApplicationLifetime, uint32_t) override {}
};

struct Scene {
  TestBrain brain = {};
  BrainBase *previousBrain = nullptr;
  Rack racks[3] = {};
  Machine machines[3] = {};
  ApplicationDeployment target = {};
  ApplicationDeployment donorX = {};
  ApplicationDeployment donorY = {};
  ContainerView x = {};
  ContainerView y = {};

  Scene()
  {
    previousBrain = thisBrain;
    thisBrain = &brain;
    brain.brainConfig.architecture = nametagCurrentBuildMachineArchitecture();

    for (uint32_t index = 0; index < 3; ++index)
    {
      Rack& rack = racks[index];
      Machine& machine = machines[index];
      rack.uuid = 0xC0010000u + index;
      machine.uuid = uint128_t(0xC0011000u + index);
      machine.rack = &rack;
      machine.state = MachineState::healthy;
      machine.lifetime = MachineLifetime::owned;
      machine.hardware.inventoryComplete = true;
      machine.hardware.cpu.architecture = nametagCurrentBuildMachineArchitecture();
      rack.machines.insert(&machine);
      brain.racks.insert_or_assign(rack.uuid, &rack);
      brain.machines.insert(&machine);
    }

    // A begins with X, B with Y, and C is empty.  Moving Y to C then X to B
    // leaves A with the four cores and 4096 MiB required by target.
    configureMachine(machines[0], 4, 4096, 2, 0);
    configureMachine(machines[1], 3, 4096, 2, 2048);
    configureMachine(machines[2], 1, 2048, 1, 2048);
    configureDeployment(donorX, 0xC00101, 2, 4096, true, true);
    configureDeployment(donorY, 0xC00102, 1, 2048, true, true);
    configureDeployment(target, 0xC00103, 4, 4096, false, false);
    addBase(donorX, x, machines[0], 0xC0012001);
    addBase(donorY, y, machines[1], 0xC0012002);
  }

  ~Scene()
  {
    thisBrain = previousBrain;
  }

  Inputs inputs()
  {
    Inputs result = {};
    result.target = &target;
    result.machines = {&machines[0], &machines[1], &machines[2]};
    result.donorDeployments = {&donorX, &donorY};
    result.targetCanFit = [this](Machine *machine, const MachineResourcesDelta& delta) {
      return ApplicationDeployment::nFitOnMachine(&target, machine, 1, delta) == 1;
    };
    return result;
  }

  static void setMachineCapacity(Machine& machine, uint32_t totalCores, uint32_t totalMemory,
                                 uint32_t freeCores, uint32_t freeMemory)
  {
    configureMachine(machine, totalCores, totalMemory, freeCores, freeMemory);
  }

private:
  static void configureMachine(Machine& machine, uint32_t totalCores, uint32_t totalMemory,
                               uint32_t freeCores, uint32_t freeMemory)
  {
    machine.ownedLogicalCores = machine.totalLogicalCores = totalCores;
    machine.ownedMemoryMB = machine.totalMemoryMB = totalMemory;
    machine.ownedStorageMB = machine.totalStorageMB = 8192;
    machine.nLogicalCores_available = freeCores;
    machine.memoryMB_available = freeMemory;
    machine.hardware.cpu.logicalCores = totalCores;
    machine.hardware.memory.totalMB = totalMemory;
    machine.storageMB_available = 8192;
  }

  void configureDeployment(ApplicationDeployment& deployment, uint32_t applicationID,
                           uint32_t cores, uint32_t memory, bool movable, bool deployed)
  {
    deployment.plan.isStateful = false;
    deployment.plan.config.type = ApplicationType::stateless;
    deployment.plan.config.applicationID = applicationID;
    deployment.plan.config.versionID = 1;
    deployment.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
    deployment.plan.config.nLogicalCores = cores;
    deployment.plan.config.memoryMB = memory;
    deployment.plan.config.filesystemMB = 64;
    deployment.plan.config.storageMB = 64;
    deployment.plan.stateless.nBase = 1;
    deployment.plan.stateless.maxPerRackRatio = 1.0f;
    deployment.plan.stateless.maxPerMachineRatio = 1.0f;
    deployment.plan.stateless.moveableDuringCompaction = movable;
    deployment.plan.moveConstructively = movable;
    deployment.state = DeploymentState::running;
    deployment.nTargetBase = 1;
    deployment.nDeployedBase = deployed ? 1 : 0;
    deployment.nHealthyBase = deployed ? 1 : 0;
    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
  }

  void addBase(ApplicationDeployment& owner, ContainerView& container, Machine& machine, uint128_t uuid)
  {
    container.uuid = uuid;
    container.deploymentID = owner.plan.config.deploymentID();
    container.applicationID = owner.plan.config.applicationID;
    container.machine = &machine;
    container.lifetime = ApplicationLifetime::base;
    container.state = ContainerState::healthy;
    owner.containers.insert(&container);
    owner.countPerMachine[&machine] += 1;
    owner.countPerRack[machine.rack] += 1;
    brain.containers.insert_or_assign(container.uuid, &container);
    machine.upsertContainerIndexEntry(container.deploymentID, &container);
    machine.storageMB_available -= int32_t(owner.plan.config.totalStorageMB());
  }
};

// The existing one-hop owner is intentionally used as the baseline. It sees
// no fit in this scene because Y must first move B -> C before X can move A -> B.
bool baseline(Scene& scene)
{
  Inputs inputs = scene.inputs();
  State state = {};
  if (targetFits(inputs, state)) return true;
  bytell_hash_map<Machine *, MachineResourcesDelta> deltas = {};
  for (Machine *machine : scene.target.compact(deltas, false))
  {
    (void)machine;
  }
  state.deltas = std::move(deltas);
  return targetFits(inputs, state);
}

static bool unchanged(Scene& scene, ContainerState expectedYState = ContainerState::healthy)
{
  return scene.x.machine == &scene.machines[0] && scene.y.machine == &scene.machines[1] &&
         scene.x.state == ContainerState::healthy && scene.y.state == expectedYState &&
         scene.machines[0].nLogicalCores_available == 2 && scene.machines[0].memoryMB_available == 0 &&
         scene.machines[1].nLogicalCores_available == 2 && scene.machines[1].memoryMB_available == 2048 &&
         scene.machines[2].nLogicalCores_available == 1 && scene.machines[2].memoryMB_available == 2048 &&
         scene.machines[0].storageMB_available == 8064 && scene.machines[1].storageMB_available == 8064 &&
         scene.machines[2].storageMB_available == 8192 &&
         scene.donorX.countPerMachine.getIf(&scene.machines[0]) == 1 &&
         scene.donorY.countPerMachine.getIf(&scene.machines[1]) == 1 &&
         scene.donorX.countPerMachine.size() == 1 && scene.donorX.countPerRack.size() == 1 &&
         scene.donorY.countPerMachine.size() == 1 && scene.donorY.countPerRack.size() == 1 &&
         scene.target.countPerMachine.size() == 0 && scene.target.countPerRack.size() == 0 &&
         scene.target.toSchedule.empty() && scene.target.waitingOnContainers.empty() &&
         scene.brain.containers.size() == 2 && scene.machines[0].containersByDeploymentID.size() == 1 &&
         scene.machines[1].containersByDeploymentID.size() == 1 && scene.machines[2].containersByDeploymentID.size() == 0;
}

static bool expect(bool condition, const char *name)
{
  if (!condition)
  {
    std::fprintf(stderr, "FAIL: %s\n", name);
  }
  return condition;
}

static bool assertWitness()
{
  Scene scene;
  const bool noOneHopFit = !baseline(scene);
  Result result = search(scene.inputs(), Limits {2, 64});
  return expect(noOneHopFit, "baseline_requires_more_than_one_move") &&
         expect(result.admitted && !result.exhausted, "candidate_admits_two_hop_scene") &&
         expect(result.moves.size() == 2, "candidate_uses_two_moves") &&
         expect(result.moves[0].container == &scene.y && result.moves[0].from == &scene.machines[1] && result.moves[0].to == &scene.machines[2], "candidate_moves_y_b_to_c") &&
         expect(result.moves[1].container == &scene.x && result.moves[1].from == &scene.machines[0] && result.moves[1].to == &scene.machines[1], "candidate_moves_x_a_to_b") &&
         expect(result.targetMachine == &scene.machines[0], "candidate_fits_target_on_a") &&
         expect(unchanged(scene), "candidate_preserves_scene");
}

static bool assertDirectAndBounds()
{
  Scene direct;
  Scene::setMachineCapacity(direct.machines[2], 4, 4096, 4, 4096);
  Result directResult = search(direct.inputs(), Limits {2, 64});
  bool ok = expect(directResult.admitted && directResult.moves.empty(), "direct_fit_needs_no_moves") &&
            expect(baseline(direct), "baseline_reports_direct_fit");

  Scene oneHop;
  Scene::setMachineCapacity(oneHop.machines[2], 2, 4096, 2, 4096);
  ok = expect(baseline(oneHop), "baseline_reports_one_hop_fit") && ok;

  Scene depth;
  Result depthResult = search(depth.inputs(), Limits {1, 64});
  ok = expect(!depthResult.admitted && !depthResult.exhausted, "depth_one_rejects_two_hop_scene") &&
       expect(unchanged(depth), "depth_limit_preserves_scene") && ok;

  Scene nodes;
  Result nodeResult = search(nodes.inputs(), Limits {2, 1});
  bool zero = expect(search(nodes.inputs(), Limits {2, 0}).exhausted, "zero_node_cap_reports_exhaustion") &&
              expect(unchanged(nodes), "zero_node_cap_preserves_scene");
  return expect(!nodeResult.admitted && nodeResult.exhausted, "node_cap_reports_exhaustion") &&
         expect(unchanged(nodes), "node_cap_preserves_scene") && zero && ok;
}

static bool assertEligibilityGuards()
{
  bool ok = true;
  {
    Scene scene; scene.donorY.plan.stateless.moveableDuringCompaction = false;
    ok = expect(!search(scene.inputs(), Limits {2, 64}).admitted, "nonmovable_donor_rejected") && expect(unchanged(scene), "nonmovable_preserves_scene") && ok;
  }
  {
    Scene scene; scene.donorY.plan.moveConstructively = false;
    ok = expect(!search(scene.inputs(), Limits {2, 64}).admitted, "constructive_false_donor_rejected") && expect(unchanged(scene), "constructive_false_preserves_scene") && ok;
  }
  {
    Scene scene; scene.donorY.plan.isStateful = true;
    ok = expect(!search(scene.inputs(), Limits {2, 64}).admitted, "stateful_donor_rejected") && expect(unchanged(scene), "stateful_preserves_scene") && ok;
  }
  {
    Scene scene; scene.y.state = ContainerState::scheduled;
    ok = expect(!search(scene.inputs(), Limits {2, 64}).admitted, "unhealthy_donor_rejected") && expect(unchanged(scene, ContainerState::scheduled), "unhealthy_preserves_scene") && ok;
  }
  {
    Scene scene; scene.donorY.waitingOnCompactions = true;
    ok = expect(!search(scene.inputs(), Limits {2, 64}).admitted, "busy_donor_rejected") && expect(unchanged(scene), "busy_preserves_scene") && ok;
  }
  {
    Scene scene; scene.machines[2].lifetime = MachineLifetime::spot;
    ok = expect(!search(scene.inputs(), Limits {2, 64}).admitted, "spot_cannot_accept_base") && expect(unchanged(scene), "spot_preserves_scene") && ok;
  }
  {
    Scene scene; scene.target.previous = &scene.donorY;
    ok = expect(!search(scene.inputs(), Limits {2, 64}).admitted, "predecessor_excluded") && expect(unchanged(scene), "predecessor_preserves_scene") && ok;
  }
  {
    Scene scene; scene.y.assignedGPUMemoryMBs.push_back(1);
    ok = expect(!search(scene.inputs(), Limits {2, 64}).admitted, "gpu_donor_unsupported") && expect(unchanged(scene), "gpu_preserves_scene") && ok;
  }
  {
    Scene scene; scene.machines[2].neuron.machine = &scene.machines[2]; scene.machines[2].neuron.connected = false;
    ok = expect(!search(scene.inputs(), Limits {2, 64}).admitted, "unready_destination_rejected") && expect(unchanged(scene), "unready_preserves_scene") && ok;
  }
  {
    Scene scene; scene.machines[1].neuron.machine = &scene.machines[1]; scene.machines[1].neuron.connected = false;
    ok = expect(!search(scene.inputs(), Limits {2, 64}).admitted, "unready_source_rejected") && expect(unchanged(scene), "unready_source_preserves_scene") && ok;
  }
  {
    Scene scene; scene.donorY.plan.stateless.maxPerRackRatio = 0.0f;
    ok = expect(!search(scene.inputs(), Limits {2, 64}).admitted, "concentration_rejected") && expect(unchanged(scene), "concentration_preserves_scene") && ok;
  }
  {
    Scene scene;
    Machine::Claim full = {};
    full.nFit = Machine::maxSchedulableContainers;
    scene.machines[2].claims.push_back(std::move(full));
    ok = expect(!search(scene.inputs(), Limits {2, 64}).admitted, "container_slots_rejected") && expect(unchanged(scene), "slots_preserves_scene") && ok;
  }
  {
    Scene scene; scene.target.plan.isStateful = true;
    Result result = search(scene.inputs(), Limits {2, 64});
    ok = expect(!result.admitted && result.unsupported, "stateful_target_unsupported") && expect(unchanged(scene), "stateful_target_preserves_scene") && ok;
  }
  {
    Scene scene; scene.target.plan.config.nLogicalCores = 5;
    ok = expect(!search(scene.inputs(), Limits {2, 64}).admitted, "impossible_target_rejected") && expect(unchanged(scene), "impossible_target_preserves_scene") && ok;
  }
  return ok;
}

struct Snapshot {
  std::array<int32_t, 3> cores = {};
  std::array<int32_t, 3> memory = {};
  std::array<int32_t, 3> storage = {};
  std::array<size_t, 3> indexes = {};
  size_t donorXMachineCounts = 0;
  size_t donorYMachineCounts = 0;
  size_t targetMachineCounts = 0;
  size_t brainContainers = 0;
  ContainerState xState = {};
  ContainerState yState = {};
  Machine *xMachine = nullptr;
  Machine *yMachine = nullptr;
};

static Snapshot snapshot(const Scene& scene)
{
  Snapshot result = {};
  for (uint32_t index = 0; index < 3; ++index)
  {
    result.cores[index] = scene.machines[index].nLogicalCores_available;
    result.memory[index] = scene.machines[index].memoryMB_available;
    result.storage[index] = scene.machines[index].storageMB_available;
    result.indexes[index] = scene.machines[index].containersByDeploymentID.size();
  }
  result.donorXMachineCounts = scene.donorX.countPerMachine.size();
  result.donorYMachineCounts = scene.donorY.countPerMachine.size();
  result.targetMachineCounts = scene.target.countPerMachine.size();
  result.brainContainers = scene.brain.containers.size();
  result.xState = scene.x.state;
  result.yState = scene.y.state;
  result.xMachine = scene.x.machine;
  result.yMachine = scene.y.machine;
  return result;
}

static bool unchangedFrom(const Scene& scene, const Snapshot& before)
{
  Snapshot after = snapshot(scene);
  return after.cores == before.cores && after.memory == before.memory && after.storage == before.storage &&
         after.indexes == before.indexes && after.donorXMachineCounts == before.donorXMachineCounts &&
         after.donorYMachineCounts == before.donorYMachineCounts && after.targetMachineCounts == before.targetMachineCounts &&
         after.brainContainers == before.brainContainers && after.xState == before.xState && after.yState == before.yState &&
         after.xMachine == before.xMachine && after.yMachine == before.yMachine &&
         scene.target.toSchedule.empty() && scene.target.waitingOnContainers.empty();
}

enum class BenchmarkWorkload : uint8_t { witness, direct, oneHop, impossible };

static void configureBenchmarkWorkload(Scene& scene, BenchmarkWorkload workload)
{
  switch (workload)
  {
    case BenchmarkWorkload::direct:
      Scene::setMachineCapacity(scene.machines[2], 4, 4096, 4, 4096);
      break;
    case BenchmarkWorkload::oneHop:
      Scene::setMachineCapacity(scene.machines[2], 2, 4096, 2, 4096);
      break;
    case BenchmarkWorkload::impossible:
      scene.target.plan.config.nLogicalCores = 5;
      break;
    case BenchmarkWorkload::witness:
      break;
  }
}

static const char *benchmarkWorkloadName(BenchmarkWorkload workload)
{
  switch (workload)
  {
    case BenchmarkWorkload::witness: return "witness";
    case BenchmarkWorkload::direct: return "direct";
    case BenchmarkWorkload::oneHop: return "onehop";
    case BenchmarkWorkload::impossible: return "impossible";
  }
  return "unknown";
}

struct BenchmarkRow {
  uint64_t baselineNs = 0;
  uint64_t candidateNs = 0;
  bool baselineAdmitted = false;
  bool candidateAdmitted = false;
  uint32_t moves = 0;
  uint32_t expandedNodes = 0;
  bool exhausted = false;
  bool searched = false;
};

static BenchmarkRow runBenchmarkRow(BenchmarkWorkload workload,
                                    const std::array<uint8_t, 3>& machineOrder,
                                    const std::array<uint8_t, 2>& donorOrder,
                                    bool candidateFirst)
{
  Scene scene;
  configureBenchmarkWorkload(scene, workload);
  Inputs inputs = scene.inputs();
  inputs.machines.clear();
  inputs.donorDeployments.clear();
  for (uint8_t index : machineOrder) inputs.machines.push_back(&scene.machines[index]);
  for (uint8_t index : donorOrder)
    inputs.donorDeployments.push_back(index == 0 ? &scene.donorX : &scene.donorY);
  const Snapshot before = snapshot(scene);

  bool baselineAdmitted = false;
  bool baselineForCandidate = false;
  uint64_t baselineNs = 0;
  uint64_t candidateNs = 0;
  Result result = {};
  auto measureBaseline = [&] {
    const auto started = std::chrono::steady_clock::now();
    baselineAdmitted = baseline(scene);
    baselineNs = uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - started).count());
  };
  auto measureCandidate = [&] {
    const auto started = std::chrono::steady_clock::now();
    baselineForCandidate = baseline(scene);
    if (baselineForCandidate == false)
    {
      result = search(inputs);
    }
    candidateNs = uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - started).count());
  };
  if (candidateFirst)
  {
    measureCandidate();
    measureBaseline();
  }
  else
  {
    measureBaseline();
    measureCandidate();
  }
  const bool candidateAdmitted = baselineForCandidate || result.admitted;

  const bool expectedBaseline = workload == BenchmarkWorkload::direct || workload == BenchmarkWorkload::oneHop;
  const bool expectedCandidate = workload != BenchmarkWorkload::impossible;
  bool exactWitness = true;
  if (workload == BenchmarkWorkload::witness)
  {
    exactWitness = result.moves.size() == 2 &&
                   result.moves[0].container == &scene.y && result.moves[0].from == &scene.machines[1] && result.moves[0].to == &scene.machines[2] &&
                   result.moves[1].container == &scene.x && result.moves[1].from == &scene.machines[0] && result.moves[1].to == &scene.machines[1] &&
                   result.targetMachine == &scene.machines[0];
  }
  else if (baselineForCandidate)
  {
    exactWitness = result.moves.empty();
  }
  if (!expect(baselineAdmitted == expectedBaseline, "benchmark_baseline_admission") ||
      !expect(baselineForCandidate == baselineAdmitted, "benchmark_baseline_repeatable") ||
      !expect(candidateAdmitted == expectedCandidate, "benchmark_candidate_admission") ||
      !expect(exactWitness, "benchmark_witness_moves") ||
      !expect(unchangedFrom(scene, before), "benchmark_preserves_scene"))
  {
    std::abort();
  }
  return BenchmarkRow {
      baselineNs, candidateNs,
      baselineAdmitted, candidateAdmitted, uint32_t(result.moves.size()), result.expandedNodes,
      result.exhausted, !baselineForCandidate};
}

static bool runBenchmark()
{
  constexpr std::array<std::array<uint8_t, 3>, 6> machineOrders = {{
      {0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}};
  constexpr std::array<std::array<uint8_t, 2>, 2> donorOrders = {{{0, 1}, {1, 0}}};
  constexpr std::array<BenchmarkWorkload, 4> workloads = {{
      BenchmarkWorkload::witness, BenchmarkWorkload::direct, BenchmarkWorkload::oneHop, BenchmarkWorkload::impossible}};
  std::fprintf(stdout, "workload,sample,baseline_ns,candidate_ns,baseline_admitted,candidate_admitted,moves,expanded_nodes,exhausted,searched\n");
  bool ok = true;
  for (BenchmarkWorkload workload : workloads)
  {
    for (size_t machineIndex = 0; machineIndex < machineOrders.size(); ++machineIndex)
    {
      for (size_t donorIndex = 0; donorIndex < donorOrders.size(); ++donorIndex)
      {
        std::vector<uint64_t> candidateSamples;
        candidateSamples.reserve(30);
        for (uint32_t sample = 0; sample < 30; ++sample)
        {
          BenchmarkRow row = runBenchmarkRow(workload, machineOrders[machineIndex], donorOrders[donorIndex], (sample & 1u) != 0);
          std::fprintf(stdout, "%s-%zu-%zu,%u,%llu,%llu,%u,%u,%zu,%u,%u,%u\n",
                       benchmarkWorkloadName(workload), machineIndex, donorIndex, sample,
                       static_cast<unsigned long long>(row.baselineNs), static_cast<unsigned long long>(row.candidateNs),
                       unsigned(row.baselineAdmitted), unsigned(row.candidateAdmitted), size_t(row.moves),
                       unsigned(row.expandedNodes), unsigned(row.exhausted), unsigned(row.searched));
          candidateSamples.push_back(row.candidateNs);
        }
        std::sort(candidateSamples.begin(), candidateSamples.end());
        const uint64_t p95 = candidateSamples[(candidateSamples.size() * 95 + 99) / 100 - 1];
        ok = expect(p95 <= 2'000'000, "benchmark_candidate_p95_under_2ms") && ok;
      }
    }
  }
  return ok;
}

} // namespace prodigy::test::compaction

int main(int argc, char **argv)
{
  using namespace prodigy::test::compaction;
  if (argc == 2 && std::strcmp(argv[1], "--benchmark") == 0)
  {
    return runBenchmark() ? 0 : 1;
  }
  if (argc != 1)
  {
    std::fprintf(stderr, "usage: %s [--benchmark]\n", argv[0]);
    return 2;
  }
  return assertWitness() && assertDirectAndBounds() && assertEligibilityGuards() ? 0 : 1;
}
