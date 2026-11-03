#include <networking/includes.h>
#include <prodigy/neuron/neuron.h>

#include <cassert>
#include <filesystem>
#include <fstream>
#include <unistd.h>

class RetainedCgroupNeuron final : public Neuron {
public:
  String cgroupRoot = {};
  bool restoreSucceeds = false;
  uint32_t published = 0;

  void seed(const String& root, uint8_t datacenterFragment, uint32_t machineFragment)
  {
    cgroupRoot = root;
    lcsubnet6 = {};
    lcsubnet6.dpfx = datacenterFragment;
    lcsubnet6.mpfx[0] = uint8_t((machineFragment >> 16) & 0xffu);
    lcsubnet6.mpfx[1] = uint8_t((machineFragment >> 8) & 0xffu);
    lcsubnet6.mpfx[2] = uint8_t(machineFragment & 0xffu);
    brain = new NeuronBrainControlStream();
    brain->isFixedFile = true;
    brain->fslot = 1;
    brain->connected = true;
  }

  bool inventoryComplete()
  {
    String failure = {};
    return liveContainerInventoryComplete(failure);
  }

  bool publishedExact(uint128_t uuid, pid_t pid) const
  {
    auto found = containers.find(uuid);
    return found != containers.end() && found->second != nullptr &&
        found->second->pid == pid && containerByPid.find(pid) != containerByPid.end() &&
        containerByPid.find(pid)->second == found->second;
  }

  void setFragment(uint8_t datacenterFragment, uint32_t machineFragment)
  {
    lcsubnet6 = {};
    lcsubnet6.dpfx = datacenterFragment;
    lcsubnet6.mpfx[0] = uint8_t((machineFragment >> 16) & 0xffu);
    lcsubnet6.mpfx[1] = uint8_t((machineFragment >> 8) & 0xffu);
    lcsubnet6.mpfx[2] = uint8_t(machineFragment & 0xffu);
  }

  void receiveBootstrap(const ContainerPlan& plan)
  {
    NeuronContainerBootstrap bootstrap = {};
    bootstrap.plan = plan;
    String serialized = {};
    assert(BitseryEngine::serialize(serialized, bootstrap));
    String frame = {};
    uint32_t header = Message::appendHeader(frame, NeuronTopic::stateUpload);
    Message::appendAlignedBuffer<Alignment::one>(
        frame, reinterpret_cast<const uint8_t *>(&lcsubnet6), sizeof(lcsubnet6));
    Message::appendValue(frame, serialized);
    Message::finish(frame, header);
    neuronHandler(reinterpret_cast<Message *>(frame.data()));
  }

protected:
  String containerCgroupInventoryRoot(void) const override { return cgroupRoot; }

  ProdigyHostTask<bool> restoreStateUploadNetworkAsync(
      Container *, CoroutineStack *, String *, std::function<bool()> current) override
  {
    co_return restoreSucceeds && current();
  }

  void queueRestoredStateUploadContainerWaitid(Container *) override {}

  void pushContainer(Container *container) override
  {
    assert(container != nullptr);
    containers.insert_or_assign(container->plan.uuid, container);
    containerByPid.insert_or_assign(container->pid, container);
    ++published;
  }
};

static ContainerPlan retainedPlan(uint128_t uuid, uint8_t fragment)
{
  ContainerPlan plan = {};
  plan.uuid = uuid;
  plan.fragment = fragment;
  plan.state = ContainerState::scheduled;
  plan.config.applicationID = uint16_t(400 + fragment);
  plan.config.versionID = 1;
  plan.config.memoryMB = 64;
  plan.config.nLogicalCores = 1;
  plan.config.runAsID = 0;
  plan.config.type = ApplicationType::stateless;
  return plan;
}

static void writeRetainedCgroup(const std::filesystem::path& root, uint128_t uuid, pid_t pid)
{
  const auto leaf = root / (std::to_string(uint64_t(uuid)) + ".slice") / "leaf";
  std::filesystem::create_directories(leaf);
  std::ofstream(leaf.parent_path() / "cgroup.events") << "populated 1\nfrozen 0\n";
  std::ofstream(leaf.parent_path() / "cpuset.cpus") << "0\n";
  std::ofstream(leaf.parent_path() / "cpuset.cpus.effective") << "0\n";
  std::ofstream(leaf / "cgroup.procs") << pid << "\n";
}

static String makeRoot(const char *suffix)
{
  const auto base = std::filesystem::current_path() / ".run";
  std::filesystem::create_directories(base);
  std::string pattern = (base / (std::string("prodigy-retained-cgroup-") + suffix + "-XXXXXX")).string();
  char *created = mkdtemp(pattern.data());
  assert(created != nullptr);
  return String(created);
}

static void testThreeNeuronAuthenticatedPendingOwners()
{
  const pid_t self = getpid();
  Vector<std::unique_ptr<RetainedCgroupNeuron>> neurons = {};
  Vector<String> roots = {};
  Vector<ContainerPlan> plans = {};
  for (uint8_t index = 0; index < 3; ++index)
  {
    roots.push_back(makeRoot("three"));
    plans.push_back(retainedPlan(uint128_t(0x771100 + index), uint8_t(index + 1)));
    writeRetainedCgroup(std::filesystem::path(roots.back().c_str()), plans.back().uuid, self);
    auto neuron = std::make_unique<RetainedCgroupNeuron>();
    neuron->seed(roots.back(), 1, uint32_t(0x120000 + index));
    neuron->receiveBootstrap(plans.back());
    assert(neuron->inventoryComplete()); // Exact authenticated pending owner holds the fence.
    assert(!neuron->publishedExact(plans.back().uuid, self));
    neurons.push_back(std::move(neuron));
  }

  for (uint32_t index = 0; index < neurons.size(); ++index)
  {
    neurons[index]->restoreSucceeds = true;
    neurons[index]->receiveBootstrap(plans[index]);
    assert(neurons[index]->publishedExact(plans[index].uuid, self));
    assert(neurons[index]->inventoryComplete());
    assert(neurons[index]->published == 1);
    neurons[index]->receiveBootstrap(plans[index]);
    assert(neurons[index]->published == 1); // exact replay never schedules a duplicate
  }
  for (String& root : roots) std::filesystem::remove_all(root.c_str());
}

static void testRejectsUnprovenCgroupVariants()
{
  const pid_t self = getpid();

  String absentRoot = makeRoot("absent");
  const ContainerPlan absent = retainedPlan(0x771201, 1);
  writeRetainedCgroup(std::filesystem::path(absentRoot.c_str()), absent.uuid, self);
  RetainedCgroupNeuron absentNeuron = {};
  absentNeuron.seed(absentRoot, 1, 0x130001);
  assert(!absentNeuron.inventoryComplete()); // No authoritative bootstrap.

  String pidRoot = makeRoot("pid");
  const ContainerPlan pidPlan = retainedPlan(0x771202, 2);
  writeRetainedCgroup(std::filesystem::path(pidRoot.c_str()), pidPlan.uuid, self);
  RetainedCgroupNeuron pidNeuron = {};
  pidNeuron.seed(pidRoot, 1, 0x130002);
  pidNeuron.receiveBootstrap(pidPlan);
  const auto pidLeaf = std::filesystem::path(pidRoot.c_str()) /
      (std::to_string(uint64_t(pidPlan.uuid)) + ".slice") / "leaf";
  std::ofstream(pidLeaf / "cgroup.procs", std::ios::trunc) << self + 1 << "\n";
  assert(!pidNeuron.inventoryComplete()); // Exact PID, not merely UUID/name, is required.

  String nameRoot = makeRoot("name");
  const ContainerPlan namePlan = retainedPlan(0x771203, 3);
  const auto namePath = std::filesystem::path(nameRoot.c_str()) /
      (std::to_string(uint64_t(namePlan.uuid)) + ".slice");
  const auto differentNamePath = std::filesystem::path(nameRoot.c_str()) /
      (std::to_string(uint64_t(namePlan.uuid + 1)) + ".slice");
  writeRetainedCgroup(std::filesystem::path(nameRoot.c_str()), namePlan.uuid, self);
  RetainedCgroupNeuron nameNeuron = {};
  nameNeuron.seed(nameRoot, 1, 0x130003);
  nameNeuron.receiveBootstrap(namePlan);
  std::filesystem::rename(namePath, differentNamePath);
  assert(!nameNeuron.inventoryComplete()); // Bootstrap cannot open a different cgroup.

  String fragmentRoot = makeRoot("fragment");
  const ContainerPlan fragmentPlan = retainedPlan(0x771204, 4);
  writeRetainedCgroup(std::filesystem::path(fragmentRoot.c_str()), fragmentPlan.uuid, self);
  RetainedCgroupNeuron fragmentNeuron = {};
  fragmentNeuron.seed(fragmentRoot, 1, 0x130004);
  fragmentNeuron.receiveBootstrap(fragmentPlan);
  assert(fragmentNeuron.inventoryComplete());
  fragmentNeuron.setFragment(1, 0x1300ff);
  assert(!fragmentNeuron.inventoryComplete()); // Pending owner is scoped to the admitted fragment.

  std::filesystem::remove_all(absentRoot.c_str());
  std::filesystem::remove_all(pidRoot.c_str());
  std::filesystem::remove_all(nameRoot.c_str());
  std::filesystem::remove_all(fragmentRoot.c_str());
}

int main()
{
  testThreeNeuronAuthenticatedPendingOwners();
  testRejectsUnprovenCgroupVariants();
  return 0;
}
