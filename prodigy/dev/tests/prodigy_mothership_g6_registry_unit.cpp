#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <unistd.h>

#include <prodigy/mothership/mothership.cluster.registry.h>

static String digest(char value)
{
  String result = {};
  for (uint32_t index = 0; index < 64; ++index) result.append(value);
  return result;
}

static void truthRetirementRegressions(const String& path, bool adoptedMode = false)
{
  String failure;
  MothershipProdigyCluster owner = {};
  owner.name = "truth-owner"_ctv; owner.clusterUUID = 0x901;
  owner.deploymentMode = MothershipClusterDeploymentMode::remote;
  owner.provider = MothershipClusterProvider::vultr;
  owner.providerScope = "ewr"_ctv; owner.providerCredentialName = "test-account"_ctv;
  owner.includeLocalMachine = false; owner.nBrains = 3;
  for (uint32_t i = 0; i < 3; ++i) {
    ClusterMachine machine = {};
    machine.source = ClusterMachineSource::created;
    machine.backing = ClusterMachineBacking::cloud;
    machine.kind = MachineConfig::MachineKind::vm;
    machine.isBrain = true;
    machine.uuid = 0x910 + i;
    machine.hasCloud = true;
    machine.cloud.cloudID.snprintf<"vultr-{itoa}"_ctv>(i);
    owner.topology.machines.push_back(machine);
  }
  if (adoptedMode) {
    for (auto& machine : owner.topology.machines) {
      machine.source = ClusterMachineSource::adopted;
      machine.ssh.address.snprintf<"2001:db8::{itoh}"_ctv>(machine.uuid);
      machine.ssh.user = "root"_ctv;
      machine.ssh.privateKeyPath = "/keys/truth"_ctv;
      machine.ssh.hostPublicKeyOpenSSH = "ssh-ed25519 pinned-key"_ctv;
      MothershipProdigyClusterMachine registered;
      registered.source = MothershipClusterMachineSource::adopted;
      registered.backing = machine.backing; registered.kind = machine.kind;
      registered.lifetime = machine.lifetime; registered.isBrain = machine.isBrain;
      registered.uuid = machine.uuid; registered.rackUUID = machine.rackUUID;
      registered.hasCloud = true; registered.cloud = machine.cloud; registered.ssh = machine.ssh;
      owner.machines.push_back(registered);
    }
    String inventory;
    assert(mothershipTruthRetirementInventoryDigest(owner, inventory));
    auto invalid = owner;
    invalid.topology.machines[1] = invalid.topology.machines[0];
    assert(!mothershipTruthRetirementInventoryDigest(invalid, inventory));
    invalid = owner; invalid.machines[1] = invalid.machines[0];
    assert(!mothershipTruthRetirementInventoryDigest(invalid, inventory));
    invalid = owner; invalid.machines.pop_back();
    assert(!mothershipTruthRetirementInventoryDigest(invalid, inventory));
    invalid = owner; invalid.machines[0].ssh.hostPublicKeyOpenSSH = "replacement"_ctv;
    assert(!mothershipTruthRetirementInventoryDigest(invalid, inventory));
    invalid = owner; invalid.machines[0].ssh.privateKeyPath.clear();
    assert(!mothershipTruthRetirementInventoryDigest(invalid, inventory));
    invalid = owner; invalid.topology.machines[0].ssh.port = 0;
    assert(!mothershipTruthRetirementInventoryDigest(invalid, inventory));
    invalid = owner; invalid.includeLocalMachine = true;
    assert(!mothershipTruthRetirementInventoryDigest(invalid, inventory));
    invalid = owner; invalid.nBrains = 2;
    assert(!mothershipTruthRetirementInventoryDigest(invalid, inventory));
  }
  MothershipProdigyCluster next = owner;
  next.name = "truth-next"_ctv; next.clusterUUID = 0x902;
  for (uint32_t i = 0; i < 3; ++i) {
    next.topology.machines[i].uuid = 0x920 + i;
    next.topology.machines[i].cloud.cloudID.snprintf<"next-{itoa}"_ctv>(i);
    if (adoptedMode) {
      next.machines[i].uuid = next.topology.machines[i].uuid;
      next.machines[i].cloud = next.topology.machines[i].cloud;
    }
  }
  auto writeCluster = [&](TidesDB& db, const MothershipProdigyCluster& cluster) {
    MothershipProdigyClusterRecordV5 record = {}; record.cluster = cluster;
    record.internalTransportProfile = cluster.internalTransportProfile;
    for (const auto& machine : cluster.machines) {
      record.adoptedMachineRackUUIDs.push_back(machine.rackUUID);
      record.adoptedMachineUUIDs.push_back(machine.uuid);
    }
    String payload, value, key;
    assert(BitseryEngine::serialize(payload, record));
    value.assign("PRODIGY-MOTHERSHIP-CLUSTER\nversion=5\n\n"_ctv);
    const auto headerSize = value.size();
    value.append(payload);
    assert(value.size() == headerSize + payload.size());
    key.assignItoh(cluster.clusterUUID);
    assert(db.write("clusters"_ctv, cluster.name, value, &failure));
    assert(db.write("clusters_by_uuid"_ctv, key, cluster.name, &failure));
  };
  { TidesDB db(path, TidesDB::Durability::full); writeCluster(db, owner); writeCluster(db, next); }
  MothershipApplicationPlacement pending;
  {
    MothershipTruthLifecycleLock first, second;
    assert(first.acquire(path, &failure));
    assert(!second.acquire(path, &failure));
  }
  {
    MothershipClusterRegistry registry(path);
    MothershipApplicationPlacement placed; bool resumed = false;
    assert(registry.beginTruthOwnerRetirement(owner, placed, &failure) && placed.truthRetirementStartedGeneration == 0);
    assert(registry.admitTruthPlacement(owner.clusterUUID, digest('a'), placed, resumed, &failure));
    assert(!registry.removeCluster(owner.name, &failure));
    auto bad = owner; bad.topology.machines[0].cloud.cloudID = "wrong"_ctv;
    assert(!registry.beginTruthOwnerRetirement(bad, placed, &failure));
    bad = owner; bad.topology.machines[0].source = adoptedMode ? ClusterMachineSource::created : ClusterMachineSource::adopted;
    assert(!registry.beginTruthOwnerRetirement(bad, placed, &failure));
    assert(registry.beginTruthOwnerRetirement(next, placed, &failure) && placed.truthRetirementStartedGeneration == 0);
    String expectedInventory, actualInventory, identity;
    if (!mothershipTruthRetirementInventoryDigest(owner, expectedInventory)) {
      std::fprintf(stderr, "Truth retirement fixture owner inventory invalid\n");
      assert(false);
    }
    identity.assignItoh(owner.clusterUUID);
    MothershipProdigyCluster stored;
    if (!registry.getClusterByIdentity(identity, stored, &failure)) {
      std::fprintf(stderr, "Truth retirement fixture lookup: %s\n", failure.c_str());
      assert(false);
    }
    assert(stored.clusterUUID == owner.clusterUUID && stored.name == owner.name);
    if (!mothershipTruthRetirementInventoryDigest(stored, actualInventory)) {
      std::fprintf(stderr, "Truth retirement fixture stored inventory invalid: machines=%zu brains=%u\n",
                   stored.topology.machines.size(), stored.nBrains);
      assert(false);
    }
    if (expectedInventory != actualInventory) {
      std::fprintf(stderr, "Truth retirement fixture inventory mismatch: expected=%s actual=%s\n",
                   expectedInventory.c_str(), actualInventory.c_str());
      assert(false);
    }
    if (!registry.beginTruthOwnerRetirement(owner, pending, &failure)) {
      std::fprintf(stderr, "Truth retirement begin: %s\n", failure.c_str());
      assert(false);
    }
    assert(pending.version == 4 && pending.truthRetirementExpectedGeneration == 1 &&
           pending.truthRetirementStartedGeneration == 2 && pending.truthRetirementCompletedGeneration == 0);
    assert(registry.beginTruthOwnerRetirement(owner, placed, &failure) &&
           placed.truthRetirementStartedGeneration == pending.truthRetirementStartedGeneration);
  }
  {
    MothershipClusterRegistry registry(path);
    MothershipApplicationPlacement placed; bool resumed = false;
    assert(registry.loadTruthPlacement(placed, &failure) && placed.truthRetirementStartedGeneration == 2);
    assert(!registry.admitTruthPlacement(owner.clusterUUID, digest('b'), placed, resumed, &failure));
    assert(!registry.admitTruthPlacement(next.clusterUUID, digest('b'), placed, resumed, &failure));
    assert(!registry.removeCluster(owner.name, &failure));
    auto bad = pending; ++bad.truthRetirementExpectedGeneration;
    assert(!registry.completeTruthOwnerRetirement(owner, bad, digest('c'), &failure));
    bad = pending; ++bad.truthRetirementStartedGeneration;
    assert(!registry.completeTruthOwnerRetirement(owner, bad, digest('c'), &failure));
    bad = pending; bad.truthRetirementInventorySHA256 = digest('d');
    assert(!registry.completeTruthOwnerRetirement(owner, bad, digest('c'), &failure));
    assert(!registry.completeTruthOwnerRetirement(next, pending, digest('c'), &failure));
    assert(!registry.completeTruthOwnerRetirement(owner, pending, "bad"_ctv, &failure));
    assert(registry.completeTruthOwnerRetirement(owner, pending, digest('c'), &failure));
    assert(registry.completeTruthOwnerRetirement(owner, pending, digest('c'), &failure));
    assert(!registry.completeTruthOwnerRetirement(owner, pending, digest('d'), &failure));
    assert(!registry.admitTruthPlacement(next.clusterUUID, digest('b'), placed, resumed, &failure));
  }
  { // Completed cleanup is still bound to the frozen registered inventory.
    TidesDB db(path, TidesDB::Durability::full);
    auto changed = owner; changed.topology.machines[0].cloud.cloudID = "different-vm"_ctv;
    writeCluster(db, changed);
  }
  {
    MothershipClusterRegistry registry(path);
    assert(!registry.removeCluster(owner.name, &failure));
    assert(!registry.completeTruthOwnerRetirement(owner, pending, digest('c'), &failure));
  }
  { TidesDB db(path, TidesDB::Durability::full); writeCluster(db, owner); }
  {
    MothershipClusterRegistry registry(path);
    assert(registry.removeCluster(owner.name, &failure));
    assert(registry.completeTruthOwnerRetirement(owner, pending, digest('c'), &failure));
  }
  { // A new registered cluster may reuse the retired name but not its UUID.
    TidesDB db(path, TidesDB::Durability::full);
    next.name = owner.name;
    writeCluster(db, next);
  }
  {
    MothershipClusterRegistry registry(path);
    MothershipApplicationPlacement placed; bool resumed = false;
    assert(!registry.admitTruthPlacement(owner.clusterUUID, digest('b'), placed, resumed, &failure));
    assert(!registry.admitTruthPlacement(next.clusterUUID, digest('a'), placed, resumed, &failure));
    assert(registry.admitTruthPlacement(next.clusterUUID, digest('b'), placed, resumed, &failure) && !resumed);
    assert(placed.generation == 4 && placed.ownerClusterUUID == next.clusterUUID &&
           placed.truthRetirementOwnerClusterUUID == owner.clusterUUID &&
           placed.truthRetirementCleanupSHA256 == digest('c') && placed.observationReceiptSHA256 == digest('b'));
    assert(!registry.completeTruthOwnerRetirement(owner, pending, digest('c'), &failure));
    assert(registry.loadTruthPlacement(placed, &failure) && placed.ownerClusterUUID == next.clusterUUID && placed.generation == 4);
  }
}

static void testTruthRetirementRegressions(const String& path)
{
  String failure;
  MothershipProdigyCluster cluster = {};
  cluster.name = "truth-test-owner"_ctv; cluster.clusterUUID = 0xa01;
  cluster.deploymentMode = MothershipClusterDeploymentMode::test;
  cluster.provider = MothershipClusterProvider::unknown;
  cluster.includeLocalMachine = false; cluster.nBrains = 1;
  cluster.test.specified = true; cluster.test.workspaceRoot = "/tmp/truth-test-owner"_ctv;
  cluster.test.machineCount = 2; cluster.test.machineLogicalCores = 8;
  cluster.test.machineMemoryMB = 16384; cluster.test.machineStorageMB = 262144;
  cluster.test.interContainerMTU = 1448;
  cluster.topology.version = 6;
  for (uint32_t i = 0; i < 2; ++i) {
    ClusterMachine machine = {}; machine.uuid = 0xa10 + i; machine.isBrain = i == 0;
    machine.source = ClusterMachineSource::created; machine.backing = ClusterMachineBacking::owned;
    machine.kind = MachineConfig::MachineKind::vm; machine.ownedLogicalCores = 8;
    machine.ownedMemoryMB = 16384; machine.ownedStorageMB = 262144;
    cluster.topology.machines.push_back(machine);
  }
  auto writeCluster = [&](const MothershipProdigyCluster& value) {
    TidesDB db(path, TidesDB::Durability::full); MothershipProdigyClusterRecordV5 record = {};
    record.cluster = value; record.internalTransportProfile = value.internalTransportProfile;
    String payload, stored, identity; assert(BitseryEngine::serialize(payload, record));
    stored.assign("PRODIGY-MOTHERSHIP-CLUSTER\nversion=5\n\n"_ctv); stored.append(payload);
    identity.assignItoh(value.clusterUUID);
    assert(db.write("clusters"_ctv, value.name, stored, &failure));
    assert(db.write("clusters_by_uuid"_ctv, identity, value.name, &failure));
  };
  writeCluster(cluster);
  MothershipApplicationPlacement placement, pending; bool resumed = false;
  {
    MothershipClusterRegistry registry(path);
    assert(registry.beginTruthOwnerRetirement(cluster, placement, &failure));
    assert(registry.admitTruthPlacement(cluster.clusterUUID, digest('a'), placement, resumed, &failure));
    assert(registry.beginTruthOwnerRetirement(cluster, pending, &failure));
    assert(pending.truthRetirementStartedGeneration != 0 && pending.truthRetirementCompletedGeneration == 0);
    assert(!registry.removeCluster(cluster.name, &failure)); // The completion fence remains mandatory.
  }
  { // Both request configuration and topology are bound to the registered test inventory.
    auto changed = cluster; changed.test.workspaceRoot = "/tmp/other-workspace"_ctv; writeCluster(changed);
    MothershipClusterRegistry registry(path);
    assert(!registry.beginTruthOwnerRetirement(cluster, placement, &failure));
    assert(!registry.completeTruthOwnerRetirement(cluster, pending, digest('b'), &failure));
  }
  {
    auto changed = cluster; ++changed.topology.version; writeCluster(changed);
    MothershipClusterRegistry registry(path);
    assert(!registry.beginTruthOwnerRetirement(cluster, placement, &failure));
    assert(!registry.completeTruthOwnerRetirement(cluster, pending, digest('b'), &failure));
  }
  writeCluster(cluster);
  {
    MothershipClusterRegistry registry(path);
    assert(registry.beginTruthOwnerRetirement(cluster, placement, &failure));
    assert(registry.completeTruthOwnerRetirement(cluster, pending, digest('b'), &failure));
    assert(registry.completeTruthOwnerRetirement(cluster, pending, digest('b'), &failure)); // Replay is idempotent.
    assert(registry.removeCluster(cluster.name, &failure));
  }
}

static DeploymentPlan graphPlan(uint16_t app, bool replica)
{
  DeploymentPlan plan = {};
  plan.config.type = ApplicationType::stateful; plan.isStateful = true;
  plan.config.applicationID = app; plan.config.versionID = 1;
  plan.config.containerBlobSHA256 = digest('a'); plan.config.containerBlobBytes = 4096;
  plan.stateful.neverShard = true; plan.stateful.seedingAlways = true;
  plan.stateful.clientPrefix = replica ? 0 : prodigyRuntimeStatefulServicePrefix(app, 1);
  plan.stateful.siblingPrefix = prodigyRuntimeStatefulServicePrefix(app, 2);
  plan.stateful.cousinPrefix = prodigyRuntimeStatefulServicePrefix(app, 3);
  plan.stateful.seedingPrefix = prodigyRuntimeStatefulServicePrefix(app, 4);
  plan.stateful.shardingPrefix = prodigyRuntimeStatefulServicePrefix(app, 5);
  plan.whiteholes.emplace_back();
  return plan;
}

static DeploymentPlan graphAllMastersPlan(uint16_t app)
{
  DeploymentPlan plan = graphPlan(app, false);
  plan.stateful.allMasters = true;
  plan.stateful.seedingAlways = false;
  plan.whiteholes.clear();
  return plan;
}

static void installGraphReplicaRoutes(MothershipClusterRegistry& registry, uint16_t app,
                                      uint128_t replica, uint128_t owner, uint128_t identity,
                                      String& failure);

static void graphMembershipRegressions(const String& path)
{
  String failure;
  String replicaIdentity, siblingIdentity;
  replicaIdentity.assignItoh(uint128_t(0x202)); siblingIdentity.assignItoh(uint128_t(0x203));
  { // Existing v1 bytes must remain readable without an appended member list.
    TidesDB db(path, TidesDB::Durability::full);
    for (uint16_t app : {uint16_t(2), uint16_t(5)}) {
      MothershipApplicationPlacement old = {};
      old.version = 1; old.applicationID = app; old.ownerClusterUUID = 0x201;
      old.policy = MothershipApplicationPlacement::Policy::retainedSource;
      old.observationReceiptSHA256 = digest('b');
      String key, encoded; key.assignItoa(app); BitseryEngine::serialize(encoded, old);
      assert(db.write("application_placements"_ctv, key, encoded, &failure));
    }
  }
  String topologyDigest, thirdTopologyDigest;
  {
    MothershipClusterRegistry registry(path);
    for (uint128_t uuid : {uint128_t(0x201), uint128_t(0x202), uint128_t(0x203)}) {
      MothershipProdigyCluster cluster = {};
      cluster.name.snprintf<"graph-{itoh}"_ctv>(uuid); cluster.clusterUUID = uuid;
      cluster.deploymentMode = MothershipClusterDeploymentMode::test;
      cluster.architecture = nametagCurrentBuildMachineArchitecture();
      cluster.test.specified = true;
      cluster.test.workspaceRoot.snprintf<"{}/graph-{itoh}"_ctv>(path, uuid);
      cluster.test.machineCount = 1; cluster.test.enableFakeIpv4Boundary = false;
      cluster.nBrains = 1; cluster.includeLocalMachine = false;
      cluster.topology.version = 7;
      ClusterMachine machine = {}; machine.uuid = uuid + 0x1000; machine.isBrain = true;
      machine.kind = MachineConfig::MachineKind::vm;
      machine.backing = ClusterMachineBacking::owned; machine.lifetime = MachineLifetime::owned;
      cluster.topology.machines.push_back(machine);
      if (!registry.createCluster(cluster, &cluster, &failure)) {
        std::fprintf(stderr, "graph fixture createCluster: %s\n", failure.c_str()); assert(false);
      }
      if (uuid == 0x202) { String bytes; BitseryEngine::serialize(bytes, cluster.topology);
        assert(prodigyComputeSHA256Hex(bytes, topologyDigest)); }
      if (uuid == 0x203) { String bytes; BitseryEngine::serialize(bytes, cluster.topology);
        assert(prodigyComputeSHA256Hex(bytes, thirdTopologyDigest)); }
    }
    for (uint16_t app : {uint16_t(2), uint16_t(5)}) {
      installGraphReplicaRoutes(registry, app, 0x202, 0x201, 0x2020 + app, failure);
      installGraphReplicaRoutes(registry, app, 0x203, 0x201, 0x2030 + app, failure);
    }
    for (uint16_t app : {uint16_t(2), uint16_t(5)}) {
      MothershipApplicationPlacement placed; bool resumed = false;
      assert(registry.loadApplicationPlacement(app, placed, &failure) && placed.version == 1 && placed.graphReplicas.empty());
      const auto replica = graphPlan(app, true);
      auto admit = [&](const DeploymentPlan& candidate, uint128_t cluster = 0x202, uint64_t generation = 1,
                       uint64_t topology = 7) {
        return registry.admitGraphReplicaPlacement(candidate, cluster, 0x201, generation, topology,
            topologyDigest, digest('c'), placed, resumed, &failure);
      };
      auto bad = replica; bad.stateful.allMasters = true; assert(!admit(bad));
      bad = replica; bad.stateful.neverShard = false; assert(!admit(bad));
      bad = replica; bad.stateful.clientPrefix = prodigyRuntimeStatefulServicePrefix(app, 1); assert(!admit(bad));
      bad = replica; ++bad.stateful.siblingPrefix; assert(!admit(bad));
      bad = replica; ++bad.stateful.seedingPrefix; assert(!admit(bad));
      bad = replica; bad.whiteholes.clear(); assert(!admit(bad));
      bad = replica; bad.whiteholes.push_back({}); assert(!admit(bad));
      bad = replica; bad.whiteholes[0].family = ExternalAddressFamily::ipv4; assert(!admit(bad));
      bad = replica; bad.whiteholes[0].transport = ExternalAddressTransport::quic; assert(!admit(bad));
      bad = replica; bad.whiteholes[0].hasAddress = true; assert(!admit(bad));
      bad = replica; bad.whiteholes[0].address = IPAddress("2001:db8::1", true); assert(!admit(bad));
      bad = replica; bad.whiteholes[0].bindingNonce = 1; assert(!admit(bad));
      bad = replica; bad.whiteholes[0].sourcePort = 12000; assert(!admit(bad));
      bad = replica; bad.config.applicationID = 10; assert(!admit(bad));
      assert(!admit(replica, 0x204)); // Unregistered cluster.
      assert(!admit(replica, 0x201)); // Writer owner cannot become replica.
      assert(!admit(replica, 0x202, 1, 6)); // Stale cluster generation.
      assert(!registry.admitGraphReplicaPlacement(replica, 0x202, 0x203, 1, 7,
          topologyDigest, digest('c'), placed, resumed, &failure));
      bad = replica; bad.whiteholes[0].source = ExternalAddressSource::hostPublicAddress;
      assert(prodigyGraphDeploymentPlanCanonical(bad, true));
      assert(admit(replica) && !resumed && placed.version == 3 && placed.generation == 2);
      assert(placed.ownerClusterUUID == 0x201 && placed.graphReplicas.size() == 1 &&
          placed.graphReplicas[0].clusterUUID == 0x202 && placed.graphReplicas[0].membershipGeneration == 2);
      assert(!admit(replica)); // Even exact bytes cannot replay stale membership.
      assert(admit(replica, 0x202, 2) && resumed);
      bad = replica; ++bad.config.versionID; assert(!admit(bad, 0x202, 2));
      bad = replica; bad.config.containerBlobSHA256 = digest('d'); assert(!admit(bad, 0x202, 2));
      const auto writer = graphPlan(app, false);
      auto unresolvedWriter = writer;
      unresolvedWriter.whiteholes.clear();
      assert(!registry.admitApplicationPlacement(unresolvedWriter, 0x201, digest('d'), placed, resumed, &failure));
      unresolvedWriter = writer;
      unresolvedWriter.whiteholes[0].family = ExternalAddressFamily::ipv4;
      assert(!registry.admitApplicationPlacement(unresolvedWriter, 0x201, digest('d'), placed, resumed, &failure));
      assert(!registry.admitApplicationPlacement(writer, 0x202, digest('d'), placed, resumed, &failure));
      assert(registry.admitApplicationPlacement(writer, 0x201, digest('d'), placed, resumed, &failure));
      assert(!registry.admitApplicationPlacement(replica, 0x201, digest('d'), placed, resumed, &failure));
      assert(registry.admitGraphReplicaPlacement(replica, 0x203, 0x201, 2, 7, thirdTopologyDigest,
          digest('e'), placed, resumed, &failure) && !resumed && placed.generation == 3);
      assert(!admit(replica, 0x202, 2));
      assert(admit(replica, 0x202, 3) && resumed);
    }
  }
  { // Cold registry reopen preserves owner and exact non-writer membership.
    MothershipClusterRegistry registry(path);
    for (uint16_t app : {uint16_t(2), uint16_t(5)}) {
      MothershipApplicationPlacement placed; bool resumed = false;
      assert(registry.loadApplicationPlacement(app, placed, &failure) && placed.version == 3 &&
          placed.ownerClusterUUID == 0x201 && placed.generation == 3 && placed.graphReplicas.size() == 2);
      assert(registry.admitGraphReplicaPlacement(graphPlan(app, true), 0x202, 0x201, 3, 7,
          topologyDigest, digest('e'), placed, resumed, &failure) && resumed);
    }
  }
  { // Version two remains readable when the additive retirement journal is absent.
    TidesDB db(path, TidesDB::Durability::full);
    for (uint16_t app : {uint16_t(2), uint16_t(5)}) {
      String key, bytes; key.assignItoa(app);
      assert(db.read("application_placements"_ctv, key, bytes, &failure));
      MothershipApplicationPlacement placement;
      assert(BitseryEngine::deserializeSafe(bytes, placement));
      placement.version = 2; BitseryEngine::serialize(bytes, placement);
      assert(db.write("application_placements"_ctv, key, bytes, &failure));
    }
  }
  {
    MothershipClusterRegistry registry(path);
    MothershipProdigyCluster target;
    assert(registry.getClusterByIdentity(replicaIdentity, target, &failure));
    assert(!registry.removeCluster(target.name, &failure) &&
        failure == "cluster removal requires completed graph replica retirement"_ctv);
    for (uint16_t app : {uint16_t(2), uint16_t(5)}) {
      MothershipApplicationPlacement placed; bool resumed = false;
      assert(registry.loadApplicationPlacement(app, placed, &failure) && placed.version == 2);
      const auto member = placed.graphReplicas[0];
      auto retire = [&](const MothershipGraphReplicaPlacement& candidate, uint64_t generation,
                        bool complete = false, String receipt = {}) {
        return registry.retireGraphReplicaPlacement(app, candidate, 0x201, generation, complete,
            receipt, placed, resumed, &failure);
      };
      assert(!retire(member, 3, true, digest('f'))); // Cleanup cannot precede durable fence.
      auto bad = member; ++bad.deploymentID; assert(!retire(bad, 3));
      bad = member; ++bad.membershipGeneration; assert(!retire(bad, 3));
      bad = member; bad.artifactSHA256 = digest('f'); assert(!retire(bad, 3));
      assert(!registry.retireGraphReplicaPlacement(app, member, 0x203, 3, false, {}, placed, resumed, &failure));
      assert(!retire(member, 2));
      assert(retire(member, 3) && !resumed && placed.version == 3 && placed.generation == 4 &&
          placed.graphReplicas.size() == 2 && placed.graphReplicaRetirements.size() == 1 &&
          placed.graphReplicaRetirements[0].completedGeneration == 0);
      assert(!retire(member, 3));
      assert(retire(member, 4) && resumed);
      assert(!registry.admitGraphReplicaPlacement(graphPlan(app, true), 0x202, 0x201, 4, 7,
          topologyDigest, digest('e'), placed, resumed, &failure));
      assert(registry.admitGraphReplicaPlacement(graphPlan(app, true), 0x203, 0x201, 4, 7,
          thirdTopologyDigest, digest('e'), placed, resumed, &failure) && resumed);
    }
  }
  { // Crash/partial teardown: pending membership remains fenced and resumable.
    MothershipClusterRegistry registry(path);
    for (uint16_t app : {uint16_t(2), uint16_t(5)}) {
      MothershipApplicationPlacement placed; bool resumed = false;
      assert(registry.loadApplicationPlacement(app, placed, &failure) && placed.generation == 4 &&
          placed.graphReplicaRetirements[0].completedGeneration == 0);
      const auto member = placed.graphReplicaRetirements[0].member;
      auto bad = member; bad.canonicalPlanSHA256 = digest('f');
      assert(!registry.retireGraphReplicaPlacement(app, bad, 0x201, 4, true, digest('f'), placed, resumed, &failure));
      assert(!registry.retireGraphReplicaPlacement(app, member, 0x201, 4, true, {}, placed, resumed, &failure));
      assert(registry.retireGraphReplicaPlacement(app, member, 0x201, 4, true, digest('f'), placed, resumed, &failure) &&
          !resumed && placed.generation == 5 && placed.graphReplicas.size() == 1 &&
          placed.graphReplicas[0].clusterUUID == 0x203 && placed.graphReplicaRetirements[0].completedGeneration == 5);
      assert(!registry.retireGraphReplicaPlacement(app, member, 0x201, 4, true, digest('f'), placed, resumed, &failure));
      assert(!registry.retireGraphReplicaPlacement(app, member, 0x201, 5, true, digest('e'), placed, resumed, &failure));
      assert(registry.retireGraphReplicaPlacement(app, member, 0x201, 5, true, digest('f'), placed, resumed, &failure) && resumed);
      assert(!registry.admitGraphReplicaPlacement(graphPlan(app, true), 0x202, 0x201, 5, 7,
          topologyDigest, digest('e'), placed, resumed, &failure));
      assert(!registry.retireGraphReplicaPlacement(10, member, 0x201, 5, false, {}, placed, resumed, &failure));
    }
    MothershipProdigyCluster target;
    assert(registry.getClusterByIdentity(replicaIdentity, target, &failure));
    if (!registry.removeCluster(target.name, &failure)) {
      std::fprintf(stderr, "graph fixture removeCluster: %s\n", failure.c_str()); assert(false);
    }
    MothershipProdigyCluster fresh;
    assert(registry.getClusterByIdentity(siblingIdentity, fresh, &failure));
    const uint8_t siblingDatacenterFragment = fresh.datacenterFragment;
    fresh.name = "graph-204"_ctv; fresh.clusterUUID = 0x204;
    // This is a new real cluster identity, not a clone of the sibling site's
    // globally leased address byte. Let the registry allocate a fresh tag.
    fresh.datacenterFragment = 0;
    fresh.test.workspaceRoot.snprintf<"{}/graph-204"_ctv>(path);
    fresh.controls.clear(); fresh.topology.machines[0].uuid = 0x1204;
    assert(registry.createCluster(fresh, &fresh, &failure));
    assert(fresh.datacenterFragment != 0 &&
        fresh.datacenterFragment != siblingDatacenterFragment);
    String bytes, freshDigest; BitseryEngine::serialize(bytes, fresh.topology);
    assert(prodigyComputeSHA256Hex(bytes, freshDigest));
    for (uint16_t app : {uint16_t(2), uint16_t(5)}) {
      installGraphReplicaRoutes(registry, app, 0x204, 0x201, 0x2040 + app, failure);
      MothershipApplicationPlacement placed; bool resumed = false;
      assert(registry.admitGraphReplicaPlacement(graphPlan(app, true), 0x204, 0x201, 5, 7,
          freshDigest, digest('e'), placed, resumed, &failure) && !resumed && placed.generation == 6);
    }
  }
  { // Completed removal is durable, preserves sibling replica and writer owner.
    MothershipClusterRegistry registry(path);
    MothershipProdigyCluster removed;
    assert(!registry.getClusterByIdentity(replicaIdentity, removed, &failure) && failure == "record not found"_ctv);
    for (uint16_t app : {uint16_t(2), uint16_t(5)}) {
      MothershipApplicationPlacement placed;
      assert(registry.loadApplicationPlacement(app, placed, &failure) && placed.ownerClusterUUID == 0x201 &&
          placed.generation == 6 && placed.graphReplicas.size() == 2 &&
          placed.graphReplicas[0].clusterUUID == 0x203 && placed.graphReplicas[1].clusterUUID == 0x204 &&
          placed.graphReplicaRetirements.size() == 1 && placed.graphReplicaRetirements[0].completedGeneration == 5);
    }
  }
}

static void graphAllMastersPlacementRegressions(const String& path)
{
  MothershipClusterRegistry registry(path);
  String failure;
  for (uint16_t app : {uint16_t(2), uint16_t(5)}) {
    const auto plan = graphAllMastersPlan(app);
    MothershipApplicationPlacement placement; bool resumed = true;
    // Genesis on two registered sites has no retained-source placement and
    // therefore cannot be fenced as a Truth singleton.
    assert(registry.admitApplicationPlacement(plan, 0x201, digest('a'), placement, resumed, &failure));
    assert(placement.ownerClusterUUID == 0 && !resumed);
    assert(registry.admitApplicationPlacement(plan, 0x202, digest('b'), placement, resumed, &failure));
    assert(placement.ownerClusterUUID == 0 && !resumed);
    auto bad = plan; bad.stateful.clientPrefix = 0;
    assert(!registry.admitApplicationPlacement(bad, 0x201, digest('a'), placement, resumed, &failure));
    bad = plan; ++bad.stateful.cousinPrefix;
    assert(!registry.admitApplicationPlacement(bad, 0x201, digest('a'), placement, resumed, &failure));
    bad = plan; ++bad.stateful.seedingPrefix;
    assert(!registry.admitApplicationPlacement(bad, 0x201, digest('a'), placement, resumed, &failure));
    bad = plan; bad.stateful.seedingAlways = true;
    assert(!registry.admitApplicationPlacement(bad, 0x201, digest('a'), placement, resumed, &failure));
    bad = plan; bad.whiteholes.emplace_back();
    assert(!registry.admitApplicationPlacement(bad, 0x201, digest('a'), placement, resumed, &failure));
  }
  MothershipApplicationPlacement truth; bool resumed = false;
  assert(registry.admitApplicationPlacement(10, 0x201, digest('c'), truth, resumed, &failure));
  assert(!registry.admitApplicationPlacement(10, 0x202, digest('d'), truth, resumed, &failure));
}

static CousinRouteRecord makeRoute()
{
  CousinRouteRecord value = {};
  value.routeUUID = 0x101; value.operationUUID = 0x102; value.pairUUID = 0x103;
  value.logicalWorkloadUUID = 0x104; value.logicalServiceUUID = 0x105;
  value.sourceClusterUUID = 0x201; value.destinationClusterUUID = 0x202;
  value.sourceApplicationID = 7; value.destinationApplicationID = 19;
  value.sourceCousinServicePrefix = MeshServices::generateStatefulService(7, 3);
  value.destinationCousinServicePrefix = MeshServices::generateStatefulService(19, 3);
  value.slots.insert(3); value.destinationRoutablePrefixUUID = 0x106;
  value.destinationPublicAddress = IPAddress("2001:db8::1", true); value.destinationTCPPort = 443;
  value.sourcePermissionUUID = 0x301; value.destinationPermissionUUID = 0x302;
  value.transportProtocol = IPPROTO_TCP; value.destinationCIDR = 64; value.pathMTU = 1500;
  value.generation = 1; value.issuedAtMs = 100; value.expiresAtMs = 200;
  value.keyEpoch = 1; value.rootGeneration = 1;
  return value;
}

static ProdigyLocalCousinServicePermission makePermission(const CousinRouteRecord& route, bool source)
{
  ProdigyLocalCousinServicePermission value = {};
  value.protocolVersion = ProdigyLocalCousinServicePermission::baselineVersion;
  value.permissionUUID = source ? route.sourcePermissionUUID : route.destinationPermissionUUID;
  value.pairUUID = route.pairUUID; value.logicalWorkloadUUID = route.logicalWorkloadUUID;
  value.logicalServiceUUID = route.logicalServiceUUID;
  value.localClusterUUID = source ? route.sourceClusterUUID : route.destinationClusterUUID;
  value.peerClusterUUID = source ? route.destinationClusterUUID : route.sourceClusterUUID;
  value.localHalf = source ? CousinRouteHalf::source : CousinRouteHalf::destination;
  value.localApplicationID = source ? route.sourceApplicationID : route.destinationApplicationID;
  value.peerApplicationID = source ? route.destinationApplicationID : route.sourceApplicationID;
  value.localCousinServicePrefix = source ? route.sourceCousinServicePrefix : route.destinationCousinServicePrefix;
  value.peerCousinServicePrefix = source ? route.destinationCousinServicePrefix : route.sourceCousinServicePrefix;
  value.slots = route.slots;
  value.localDeploymentID = (uint64_t(value.localApplicationID) << 48) | (source ? 1 : 2);
  value.canonicalPlanSHA256 = digest(source ? 'a' : 'b'); value.artifactSHA256 = digest(source ? 'c' : 'd');
  value.artifactBytes = 8192; value.generation = 1; value.acceptedAuthorityGeneration = 7;
  value.baselineLogicalCores = 2; value.baselineMemoryMB = 1024; value.baselineStorageMB = 1024;
  return value;
}

static CousinRouteApplyReceipt makeRouteReceipt(const CousinRouteRecord& route, CousinRouteHalf half)
{
  CousinRouteApplyReceipt value = {};
  value.routeUUID = route.routeUUID; value.generation = route.generation;
  assert(cousinRouteAuthorizationDigest(route, value.authorizationSHA256));
  value.localClusterUUID = half == CousinRouteHalf::source ? route.sourceClusterUUID : route.destinationClusterUUID;
  value.localHalf = half; value.keyEpoch = route.keyEpoch;
  value.localRuntimeRevision = half == CousinRouteHalf::source ? 7 : 8;
  value.installedState = route.state;
  return value;
}

static void installGraphReplicaRoutes(MothershipClusterRegistry& registry, uint16_t app,
                                      uint128_t replica, uint128_t owner, uint128_t identity,
                                      String& failure)
{
  for (uint32_t role : {uint32_t(2), uint32_t(4)}) {
    CousinRouteRecord route = {};
    route.routeUUID = identity * 16 + role; route.operationUUID = identity * 16 + role + 0x1000;
    route.pairUUID = identity; route.logicalWorkloadUUID = identity + 1; route.logicalServiceUUID = identity + role;
    route.sourceClusterUUID = replica; route.destinationClusterUUID = owner;
    route.sourceApplicationID = app; route.destinationApplicationID = app;
    route.sourceCousinServicePrefix = prodigyRuntimeStatefulServicePrefix(app, role);
    route.destinationCousinServicePrefix = route.sourceCousinServicePrefix;
    route.slots.insert(0); route.destinationRoutablePrefixUUID = identity + role;
    route.destinationPublicAddress = IPAddress("2001:db8::1", true); route.destinationTCPPort = 443;
    route.sourcePermissionUUID = identity + role + 0x2000; route.destinationPermissionUUID = identity + role + 0x3000;
    route.transportProtocol = IPPROTO_TCP; route.destinationCIDR = 64; route.pathMTU = 1500;
    route.generation = 1; route.issuedAtMs = Time::now<TimeResolution::ms>() - 1;
    route.expiresAtMs = route.issuedAtMs + 60000; route.keyEpoch = 1; route.rootGeneration = 1;
    CousinRouteRecord storedRoute = {}; CousinRouteApplyReceipt storedReceipt = {}; bool resumed = false;
    assert(registry.recordCousinRoute(route, storedRoute, resumed, &failure) && !resumed);
    assert(registry.recordCousinRouteApplyReceipt(makeRouteReceipt(route, CousinRouteHalf::source),
        storedReceipt, resumed, &failure) && !resumed);
    assert(registry.recordCousinRouteApplyReceipt(makeRouteReceipt(route, CousinRouteHalf::destination),
        storedReceipt, resumed, &failure) && !resumed);
  }
}

static MothershipPhysicalFaultMachineObservation observation(uint128_t cluster, uint128_t machine,
                                                             uint64_t topology, char state)
{
  MothershipPhysicalFaultMachineObservation value = {};
  value.clusterUUID = cluster; value.machineUUID = machine; value.topologyVersion = topology;
  value.stateSHA256 = digest(state);
  return value;
}

static void interruptedLocalUpgradeRegressions(const String& path)
{
  MothershipLocalAuthorityRecoveryCohortRequest request;
  request.protocolVersion=2;request.operationUUID=0xc101;
  request.clusterUUID=mothershipLocalInterruptedUpgradeClusterUUID();request.topologyVersion=17;
  request.timeoutMilliseconds=300000;
  auto& intent=request.runtime;
  intent.upgradeOperationUUID=mothershipLocalInterruptedUpgradeOperationUUID();
  intent.predecessorRecoveryUUID=mothershipLocalInterruptedUpgradePredecessorUUID();
  intent.bundlePath="/approved/runtime54.bundle.tar.zst"_ctv;
  intent.targetContractSHA256="9148f79b5ea66f6ff3d17831ddc487498181549bc77b547c427a9e35f8fa35ac"_ctv;
  const uint128_t machines[]={
    (uint128_t(0x0bf4487bf41a4eccULL)<<64)|0x9f3e5e316ff23a88ULL,
    (uint128_t(0x88e88d94e0de497dULL)<<64)|0x9ef43113fd04909bULL,
    (uint128_t(0xcbba7c68cf034a26ULL)<<64)|0xb1062449e8572b8aULL};
  const char *linuxIDs[]={"081d00c431314065990ff533082074f7","cc8defd48fde42c8b304c77971e19a29","0ef2a43f92fd48b8a04e3dd8e4eaf80d"};
  for(uint32_t i=0;i<3;++i) {
    MothershipLocalAuthorityRecoveryExecutor e;e.machineUUID=machines[i];e.boundaryUUID=i+100;
    e.executorOperationUUID=i+200;e.immutableBoundarySHA256=digest('a');request.executors.push_back(e);
    MothershipLocalRecoveryRuntimeMember m;m.machineUUID=machines[i];m.linuxMachineID.assign(linuxIDs[i]);
    m.beforeBootID="00000000-0000-4000-8000-000000000001"_ctv;m.runtimeRoot="/root/prodigy"_ctv;
    m.gatewayInventory="sealed-existing-owner-inventory"_ctv;m.installRequired=i!=0;intent.members.push_back(m);
  }
  for(uint128_t pair:{uint128_t(1),uint128_t(2)})for(uint32_t i=0;i<3;++i) {
    CrossClusterMasqueGatewayAuthority g;g.pairUUID=pair;g.pairOperationUUID=pair+100;
    g.localClusterUUID=request.clusterUUID;g.peerClusterUUID=pair+1000;
    g.localMachineUUID=machines[i];g.peerMachineUUID=pair*100+i;
    g.localDatacenterFragment=1;g.peerDatacenterFragment=uint8_t(pair+1);
    g.localSitePrefix=prodigyContainerDatacenterSitePrefix(1);g.peerSitePrefix=prodigyContainerDatacenterSitePrefix(pair+1);
    g.artifactSHA256="a31d6be8fd338c5d9056822ca4eb42dc7f5cee9a2a60a08672847b016a92f631"_ctv;g.artifactBytes=4260945;
    g.listenerPublicUDPEndpoint.is6=true;g.listenerPublicUDPEndpoint.v6[0]=0x20;g.listenerPublicUDPPort=4433;
    g.localIdentitySHA256=g.peerIdentitySHA256=g.peerTrustSHA256=digest('e');
    g.generation=g.keyGeneration=g.pairAuthorityGeneration=1;g.gatewaySlot=i;g.tunnelSlot=i;
    assert(prodigyDeriveCrossClusterMasquePrivateBGPTuple(g));g.privateSessionCredentialSHA256=digest('e');
    assert(prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(g));intent.gateways.push_back(g);
  }
  String failure;bool resumed=false;
  auto objectSHA=[&](auto value){String bytes,hash;assert(BitseryEngine::serialize(bytes,value));assert(prodigyComputeSHA256Hex(bytes,hash));return hash;};
  MothershipUpgradeAdmissionRecord admission;
  admission.clusterUUID=request.clusterUUID;admission.operationID=intent.upgradeOperationUUID;
  admission.sourceBundleSHA256=mothershipLocalInterruptedUpgradeSourceBundle;
  admission.sourceProdigySHA256=mothershipLocalInterruptedUpgradeSourceRuntime;
  admission.sourceContractSHA256=digest('b');admission.sourceMothershipSHA256=digest('c');admission.sourceReleaseID="source53"_ctv;
  admission.targetBundleSHA256=mothershipLocalInterruptedUpgradeTargetBundle;admission.targetContractSHA256=intent.targetContractSHA256;
  admission.authorityGeneration=7;admission.masterUUID=machines[2];admission.masterBootNs=1;
  admission.semanticObservationSHA256=digest('d');admission.approvedPath=1;admission.observationReceiptVersion=1;
  admission.observationReportSHA256=digest('e');admission.plannerInputSHA256=digest('f');admission.eligible=true;
  MothershipLocalAuthorityRecoveryCohortRequest predecessor=request;
  predecessor.protocolVersion=1;predecessor.runtime={};predecessor.operationUUID=intent.predecessorRecoveryUUID;
  for(auto& e:predecessor.executors)e.executorOperationUUID+=100;
  MothershipLocalAuthorityRecoveryCohortRecord prior,record;
  String frozenRequest;
  {
    MothershipClusterRegistry registry(path);MothershipUpgradeAdmissionRecord stored;
    assert(registry.recordUpgradeAdmission(admission,stored,resumed,&failure));intent.admissionSHA256=objectSHA(stored);
    assert(registry.admitLocalAuthorityRecoveryCohort(predecessor,prior,resumed,&failure));
    intent.predecessorRecoverySHA256=objectSHA(prior);
    assert(!registry.admitLocalAuthorityRecoveryCohort(request,record,resumed,&failure)); // unresolved predecessor
    for(auto phase:{MothershipLocalAuthorityRecoveryPhase::armed,MothershipLocalAuthorityRecoveryPhase::released,
                    MothershipLocalAuthorityRecoveryPhase::recovered})
      for(const auto& e:predecessor.executors)
        assert(registry.advanceLocalAuthorityRecoveryCohort(predecessor.operationUUID,e.boundaryUUID,phase,digest('1'),prior,resumed,&failure));
    intent.predecessorRecoverySHA256=objectSHA(prior);
    assert(mothershipLocalAuthorityRecoveryCohortRequestValid(request,&failure));
    auto rejects=[&](auto mutation) {auto bad=request;mutation(bad);assert(!registry.admitLocalAuthorityRecoveryCohort(bad,record,resumed,&failure));};
    rejects([](auto& r){r.runtime.admissionSHA256=digest('0');});
    rejects([](auto& r){r.runtime.targetContractSHA256=digest('0');});
    rejects([](auto& r){r.executors[1].boundaryUUID+=1000;});
    rejects([](auto& r){r.runtime.members[1].linuxMachineID="ffffffffffffffffffffffffffffffff"_ctv;});
    rejects([](auto& r){r.runtime.members[0].installRequired=true;});
    rejects([](auto& r){r.runtime.gateways[1]=r.runtime.gateways[0];});
    rejects([](auto& r){r.runtime.gateways[0].artifactSHA256=digest('0');});
    assert(registry.admitLocalAuthorityRecoveryCohort(request,record,resumed,&failure) && !resumed);
    assert(registry.admitLocalAuthorityRecoveryCohort(request,record,resumed,&failure) && resumed);
    assert(BitseryEngine::serialize(frozenRequest,record.request));
    auto p=record.runtimeProgress[1];p.installDispatched=true;
    assert(!registry.checkpointLocalRecoveryRuntime(request.operationUUID,p,record,&failure)); // before arm
    for(const auto& e:request.executors)
      assert(registry.advanceLocalAuthorityRecoveryCohort(request.operationUUID,e.boundaryUUID,MothershipLocalAuthorityRecoveryPhase::armed,digest('2'),record,resumed,&failure));
    for(uint32_t i=1;i<3;++i) {
      p=record.runtimeProgress[i];p.installDispatched=true;
      assert(registry.checkpointLocalRecoveryRuntime(request.operationUUID,p,record,&failure));
      assert(!registry.advanceLocalAuthorityRecoveryCohort(request.operationUUID,p.boundaryUUID,MothershipLocalAuthorityRecoveryPhase::released,digest('3'),record,resumed,&failure));
      p.stateSHA256=digest('4');p.secretsSHA256=digest('5');
      assert(registry.checkpointLocalRecoveryRuntime(request.operationUUID,p,record,&failure));
      assert(registry.checkpointLocalRecoveryRuntime(request.operationUUID,p,record,&failure));
      auto changed=p;changed.stateSHA256=digest('6');
      assert(!registry.checkpointLocalRecoveryRuntime(request.operationUUID,changed,record,&failure));
    }
    for(const auto& e:request.executors)
      assert(registry.advanceLocalAuthorityRecoveryCohort(request.operationUUID,e.boundaryUUID,MothershipLocalAuthorityRecoveryPhase::released,digest('3'),record,resumed,&failure));
    assert(!registry.advanceLocalAuthorityRecoveryCohort(request.operationUUID,request.executors[0].boundaryUUID,
        MothershipLocalAuthorityRecoveryPhase::recovered,digest('7'),record,resumed,&failure)); // no activation boot
  }
  { // The registry can reopen after the seed reboot without changing any intent or snapshot binding.
    MothershipClusterRegistry registry(path);assert(registry.loadLocalAuthorityRecoveryCohort(request.operationUUID,record,&failure));
    String loaded;assert(BitseryEngine::serialize(loaded,record.request) && loaded==frozenRequest);
    assert(record.runtimeProgress[1].stateSHA256==digest('4') && record.runtimeProgress[2].secretsSHA256==digest('5'));
    for(uint32_t i=0;i<3;++i) {
      auto p=record.runtimeProgress[i];p.activationBootID=request.runtime.members[i].beforeBootID;
      assert(!registry.checkpointLocalRecoveryRuntime(request.operationUUID,p,record,&failure));
      p.activationBootID="00000000-0000-4000-8000-000000000002"_ctv;
      assert(registry.checkpointLocalRecoveryRuntime(request.operationUUID,p,record,&failure));
      auto changed=p;changed.activationBootID="00000000-0000-4000-8000-000000000003"_ctv;
      assert(!registry.checkpointLocalRecoveryRuntime(request.operationUUID,changed,record,&failure));
    }
    for(const auto& e:request.executors)
      assert(registry.advanceLocalAuthorityRecoveryCohort(request.operationUUID,e.boundaryUUID,MothershipLocalAuthorityRecoveryPhase::recovered,digest('7'),record,resumed,&failure));
    assert(registry.admitLocalAuthorityRecoveryCohort(request,record,resumed,&failure) && resumed);
    assert(record.phase==MothershipLocalAuthorityRecoveryPhase::recovered);
    MothershipLocalAuthorityRecoveryCohortRecord retained;
    assert(registry.loadLocalAuthorityRecoveryCohort(predecessor.operationUUID,retained,&failure));
    assert(objectSHA(retained)==intent.predecessorRecoverySHA256); // original completed record is immutable
  }
  {
    // A completed protocol-two cohort is durable history, not an admission for
    // the release-specific migration compiled into a later Mothership.  Its
    // structural proof must remain readable without authorizing a replay of
    // that historical request or poisoning a new protocol-three admission.
    auto historical=record;
    historical.request.operationUUID=0xc0ff;
    historical.request.runtime.upgradeOperationUUID=0xd001;
    historical.request.runtime.predecessorRecoveryUUID=0xd002;
    historical.request.runtime.targetContractSHA256=digest('8');
    assert(!mothershipLocalAuthorityRecoveryCohortRequestValid(historical.request,&failure));
    assert(mothershipLocalAuthorityRecoveryCohortRecordValid(historical,&failure));
    auto unfinished=historical;unfinished.request.operationUUID=0xc0fe;
    unfinished.phase=MothershipLocalAuthorityRecoveryPhase::armed;
    for(auto& boundary:unfinished.boundaries)boundary.phase=MothershipLocalAuthorityRecoveryPhase::armed;
    assert(!mothershipLocalAuthorityRecoveryCohortRecordValid(unfinished,&failure));
    String unfinishedPath;unfinishedPath.snprintf<"{}-unfinished-history"_ctv>(path);
    String unfinishedKey,unfinishedBytes;unfinishedKey.assignItoh(unfinished.request.operationUUID);
    assert(BitseryEngine::serialize(unfinishedBytes,unfinished));
    { TidesDB db(unfinishedPath,TidesDB::Durability::full);
      assert(db.write("local_authority_recovery_cohorts"_ctv,unfinishedKey,unfinishedBytes,&failure)); }
    { MothershipClusterRegistry registry(unfinishedPath);MothershipLocalAuthorityRecoveryCohortRecord loaded;
      assert(!registry.loadLocalAuthorityRecoveryCohort(unfinished.request.operationUUID,loaded,&failure)); }
    String key,bytes;key.assignItoh(historical.request.operationUUID);
    assert(BitseryEngine::serialize(bytes,historical));
    { TidesDB db(path,TidesDB::Durability::full);
      assert(db.write("local_authority_recovery_cohorts"_ctv,key,bytes,&failure)); }
    MothershipLocalAuthorityRecoveryCohortRecord loaded;
    MothershipClusterRegistry registry(path);
    assert(registry.loadLocalAuthorityRecoveryCohort(historical.request.operationUUID,loaded,&failure));
    assert(loaded.phase==MothershipLocalAuthorityRecoveryPhase::recovered);
  }
  ClusterStatusReport report={};report.hasTopology=true;report.topology.version=request.topologyVersion;
  report.nMachines=3;report.nApplications=0;
  for(const auto& m:intent.members) {
    ClusterMachine machine;machine.uuid=m.machineUUID;report.topology.machines.push_back(machine);
    MachineStatusReport status;status.machineUUID.assignItoh(m.machineUUID);status.isBrain=status.runtimeReady=status.controlPlaneReachable=true;
    status.state="healthy"_ctv;status.updateStage="idle"_ctv;status.currentMaster=!m.installRequired;
    status.runningProdigyVersion=m.installRequired ? String("53"_ctv) : String("54"_ctv);
    status.approvedBundleSHA256=m.installRequired ? String(mothershipLocalInterruptedUpgradeSourceBundle) : String(mothershipLocalInterruptedUpgradeTargetBundle);
    report.machineReports.push_back(status);
  }
  assert(mothershipLocalRecoveryRuntimeReportValid(request,report,false));
  assert(!mothershipLocalRecoveryRuntimeReportValid(request,report,true));
  auto bad=report;bad.nApplications=1;assert(!mothershipLocalRecoveryRuntimeReportValid(request,bad,false));
  bad=report;bad.machineReports[1].activeContainers=1;assert(!mothershipLocalRecoveryRuntimeReportValid(request,bad,false));
  bad=report;bad.machineReports[1].updateStage="updating"_ctv;assert(!mothershipLocalRecoveryRuntimeReportValid(request,bad,false));
  bad=report;bad.machineReports[0].approvedBundleSHA256=digest('0');assert(!mothershipLocalRecoveryRuntimeReportValid(request,bad,false));
  for(auto& status:report.machineReports){status.runningProdigyVersion="54"_ctv;status.approvedBundleSHA256=mothershipLocalInterruptedUpgradeTargetBundle;}
  assert(mothershipLocalRecoveryRuntimeReportValid(request,report,true));

  // The current active-workload recovery uses the same durable owner, but its
  // identities come from the admitted upgrade rather than historical literals.
  auto active=request;
  active.protocolVersion=MothershipLocalAuthorityRecoveryCohortRequest::admittedRuntimeUpgradeVersion;
  active.operationUUID=0xc102;active.runtime.predecessorRecoveryUUID=0;
  active.runtime.predecessorRecoverySHA256.clear();
  for(auto& member:active.runtime.members)member.installRequired=true;
  auto& identity=active.admittedRuntime;
  identity.sourceBundleSHA256=admission.sourceBundleSHA256;
  identity.sourceContractSHA256=admission.sourceContractSHA256;
  identity.sourceReleaseID=admission.sourceReleaseID;
  identity.sourceProdigySHA256=admission.sourceProdigySHA256;
  identity.sourceMothershipSHA256=admission.sourceMothershipSHA256;
  identity.sourceBinaryVersion="53"_ctv;
  identity.targetBundleSHA256=admission.targetBundleSHA256;
  identity.targetReleaseID="target54"_ctv;
  identity.targetProdigySHA256=mothershipLocalInterruptedUpgradeTargetRuntime;
  identity.targetMothershipSHA256=digest('9');identity.targetBinaryVersion="54"_ctv;
  identity.authorityGeneration=admission.authorityGeneration;identity.masterUUID=admission.masterUUID;
  identity.masterBootNs=admission.masterBootNs;
  identity.semanticObservationSHA256=admission.semanticObservationSHA256;
  for(uint16_t application=2;application<5;++application) {
    MothershipLocalRecoveryWorkloadIdentity workload;workload.applicationID=application;
    workload.deploymentID=(uint64_t(application)<<48)|uint64_t(application);
    workload.stateful=true;workload.shardGroups=3;workload.target=3;workload.targetBase=3;
    identity.workloads.push_back(workload);
  }
  identity.activeDeploymentCount=identity.workloads.size();
  assert(mothershipLocalAuthorityRecoveryCohortRequestValid(active,&failure));
  {
    DeploymentStatusReport deployment={};deployment.versionID=2026102708;
    deployment.isStateful=true;deployment.nShardGroups=3;
    deployment.nTarget=9;deployment.nTargetBase=9;
    MothershipLocalRecoveryWorkloadIdentity observed;
    assert(mothershipLocalRecoveryWorkloadIdentityFromReport(4,deployment,observed));
    assert(observed.applicationID==4 && observed.deploymentID==((uint64_t(4)<<48)|2026102708));
    // Retained deployments are intentionally dormant while their healthy
    // containers remain materialized. Preserve that exact zero-target intent.
    deployment.nTarget=0;deployment.nTargetBase=0;
    assert(mothershipLocalRecoveryWorkloadIdentityFromReport(4,deployment,observed));
    assert(observed.target==0 && observed.targetBase==0 && observed.targetSurge==0);
    deployment.nTargetSurge=1;
    assert(!mothershipLocalRecoveryWorkloadIdentityFromReport(4,deployment,observed));
    deployment.nTargetSurge=0;
    deployment.versionID=uint64_t(1)<<48;
    assert(!mothershipLocalRecoveryWorkloadIdentityFromReport(4,deployment,observed));
  }
  MothershipLocalAuthorityRecoveryCohortRecord activeRecord;
  {
    MothershipClusterRegistry registry(path);
    assert(registry.admitLocalAuthorityRecoveryCohort(active,activeRecord,resumed,&failure) && !resumed);
    assert(registry.admitLocalAuthorityRecoveryCohort(active,activeRecord,resumed,&failure) && resumed);
    auto changed=active;changed.admittedRuntime.sourceBundleSHA256=digest('0');
    assert(!registry.admitLocalAuthorityRecoveryCohort(changed,activeRecord,resumed,&failure));
    changed=active;changed.runtime.members[1].beforeBootID="00000000-0000-4000-8000-000000000009"_ctv;
    assert(!registry.admitLocalAuthorityRecoveryCohort(changed,activeRecord,resumed,&failure));
  }
  ClusterStatusReport activeReport={};activeReport.hasTopology=true;
  activeReport.topology.version=active.topologyVersion;activeReport.nMachines=3;activeReport.nApplications=3;
  for(const auto& member:active.runtime.members) {
    ClusterMachine machine;machine.uuid=member.machineUUID;machine.isBrain=true;
    machine.kind=MachineConfig::MachineKind::vm;machine.backing=ClusterMachineBacking::owned;
    machine.lifetime=MachineLifetime::owned;activeReport.topology.machines.push_back(machine);
    MachineStatusReport status;status.machineUUID.assignItoh(member.machineUUID);
    status.isBrain=status.runtimeReady=status.controlPlaneReachable=true;status.state="healthy"_ctv;
    status.updateStage="idle"_ctv;status.currentMaster=member.machineUUID==identity.masterUUID;
    status.runningProdigyVersion=identity.sourceBinaryVersion;
    status.approvedBundleSHA256=identity.sourceBundleSHA256;activeReport.machineReports.push_back(status);
  }
  for(const auto& workload:identity.workloads) {
    ApplicationStatusReport application;application.applicationID=workload.applicationID;
    DeploymentStatusReport deployment;deployment.versionID=workload.deploymentID&((uint64_t(1)<<48)-1);
    deployment.isStateful=workload.stateful;deployment.nShardGroups=workload.shardGroups;
    deployment.nTarget=workload.target;deployment.nTargetBase=workload.targetBase;
    deployment.nTargetSurge=workload.targetSurge;application.deploymentReports.push_back(deployment);
    activeReport.applicationReports.push_back(std::move(application));
  }
  assert(mothershipLocalRecoveryRuntimeReportValid(active,activeReport,false));
  bad=activeReport;bad.applicationReports[1].deploymentReports[0].nTarget=4;
  assert(!mothershipLocalRecoveryRuntimeReportValid(active,bad,false));
  bad=activeReport;bad.machineReports[0].approvedBundleSHA256=digest('0');
  assert(!mothershipLocalRecoveryRuntimeReportValid(active,bad,false));
  for(auto& status:activeReport.machineReports) {
    status.runningProdigyVersion=identity.targetBinaryVersion;
    status.approvedBundleSHA256=identity.targetBundleSHA256;
  }
  assert(mothershipLocalRecoveryRuntimeReportValid(active,activeReport,true));

  // A released protocol-three cohort remains immutable history. A completed
  // protocol-four successor may discharge it for later admissions only when
  // the durable predecessor hash and every runtime boundary remain exact.
  const String activeBoots[]={"00000000-0000-4000-8000-000000000011"_ctv,
                              "00000000-0000-4000-8000-000000000012"_ctv,
                              "00000000-0000-4000-8000-000000000013"_ctv};
  {
    MothershipClusterRegistry registry(path);
    for(const auto& executor:active.executors)
      assert(registry.advanceLocalAuthorityRecoveryCohort(active.operationUUID,executor.boundaryUUID,
          MothershipLocalAuthorityRecoveryPhase::armed,digest('a'),activeRecord,resumed,&failure));
    for(uint32_t index=0;index<3;++index) {
      auto progress=activeRecord.runtimeProgress[index];progress.installDispatched=true;
      progress.stateSHA256=digest('b');progress.secretsSHA256=digest('c');
      assert(registry.checkpointLocalRecoveryRuntime(active.operationUUID,progress,activeRecord,&failure));
    }
    for(const auto& executor:active.executors)
      assert(registry.advanceLocalAuthorityRecoveryCohort(active.operationUUID,executor.boundaryUUID,
          MothershipLocalAuthorityRecoveryPhase::released,digest('d'),activeRecord,resumed,&failure));
    for(uint32_t index=0;index<3;++index) {
      auto progress=activeRecord.runtimeProgress[index];progress.activationBootID=activeBoots[index];
      assert(registry.checkpointLocalRecoveryRuntime(active.operationUUID,progress,activeRecord,&failure));
    }
    assert(activeRecord.phase==MothershipLocalAuthorityRecoveryPhase::released);
  }
  const String releasedActiveSHA=objectSHA(activeRecord);

  auto superseding=active;
  superseding.protocolVersion=
      MothershipLocalAuthorityRecoveryCohortRequest::admittedRuntimeSupersedingUpgradeVersion;
  superseding.operationUUID=0xc103;superseding.runtime.upgradeOperationUUID=0xe103;
  superseding.runtime.predecessorRecoveryUUID=active.operationUUID;
  superseding.runtime.predecessorRecoverySHA256=releasedActiveSHA;
  superseding.runtime.targetContractSHA256=digest('4');
  for(uint32_t index=0;index<3;++index)
    superseding.runtime.members[index].beforeBootID=activeBoots[index];
  auto& supersedingIdentity=superseding.admittedRuntime;
  supersedingIdentity.sourceBundleSHA256=identity.targetBundleSHA256;
  supersedingIdentity.sourceContractSHA256=active.runtime.targetContractSHA256;
  supersedingIdentity.sourceReleaseID=identity.targetReleaseID;
  supersedingIdentity.sourceProdigySHA256=identity.targetProdigySHA256;
  supersedingIdentity.sourceMothershipSHA256=identity.targetMothershipSHA256;
  supersedingIdentity.sourceBinaryVersion=identity.targetBinaryVersion;
  supersedingIdentity.targetBundleSHA256=digest('5');
  supersedingIdentity.targetReleaseID="target55"_ctv;
  supersedingIdentity.targetProdigySHA256=digest('6');
  supersedingIdentity.targetMothershipSHA256=digest('7');
  supersedingIdentity.targetBinaryVersion="55"_ctv;
  MothershipUpgradeAdmissionRecord supersedingAdmission=admission;
  supersedingAdmission.operationID=superseding.runtime.upgradeOperationUUID;
  supersedingAdmission.sourceBundleSHA256=supersedingIdentity.sourceBundleSHA256;
  supersedingAdmission.sourceContractSHA256=supersedingIdentity.sourceContractSHA256;
  supersedingAdmission.sourceReleaseID=supersedingIdentity.sourceReleaseID;
  supersedingAdmission.sourceProdigySHA256=supersedingIdentity.sourceProdigySHA256;
  supersedingAdmission.sourceMothershipSHA256=supersedingIdentity.sourceMothershipSHA256;
  supersedingAdmission.targetBundleSHA256=supersedingIdentity.targetBundleSHA256;
  supersedingAdmission.targetContractSHA256=superseding.runtime.targetContractSHA256;
  supersedingAdmission.eligible=false;
  supersedingAdmission.approvedPath=0;
  supersedingAdmission.firstStopGate=
      "generation-fenced peer upgrade observation is incomplete"_ctv;
  MothershipLocalAuthorityRecoveryCohortRecord supersedingRecord;
  {
    MothershipClusterRegistry registry(path);MothershipUpgradeAdmissionRecord stored;
    assert(registry.recordUpgradeAdmission(supersedingAdmission,stored,resumed,&failure));
    superseding.runtime.admissionSHA256=objectSHA(stored);
    assert(mothershipLocalAuthorityRecoveryCohortRequestValid(superseding,&failure));
    assert(mothershipLocalReleasedRuntimeRecoveryCanBeSuperseded(
        activeRecord,releasedActiveSHA,superseding,&failure));

    auto rejects=[&](auto mutation) {auto changed=superseding;mutation(changed);
      assert(!mothershipLocalReleasedRuntimeRecoveryCanBeSuperseded(
          activeRecord,releasedActiveSHA,changed,&failure));};
    rejects([](auto& value){value.runtime.predecessorRecoverySHA256=digest('0');});
    rejects([](auto& value){value.admittedRuntime.sourceBundleSHA256=digest('0');});
    rejects([](auto& value){++value.admittedRuntime.workloads[0].target;
                            ++value.admittedRuntime.workloads[0].targetBase;});
    rejects([](auto& value){value.runtime.gateways[0].artifactSHA256=digest('0');});
    rejects([](auto& value){value.executors[0].immutableBoundarySHA256=digest('0');});

    auto missing=superseding;missing.runtime.predecessorRecoverySHA256=digest('0');
    assert(mothershipLocalAuthorityRecoveryCohortRequestValid(missing,&failure));
    assert(!registry.admitLocalAuthorityRecoveryCohort(missing,supersedingRecord,resumed,&failure));
    assert(registry.admitLocalAuthorityRecoveryCohort(superseding,supersedingRecord,resumed,&failure) && !resumed);
    assert(registry.admitLocalAuthorityRecoveryCohort(superseding,supersedingRecord,resumed,&failure) && resumed);
  }

  const String supersedingBoots[]={"00000000-0000-4000-8000-000000000021"_ctv,
                                    "00000000-0000-4000-8000-000000000022"_ctv,
                                    "00000000-0000-4000-8000-000000000023"_ctv};
  {
    MothershipClusterRegistry registry(path);
    for(const auto& executor:superseding.executors)
      assert(registry.advanceLocalAuthorityRecoveryCohort(superseding.operationUUID,executor.boundaryUUID,
          MothershipLocalAuthorityRecoveryPhase::armed,digest('8'),supersedingRecord,resumed,&failure));
    for(uint32_t index=0;index<3;++index) {
      auto progress=supersedingRecord.runtimeProgress[index];progress.installDispatched=true;
      progress.stateSHA256=digest('9');progress.secretsSHA256=digest('a');
      assert(registry.checkpointLocalRecoveryRuntime(superseding.operationUUID,progress,supersedingRecord,&failure));
    }
    for(const auto& executor:superseding.executors)
      assert(registry.advanceLocalAuthorityRecoveryCohort(superseding.operationUUID,executor.boundaryUUID,
          MothershipLocalAuthorityRecoveryPhase::released,digest('b'),supersedingRecord,resumed,&failure));
    for(uint32_t index=0;index<3;++index) {
      auto progress=supersedingRecord.runtimeProgress[index];
      progress.activationBootID=supersedingBoots[index];
      assert(registry.checkpointLocalRecoveryRuntime(
          superseding.operationUUID,progress,supersedingRecord,&failure));
    }
    for(const auto& executor:superseding.executors)
      assert(registry.advanceLocalAuthorityRecoveryCohort(superseding.operationUUID,executor.boundaryUUID,
          MothershipLocalAuthorityRecoveryPhase::recovered,digest('c'),supersedingRecord,resumed,&failure));
    assert(supersedingRecord.phase==MothershipLocalAuthorityRecoveryPhase::recovered);
    MothershipLocalAuthorityRecoveryCohortRecord loaded;
    assert(registry.loadLocalAuthorityRecoveryCohort(superseding.operationUUID,loaded,&failure));
    assert(mothershipLocalAuthorityRecoveryCohortRecordValid(loaded,&failure));
  }

  auto future=superseding;
  future.protocolVersion=MothershipLocalAuthorityRecoveryCohortRequest::admittedRuntimeUpgradeVersion;
  future.operationUUID=0xc104;future.runtime.upgradeOperationUUID=0xe104;
  future.runtime.predecessorRecoveryUUID=0;future.runtime.predecessorRecoverySHA256.clear();
  future.runtime.targetContractSHA256=digest('d');
  for(uint32_t index=0;index<3;++index)
    future.runtime.members[index].beforeBootID=supersedingBoots[index];
  auto& futureIdentity=future.admittedRuntime;
  futureIdentity.sourceBundleSHA256=supersedingIdentity.targetBundleSHA256;
  futureIdentity.sourceContractSHA256=superseding.runtime.targetContractSHA256;
  futureIdentity.sourceReleaseID=supersedingIdentity.targetReleaseID;
  futureIdentity.sourceProdigySHA256=supersedingIdentity.targetProdigySHA256;
  futureIdentity.sourceMothershipSHA256=supersedingIdentity.targetMothershipSHA256;
  futureIdentity.sourceBinaryVersion=supersedingIdentity.targetBinaryVersion;
  futureIdentity.targetBundleSHA256=digest('e');futureIdentity.targetReleaseID="target56"_ctv;
  futureIdentity.targetProdigySHA256=digest('f');futureIdentity.targetMothershipSHA256=digest('1');
  futureIdentity.targetBinaryVersion="56"_ctv;
  MothershipUpgradeAdmissionRecord futureAdmission=supersedingAdmission;
  futureAdmission.operationID=future.runtime.upgradeOperationUUID;
  futureAdmission.sourceBundleSHA256=futureIdentity.sourceBundleSHA256;
  futureAdmission.sourceContractSHA256=futureIdentity.sourceContractSHA256;
  futureAdmission.sourceReleaseID=futureIdentity.sourceReleaseID;
  futureAdmission.sourceProdigySHA256=futureIdentity.sourceProdigySHA256;
  futureAdmission.sourceMothershipSHA256=futureIdentity.sourceMothershipSHA256;
  futureAdmission.targetBundleSHA256=futureIdentity.targetBundleSHA256;
  futureAdmission.targetContractSHA256=future.runtime.targetContractSHA256;
  {
    MothershipClusterRegistry registry(path);MothershipUpgradeAdmissionRecord stored;
    assert(registry.recordUpgradeAdmission(futureAdmission,stored,resumed,&failure));
    future.runtime.admissionSHA256=objectSHA(stored);
    assert(mothershipLocalAuthorityRecoveryCohortRequestValid(future,&failure));
    MothershipLocalAuthorityRecoveryCohortRecord futureRecord;
    assert(registry.admitLocalAuthorityRecoveryCohort(future,futureRecord,resumed,&failure) && !resumed);
  }
}

static void unreadyUpgradeReportRegressions()
{
  const uint128_t targetMachine = 0x101;
  MothershipProdigyCluster cluster = {};
  cluster.clusterUUID = 0x201;
  for (uint128_t machineUUID : {targetMachine, uint128_t(0x102), uint128_t(0x103)})
  {
    ClusterMachine machine = {};
    machine.uuid = machineUUID;
    machine.isBrain = true;
    cluster.topology.machines.push_back(machine);
  }

  MothershipUpgradeAdmissionRecord admission = {};
  admission.clusterUUID = cluster.clusterUUID;
  admission.operationID = 0x301;
  admission.sourceBundleSHA256 = digest('a');
  admission.targetBundleSHA256 = digest('b');
  admission.targetContractSHA256 = digest('c');
  admission.authorityGeneration = 41;
  admission.masterUUID = 0x103;
  admission.masterBootNs = 71;
  // Deliberately unrelated to the post-reboot report: deployment must obtain a
  // fresh normal admission rather than reusing this pre-reboot semantic digest.
  admission.semanticObservationSHA256 = digest('d');

  MothershipUpgradeAdmissionReport complete = {};
  complete.clusterUUID = cluster.clusterUUID;
  complete.observationReceiptVersion = 12;
  complete.authorityGeneration = admission.authorityGeneration;
  complete.masterUUID = admission.masterUUID;
  complete.masterBootNs = admission.masterBootNs;
  complete.master = true;
  complete.authorityQuorumHealthy = true;
  complete.authorityAcknowledged = true;
  complete.recoveryWitnessAcknowledged = true;
  complete.currentUpdaterSupportsSerialFollowers = true;
  complete.fleetBundleDigestsFresh = true;
  complete.fleetInventoriesFresh = true;
  complete.observationComplete = true;
  complete.commissionedBrainCount = 3;
  complete.healthyCommissionedBrainCount = 3;
  complete.commissionedPeerTransportVerified = true;
  complete.operationID.assignItoh(admission.operationID);
  complete.targetBundleSHA256 = admission.targetBundleSHA256;
  complete.targetContractSHA256 = admission.targetContractSHA256;
  complete.requiredStagingBytes = 1'048'576;
  complete.stagingCapacityResponsesComplete = true;
  complete.stagingCapacityComplete = true;
  complete.masterApprovedBundleSHA256 = admission.sourceBundleSHA256;
  for (const auto& machine : cluster.topology.machines)
  {
    ProdigyUpgradeAdmissionPeerObservation peer = {};
    const bool masterSelf = machine.uuid == admission.masterUUID;
    peer.brainUUID = peer.machineUUID = machine.uuid;
    peer.receiptVersion = complete.observationReceiptVersion;
    peer.authorityGeneration = admission.authorityGeneration;
    peer.requesterTransportGeneration = masterSelf ? 0 : (machine.uuid == targetMachine ? 99 : 7);
    peer.masterUUID = masterSelf ? 0 : admission.masterUUID;
    peer.masterBootNs = masterSelf ? 0 : admission.masterBootNs;
    peer.codeSupportsSerialFollowers = true;
    peer.localInstalledBundleVerified = true;
    peer.stateUploadFresh = true;
    peer.authorityAcknowledged = true;
    peer.recoveryWitnessAcknowledged = true;
    peer.operationID = complete.operationID;
    peer.targetBundleSHA256 = complete.targetBundleSHA256;
    peer.targetContractSHA256 = complete.targetContractSHA256;
    peer.requiredStagingBytes = complete.requiredStagingBytes;
    peer.stagingAvailableBytes = complete.requiredStagingBytes * 2;
    peer.stagingCapacityProbeComplete = true;
    peer.stagingCapacityVerified = true;
    peer.installedBundleSHA256 = admission.sourceBundleSHA256;
    complete.peers.push_back(std::move(peer));
  }

  String failure = {};
  assert(mothershipLocalVMUnreadyUpgradeReportValid(
      complete, admission, cluster, targetMachine, true, 11, &failure));

  auto invalid = complete;
  invalid.observationComplete = false;
  assert(!mothershipLocalVMUnreadyUpgradeReportValid(
      invalid, admission, cluster, targetMachine, true, 11, &failure));
  assert(failure == "unready local VM recovery authority proof field=observation-complete"_ctv);
  invalid = complete; invalid.fleetInventoriesFresh = false;
  assert(!mothershipLocalVMUnreadyUpgradeReportValid(
      invalid, admission, cluster, targetMachine, true, 11, &failure));
  invalid = complete; invalid.fleetBundleDigestsFresh = false;
  assert(!mothershipLocalVMUnreadyUpgradeReportValid(
      invalid, admission, cluster, targetMachine, true, 11, &failure));
  invalid = complete; ++invalid.authorityGeneration;
  assert(!mothershipLocalVMUnreadyUpgradeReportValid(
      invalid, admission, cluster, targetMachine, true, 11, &failure));
  invalid = complete; invalid.masterApprovedBundleSHA256 = digest('0');
  assert(!mothershipLocalVMUnreadyUpgradeReportValid(
      invalid, admission, cluster, targetMachine, true, 11, &failure));
  invalid = complete; invalid.peers[2].masterUUID = admission.masterUUID;
  assert(!mothershipLocalVMUnreadyUpgradeReportValid(
      invalid, admission, cluster, targetMachine, true, 11, &failure));
  invalid = complete; invalid.peers[2].requesterTransportGeneration = 1;
  assert(!mothershipLocalVMUnreadyUpgradeReportValid(
      invalid, admission, cluster, targetMachine, true, 11, &failure));
  invalid = complete; invalid.peers[0].masterUUID = 0;
  assert(!mothershipLocalVMUnreadyUpgradeReportValid(
      invalid, admission, cluster, targetMachine, true, 11, &failure));
  invalid = complete; ++invalid.peers[0].masterBootNs;
  assert(!mothershipLocalVMUnreadyUpgradeReportValid(
      invalid, admission, cluster, targetMachine, true, 11, &failure));
  invalid = complete; invalid.peers[1].installedBundleSHA256 = digest('0');
  assert(!mothershipLocalVMUnreadyUpgradeReportValid(
      invalid, admission, cluster, targetMachine, true, 11, &failure));
  invalid = complete; invalid.peers[1].targetBundleSHA256 = digest('0');
  assert(!mothershipLocalVMUnreadyUpgradeReportValid(
      invalid, admission, cluster, targetMachine, true, 11, &failure));
  invalid = complete; invalid.peers[2].machineUUID = 0x999;
  assert(!mothershipLocalVMUnreadyUpgradeReportValid(
      invalid, admission, cluster, targetMachine, true, 11, &failure));
  invalid = complete; --invalid.peers[1].requiredStagingBytes;
  assert(!mothershipLocalVMUnreadyUpgradeReportValid(
      invalid, admission, cluster, targetMachine, true, 11, &failure));

  auto incomplete = complete;
  incomplete.observationComplete = false;
  incomplete.fleetBundleDigestsFresh = false;
  incomplete.fleetInventoriesFresh = false;
  incomplete.healthyCommissionedBrainCount = 2;
  incomplete.peers[0].stateUploadFresh = false;
  assert(mothershipLocalVMUnreadyUpgradeReportValid(
      incomplete, admission, cluster, targetMachine, false, 0, &failure));
  assert(mothershipLocalVMUnreadyUpgradePreRecoveryReportValid(
      incomplete, admission, cluster, targetMachine, &failure));
  assert(mothershipLocalVMUnreadyUpgradePreRecoveryReportValid(
      complete, admission, cluster, targetMachine, &failure));
  auto hybrid = complete;
  hybrid.fleetInventoriesFresh = false;
  assert(!mothershipLocalVMUnreadyUpgradePreRecoveryReportValid(
      hybrid, admission, cluster, targetMachine, &failure));
  hybrid = incomplete;
  hybrid.healthyCommissionedBrainCount = 3;
  assert(!mothershipLocalVMUnreadyUpgradePreRecoveryReportValid(
      hybrid, admission, cluster, targetMachine, &failure));
  incomplete.peers[1].stateUploadFresh = false;
  incomplete.healthyCommissionedBrainCount = 1;
  assert(!mothershipLocalVMUnreadyUpgradeReportValid(
      incomplete, admission, cluster, targetMachine, false, 0, &failure));
}

int main()
{
  char directoryTemplate[] = "/tmp/prodigy-g6-registry-XXXXXX";
  char *directory = ::mkdtemp(directoryTemplate);
  assert(directory != nullptr);
  struct ScopedDirectory {
    std::filesystem::path path;
    ~ScopedDirectory() { std::filesystem::remove_all(path); }
  } cleanup {directory};

  String path(directory), failure = {};
  unreadyUpgradeReportRegressions();
  MothershipProductionPairIntent intent = {};
  intent.operationUUID = 0x401; intent.route = makeRoute();
  intent.sourcePermission = makePermission(intent.route, true);
  intent.destinationPermission = makePermission(intent.route, false);
  intent.sourceRouteReceipt = makeRouteReceipt(intent.route, CousinRouteHalf::source);
  intent.destinationRouteReceipt = makeRouteReceipt(intent.route, CousinRouteHalf::destination);
  intent.sourceWorkload.clusterUUID = intent.route.sourceClusterUUID;
  intent.sourceWorkload.applicationID = 31;
  intent.sourceWorkload.deploymentID = (uint64_t(31) << 48) | 11;
  intent.sourceWorkload.canonicalPlanSHA256 = digest('e');
  intent.sourceWorkload.artifactSHA256 = digest('f'); intent.sourceWorkload.artifactBytes = 4096;
  intent.sourceWorkload.replicas = 1; intent.sourceWorkload.endpointMachineUUID = 0x601;
  intent.sourceWorkload.endpointIPv4 = "192.0.2.1"_ctv; intent.sourceWorkload.endpointTCPPort = 8080;
  intent.targetWorkload.clusterUUID = intent.route.destinationClusterUUID;
  intent.targetWorkload.applicationID = 31;
  intent.targetWorkload.deploymentID = (uint64_t(31) << 48) | 12;
  intent.targetWorkload.canonicalPlanSHA256 = intent.sourceWorkload.canonicalPlanSHA256;
  intent.targetWorkload.artifactSHA256 = digest('f'); intent.targetWorkload.artifactBytes = 4096;
  intent.targetWorkload.replicas = 1; intent.targetWorkload.endpointMachineUUID = 0x602;
  intent.targetWorkload.endpointIPv4 = "198.51.100.2"_ctv; intent.targetWorkload.endpointTCPPort = 8080;
  intent.physicalBoundaryUUID = 0x501;
  intent.selectorMachineUUID = 0x603;
  intent.selectorExecutorKind = MothershipPhysicalFaultExecutorKind::localVM;
  intent.selectorLocalVMBoundaryUUID = 0x801;
  intent.selectorAddress = "192.0.2.3"_ctv;
  intent.selectorTCPPort = 18080;
  intent.ingressWitnessMachineUUID = 0x601;
  intent.ingressWitnessExecutorKind = MothershipPhysicalFaultExecutorKind::localVM;
  intent.ingressWitnessLocalVMBoundaryUUID = 0x803;
  assert(intent.selectorMachineUUID != intent.sourceWorkload.endpointMachineUUID);

  {
    MothershipClusterRegistry registry(path);
    CousinRouteRecord storedRoute = {}; CousinRouteApplyReceipt storedReceipt = {};
    bool resumed = false;

    MothershipLocalMembershipCleanupRecord cleanupIntent = {};
    cleanupIntent.clusterUUID = 0xa01;
    cleanupIntent.desiredSpecSHA256 = digest('a');
    MothershipLocalMembershipCleanupMachine cleanupMachine = {};
    cleanupMachine.machine.source = MothershipClusterMachineSource::adopted;
    cleanupMachine.machine.backing = ClusterMachineBacking::owned;
    cleanupMachine.machine.kind = MachineConfig::MachineKind::vm;
    cleanupMachine.machine.lifetime = MachineLifetime::owned;
    cleanupMachine.machine.isBrain = true;
    cleanupMachine.machine.ssh.address = "10.66.6.2"_ctv;
    cleanupMachine.machine.ssh.user = "root"_ctv;
    cleanupMachine.machine.ssh.port = 22;
    cleanupMachine.machine.uuid = 0xa02;
    cleanupMachine.machine.rackUUID = 17;
    cleanupIntent.machines.push_back(cleanupMachine);
    cleanupMachine.machine.ssh.address = "10.66.6.3"_ctv;
    cleanupMachine.machine.uuid = 0xa03;
    cleanupMachine.machine.rackUUID = 19;
    cleanupIntent.machines.push_back(cleanupMachine);
    MothershipLocalMembershipCleanupRecord storedCleanup = {};
    assert(registry.admitLocalMembershipCleanup(
        cleanupIntent, storedCleanup, resumed, &failure) && !resumed);
    assert(storedCleanup.machines.size() == 2 &&
           storedCleanup.machines[0].machine.uuid == 0xa02 &&
           storedCleanup.machines[0].machine.rackUUID == 17 &&
           storedCleanup.machines[1].machine.uuid == 0xa03 &&
           storedCleanup.machines[1].machine.rackUUID == 19);
    assert(registry.admitLocalMembershipCleanup(
        cleanupIntent, storedCleanup, resumed, &failure) && resumed);
    auto conflictingCleanup = cleanupIntent;
    conflictingCleanup.desiredSpecSHA256 = digest('b');
    assert(!registry.admitLocalMembershipCleanup(
        conflictingCleanup, storedCleanup, resumed, &failure));
    conflictingCleanup = cleanupIntent;
    conflictingCleanup.machines[1].machine.uuid++;
    assert(!registry.admitLocalMembershipCleanup(
        conflictingCleanup, storedCleanup, resumed, &failure));
    assert(registry.commitLocalMembershipCleanup(
        cleanupIntent.clusterUUID, cleanupIntent.desiredSpecSHA256,
        storedCleanup, resumed, &failure) && !resumed);
    assert(registry.commitLocalMembershipCleanup(
        cleanupIntent.clusterUUID, cleanupIntent.desiredSpecSHA256,
        storedCleanup, resumed, &failure) && resumed);
    assert(!registry.clearCompletedLocalMembershipCleanup(
        cleanupIntent.clusterUUID, cleanupIntent.desiredSpecSHA256, &failure));
    assert(registry.completeLocalMembershipCleanupMachine(
        cleanupIntent.clusterUUID, cleanupIntent.desiredSpecSHA256, 0,
        storedCleanup, resumed, &failure) && !resumed);
    assert(storedCleanup.machines[0].cleaned && !storedCleanup.machines[1].cleaned);
    assert(registry.completeLocalMembershipCleanupMachine(
        cleanupIntent.clusterUUID, cleanupIntent.desiredSpecSHA256, 0,
        storedCleanup, resumed, &failure) && resumed);
    assert(!registry.clearCompletedLocalMembershipCleanup(
        cleanupIntent.clusterUUID, cleanupIntent.desiredSpecSHA256, &failure));
    assert(registry.completeLocalMembershipCleanupMachine(
        cleanupIntent.clusterUUID, cleanupIntent.desiredSpecSHA256, 1,
        storedCleanup, resumed, &failure) && !resumed);
    assert(registry.clearCompletedLocalMembershipCleanup(
        cleanupIntent.clusterUUID, cleanupIntent.desiredSpecSHA256, &failure));
    assert(!registry.loadLocalMembershipCleanup(
        cleanupIntent.clusterUUID, storedCleanup, &failure) &&
        failure.equal("record not found"_ctv));

    assert(registry.recordCousinRoute(intent.route, storedRoute, resumed, &failure) && !resumed);
    assert(registry.recordCousinRouteApplyReceipt(intent.sourceRouteReceipt, storedReceipt, resumed, &failure));
    assert(registry.recordCousinRouteApplyReceipt(intent.destinationRouteReceipt, storedReceipt, resumed, &failure));

    MothershipProductionPairRecord pair = {};
    assert(registry.admitProductionPair(intent, 1000, pair, resumed, &failure) && !resumed);
    assert(registry.admitProductionPair(intent, 1001, pair, resumed, &failure) && resumed);
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::targetAdmitted,
                                          digest('1'), 1001, pair, resumed, &failure) && !resumed);
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::targetAdmitted,
                                          digest('1'), 1001, pair, resumed, &failure) && resumed);
    assert(!registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::targetAdmitted,
                                           digest('2'), 1001, pair, resumed, &failure));

    MothershipLocalVMBoundaryDescriptor localBoundary = {};
    localBoundary.vmBoundaryUUID = 0x801; localBoundary.clusterUUID = intent.route.sourceClusterUUID;
    localBoundary.machineUUID = intent.selectorMachineUUID; localBoundary.taskID = "g6-local-1"_ctv;
    localBoundary.hostAddress = "192.0.2.10"_ctv;
    localBoundary.hostUser = "root"_ctv; localBoundary.hostPrivateKeyPath = "/tmp/g6-key"_ctv;
    localBoundary.hostPublicKeyOpenSSH = "ssh-ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA g6"_ctv;
    localBoundary.statePath = "/var/tmp/prodigy-g6/machine-1.json"_ctv;
    localBoundary.executorSHA256 = digest('7'); localBoundary.immutableStateSHA256 = digest('8');
    localBoundary.registeredAtMs = 1003;
    assert(mothershipPhysicalFaultProviderStateRootValid(
        "/var/lib/prodigy/mothership-physical-faults"_ctv));
    assert(!mothershipPhysicalFaultProviderStateRootValid("/tmp/physical-faults"_ctv));
    MothershipLocalVMBoundaryDescriptor targetLocal = localBoundary;
    targetLocal.vmBoundaryUUID = 0x802; targetLocal.clusterUUID = intent.route.destinationClusterUUID;
    targetLocal.machineUUID = intent.targetWorkload.endpointMachineUUID;
    targetLocal.taskID = "g6-local-2"_ctv; targetLocal.statePath = "/var/tmp/prodigy-g6/machine-2.json"_ctv;
    MothershipLocalVMBoundaryDescriptor storedLocal = {};
    assert(registry.registerLocalVMBoundary(localBoundary, storedLocal, resumed, &failure) && !resumed);
    assert(registry.registerLocalVMBoundary(targetLocal, storedLocal, resumed, &failure) && !resumed);
    auto refreshedLocal = localBoundary;
    refreshedLocal.executorSHA256 = digest('6');
    const auto rejectsBoundaryRefreshDrift = [&](auto mutate) {
      auto drifted = refreshedLocal;
      mutate(drifted);
      assert(!registry.refreshLocalVMBoundaryExecutor(localBoundary, drifted, storedLocal, resumed, &failure));
    };
    rejectsBoundaryRefreshDrift([](auto& value) { value.vmBoundaryUUID++; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.clusterUUID++; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.machineUUID++; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.taskID = "g6-other-task"_ctv; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.hostAddress = "192.0.2.11"_ctv; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.hostPort++; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.hostUser = "admin"_ctv; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.hostPrivateKeyPath = "/tmp/g6-other-key"_ctv; });
    rejectsBoundaryRefreshDrift([](auto& value) {
      value.hostPublicKeyOpenSSH = "ssh-ed25519 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB g6"_ctv;
    });
    rejectsBoundaryRefreshDrift([](auto& value) { value.statePath = "/var/tmp/prodigy-g6/other.json"_ctv; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.immutableStateSHA256 = digest('0'); });
    rejectsBoundaryRefreshDrift([](auto& value) { value.registeredAtMs++; });
    rejectsBoundaryRefreshDrift([](auto& value) { value.retired = true; });
    auto staleExpectedLocal = localBoundary;
    staleExpectedLocal.executorSHA256 = digest('5');
    assert(!registry.refreshLocalVMBoundaryExecutor(staleExpectedLocal, refreshedLocal,
                                                   storedLocal, resumed, &failure));
    assert(registry.refreshLocalVMBoundaryExecutor(localBoundary, refreshedLocal,
                                                   storedLocal, resumed, &failure) && !resumed);
    assert(storedLocal.executorSHA256 == digest('6'));
    assert(registry.refreshLocalVMBoundaryExecutor(localBoundary, refreshedLocal,
                                                   storedLocal, resumed, &failure) && resumed);
    localBoundary = refreshedLocal;

    Vector<uint128_t> expectedBoundaryMachines = {0x601, 0x602, 0x603};
    Vector<MothershipLocalVMBoundaryDescriptor> inspectedBoundaries = {localBoundary};
    assert(!MothershipClusterRegistry::activeLocalVMBoundariesExactForMachines(
        localBoundary.clusterUUID, expectedBoundaryMachines, inspectedBoundaries, &failure));
    auto secondBoundary = localBoundary;
    secondBoundary.vmBoundaryUUID = 0x804; secondBoundary.machineUUID = 0x602;
    auto thirdBoundary = localBoundary;
    thirdBoundary.vmBoundaryUUID = 0x805; thirdBoundary.machineUUID = 0x601;
    inspectedBoundaries.push_back(secondBoundary); inspectedBoundaries.push_back(thirdBoundary);
    assert(MothershipClusterRegistry::activeLocalVMBoundariesExactForMachines(
        localBoundary.clusterUUID, expectedBoundaryMachines, inspectedBoundaries, &failure));
    auto duplicateBoundary = secondBoundary;
    duplicateBoundary.vmBoundaryUUID = 0x806;
    inspectedBoundaries.push_back(duplicateBoundary);
    assert(!MothershipClusterRegistry::activeLocalVMBoundariesExactForMachines(
        localBoundary.clusterUUID, expectedBoundaryMachines, inspectedBoundaries, &failure));
    inspectedBoundaries.pop_back();
    auto injectedNewlineKey = localBoundary;
    String unsafePublicKey = {};
    unsafePublicKey.append("ssh-ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA g6"_ctv);
    unsafePublicKey.append('\n');
    assert(unsafePublicKey[unsafePublicKey.size() - 1] == '\n');
    injectedNewlineKey.hostPublicKeyOpenSSH = std::move(unsafePublicKey);
    assert(!registry.registerLocalVMBoundary(injectedNewlineKey, storedLocal, resumed, &failure));

    MothershipPhysicalServiceTransitBoundary boundary = {};
    boundary.boundaryUUID = 0x501; boundary.pairOperationUUID = intent.operationUUID;
    boundary.routeUUID = intent.route.routeUUID; boundary.routeGeneration = intent.route.generation;
    boundary.sourceClusterUUID = intent.route.sourceClusterUUID;
    boundary.targetClusterUUID = intent.route.destinationClusterUUID;
    boundary.sourceMachineUUID = intent.selectorMachineUUID; boundary.targetMachineUUID = 0x602;
    boundary.sourceExecutorKind = MothershipPhysicalFaultExecutorKind::localVM;
    boundary.targetExecutorKind = MothershipPhysicalFaultExecutorKind::localVM;
    boundary.sourceLocalVMBoundaryUUID = localBoundary.vmBoundaryUUID;
    boundary.targetLocalVMBoundaryUUID = targetLocal.vmBoundaryUUID;
    boundary.sourceAddress = intent.selectorAddress;
    boundary.targetAddress = intent.targetWorkload.endpointIPv4;
    boundary.sourceTCPPort = intent.selectorTCPPort;
    boundary.targetTCPPort = intent.targetWorkload.endpointTCPPort; boundary.pathMTU = intent.route.pathMTU;
    assert(cousinRouteAuthorizationDigest(intent.route, boundary.routeAuthorizationSHA256));
    boundary.admissionReceiptSHA256 = digest('2'); boundary.admittedAtMs = 1002;
    MothershipPhysicalServiceTransitBoundary storedBoundary = {};
    assert(registry.admitPhysicalServiceTransitBoundary(boundary, storedBoundary, resumed, &failure) && !resumed);
    assert(registry.admitPhysicalServiceTransitBoundary(boundary, storedBoundary, resumed, &failure) && resumed);
    auto changedSourcePort = boundary; changedSourcePort.sourceTCPPort++;
    assert(!registry.admitPhysicalServiceTransitBoundary(changedSourcePort, storedBoundary, resumed, &failure));
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::transitApplied,
                                          boundary.admissionReceiptSHA256, 1002, pair, resumed, &failure));

    MothershipPhysicalClusterNetworkFaultRequest network = {};
    network.operationUUID = 0x701; network.boundaryUUID = boundary.boundaryUUID;
    network.sourceClusterUUID = boundary.sourceClusterUUID; network.targetClusterUUID = boundary.targetClusterUUID;
    network.sourceMachineUUID = boundary.sourceMachineUUID; network.targetMachineUUID = boundary.targetMachineUUID;
    network.direction = MothershipPhysicalFaultDirection::sourceToTarget; network.durationMilliseconds = 1000;
    network.routeUUID = boundary.routeUUID; network.routeGeneration = boundary.routeGeneration;
    network.routeAuthorizationSHA256 = boundary.routeAuthorizationSHA256;
    network.sourceAddress = boundary.sourceAddress; network.targetAddress = boundary.targetAddress;
    network.sourceTopologyVersion = 7; network.targetTopologyVersion = 8;
    MothershipPhysicalClusterNetworkFaultRecord networkRecord = {};
    const auto sourceAdmission = observation(network.sourceClusterUUID, network.sourceMachineUUID, 7, 'e');
    const auto targetAdmission = observation(network.targetClusterUUID, network.targetMachineUUID, 8, 'f');
    assert(registry.admitPhysicalClusterNetworkFault(network, sourceAdmission, targetAdmission,
                                                     networkRecord, resumed, &failure) && !resumed);
    assert(networkRecord.sourceAdmission.stateSHA256 == sourceAdmission.stateSHA256);
    assert(networkRecord.targetAdmission.stateSHA256 == targetAdmission.stateSHA256);
    assert(registry.admitPhysicalClusterNetworkFault(network, sourceAdmission, targetAdmission,
                                                     networkRecord, resumed, &failure) && resumed);
    auto staleSourceAdmission = sourceAdmission; staleSourceAdmission.stateSHA256 = digest('0');
    assert(!registry.admitPhysicalClusterNetworkFault(network, staleSourceAdmission, targetAdmission,
                                                      networkRecord, resumed, &failure));
    auto retargeted = network; retargeted.targetMachineUUID++;
    assert(!registry.admitPhysicalClusterNetworkFault(retargeted, sourceAdmission, targetAdmission,
                                                      networkRecord, resumed, &failure));
    auto reassigned = network; reassigned.targetAddress = "2001:db8::2"_ctv;
    assert(!registry.admitPhysicalClusterNetworkFault(reassigned, sourceAdmission, targetAdmission,
                                                      networkRecord, resumed, &failure));
    MothershipPhysicalClusterNetworkFaultReceipt networkReceipt = {};
    networkReceipt.operationUUID = network.operationUUID; networkReceipt.boundaryUUID = network.boundaryUUID;
    networkReceipt.admission = network;
    networkReceipt.sourceBefore = sourceAdmission;
    networkReceipt.targetBefore = targetAdmission;
    networkReceipt.sourceAfter = networkReceipt.sourceBefore; networkReceipt.targetAfter = networkReceipt.targetBefore;
    networkReceipt.sourceInstalledAtMonotonicMilliseconds = 100;
    networkReceipt.sourceRestoredAtMonotonicMilliseconds = 1100;
    networkReceipt.sourceRestored = true; networkReceipt.restored = true;
    auto mismatchedNetworkReceipt = networkReceipt;
    mismatchedNetworkReceipt.sourceBefore.stateSHA256 = digest('a');
    mismatchedNetworkReceipt.sourceAfter = mismatchedNetworkReceipt.sourceBefore;
    assert(!registry.recordPhysicalClusterNetworkFaultReceipt(network, mismatchedNetworkReceipt,
                                                               networkRecord, resumed, &failure));
    assert(registry.recordPhysicalClusterNetworkFaultReceipt(network, networkReceipt, networkRecord, resumed, &failure) && !resumed);
    assert(registry.recordPhysicalClusterNetworkFaultReceipt(network, networkReceipt, networkRecord, resumed, &failure) && resumed);

    auto bidirectional = network; bidirectional.operationUUID++;
    bidirectional.direction = MothershipPhysicalFaultDirection::both;
    MothershipPhysicalClusterNetworkFaultReceipt bidirectionalReceipt = networkReceipt;
    bidirectionalReceipt.operationUUID = bidirectional.operationUUID;
    bidirectionalReceipt.admission = bidirectional;
    assert(!mothershipPhysicalClusterNetworkFaultReceiptValid(bidirectional, bidirectionalReceipt, &failure));
    bidirectionalReceipt.targetInstalledAtMonotonicMilliseconds = 200;
    bidirectionalReceipt.targetRestoredAtMonotonicMilliseconds = 1200;
    bidirectionalReceipt.targetRestored = true;
    assert(mothershipPhysicalClusterNetworkFaultReceiptValid(bidirectional, bidirectionalReceipt, &failure));

    assert(registry.registerLocalVMBoundary(localBoundary, storedLocal, resumed, &failure) && resumed);
    MothershipLocalVMBoundaryDescriptor foundLocal = {};
    assert(registry.findActiveLocalVMBoundary(localBoundary.clusterUUID, localBoundary.machineUUID,
                                              foundLocal, &failure));
    assert(foundLocal.vmBoundaryUUID == localBoundary.vmBoundaryUUID);
    auto duplicateMachine = localBoundary; duplicateMachine.vmBoundaryUUID++;
    assert(!registry.registerLocalVMBoundary(duplicateMachine, storedLocal, resumed, &failure));

    MothershipLocalVMMachineFaultRequest local = {};
    local.operationUUID = 0x901; local.vmBoundaryUUID = localBoundary.vmBoundaryUUID;
    local.clusterUUID = localBoundary.clusterUUID; local.machineUUID = localBoundary.machineUUID;
    local.action = MothershipLocalVMMachineFaultAction::coldReboot;
    local.durationMilliseconds = 1000; local.expectedBootSHA256 = digest('9');
    MothershipLocalVMMachineFaultRecord localRecord = {};
    const auto localAdmission = observation(local.clusterUUID, local.machineUUID, 9, '9');
    assert(registry.admitLocalVMMachineFault(local, localAdmission, localRecord, resumed, &failure) && !resumed);
    assert(localRecord.admission.stateSHA256 == local.expectedBootSHA256);
    assert(registry.admitLocalVMMachineFault(local, localAdmission, localRecord, resumed, &failure) && resumed);
    auto staleLocalAdmission = localAdmission; staleLocalAdmission.topologyVersion++;
    assert(!registry.admitLocalVMMachineFault(local, staleLocalAdmission, localRecord, resumed, &failure));
    MothershipLocalVMMachineFaultReceipt localReceipt = {};
    localReceipt.operationUUID = local.operationUUID; localReceipt.vmBoundaryUUID = local.vmBoundaryUUID;
    localReceipt.before = observation(local.clusterUUID, local.machineUUID, 9, '9');
    localReceipt.after = observation(local.clusterUUID, local.machineUUID, 10, '0');
    localReceipt.restoredBootSHA256 = digest('0'); localReceipt.faultedAtMonotonicMilliseconds = 1000;
    localReceipt.restoredAtMonotonicMilliseconds = 2000; localReceipt.restored = true;
    auto mismatchedLocalReceipt = localReceipt;
    mismatchedLocalReceipt.before.topologyVersion++;
    assert(!registry.recordLocalVMMachineFaultReceipt(local, mismatchedLocalReceipt,
                                                       localRecord, resumed, &failure));
    assert(registry.recordLocalVMMachineFaultReceipt(local, localReceipt, localRecord, resumed, &failure) && !resumed);
    assert(registry.recordLocalVMMachineFaultReceipt(local, localReceipt, localRecord, resumed, &failure) && resumed);

    MothershipLocalVMMachineFaultRequest unready = {};
    unready.protocolVersion = MothershipLocalVMMachineFaultRequest::unreadyUpgradeRecoveryVersion;
    unready.operationUUID = 0x902; unready.vmBoundaryUUID = localBoundary.vmBoundaryUUID;
    unready.clusterUUID = localBoundary.clusterUUID; unready.machineUUID = localBoundary.machineUUID;
    unready.action = MothershipLocalVMMachineFaultAction::recoverUnreadyUpgrade;
    unready.durationMilliseconds = 1000; unready.expectedBootSHA256 = digest('a');
    unready.upgradeOperationUUID = 0x903; unready.targetBundleSHA256 = digest('b');
    unready.targetContractSHA256 = digest('c'); unready.upgradeAdmissionSHA256 = digest('d');
    unready.expectedBoundarySHA256 = localBoundary.immutableStateSHA256;
    for (uint32_t index = 0; index != 32; ++index) unready.expectedLinuxMachineID.append('e');
    unready.expectedLinuxBootID = "12345678-1234-4abc-8def-123456789abc"_ctv;
    unready.expectedQemuPID = 42; unready.expectedQemuStarttime = "700"_ctv;
    unready.incompleteObservationReceiptVersion = 7;
    auto unreadyAdmission = observation(unready.clusterUUID, unready.machineUUID, 11, 'a');
    assert(registry.admitLocalVMMachineFault(unready, unreadyAdmission,
                                             localRecord, resumed, &failure) && !resumed);
    assert(registry.admitLocalVMMachineFault(unready, unreadyAdmission,
                                             localRecord, resumed, &failure) && resumed);
    auto substitutedBoundary = unready; substitutedBoundary.expectedBoundarySHA256 = digest('f');
    assert(!registry.admitLocalVMMachineFault(substitutedBoundary, unreadyAdmission,
                                              localRecord, resumed, &failure));
    MothershipLocalVMMachineFaultReceipt unreadyReceipt = {};
    unreadyReceipt.protocolVersion = MothershipLocalVMMachineFaultReceipt::unreadyUpgradeRecoveryVersion;
    unreadyReceipt.operationUUID = unready.operationUUID;
    unreadyReceipt.vmBoundaryUUID = unready.vmBoundaryUUID;
    unreadyReceipt.before = unreadyAdmission;
    unreadyReceipt.after = observation(unready.clusterUUID, unready.machineUUID, 12, 'b');
    unreadyReceipt.restoredBootSHA256 = digest('b');
    unreadyReceipt.faultedAtMonotonicMilliseconds = 1000;
    unreadyReceipt.restoredAtMonotonicMilliseconds = 2000; unreadyReceipt.restored = true;
    unreadyReceipt.beforeLinuxMachineID = unready.expectedLinuxMachineID;
    unreadyReceipt.beforeLinuxBootID = unready.expectedLinuxBootID;
    unreadyReceipt.beforeQemuPID = unready.expectedQemuPID;
    unreadyReceipt.beforeQemuStarttime = unready.expectedQemuStarttime;
    unreadyReceipt.afterLinuxMachineID = unready.expectedLinuxMachineID;
    unreadyReceipt.afterLinuxBootID = "abcdef12-3456-4abc-8def-123456789abc"_ctv;
    unreadyReceipt.afterQemuPID = 43; unreadyReceipt.afterQemuStarttime = "800"_ctv;
    unreadyReceipt.completedObservationReceiptVersion = 8;
    unreadyReceipt.completedUpgradeReportSHA256 = digest('e');
    assert(registry.recordLocalVMMachineFaultReceipt(unready, unreadyReceipt,
                                                      localRecord, resumed, &failure) && !resumed);
    assert(registry.recordLocalVMMachineFaultReceipt(unready, unreadyReceipt,
                                                      localRecord, resumed, &failure) && resumed);

    MothershipLocalAuthorityRecoveryCohortRequest cohort = {};
    cohort.operationUUID = 0xb01; cohort.clusterUUID = localBoundary.clusterUUID;
    cohort.topologyVersion = 17;
    cohort.timeoutMilliseconds = mothershipLocalAuthorityRecoveryMinimumTimeoutMilliseconds;
    for (uint128_t machine : {uint128_t(0xb11), uint128_t(0xb12), uint128_t(0xb13)})
    {
      MothershipLocalAuthorityRecoveryExecutor executor = {};
      executor.machineUUID = machine; executor.boundaryUUID = machine + 0x100;
      executor.executorOperationUUID = machine + 0x200; executor.immutableBoundarySHA256 = digest('a');
      cohort.executors.push_back(std::move(executor));
    }
    MothershipLocalAuthorityRecoveryCohortRecord cohortRecord = {};
    assert(registry.admitLocalAuthorityRecoveryCohort(cohort, cohortRecord, resumed, &failure) && !resumed);
    assert(registry.admitLocalAuthorityRecoveryCohort(cohort, cohortRecord, resumed, &failure) && resumed);
    auto conflictingCohort = cohort; conflictingCohort.timeoutMilliseconds++;
    assert(!registry.admitLocalAuthorityRecoveryCohort(conflictingCohort, cohortRecord, resumed, &failure));
    assert(registry.advanceLocalAuthorityRecoveryCohort(
        cohort.operationUUID, cohort.executors[0].boundaryUUID, MothershipLocalAuthorityRecoveryPhase::armed,
        digest('b'), cohortRecord, resumed, &failure) && !resumed);
    assert(!registry.advanceLocalAuthorityRecoveryCohort(
        cohort.operationUUID, cohort.executors[0].boundaryUUID, MothershipLocalAuthorityRecoveryPhase::released,
        digest('c'), cohortRecord, resumed, &failure));
    for (uint32_t index = 1; index < cohort.executors.size(); ++index)
    {
      const auto& executor = cohort.executors[index];
      assert(registry.advanceLocalAuthorityRecoveryCohort(
          cohort.operationUUID, executor.boundaryUUID, MothershipLocalAuthorityRecoveryPhase::armed,
          digest('b'), cohortRecord, resumed, &failure) && !resumed);
    }
    assert(cohortRecord.phase == MothershipLocalAuthorityRecoveryPhase::armed);
    assert(registry.advanceLocalAuthorityRecoveryCohort(
        cohort.operationUUID, cohort.executors[0].boundaryUUID, MothershipLocalAuthorityRecoveryPhase::armed,
        digest('b'), cohortRecord, resumed, &failure) && resumed);
    assert(!registry.advanceLocalAuthorityRecoveryCohort(
        cohort.operationUUID, cohort.executors[0].boundaryUUID, MothershipLocalAuthorityRecoveryPhase::recovered,
        digest('c'), cohortRecord, resumed, &failure));
    for (const auto& executor : cohort.executors)
      assert(registry.advanceLocalAuthorityRecoveryCohort(
          cohort.operationUUID, executor.boundaryUUID, MothershipLocalAuthorityRecoveryPhase::released,
          digest('c'), cohortRecord, resumed, &failure) && !resumed);
    for (const auto& executor : cohort.executors)
      assert(registry.advanceLocalAuthorityRecoveryCohort(
          cohort.operationUUID, executor.boundaryUUID, MothershipLocalAuthorityRecoveryPhase::recovered,
          digest('d'), cohortRecord, resumed, &failure) && !resumed);
    assert(cohortRecord.phase == MothershipLocalAuthorityRecoveryPhase::recovered);
    assert(registry.advanceLocalAuthorityRecoveryCohort(
        cohort.operationUUID, cohort.executors[0].boundaryUUID, MothershipLocalAuthorityRecoveryPhase::recovered,
        digest('d'), cohortRecord, resumed, &failure) && resumed);
    assert(!registry.advanceLocalAuthorityRecoveryCohort(
        cohort.operationUUID, cohort.executors[0].boundaryUUID, MothershipLocalAuthorityRecoveryPhase::recovered,
        digest('e'), cohortRecord, resumed, &failure));

    MothershipPhysicalServiceTransitBoundary closed = {};
    assert(!registry.closePhysicalServiceTransitBoundary(boundary.boundaryUUID, digest('8'), closed, resumed, &failure));
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::sourceIngressWitnessed,
                                          digest('3'), 1003, pair, resumed, &failure));
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::targetSelected,
                                          digest('4'), 1004, pair, resumed, &failure));
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::targetIngressWitnessed,
                                          digest('5'), 1005, pair, resumed, &failure));
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::sourceDrained,
                                          digest('6'), 1006, pair, resumed, &failure));
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::sourceRetired,
                                          digest('7'), 1007, pair, resumed, &failure));
    assert(registry.advanceProductionPair(intent.operationUUID, MothershipProductionPairPhase::cleanupComplete,
                                          digest('8'), 1008, pair, resumed, &failure));
    assert(registry.closePhysicalServiceTransitBoundary(boundary.boundaryUUID, digest('8'), closed, resumed, &failure) && !resumed);
    assert(closed.admissionReceiptSHA256 == digest('2') && closed.cleanupReceiptSHA256 == digest('8'));
    assert(registry.closePhysicalServiceTransitBoundary(boundary.boundaryUUID, digest('8'), closed, resumed, &failure) && resumed);
    assert(!registry.closePhysicalServiceTransitBoundary(boundary.boundaryUUID, digest('9'), closed, resumed, &failure));

    MothershipProductionPairIntent abortedIntent = intent;
    abortedIntent.operationUUID = 0x402; abortedIntent.physicalBoundaryUUID = 0x502;
    assert(registry.admitProductionPair(abortedIntent, 1010, pair, resumed, &failure) && !resumed);
    assert(registry.advanceProductionPair(abortedIntent.operationUUID, MothershipProductionPairPhase::targetAdmitted,
                                          digest('a'), 1011, pair, resumed, &failure));
    MothershipPhysicalServiceTransitBoundary abortBoundary = boundary;
    abortBoundary.boundaryUUID = abortedIntent.physicalBoundaryUUID;
    abortBoundary.pairOperationUUID = abortedIntent.operationUUID;
    abortBoundary.admissionReceiptSHA256 = digest('b'); abortBoundary.cleanupReceiptSHA256.clear(); abortBoundary.closed = false;
    assert(registry.admitPhysicalServiceTransitBoundary(abortBoundary, storedBoundary, resumed, &failure) && !resumed);
    const String abortReceipt = digest('c');
    assert(registry.closePhysicalServiceTransitBoundaryBeforeTransit(abortBoundary.boundaryUUID, abortReceipt,
                                                                      closed, resumed, &failure) && !resumed);
    assert(registry.abortProductionPairBeforeTransit(abortedIntent.operationUUID, abortReceipt, 1012,
                                                     pair, resumed, &failure) && !resumed);
    assert(pair.phase == MothershipProductionPairPhase::abortedBeforeTransit);
    assert(registry.abortProductionPairBeforeTransit(abortedIntent.operationUUID, abortReceipt, 1012,
                                                     pair, resumed, &failure) && resumed);
    assert(registry.closePhysicalServiceTransitBoundaryBeforeTransit(abortBoundary.boundaryUUID, abortReceipt,
                                                                      closed, resumed, &failure) && resumed);
    assert(!registry.abortProductionPairBeforeTransit(abortedIntent.operationUUID, digest('d'), 1012,
                                                      pair, resumed, &failure));

    MothershipProductionPairIntent preCutoverIntent = intent;
    preCutoverIntent.operationUUID = 0x404; preCutoverIntent.physicalBoundaryUUID = 0x504;
    assert(registry.admitProductionPair(preCutoverIntent, 1013, pair, resumed, &failure) && !resumed);
    assert(registry.advanceProductionPair(preCutoverIntent.operationUUID, MothershipProductionPairPhase::targetAdmitted,
                                          digest('a'), 1014, pair, resumed, &failure));
    MothershipPhysicalServiceTransitBoundary preCutoverBoundary = boundary;
    preCutoverBoundary.boundaryUUID = preCutoverIntent.physicalBoundaryUUID;
    preCutoverBoundary.pairOperationUUID = preCutoverIntent.operationUUID;
    preCutoverBoundary.admissionReceiptSHA256 = digest('b');
    preCutoverBoundary.cleanupReceiptSHA256.clear(); preCutoverBoundary.closed = false;
    assert(registry.admitPhysicalServiceTransitBoundary(preCutoverBoundary, storedBoundary, resumed, &failure) && !resumed);
    assert(registry.advanceProductionPair(preCutoverIntent.operationUUID, MothershipProductionPairPhase::transitApplied,
                                          digest('c'), 1015, pair, resumed, &failure));
    const String preCutoverPendingReceipt = digest('d');
    const String preCutoverAbortReceipt = digest('e');
    assert(registry.prepareProductionPairAbortBeforeCutover(preCutoverIntent.operationUUID, preCutoverPendingReceipt,
                                                            1016, pair, resumed, &failure) && !resumed);
    assert(pair.phase == MothershipProductionPairPhase::abortBeforeCutoverPending &&
           pair.cleanupReceiptSHA256 == preCutoverPendingReceipt);
    // Simulate a crash after the provider has removed the selector but before
    // the terminal pair write.  The durable pending record is the retry input.
    assert(registry.loadProductionPair(preCutoverIntent.operationUUID, pair, &failure) &&
           pair.phase == MothershipProductionPairPhase::abortBeforeCutoverPending &&
           pair.cleanupReceiptSHA256 == preCutoverPendingReceipt);
    assert(registry.prepareProductionPairAbortBeforeCutover(preCutoverIntent.operationUUID, preCutoverPendingReceipt,
                                                            1016, pair, resumed, &failure) && resumed);
    assert(!registry.prepareProductionPairAbortBeforeCutover(preCutoverIntent.operationUUID, digest('f'), 1016,
                                                             pair, resumed, &failure));
    assert(!registry.closePhysicalServiceTransitBoundary(preCutoverBoundary.boundaryUUID, preCutoverAbortReceipt,
                                                         closed, resumed, &failure));
    assert(registry.abortProductionPairBeforeCutover(preCutoverIntent.operationUUID, preCutoverAbortReceipt, 1016,
                                                     pair, resumed, &failure) && !resumed);
    assert(pair.phase == MothershipProductionPairPhase::abortedBeforeCutover);
    assert(registry.abortProductionPairBeforeCutover(preCutoverIntent.operationUUID, preCutoverAbortReceipt, 1016,
                                                     pair, resumed, &failure) && resumed);
    assert(!registry.abortProductionPairBeforeCutover(preCutoverIntent.operationUUID, digest('f'), 1016,
                                                      pair, resumed, &failure));
    assert(registry.closePhysicalServiceTransitBoundary(preCutoverBoundary.boundaryUUID, preCutoverAbortReceipt,
                                                        closed, resumed, &failure) && !resumed);
    assert(registry.closePhysicalServiceTransitBoundary(preCutoverBoundary.boundaryUUID, preCutoverAbortReceipt,
                                                        closed, resumed, &failure) && resumed);
    assert(!registry.closePhysicalServiceTransitBoundary(preCutoverBoundary.boundaryUUID, digest('f'),
                                                         closed, resumed, &failure));
    MothershipProductionPairIntent nextIntent = abortedIntent;
    nextIntent.operationUUID = 0x403; nextIntent.physicalBoundaryUUID = 0x503;
    assert(registry.admitProductionPair(nextIntent, 1017, pair, resumed, &failure) && !resumed);
  }

  {
    MothershipClusterRegistry reopened(path);
    MothershipApplicationPlacement placement;
    bool placementResumed = false;
    for (uint16_t applicationID : {uint16_t(2), uint16_t(5), uint16_t(10)}) {
      assert(reopened.admitApplicationPlacement(applicationID, 0x201, digest('a'), placement, placementResumed, &failure) && !placementResumed);
      assert(placement.ownerClusterUUID == 0x201 && placement.generation == 1);
      assert(placement.policy == (applicationID == 10 ? MothershipApplicationPlacement::Policy::hardSingleton : MothershipApplicationPlacement::Policy::retainedSource));
      assert(reopened.admitApplicationPlacement(applicationID, 0x201, digest('b'), placement, placementResumed, &failure) && placementResumed);
      assert(!reopened.admitApplicationPlacement(applicationID, 0x202, digest('c'), placement, placementResumed, &failure));
      assert(!reopened.admitApplicationPlacement(applicationID, 0x203, digest('d'), placement, placementResumed, &failure));
      DeploymentPlan pairedStateless;
      pairedStateless.config.applicationID = applicationID;
      pairedStateless.config.type = ApplicationType::stateless; pairedStateless.isStateful = false;
      assert(mothershipApplicationPlacementRequired(pairedStateless.config.applicationID));
      assert(!reopened.admitApplicationPlacement(pairedStateless, 0x202, digest('e'), placement, placementResumed, &failure));
      assert(reopened.admitApplicationPlacement(pairedStateless, 0x201, digest('e'), placement, placementResumed, &failure) == (applicationID == 10));
      assert(reopened.loadApplicationPlacement(applicationID, placement, &failure) && placement.ownerClusterUUID == 0x201);
    }
    MothershipProductionPairRecord pair = {}; MothershipPhysicalServiceTransitBoundary boundary = {};
    MothershipLocalVMBoundaryDescriptor localBoundary = {};
    assert(reopened.loadProductionPair(intent.operationUUID, pair, &failure) &&
           pair.phase == MothershipProductionPairPhase::cleanupComplete);
    assert(reopened.loadPhysicalServiceTransitBoundary(0x501, boundary, &failure) && boundary.closed &&
           boundary.admissionReceiptSHA256 == digest('2') && boundary.cleanupReceiptSHA256 == digest('8'));
    assert(reopened.loadProductionPair(0x404, pair, &failure) &&
           pair.phase == MothershipProductionPairPhase::abortedBeforeCutover &&
           pair.cleanupReceiptSHA256 == digest('e'));
    assert(reopened.loadPhysicalServiceTransitBoundary(0x504, boundary, &failure) && boundary.closed &&
           boundary.cleanupReceiptSHA256 == digest('e'));
    assert(reopened.loadLocalVMBoundary(0x801, localBoundary, &failure) && !localBoundary.retired &&
           localBoundary.executorSHA256 == digest('6'));
    MothershipLocalAuthorityRecoveryCohortRecord cohort = {};
    assert(reopened.loadLocalAuthorityRecoveryCohort(0xb01, cohort, &failure) &&
           cohort.phase == MothershipLocalAuthorityRecoveryPhase::recovered);
  }

  { // A new registry object/fresh deploy identity does not release source ownership.
    MothershipClusterRegistry reopened(path); MothershipApplicationPlacement placement; bool resumed = false;
    assert(reopened.loadTruthPlacement(placement, &failure) && placement.ownerClusterUUID == 0x201);
    assert(!reopened.admitTruthPlacement(0x202, digest('f'), placement, resumed, &failure));
  }
  graphMembershipRegressions(path);
  graphAllMastersPlacementRegressions(path);
  String truthPath; truthPath.snprintf<"{}/truth-retirement"_ctv>(path);
  truthRetirementRegressions(truthPath);
  String adoptedTruthPath; adoptedTruthPath.snprintf<"{}/truth-adopted-retirement"_ctv>(path);
  truthRetirementRegressions(adoptedTruthPath, true);
  String testTruthPath; testTruthPath.snprintf<"{}/truth-test-retirement"_ctv>(path);
  testTruthRetirementRegressions(testTruthPath);
  String localUpgradePath;localUpgradePath.snprintf<"{}/local-interrupted-upgrade"_ctv>(path);
  interruptedLocalUpgradeRegressions(localUpgradePath);
  std::puts("PASS: G6 registry persists exact production-pair, transit, fault and retained-placement owners");
  return 0;
}
