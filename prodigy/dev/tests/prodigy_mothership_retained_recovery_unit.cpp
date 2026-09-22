#include <cassert>
#include <cstdio>

#include <prodigy/mothership/mothership.retained.recovery.h>
#include <prodigy/mothership/mothership.retained.recovery.command.h>
#include <prodigy/mothership/mothership.tidesdb.migration.h>

static void assertRetainedBootstrapUnorderedMapRoundTrip(void)
{
  NeuronContainerBootstrap bootstrap = {};
  for (uint64_t index = 0; index < 16; ++index)
  {
    const uint64_t subscriptionService = 1000 + index;
    const uint64_t advertisementService = 2000 + index;
    bootstrap.plan.subscriptions[subscriptionService] = Subscription(
        subscriptionService, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::any);
    bootstrap.plan.advertisements[advertisementService] = Advertisement(
        advertisementService, ContainerState::scheduled, ContainerState::destroying, uint16_t(3000 + index));

    SubscriptionPairing subscriptionPairing = {};
    subscriptionPairing.secret = 10 + index;
    subscriptionPairing.address = 20 + index;
    subscriptionPairing.service = subscriptionService;
    subscriptionPairing.port = uint16_t(4000 + index);
    bootstrap.plan.subscriptionPairings.insert(subscriptionService, subscriptionPairing);

    AdvertisementPairing advertisementPairing = {};
    advertisementPairing.secret = 30 + index;
    advertisementPairing.address = 40 + index;
    advertisementPairing.service = advertisementService;
    bootstrap.plan.advertisementPairings.insert(advertisementService, advertisementPairing);
  }

  String serialized = {};
  BitseryEngine::serialize(serialized, bootstrap);
  NeuronContainerBootstrap roundTrip = {};
  assert(BitseryEngine::deserializeSafe(serialized, roundTrip));
  assert(prodigyPersistentRetainedBootstrapEqual(bootstrap, roundTrip));

  auto changed = roundTrip.plan.advertisements.find(2000);
  assert(changed != roundTrip.plan.advertisements.end());
  changed->second.port += 1;
  assert(!prodigyPersistentRetainedBootstrapEqual(bootstrap, roundTrip));
}

int main()
{
  // Recovery must reject malformed input before it opens or mutates a private
  // state copy.  This is the boundary used by the command owner before fence.
  ProdigyPersistentBrainSnapshot snapshot = {};
  bytell_hash_map<uint64_t, DeploymentPlan> plans = {};
  Vector<MothershipRetainedRecoveryMachineInput> machines = {};
  String failure = {};
  assert(!mothershipPrepareRetainedRecoverySnapshot(snapshot, plans, machines,
                                                    "not-a-digest"_ctv, &failure));
  assert(failure.size() > 0);

  String quiesce = {};
  mothershipBuildTidesDBMigrationServiceQuiesceCommand(quiesce);
  assert(strstr(quiesce.c_str(), "retained containers require a recovery checkpoint") != nullptr);

  using namespace MothershipRetainedRecovery;
  assertRetainedBootstrapUnorderedMapRoundTrip();
  Request request;request.clusterUUID=1;request.bundleSHA.assign("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv);
  String bytes;BitseryEngine::serialize(bytes,request);Request decoded;
  assert(BitseryEngine::deserializeSafe(bytes,decoded) && decoded.clusterUUID==1 && decoded.bundleSHA==request.bundleSHA);
  Manifest sealedManifest = {}; Manifest successor = {};
  Record record = {}; record.machine=1; record.container=2; record.pid=3; record.created=4; record.start="5"; record.executableSHA=std::string(64,'a'); record.paramsSHA=std::string(64,'b'); record.paramsPath="/root/params"; record.canonical=true;
  sealedManifest.records.push_back(record); successor.records.push_back(record);
  assert(sameRecordIdentity(sealedManifest,successor));
  successor.records[0].pid++;
  assert(!sameRecordIdentity(sealedManifest,successor));
  MothershipTidesMigration::Plan predecessorPlan = {}, successorPlan = {};
  predecessorPlan.operationID=1; successorPlan.operationID=2; predecessorPlan.operationRoot="/root/old"; successorPlan.operationRoot="/root/new";
  predecessorPlan.clusterUUID=7; successorPlan.clusterUUID=7; predecessorPlan.identity="7"; successorPlan.identity="7";
  predecessorPlan.registryRoot="/root/registry"; successorPlan.registryRoot="/root/registry"; predecessorPlan.runtimeRoot="/root/prodigy"; successorPlan.runtimeRoot="/root/prodigy";
  predecessorPlan.statePath="/var/lib/prodigy/state"; successorPlan.statePath=predecessorPlan.statePath; predecessorPlan.secretsPath="/var/lib/prodigy/secrets"; successorPlan.secretsPath=predecessorPlan.secretsPath;
  predecessorPlan.oldRuntimeSHA=std::string(64,'a'); successorPlan.oldRuntimeSHA=predecessorPlan.oldRuntimeSHA; predecessorPlan.oldBundleSHA=std::string(64,'b'); successorPlan.oldBundleSHA=predecessorPlan.oldBundleSHA;
  MothershipTidesMigration::Machine plannedMachine = {}; plannedMachine.uuid=3; plannedMachine.linuxID="0123456789abcdef0123456789abcdef"; plannedMachine.address="fd72::1"; predecessorPlan.machines.push_back(plannedMachine); successorPlan.machines.push_back(plannedMachine);
  assert(samePlanTarget(predecessorPlan,successorPlan)); successorPlan.operationRoot=predecessorPlan.operationRoot;
  assert(!samePlanTarget(predecessorPlan,successorPlan));
  successorPlan.operationRoot="/root/new";
  for (auto member : {&MothershipTidesMigration::Plan::statePath, &MothershipTidesMigration::Plan::secretsPath,
                      &MothershipTidesMigration::Plan::runtimeRoot, &MothershipTidesMigration::Plan::registryRoot,
                      &MothershipTidesMigration::Plan::oldRuntimeSHA, &MothershipTidesMigration::Plan::oldBundleSHA}) {
    auto invalid=successorPlan; invalid.*member+="-changed";
    assert(!samePlanTarget(predecessorPlan,invalid));
  }
  auto wrongMachine=successorPlan; wrongMachine.machines[0].linuxID[0]='f';
  assert(!samePlanTarget(predecessorPlan,wrongMachine));
  MothershipTidesMigration::Machine inventoryMachine = {}; inventoryMachine.uuid=1;
  assert(inventoryProgram("/sealed-manifest",inventoryMachine,InventoryMode::sealed).find("actual==expected")!=std::string::npos);
  assert(inventoryProgram("/sealed-manifest",inventoryMachine,InventoryMode::canonical).find("canonical_only=True")!=std::string::npos);
  assert(inventoryProgram("/sealed-manifest",inventoryMachine,InventoryMode::retire).find("canonical <= actual <= expected")!=std::string::npos);
  for (auto mode : {InventoryMode::sealed, InventoryMode::canonical, InventoryMode::remaining, InventoryMode::retire}) {
    const auto command=inventoryProgram("/sealed-MODE-manifest",inventoryMachine,mode);
    assert(command.find("/sealed-MODE-manifest")!=std::string::npos);
    if(mode!=InventoryMode::retire) assert(command.find("pidfd_send_signal")==std::string::npos);
    String syntaxFailure;
    const auto check="python3 -c "+quote("import ast,shlex,sys; ast.parse(shlex.split(sys.argv[1])[2])")+" "+quote(command);
    assert(prodigyRunLocalShellCommand(text(check),&syntaxFailure));
  }
  const auto stop=MothershipTidesMigration::quiesceServiceCommand();
  assert(stop.find("retained containers require")<stop.find("systemctl stop"));
  assert(MothershipTidesMigration::quiesceServiceCommand(true).find("retained containers require")==std::string::npos);
  assert(!prepareLocal("/absent/request","/var/lib/prodigy/state",false,&failure));
  // Exercise the actual private-copy save and independent reopen/readback.
  const auto root=std::filesystem::current_path()/".run"/("retained-recovery-"+std::to_string(::getpid()));
  assert(!std::filesystem::exists(root));std::filesystem::create_directories(root);
  const auto statePath=(root/"state.new10").string(), requestPath=(root/"request").string();
  snapshot.brainConfig.clusterUUID=1;snapshot.brainConfig.datacenterFragment=7;
  DeploymentPlan deployment = {};deployment.config.type=ApplicationType::stateless;deployment.config.applicationID=77;deployment.config.versionID=9;
  deployment.config.memoryMB=256;deployment.config.storageMB=128;deployment.config.nLogicalCores=1;
  const auto deploymentID=deployment.config.deploymentID();
  snapshot.masterAuthority.deploymentPlans[deploymentID]=deployment;
  request.plans=snapshot.masterAuthority.deploymentPlans;
  for(uint32_t i=1;i<=3;++i) {
    ClusterMachine machine = {};machine.uuid=i;snapshot.topology.machines.push_back(machine);
    MothershipRetainedRecoveryMachineInput input;input.machineUUID=i;input.machineFragment=i;
    ContainerParameters params = {};params.uuid=i+100;params.deploymentID=deploymentID;
    params.memoryMB=deployment.config.memoryMB;params.storageMB=deployment.config.storageMB;
    params.nLogicalCores=applicationSharedCPUCoreHint(deployment.config);params.cpuMode=deployment.config.cpuMode;params.requestedCPUMillis=applicationRequestedCPUMillis(deployment.config);
    params.private6.network.is6=true;params.private6.cidr=128;
    std::memcpy(params.private6.network.v6,container_network_subnet6.value,11);
    params.private6.network.v6[11]=7;params.private6.network.v6[12]=0;params.private6.network.v6[13]=0;params.private6.network.v6[14]=i;params.private6.network.v6[15]=1;
    for(uint64_t service=1;service<=16;++service) {
      SubscriptionPairing subscriptionPairing = {};subscriptionPairing.secret=service;subscriptionPairing.address=service+100;subscriptionPairing.service=service;subscriptionPairing.port=uint16_t(5000+service);
      params.subscriptionPairings.insert(service,subscriptionPairing);
      AdvertisementPairing advertisementPairing = {};advertisementPairing.secret=service+200;advertisementPairing.address=service+300;advertisementPairing.service=service+1000;
      params.advertisementPairings.insert(service+1000,advertisementPairing);
    }
    input.parameters.push_back(params);input.observedCreatedAtMs.push_back(1790040000000LL);request.machines.push_back(input);
  }
  // BrainConfig and API credentials contain nested unordered maps as well.
  ApiCredential credential = {};credential.name="fixture"_ctv;
  for (uint32_t index=0;index<32;++index) {
    String key;key.snprintf<"key-{itoa}"_ctv>(index);
    MachineConfig machine = {};machine.slug=key;machine.nLogicalCores=index+1;
    snapshot.brainConfig.configBySlug[key]=machine;
    snapshot.brainConfig.dnsCredential.metadata[key]=key;
    credential.metadata[key]=key;
  }
  ApplicationApiCredentialSet credentials = {};credentials.applicationID=77;credentials.credentials.push_back(credential);
  snapshot.masterAuthority.apiCredentialSetsByApp[77]=credentials;
  String snapshotBytes;BitseryEngine::serialize(snapshotBytes,snapshot);
  ProdigyPersistentBrainSnapshot snapshotRoundTrip;
  assert(BitseryEngine::deserializeSafe(snapshotBytes,snapshotRoundTrip));
  assert(prodigyPersistentBrainSnapshotsEqual(snapshot,snapshotRoundTrip));
  snapshotRoundTrip.brainConfig.configBySlug.begin()->second.nLogicalCores+=1;
  assert(!prodigyPersistentBrainSnapshotsEqual(snapshot,snapshotRoundTrip));
  snapshotRoundTrip=snapshot;
  snapshotRoundTrip.masterAuthority.apiCredentialSetsByApp[77].credentials[0].metadata.begin()->second="changed"_ctv;
  assert(!prodigyPersistentBrainSnapshotsEqual(snapshot,snapshotRoundTrip));
  auto preparedSnapshot=snapshot;
  assert(mothershipPrepareRetainedRecoverySnapshot(preparedSnapshot,request.plans,request.machines,request.bundleSHA,&failure));
  auto preexistingSnapshot=preparedSnapshot;
  String& originalBootstrap=preexistingSnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[0].containerBootstraps[0];
  NeuronContainerBootstrap decodedBootstrap = {};assert(BitseryEngine::deserializeSafe(originalBootstrap,decodedBootstrap));
  NeuronContainerBootstrap reorderedBootstrap=decodedBootstrap;
  Vector<std::pair<uint64_t,Vector<SubscriptionPairing>>> subscriptionPairings = {};
  for(const auto& [service,pairings]:decodedBootstrap.plan.subscriptionPairings) subscriptionPairings.emplace_back(service,pairings);
  reorderedBootstrap.plan.subscriptionPairings.clear();
  for(auto iterator=subscriptionPairings.rbegin();iterator!=subscriptionPairings.rend();++iterator)
    for(const SubscriptionPairing& pairing:iterator->second) reorderedBootstrap.plan.subscriptionPairings.insert(iterator->first,pairing);
  String reorderedBytes = {};BitseryEngine::serialize(reorderedBytes,reorderedBootstrap);
  assert(!originalBootstrap.equals(reorderedBytes));
  originalBootstrap=std::move(reorderedBytes);
  assert(prodigyPersistentRetainedBootstrapEqual(decodedBootstrap,reorderedBootstrap));
  { ProdigyPersistentStateStore store(MothershipTidesMigration::text(statePath)); assert(store.saveBrainSnapshot(preexistingSnapshot,&failure)); }
  std::filesystem::create_directories(statePath+".secrets");
  BitseryEngine::serialize(bytes,request);MothershipTidesMigration::durable(requestPath,bytes);
  WitnessSet sealed;sealed.requestSHA=MothershipTidesMigration::text(MothershipTidesMigration::digest(requestPath));
  sealed.witnesses=preparedSnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
  BitseryEngine::serialize(bytes,sealed);MothershipTidesMigration::durable(requestPath+".witnesses",bytes);
  const bool prepared=prepareLocal(requestPath.c_str(),statePath.c_str(),false,&failure);
  if(!prepared)std::fprintf(stderr,"private recovery preparation: %s\n",failure.c_str());
  assert(prepared);
  assert(prepareLocal(requestPath.c_str(),statePath.c_str(),true,&failure));
  ProdigyPersistentBrainSnapshot after;loadSnapshot(statePath,after);
  assert(after.masterAuthority.runtimeState.generation==1 && after.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses.size()==3);
  assert(after.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[0].containerBootstraps[0].equals(sealed.witnesses[0].containerBootstraps[0]));
  // A saved request is an idempotent retry even if its outer marker was lost.
  assert(prepareLocal(requestPath.c_str(),statePath.c_str(),false,&failure));
  request.machines[0].parameters[0].memoryMB+=1;
  BitseryEngine::serialize(bytes,request);MothershipTidesMigration::durable(requestPath,bytes);
  assert(!prepareLocal(requestPath.c_str(),statePath.c_str(),true,&failure));
  std::filesystem::remove_all(root);
  return 0;
}
