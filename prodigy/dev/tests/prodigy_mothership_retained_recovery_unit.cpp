#include <cassert>
#include <cstdio>

#include <prodigy/mothership/mothership.retained.recovery.h>
#include <prodigy/mothership/mothership.retained.recovery.command.h>
#include <prodigy/mothership/mothership.tidesdb.migration.h>

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
  Request request;request.clusterUUID=1;request.bundleSHA.assign("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv);
  String bytes;BitseryEngine::serialize(bytes,request);Request decoded;
  assert(BitseryEngine::deserializeSafe(bytes,decoded) && decoded.clusterUUID==1 && decoded.bundleSHA==request.bundleSHA);
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
    input.parameters.push_back(params);input.observedCreatedAtMs.push_back(1790040000000LL);request.machines.push_back(input);
  }
  { ProdigyPersistentStateStore store(MothershipTidesMigration::text(statePath)); assert(store.saveBrainSnapshot(snapshot,&failure)); }
  std::filesystem::create_directories(statePath+".secrets");
  BitseryEngine::serialize(bytes,request);MothershipTidesMigration::durable(requestPath,bytes);
  const bool prepared=prepareLocal(requestPath.c_str(),statePath.c_str(),false,&failure);
  if(!prepared)std::fprintf(stderr,"private recovery preparation: %s\n",failure.c_str());
  assert(prepared);
  assert(prepareLocal(requestPath.c_str(),statePath.c_str(),true,&failure));
  ProdigyPersistentBrainSnapshot after;loadSnapshot(statePath,after);
  assert(after.masterAuthority.runtimeState.generation==1 && after.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses.size()==3);
  // A saved request is an idempotent retry even if its outer marker was lost.
  assert(prepareLocal(requestPath.c_str(),statePath.c_str(),false,&failure));
  request.machines[0].parameters[0].memoryMB+=1;
  BitseryEngine::serialize(bytes,request);MothershipTidesMigration::durable(requestPath,bytes);
  assert(!prepareLocal(requestPath.c_str(),statePath.c_str(),true,&failure));
  std::filesystem::remove_all(root);
  return 0;
}
