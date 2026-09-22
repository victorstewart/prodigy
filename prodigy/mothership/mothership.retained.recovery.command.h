#pragma once

// Explicit retained-fleet repair. Reuses the migration owner's SSH authority,
// bundle installation, fences, receipt, atomic renames and activation boundary.
#include <prodigy/mothership/mothership.tidesdb.migration.command.h>
#include <prodigy/mothership/mothership.retained.recovery.h>
#include <prodigy/wire.h>
#include <set>

template<typename S> void serialize(S&& s, MothershipRetainedRecoveryMachineInput& m) {
  s.value16b(m.machineUUID); s.value4b(m.machineFragment); s.object(m.parameters); s.object(m.observedCreatedAtMs);
}

namespace MothershipRetainedRecovery {
using namespace MothershipTidesMigration;
struct Request {
  uint128_t clusterUUID = 0;
  String bundleSHA;
  bytell_hash_map<uint64_t,DeploymentPlan> plans;
  Vector<MothershipRetainedRecoveryMachineInput> machines;
};
template<typename S> void serialize(S&& s, Request& r) {
  s.value16b(r.clusterUUID); s.text1b(r.bundleSHA,UINT32_MAX); s.object(r.plans); s.object(r.machines);
}
// The seed generates these bytes once. Every Brain must receive identical
// witness strings, even when unordered maps decode in a different order.
struct WitnessSet {
  String requestSHA;
  Vector<ProdigyPersistentUpdateSelfMachineRecoveryWitness> witnesses;
};
template<typename S> void serialize(S&& s, WitnessSet& w) {
  s.text1b(w.requestSHA,64); s.object(w.witnesses);
}
inline bool witnessesEquivalent(const Vector<ProdigyPersistentUpdateSelfMachineRecoveryWitness>& a,
                                const Vector<ProdigyPersistentUpdateSelfMachineRecoveryWitness>& b) {
  if(a.size()!=b.size())return false;
  for(uint32_t i=0;i<a.size();++i) {
    if(a[i].machineUUID!=b[i].machineUUID || a[i].bundleRegistered!=b[i].bundleRegistered || a[i].containerBootstraps.size()!=b[i].containerBootstraps.size())return false;
    for(uint32_t j=0;j<a[i].containerBootstraps.size();++j) {
      NeuronContainerBootstrap left,right;
      if(!BitseryEngine::deserializeSafe(a[i].containerBootstraps[j],left) ||
         !BitseryEngine::deserializeSafe(b[i].containerBootstraps[j],right) ||
         !prodigyPersistentRetainedBootstrapEqual(left,right))return false;
    }
  }
  return true;
}
struct Record {
  uint128_t machine=0, container=0;
  uint64_t pid=0, created=0;
  std::string start, executableSHA, paramsSHA, paramsPath;
  bool canonical=false;
};
struct Manifest {
  Request request;
  std::vector<Record> records;
};
inline void privateFile(const std::string& path, uint64_t maximum=UINT32_MAX) {
  struct stat st{};
  require(::lstat(path.c_str(),&st)==0 && S_ISREG(st.st_mode) && !(st.st_mode&0077) && st.st_nlink==1 && st.st_uid==::geteuid() && st.st_size>0 && uint64_t(st.st_size)<=maximum,"recovery input must be a private owned regular file");
}
inline uint64_t number(simdjson::dom::element e,const char *key) {
  uint64_t n=0; require(e[key].get_uint64().get(n)==simdjson::SUCCESS,"invalid recovery integer"); return n;
}
inline Manifest parseManifest(const std::string& path,const Plan& p) {
  privateFile(path,1024*1024); simdjson::dom::parser parser; simdjson::dom::element doc;
  auto raw=read(path); require(parser.parse(raw).get(doc)==simdjson::SUCCESS,"invalid recovery manifest JSON");
  require(number(doc,"schemaVersion")==1 && uuid(field(doc,"clusterUUID"))==p.clusterUUID,"recovery manifest cluster mismatch");
  Manifest m; m.request.clusterUUID=p.clusterUUID; m.request.bundleSHA=text(field(doc,"bundleSHA256"));
  require(prodigyIsSHA256HexDigest(m.request.bundleSHA),"invalid recovery bundle digest");
  simdjson::dom::array machines; require(doc["machines"].get_array().get(machines)==simdjson::SUCCESS,"recovery machines missing");
  bytell_hash_set<uint128_t> seenMachines,seenContainers; uint32_t canonical=0;
  for(auto item:machines) {
    MothershipRetainedRecoveryMachineInput machine; machine.machineUUID=uuid(field(item,"machineUUID"));
    const auto fragment=number(item,"machineFragment"); require(fragment>0 && fragment<=0xffffff,"invalid recovery machine fragment"); machine.machineFragment=fragment;
    require(seenMachines.insert(machine.machineUUID).second,"duplicate recovery machine");
    bool selected=false; for(const auto& expected:p.machines) selected|=expected.uuid==machine.machineUUID;
    require(selected,"unregistered recovery machine");
    simdjson::dom::array records; require(item["records"].get_array().get(records)==simdjson::SUCCESS,"recovery process records missing");
    std::set<uint64_t> pids;
    for(auto entry:records) {
      Record r; r.machine=machine.machineUUID;r.container=uuid(field(entry,"uuid"));r.pid=number(entry,"pid");r.created=number(entry,"createdAtMs");r.start=field(entry,"start");
      r.executableSHA=field(entry,"exeSHA256");r.paramsSHA=field(entry,"paramsSHA256");r.paramsPath=field(entry,"paramsPath");pathCheck(r.paramsPath);
      require(entry["canonical"].get_bool().get(r.canonical)==simdjson::SUCCESS,"missing canonical recovery membership");
      require(r.pid>1 && r.pid<=INT_MAX && r.created>0 && r.created<=INT64_MAX && r.start.find_first_not_of("0123456789")==std::string::npos &&
          prodigyIsSHA256HexDigest(text(r.executableSHA)) && prodigyIsSHA256HexDigest(text(r.paramsSHA)) && pids.insert(r.pid).second && seenContainers.insert(r.container).second,"invalid or duplicated recovery process identity");
      canonical+=r.canonical; m.records.push_back(std::move(r));
    }
    m.request.machines.push_back(std::move(machine));
  }
  require(seenMachines.size()==3 && canonical==23,"recovery requires the sealed three-host inventory with 23 canonical containers");
  return m;
}
inline void loadSnapshot(const std::string& path,ProdigyPersistentBrainSnapshot& snapshot) {
  require(fs::is_directory(path) && fs::is_directory(path+".secrets") && !fs::is_symlink(path) && !fs::is_symlink(path+".secrets"),"paired private recovery databases absent");
  ProdigyPersistentStateStore store(text(path)); String failure;
  require(store.loadBrainSnapshot(snapshot,&failure),"private recovery snapshot unreadable");
}
// Only the staged Mothership invokes this against its private paired copy.
inline bool prepareLocal(const char *requestPath,const char *statePath,bool verifyOnly,String *failure) {
  try {
    privateFile(requestPath); const std::string path=statePath;pathCheck(path);
    require(path.ends_with("/state.new10") || (verifyOnly && path=="/var/lib/prodigy/state"),"recovery suboperation refuses an unowned database path");
    require(::getenv("PRODIGY_STATE_SECRETS_DB")==nullptr,"recovery refuses a secrets-path override");
    Request request;require(BitseryEngine::deserializeSafe(text(read(requestPath)),request),"recovery request decode failed");
    ProdigyPersistentBrainSnapshot before;loadSnapshot(path,before);require(before.brainConfig.clusterUUID==request.clusterUUID,"recovery request targets another cluster");
    const auto witnessPath=std::string(requestPath)+".witnesses";privateFile(witnessPath);
    WitnessSet sealed;require(BitseryEngine::deserializeSafe(text(read(witnessPath)),sealed) && sealed.requestSHA==text(digest(requestPath)),"sealed recovery witnesses differ from request");
    const bool alreadyPrepared=before.masterAuthority.runtimeState.updateSelf.active();
    require(!verifyOnly || alreadyPrepared,"recovery snapshot is not prepared");
    auto expected=before;
    if(alreadyPrepared) {
      expected.masterAuthority.runtimeState.updateSelf={};
      require(expected.masterAuthority.runtimeState.generation>0,"recovery generation missing"); --expected.masterAuthority.runtimeState.generation;
    }
    String why;
    require(mothershipPrepareRetainedRecoverySnapshot(expected,request.plans,request.machines,request.bundleSHA,&why),str(why).c_str());
    require(witnessesEquivalent(expected.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses,sealed.witnesses),"sealed witnesses differ from validated retained fleet");
    expected.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses=sealed.witnesses;
    if(alreadyPrepared) {
      auto comparable=before;
      require(witnessesEquivalent(comparable.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses,sealed.witnesses),"existing prepared witnesses differ from retained fleet");
      comparable.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses=sealed.witnesses;
      require(prodigyPersistentBrainSnapshotsEqual(comparable,expected),"prepared recovery snapshot content differs");
    }
    if(verifyOnly) { require(prodigyPersistentBrainSnapshotsEqual(before,expected),"prepared recovery snapshot readback differs");return true; }
    { ProdigyPersistentStateStore store(text(path)); require(store.saveBrainSnapshot(expected,&why),"private recovery snapshot write failed"); }
    ProdigyPersistentBrainSnapshot observed;loadSnapshot(path,observed);
    require(prodigyPersistentBrainSnapshotsEqual(expected,observed),"private recovery snapshot did not persist exactly");return true;
  } catch(const std::exception& e) { if(failure) failure->assign(e.what());return false; }
}

// Python is only an identity observer / pidfd transport launched by Mothership.
// It cannot choose a process or delete a directory: every identity is sealed.
enum class InventoryMode { sealed, canonical, remaining, retire };
inline std::string inventoryProgram(const std::string& manifestPath,const MothershipTidesMigration::Machine& machine,InventoryMode mode) {
  String machineID;machineID.snprintf<"{itoh}"_ctv>(machine.uuid);
  std::string code="import json,os,pathlib,hashlib,signal,time\nm=json.load(open("+quote(manifestPath)+"))\nselected=[x for x in m['machines'] if int(x['machineUUID'],16)==int("+quote(str(machineID))+",16)]\nassert len(selected)==1\nrecords=selected[0]['records']\ncanonical_only="+std::string(mode==InventoryMode::canonical?"True":"False")+"\n";
  code+=R"PY(def sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def verify(r):
 p=r['pid'];u=str(int(r['uuid'],16));base=pathlib.Path('/proc')/str(p)
 assert base.joinpath('stat').read_text().rsplit(') ',1)[1].split()[19]==r['start'],'process start changed'
 assert base.joinpath('cgroup').read_text().strip()=='0::/containers.slice/'+u+'.slice/leaf','process cgroup changed'
 assert sha(base/'exe')==r['exeSHA256'],'process executable changed'
 f=pathlib.Path(r['paramsPath']);s=f.lstat()
 assert f.is_file() and not f.is_symlink() and s.st_uid==0 and s.st_nlink==1 and s.st_mode&0o077==0,'unsafe parameters file'
 assert sha(f)==r['paramsSHA256'],'parameters copy changed'
 found=[]
 for fd in (base/'fd').iterdir():
  try:
   if os.readlink(fd)=='/memfd:container.params (deleted)':found.append(fd)
  except FileNotFoundError:pass
 assert len(found)==1 and sha(found[0])==r['paramsSHA256'],'live startup parameters changed'
 return base
)PY";
  if(mode==InventoryMode::sealed || mode==InventoryMode::canonical) code+=R"PY(expected={(str(int(r['uuid'],16)),r['pid']) for r in records if (not canonical_only or r['canonical'])}
actual=set()
for leaf in pathlib.Path('/sys/fs/cgroup/containers.slice').glob('*.slice/leaf'):
 for p in (leaf/'cgroup.procs').read_text().split():actual.add((leaf.parent.name[:-6],int(p)))
assert actual==expected,'retained process inventory changed'
for r in records:
 if (not canonical_only or r['canonical']):verify(r)
print('retained inventory verified',len(expected))
)PY";
  else code+=R"PY(expected={(str(int(r['uuid'],16)),r['pid']) for r in records}
canonical={(str(int(r['uuid'],16)),r['pid']) for r in records if r['canonical']}
actual=set()
for leaf in pathlib.Path('/sys/fs/cgroup/containers.slice').glob('*.slice/leaf'):
 for p in (leaf/'cgroup.procs').read_text().split():actual.add((leaf.parent.name[:-6],int(p)))
assert canonical <= actual <= expected,'retained process inventory changed'
for r in records:
 if (str(int(r['uuid'],16)),r['pid']) in actual:verify(r)
)PY";
  if(mode==InventoryMode::retire) code+=R"PY(for r in records:
 if r['canonical']:continue
 base=pathlib.Path('/proc')/str(r['pid'])
 if not base.exists():continue
 try: fd=os.pidfd_open(r['pid'],0)
 except ProcessLookupError:
  assert not base.exists(),'pid changed during retirement'; continue
 try:
  verify(r); signal.pidfd_send_signal(fd,signal.SIGTERM)
  for _ in range(50):
   if not base.exists():break
   time.sleep(.1)
  if base.exists():
   verify(r);signal.pidfd_send_signal(fd,signal.SIGKILL)
   for _ in range(50):
    if not base.exists():break
    time.sleep(.1)
  assert not base.exists(),'retired process did not exit'
 finally:os.close(fd)
print('pinned stateless extras retired')
)PY";
  return "python3 -c "+quote(code);
}
inline bool sameRecordIdentity(const Manifest& left,const Manifest& right) {
  if(left.records.size()!=right.records.size())return false;
  std::map<uint128_t,const Record*> index;
  for(const auto& record:left.records)index.emplace(record.container,&record);
  for(const auto& record:right.records) {
    const auto found=index.find(record.container); if(found==index.end())return false;
    const auto& expected=*found->second;
    if(expected.machine!=record.machine || expected.pid!=record.pid || expected.created!=record.created || expected.start!=record.start || expected.executableSHA!=record.executableSHA || expected.paramsSHA!=record.paramsSHA || expected.paramsPath!=record.paramsPath || expected.canonical!=record.canonical)return false;
  }
  return true;
}
inline bool sameCanonicalRecordIdentity(const Manifest& left,const Manifest& right) {
  std::map<uint128_t,const Record*> index;
  for(const auto& record:left.records)if(record.canonical)index.emplace(record.container,&record);
  if(index.size()!=23)return false;
  uint32_t canonical=0;
  for(const auto& record:right.records) {
    if(!record.canonical)continue;
    canonical++;
    const auto found=index.find(record.container); if(found==index.end())return false;
    const auto& expected=*found->second;
    if(expected.machine!=record.machine || expected.pid!=record.pid || expected.created!=record.created || expected.start!=record.start || expected.executableSHA!=record.executableSHA || expected.paramsSHA!=record.paramsSHA || expected.paramsPath!=record.paramsPath)return false;
  }
  return canonical==23;
}
inline bool samePlanTarget(const Plan& oldPlan,const Plan& successor) {
  if(oldPlan.operationID==successor.operationID || oldPlan.operationRoot==successor.operationRoot || oldPlan.clusterUUID!=successor.clusterUUID || oldPlan.identity!=successor.identity || oldPlan.registryRoot!=successor.registryRoot || oldPlan.runtimeRoot!=successor.runtimeRoot || oldPlan.statePath!=successor.statePath || oldPlan.secretsPath!=successor.secretsPath || oldPlan.oldRuntimeSHA!=successor.oldRuntimeSHA || oldPlan.oldBundleSHA!=successor.oldBundleSHA || oldPlan.machines.size()!=successor.machines.size())return false;
  for(size_t i=0;i<oldPlan.machines.size();++i)if(oldPlan.machines[i].uuid!=successor.machines[i].uuid || oldPlan.machines[i].linuxID!=successor.machines[i].linuxID || oldPlan.machines[i].address!=successor.machines[i].address)return false;
  return true;
}
inline bool sameContainedSuccessorTarget(const Plan& predecessor,const MothershipTidesDBMigrationReceipt& receipt,const Plan& successor) {
  if(successor.oldRuntimeSHA!=str(receipt.newRuntimeSHA256) || successor.oldBundleSHA!=str(receipt.approvedBundleSHA256))return false;
  Plan current=predecessor;
  current.oldRuntimeSHA=successor.oldRuntimeSHA;
  current.oldBundleSHA=successor.oldBundleSHA;
  return samePlanTarget(current,successor);
}
inline void requirePreactivation(Execution& e,const Execution *successor=nullptr) {
  require(e.receipt.phase>=MothershipTidesDBMigrationPhase::writersQuiesced && !e.receipt.activationBoundaryCrossed,"retained action requires a fenced pre-activation operation");
  for(const auto& database:e.receipt.databases) {
    require(!database.swapped,"retained action refuses a database swap");
    require(e.exists(database,database.livePath) && !e.exists(database,database.retainedV9Path),"retained action found an incomplete database swap");
  }
  for(const auto& machine:e.plan.machines) {
    std::string fence="test \"$(cat "+quote(e.fencePath())+")\" = "+quote(e.plan.planSHA);
    if(successor)fence="( "+fence+" || test \"$(cat "+quote(successor->fencePath())+")\" = "+quote(successor->plan.planSHA)+" )";
    e.run(machine.uuid,"test \"$(systemctl show -p MainPID --value prodigy)\" = 0; "+fence+
      "; test \"$(sha256sum "+quote(e.plan.runtimeRoot+"/prodigy")+" | cut -d' ' -f1)\" = "+quote(e.plan.oldRuntimeSHA)+
      "; test \"$(sha256sum "+quote(e.plan.runtimeRoot+"/prodigy.bundle.tar.zst")+" | cut -d' ' -f1)\" = "+quote(e.plan.oldBundleSHA));
  }
}
inline bool runFile(const char *file,const char *action,String *failure=nullptr,const char *repairBundle=nullptr,const char *successorFile=nullptr) {
  try {
    require(std::strcmp(action,"recover")==0 || std::strcmp(action,"prepare")==0 || std::strcmp(action,"retire-extras")==0 || std::strcmp(action,"retire-extras-preactivation")==0 || std::strcmp(action,"supersede-preactivation")==0 || std::strcmp(action,"contain-active")==0,"invalid retained recovery action");
    Plan plan=parse(file);plan.retainedRecovery=true;
    simdjson::dom::parser parser;simdjson::dom::element doc;auto raw=read(file);require(parser.parse(raw).get(doc)==simdjson::SUCCESS,"invalid recovery plan");
    bool mode=false;require(doc["retainedRecoveryMode"].get_bool().get(mode)==simdjson::SUCCESS && mode,"explicit retained recovery mode required");
    const auto manifestPath=field(doc,"retainedManifestPath"), manifestSHA=field(doc,"retainedManifestSHA256");pathCheck(manifestPath);
    require(digest(manifestPath)==manifestSHA,"retained manifest digest mismatch");
    Manifest manifest=parseManifest(manifestPath,plan);
    Execution e(std::move(plan));e.initialize();
    require(manifest.request.bundleSHA==e.receipt.approvedBundleSHA256,"retained manifest bundle mismatch");
    // The same outer Mothership client lock excludes registry writers. Reading
    // the existing v10 registry uses its normal owner, never the v9 exporter.
    { MothershipClusterRegistry registry(text(e.plan.registryRoot+"/clusters"));String why;
      require(registry.getClusterByIdentity(text(e.plan.identity),e.cluster,&why),"v10 registry authority unavailable"); }
    require(e.cluster.clusterUUID==e.plan.clusterUUID && e.cluster.nBrains==3 && e.cluster.machines.size()==3 && str(e.cluster.remoteProdigyPath)==e.plan.runtimeRoot,"retained cluster authority differs");
    for(auto& m:e.plan.machines) {resolveRegisteredMachine(e.cluster,m);e.machines.emplace(m.uuid,&m);}
    e.buildArtifactManifest();
    auto verify=[&](InventoryMode mode=InventoryMode::sealed) {for(auto& m:e.plan.machines)e.run(m.uuid,inventoryProgram(e.remoteRoot+"/retained-manifest.json",m,mode));};
    const auto containment=e.plan.operationRoot+"/activation-contained";
    if(std::strcmp(action,"contain-active")==0) {
      require(e.receipt.activationBoundaryCrossed && e.receipt.phase==MothershipTidesDBMigrationPhase::completed,"containment requires a completed activated operation");
      // Validate the installed generation on every host before fencing any host.
      // Never roll back a database that has had v10 writers.
      for(const auto& machine:e.plan.machines)e.run(machine.uuid,
        "test \"$(sha256sum "+quote(e.plan.runtimeRoot+"/prodigy")+" | cut -d' ' -f1)\" = "+quote(str(e.receipt.newRuntimeSHA256))+
        "; test \"$(sha256sum "+quote(e.plan.runtimeRoot+"/prodigy.bundle.tar.zst")+" | cut -d' ' -f1)\" = "+quote(str(e.receipt.approvedBundleSHA256)));
      durable(containment,text(e.plan.planSHA+"\n"));
      e.fenceWriters();
      for(const auto& machine:e.plan.machines)e.run(machine.uuid,
        quiesceServiceCommand(true)+e.observeContainers()+"snapshot_containers > "+quote(e.remoteRoot+"/containers.contained")+"; sync -f "+quote(e.remoteRoot));
      return true;
    }
    const bool predecessorContained=fs::exists(containment);
    if(predecessorContained) {
      privateFile(containment,4096);
      require(read(containment)==e.plan.planSHA+"\n" && e.receipt.activationBoundaryCrossed && e.receipt.phase==MothershipTidesDBMigrationPhase::completed,"contained recovery receipt differs");
    }
    if(predecessorContained && std::strcmp(action,"supersede-preactivation")!=0)throw std::runtime_error("activated recovery is contained; use a fresh retained recovery plan");
    const auto superseded=e.plan.operationRoot+"/superseded-by";
    if(fs::exists(superseded)) { privateFile(superseded,4096); if(std::strcmp(action,"supersede-preactivation")!=0)throw std::runtime_error("retained operation was superseded before activation"); }
    if(std::strcmp(action,"retire-extras-preactivation")==0) {
      requirePreactivation(e); require(e.receipt.phase==MothershipTidesDBMigrationPhase::validated,"extra retirement requires prepared private copies");
      for(const auto& database:e.receipt.databases)require(e.exists(database,database.livePath) && e.exists(database,database.copiedV9Path) && e.exists(database,database.preparedV10Path) && !e.exists(database,database.retainedV9Path),"extra retirement database state differs");
      for(const auto& machine:e.plan.machines) {
        const auto request=e.remoteRoot+"/recovery.request", marker=e.remoteRoot+"/prepared.request.sha256";
        e.run(machine.uuid,"test -f "+quote(marker)+"; test \"$(cat "+quote(marker)+")\" = "+quote(digest(e.plan.operationRoot+"/recovery.request"))+"; LD_LIBRARY_PATH="+quote(e.remoteRuntime+"/lib")+" "+quote(e.remoteRuntime+"/tools/mothership")+" prepareRetainedRecoveryLocal "+quote(request)+" "+quote(e.remoteRoot+"/state.new10")+" verify");
      }
      const auto authority=e.plan.operationRoot+"/stateless-extras-authority"; privateFile(authority,4096);
      require(read(authority)==e.plan.planSHA+"\n"+manifestSHA+"\n"+digest(e.plan.operationRoot+"/recovery.request")+"\n","stateless extra authority differs");
      const auto started=e.plan.operationRoot+"/extras-retirement-started";
      if(!fs::exists(started)) { verify(InventoryMode::sealed); durable(started,text(e.plan.planSHA+"\n"+manifestSHA+"\n")); }
      else require(read(started)==e.plan.planSHA+"\n"+manifestSHA+"\n","extra retirement marker differs");
      verify(InventoryMode::remaining); verify(InventoryMode::retire); verify(InventoryMode::canonical); e.acceptStoppedContainerBaseline(); durable(fs::path(e.plan.operationRoot)/"extras-retired",text(manifestSHA)); return true;
    }
    if(std::strcmp(action,"supersede-preactivation")==0) {
      require(successorFile && !repairBundle,"supersession requires exactly a successor retained plan");
      Plan successorPlan=parse(successorFile); successorPlan.retainedRecovery=true;
      simdjson::dom::parser successorParser; simdjson::dom::element successorDoc; auto successorRaw=read(successorFile);
      require(successorParser.parse(successorRaw).get(successorDoc)==simdjson::SUCCESS,"invalid successor recovery plan"); bool successorMode=false;
      require(successorDoc["retainedRecoveryMode"].get_bool().get(successorMode)==simdjson::SUCCESS && successorMode,"successor retained recovery mode required");
      const auto successorManifestPath=field(successorDoc,"retainedManifestPath"), successorManifestSHA=field(successorDoc,"retainedManifestSHA256"); pathCheck(successorManifestPath);
      require(digest(successorManifestPath)==successorManifestSHA,"successor retained manifest digest mismatch"); Manifest successorManifest=parseManifest(successorManifestPath,successorPlan);
      require(predecessorContained ? sameCanonicalRecordIdentity(manifest,successorManifest) : sameRecordIdentity(manifest,successorManifest),"successor retained manifest does not preserve the predecessor canonical inventory");
      require(successorPlan.planSHA!=e.plan.planSHA && (predecessorContained ? sameContainedSuccessorTarget(e.plan,e.receipt,successorPlan) : samePlanTarget(e.plan,successorPlan)) && !successorPlan.operationRoot.starts_with(e.plan.operationRoot+"/") && !e.plan.operationRoot.starts_with(successorPlan.operationRoot+"/"),"invalid retained successor identity");
      Execution successor(std::move(successorPlan)); successor.initialize(); require(successorManifest.request.bundleSHA==successor.receipt.approvedBundleSHA256,"successor retained manifest bundle mismatch");
      successor.cluster=e.cluster; for(auto& machine:successor.plan.machines) { resolveRegisteredMachine(successor.cluster,machine); successor.machines.emplace(machine.uuid,&machine); }
      require(successor.receipt.phase<=MothershipTidesDBMigrationPhase::writersQuiesced && !successor.receipt.activationBoundaryCrossed,"successor already crossed preparation");
      if(predecessorContained) {
        for(const auto& database:e.receipt.databases)require(database.swapped && e.exists(database,database.livePath) && e.exists(database,database.retainedV9Path) && !e.exists(database,database.preparedV10Path),"contained predecessor database state differs");
        for(const auto& machine:e.plan.machines) {
          const std::string fence="( test \"$(cat "+quote(e.fencePath())+")\" = "+quote(e.plan.planSHA)+" || test \"$(cat "+quote(successor.fencePath())+")\" = "+quote(successor.plan.planSHA)+" )";
          e.run(machine.uuid,"test \"$(systemctl show -p MainPID --value prodigy)\" = 0; "+fence+
                "; test \"$(sha256sum "+quote(e.plan.runtimeRoot+"/prodigy")+" | cut -d' ' -f1)\" = "+quote(str(e.receipt.newRuntimeSHA256))+
                "; test \"$(sha256sum "+quote(e.plan.runtimeRoot+"/prodigy.bundle.tar.zst")+" | cut -d' ' -f1)\" = "+quote(str(e.receipt.approvedBundleSHA256)));
        }
      } else { requirePreactivation(e,&successor); verify(InventoryMode::sealed); }
      for(auto& machine:successor.plan.machines)successor.run(machine.uuid,"test \"$(realpath -m "+quote(successor.remoteRoot)+")\" = "+quote(successor.remoteRoot)+"; umask 077; mkdir -p "+quote(successor.remoteRoot)+"; chmod 700 "+quote(successor.remoteRoot));
      for(auto& machine:successor.plan.machines)successor.upload(machine,successorManifestPath,successor.remoteRoot+"/retained-manifest.json");
      for(auto& machine:successor.plan.machines)successor.run(machine.uuid,inventoryProgram(successor.remoteRoot+"/retained-manifest.json",machine,InventoryMode::sealed));
      if(fs::exists(superseded))require(read(superseded)==successor.plan.planSHA+"\n","supersession selects another successor"); else durable(superseded,text(successor.plan.planSHA+"\n"));
      successor.buildArtifactManifest(); successor.stageInheritedQuiesced(e);
      durable(fs::path(successor.plan.operationRoot)/(predecessorContained?"inherited-contained":"inherited-preactivation"),text(e.plan.planSHA+"\n"+manifestSHA+"\n"));
      require(successor.receipt.phase<=MothershipTidesDBMigrationPhase::writersQuiesced && !successor.receipt.activationBoundaryCrossed,"successor already crossed activation");
      successor.receipt.phase=MothershipTidesDBMigrationPhase::writersQuiesced; successor.persist(successor.receipt,nullptr); return true;
    }
    if(std::strcmp(action,"retire-extras")==0) {
      require(e.receipt.phase==MothershipTidesDBMigrationPhase::completed && e.receipt.activationBoundaryCrossed,"recovery has not activated");
      // Root submits this explicit action only after inspecting canonical normal
      // application health; the identity gate still runs immediately per PID.
      const auto marker=e.plan.operationRoot+"/canonical-health-attestation";privateFile(marker,4096);
      require(read(marker)==e.plan.planSHA+"\n"+manifestSHA+"\n","canonical health attestation differs");
      verify(InventoryMode::sealed); verify(InventoryMode::remaining); verify(InventoryMode::retire); verify(InventoryMode::canonical); durable(fs::path(e.plan.operationRoot)/"extras-retired",text(manifestSHA));return true;
    }
    if(e.receipt.phase==MothershipTidesDBMigrationPhase::completed)return true;
    if(e.receipt.phase<MothershipTidesDBMigrationPhase::preflighted) {
      e.stageAndPreflight();
      for(auto& m:e.plan.machines)e.upload(m,manifestPath,e.remoteRoot+"/retained-manifest.json");
      verify();e.receipt.phase=MothershipTidesDBMigrationPhase::preflighted;e.persist(e.receipt,nullptr);
    }
    const auto retiredMarker=e.plan.operationRoot+"/extras-retired";
    const bool extrasRetired=fs::exists(retiredMarker);
    if(extrasRetired) { privateFile(retiredMarker,4096); require(read(retiredMarker)==manifestSHA,"retired inventory marker differs"); }
    if(e.receipt.phase<MothershipTidesDBMigrationPhase::writersQuiesced) {verify(extrasRetired?InventoryMode::canonical:InventoryMode::sealed);e.quiesce();}
    if(!e.receipt.activationBoundaryCrossed) {
      for(auto& m:e.plan.machines)e.run(m.uuid,"test \"$(systemctl show -p MainPID --value prodigy)\" = 0; test \"$(cat "+quote(e.fencePath())+")\" = "+quote(e.plan.planSHA));
    }
    // A repair CLI may resume an immutable, pre-activation operation using a
    // separately approved Discombobulator tool bundle. The deployment bundle,
    // receipt, databases and writer fences retain their original identities.
    std::string preparationRuntime=e.remoteRuntime;
    if(repairBundle) {
      require(e.receipt.phase>=MothershipTidesDBMigrationPhase::writersQuiesced && !e.receipt.activationBoundaryCrossed,"repair tools require a fenced pre-activation recovery");
      pathCheck(repairBundle);String approved,why;
      require(prodigyApproveBundleArtifact(text(repairBundle),approved,&why),"recovery tool bundle not approved");
      Plan helperPlan=e.plan;helperPlan.operationRoot+="/tool-"+str(approved);helperPlan.bundle=repairBundle;
      Execution helper(std::move(helperPlan));helper.cluster=e.cluster;helper.machines=e.machines;helper.receipt=e.receipt;
      fs::create_directories(helper.plan.operationRoot);require(::chmod(helper.plan.operationRoot.c_str(),0700)==0,"cannot protect recovery tool directory");
      require(prodigyInstallBundleToRoot(text(repairBundle),text(helper.localRuntime),&why),"recovery tool staging failed");
      require(digest("/proc/self/exe")==digest(helper.localRuntime+"/tools/mothership"),"repair bundle does not contain this Mothership");
      helper.receipt.approvedBundleSHA256=approved;helper.receipt.newRuntimeSHA256=text(digest(helper.localRuntime+"/prodigy"));
      helper.buildArtifactManifest();helper.stageAndPreflight();preparationRuntime=helper.remoteRuntime;
    }
    const auto requestPath=e.plan.operationRoot+"/recovery.request", authorityPath=e.plan.operationRoot+"/stateless-extras-authority";
    if(e.receipt.phase<MothershipTidesDBMigrationPhase::validated || !fs::exists(authorityPath)) {
      for(auto& db:e.receipt.databases) {
        String why;if(!e.exists(db,db.copiedV9Path))require(e.copySource(db,&why),"retained v10 copy failed");
        if(!e.exists(db,db.preparedV10Path)) e.run(db.machineUUID,"test ! -e "+quote(str(db.preparedV10Path)+".partial")+"; cp -a --reflink=auto "+quote(str(db.copiedV9Path))+" "+quote(str(db.preparedV10Path)+".partial")+"; sync -f "+quote(str(db.preparedV10Path)+".partial")+"; mv -T "+quote(str(db.preparedV10Path)+".partial")+" "+quote(str(db.preparedV10Path))+"; sync -f "+quote(e.remoteRoot));
      }
      const bool requestAlreadySealed=fs::exists(requestPath);
      if(!requestAlreadySealed || !fs::exists(authorityPath)) {
        // This command runs on the selected seed; prove that before using the
        // seed's stopped private copy as shared deployment-plan authority.
        require(read("/etc/machine-id")==e.plan.machines[0].linuxID+"\n","retained recovery must run on selected seed");
        ProdigyPersistentBrainSnapshot seed;loadSnapshot(e.remoteRoot+"/state.copy10",seed);
        require(seed.brainConfig.clusterUUID==e.plan.clusterUUID,"seed authority cluster mismatch");manifest.request.plans=seed.masterAuthority.deploymentPlans;
        for(const auto& r:manifest.records) {
          String encoded,why,bytes;
          require(e.command(r.machine,"test \"$(sha256sum "+quote(r.paramsPath)+" | cut -d' ' -f1)\" = "+quote(r.paramsSHA)+"; base64 -w0 "+quote(r.paramsPath),&why,&encoded),"retained parameters read failed");
          require(Base64::decode(encoded,bytes),"retained parameters encoding invalid");ContainerParameters params;
          require(ProdigyWire::deserializeStartupContainerParameters(bytes,params) && params.uuid==r.container,"retained parameters identity invalid");
          auto deployment=manifest.request.plans.find(params.deploymentID);require(deployment!=manifest.request.plans.end(),"retained deployment absent from authority");
          prodigyRestoreRetainedStartupCPUFields(bytes,deployment->second,params);
          if(!r.canonical) {require(!deployment->second.isStateful && deployment->second.config.type==ApplicationType::stateless,"extra retirement would affect a stateful container");continue;}
          for(auto& m:manifest.request.machines)if(m.machineUUID==r.machine) {m.parameters.push_back(std::move(params));m.observedCreatedAtMs.push_back(r.created);}
        }
        String bytes;BitseryEngine::serialize(bytes,manifest.request); if(!requestAlreadySealed)durable(requestPath,bytes);
        durable(authorityPath,text(e.plan.planSHA+"\n"+manifestSHA+"\n"+digest(requestPath)+"\n"));
      }
      const auto witnessPath=requestPath+".witnesses";
      if(!fs::exists(witnessPath)) {
        require(read("/etc/machine-id")==e.plan.machines[0].linuxID+"\n","witness sealing requires the selected seed");
        Request request;require(BitseryEngine::deserializeSafe(text(read(requestPath)),request),"sealed request unreadable");
        ProdigyPersistentBrainSnapshot seed;loadSnapshot(e.remoteRoot+"/state.copy10",seed);String why;
        require(mothershipPrepareRetainedRecoverySnapshot(seed,request.plans,request.machines,request.bundleSHA,&why),str(why).c_str());
        WitnessSet sealed;sealed.requestSHA=text(digest(requestPath));sealed.witnesses=seed.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
        String bytes;BitseryEngine::serialize(bytes,sealed);durable(witnessPath,bytes);
      }
      for(auto& m:e.plan.machines) {
        e.upload(m,requestPath,e.remoteRoot+"/recovery.request");
        e.upload(m,witnessPath,e.remoteRoot+"/recovery.request.witnesses");
        const auto marker=e.remoteRoot+"/prepared.request.sha256",requestSHA=digest(requestPath);
        std::string cmd="test \"$(systemctl show -p MainPID --value prodigy)\" = 0; ";
        const auto invoke="LD_LIBRARY_PATH="+quote(preparationRuntime+"/lib")+" "+quote(preparationRuntime+"/tools/mothership")+" prepareRetainedRecoveryLocal "+quote(e.remoteRoot+"/recovery.request")+" "+quote(e.remoteRoot+"/state.new10");
        cmd+="if test -f "+quote(marker)+"; then test \"$(cat "+quote(marker)+")\" = "+quote(requestSHA)+"; "+invoke+" verify; else "+invoke+" prepare; printf %s "+quote(requestSHA)+" > "+quote(marker)+"; sync -f "+quote(marker)+"; fi";e.run(m.uuid,cmd);
      }
      verify(extrasRetired?InventoryMode::canonical:InventoryMode::sealed);e.receipt.phase=MothershipTidesDBMigrationPhase::validated;e.persist(e.receipt,nullptr);
    }
    if(std::strcmp(action,"prepare")==0) {require(!e.receipt.activationBoundaryCrossed,"recovery already activated");return true;}
    if(e.receipt.phase<MothershipTidesDBMigrationPhase::swapped) {
      for(auto& db:e.receipt.databases) {
        if(db.swapped)continue;String why;
        bool live=e.exists(db,db.livePath),old=e.exists(db,db.retainedV9Path),prepared=e.exists(db,db.preparedV10Path);
        require(!(live && old && prepared),"ambiguous retained database swap");
        if(live && !old && prepared)require(e.rename(db,db.livePath,db.retainedV9Path,&why),"retained original rename failed");
        if(!e.exists(db,db.livePath) && prepared)require(e.rename(db,db.preparedV10Path,db.livePath,&why),"prepared recovery rename failed");
        require(e.exists(db,db.livePath) && e.exists(db,db.retainedV9Path) && !e.exists(db,db.preparedV10Path),"retained recovery swap incomplete");db.swapped=true;e.persist(e.receipt,nullptr);
      }
      e.receipt.phase=MothershipTidesDBMigrationPhase::swapped;e.persist(e.receipt,nullptr);
    }
    if(!e.receipt.activationBoundaryCrossed) {
      verify(extrasRetired?InventoryMode::canonical:InventoryMode::sealed);for(auto& m:e.plan.machines)e.run(m.uuid,"LD_LIBRARY_PATH="+quote(preparationRuntime+"/lib")+" "+quote(preparationRuntime+"/tools/mothership")+" prepareRetainedRecoveryLocal "+quote(e.remoteRoot+"/recovery.request")+" "+quote(e.plan.statePath)+" verify");
      e.installRuntimes();
    }
    e.activate();return true;
  } catch(const std::exception& error) {if(failure)failure->assign(error.what());return false;}
}
} // namespace MothershipRetainedRecovery
