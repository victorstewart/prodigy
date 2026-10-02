#pragma once

#include <cstring>

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
  // Empty for the established uniform-predecessor format.  A nonempty value
  // is an explicitly approved normal-update payload that may be replaced only
  // through the mixed-handoff proof below.
  String interruptedBundleSHA;
  Vector<uint128_t> mixedSuccessorMachineUUIDs;
  bytell_hash_map<uint64_t,DeploymentPlan> plans;
  Vector<MothershipRetainedRecoveryMachineInput> machines;
};
template<typename S> void serialize(S&& s, Request& r) {
  s.value16b(r.clusterUUID); s.text1b(r.bundleSHA,UINT32_MAX); s.text1b(r.interruptedBundleSHA,UINT32_MAX);
  s.object(r.mixedSuccessorMachineUUIDs); s.object(r.plans); s.object(r.machines);
}
// A schema-four request is explicitly framed, leaving the established request
// serialization byte-for-byte usable by an older retained operation.
struct Schema4Request {
  Request request;
  MothershipRetainedRecoveryMixedProof proof;
};
template<typename S> void serialize(S&& s, Schema4Request& r) {
  s.object(r.request); s.value4b(r.proof.canonicalContainerCount);
  s.value4b(r.proof.staleCoordinatorCanonicalContainerCount);
  s.value4b(r.proof.interruptedExpectedEchos); s.value16b(r.proof.staleExcludedContainerUUID);
}
// The original schema-four request is immutable evidence.  A retirement never
// rewrites it: this separately framed envelope records exactly which sealed
// record was excluded after the stopped-process proof completed.
struct Schema4RetiredConflictingClientRequest {
  Schema4Request request;
  uint128_t retiredConflictingClientUUID = 0;
};
template<typename S> void serialize(S&& s, Schema4RetiredConflictingClientRequest& r) {
  s.object(r.request); s.value16b(r.retiredConflictingClientUUID);
}
// A fresh recovery may explicitly retain an authenticated Brain whose host
// rebooted before any application container could be reconstructed.  Keep the
// established request bytes intact: this envelope binds that exceptional
// machine identity to a uniform fresh request and never carries a stale
// schema-four coordinator proof.
struct Schema6EmptyInventoryRequest {
  Schema4Request request;
  uint128_t emptyRetainedInventoryMachineUUID = 0;
};
template<typename S> void serialize(S&& s, Schema6EmptyInventoryRequest& r) {
  s.object(r.request); s.value16b(r.emptyRetainedInventoryMachineUUID);
}
inline String encodeRequest(const Request& request,const Plan& plan,uint128_t emptyRetainedInventoryMachineUUID = 0) {
  String bytes;
  if (emptyRetainedInventoryMachineUUID != 0) {
    Schema6EmptyInventoryRequest wrapped; wrapped.request.request=request;
    require(plan.schemaVersion != 4 && request.interruptedBundleSHA.empty(),
            "empty retained inventory requires a uniform fresh recovery plan");
    wrapped.emptyRetainedInventoryMachineUUID=emptyRetainedInventoryMachineUUID;
    BitseryEngine::serialize(bytes,wrapped);
    require(!bytes.empty(),"empty-inventory request serialization is empty");
    String framed={}; framed.append("RRF6",4); framed.append(bytes.data(),bytes.size());
    require(framed.size()==4+bytes.size(),"empty-inventory request framing is incomplete");
    return framed;
  }
  if (plan.schemaVersion == 4) {
    Schema4Request wrapped; wrapped.request=request;
    wrapped.proof.canonicalContainerCount=plan.sealedCanonicalContainerCount;
    wrapped.proof.staleCoordinatorCanonicalContainerCount=plan.staleCoordinatorCanonicalContainerCount;
    wrapped.proof.interruptedExpectedEchos=plan.sealedInterruptedExpectedEchos;
    wrapped.proof.staleExcludedContainerUUID=plan.staleExcludedContainerUUID;
    BitseryEngine::serialize(bytes,wrapped);
    require(!bytes.empty(),"schema-four request serialization is empty");
    String framed={}; framed.append("RRF4",4); framed.append(bytes.data(),bytes.size());
    require(framed.size()==4+bytes.size(),"schema-four request framing is incomplete");
    return framed;
  }
  Request copy=request; BitseryEngine::serialize(bytes,copy); return bytes;
}
inline String encodeRetiredConflictingClientRequest(const Request& request,
                                                    const MothershipRetainedRecoveryMixedProof& proof,
                                                    uint128_t retiredConflictingClientUUID) {
  require(retiredConflictingClientUUID != 0 && proof.staleExcludedContainerUUID == retiredConflictingClientUUID,
          "invalid retired conflicting-client request");
  Schema4RetiredConflictingClientRequest wrapped; wrapped.request.request=request;
  wrapped.request.proof=proof; wrapped.retiredConflictingClientUUID=retiredConflictingClientUUID;
  String bytes; BitseryEngine::serialize(bytes,wrapped); require(!bytes.empty(),"retired request serialization is empty");
  String framed={}; framed.append("RRF5",4); framed.append(bytes.data(),bytes.size()); return framed;
}
inline bool decodeRequest(const std::string& raw,Request& request,MothershipRetainedRecoveryMixedProof *proof,
                          uint128_t *retiredConflictingClientUUID = nullptr,
                          uint128_t *emptyRetainedInventoryMachineUUID = nullptr) {
  if (raw.size()>=4 && raw.compare(0,4,"RRF6")==0) {
    Schema6EmptyInventoryRequest wrapped;
    if (!BitseryEngine::deserializeSafe(text(raw.substr(4)),wrapped) ||
        wrapped.emptyRetainedInventoryMachineUUID == 0 ||
        wrapped.request.proof.canonicalContainerCount != 0 ||
        wrapped.request.proof.staleCoordinatorCanonicalContainerCount != 0 ||
        wrapped.request.proof.interruptedExpectedEchos != 0 ||
        wrapped.request.proof.staleExcludedContainerUUID != 0) return false;
    request=std::move(wrapped.request.request); if(proof)*proof=wrapped.request.proof;
    if(retiredConflictingClientUUID)*retiredConflictingClientUUID=0;
    if(emptyRetainedInventoryMachineUUID)*emptyRetainedInventoryMachineUUID=wrapped.emptyRetainedInventoryMachineUUID;
    return true;
  }
  if (raw.size()>=4 && raw.compare(0,4,"RRF5")==0) {
    Schema4RetiredConflictingClientRequest wrapped;
    if (!BitseryEngine::deserializeSafe(text(raw.substr(4)),wrapped) ||
        wrapped.retiredConflictingClientUUID == 0 ||
        wrapped.request.proof.staleExcludedContainerUUID != wrapped.retiredConflictingClientUUID ||
        wrapped.request.proof.canonicalContainerCount != wrapped.request.proof.staleCoordinatorCanonicalContainerCount + 1)
      return false;
    request=std::move(wrapped.request.request); if(proof)*proof=wrapped.request.proof;
    if(retiredConflictingClientUUID)*retiredConflictingClientUUID=wrapped.retiredConflictingClientUUID;
    if(emptyRetainedInventoryMachineUUID)*emptyRetainedInventoryMachineUUID=0; return true;
  }
  if (raw.size()>=4 && raw.compare(0,4,"RRF4")==0) {
    Schema4Request wrapped;
    if (!BitseryEngine::deserializeSafe(text(raw.substr(4)),wrapped) ||
        wrapped.proof.canonicalContainerCount==0 ||
        wrapped.proof.staleCoordinatorCanonicalContainerCount==0 ||
        wrapped.proof.staleCoordinatorCanonicalContainerCount>=wrapped.proof.canonicalContainerCount ||
        wrapped.proof.canonicalContainerCount>256 || wrapped.proof.interruptedExpectedEchos==0 || wrapped.proof.staleExcludedContainerUUID==0) return false;
    request=std::move(wrapped.request); if(proof)*proof=wrapped.proof;
    if(retiredConflictingClientUUID)*retiredConflictingClientUUID=0;
    if(emptyRetainedInventoryMachineUUID)*emptyRetainedInventoryMachineUUID=0; return true;
  }
  if (!BitseryEngine::deserializeSafe(text(raw),request)) return false;
  if(proof)*proof={}; if(retiredConflictingClientUUID)*retiredConflictingClientUUID=0;
  if(emptyRetainedInventoryMachineUUID)*emptyRetainedInventoryMachineUUID=0; return true;
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
  uint32_t canonicalContainerCount = 23;
  uint128_t emptyRetainedInventoryMachineUUID = 0;
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
  simdjson::dom::element declaredCanonicalCount;
  const bool hasDeclaredCanonicalCount=doc["canonicalContainerCount"].get(declaredCanonicalCount)==simdjson::SUCCESS;
  if (hasDeclaredCanonicalCount || p.schemaVersion >= 4) {
    uint64_t canonicalCount=0;
    require(hasDeclaredCanonicalCount && declaredCanonicalCount.get_uint64().get(canonicalCount)==simdjson::SUCCESS,
            "invalid declared canonical inventory count");
    require(canonicalCount<=256,"declared canonical inventory count overflow");
    m.canonicalContainerCount=uint32_t(canonicalCount);
    require(m.canonicalContainerCount>0 && m.canonicalContainerCount<=256,"invalid declared canonical inventory count");
    if (p.schemaVersion >= 4)
      require(m.canonicalContainerCount==p.sealedCanonicalContainerCount,"recovery manifest count differs from sealed plan");
  }

  require(prodigyIsSHA256HexDigest(m.request.bundleSHA),"invalid recovery bundle digest");
  simdjson::dom::array machines; require(doc["machines"].get_array().get(machines)==simdjson::SUCCESS,"recovery machines missing");
  bytell_hash_set<uint128_t> seenMachines,seenContainers; uint32_t canonical=0;
  for(auto item:machines) {
    MothershipRetainedRecoveryMachineInput machine; machine.machineUUID=uuid(field(item,"machineUUID"));
    const auto fragment=number(item,"machineFragment"); require(fragment>0 && fragment<=0xffffff,"invalid recovery machine fragment"); machine.machineFragment=fragment;
    require(seenMachines.insert(machine.machineUUID).second,"duplicate recovery machine");
    bool selected=false; for(const auto& expected:p.machines) selected|=expected.uuid==machine.machineUUID;
    require(selected,"unregistered recovery machine");
    simdjson::dom::element emptyInventory;
    const bool hasEmptyInventory=item["emptyRetainedInventory"].get(emptyInventory)==simdjson::SUCCESS;
    bool declaredEmptyInventory=false;
    if (hasEmptyInventory)
      require(emptyInventory.get_bool().get(declaredEmptyInventory)==simdjson::SUCCESS,
              "empty retained inventory declaration is not boolean");
    simdjson::dom::array records; require(item["records"].get_array().get(records)==simdjson::SUCCESS,"recovery process records missing");
    std::set<uint64_t> pids; uint32_t machineRecords=0;
    for(auto entry:records) {
      Record r; r.machine=machine.machineUUID;r.container=uuid(field(entry,"uuid"));r.pid=number(entry,"pid");r.created=number(entry,"createdAtMs");r.start=field(entry,"start");
      r.executableSHA=field(entry,"exeSHA256");r.paramsSHA=field(entry,"paramsSHA256");r.paramsPath=field(entry,"paramsPath");pathCheck(r.paramsPath);
      require(entry["canonical"].get_bool().get(r.canonical)==simdjson::SUCCESS,"missing canonical recovery membership");
      require(r.pid>1 && r.pid<=INT_MAX && r.created>0 && r.created<=INT64_MAX && r.start.find_first_not_of("0123456789")==std::string::npos &&
          prodigyIsSHA256HexDigest(text(r.executableSHA)) && prodigyIsSHA256HexDigest(text(r.paramsSHA)) && pids.insert(r.pid).second && seenContainers.insert(r.container).second,"invalid or duplicated recovery process identity");
      canonical+=r.canonical; ++machineRecords; m.records.push_back(std::move(r));
    }
    if (declaredEmptyInventory) {
      require(machineRecords==0 && m.emptyRetainedInventoryMachineUUID==0,
              "empty retained inventory declaration is invalid");
      m.emptyRetainedInventoryMachineUUID=machine.machineUUID;
    } else require(machineRecords!=0,"retained recovery machine has no sealed process inventory");
    m.request.machines.push_back(std::move(machine));
  }
  require(seenMachines.size()==3 && canonical==m.canonicalContainerCount,"recovery canonical inventory differs from sealed three-host declaration");
  return m;
}
inline void loadSnapshot(const std::string& path,ProdigyPersistentBrainSnapshot& snapshot) {
  require(fs::is_directory(path) && fs::is_directory(path+".secrets") && !fs::is_symlink(path) && !fs::is_symlink(path+".secrets"),"paired private recovery databases absent");
  ProdigyPersistentStateStore store(text(path)); String failure;
  require(store.loadBrainSnapshot(snapshot,&failure),"private recovery snapshot unreadable");
}
// Read-only companion to the retirement action.  It deliberately opens only
// the stopped copy and returns a compact coordinator kind; Mothership gathers
// all three kinds before it writes a retirement-started marker or signals a
// PID.  No state-store save path is reachable here.
inline bool verifyRetiredConflictingClientLocal(const char *requestPath,const char *statePath,
                                                uint128_t target,const String& previousBundleSHA256,
                                                String *kind,String *failure) {
  try {
    privateFile(requestPath); const std::string path=statePath; pathCheck(path);
    require(path.ends_with("/state.copy10"),"retirement verifier refuses a non-private state copy");
    Request request; MothershipRetainedRecoveryMixedProof proof; uint128_t encodedTarget=0;
    require(decodeRequest(read(requestPath),request,&proof,&encodedTarget) && encodedTarget==0 && target!=0 &&
            proof.staleExcludedContainerUUID==target && proof.canonicalContainerCount==24 &&
            proof.staleCoordinatorCanonicalContainerCount==23,"retirement verifier request differs from sealed proof");
    ProdigyPersistentBrainSnapshot snapshot;loadSnapshot(path,snapshot);
    require(proof.validFor(snapshot),"retirement verifier snapshot differs from frozen topology");
    const auto& update=snapshot.masterAuthority.runtimeState.updateSelf;
    const uint32_t count=mothershipRetainedRecoveryWitnessContainerCount(update.machineRecoveryWitnesses);
    if(count==proof.staleCoordinatorCanonicalContainerCount) kind->assign("stale23"_ctv);
    else if(count==proof.canonicalContainerCount && update.state==0 && update.expectedEchos==0) kind->assign("dormant24"_ctv);
    else if(count==proof.canonicalContainerCount && update.expectedEchos==proof.interruptedExpectedEchos) kind->assign("interrupted24"_ctv);
    else throw std::runtime_error("retirement verifier found an unrecognized coordinator");
    String why; require(mothershipPrepareRetiredConflictingClientSchema4Snapshot(snapshot,request.plans,request.machines,
        request.bundleSHA,previousBundleSHA256,request.interruptedBundleSHA,request.mixedSuccessorMachineUUIDs,
        proof,target,&why),str(why).c_str());
    return true;
  } catch(const std::exception& error) { if(failure)failure->assign(error.what()); return false; }
}
// Only the staged Mothership invokes this against its private paired copy.
inline bool prepareLocal(const char *requestPath,const char *statePath,bool verifyOnly,String *failure,const String& previousBundleSHA256={}) {
  try {
    privateFile(requestPath); const std::string path=statePath;pathCheck(path);
    require(path.ends_with("/state.new10") || (verifyOnly && path=="/var/lib/prodigy/state"),"recovery suboperation refuses an unowned database path");
    require(::getenv("PRODIGY_STATE_SECRETS_DB")==nullptr,"recovery refuses a secrets-path override");
    Request request; MothershipRetainedRecoveryMixedProof proof; uint128_t retiredConflictingClientUUID=0, emptyRetainedInventoryMachineUUID=0;
    require(decodeRequest(read(requestPath),request,&proof,&retiredConflictingClientUUID,&emptyRetainedInventoryMachineUUID),"recovery request decode failed");
    require(emptyRetainedInventoryMachineUUID == 0 || request.interruptedBundleSHA.empty(),
            "empty retained inventory cannot reinterpret an interrupted handoff");
    ProdigyPersistentBrainSnapshot before;loadSnapshot(path,before);require(before.brainConfig.clusterUUID==request.clusterUUID,"recovery request targets another cluster");
    require(!proof.canonicalContainerCount || proof.validFor(before),"recovery request proof differs from frozen topology");
    const auto witnessPath=std::string(requestPath)+".witnesses";privateFile(witnessPath);
    WitnessSet sealed;require(BitseryEngine::deserializeSafe(text(read(witnessPath)),sealed) && sealed.requestSHA==text(digest(requestPath)),"sealed recovery witnesses differ from request");
    // An interrupted normal update is active too. Only the recovery envelope
    // may skip a generation increment on retry; verify its witnesses below.
    const bool alreadyPrepared=mothershipRetainedRecoveryEnvelopeMatches(before.masterAuthority.runtimeState.updateSelf,request.bundleSHA);
    require(!verifyOnly || alreadyPrepared,"recovery snapshot is not prepared");
    auto expected=before;
    if(alreadyPrepared && retiredConflictingClientUUID == 0) {
      expected.masterAuthority.runtimeState.updateSelf={};
      require(expected.masterAuthority.runtimeState.generation>0,"recovery generation missing"); --expected.masterAuthority.runtimeState.generation;
    }
    String why;
    const bool mixed = !request.interruptedBundleSHA.empty();
    if (retiredConflictingClientUUID != 0) {
      if (alreadyPrepared) {
        expected.masterAuthority.runtimeState.updateSelf={};
        require(expected.masterAuthority.runtimeState.generation>0,"retired recovery generation missing");
        --expected.masterAuthority.runtimeState.generation;
        for(const auto& state:expected.masterAuthority.containerRuntimeStates)
          require(state.plan.uuid!=retiredConflictingClientUUID,"prepared retired recovery retains its canonical runtime target");
        require(mothershipPrepareRetainedRecoverySnapshot(expected,request.plans,request.machines,
                request.bundleSHA,&why,previousBundleSHA256,request.interruptedBundleSHA,0,nullptr,false,false,
                emptyRetainedInventoryMachineUUID),str(why).c_str());
      } else {
      // RRF5 never stands alone: the adjacent immutable RRF4 source is
      // uploaded with it and is revalidated against this private copy before
      // the selected 23-record envelope is admitted.
      const std::string originalPath=std::string(requestPath)+".original"; privateFile(originalPath);
      Request original; MothershipRetainedRecoveryMixedProof originalProof; uint128_t originalRetired=0;
      require(decodeRequest(read(originalPath),original,&originalProof,&originalRetired) && originalRetired==0 &&
              originalProof.staleExcludedContainerUUID==retiredConflictingClientUUID &&
              originalProof.canonicalContainerCount==proof.canonicalContainerCount &&
              originalProof.staleCoordinatorCanonicalContainerCount==proof.staleCoordinatorCanonicalContainerCount &&
              original.machines.size()==3,"retired recovery source request differs");
      require(original.clusterUUID==request.clusterUUID && original.bundleSHA==request.bundleSHA &&
              original.interruptedBundleSHA==request.interruptedBundleSHA && original.plans.size()==request.plans.size() &&
              original.machines.size()==request.machines.size(),
              "retired recovery projection changes the sealed request authority");
      uint32_t projectedTargetCount=0;
      for(uint32_t machineIndex=0;machineIndex<original.machines.size();++machineIndex) {
        const auto& full=original.machines[machineIndex]; const auto& projected=request.machines[machineIndex];
        uint32_t targetCount=0; for(const auto& parameters:full.parameters) targetCount+=parameters.uuid==retiredConflictingClientUUID;
        require(full.machineUUID==projected.machineUUID && full.machineFragment==projected.machineFragment &&
                full.parameters.size()==projected.parameters.size()+targetCount &&
                full.observedCreatedAtMs.size()==full.parameters.size() &&
                projected.observedCreatedAtMs.size()==projected.parameters.size(),"retired recovery projection changes a machine inventory");
        projectedTargetCount+=targetCount;
        uint32_t projectedIndex=0;
        for(uint32_t fullIndex=0;fullIndex<full.parameters.size();++fullIndex) {
          if(full.parameters[fullIndex].uuid==retiredConflictingClientUUID) continue;
          require(projectedIndex<projected.parameters.size(),"retired recovery projection truncates a machine inventory");
          const auto plan=original.plans.find(full.parameters[fullIndex].deploymentID);
          require(plan!=original.plans.end() && projected.parameters[projectedIndex].deploymentID==plan->first,
                  "retired recovery projection changes deployment authority");
          NeuronContainerBootstrap left={},right={}; String leftFailure={},rightFailure={};
          require(prodigyBuildRetainedContainerBootstrap(plan->second,full.parameters[fullIndex],full.machineFragment,
                  before.brainConfig.datacenterFragment,full.observedCreatedAtMs[fullIndex],left,&leftFailure) &&
                  prodigyBuildRetainedContainerBootstrap(plan->second,projected.parameters[projectedIndex],projected.machineFragment,
                  before.brainConfig.datacenterFragment,projected.observedCreatedAtMs[projectedIndex],right,&rightFailure) &&
                  prodigyPersistentRetainedBootstrapEqual(left,right) && full.observedCreatedAtMs[fullIndex]==projected.observedCreatedAtMs[projectedIndex++],
                  "retired recovery projection changes a retained container");
        }
        require(projectedIndex==projected.parameters.size(),"retired recovery projection contains an unknown container");
      }
      require(projectedTargetCount==1,"retired recovery projection omits a different container");
      require(mothershipPrepareRetiredConflictingClientSchema4Snapshot(expected,original.plans,original.machines,
              request.bundleSHA,previousBundleSHA256,original.interruptedBundleSHA,
              original.mixedSuccessorMachineUUIDs,originalProof,retiredConflictingClientUUID,&why),str(why).c_str());
      }
    } else if (mixed) {
      require(prodigyIsSHA256HexDigest(request.interruptedBundleSHA) &&
              (proof.canonicalContainerCount ? request.mixedSuccessorMachineUUIDs.size()==1 : request.mixedSuccessorMachineUUIDs.size()==2),
              "invalid sealed mixed handoff");
      for (size_t i=0;i<request.mixedSuccessorMachineUUIDs.size();++i)
        require(request.mixedSuccessorMachineUUIDs[i]!=0 && (!i || request.mixedSuccessorMachineUUIDs[i-1]<request.mixedSuccessorMachineUUIDs[i]),"invalid sealed mixed handoff");
      if (!mothershipPrepareRetainedRecoverySnapshot(expected,request.plans,request.machines,
                                                     request.bundleSHA,&why,previousBundleSHA256,
                                                     request.interruptedBundleSHA,0,nullptr,false,true,
                                                     emptyRetainedInventoryMachineUUID)) {
        // A successor can retain the sealed interrupted envelope or a later
        // pre-exec echo collection with the known earlier digest failure.
        // Both forms prove the same inventory before the old coordinator's
        // later handoff case is considered.
        expected=before;
        if (!(proof.canonicalContainerCount ?
              mothershipPrepareRetainedRecoverySchema4Snapshot(
                  expected,request.plans,request.machines,request.bundleSHA,
                  previousBundleSHA256,request.interruptedBundleSHA,
                  request.mixedSuccessorMachineUUIDs,proof,&why) :
              mothershipPrepareRetainedRecoveryMixedInterruptedSnapshot(
                  expected,request.plans,request.machines,request.bundleSHA,
                  previousBundleSHA256,request.interruptedBundleSHA,
                  request.mixedSuccessorMachineUUIDs,&why))) {
          expected=before;
          require(!proof.canonicalContainerCount && mothershipPrepareRetainedRecoveryMixedHandoffSnapshot(
              expected,request.plans,request.machines,request.bundleSHA,
              previousBundleSHA256,request.interruptedBundleSHA,
              request.mixedSuccessorMachineUUIDs,&why),str(why).c_str());
        }
      }
    } else {
      require(mothershipPrepareRetainedRecoverySnapshot(expected,request.plans,request.machines,
                                                        request.bundleSHA,&why,previousBundleSHA256,{},0,nullptr,false,true,
                                                        emptyRetainedInventoryMachineUUID),str(why).c_str());
    }
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
enum class InventoryMode { sealed, canonical, remaining, retire, retireConflictingClient };
inline std::string inventoryProgram(const std::string& manifestPath,const MothershipTidesMigration::Machine& machine,
                                    InventoryMode mode,uint128_t retiredConflictingClientUUID=0) {
  require(mode != InventoryMode::retireConflictingClient || retiredConflictingClientUUID != 0,
          "missing sealed conflicting-client retirement UUID");
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
  else if(mode!=InventoryMode::retireConflictingClient) code+=R"PY(expected={(str(int(r['uuid'],16)),r['pid']) for r in records}
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
  if(mode==InventoryMode::retireConflictingClient) {
    String target;target.snprintf<"{itoh}"_ctv>(retiredConflictingClientUUID);
    code+=R"PY(target=str(int(")PY"+str(target)+R"PY(",16))
matches=[r for r in records if str(int(r['uuid'],16))==target]
assert len(matches)==1 and matches[0]['canonical'],'sealed conflicting-client target differs'
r=matches[0];base=pathlib.Path('/proc')/str(r['pid'])
if base.exists():
 fd=os.pidfd_open(r['pid'],0)
 try:
  verify(r); signal.pidfd_send_signal(fd,signal.SIGTERM)
  for _ in range(50):
   if not base.exists():break
   time.sleep(.1)
  if base.exists():
   verify(r); signal.pidfd_send_signal(fd,signal.SIGKILL)
   for _ in range(50):
    if not base.exists():break
    time.sleep(.1)
  assert not base.exists(),'retired conflicting client did not exit'
 finally:os.close(fd)
assert not base.exists(),'retired conflicting client PID changed'
print('sealed conflicting client retired')
)PY";
  }
  return "python3 -c "+quote(code);
}
// The immutable manifest remains the authority for identity checks.  The
// derived manifest is a bounded receipt: it changes exactly one canonical bit
// after the target process has exited; it never names or touches storage.
inline std::string derivedConflictingClientManifestProgram(const std::string& manifestPath,uint128_t targetUUID) {
  String target;target.snprintf<"{itoh}"_ctv>(targetUUID);
  std::string code="import json\nm=json.load(open("+quote(manifestPath)+"))\nt='"+str(target)+"'\nfound=[]\nfor machine in m['machines']:\n for record in machine['records']:\n  if int(record['uuid'],16)==int(t,16):found.append(record)\nassert len(found)==1 and found[0]['canonical']\nassert m['canonicalContainerCount']>0\nfound[0]['canonical']=False\nm['canonicalContainerCount']-=1\nprint(json.dumps(m,sort_keys=True,separators=(',',':')))\n";
  return "python3 -c "+quote(code);
}
inline std::string conflictingClientStorageProgram(const std::string& manifestPath,uint128_t targetUUID,bool afterExit) {
  String target;target.snprintf<"{itoh}"_ctv>(targetUUID);
  std::string code="import json,os,pathlib\nm=json.load(open("+quote(manifestPath)+"))\nt=int('"+str(target)+"',16)\nr=[r for x in m['machines'] for r in x['records'] if int(r['uuid'],16)==t]\nassert len(r)==1\nr=r[0];host=pathlib.Path('/containers/storage')/str(t);kv=host/'kvdb'\nh=host.stat();k=kv.stat();assert host.is_dir() and kv.is_dir()\n";
  if(!afterExit) code+="p=pathlib.Path('/proc')/str(r['pid'])/'root'/'storage';s=p.stat();q=(p/'kvdb').stat();assert (s.st_dev,s.st_ino)==(h.st_dev,h.st_ino) and (q.st_dev,q.st_ino)==(k.st_dev,k.st_ino)\n";
  code+="print(f'{h.st_dev}:{h.st_ino} {k.st_dev}:{k.st_ino} {host}')\n";
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
  if(index.size()!=left.canonicalContainerCount || left.canonicalContainerCount!=right.canonicalContainerCount)return false;
  uint32_t canonical=0;
  for(const auto& record:right.records) {
    if(!record.canonical)continue;
    canonical++;
    const auto found=index.find(record.container); if(found==index.end())return false;
    const auto& expected=*found->second;
    if(expected.machine!=record.machine || expected.pid!=record.pid || expected.created!=record.created || expected.start!=record.start || expected.executableSHA!=record.executableSHA || expected.paramsSHA!=record.paramsSHA || expected.paramsPath!=record.paramsPath)return false;
  }
  return canonical==left.canonicalContainerCount;
}
inline bool retainedRecoveryHasMixedInstalledPredecessors(const Plan& plan) {
  std::set<std::pair<std::string,std::string>> installed;
  for (const auto& machine : plan.machines)
    installed.emplace(machine.installedRuntimeSHA,machine.installedBundleSHA);
  return installed.size() > 1;
}
inline bool samePlanTarget(const Plan& oldPlan,const Plan& successor) {
  if(oldPlan.operationID==successor.operationID || oldPlan.operationRoot==successor.operationRoot || oldPlan.schemaVersion!=successor.schemaVersion || oldPlan.clusterUUID!=successor.clusterUUID || oldPlan.identity!=successor.identity || oldPlan.registryRoot!=successor.registryRoot || oldPlan.runtimeRoot!=successor.runtimeRoot || oldPlan.statePath!=successor.statePath || oldPlan.secretsPath!=successor.secretsPath || oldPlan.oldRuntimeSHA!=successor.oldRuntimeSHA || oldPlan.oldBundleSHA!=successor.oldBundleSHA || oldPlan.serviceRuntimeSHA!=successor.serviceRuntimeSHA || oldPlan.serviceBundleSHA!=successor.serviceBundleSHA || oldPlan.serviceBundlePath!=successor.serviceBundlePath || oldPlan.sealedCanonicalContainerCount!=successor.sealedCanonicalContainerCount || oldPlan.staleCoordinatorCanonicalContainerCount!=successor.staleCoordinatorCanonicalContainerCount || oldPlan.sealedInterruptedExpectedEchos!=successor.sealedInterruptedExpectedEchos || oldPlan.staleExcludedContainerUUID!=successor.staleExcludedContainerUUID || oldPlan.mixedPredecessors!=successor.mixedPredecessors || oldPlan.machines.size()!=successor.machines.size() || oldPlan.approvedPredecessors.size()!=successor.approvedPredecessors.size())return false;
  for(size_t i=0;i<oldPlan.machines.size();++i)if(oldPlan.machines[i].uuid!=successor.machines[i].uuid || oldPlan.machines[i].linuxID!=successor.machines[i].linuxID || oldPlan.machines[i].address!=successor.machines[i].address || oldPlan.machines[i].runtimeRoot!=successor.machines[i].runtimeRoot || oldPlan.machines[i].installedRuntimeSHA!=successor.machines[i].installedRuntimeSHA || oldPlan.machines[i].installedBundleSHA!=successor.machines[i].installedBundleSHA)return false;
  for(size_t i=0;i<oldPlan.approvedPredecessors.size();++i)if(oldPlan.approvedPredecessors[i].runtimeSHA!=successor.approvedPredecessors[i].runtimeSHA || oldPlan.approvedPredecessors[i].bundleSHA!=successor.approvedPredecessors[i].bundleSHA || oldPlan.approvedPredecessors[i].bundlePath!=successor.approvedPredecessors[i].bundlePath)return false;
  return true;
}
inline bool sameContainedSuccessorTarget(const Plan& predecessor,const MothershipTidesDBMigrationReceipt& receipt,const Plan& successor) {
  // A mixed predecessor has multiple prior executable roots.  The existing
  // contained-successor protocol has one active receipt identity, so refuse
  // to reinterpret it as a mixed handoff.
  if(predecessor.mixedPredecessors || successor.mixedPredecessors)return false;
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
      "; test \"$(sha256sum "+quote(e.activeRuntimeRoot(machine)+"/prodigy")+" | cut -d' ' -f1)\" = "+quote(machine.installedRuntimeSHA)+
      "; test \"$(sha256sum "+quote(e.activeRuntimeRoot(machine)+"/prodigy.bundle.tar.zst")+" | cut -d' ' -f1)\" = "+quote(machine.installedBundleSHA));
  }
}
// A repair bundle supplies tools only. It cannot replace the deployment bundle,
// its receipt, or the writer fence. The invoking Mothership must itself be one
// of the checked Discombobulator outputs in that bundle.
inline std::string stageRepairTools(Execution& e,const char *repairBundle) {
  pathCheck(repairBundle); String approved,why;
  require(prodigyApproveBundleArtifact(text(repairBundle),approved,&why),"recovery tool bundle not approved");
  Plan helperPlan=e.plan;helperPlan.operationRoot+="/tool-"+str(approved);helperPlan.bundle=repairBundle;
  Execution helper(std::move(helperPlan));helper.cluster=e.cluster;helper.machines=e.machines;helper.receipt=e.receipt;
  fs::create_directories(helper.plan.operationRoot);require(::chmod(helper.plan.operationRoot.c_str(),0700)==0,"cannot protect recovery tool directory");
  require(prodigyInstallBundleToRoot(text(repairBundle),text(helper.localRuntime),&why),"recovery tool staging failed");
  require(digest("/proc/self/exe")==digest(helper.localRuntime+"/tools/mothership"),"repair bundle does not contain this Mothership");
  helper.receipt.approvedBundleSHA256=approved;helper.receipt.newRuntimeSHA256=text(digest(helper.localRuntime+"/prodigy"));
  helper.buildArtifactManifest();helper.stageAndPreflight();return helper.remoteRuntime;
}
inline std::string containedGuard(const Execution& e) {
  return "test \"$(systemctl show -p MainPID --value prodigy)\" = 0; test \"$(cat "+quote(e.fencePath())+")\" = "+quote(e.plan.planSHA)+
    "; test \"$(sha256sum "+quote(e.plan.runtimeRoot+"/prodigy")+" | cut -d' ' -f1)\" = "+quote(str(e.receipt.newRuntimeSHA256))+
    "; test \"$(sha256sum "+quote(e.plan.runtimeRoot+"/prodigy.bundle.tar.zst")+" | cut -d' ' -f1)\" = "+quote(str(e.receipt.approvedBundleSHA256))+"; "+
    e.observeContainers()+"snapshot_containers > "+quote(e.remoteRoot+"/containers.compact-check")+"; cmp "+quote(e.remoteRoot+"/containers.contained")+" "+quote(e.remoteRoot+"/containers.compact-check")+"; ";
}
inline std::string compactionBaselineSHA(const std::string& output) {
  simdjson::dom::parser parser;simdjson::dom::element doc;bool complete=false;
  require(parser.parse(output).get(doc)==simdjson::SUCCESS && doc["reclaimComplete"].get_bool().get(complete)==simdjson::SUCCESS && complete,
          "compaction result is incomplete");
  const auto sha=field(doc,"logicalSHA256");
  require(prodigyIsSHA256HexDigest(text(sha)),"invalid compaction baseline digest");
  return sha;
}
inline void compactContained(Execution& e,const char *repairBundle) {
  require(repairBundle && e.receipt.activationBoundaryCrossed && e.receipt.phase==MothershipTidesDBMigrationPhase::completed,
          "compaction requires a contained completed recovery and a sealed tool bundle");
  // This baseline was captured by contain-active after stopping the Brains. It
  // deliberately retains their current processes, including a degraded fleet;
  // it does not grant permission to launch replacements or retire survivors.
  const auto guard=containedGuard(e);
  for(const auto& machine:e.plan.machines)e.run(machine.uuid,guard);
  const auto runtime=stageRepairTools(e,repairBundle);
  for(const auto& db:e.receipt.databases) {
    require(db.machineUUID!=0 && db.swapped && (str(db.livePath)==e.plan.statePath || str(db.livePath)==e.plan.secretsPath),
            "contained maintenance requires the active paired Brain databases");
    const auto label=str(db.label);
    require(!label.empty() && label.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")==std::string::npos,
            "invalid compaction database label");
    const auto baseline=e.remoteRoot+"/compact-"+label+".kv", capture=baseline+".result.json";
    // The helper persists the current logical stream before maintenance and
    // refuses a retry if that baseline has changed. Original retained databases
    // and migration streams are never opened or removed here.
    e.run(db.machineUUID,guard+"umask 077; if ! LD_LIBRARY_PATH="+quote(runtime+"/lib")+" "+quote(runtime+"/tools/prodigy_tidesdb10_import")+
          " --compact "+quote(str(db.livePath))+" "+quote(baseline)+" > "+quote(capture)+"; then exit 1; fi; "+guard);
    const auto output=e.readPath(db.machineUUID,capture);
    (void)compactionBaselineSHA(output);
    String machine;machine.snprintf<"{itoh}"_ctv>(db.machineUUID);
    durable(fs::path(e.plan.operationRoot)/("compact-"+str(machine)+"-"+label+".json"),text(output));
  }
  for(const auto& machine:e.plan.machines)e.run(machine.uuid,guard);
  durable(fs::path(e.plan.operationRoot)/"compacted-contained",text(e.plan.planSHA+"\n"+digest(repairBundle)+"\n"));
}
inline void resumeCompacted(Execution& e,const char *repairBundle) {
  require(repairBundle && e.receipt.activationBoundaryCrossed && e.receipt.phase==MothershipTidesDBMigrationPhase::completed,
          "resume requires a contained completed recovery and its maintenance tools");
  const auto marker=e.plan.operationRoot+"/compacted-contained";
  privateFile(marker,4096);
  const auto binding=e.plan.planSHA+"\n"+digest(repairBundle)+"\n";
  require(read(marker)==binding,"resume maintenance bundle differs");
  require(!fs::exists(e.plan.operationRoot+"/compaction-resume-started"),"resume already started; inspect the running generation before another lifecycle action");
  const auto guard=containedGuard(e);
  for(const auto& machine:e.plan.machines)e.run(machine.uuid,guard);
  const auto runtime=stageRepairTools(e,repairBundle);
  for(const auto& db:e.receipt.databases) {
    String machine;machine.snprintf<"{itoh}"_ctv>(db.machineUUID);
    const auto label=str(db.label),result=e.plan.operationRoot+"/compact-"+str(machine)+"-"+label+".json";
    privateFile(result,65536);
    const auto baseline=e.remoteRoot+"/compact-"+label+".kv",sha=compactionBaselineSHA(read(result));
    e.run(db.machineUUID,guard+"test \"$(sha256sum "+quote(baseline)+" | cut -d' ' -f1)\" = "+quote(sha)+
          "; LD_LIBRARY_PATH="+quote(runtime+"/lib")+" "+quote(runtime+"/tools/prodigy_tidesdb10_import")+" --verify "+quote(baseline)+" "+quote(str(db.livePath)));
  }
  // Verify every host and logical database before the first fence is removed.
  // Resume the same installed generation; its persisted normal update/recovery
  // operations continue through their existing owners after reconnect.
  for(const auto& machine:e.plan.machines)e.run(machine.uuid,guard);
  durable(fs::path(e.plan.operationRoot)/"compaction-resume-started",text(binding));
  e.activate();
  durable(fs::path(e.plan.operationRoot)/"compaction-resumed",text(binding));
}
inline bool runFile(const char *file,const char *action,String *failure=nullptr,const char *repairBundle=nullptr,const char *successorFile=nullptr) {
  try {
    require(std::strcmp(action,"recover")==0 || std::strcmp(action,"prepare")==0 || std::strcmp(action,"retire-extras")==0 || std::strcmp(action,"retire-extras-preactivation")==0 || std::strcmp(action,"check-conflicting-client-preactivation")==0 || std::strcmp(action,"retire-conflicting-client-preactivation")==0 || std::strcmp(action,"supersede-preactivation")==0 || std::strcmp(action,"contain-active")==0 || std::strcmp(action,"compact-contained")==0 || std::strcmp(action,"resume-compacted")==0,"invalid retained recovery action");
    Plan plan=parse(file);plan.retainedRecovery=true;
    simdjson::dom::parser parser;simdjson::dom::element doc;auto raw=read(file);require(parser.parse(raw).get(doc)==simdjson::SUCCESS,"invalid recovery plan");
    bool mode=false;require(doc["retainedRecoveryMode"].get_bool().get(mode)==simdjson::SUCCESS && mode,"explicit retained recovery mode required");
    const auto manifestPath=field(doc,"retainedManifestPath"), manifestSHA=field(doc,"retainedManifestSHA256");pathCheck(manifestPath);
    require(digest(manifestPath)==manifestSHA,"retained manifest digest mismatch");
    Manifest manifest=parseManifest(manifestPath,plan);
    Execution e(std::move(plan));e.initialize();
    require(manifest.emptyRetainedInventoryMachineUUID == 0 || !e.plan.mixedPredecessors,
            "empty retained inventory requires a uniform fresh recovery plan");
    require(manifest.request.bundleSHA==e.receipt.approvedBundleSHA256,"retained manifest bundle mismatch");
    // The same outer Mothership client lock excludes registry writers. Reading
    // the existing v10 registry uses its normal owner, never the v9 exporter.
    { MothershipClusterRegistry registry(text(e.plan.registryRoot+"/clusters"));String why;
      require(registry.getClusterByIdentity(text(e.plan.identity),e.cluster,&why),"v10 registry authority unavailable"); }
    require(e.cluster.clusterUUID==e.plan.clusterUUID && e.cluster.nBrains==3 && e.cluster.machines.size()==3 && str(e.cluster.remoteProdigyPath)==e.plan.runtimeRoot,"retained cluster authority differs");
    for(auto& m:e.plan.machines) {resolveRegisteredMachine(e.cluster,m);e.machines.emplace(m.uuid,&m);}
    e.buildArtifactManifest();
    const auto conflictingRetiredMarker=e.plan.operationRoot+"/conflicting-client-retired";
    const bool conflictingClientRetired=fs::exists(conflictingRetiredMarker);
    if(conflictingClientRetired) privateFile(conflictingRetiredMarker,4096);
    auto verify=[&](InventoryMode mode=InventoryMode::sealed) {
      const bool derived=conflictingClientRetired && mode==InventoryMode::sealed;
      for(auto& m:e.plan.machines)e.run(m.uuid,inventoryProgram(e.remoteRoot+(derived?"/retained-manifest.retired-conflicting-client.json":"/retained-manifest.json"),m,derived?InventoryMode::canonical:mode));
    };
    const auto containment=e.plan.operationRoot+"/activation-contained";
    if(std::strcmp(action,"contain-active")==0) {
      require(e.receipt.activationBoundaryCrossed && e.receipt.phase==MothershipTidesDBMigrationPhase::completed,"containment requires a completed activated operation");
      // Validate the installed generation on every host before fencing any host.
      // Never roll back a database that has had v10 writers.
      for(const auto& machine:e.plan.machines)e.run(machine.uuid,
        "test \"$(sha256sum "+quote(e.serviceRuntimeRoot()+"/prodigy")+" | cut -d' ' -f1)\" = "+quote(str(e.receipt.newRuntimeSHA256))+
        "; test \"$(sha256sum "+quote(e.serviceRuntimeRoot()+"/prodigy.bundle.tar.zst")+" | cut -d' ' -f1)\" = "+quote(str(e.receipt.approvedBundleSHA256)));
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
    if(std::strcmp(action,"compact-contained")==0) {
      require(predecessorContained && !successorFile && !fs::exists(e.plan.operationRoot+"/superseded-by") && !fs::exists(e.plan.operationRoot+"/compaction-resume-started"),"compaction requires the current contained operation");
      compactContained(e,repairBundle);return true;
    }
    if(std::strcmp(action,"resume-compacted")==0) {
      require(predecessorContained && !successorFile && !fs::exists(e.plan.operationRoot+"/superseded-by"),"resume requires the current contained operation");
      resumeCompacted(e,repairBundle);return true;
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
    if(std::strcmp(action,"check-conflicting-client-preactivation")==0 || std::strcmp(action,"retire-conflicting-client-preactivation")==0) {
      const bool readOnlyCheck=std::strcmp(action,"check-conflicting-client-preactivation")==0;
      require(e.plan.schemaVersion==4 && e.plan.sealedCanonicalContainerCount==24 &&
              e.plan.staleCoordinatorCanonicalContainerCount==23 &&
              e.plan.staleExcludedContainerUUID!=0 &&
              e.receipt.phase<=MothershipTidesDBMigrationPhase::writersQuiesced && !e.receipt.activationBoundaryCrossed,
              "conflicting-client retirement requires the sealed schema-four preactivation inventory");
      const auto originalRequestPath=e.plan.operationRoot+"/recovery.request";
      const auto derivedRequestPath=e.plan.operationRoot+"/recovery.request.retired-conflicting-client";
      const auto derivedManifestPath=e.plan.operationRoot+"/retained-manifest.retired-conflicting-client.json";
      const auto started=e.plan.operationRoot+"/conflicting-client-retirement-started";
      const auto completed=e.plan.operationRoot+"/conflicting-client-retired";
      const auto authority=e.plan.operationRoot+"/conflicting-client-retirement-authority";
      privateFile(originalRequestPath); Request original; MothershipRetainedRecoveryMixedProof proof; uint128_t encodedTarget=0;
      require(decodeRequest(read(originalRequestPath),original,&proof,&encodedTarget) && encodedTarget==0 &&
              proof.canonicalContainerCount==24 && proof.staleCoordinatorCanonicalContainerCount==23 &&
              proof.staleExcludedContainerUUID==e.plan.staleExcludedContainerUUID,
              "immutable schema-four recovery request differs from sealed retirement proof");
      require(original.machines.size()==3 && original.mixedSuccessorMachineUUIDs.size()==1,
              "immutable schema-four recovery request has no sealed mixed predecessor proof");
      const uint128_t target=e.plan.staleExcludedContainerUUID;
      String targetText;targetText.snprintf<"{itoh}"_ctv>(target);
      for(auto& machine:e.plan.machines)e.upload(machine,originalRequestPath,e.remoteRoot+"/recovery.request.original");
      uint32_t stale23=0, full24=0;
      for(uint32_t index=0;index<e.plan.machines.size();++index) {
        String output,why;
        const std::string command="LD_LIBRARY_PATH="+quote(e.remoteRuntime+"/lib")+" "+quote(e.remoteRuntime+"/tools/mothership")+
          " verifyRetiredConflictingClientLocal "+quote(e.remoteRoot+"/recovery.request.original")+" "+quote(e.remoteRoot+"/state.copy10")+
          " "+quote(str(targetText))+" "+quote(e.plan.oldBundleSHA);
        if (!e.command(e.plan.machines[index].uuid,command,&why,&output,30'000)) {
          String host;host.snprintf<"{itoh}"_ctv>(e.plan.machines[index].uuid);
          String diagnostic;diagnostic.snprintf<"conflicting-client private-copy validation failed machine {}: {}"_ctv>(host,why);
          require(false,str(diagnostic).c_str());
        }
        const auto report=str(output);
        if(report.find("kind=stale23")!=std::string::npos) ++stale23;
        if(report.find("kind=dormant24")!=std::string::npos || report.find("kind=interrupted24")!=std::string::npos) ++full24;
        if(index==0) require(report.find("kind=dormant24")!=std::string::npos || report.find("kind=interrupted24")!=std::string::npos,
                              "selected seed does not retain the full schema-four coordinator proof");
      }
      require(stale23>=1 && full24>=1,"all three private recovery copies do not prove the sealed stale23/full24 transition");
      if(readOnlyCheck) return true;
      if(!fs::exists(completed)) {
        require(!fs::exists(started) || fs::is_regular_file(started),"conflicting-client retirement checkpoint is unsafe");
        // Validate the full sealed 24-record request and its stale 23-witness
        // proof before touching one PID.  This copies only the stopped seed
        // authority; it does not write a database or alter a container mount.
        Request derived=original; uint32_t removed=0;
        for(auto& machine:derived.machines) {
          Vector<ContainerParameters> parameters; Vector<int64_t> created;
          for(uint32_t index=0;index<machine.parameters.size();++index) {
            if(machine.parameters[index].uuid==target) {++removed;continue;}
            parameters.push_back(std::move(machine.parameters[index])); created.push_back(machine.observedCreatedAtMs[index]);
          }
          machine.parameters=std::move(parameters); machine.observedCreatedAtMs=std::move(created);
        }
        require(removed==1,"sealed conflicting-client target is absent from immutable request");
        if(!fs::exists(derivedRequestPath)) durable(derivedRequestPath,encodeRetiredConflictingClientRequest(derived,proof,target));
        String generated,whyRemote;
        require(e.command(e.plan.machines[0].uuid,derivedConflictingClientManifestProgram(manifestPath,target),&whyRemote,&generated,30'000),
                "unable to derive sealed conflicting-client manifest");
        require(!generated.empty(),"derived conflicting-client manifest is empty");
        if(!fs::exists(derivedManifestPath)) durable(derivedManifestPath,generated);
        privateFile(derivedManifestPath,1024*1024);
        const auto targetRecord=std::find_if(manifest.records.begin(),manifest.records.end(),[&](const auto& record){return record.container==target;});
        require(targetRecord!=manifest.records.end(),"sealed conflicting-client target is absent from manifest");
        const auto storageReceipt=e.plan.operationRoot+"/conflicting-client-retired-storage";
        if(!fs::exists(storageReceipt)) {
          String storage,storageFailure;
          require(e.command(targetRecord->machine,conflictingClientStorageProgram(e.remoteRoot+"/retained-manifest.json",target,false),&storageFailure,&storage,30'000),
                  "conflicting-client storage mount proof failed");
          durable(storageReceipt,storage);
        }
        privateFile(storageReceipt,4096);
        const String marker=text(e.plan.planSHA+"\n"+manifestSHA+"\n"+digest(originalRequestPath)+"\n"+digest(derivedManifestPath)+"\n"+digest(derivedRequestPath)+"\n"+str(targetText)+"\n");
        const bool newlyStarted=!fs::exists(started);
        if(!newlyStarted) { privateFile(started,4096); require(read(started)==str(marker),"conflicting-client retirement start differs"); }
        else durable(started,marker);
        for(auto& machine:e.plan.machines)e.upload(machine,derivedManifestPath,e.remoteRoot+"/retained-manifest.retired-conflicting-client.json");
        if(newlyStarted) verify(InventoryMode::sealed);
        for(auto& machine:e.plan.machines) if(machine.uuid==targetRecord->machine)
          e.run(machine.uuid,inventoryProgram(e.remoteRoot+"/retained-manifest.json",machine,InventoryMode::retireConflictingClient,target));
        String afterStorage,afterStorageFailure;
        require(e.command(targetRecord->machine,conflictingClientStorageProgram(e.remoteRoot+"/retained-manifest.json",target,true),&afterStorageFailure,&afterStorage,30'000) &&
                str(afterStorage)==read(storageReceipt),"conflicting-client storage changed during PID retirement");
        for(auto& machine:e.plan.machines)e.run(machine.uuid,inventoryProgram(e.remoteRoot+"/retained-manifest.retired-conflicting-client.json",machine,InventoryMode::canonical));
        // pidfd retirement leaves /containers/storage and its mounts alone.
        e.acceptStoppedContainerBaseline(); durable(authority,marker); durable(completed,marker); return true;
      }
      privateFile(completed,4096); require(fs::exists(derivedManifestPath) && fs::exists(derivedRequestPath),"completed conflicting-client retirement artifacts absent");
      privateFile(derivedManifestPath,1024*1024); privateFile(derivedRequestPath,1024*1024);
      const String marker=text(e.plan.planSHA+"\n"+manifestSHA+"\n"+digest(originalRequestPath)+"\n"+digest(derivedManifestPath)+"\n"+digest(derivedRequestPath)+"\n"+str(targetText)+"\n");
      require(read(completed)==str(marker),"completed conflicting-client retirement differs");
      privateFile(authority,4096); require(read(authority)==str(marker),"conflicting-client retirement authority differs");
      for(auto& machine:e.plan.machines)e.upload(machine,derivedManifestPath,e.remoteRoot+"/retained-manifest.retired-conflicting-client.json");
      for(auto& machine:e.plan.machines)e.run(machine.uuid,inventoryProgram(e.remoteRoot+"/retained-manifest.retired-conflicting-client.json",machine,InventoryMode::canonical));
      return true;
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
      if(e.receipt.phase<MothershipTidesDBMigrationPhase::validated) {
        requirePreactivation(e);
        verify(extrasRetired?InventoryMode::canonical:InventoryMode::sealed);
      }
    }
    // A repair CLI may resume an immutable, pre-activation operation using a
    // separately approved Discombobulator tool bundle. The deployment bundle,
    // receipt, databases and writer fences retain their original identities.
    std::string preparationRuntime=e.remoteRuntime;
    if(repairBundle) {
      require(e.receipt.phase>=MothershipTidesDBMigrationPhase::writersQuiesced && !e.receipt.activationBoundaryCrossed,"repair tools require a fenced pre-activation recovery");
      preparationRuntime=stageRepairTools(e,repairBundle);
    }
    const auto requestPath=e.plan.operationRoot+(conflictingClientRetired?"/recovery.request.retired-conflicting-client":"/recovery.request");
    const auto authorityPath=e.plan.operationRoot+(conflictingClientRetired?"/conflicting-client-retirement-authority":"/stateless-extras-authority");
    if(e.receipt.phase<MothershipTidesDBMigrationPhase::validated || !fs::exists(authorityPath)) {
      if(conflictingClientRetired) {
        privateFile(requestPath); privateFile(authorityPath,4096);
      } else {
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
        // Schema-v2 also represents a uniform executable temporarily installed
        // below a root other than systemd's registered service root. That uses
        // the normal retained-snapshot predicate, which still validates any
        // active coordinator against the target and logical predecessor digests.
        // Only genuinely mixed installed predecessors use interrupted handoff.
        if (e.plan.mixedPredecessors && retainedRecoveryHasMixedInstalledPredecessors(e.plan)) {
          for (const auto& machine : e.plan.machines) {
            if (machine.installedBundleSHA != e.plan.oldBundleSHA) {
              manifest.request.interruptedBundleSHA=text(machine.installedBundleSHA);
              manifest.request.mixedSuccessorMachineUUIDs.push_back(machine.uuid);
            }
          }
          std::sort(manifest.request.mixedSuccessorMachineUUIDs.begin(),manifest.request.mixedSuccessorMachineUUIDs.end());
          const size_t split=manifest.request.mixedSuccessorMachineUUIDs.size();
          require(split>0 && split<e.plan.machines.size() && prodigyIsSHA256HexDigest(manifest.request.interruptedBundleSHA),"invalid mixed predecessor mapping");
          require(split==2 || (e.plan.schemaVersion==4 && e.plan.explicitMixedRuntimeInventory && split==1),
                  "legacy mixed predecessor mapping requires two successors");
        }
        for(const auto& r:manifest.records) {
          String encoded,why,bytes,machine,container,diagnostic,phase;
          machine.snprintf<"{itoh}"_ctv>(r.machine);container.snprintf<"{itoh}"_ctv>(r.container);
          const bool readParameters=e.command(r.machine,"test \"$(sha256sum "+quote(r.paramsPath)+" | cut -d' ' -f1)\" = "+quote(r.paramsSHA)+"; base64 -w0 "+quote(r.paramsPath),&why,&encoded,30'000);
          // `encoded` is a credential-bearing parameters blob.  The generic
          // command owner includes stdout in some failures, so preserve only a
          // transport phase here rather than relaying that output into logs.
          if(std::strstr(why.c_str(),"timed out waiting for ssh io") != nullptr) phase.assign("ssh io timed out"_ctv);
          else if(std::strstr(why.c_str(),"timed out while trying to wait for eof") != nullptr) phase.assign("ssh eof wait timed out"_ctv);
          else if(std::strstr(why.c_str(),"timed out while closing ssh session") != nullptr) phase.assign("ssh session close timed out"_ctv);
          else if(std::strstr(why.c_str(),"failed to execute remote command") != nullptr) phase.assign("ssh exec failed"_ctv);
          else if(std::strstr(why.c_str(),"failed to read remote command") != nullptr) phase.assign("ssh command read failed"_ctv);
          else if(std::strstr(why.c_str(),"timed out") != nullptr) phase.assign("ssh command timed out"_ctv);
          else phase.assign("remote parameters command failed"_ctv);
          diagnostic.snprintf<"retained parameters read failed machine {} container {}: {}"_ctv>(machine,container,phase);
          require(readParameters,str(diagnostic).c_str());
          require(Base64::decode(encoded,bytes),"retained parameters encoding invalid");ContainerParameters params;
          require(ProdigyWire::deserializeStartupContainerParameters(bytes,params) && params.uuid==r.container,"retained parameters identity invalid");
          auto deployment=manifest.request.plans.find(params.deploymentID);require(deployment!=manifest.request.plans.end(),"retained deployment absent from authority");
          prodigyRestoreRetainedStartupCPUFields(bytes,deployment->second,params);
          if(!r.canonical) {require(!deployment->second.isStateful && deployment->second.config.type==ApplicationType::stateless,"extra retirement would affect a stateful container");continue;}
          for(auto& m:manifest.request.machines)if(m.machineUUID==r.machine) {m.parameters.push_back(std::move(params));m.observedCreatedAtMs.push_back(r.created);}
        }
        String bytes=encodeRequest(manifest.request,e.plan,manifest.emptyRetainedInventoryMachineUUID); if(!requestAlreadySealed)durable(requestPath,bytes);
        durable(authorityPath,text(e.plan.planSHA+"\n"+manifestSHA+"\n"+digest(requestPath)+"\n"));
      }
      }
      const auto witnessPath=requestPath+".witnesses";
      if(!fs::exists(witnessPath)) {
        require(read("/etc/machine-id")==e.plan.machines[0].linuxID+"\n","witness sealing requires the selected seed");
        Request request; MothershipRetainedRecoveryMixedProof proof; uint128_t retiredConflictingClientUUID=0, emptyRetainedInventoryMachineUUID=0;
        require(decodeRequest(read(requestPath),request,&proof,&retiredConflictingClientUUID,&emptyRetainedInventoryMachineUUID),"sealed request unreadable");
        ProdigyPersistentBrainSnapshot seed;loadSnapshot(e.remoteRoot+"/state.copy10",seed);String why;
        if (retiredConflictingClientUUID != 0) {
          const auto originalRequestPath=e.plan.operationRoot+"/recovery.request"; privateFile(originalRequestPath);
          Request original; MothershipRetainedRecoveryMixedProof originalProof; uint128_t originalRetired=0;
          require(decodeRequest(read(originalRequestPath),original,&originalProof,&originalRetired) && originalRetired==0 &&
                  originalProof.staleExcludedContainerUUID==retiredConflictingClientUUID,
                  "retired witness source differs from immutable request");
          require(mothershipPrepareRetiredConflictingClientSchema4Snapshot(seed,original.plans,original.machines,
                  request.bundleSHA,text(e.plan.oldBundleSHA),original.interruptedBundleSHA,
                  original.mixedSuccessorMachineUUIDs,originalProof,retiredConflictingClientUUID,&why),str(why).c_str());
        } else if (!request.interruptedBundleSHA.empty()) {
          if (proof.canonicalContainerCount) require(mothershipPrepareRetainedRecoverySchema4Snapshot(
                      seed,request.plans,request.machines,request.bundleSHA,text(e.plan.oldBundleSHA),
                      request.interruptedBundleSHA,request.mixedSuccessorMachineUUIDs,proof,&why),str(why).c_str());
          else require(mothershipPrepareRetainedRecoveryMixedHandoffSnapshot(
                      seed,request.plans,request.machines,request.bundleSHA,text(e.plan.oldBundleSHA),
                      request.interruptedBundleSHA,request.mixedSuccessorMachineUUIDs,&why),str(why).c_str());
        } else {
          require(mothershipPrepareRetainedRecoverySnapshot(seed,request.plans,request.machines,
                                                            request.bundleSHA,&why,text(e.plan.oldBundleSHA),{},0,nullptr,false,true,
                                                            emptyRetainedInventoryMachineUUID),str(why).c_str());
        }
        WitnessSet sealed;sealed.requestSHA=text(digest(requestPath));sealed.witnesses=seed.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
        String bytes;BitseryEngine::serialize(bytes,sealed);durable(witnessPath,bytes);
      }
      for(auto& m:e.plan.machines) {
        e.upload(m,requestPath,e.remoteRoot+"/recovery.request");
        if(conflictingClientRetired)e.upload(m,e.plan.operationRoot+"/recovery.request",e.remoteRoot+"/recovery.request.original");
        e.upload(m,witnessPath,e.remoteRoot+"/recovery.request.witnesses");
        const auto marker=e.remoteRoot+"/prepared.request.sha256",requestSHA=digest(requestPath);
        std::string cmd="test \"$(systemctl show -p MainPID --value prodigy)\" = 0; ";
        const auto invoke="LD_LIBRARY_PATH="+quote(preparationRuntime+"/lib")+" "+quote(preparationRuntime+"/tools/mothership")+" prepareRetainedRecoveryLocal "+quote(e.remoteRoot+"/recovery.request")+" "+quote(e.remoteRoot+"/state.new10");
        cmd+="if test -f "+quote(marker)+"; then test \"$(cat "+quote(marker)+")\" = "+quote(requestSHA)+"; "+invoke+" verify; else "+invoke+" prepare "+quote(e.plan.oldBundleSHA)+"; printf %s "+quote(requestSHA)+" > "+quote(marker)+"; sync -f "+quote(marker)+"; fi";e.run(m.uuid,cmd);
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
