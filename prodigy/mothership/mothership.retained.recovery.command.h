#pragma once

#include <cstring>

// Explicit retained-fleet repair. Reuses the migration owner's SSH authority,
// bundle installation, fences, receipt, atomic renames and activation boundary.
#include <prodigy/mothership/mothership.tidesdb.migration.command.h>
#include <prodigy/mothership/mothership.retained.recovery.h>
#include <prodigy/mothership/mothership.cluster.remove.h>
#include <prodigy/containerstore.h>
#include <prodigy/wire.h>
#include <set>
#include <thread>

// Existing retained-fleet frames embed these records inline. Their seed field
// is fixed-layout: the next embedded record is not an optional startup tail.
template<typename S> void mothershipSerializeRetainedParameters(S& s, ContainerParameters& parameters) {
  prodigySerializeContainerParameterFields(s, parameters);
  s.object(parameters.statefulStoreSeedAuthority);
}
template<typename S> void serialize(S&& s, MothershipRetainedRecoveryMachineInput& m) {
  s.value16b(m.machineUUID); s.value4b(m.machineFragment);
  s.container(m.parameters, UINT16_MAX, [](S& entry, ContainerParameters& parameters) {
    mothershipSerializeRetainedParameters(entry, parameters);
  });
  s.object(m.observedCreatedAtMs);
}

namespace MothershipRetainedRecovery {
using namespace MothershipTidesMigration;
// The persistent local-state codec has EOF-delimited optional tails.  Keep it
// in a length-framed standalone byte string whenever it is carried beside
// other recovery fields, rather than embedding it in an outer Bitsery object.
struct RuntimeStartupCapturedSourceTail {
  String snapshotBytes;
  String privateStatePath;
  MothershipRetainedRecoveryMachineInput census;
  Vector<String> parameterSHA256;
};
template<typename S> void serialize(S&& s, RuntimeStartupCapturedSourceTail& source) {
  s.text1b(source.snapshotBytes,256*1024*1024); s.text1b(source.privateStatePath,4096);
  s.object(source.census); s.container(source.parameterSHA256,UINT16_MAX,[](auto& entry,auto& digest){entry.text1b(digest,64);});
}
struct RuntimeStartupCapturedSource {
  ProdigyPersistentLocalBrainState local;
  String snapshotBytes;
  String privateStatePath;
  MothershipRetainedRecoveryMachineInput census;
  Vector<String> parameterSHA256;
};
struct RuntimeStartupCapturedSourceEnvelope {
  uint64_t magic = 0x5254434150535632ULL;
  uint32_t version = 2;
  String localBytes;
  RuntimeStartupCapturedSourceTail tail;
};
template<typename S> void serialize(S&& s, RuntimeStartupCapturedSourceEnvelope& source) {
  s.value8b(source.magic); s.value4b(source.version); s.text1b(source.localBytes,16*1024*1024); s.object(source.tail);
}
inline bool encodeRuntimeStartupCapturedSource(const RuntimeStartupCapturedSource& captured, String& bytes, String *failure = nullptr) {
  auto reject=[&](const char *why) { if(failure) failure->assign(why); return false; };
  if(captured.local.uuid==0 || captured.local.ownerClusterUUID==0 || captured.snapshotBytes.size()>256*1024*1024 ||
      captured.privateStatePath.size()>4096 || captured.census.parameters.size()>UINT16_MAX ||
      captured.census.parameters.size()!=captured.census.observedCreatedAtMs.size() ||
      captured.parameterSHA256.size()!=captured.census.parameters.size())
    return reject("runtime startup captured source bounds are invalid");
  for(const String& digest:captured.parameterSHA256) if(!prodigyIsSHA256HexDigest(digest))
    return reject("runtime startup captured parameter digest is invalid");
  RuntimeStartupCapturedSourceEnvelope envelope = {};
  if(!BitseryEngine::serialize(envelope.localBytes,captured.local) || envelope.localBytes.empty() || envelope.localBytes.size()>16*1024*1024)
    return reject("runtime startup captured local serialization failed");
  envelope.tail.snapshotBytes=captured.snapshotBytes; envelope.tail.privateStatePath=captured.privateStatePath;
  envelope.tail.census=captured.census; envelope.tail.parameterSHA256=captured.parameterSHA256;
  bytes.clear();
  if(!BitseryEngine::serialize(bytes,envelope)) return reject("runtime startup captured source serialization failed");
  return true;
}
inline bool decodeRuntimeStartupCapturedSource(const String& bytes, RuntimeStartupCapturedSource& captured, String *failure = nullptr) {
  auto reject=[&](const char *why) { if(failure) failure->assign(why); return false; };
  uint64_t magic = 0; uint32_t version = 0;
  if(bytes.size()<sizeof(magic)+sizeof(version)) return reject("runtime startup captured source envelope is invalid");
  std::memcpy(&magic,bytes.data(),sizeof(magic)); std::memcpy(&version,bytes.data()+sizeof(magic),sizeof(version));
  if(magic!=0x5254434150535632ULL || version!=2) return reject("runtime startup captured source envelope is invalid");
  RuntimeStartupCapturedSourceEnvelope envelope = {};
  if(!BitseryEngine::deserializeSafe(bytes,envelope) || envelope.magic!=magic || envelope.version!=version ||
      envelope.localBytes.empty() || envelope.localBytes.size()>16*1024*1024) return reject("runtime startup captured source envelope is invalid");
  RuntimeStartupCapturedSource result = {};
  if(!BitseryEngine::deserializeSafe(envelope.localBytes,result.local) || result.local.uuid==0 || result.local.ownerClusterUUID==0)
    return reject("runtime startup captured local bytes are invalid");
  result.snapshotBytes=std::move(envelope.tail.snapshotBytes); result.privateStatePath=std::move(envelope.tail.privateStatePath);
  result.census=std::move(envelope.tail.census); result.parameterSHA256=std::move(envelope.tail.parameterSHA256);
  captured=std::move(result); return true;
}
inline bool decodeLegacyRuntimeStartupCapturedSource(const String& bytes, const ProdigyPersistentLocalBrainState& canonicalLocal,
                                                     RuntimeStartupCapturedSource& captured, String *failure = nullptr) {
  auto reject=[&](const char *why) { if(failure) failure->assign(why); return false; };
  String localBytes = {};
  if(canonicalLocal.uuid==0 || canonicalLocal.ownerClusterUUID==0 || !BitseryEngine::serialize(localBytes,canonicalLocal) ||
      localBytes.empty() || bytes.size()<=localBytes.size() || std::memcmp(bytes.data(),localBytes.data(),localBytes.size())!=0)
    return reject("legacy runtime startup captured local prefix differs");
  ProdigyPersistentLocalBrainState decodedLocal = {};
  if(!BitseryEngine::deserializeSafe(localBytes,decodedLocal)) return reject("legacy runtime startup captured local bytes are invalid");
  String tailBytes = {}; tailBytes.assign(bytes.data()+localBytes.size(),bytes.size()-localBytes.size());
  RuntimeStartupCapturedSourceTail tail = {};
  if(!BitseryEngine::deserializeSafe(tailBytes,tail)) return reject("legacy runtime startup captured tail is invalid");
  RuntimeStartupCapturedSource result = {};
  result.local=std::move(decodedLocal); result.snapshotBytes=std::move(tail.snapshotBytes); result.privateStatePath=std::move(tail.privateStatePath);
  result.census=std::move(tail.census); result.parameterSHA256=std::move(tail.parameterSHA256);
  captured=std::move(result); return true;
}
// Persistent snapshot storage carries the transport-authority root in its
// private paired sidecar. The ordinary snapshot wire intentionally omits that
// root, so bind captured bytes to the canonical snapshot's public projection,
// then retain the full canonical object for private preparation.
inline bool restoreRuntimeStartupCapturedAuthority(RuntimeStartupCapturedSource& captured,
                                                    const ProdigyPersistentLocalBrainState& canonicalLocal,
                                                    const ProdigyPersistentBrainSnapshot& canonicalSnapshot,
                                                    ProdigyPersistentBrainSnapshot& restoredSnapshot,
                                                    String *failure = nullptr) {
  auto reject=[&](const char *why) { if(failure) failure->assign(why); return false; };
  String canonicalWire = {};
  ProdigyPersistentBrainSnapshot canonicalCopy=canonicalSnapshot, canonicalPublic={}, capturedPublic={};
  if(!BitseryEngine::serialize(canonicalWire,canonicalCopy) ||
      !BitseryEngine::deserializeSafe(canonicalWire,canonicalPublic) ||
      !BitseryEngine::deserializeSafe(captured.snapshotBytes,capturedPublic))
    return reject("runtime startup captured snapshot public projection is invalid");
  if(!prodigyPersistentBrainSnapshotsEqual(canonicalPublic,capturedPublic))
    return reject("runtime startup captured snapshot public projection differs from canonical private authority");
  if(!prodigyPersistentSerializedEqual(canonicalLocal,captured.local))
    return reject("runtime startup captured local public projection differs from canonical private authority");
  RuntimeStartupCapturedSource result=captured;
  result.local=canonicalLocal;
  captured=std::move(result); restoredSnapshot=canonicalSnapshot;
  return true;
}
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
// RRF7 carries only runtime records recovered from a separately sealed,
// stopped authority snapshot.  The request is private, but its source and the
// selected credential-bearing records are both SHA-bound before it can fence a
// fleet.  Remote prepare never invents ContainerParameters for this path.
struct ColdCanonicalSource {
  String sourceStatePath;
  String sourceSnapshotSHA256;
  String selectedStatesSHA256;
  Vector<uint128_t> requestedContainerUUIDs;
  // The exact credential-bearing state payload is hashed before it enters the
  // outer request.  Never derive this binding by reserializing decoded maps.
  String serializedStates;
  Vector<BrainReplicatedContainerRuntimeState> states;
};
template<typename S> void serialize(S&& s, ColdCanonicalSource& source) {
  s.text1b(source.sourceStatePath, UINT32_MAX); s.text1b(source.sourceSnapshotSHA256, 64);
  s.text1b(source.selectedStatesSHA256, 64); s.object(source.requestedContainerUUIDs);
  s.text1b(source.serializedStates, UINT32_MAX);
}
inline String coldCanonicalPayloadDigest(const String& payload);
struct Schema7ColdCanonicalSourceRequest {
  Schema6EmptyInventoryRequest request;
  ColdCanonicalSource source;
};
template<typename S> void serialize(S&& s, Schema7ColdCanonicalSourceRequest& r) {
  s.object(r.request); s.object(r.source);
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
inline String encodeColdCanonicalSourceRequest(const Request& request, const Plan& plan,
                                               uint128_t emptyRetainedInventoryMachineUUID,
                                               const ColdCanonicalSource& source) {
  require(plan.schemaVersion != 4 && request.interruptedBundleSHA.empty() &&
              emptyRetainedInventoryMachineUUID != 0 && source.states.empty() == false &&
              source.requestedContainerUUIDs.empty() == false &&
              prodigyIsSHA256HexDigest(source.sourceSnapshotSHA256) &&
              prodigyIsSHA256HexDigest(source.selectedStatesSHA256),
          "invalid cold canonical source request");
  Schema7ColdCanonicalSourceRequest wrapped; wrapped.request.request.request=request;
  wrapped.request.emptyRetainedInventoryMachineUUID=emptyRetainedInventoryMachineUUID;
  wrapped.source=source;
  String bytes; BitseryEngine::serialize(bytes,wrapped);
  require(!bytes.empty(),"cold canonical source request serialization is empty");
  String framed={}; framed.append("RRF7",4); framed.append(bytes.data(),bytes.size()); return framed;
}
// A partial application handoff reuses the existing durable recovery owner.
// Its explicit descriptor is sealed with the complete observed inventory; the
// pure preparation owner must prove the exact two-old/one-new cohort.
struct Schema8PartialHandoffRequest {
  String coldRequest;
  ProdigyMaterializedStatefulRecoveryOperation operation;
};
template<typename S> void serialize(S&& s, Schema8PartialHandoffRequest& r) {
  s.text1b(r.coldRequest, UINT32_MAX); s.object(r.operation);
}
// RRF9 is a projection of the ordinary canonical request.  It carries the
// sealed startup parameters for exactly one noncanonical, stateful orphan so
// preactivation can retire it without recreating its already-culled plan.
struct Schema9OrphanedStatefulPredecessorRequest {
  String canonicalRequest;
  MothershipRetainedRecoveryOrphanedStatefulPredecessor orphan;
};
template<typename S> void serialize(S&& s, Schema9OrphanedStatefulPredecessorRequest& r) {
  s.text1b(r.canonicalRequest, UINT32_MAX); s.object(r.orphan.operation);
  s.value16b(r.orphan.machineUUID); mothershipSerializeRetainedParameters(s, r.orphan.parameters);
  s.text1b(r.orphan.priorRequestSHA256, 128); s.text1b(r.orphan.priorManifestSHA256, 128);
  s.text1b(r.orphan.rejectedCandidateSHA256, 128);
  s.container(r.orphan.successorBootstraps, 3, [](S& nested,
      MothershipRetainedRecoverySealedSuccessorBootstrap& bootstrap) {
    nested.value16b(bootstrap.machineUUID); nested.text1b(bootstrap.bootstrap, UINT32_MAX);
  });
}
inline bool partialHandoffEnvelopeValid(const ProdigyMaterializedStatefulRecoveryOperation& operation) {
  return prodigyCanonicalOperationUUID(operation.operationID) && operation.activeDeploymentID != 0 &&
      operation.successorDeploymentID != 0 && operation.activeDeploymentID != operation.successorDeploymentID &&
      prodigyIsSHA256HexDigest(operation.successorBlobSHA256) && operation.accepted && operation.started &&
      !operation.completed && operation.updatedAtMs > 0;
}
inline bool partialHandoffsEqual(const ProdigyMaterializedStatefulRecoveryOperation& lhs,
                                 const ProdigyMaterializedStatefulRecoveryOperation& rhs) {
  return mothershipRetainedRecoveryPartialHandoffEqual(lhs,rhs);
}
inline String encodePartialHandoffRequest(const Request& request, const Plan& plan,
                                          uint128_t emptyMachine, const ColdCanonicalSource& source,
                                          const ProdigyMaterializedStatefulRecoveryOperation& operation) {
  require(partialHandoffEnvelopeValid(operation),"invalid partial handoff descriptor");
  Schema8PartialHandoffRequest wrapped;
  wrapped.coldRequest=encodeColdCanonicalSourceRequest(request,plan,emptyMachine,source);
  wrapped.operation=operation;
  String bytes; BitseryEngine::serialize(bytes,wrapped);
  require(!bytes.empty(),"partial handoff serialization is empty");
  String framed; framed.append("RRF8",4); framed.append(bytes.data(),bytes.size()); return framed;
}
inline String encodeOrphanedStatefulPredecessorRequest(
    const Request& request, const Plan& plan,
    const MothershipRetainedRecoveryOrphanedStatefulPredecessor& orphan) {
  require(mothershipRetainedRecoveryOrphanedStatefulPredecessorValid(orphan) &&
              plan.schemaVersion != 4 && request.interruptedBundleSHA.empty(),
          "invalid orphaned stateful predecessor request");
  Schema9OrphanedStatefulPredecessorRequest wrapped = {};
  wrapped.canonicalRequest = encodeRequest(request, plan);
  wrapped.orphan = orphan;
  String bytes = {}; BitseryEngine::serialize(bytes, wrapped);
  require(!bytes.empty(), "orphaned stateful predecessor request serialization is empty");
  String framed = {}; framed.append("RRF9", 4); framed.append(bytes.data(), bytes.size()); return framed;
}
inline bool decodeRequest(const std::string& raw,Request& request,MothershipRetainedRecoveryMixedProof *proof,
                          uint128_t *retiredConflictingClientUUID = nullptr,
                          uint128_t *emptyRetainedInventoryMachineUUID = nullptr,
                          ColdCanonicalSource *coldCanonicalSource = nullptr,
                          ProdigyMaterializedStatefulRecoveryOperation *partialHandoff = nullptr,
                          MothershipRetainedRecoveryOrphanedStatefulPredecessor *orphanedPredecessor = nullptr) {
  if(partialHandoff)*partialHandoff={};
  if(orphanedPredecessor)*orphanedPredecessor={};
  if (raw.size()>=4 && raw.compare(0,4,"RRF9")==0) {
    Schema9OrphanedStatefulPredecessorRequest wrapped = {};
    Request nested = {}; MothershipRetainedRecoveryMixedProof nestedProof = {};
    uint128_t nestedRetired = 0, nestedEmptyMachine = 0;
    ColdCanonicalSource nestedCold = {};
    ProdigyMaterializedStatefulRecoveryOperation nestedPartial = {};
    MothershipRetainedRecoveryOrphanedStatefulPredecessor nestedOrphan = {};
    if (!BitseryEngine::deserializeSafe(text(raw.substr(4)), wrapped) ||
        !mothershipRetainedRecoveryOrphanedStatefulPredecessorValid(wrapped.orphan) ||
        wrapped.canonicalRequest.empty() ||
        !decodeRequest(str(wrapped.canonicalRequest), nested, &nestedProof, &nestedRetired,
                       &nestedEmptyMachine, &nestedCold, &nestedPartial, &nestedOrphan) ||
        nestedProof.canonicalContainerCount != 0 || nestedRetired != 0 || nestedEmptyMachine != 0 ||
        !nestedCold.states.empty() || !nestedPartial.operationID.empty() ||
        nestedOrphan.parameters.uuid != 0) return false;
    request = std::move(nested);
    if (proof) *proof = nestedProof;
    if (retiredConflictingClientUUID) *retiredConflictingClientUUID = 0;
    if (emptyRetainedInventoryMachineUUID) *emptyRetainedInventoryMachineUUID = 0;
    if (coldCanonicalSource) *coldCanonicalSource = {};
    if (partialHandoff) *partialHandoff = {};
    if (orphanedPredecessor) *orphanedPredecessor = std::move(wrapped.orphan);
    return true;
  }
  if (raw.size()>=4 && raw.compare(0,4,"RRF8")==0) {
    Schema8PartialHandoffRequest wrapped;
    if (!BitseryEngine::deserializeSafe(text(raw.substr(4)),wrapped) ||
        !partialHandoffEnvelopeValid(wrapped.operation) || wrapped.coldRequest.size()<4 ||
        std::memcmp(wrapped.coldRequest.data(),"RRF7",4)!=0 ||
        !decodeRequest(str(wrapped.coldRequest),request,proof,retiredConflictingClientUUID,
                       emptyRetainedInventoryMachineUUID,coldCanonicalSource)) return false;
    if(partialHandoff)*partialHandoff=std::move(wrapped.operation);
    return true;
  }
  if (raw.size()>=4 && raw.compare(0,4,"RRF7")==0) {
    Schema7ColdCanonicalSourceRequest wrapped;
    if (!BitseryEngine::deserializeSafe(text(raw.substr(4)),wrapped) ||
        wrapped.request.emptyRetainedInventoryMachineUUID == 0 ||
        wrapped.request.request.proof.canonicalContainerCount != 0 ||
        wrapped.request.request.proof.staleCoordinatorCanonicalContainerCount != 0 ||
        wrapped.request.request.proof.interruptedExpectedEchos != 0 ||
        wrapped.request.request.proof.staleExcludedContainerUUID != 0 ||
        wrapped.source.serializedStates.empty() || wrapped.source.requestedContainerUUIDs.empty() ||
        !prodigyIsSHA256HexDigest(wrapped.source.sourceSnapshotSHA256) ||
        !prodigyIsSHA256HexDigest(wrapped.source.selectedStatesSHA256) ||
        coldCanonicalPayloadDigest(wrapped.source.serializedStates)!=wrapped.source.selectedStatesSHA256 ||
        !BitseryEngine::deserializeSafe(wrapped.source.serializedStates,wrapped.source.states) ||
        wrapped.source.states.size()!=wrapped.source.requestedContainerUUIDs.size()) return false;
    for (uint32_t index=0;index<wrapped.source.requestedContainerUUIDs.size();++index) {
      if (wrapped.source.requestedContainerUUIDs[index]==0 ||
          (index && wrapped.source.requestedContainerUUIDs[index-1]>=wrapped.source.requestedContainerUUIDs[index]) ||
          wrapped.source.states[index].machineUUID!=wrapped.request.emptyRetainedInventoryMachineUUID ||
          wrapped.source.states[index].plan.uuid!=wrapped.source.requestedContainerUUIDs[index]) return false;
    }
    request=std::move(wrapped.request.request.request); if(proof)*proof=wrapped.request.request.proof;
    if(retiredConflictingClientUUID)*retiredConflictingClientUUID=0;
    if(emptyRetainedInventoryMachineUUID)*emptyRetainedInventoryMachineUUID=wrapped.request.emptyRetainedInventoryMachineUUID;
    if(coldCanonicalSource)*coldCanonicalSource=std::move(wrapped.source); return true;
  }
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
    if(coldCanonicalSource)*coldCanonicalSource={};
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
    if(emptyRetainedInventoryMachineUUID)*emptyRetainedInventoryMachineUUID=0; if(coldCanonicalSource)*coldCanonicalSource={}; return true;
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
    if(emptyRetainedInventoryMachineUUID)*emptyRetainedInventoryMachineUUID=0; if(coldCanonicalSource)*coldCanonicalSource={}; return true;
  }
  if (!BitseryEngine::deserializeSafe(text(raw),request)) return false;
  if(proof)*proof={}; if(retiredConflictingClientUUID)*retiredConflictingClientUUID=0;
  if(emptyRetainedInventoryMachineUUID)*emptyRetainedInventoryMachineUUID=0; if(coldCanonicalSource)*coldCanonicalSource={}; return true;
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
inline bool witnessesExact(const Vector<ProdigyPersistentUpdateSelfMachineRecoveryWitness>& a,
                           const Vector<ProdigyPersistentUpdateSelfMachineRecoveryWitness>& b) {
  if (a.size()!=b.size()) return false;
  for (uint32_t i=0;i<a.size();++i) {
    if (a[i].machineUUID!=b[i].machineUUID || a[i].bundleRegistered!=b[i].bundleRegistered ||
        a[i].containerBootstraps.size()!=b[i].containerBootstraps.size()) return false;
    for (uint32_t j=0;j<a[i].containerBootstraps.size();++j)
      if (a[i].containerBootstraps[j]!=b[i].containerBootstraps[j]) return false;
  }
  return true;
}
// Runtime-startup recovery keeps the operation's captured authority separate
// from the private paired state copy on which it is prepared.  The controller
// binds the raw captured snapshot bytes to stopped-process proof; this record
// deliberately carries that byte digest rather than trying to reproduce it by
// serializing decoded unordered persistent maps.
struct RuntimeStartupSource {
  uint128_t memberUUID = 0;
  String stoppedProofSHA256;
  String stateSHA256;
  String secretsSHA256;
  String snapshotSHA256;
};
template<typename S> void serialize(S&& s, RuntimeStartupSource& source) {
  s.value16b(source.memberUUID); s.text1b(source.stoppedProofSHA256,64);
  s.text1b(source.stateSHA256,64); s.text1b(source.secretsSHA256,64);
  s.text1b(source.snapshotSHA256,64);
}
// The member census is private operation input.  Its ContainerParameters are
// normalized by the capture owner; this header only checks its topology and
// uses the existing retained-recovery validator to bind it to authority.
struct RuntimeStartupRequest {
  uint32_t version = 1;
  String bindingSHA256;
  uint128_t clusterUUID = 0;
  String targetBundleSHA256;
  String sourceBundleSHA256;
  String rejectedCandidateSHA256;
  ClusterTopology topology;
  Vector<RuntimeStartupSource> sources;
  Vector<MothershipRetainedRecoveryMachineInput> machines;
};
template<typename S> void serialize(S&& s, RuntimeStartupRequest& request) {
  s.value4b(request.version); s.text1b(request.bindingSHA256,64);
  s.value16b(request.clusterUUID); s.text1b(request.targetBundleSHA256,64); s.text1b(request.rejectedCandidateSHA256,64);
  if (request.version >= 2) s.text1b(request.sourceBundleSHA256,64);
  s.object(request.topology); s.object(request.sources); s.object(request.machines);
}
struct RuntimeStartupPrepared {
  String requestSHA256;
  String sourceSnapshotSHA256;
  String preparedSnapshotSHA256;
  WitnessSet candidateWitnesses;
};
template<typename S> void serialize(S&& s, RuntimeStartupPrepared& prepared) {
  s.text1b(prepared.requestSHA256,64); s.text1b(prepared.sourceSnapshotSHA256,64);
  s.text1b(prepared.preparedSnapshotSHA256,64); s.object(prepared.candidateWitnesses);
}
inline bool runtimeStartupRequestValid(const RuntimeStartupRequest& request, String *failure = nullptr) {
  auto reject=[&](const char *why) { if (failure) failure->assign(why); return false; };
  if ((request.version != 1 && request.version != 2) || request.clusterUUID == 0 ||
      !prodigyIsSHA256HexDigest(request.bindingSHA256) ||
      !prodigyIsSHA256HexDigest(request.targetBundleSHA256) ||
      (request.version >= 2 && !prodigyIsSHA256HexDigest(request.sourceBundleSHA256)) ||
      (!request.rejectedCandidateSHA256.empty() && !prodigyIsSHA256HexDigest(request.rejectedCandidateSHA256)) ||
      request.topology.machines.size() != 3 || request.sources.size() != 3 || request.machines.size() != 3)
    return reject("runtime startup request shape is invalid");
  bytell_hash_set<uint128_t> topologyMembers, sourceMembers, censusMembers;
  for (const ClusterMachine& machine : request.topology.machines) {
    if (!machine.isBrain || machine.uuid == 0 || !topologyMembers.insert(machine.uuid).second)
      return reject("runtime startup request topology is not an exact three-Brain set");
  }
  for (const RuntimeStartupSource& source : request.sources) {
    if (source.memberUUID == 0 || !topologyMembers.contains(source.memberUUID) || !sourceMembers.insert(source.memberUUID).second ||
        !prodigyIsSHA256HexDigest(source.stoppedProofSHA256) || !prodigyIsSHA256HexDigest(source.stateSHA256) ||
        !prodigyIsSHA256HexDigest(source.secretsSHA256) || !prodigyIsSHA256HexDigest(source.snapshotSHA256))
      return reject("runtime startup request source proof is invalid");
  }
  for (const MothershipRetainedRecoveryMachineInput& machine : request.machines) {
    if (machine.machineUUID == 0 || !topologyMembers.contains(machine.machineUUID) ||
        !censusMembers.insert(machine.machineUUID).second || machine.machineFragment == 0 ||
        machine.parameters.empty() || machine.parameters.size() != machine.observedCreatedAtMs.size())
      return reject("runtime startup request census shape is invalid");
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
  struct ColdCanonicalSourceInput {
    std::string statePath;
    String aggregateSHA256;
    Vector<uint128_t> requestedContainerUUIDs;
    struct StorageMetadata {
      uint128_t containerUUID = 0;
      // Literal "missing" is a sealed recovery instruction: the complete
      // immutable /containers/<uuid> artifact root is absent, while the
      // separate storage directory remains required and identity-bound.
      String rootfsMetadata;
      String storageMetadata;
    };
    Vector<StorageMetadata> storage;
  } coldCanonicalSource;
  ProdigyMaterializedStatefulRecoveryOperation partialHandoff;
  MothershipRetainedRecoveryOrphanedStatefulPredecessor orphanedStatefulPredecessor;
  String orphanedStatefulPredecessorPriorRequestPath;
  String orphanedStatefulPredecessorPriorManifestPath;
  // A sealed earlier canonical request may supply only plans that the current
  // stopped authority no longer retains. It never replaces current authority.
  String priorCanonicalRequestPath;
  String priorCanonicalRequestSHA256;
  struct ArtifactInput {
    uint64_t deploymentID = 0;
    String blobPath;
    String sha256;
    uint64_t bytes = 0;
  };
  Vector<ArtifactInput> artifacts;
};
inline bool coldCanonicalMetadata(const String& value) {
  if (value.size() <= 4) return false;
  for (uint32_t index=0;index<value.size();++index) {
    const char character=value[index];
    if (!((character >= '0' && character <= '9') ||
          (character >= 'a' && character <= 'f') || character == ':')) return false;
  }
  return true;
}
inline bool coldCanonicalUUIDsAreStrictlySorted(const Vector<uint128_t>& values) {
  for (uint32_t index=0;index<values.size();++index)
    if (values[index] == 0 || (index && values[index-1] >= values[index])) return false;
  return true;
}
inline bool coldCanonicalUUIDsEqual(const Vector<uint128_t>& lhs,const Vector<uint128_t>& rhs) {
  if (lhs.size()!=rhs.size()) return false;
  for (uint32_t index=0;index<lhs.size();++index) if (lhs[index]!=rhs[index]) return false;
  return true;
}
inline String coldCanonicalStateAggregateDigest(const std::string& statePath) {
  const fs::path state(statePath), parent=state.parent_path();
  require(fs::is_directory(state) && fs::is_directory(state.string()+".secrets") &&
              !fs::is_symlink(state) && !fs::is_symlink(state.string()+".secrets"),
          "cold canonical source state and secrets are unavailable");
  std::vector<fs::path> files;
  String manifest = {};
  for (const fs::path& root : {state,fs::path(state.string()+".secrets")}) {
    std::vector<fs::path> rootFiles;
    for (const auto& entry : fs::recursive_directory_iterator(root)) {
      require(!entry.is_symlink(),"cold canonical source contains a symlink");
      if (entry.is_regular_file()) rootFiles.push_back(entry.path());
      else require(entry.is_directory(),"cold canonical source contains a non-regular entry");
    }
    std::sort(rootFiles.begin(),rootFiles.end());
    for (const fs::path& file : rootFiles) {
      files.push_back(file);
      struct stat metadata = {};
      require(::lstat(file.c_str(),&metadata)==0 && S_ISREG(metadata.st_mode) &&
                  metadata.st_nlink==1 && metadata.st_uid==::geteuid(),
              "cold canonical source file is not regular and owned");
      String fileDigest = {}, failure = {};
      require(prodigyComputeFileSHA256Hex(text(file.string()),fileDigest,&failure),
              "cold canonical source file digest failed");
      const std::string relative=fs::relative(file,parent).string();
      manifest.append(relative.data(),relative.size()); manifest.append("  ",2);
      manifest.append(fileDigest.data(),fileDigest.size()); manifest.append("\n",1);
    }
  }
  require(!files.empty(),"cold canonical source has no files");
  String digest = {}, failure = {};
  require(prodigyComputeSHA256Hex(manifest,digest,&failure),"cold canonical source aggregate digest failed");
  return digest;
}

inline String coldCanonicalPayloadDigest(const String& payload) {
  String digest = {}, failure = {};
  require(!payload.empty() && prodigyComputeSHA256Hex(payload,digest,&failure),
          "cold canonical runtime-state digest failed");
  return digest;
}
inline String coldCanonicalRuntimeStatesDigest(const Vector<BrainReplicatedContainerRuntimeState>& input,
                                               String *serializedPayload = nullptr) {
  Vector<BrainReplicatedContainerRuntimeState> states=input;
  std::sort(states.begin(),states.end(),[](const auto& lhs,const auto& rhs) {
    return lhs.plan.uuid == rhs.plan.uuid ? lhs.machineUUID < rhs.machineUUID : lhs.plan.uuid < rhs.plan.uuid;
  });
  String serialized = {};
  BitseryEngine::serialize(serialized,states);
  if (serializedPayload) *serializedPayload=serialized;
  return coldCanonicalPayloadDigest(serialized);
}
inline void privateFile(const std::string& path, uint64_t maximum=UINT32_MAX) {
  struct stat st{};
  require(::lstat(path.c_str(),&st)==0 && S_ISREG(st.st_mode) && !(st.st_mode&0077) && st.st_nlink==1 && st.st_uid==::geteuid() && st.st_size>0 && uint64_t(st.st_size)<=maximum,"recovery input must be a private owned regular file");
}
inline bool loadRuntimeStartupRequest(const std::string& path,RuntimeStartupRequest& request,String& exactRequestSHA256,String *failure=nullptr) {
  try {
    privateFile(path,16*1024*1024); const std::string bytes=read(path); String raw=text(bytes);
    require(prodigyComputeSHA256Hex(raw,exactRequestSHA256,failure) &&
                BitseryEngine::deserializeSafe(raw,request) && runtimeStartupRequestValid(request,failure),
            failure && failure->size()?str(*failure).c_str():"runtime startup request is unreadable");
    return true;
  } catch(const std::exception& error) { if(failure) failure->assign(error.what()); return false; }
}
inline bool durableRuntimeStartupRequest(const std::string& path,const String& exactRequestBytes,String *failure=nullptr) {
  try {
    RuntimeStartupRequest request={}; String digest={};
    require(!exactRequestBytes.empty() && BitseryEngine::deserializeSafe(exactRequestBytes,request) &&
                runtimeStartupRequestValid(request,failure) && prodigyComputeSHA256Hex(exactRequestBytes,digest,failure),
            failure && failure->size()?str(*failure).c_str():"runtime startup request bytes are invalid");
    if (fs::exists(path)) { privateFile(path,16*1024*1024); require(read(path)==str(exactRequestBytes),"runtime startup request bytes changed"); }
    else durable(path,exactRequestBytes);
    return true;
  } catch(const std::exception& error) { if(failure) failure->assign(error.what()); return false; }
}
inline uint64_t number(simdjson::dom::element e,const char *key) {
  uint64_t n=0; require(e[key].get_uint64().get(n)==simdjson::SUCCESS,"invalid recovery integer"); return n;
}
inline Manifest parseManifest(const std::string& path,const Plan& p) {
  privateFile(path,1024*1024); simdjson::dom::parser parser; simdjson::dom::element doc;
  auto raw=read(path); require(parser.parse(raw).get(doc)==simdjson::SUCCESS,"invalid recovery manifest JSON");
  const uint64_t schemaVersion=number(doc,"schemaVersion");
  require((schemaVersion==1 || schemaVersion==2 || schemaVersion==3 || schemaVersion==4) && uuid(field(doc,"clusterUUID"))==p.clusterUUID,"recovery manifest cluster mismatch");
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
  simdjson::dom::element priorCanonicalPath, priorCanonicalSHA;
  const bool hasPriorCanonicalPath=doc["priorCanonicalRequestPath"].get(priorCanonicalPath)==simdjson::SUCCESS;
  const bool hasPriorCanonicalSHA=doc["priorCanonicalRequestSHA256"].get(priorCanonicalSHA)==simdjson::SUCCESS;
  require(hasPriorCanonicalPath==hasPriorCanonicalSHA,
          "prior canonical request path and digest must be supplied together");
  if (hasPriorCanonicalPath) {
    std::string_view pathValue, digestValue;
    require(priorCanonicalPath.get_string().get(pathValue)==simdjson::SUCCESS &&
                priorCanonicalSHA.get_string().get(digestValue)==simdjson::SUCCESS,
            "prior canonical request authority is invalid");
    m.priorCanonicalRequestPath.assign(pathValue.data(),pathValue.size());
    m.priorCanonicalRequestSHA256.assign(digestValue.data(),digestValue.size());
    pathCheck(str(m.priorCanonicalRequestPath));
    require(prodigyIsSHA256HexDigest(m.priorCanonicalRequestSHA256),
            "prior canonical request digest is invalid");
  }
  simdjson::dom::element artifacts;
  if (doc["artifacts"].get(artifacts)==simdjson::SUCCESS) {
    simdjson::dom::array inputs;
    require(artifacts.get_array().get(inputs)==simdjson::SUCCESS,"recovery artifacts are invalid");
    bytell_hash_set<uint64_t> deploymentIDs;
    for (auto input : inputs) {
      Manifest::ArtifactInput artifact = {};
      artifact.deploymentID=number(input,"deploymentID");
      artifact.blobPath=text(field(input,"blobPath")); artifact.sha256=text(field(input,"sha256"));
      artifact.bytes=number(input,"bytes");
      pathCheck(str(artifact.blobPath));
      require(artifact.deploymentID != 0 && artifact.bytes != 0 &&
                  prodigyIsSHA256HexDigest(artifact.sha256) && deploymentIDs.insert(artifact.deploymentID).second,
              "recovery artifact identity is invalid or duplicated");
      m.artifacts.push_back(std::move(artifact));
    }
  }
  if (schemaVersion == 2 || schemaVersion == 3) {
    require(m.emptyRetainedInventoryMachineUUID != 0 && p.schemaVersion != 4,
            "cold canonical source requires a uniform empty retained machine");
    simdjson::dom::element cold;
    require(doc["coldCanonicalSource"].get(cold)==simdjson::SUCCESS,"cold canonical source is missing");
    m.coldCanonicalSource.statePath=field(cold,"sourceStatePath"); pathCheck(m.coldCanonicalSource.statePath);
    require(m.coldCanonicalSource.statePath.ends_with("/state.copy10") &&
                m.coldCanonicalSource.statePath.starts_with("/root/nametag/.run/"),
            "cold canonical source path is not a task-owned stopped state copy");
    m.coldCanonicalSource.aggregateSHA256=text(field(cold,"sourceStateAggregateSHA256"));
    require(prodigyIsSHA256HexDigest(m.coldCanonicalSource.aggregateSHA256),"cold canonical source aggregate digest is invalid");
    simdjson::dom::array requested;
    require(cold["requestedContainerUUIDs"].get_array().get(requested)==simdjson::SUCCESS,
            "cold canonical source requested UUIDs are missing");
    for (auto item : requested) {
      std::string_view value;
      require(item.get_string().get(value)==simdjson::SUCCESS,"cold canonical source UUID is invalid");
      m.coldCanonicalSource.requestedContainerUUIDs.push_back(uuid(std::string(value)));
    }
    require(coldCanonicalUUIDsAreStrictlySorted(m.coldCanonicalSource.requestedContainerUUIDs),
            "cold canonical source UUIDs are not sorted and unique");
    simdjson::dom::array storage;
    require(cold["storage"].get_array().get(storage)==simdjson::SUCCESS,"cold canonical source storage metadata is missing");
    for (auto item : storage) {
      Manifest::ColdCanonicalSourceInput::StorageMetadata entry = {};
      entry.containerUUID=uuid(field(item,"containerUUID"));
      entry.rootfsMetadata=text(field(item,"rootfsMetadata")); entry.storageMetadata=text(field(item,"storageMetadata"));
      require((entry.rootfsMetadata=="missing"_ctv || coldCanonicalMetadata(entry.rootfsMetadata)) &&
                  entry.storageMetadata!="missing"_ctv && coldCanonicalMetadata(entry.storageMetadata),
              "cold canonical source storage metadata is invalid");
      m.coldCanonicalSource.storage.push_back(std::move(entry));
    }
    std::sort(m.coldCanonicalSource.storage.begin(),m.coldCanonicalSource.storage.end(),[](const auto& lhs,const auto& rhs) {
      return lhs.containerUUID<rhs.containerUUID;
    });
    require(m.coldCanonicalSource.storage.size()==m.coldCanonicalSource.requestedContainerUUIDs.size(),
            "cold canonical source storage metadata count differs");
    for(uint32_t index=0;index<m.coldCanonicalSource.storage.size();++index)
      require(m.coldCanonicalSource.storage[index].containerUUID==m.coldCanonicalSource.requestedContainerUUIDs[index],
              "cold canonical source storage UUID set differs");
  }
  simdjson::dom::element handoff;
  const bool hasHandoff=doc["partialStatefulHandoff"].get(handoff)==simdjson::SUCCESS;
  simdjson::dom::element orphan;
  const bool hasOrphan=doc["orphanedStatefulPredecessor"].get(orphan)==simdjson::SUCCESS;
  require(hasHandoff==(schemaVersion==3) && hasOrphan==(schemaVersion==4),
          "retained handoff authority requires its explicit manifest schema");
  if (hasHandoff) {
    auto& operation=m.partialHandoff;
    operation.operationID=text(field(handoff,"operationID"));
    operation.activeDeploymentID=number(handoff,"activeDeploymentID");
    operation.successorDeploymentID=number(handoff,"successorDeploymentID");
    operation.successorBlobSHA256=text(field(handoff,"successorBlobSHA256"));
    const uint64_t updated=number(handoff,"updatedAtMs");
    require(updated>0 && updated<=INT64_MAX,"invalid partial handoff timestamp");
    operation.updatedAtMs=int64_t(updated); operation.accepted=true; operation.started=true;
    require(partialHandoffEnvelopeValid(operation),"invalid partial handoff authority");
    std::string identity=str(operation.operationID);
    identity.erase(std::remove(identity.begin(),identity.end(),'-'),identity.end());
    require(uuid("0x"+identity)==p.operationID,"partial handoff operation differs from sealed migration identity");
  }
  if (hasOrphan) {
    auto& descriptor=m.orphanedStatefulPredecessor;
    descriptor.operation.operationID=text(field(orphan,"operationID"));
    descriptor.operation.activeDeploymentID=number(orphan,"activeDeploymentID");
    descriptor.operation.successorDeploymentID=number(orphan,"successorDeploymentID");
    descriptor.operation.successorBlobSHA256=text(field(orphan,"successorBlobSHA256"));
    const uint64_t updated=number(orphan,"updatedAtMs");
    require(updated>0 && updated<=INT64_MAX,"invalid orphaned stateful predecessor timestamp");
    descriptor.operation.updatedAtMs=int64_t(updated); descriptor.operation.accepted=true; descriptor.operation.started=true;
    descriptor.machineUUID=uuid(field(orphan,"machineUUID"));
    descriptor.parameters.uuid=uuid(field(orphan,"containerUUID"));
    descriptor.priorRequestSHA256=text(field(orphan,"priorRequestSHA256"));
    descriptor.priorManifestSHA256=text(field(orphan,"priorManifestSHA256"));
    simdjson::dom::element rejectedCandidate;
    if (orphan["rejectedCandidateSHA256"].get(rejectedCandidate)==simdjson::SUCCESS) {
      std::string_view value; require(rejectedCandidate.get_string().get(value)==simdjson::SUCCESS,
          "orphaned stateful predecessor rejected candidate digest is invalid");
      descriptor.rejectedCandidateSHA256.assign(value.data(), value.size());
    }
    m.orphanedStatefulPredecessorPriorRequestPath=text(field(orphan,"priorRequestPath"));
    m.orphanedStatefulPredecessorPriorManifestPath=text(field(orphan,"priorManifestPath"));
    require(!m.orphanedStatefulPredecessorPriorRequestPath.empty() &&
                !m.orphanedStatefulPredecessorPriorManifestPath.empty(),
            "orphaned stateful predecessor historical source paths are missing");
    // The migration attempt and the durable application handoff are separate
    // authority domains. A later sealed migration may carry the same active
    // handoff; its operation ID must not be forced to equal this attempt ID.
    require(partialHandoffEnvelopeValid(descriptor.operation) &&
                descriptor.machineUUID != 0 && descriptor.parameters.uuid != 0,
            "orphaned stateful predecessor authority is invalid");
    uint32_t matches=0, extras=0;
    for (const Record& record : m.records) {
      extras += !record.canonical;
      if (record.container != descriptor.parameters.uuid) continue;
      ++matches;
      require(record.machine==descriptor.machineUUID && !record.canonical,
              "orphaned stateful predecessor is not the one sealed noncanonical record");
    }
    require(matches==1 && extras==1,"orphaned stateful predecessor record is absent, duplicated, or has unrelated extras");
  }
  return m;
}
// Decode a separately hashed historical request only at sealing time.  The
// historical request can prove a plan for a currently canonical process but
// cannot introduce a process, machine, or deployment on its own.
inline bool loadPriorCanonicalRecoveryRequest(const Manifest& manifest,Request& prior) {
  prior={};
  if(manifest.priorCanonicalRequestPath.empty()) return false;
  const std::string path=str(manifest.priorCanonicalRequestPath);
  privateFile(path);
  require(text(digest(path))==manifest.priorCanonicalRequestSHA256,
          "prior canonical request digest differs");
  MothershipRetainedRecoveryMixedProof proof={}; uint128_t retired=0, emptyMachine=0;
  ColdCanonicalSource cold={}; ProdigyMaterializedStatefulRecoveryOperation handoff={};
  MothershipRetainedRecoveryOrphanedStatefulPredecessor orphan={};
  require(decodeRequest(read(path),prior,&proof,&retired,&emptyMachine,&cold,&handoff,&orphan) &&
              prior.clusterUUID==manifest.request.clusterUUID,
          "prior canonical request is malformed or cluster differs");
  return true;
}
inline const DeploymentPlan& bindCanonicalRecoveryPlan(Manifest& manifest,const Request *prior,
                                                        const Record& record,uint64_t deploymentID) {
  auto current=manifest.request.plans.find(deploymentID);
  if(!prior) {
    require(current!=manifest.request.plans.end(),"retained deployment absent from authority");
    return current->second;
  }
  const auto historical=prior->plans.find(deploymentID);
  if(current!=manifest.request.plans.end()) {
    require(historical==prior->plans.end() ||
                mothershipRetainedRecoveryPlansEqual(current->second,historical->second),
            "prior canonical request conflicts with retained authority");
    return current->second;
  }
  require(record.canonical && historical!=prior->plans.end(),
          "prior canonical request lacks a missing canonical deployment plan");
  manifest.request.plans.insert_or_assign(deploymentID,historical->second);
  current=manifest.request.plans.find(deploymentID);
  require(current!=manifest.request.plans.end(),"missing canonical deployment plan was not admitted");
  return current->second;
}
inline void loadSnapshot(const std::string& path,ProdigyPersistentBrainSnapshot& snapshot);
inline bool prepareLocal(const char *requestPath,const char *statePath,bool verifyOnly,String *failure,
                         const String& previousBundleSHA256);
inline const DeploymentPlan& bindRecoveryArtifact(const Request& request,uint64_t deploymentID,
                                                 const ColdCanonicalSource *coldCanonicalSource=nullptr) {
  const auto plan=request.plans.find(deploymentID);
  require(plan!=request.plans.end() && plan->second.config.containerBlobBytes!=0 &&
              prodigyIsSHA256HexDigest(plan->second.config.containerBlobSHA256),
          "recovery artifact deployment plan is unavailable");
  bool canonical=false;
  for(const auto& machine:request.machines) for(const auto& parameters:machine.parameters)
    canonical |= parameters.deploymentID==deploymentID;
  if (!canonical && coldCanonicalSource) for (const auto& state:coldCanonicalSource->states) {
    if (state.plan.config.deploymentID()!=deploymentID) continue;
    String selected={}, approved={}; ApplicationConfig selectedConfig=state.plan.config, approvedConfig=plan->second.config;
    BitseryEngine::serialize(selected,selectedConfig); BitseryEngine::serialize(approved,approvedConfig);
    require(selected==approved,"cold canonical recovery artifact deployment config differs");
    canonical=true;
  }
  require(canonical,"recovery artifact deployment is not canonical");
  return plan->second;
}
inline void validateRecoveryArtifacts(const Manifest& manifest,const Request& request,
                                      const ColdCanonicalSource *coldCanonicalSource=nullptr) {
  for(const auto& artifact:manifest.artifacts) {
    const DeploymentPlan& plan=bindRecoveryArtifact(request,artifact.deploymentID,coldCanonicalSource);
    require(plan.config.containerBlobSHA256==artifact.sha256 && plan.config.containerBlobBytes==artifact.bytes,
            "recovery artifact differs from sealed deployment plan");
  }
}
// A missing artifact root is an explicit cold-recovery exception.  It is
// never inferred from a failed stat: the sealed source must name it, retain
// the stateful storage identity, and bind the exact original image to the
// selected runtime record before the activation boundary.
inline void validateColdCanonicalMissingRootfsArtifacts(
    const Manifest& manifest,const Request& request,const ColdCanonicalSource& source) {
  require(source.states.size()==manifest.coldCanonicalSource.storage.size() &&
              source.states.size()==source.requestedContainerUUIDs.size(),
          "cold canonical missing-rootfs source is incomplete");
  for (uint32_t index=0;index<source.states.size();++index) {
    const auto& sealed=manifest.coldCanonicalSource.storage[index];
    const auto& state=source.states[index];
    require(sealed.containerUUID==source.requestedContainerUUIDs[index] &&
                state.plan.uuid==sealed.containerUUID,
            "cold canonical missing-rootfs identity differs");
    if (sealed.rootfsMetadata!="missing"_ctv) continue;
    const uint64_t deploymentID=state.plan.config.deploymentID();
    const auto plan=request.plans.find(deploymentID);
    require(deploymentID!=0 && plan!=request.plans.end(),
            "cold canonical missing-rootfs deployment plan is unavailable");
    String selectedConfig={}, approvedConfig={};
    ApplicationConfig selected=state.plan.config, approved=plan->second.config;
    BitseryEngine::serialize(selectedConfig,selected);
    BitseryEngine::serialize(approvedConfig,approved);
    require(selectedConfig==approvedConfig,
            "cold canonical missing-rootfs deployment config differs");
    const Manifest::ArtifactInput *artifact=nullptr;
    for (const auto& candidate:manifest.artifacts) if (candidate.deploymentID==deploymentID) {
      require(artifact==nullptr,"cold canonical missing-rootfs artifact is duplicated");
      artifact=&candidate;
    }
    require(artifact!=nullptr,"cold canonical missing-rootfs artifact is absent");
    const DeploymentPlan& bound=bindRecoveryArtifact(request,deploymentID,&source);
    require(bound.config.containerBlobSHA256==artifact->sha256 &&
                bound.config.containerBlobBytes==artifact->bytes,
            "cold canonical missing-rootfs artifact differs from sealed deployment plan");
  }
}
// Local, fenced artifact preparation.  It works only after the same sealed
// request has verified the private prepared snapshot; ContainerStore retains
// no-replace ownership of the final image path.
inline bool prepareArtifactLocal(const char *requestPath,const char *statePath,uint64_t deploymentID,
                                 const char *blobPath,bool verifyOnly,String *failure) {
  try {
    require(deploymentID!=0 && blobPath!=nullptr && blobPath[0]!=0,
            "recovery artifact input is invalid");
    privateFile(requestPath); const std::string state=statePath, blob=blobPath;
    pathCheck(state); pathCheck(blob); privateFile(blob);
    require(prepareLocal(requestPath,statePath,true,failure,String{}),
            failure && failure->size() ? str(*failure).c_str() : "recovery artifact requires a prepared snapshot");
    Request request={}; MothershipRetainedRecoveryMixedProof proof={}; uint128_t retired=0,empty=0;
    ColdCanonicalSource cold={}; ProdigyMaterializedStatefulRecoveryOperation handoff={};
    MothershipRetainedRecoveryOrphanedStatefulPredecessor orphan={};
    require(decodeRequest(read(requestPath),request,&proof,&retired,&empty,&cold,&handoff,&orphan),
            "recovery artifact request decode failed");
    const DeploymentPlan& plan=bindRecoveryArtifact(request,deploymentID,&cold);
    ProdigyPersistentBrainSnapshot prepared={}; loadSnapshot(state,prepared);
    const auto preparedPlan=prepared.masterAuthority.deploymentPlans.find(deploymentID);
    require(preparedPlan!=prepared.masterAuthority.deploymentPlans.end() &&
                mothershipRetainedRecoveryPlansEqual(preparedPlan->second,plan),
            "recovery artifact prepared snapshot plan differs");
    if (verifyOnly) {
      require(ContainerStore::verify(deploymentID,plan.config.containerBlobSHA256,
                                     plan.config.containerBlobBytes,nullptr,nullptr,failure),
              failure && failure->size() ? str(*failure).c_str() : "recovery artifact final is unavailable");
      return true;
    }
    String blobBytes={}; Filesystem::openReadAtClose(-1,text(blob),blobBytes);
    String stage=ContainerStore::pathForContainerImage(deploymentID);
    stage.append(".retained-recovery.XXXXXX"_ctv); stage.addNullTerminator();
    const int stageFD=::mkstemp(reinterpret_cast<char*>(stage.data()));
    require(stageFD>=0,"recovery artifact stage creation failed");
    struct stat createdStage = {}; require(::fstat(stageFD,&createdStage)==0,"recovery artifact stage identity failed");
    ::close(stageFD);
    ContainerStore::PreparedAppArtifact preparedArtifact={}; String artifactFailure={};
    if (!ContainerStore::prepareAppArtifactAtPath(preparedArtifact,deploymentID,stage,blobBytes,
                plan.config.containerBlobSHA256,plan.config.containerBlobBytes,&artifactFailure)) {
      // Only remove the empty inode this invocation created. A different inode
      // may be a raced immutable artifact and is never ours to delete.
      struct stat currentStage = {};
      if (::stat(stage.c_str(),&currentStage)==0 && currentStage.st_dev==createdStage.st_dev &&
          currentStage.st_ino==createdStage.st_ino) (void)::unlink(stage.c_str());
      require(false,artifactFailure.size()?str(artifactFailure).c_str():"recovery artifact preparation failed");
    }
    if (!ContainerStore::publishPreparedAppArtifact(preparedArtifact,&artifactFailure) ||
        !ContainerStore::adoptPreparedAppArtifact(preparedArtifact)) {
      ContainerStore::discardPreparedAppArtifact(preparedArtifact);
      require(false,artifactFailure.size()?str(artifactFailure).c_str():"recovery artifact publication failed");
    }
    require(ContainerStore::verify(deploymentID,plan.config.containerBlobSHA256,
                                   plan.config.containerBlobBytes,nullptr,nullptr,&artifactFailure),
            artifactFailure.size()?str(artifactFailure).c_str():"recovery artifact verification failed");
    return true;
  } catch(const std::exception& error) { if(failure)failure->assign(error.what()); return false; }
}
inline void loadSnapshot(const std::string& path,ProdigyPersistentBrainSnapshot& snapshot) {
  require(fs::is_directory(path) && fs::is_directory(path+".secrets") && !fs::is_symlink(path) && !fs::is_symlink(path+".secrets"),"paired private recovery databases absent");
  ProdigyPersistentStateStore store(text(path)); String failure;
  require(store.loadBrainSnapshot(snapshot,&failure),"private recovery snapshot unreadable");
}
inline void runtimeStartupPrivateOperationRoot(const std::string& operationRoot,const std::string& statePath) {
  require(!operationRoot.empty() && fs::path(statePath)==fs::path(operationRoot)/"state.new10" &&
              fs::is_directory(operationRoot) && !fs::is_symlink(operationRoot),
          "runtime startup preparation requires its operation-private state.new10 copy");
  struct stat root={};
  require(::lstat(operationRoot.c_str(),&root)==0 && S_ISDIR(root.st_mode) && !(root.st_mode&0077) && root.st_uid==::geteuid(),
          "runtime startup operation root is not private and owned");
  require(fs::is_directory(statePath) && fs::is_directory(statePath+".secrets") &&
              !fs::is_symlink(statePath) && !fs::is_symlink(statePath+".secrets"),
          "runtime startup paired private copy is absent");
}
inline bool runtimeStartupSnapshotDigest(const ProdigyPersistentBrainSnapshot& snapshot,String& digest,String *failure=nullptr) {
  ProdigyPersistentBrainSnapshot copy=snapshot; String bytes={};
  return BitseryEngine::serialize(bytes,copy) && prodigyComputeSHA256Hex(bytes,digest,failure);
}
inline const RuntimeStartupSource *runtimeStartupSourceForMember(const RuntimeStartupRequest& request,uint128_t memberUUID) {
  for (const RuntimeStartupSource& source : request.sources) if (source.memberUUID==memberUUID) return &source;
  return nullptr;
}
inline bool runtimeStartupSourceMatches(const RuntimeStartupRequest& request,uint128_t memberUUID,
                                        const String& exactSnapshotSHA256) {
  const RuntimeStartupSource *source=runtimeStartupSourceForMember(request,memberUUID);
  return source!=nullptr && source->snapshotSHA256==exactSnapshotSHA256;
}
// This operation only writes a caller-created private paired copy.  In
// particular, sourceSnapshotSHA256 is a digest of the captured raw bytes, not
// a digest recomputed from decoded maps here.
inline bool prepareRuntimeStartupPrivate(const RuntimeStartupRequest& request,
                                         const ProdigyPersistentLocalBrainState& sourceLocal,
                                         const ProdigyPersistentBrainSnapshot& sourceSnapshot,
                                         uint128_t memberUUID,const String& exactRequestSHA256,const String& sourceSnapshotSHA256,
                                         const std::string& operationRoot,const std::string& copiedPrivateStatePath,
                                         RuntimeStartupPrepared& prepared,String *failure=nullptr) {
  try {
    require(prodigyIsSHA256HexDigest(exactRequestSHA256) && runtimeStartupRequestValid(request,failure),
            failure && failure->size() ? str(*failure).c_str() : "runtime startup request is invalid");
    require(runtimeStartupSourceMatches(request,memberUUID,sourceSnapshotSHA256) && sourceLocal.uuid==memberUUID &&
                sourceLocal.ownerClusterUUID==request.clusterUUID && sourceSnapshot.brainConfig.clusterUUID==request.clusterUUID,
            "runtime startup source identity or captured snapshot proof differs");
    const String& recordedRejected=sourceSnapshot.masterAuthority.runtimeState.updateSelf.workerExpectedBundleSHA256;
    require(recordedRejected.empty() ||
                (prodigyIsSHA256HexDigest(recordedRejected) &&
                 request.rejectedCandidateSHA256==recordedRejected),
            "runtime startup rejected candidate is not the captured update-self value");
    runtimeStartupPrivateOperationRoot(operationRoot,copiedPrivateStatePath);
    String why={};
    ProdigyPersistentLocalBrainState copiedLocal={}; ProdigyPersistentBrainSnapshot copiedSnapshot={};
    {
      ProdigyPersistentStateStore store(text(copiedPrivateStatePath));
      require(store.loadLocalBrainState(copiedLocal,&why) && store.loadBrainSnapshot(copiedSnapshot,&why) &&
                  prodigyPersistentSerializedEqual(copiedLocal,sourceLocal),
              "runtime startup private copy local authority differs from captured source");
    }
    ProdigyPersistentBrainSnapshot expected={};
    require(mothershipPrepareRuntimeRecoveryStartupAuthority(sourceLocal,sourceSnapshot,request.clusterUUID,memberUUID,
                request.topology,sourceSnapshot.masterAuthority.deploymentPlans,request.machines,
                request.targetBundleSHA256,request.sourceBundleSHA256,request.rejectedCandidateSHA256,expected,&why),
            why.size()?str(why).c_str():"runtime startup authority preparation failed");
    ProdigyPersistentBrainSnapshot comparable=expected;
    if (witnessesEquivalent(copiedSnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses,
                            expected.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses))
      comparable.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses=
          copiedSnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
    if (!prodigyPersistentBrainSnapshotsEqual(copiedSnapshot,comparable)) {
      require(prodigyPersistentBrainSnapshotsEqual(copiedSnapshot,sourceSnapshot),
              "runtime startup private copy is neither source nor idempotently prepared");
      {
        ProdigyPersistentStateStore store(text(copiedPrivateStatePath));
        require(store.saveBrainSnapshot(expected,&why),why.size()?str(why).c_str():"runtime startup private snapshot save failed");
      }
      loadSnapshot(copiedPrivateStatePath,copiedSnapshot);
    }
    require(prodigyPersistentBrainSnapshotsEqual(copiedSnapshot,comparable) ||
                prodigyPersistentBrainSnapshotsEqual(copiedSnapshot,expected),"runtime startup private snapshot readback differs");
    RuntimeStartupPrepared result={}; result.requestSHA256=exactRequestSHA256; result.sourceSnapshotSHA256=sourceSnapshotSHA256;
    require(runtimeStartupSnapshotDigest(copiedSnapshot,result.preparedSnapshotSHA256,&why),"runtime startup prepared digest failed");
    result.candidateWitnesses.requestSHA=exactRequestSHA256;
    result.candidateWitnesses.witnesses=copiedSnapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses;
    prepared=std::move(result); return true;
  } catch(const std::exception& error) { if(failure) failure->assign(error.what()); return false; }
}
// The controller seals one witness byte sequence after semantic comparison of
// all three candidates.  Finalization accepts only that same request and only
// replaces the witness vector in an already prepared private copy.
inline bool finalizeRuntimeStartupPrivate(const RuntimeStartupRequest& request,
                                          const ProdigyPersistentLocalBrainState& sourceLocal,
                                          const ProdigyPersistentBrainSnapshot& sourceSnapshot,
                                          uint128_t memberUUID,const String& exactRequestSHA256,const String& sourceSnapshotSHA256,
                                          const std::string& operationRoot,const std::string& copiedPrivateStatePath,
                                          const WitnessSet& sealed,RuntimeStartupPrepared& prepared,String *failure=nullptr) {
  try {
    RuntimeStartupPrepared candidate={}; String why={};
    require(prepareRuntimeStartupPrivate(request,sourceLocal,sourceSnapshot,memberUUID,exactRequestSHA256,sourceSnapshotSHA256,
                operationRoot,copiedPrivateStatePath,candidate,&why),why.size()?str(why).c_str():"runtime startup preparation failed");
    require(sealed.requestSHA==candidate.requestSHA256 &&
                witnessesEquivalent(candidate.candidateWitnesses.witnesses,sealed.witnesses),
            "runtime startup sealed witnesses differ from prepared candidate");
    ProdigyPersistentBrainSnapshot snapshot={};
    {
      ProdigyPersistentStateStore store(text(copiedPrivateStatePath));
      require(store.loadBrainSnapshot(snapshot,&why),"runtime startup prepared copy is unreadable");
      if (!witnessesExact(snapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses,sealed.witnesses)) {
        snapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses=sealed.witnesses;
        require(store.saveBrainSnapshot(snapshot,&why),why.size()?str(why).c_str():"runtime startup sealed witness save failed");
      }
    }
    ProdigyPersistentBrainSnapshot readback={}; loadSnapshot(copiedPrivateStatePath,readback);
    require(prodigyPersistentBrainSnapshotsEqual(snapshot,readback),"runtime startup sealed witness readback differs");
    prepared=candidate; prepared.candidateWitnesses=sealed;
    require(runtimeStartupSnapshotDigest(readback,prepared.preparedSnapshotSHA256,&why),"runtime startup sealed digest failed");
    return true;
  } catch(const std::exception& error) { if(failure) failure->assign(error.what()); return false; }
}
// The paired publication is intentionally independent of any recovery
// envelope.  A caller persists after each individual rename so an interrupted
// operation can reconcile only the proven pair state on re-entry.
template<typename Databases,typename Exists,typename Rename,typename Persist>
inline void publishPreparedPairedRecoveryDatabases(Databases& databases,Exists&& exists,Rename&& rename,Persist&& persist) {
  for (auto& database : databases) {
    if (database.swapped) continue;
    String why={};
    const bool live=exists(database,database.livePath);
    const bool retained=exists(database,database.retainedV9Path);
    const bool prepared=exists(database,database.preparedV10Path);
    require(!(live && retained && prepared),"ambiguous retained database swap");
    if (live && !retained && prepared)
      require(rename(database,database.livePath,database.retainedV9Path,&why),"retained original rename failed");
    if (!exists(database,database.livePath) && prepared)
      require(rename(database,database.preparedV10Path,database.livePath,&why),"prepared recovery rename failed");
    require(exists(database,database.livePath) && exists(database,database.retainedV9Path) &&
                !exists(database,database.preparedV10Path),"retained recovery swap incomplete");
    database.swapped=true; persist();
  }
}
inline ColdCanonicalSource deriveColdCanonicalSource(const Manifest& manifest, uint128_t emptyMachineUUID,
                                                      const ProdigyPersistentBrainSnapshot *approvedSnapshot = nullptr,
                                                      const std::string& extractionPath = {}) {
  require(manifest.coldCanonicalSource.requestedContainerUUIDs.empty()==false &&
              manifest.emptyRetainedInventoryMachineUUID==emptyMachineUUID,
          "cold canonical source is not bound to the empty retained machine");
  require(!extractionPath.empty(),"cold canonical source requires a private extraction copy");
  ProdigyPersistentBrainSnapshot source={};
  loadSnapshot(extractionPath,source);
  require(source.brainConfig.clusterUUID==manifest.request.clusterUUID && source.topology.machines.size()==3,
          "cold canonical source cluster or topology differs");
  for (const MothershipRetainedRecoveryMachineInput& expected : manifest.request.machines) {
    bool found=false;
    for (const ClusterMachine& observed : source.topology.machines) found|=observed.uuid==expected.machineUUID;
    require(found,"cold canonical source topology machine differs");
  }
  ColdCanonicalSource result={}; result.sourceStatePath.assign(manifest.coldCanonicalSource.statePath.c_str());
  result.sourceSnapshotSHA256.assign(manifest.coldCanonicalSource.aggregateSHA256);
  result.requestedContainerUUIDs=manifest.coldCanonicalSource.requestedContainerUUIDs;
  for (uint128_t requested : result.requestedContainerUUIDs) {
    const BrainReplicatedContainerRuntimeState *found=nullptr;
    for (const BrainReplicatedContainerRuntimeState& candidate : source.masterAuthority.containerRuntimeStates) {
      if (candidate.plan.uuid!=requested) continue;
      require(candidate.machineUUID==emptyMachineUUID && found==nullptr,
              "cold canonical source runtime identity is duplicated or belongs to another machine");
      found=&candidate;
    }
    require(found!=nullptr,"cold canonical source requested runtime is absent");
    if (approvedSnapshot) {
      const uint64_t deploymentID=found->plan.config.deploymentID();
      auto sourcePlan=source.masterAuthority.deploymentPlans.find(deploymentID);
      auto approvedPlan=approvedSnapshot->masterAuthority.deploymentPlans.find(deploymentID);
      require(sourcePlan!=source.masterAuthority.deploymentPlans.end() &&
                  approvedPlan!=approvedSnapshot->masterAuthority.deploymentPlans.end() &&
                  mothershipRetainedRecoveryPlansEqual(sourcePlan->second,approvedPlan->second),
              "cold canonical source deployment plan differs from stopped authority");
    }
    result.states.push_back(*found);
  }
  result.selectedStatesSHA256=coldCanonicalRuntimeStatesDigest(result.states,&result.serializedStates);
  return result;
}
inline std::string coldCanonicalStorageProgram(const Manifest::ColdCanonicalSourceInput& source) {
  std::string entries="[";
  for (uint32_t index=0;index<source.storage.size();++index) {
    if (index) entries+=",";
    String uuidText={}; uuidText.snprintf<"{itoh}"_ctv>(source.storage[index].containerUUID);
    entries+="("+quote(str(uuidText))+","+quote(str(source.storage[index].rootfsMetadata))+","+
        quote(str(source.storage[index].storageMetadata))+")";
  }
  entries+="]";
  return "python3 -c "+quote(
      "import os,stat,sys\nentries="+entries+"\n"
      "for value,expected_root,expected_storage in entries:\n"
      "  name=str(int(value,16)); artifact='/containers/'+name; root=artifact+'/rootfs'; storage='/containers/storage/'+name\n"
      "  def metadata(path):\n"
      "    item=os.lstat(path); assert stat.S_ISDIR(item.st_mode) and not stat.S_ISLNK(item.st_mode); return f'{os.major(item.st_dev)}:{os.minor(item.st_dev)}:{item.st_ino}'\n"
      "  if expected_root == 'missing':\n"
      "    try: os.lstat(artifact)\n"
      "    except FileNotFoundError: pass\n"
      "    else: raise AssertionError('cold artifact root is present')\n"
      "  else: assert metadata(root)==expected_root\n"
      "  assert metadata(storage)==expected_storage\n"
      "print('cold-canonical-storage=verified')\n");
}
inline std::string coldCanonicalExtractionProgram(const std::string& sourcePath,const std::string& extractionPath) {
  const auto parent=fs::path(extractionPath).parent_path().string();
  return "set -eu; umask 077; test -d "+quote(sourcePath)+"; test -d "+quote(sourcePath+".secrets")+
      "; test ! -L "+quote(sourcePath)+"; test ! -L "+quote(sourcePath+".secrets")+
      "; mkdir -p "+quote(parent)+"; test ! -e "+quote(extractionPath+".partial")+
      "; test ! -e "+quote(extractionPath+".secrets.partial")+
      "; rm -rf -- "+quote(extractionPath)+" "+quote(extractionPath+".secrets")+
      "; cp -a --reflink=auto -- "+quote(sourcePath)+" "+quote(extractionPath+".partial")+
      "; cp -a --reflink=auto -- "+quote(sourcePath+".secrets")+" "+quote(extractionPath+".secrets.partial")+
      "; chmod -R go-rwx -- "+quote(extractionPath+".partial")+" "+quote(extractionPath+".secrets.partial")+
      "; mv -T -- "+quote(extractionPath+".partial")+" "+quote(extractionPath)+
      "; mv -T -- "+quote(extractionPath+".secrets.partial")+" "+quote(extractionPath+".secrets")+
      "; sync -f "+quote(parent);
}
inline std::string coldCanonicalExtractionCleanupProgram(const std::string& extractionPath) {
  return "set -eu; rm -rf -- "+quote(extractionPath)+" "+quote(extractionPath+".secrets")+
      "; test ! -e "+quote(extractionPath)+"; test ! -e "+quote(extractionPath+".secrets");
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
struct PopulatedSeedRuntimeRepairRequest {
  MothershipInitialSeedRuntimeRepairBinding binding;
  MothershipPopulatedSeedRuntimeRepairProof proof;
};
template<typename S> void serialize(S&& s,PopulatedSeedRuntimeRepairRequest& request) {
  s.object(request.binding);s.object(request.proof);
}
// Only digests and non-secret identity/state scalars leave the private decoder.
// The paired copies retain the exact payload bytes; no caller invents them.
inline String populatedSeedSnapshotEvidence(const ProdigyPersistentBrainSnapshot& snapshot,
                                           const MothershipInitialSeedRuntimeRepairBinding& binding) {
  auto id=[](uint128_t value) { String encoded;encoded.assignItoh(value);return str(encoded); };
  std::string output="ISRR2_SCOPE "+str(binding.initialSeedScopeSHA256)+" 43 43\n";
  auto rows=[&](const Vector<BrainReplicatedContainerRuntimeState>& states) {
    std::vector<const BrainReplicatedContainerRuntimeState *> ordered;
    for(const auto& state:states)ordered.push_back(&state);
    std::sort(ordered.begin(),ordered.end(),[](auto a,auto b){return a->plan.uuid<b->plan.uuid;});
    for(const auto *state:ordered) {
      String digest;require(prodigyStatefulServingRuntimeDigest(*state,digest),"repair snapshot payload digest failed");
      output+=id(state->plan.uuid)+" "+id(state->machineUUID)+" "+std::to_string(unsigned(state->plan.state))+" "+
          std::to_string(unsigned(state->plan.runtimeReady))+" "+std::to_string(state->plan.nShardGroups)+" "+str(digest)+"\n";
    }
  };
  rows(snapshot.masterAuthority.servingRuntimeStates);
  output+="CANONICAL\n";rows(snapshot.masterAuthority.containerRuntimeStates);
  for(const auto& [deployment,record]:snapshot.masterAuthority.failedDeployments) {
    auto copy=record;String bytes,digest;
    require(BitseryEngine::serialize(bytes,copy) && prodigyComputeSHA256Hex(bytes,digest),"repair failure record digest failed");
    output+="FAILURE "+std::to_string(deployment)+" "+str(digest)+"\n";
  }
  return text(output);
}
// Only the staged Mothership invokes this against its private paired copy.
inline bool prepareLocal(const char *requestPath,const char *statePath,bool verifyOnly,String *failure,const String& previousBundleSHA256={}) {
  try {
    privateFile(requestPath); const std::string path=statePath;pathCheck(path);
    const auto requestBytes=read(requestPath);
    if (requestBytes.starts_with("ISRR2\n")) {
      require(verifyOnly && previousBundleSHA256.empty() && ::getenv("PRODIGY_STATE_SECRETS_DB")==nullptr &&
              path==(fs::path(requestPath).parent_path()/"state.check10").string(),
              "populated seed repair verifies only its paired private copy");
      PopulatedSeedRuntimeRepairRequest request;
      require(BitseryEngine::deserializeSafe(text(requestBytes.substr(6)),request),"populated seed repair binding invalid");
      ProdigyPersistentBrainSnapshot snapshot;loadSnapshot(path,snapshot);
      require(mothershipInitialSeedRuntimeRepairSnapshotValid(snapshot,request.binding,&request.proof),
              "populated seed repair snapshot admission failed");
      const auto evidence=fs::path(requestPath).parent_path()/"repair.snapshot-proof";
      const auto bytes=populatedSeedSnapshotEvidence(snapshot,request.binding);
      if(fs::exists(evidence)) {privateFile(evidence);require(read(evidence)==str(bytes),"populated seed snapshot proof changed");}
      else durable(evidence,bytes);
      return true;
    }
    if (requestBytes.starts_with("ISRR1\n")) {
      require(verifyOnly && previousBundleSHA256.empty() && ::getenv("PRODIGY_STATE_SECRETS_DB")==nullptr &&
              path==(fs::path(requestPath).parent_path()/"state.check10").string(),
              "initial seed repair verifies only its paired private copy");
      MothershipInitialSeedRuntimeRepairBinding binding;
      require(BitseryEngine::deserializeSafe(text(requestBytes.substr(6)),binding),"initial seed repair binding invalid");
      ProdigyPersistentBrainSnapshot snapshot; loadSnapshot(path,snapshot);
      require(mothershipInitialSeedRuntimeRepairSnapshotValid(snapshot,binding),"initial seed repair snapshot admission failed");
      return true;
    }
    require(path.ends_with("/state.new10") || (verifyOnly && path=="/var/lib/prodigy/state"),"recovery suboperation refuses an unowned database path");
    require(::getenv("PRODIGY_STATE_SECRETS_DB")==nullptr,"recovery refuses a secrets-path override");
    Request request; MothershipRetainedRecoveryMixedProof proof; uint128_t retiredConflictingClientUUID=0, emptyRetainedInventoryMachineUUID=0;
    ColdCanonicalSource coldCanonicalSource = {};
    ProdigyMaterializedStatefulRecoveryOperation partialHandoff = {};
    MothershipRetainedRecoveryOrphanedStatefulPredecessor orphanedPredecessor = {};
    require(decodeRequest(read(requestPath),request,&proof,&retiredConflictingClientUUID,
                          &emptyRetainedInventoryMachineUUID,&coldCanonicalSource,&partialHandoff,
                          &orphanedPredecessor),"recovery request decode failed");
    require(coldCanonicalSource.states.empty() ||
                (emptyRetainedInventoryMachineUUID != 0 && retiredConflictingClientUUID == 0 &&
                 coldCanonicalUUIDsAreStrictlySorted(coldCanonicalSource.requestedContainerUUIDs) &&
                 coldCanonicalSource.states.size()==coldCanonicalSource.requestedContainerUUIDs.size() &&
                 coldCanonicalPayloadDigest(coldCanonicalSource.serializedStates)==coldCanonicalSource.selectedStatesSHA256),
            "cold canonical source request is inconsistent");
    require(emptyRetainedInventoryMachineUUID == 0 || request.interruptedBundleSHA.empty(),
            "empty retained inventory cannot reinterpret an interrupted handoff");
    ProdigyPersistentBrainSnapshot before;loadSnapshot(path,before);require(before.brainConfig.clusterUUID==request.clusterUUID,"recovery request targets another cluster");
    const bool alreadyPrepared=mothershipRetainedRecoveryEnvelopeMatches(
        before.masterAuthority.runtimeState.updateSelf,request.bundleSHA);
    const bool retiringOrphanedStatefulPredecessor = orphanedPredecessor.parameters.uuid != 0;
    Vector<MothershipRetainedRecoverySealedSuccessorBootstrap> sealedOrphanSuccessors = {};
    if (retiringOrphanedStatefulPredecessor) {
      auto successor=request.plans.find(orphanedPredecessor.operation.successorDeploymentID);
      require(successor!=request.plans.end() && successor->second.isStateful && !successor->second.stateful.allMasters &&
                  successor->second.config.containerBlobSHA256.equals(orphanedPredecessor.operation.successorBlobSHA256),
              "orphaned stateful predecessor request does not bind its approved successor");
      String orphanFailure = {};
      require(mothershipRetainedRecoveryOrphanedStatefulPredecessorMatchesSnapshot(
                  before,orphanedPredecessor,&orphanFailure,alreadyPrepared),str(orphanFailure).c_str());
      bytell_hash_set<uint128_t> successorUUIDs = {}; uint32_t successorClients = 0;
      for (const auto& sealed : orphanedPredecessor.successorBootstraps) {
        NeuronContainerBootstrap observed = {};
        require(sealed.machineUUID != 0 && BitseryEngine::deserializeSafe(sealed.bootstrap, observed) &&
                    observed.plan.isStateful && observed.plan.config.deploymentID() == successor->first &&
                    observed.plan.lifetime == ApplicationLifetime::base && observed.plan.shardGroup == 0 &&
                    observed.plan.state == ContainerState::healthy && observed.plan.runtimeReady &&
                    successorUUIDs.insert(observed.plan.uuid).second,
                "orphaned stateful predecessor sealed successor proof is invalid");
        bool matched = false;
        for (const auto& machine : request.machines) for (uint32_t i=0;i<machine.parameters.size();++i) {
          const auto& parameters=machine.parameters[i]; if (machine.machineUUID != sealed.machineUUID || parameters.uuid != observed.plan.uuid) continue;
          NeuronContainerBootstrap reconstructed = {}; String why = {};
          require(prodigyBuildRetainedContainerBootstrap(successor->second, parameters, machine.machineFragment,
                  before.brainConfig.datacenterFragment, machine.observedCreatedAtMs[i], reconstructed, &why) &&
                  mothershipRetainedRecoveryBootstrapMatchesObservedLifecycle(observed,reconstructed),
                  "orphaned stateful predecessor sealed successor differs from current canonical request");
          matched = true; successorClients += observed.plan.statefulMeshRoles.client != 0;
        }
        require(matched,"orphaned stateful predecessor sealed successor is not canonical");
      }
      require(successorUUIDs.size()==2 && successorClients==1,
              "orphaned stateful predecessor does not retain an exact 2+1 healthy successor cohort");
      sealedOrphanSuccessors = orphanedPredecessor.successorBootstraps;
    }
    require(!proof.canonicalContainerCount || proof.validFor(before),"recovery request proof differs from frozen topology");
    const auto witnessPath=std::string(requestPath)+".witnesses";privateFile(witnessPath);
    WitnessSet sealed;require(BitseryEngine::deserializeSafe(text(read(witnessPath)),sealed) && sealed.requestSHA==text(digest(requestPath)),"sealed recovery witnesses differ from request");
    // An interrupted normal update is active too. Only the recovery envelope
    // may skip a generation increment on retry; verify its witnesses below.
    require(!verifyOnly || alreadyPrepared,"recovery snapshot is not prepared");
    auto expected=before;
    if(alreadyPrepared && retiredConflictingClientUUID == 0) {
      expected.masterAuthority.runtimeState.updateSelf={};
      require(expected.masterAuthority.runtimeState.generation>0,"recovery generation missing"); --expected.masterAuthority.runtimeState.generation;
    }
    if (retiringOrphanedStatefulPredecessor) {
      bytell_hash_set<uint128_t> sealedLineageUUIDs = {};
      sealedLineageUUIDs.insert(orphanedPredecessor.parameters.uuid);
      for (const auto& sealedSuccessor : sealedOrphanSuccessors) {
        NeuronContainerBootstrap bootstrap = {};
        require(BitseryEngine::deserializeSafe(sealedSuccessor.bootstrap, bootstrap),
                "orphaned stateful predecessor sealed successor cannot be decoded");
        sealedLineageUUIDs.insert(bootstrap.plan.uuid);
      }
      const uint64_t activeID = orphanedPredecessor.operation.activeDeploymentID;
      auto requestedActivePlan = request.plans.find(activeID);
      require(requestedActivePlan != request.plans.end(),
              "orphaned stateful predecessor proof-only active plan is absent");
      auto persistedActivePlan = expected.masterAuthority.deploymentPlans.find(activeID);
      require(persistedActivePlan == expected.masterAuthority.deploymentPlans.end() ||
                  mothershipRetainedRecoveryPlansEqual(
                      persistedActivePlan->second, requestedActivePlan->second),
              "orphaned stateful predecessor retained active plan differs from sealed authority");
      for (const auto& machine : request.machines)
        for (const auto& parameters : machine.parameters)
          require(parameters.deploymentID != activeID,
                  "orphaned stateful predecessor proof-only active plan is canonical");
      expected.masterAuthority.deploymentPlans.erase(activeID);
      auto& states=expected.masterAuthority.containerRuntimeStates;
      for (const auto& state : states) {
        const uint64_t deploymentID = state.plan.config.deploymentID();
        if (deploymentID != orphanedPredecessor.operation.activeDeploymentID &&
            deploymentID != orphanedPredecessor.operation.successorDeploymentID) continue;
        if (sealedLineageUUIDs.contains(state.plan.uuid)) continue;
        require((state.plan.state == ContainerState::planned || state.plan.state == ContainerState::scheduled) &&
                    !state.plan.runtimeReady,
                "orphaned stateful predecessor retains an unknown healthy or ready lineage record");
      }
      states.erase(std::remove_if(states.begin(),states.end(),[&](const auto& state) {
        return state.plan.config.deploymentID()==orphanedPredecessor.operation.activeDeploymentID ||
               state.plan.config.deploymentID()==orphanedPredecessor.operation.successorDeploymentID;
      }),states.end());
      for (const auto& state:states)
        require(state.plan.uuid!=orphanedPredecessor.parameters.uuid,
                "orphaned stateful predecessor runtime UUID changed machine identity");
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
                                                        emptyRetainedInventoryMachineUUID,coldCanonicalSource.states,
                                                        partialHandoff.operationID.empty()?nullptr:&partialHandoff,
                                                        retiringOrphanedStatefulPredecessor ? orphanedPredecessor.rejectedCandidateSHA256 : String{}),str(why).c_str());
    }
    if (retiringOrphanedStatefulPredecessor) {
      for (const auto& sealedSuccessor : sealedOrphanSuccessors) {
        NeuronContainerBootstrap bootstrap = {};
        require(BitseryEngine::deserializeSafe(sealedSuccessor.bootstrap, bootstrap),
                "orphaned stateful predecessor sealed successor cannot be restored");
        BrainReplicatedContainerRuntimeState canonical = {};
        canonical.machineUUID = sealedSuccessor.machineUUID; canonical.plan = bootstrap.plan;
        canonical.plan.state = ContainerState::scheduled; canonical.plan.runtimeReady = false;
        canonical.runtimeLogicalCores = uint16_t(applicationSharedCPUCoreHint(canonical.plan.config));
        canonical.runtimeMemoryMB = canonical.plan.config.totalMemoryMB();
        canonical.runtimeStorageMB = canonical.plan.config.totalStorageMB();
        expected.masterAuthority.containerRuntimeStates.push_back(std::move(canonical));
      }
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
print('pinned extras retired')
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
  // A schema-one predecessor records the runtime observed before containment
  // on every machine.  The contained successor instead records the receipt's
  // one installed identity on every machine; project that factual transition
  // before applying the complete immutable target comparison.
  for(const auto& machine:predecessor.machines)
    if(machine.installedRuntimeSHA!=predecessor.oldRuntimeSHA || machine.installedBundleSHA!=predecessor.oldBundleSHA)
      return false;
  Plan current=predecessor;
  current.oldRuntimeSHA=successor.oldRuntimeSHA;
  current.oldBundleSHA=successor.oldBundleSHA;
  for(auto& machine:current.machines) {
    machine.installedRuntimeSHA=successor.oldRuntimeSHA;
    machine.installedBundleSHA=successor.oldBundleSHA;
  }
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
// Provider credentials and submission stay in Mothership. Preparation freezes
// the existing durable/live cloud identity projection before any Brain stops;
// reboot never attempts a topology query against the fenced fleet.
struct InitialSeedRuntimeRepairHooks {
  virtual ~InitialSeedRuntimeRepairHooks()=default;
  virtual bool prepare(Execution&,MothershipInitialSeedRuntimeRepairBinding&,String *failure)=0;
  virtual bool reboot(Execution&,uint128_t machineUUID,String *failure)=0;
};
inline std::string repairJSON(const std::string& value) {
  String result; prodigyAppendEscapedJSONStringLiteral(result,text(value)); return str(result);
}
inline std::string repairID(uint128_t value) { String result; result.assignItoh(value); return str(result); }
template<typename T> inline std::string repairObjectSHA(T value) {
  String bytes,hash; require(BitseryEngine::serialize(bytes,value) && prodigyComputeSHA256Hex(bytes,hash),"repair authority digest failed"); return str(hash);
}
inline uint64_t repairNumber(simdjson::dom::element value,const char *key) {
  uint64_t result=0; require(value[key].get_uint64().get(result)==simdjson::SUCCESS && result,"missing repair integer"); return result;
}
inline void repairSeal(const fs::path& path,const String& bytes) {
  if (fs::exists(path)) { privateFile(path); require(read(path)==str(bytes),"immutable repair evidence changed"); }
  else durable(path,bytes);
}
struct InitialSeedRuntimeRepairManifest {
  MothershipInitialSeedRuntimeRepairBinding binding;
  bool populatedSeed=false;
  MothershipPopulatedSeedRuntimeRepairProof populatedProof;
  std::string successorBundleSHA,successorRuntimeSHA,gatewayArtifactSHA,gatewayExecutableSHA;
  uint64_t gatewayArtifactBytes=0,gatewayExecutableBytes=0;
};
inline InitialSeedRuntimeRepairManifest parseInitialSeedRepairManifest(const std::string& file,Execution& e) {
  privateFile(file); simdjson::dom::parser parser; simdjson::dom::element doc;
  auto bytes=read(file); require(parser.parse(bytes).get(doc)==simdjson::SUCCESS,"invalid initial seed repair manifest");
  bool sameState=false,sameWire=false;
  const auto predecessor=repairNumber(doc,"predecessorRuntimeRevision"),successor=repairNumber(doc,"successorRuntimeRevision");
  const bool divergentScope=predecessor==53 && successor==54;
  const bool replicatedScope=predecessor==54 && successor==55;
  const bool populatedScope=predecessor==55 && successor==56;
  require(repairNumber(doc,"schemaVersion")==1 && (divergentScope || replicatedScope || populatedScope) &&
          doc["stateFormatUnchanged"].get_bool().get(sameState)==simdjson::SUCCESS && sameState &&
          doc["wireFormatUnchanged"].get_bool().get(sameWire)==simdjson::SUCCESS && sameWire,
          "repair requires the explicitly approved same-format runtime53 to runtime54 or runtime54 to runtime55 contract");
  InitialSeedRuntimeRepairManifest m; auto& b=m.binding;
  b.clusterUUID=uuid(field(doc,"clusterUUID")); b.masterMachineUUID=uuid(field(doc,"masterMachineUUID"));
  b.initialSeedOperationUUID=uuid(field(doc,"initialSeedOperationUUID")); b.deploymentID=repairNumber(doc,"pendingDeploymentID");
  b.masterGeneration=repairNumber(doc,"masterAuthorityGeneration"); b.followerGeneration=repairNumber(doc,"followerAuthorityGeneration");
  b.initialSeedIntentSHA256=text(field(doc,"initialSeedIntentSHA256"));
  m.successorBundleSHA=field(doc,"expectedNewBundleSHA256"); m.successorRuntimeSHA=field(doc,"expectedNewRuntimeSHA256");
  m.gatewayArtifactSHA=field(doc,"gatewayArtifactSHA256"); m.gatewayArtifactBytes=repairNumber(doc,"gatewayArtifactBytes");
  m.gatewayExecutableSHA=field(doc,"gatewayExecutableSHA256"); m.gatewayExecutableBytes=repairNumber(doc,"gatewayExecutableBytes");
  for (const auto& hash:{m.successorBundleSHA,m.successorRuntimeSHA,m.gatewayArtifactSHA,m.gatewayExecutableSHA,str(b.initialSeedIntentSHA256)})
    require(prodigyIsSHA256HexDigest(text(hash)),"invalid initial seed repair digest");
  require(b.clusterUUID==e.plan.clusterUUID && b.masterMachineUUID==e.plan.machines[0].uuid &&
          b.followerGeneration!=UINT64_MAX &&
          ((replicatedScope || populatedScope) ? b.masterGeneration==b.followerGeneration : b.masterGeneration==b.followerGeneration+1) &&
          m.successorBundleSHA==str(e.receipt.approvedBundleSHA256) && m.successorRuntimeSHA==str(e.receipt.newRuntimeSHA256),
          "repair bundle, frozen master or generation mismatch");
  for (const auto& machine:e.plan.machines) b.machineUUIDs.push_back(machine.uuid);
  if(populatedScope) {
    require(e.plan.oldRuntimeSHA=="7018687562fb4dba5bc45c8d37febc968a23109e739d57c9d617b1e0d8d8da81" &&
            e.plan.oldBundleSHA=="d6ee8470f4db8017dc8a13ce17879d1b0431a21b8b726c354aadf50ff3299ddd",
            "populated repair requires the exact installed runtime55 predecessor");
    for(const auto& machine:e.plan.machines) {
      const char *mid=machine.uuid==MothershipPopulatedSeedRepair::master ? "30b778da1b2745ea8438931b72d01963" :
          machine.uuid==MothershipPopulatedSeedRepair::ord0 ? "b8250f81b66f4cfe9c3111316b16a12f" :
          machine.uuid==MothershipPopulatedSeedRepair::ord2 ? "78c6a43624b94d90a9d3d69a8b4fa80a" : "";
      require(*mid && machine.linuxID==mid,"populated repair original Linux machine identity differs");
    }
    simdjson::dom::element value;
    require(doc["populatedSeed"].get(value)==simdjson::SUCCESS,"populated repair process proof missing");
    auto& p=m.populatedProof;p.predecessorRevision=55;p.successorRevision=56;
    p.pulseMachineUUID=uuid(field(value,"pulseMachineUUID"));p.pulseContainerUUID=uuid(field(value,"pulseContainerUUID"));
    p.pulsePID=repairNumber(value,"pulsePID");p.pulseStartTicks=repairNumber(value,"pulseStartTicks");
    p.pulseExecutableSHA256=text(field(value,"pulseExecutableSHA256"));p.pulseExecutableBytes=repairNumber(value,"pulseExecutableBytes");
    p.parametersSHA256=text(field(value,"pulseParametersSHA256"));
    const auto parametersPath=field(value,"pulseParametersPath");pathCheck(parametersPath);privateFile(parametersPath,1024*1024);
    require(digest(parametersPath)==str(p.parametersSHA256),"populated repair parameters digest mismatch");
    p.startupParameters=text(read(parametersPath));
    p.storageDevice=repairNumber(value,"pulseStorageDevice");p.storageInode=repairNumber(value,"pulseStorageInode");
    p.storageUID=repairNumber(value,"pulseStorageUID");p.storageGID=repairNumber(value,"pulseStorageGID");
    p.bootID=text(field(value,"pulseBootID"));p.linuxMachineID=text(field(value,"pulseLinuxMachineID"));
    p.mountNamespace=text(field(value,"pulseMountNamespace"));p.networkNamespace=text(field(value,"pulseNetworkNamespace"));
    p.pidNamespace=text(field(value,"pulsePIDNamespace"));
    ContainerParameters parameters={};
    require(mothershipPopulatedSeedRuntimeRepairBindingValid(b,p) &&
            ProdigyWire::deserializeStartupContainerParameters(p.startupParameters,parameters) &&
            parameters.uuid==p.pulseContainerUUID && parameters.deploymentID==b.deploymentID,
            "populated repair process or typed startup identity differs");
    m.populatedSeed=true;
  }
  const auto provenance=field(doc,"gatewayProvenancePath"); pathCheck(provenance); privateFile(provenance);
  require(digest(provenance)==field(doc,"gatewayProvenanceSHA256"),"gateway package provenance digest mismatch");
  // This root-private receipt is the explicit artifact-to-executable approval.
  // Mothership consumes the existing package owner's identities, never extracts
  // a container artifact or creates a second artifact decoder.
  simdjson::dom::parser pp; simdjson::dom::element pd; auto provenanceBytes=read(provenance);
  require(pp.parse(provenanceBytes).get(pd)==simdjson::SUCCESS && field(pd,"builder")=="Discombobulator" &&
          field(pd,"runtime53QualifiedArtifactSHA256")==m.gatewayArtifactSHA,"gateway package owner mismatch");
  simdjson::dom::array files; require(pd["files"].get_array().get(files)==simdjson::SUCCESS,"gateway provenance files missing");
  uint32_t artifacts=0,executables=0;
  for (auto f:files) {
    const auto hash=field(f,"sha256"); const auto size=repairNumber(f,"bytes");
    artifacts+=hash==m.gatewayArtifactSHA && size==m.gatewayArtifactBytes;
    executables+=hash==m.gatewayExecutableSHA && size==m.gatewayExecutableBytes;
  }
  require(artifacts==1 && executables==1,"gateway provenance does not bind the approved artifact and executable");
  MothershipClusterRegistry registry(text(e.plan.registryRoot+"/clusters")); String why;
  simdjson::dom::array gateways; require(doc["gateways"].get_array().get(gateways)==simdjson::SUCCESS,"repair gateway bindings absent");
  std::set<std::pair<uint128_t,uint128_t>> seen;
  for (auto entry:gateways) {
    const auto pair=uuid(field(entry,"pairUUID")),machine=uuid(field(entry,"localMachineUUID"));
    CrossClusterMasqueGatewayAuthority authority;
    require(e.machines.contains(machine) && seen.emplace(pair,machine).second &&
            registry.loadCrossClusterMasqueGateway(pair,machine,authority,&why) &&
            authority.keyGeneration==repairNumber(entry,"keyGeneration") &&
            authority.pairAuthorityGeneration==repairNumber(entry,"pairAuthorityGeneration") &&
            authority.generation==repairNumber(entry,"generation") &&
            authority.localClusterUUID==b.clusterUUID && authority.localMachineUUID==machine &&
            authority.artifactSHA256==text(m.gatewayArtifactSHA) && authority.artifactBytes==m.gatewayArtifactBytes &&
            prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(authority) && authority.state==CrossClusterMasqueGatewayState::active,
            "repair gateway registry authority mismatch");
    b.gateways.push_back(std::move(authority));
  }
  require(b.gateways.size()==6,"repair requires the frozen six gateway authorities");
  for (auto id:b.machineUUIDs) { uint32_t count=0; for (const auto& g:b.gateways) count+=g.localMachineUUID==id; require(count==2,"repair requires two gateways per member"); }
  std::sort(b.gateways.begin(),b.gateways.end(),[](const auto& a,const auto& z) {
    return a.pairUUID<z.pairUUID || (a.pairUUID==z.pairUUID && a.localMachineUUID<z.localMachineUUID);
  });
  String authorityBytes;require(BitseryEngine::serialize(authorityBytes,b.gateways),"repair gateway authority serialization failed");
  const auto sealed=fs::path(e.plan.operationRoot)/"repair-gateway-authorities";
  require(e.receipt.phase==MothershipTidesDBMigrationPhase::accepted || fs::exists(sealed),"repair gateway authority evidence missing");
  repairSeal(sealed,authorityBytes);
  return m;
}
inline std::string initialSeedRepairInventoryProgram(const InitialSeedRuntimeRepairManifest& m,uint128_t machine,
                                                    bool gatewaysPresent=true,bool populatedPresent=false,
                                                    bool ignoreUnrelatedProcesses=false,bool allowAbsentGateways=false) {
  std::string config="{\"sha256\":"+repairJSON(m.gatewayExecutableSHA)+",\"bytes\":"+std::to_string(m.gatewayExecutableBytes)+",\"authorities\":[";
  bool comma=false;
  for (const auto& authority:m.binding.gateways) if (gatewaysPresent && authority.localMachineUUID==machine) {
    SystemContainerRuntimePlan plan; plan.kind=SystemContainerKind::crossClusterMasqueGateway;
    Vector<String> environment;
    require(prodigyBindCrossClusterMasqueGatewayRuntimePlanAuthority(plan,authority) &&
            prodigyAppendCrossClusterMasqueGatewayAuthorityEnvironment(plan,environment),"gateway environment authority invalid");
    if (comma) config+=","; comma=true; config+="[";
    for (uint32_t i=0;i<environment.size();++i) { if(i)config+=","; config+=repairJSON(str(environment[i])); }
    config+="]";
  }
  config+="],\"pulse\":";
  if(populatedPresent && m.populatedSeed && machine==m.populatedProof.pulseMachineUUID) {
    require(!gatewaysPresent,"populated seed repair admits zero observed gateway processes");
    const auto& p=m.populatedProof;
    config+="{\"uuid\":"+repairJSON(repairID(p.pulseContainerUUID))+",\"pid\":"+std::to_string(p.pulsePID)+
        ",\"start\":"+repairJSON(std::to_string(p.pulseStartTicks))+",\"sha256\":"+repairJSON(str(p.pulseExecutableSHA256))+
        ",\"bytes\":"+std::to_string(p.pulseExecutableBytes)+",\"paramsSHA256\":"+repairJSON(str(p.parametersSHA256))+
        ",\"paramsBytes\":"+std::to_string(p.startupParameters.size())+",\"bootID\":"+repairJSON(str(p.bootID))+
        ",\"machineID\":"+repairJSON(str(p.linuxMachineID))+",\"namespaces\":{\"mnt\":"+repairJSON(str(p.mountNamespace))+
        ",\"net\":"+repairJSON(str(p.networkNamespace))+",\"pid\":"+repairJSON(str(p.pidNamespace))+"},\"storage\":["+
        std::to_string(p.storageDevice)+","+std::to_string(p.storageInode)+","+std::to_string(p.storageUID)+","+
        std::to_string(p.storageGID)+"]}";
  } else config+="null";
  config+=",\"ignoreUnrelatedProcesses\":";
  config+=ignoreUnrelatedProcesses ? "true" : "false";
  config+=",\"allowAbsentGateways\":";
  config+=allowAbsentGateways ? "true" : "false";
  config+="}";
  return "python3 - "+quote(config)+R"PY( <<'ISRR_PY'
import hashlib,json,os,pathlib,re,sys
cfg=json.loads(sys.argv[1]); expected=[dict(v.split('=',1) for v in a) for a in cfg['authorities']]
assert len(expected) in (0,2)
pulse=cfg['pulse']; pulse_seen=False
ignore_unrelated=cfg['ignoreUnrelatedProcesses']; allow_absent=cfg['allowAbsentGateways']
assert not allow_absent or (ignore_unrelated and expected and not pulse)
if pulse:
    assert not expected
    assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==pulse['bootID']
    assert pathlib.Path('/etc/machine-id').read_text().strip()==pulse['machineID']
root=pathlib.Path('/sys/fs/cgroup/containers.slice'); rows=[]; matched=set(); seen=set()
assert not root.is_symlink() and (root.is_dir() or (not expected and not pulse) or allow_absent)
for directory,dirs,files in os.walk(root,followlinks=False):
    assert all(not pathlib.Path(directory,d).is_symlink() for d in dirs)
    if 'cgroup.procs' not in files: continue
    pids=pathlib.Path(directory,'cgroup.procs').read_text().split()
    if not pids: continue
    relative=str(pathlib.Path(directory).relative_to(root)); match=re.fullmatch(r'([1-9][0-9]*)\.slice/leaf',relative)
    assert match and 0<int(match[1])<2**128
    for pid in pids:
        assert pid.isdecimal() and int(pid)>1 and pid not in seen; seen.add(pid)
        proc=pathlib.Path('/proc',pid)
        start=proc.joinpath('stat').read_text().rsplit(') ',1)[1].split()[19]
        assert proc.joinpath('cgroup').read_text()==f'0::/containers.slice/{relative}\n'
        data=proc.joinpath('environ').read_bytes().split(b'\0'); env={}
        for item in data:
            if not item: continue
            key,value=item.split(b'=',1); assert key not in env; env[key]=value
        if pulse and int(match[1])==int(pulse['uuid'],16):
            assert not pulse_seen and int(pid)==pulse['pid'] and start==pulse['start']
            for name,target in pulse['namespaces'].items():
                assert os.readlink(proc/'ns'/name)==target
                assert os.readlink(pathlib.Path('/proc/1/ns')/name)!=target
            storage=pathlib.Path('/containers/storage')/match[1]
            assert storage.is_dir() and not storage.is_symlink()
            st=storage.stat(); assert [st.st_dev,st.st_ino,st.st_uid,st.st_gid]==pulse['storage']
            parameter_fds=[]
            for fd in (proc/'fd').iterdir():
                try:
                    if os.readlink(fd)=='/memfd:container.params (deleted)': parameter_fds.append(fd)
                except FileNotFoundError: pass
            assert len(parameter_fds)==1 and env.get(b'PRODIGY_PARAMS_FD')==parameter_fds[0].name.encode()
            def parameter_digest():
                with parameter_fds[0].open('rb') as f:
                    raw=f.read(1024*1024+1)
                assert len(raw)==pulse['paramsBytes']
                assert os.readlink(parameter_fds[0])=='/memfd:container.params (deleted)'
                return hashlib.sha256(raw).hexdigest()
            assert parameter_digest()==pulse['paramsSHA256']
            with proc.joinpath('exe').open('rb') as f:
                executable=hashlib.file_digest(f,'sha256').hexdigest(); executable_bytes=f.tell()
            assert executable==pulse['sha256'] and executable_bytes==pulse['bytes']
            assert parameter_digest()==pulse['paramsSHA256']
            assert proc.joinpath('stat').read_text().rsplit(') ',1)[1].split()[19]==start
            pulse_seen=True
            rows.append({'cgroup':relative,'pid':int(pid),'startTicks':start,'exeSHA256':executable,
                         'parametersSHA256':pulse['paramsSHA256'],'storage':pulse['storage'],'kind':'initialPulse'})
            continue
        matches=[i for i,e in enumerate(expected) if all(env.get(k.encode())==v.encode() for k,v in e.items())]
        if ignore_unrelated and not matches:
            assert not any(key.startswith(b'PRODIGY_MASQUE_') for key in env)
            continue
        assert len(matches)==1 and matches[0] not in matched; matched.add(matches[0])
        with proc.joinpath('exe').open('rb') as f:
            digest=hashlib.file_digest(f,'sha256').hexdigest(); size=f.tell()
        assert digest==cfg['sha256'] and size==cfg['bytes']
        assert proc.joinpath('stat').read_text().rsplit(') ',1)[1].split()[19]==start
        rows.append({'cgroup':relative,'pid':int(pid),'startTicks':start,'exeSHA256':digest,'authority':matches[0]})
if allow_absent:
    assert len(rows) in (0,len(expected)) and len(matched)==len(rows)
else:
    assert len(rows)==len(expected)+(1 if pulse else 0) and len(matched)==len(expected) and pulse_seen==bool(pulse)
print(json.dumps({'bootID':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
 'linuxMachineID':pathlib.Path('/etc/machine-id').read_text().strip(),'processes':sorted(rows,key=lambda r:r['cgroup'])},sort_keys=True,separators=(',',':')))
ISRR_PY
)PY";
}
inline std::string initialSeedRepairPreflightInventoryProgram(const InitialSeedRuntimeRepairManifest& m,uint128_t machine) {
  if(m.populatedSeed) return initialSeedRepairInventoryProgram(m,machine,false,true);
  // Manifest admission permits equal generations only for the 54 -> 55 repair.
  // That already cold-rebooted cohort must be empty; 53 -> 54 retains its two
  // live gateways per member. Both modes retain all six typed authorities.
  return initialSeedRepairInventoryProgram(m,machine,m.binding.masterGeneration!=m.binding.followerGeneration);
}
inline std::string initialSeedRepairTreeProgram(const std::string& path) {
  return "python3 - "+quote(path)+R"PY( <<'ISRR_TREE'
import hashlib,os,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]); result=hashlib.sha256()
assert root.is_dir() and not root.is_symlink()
for directory,dirs,files in os.walk(root,followlinks=False):
    dirs.sort(); files.sort()
    for name in ['']+files:
        path=pathlib.Path(directory,name); s=path.lstat()
        assert stat.S_ISDIR(s.st_mode) if name=='' else stat.S_ISREG(s.st_mode)
        result.update(str(path.relative_to(root)).encode()+b'\0'+str(stat.S_IMODE(s.st_mode)).encode()+b'\0')
        if name:
            result.update(str(s.st_size).encode()+b'\0')
            with path.open('rb') as f: result.update(hashlib.file_digest(f,'sha256').digest())
    assert all(not pathlib.Path(directory,d).is_symlink() for d in dirs)
print(result.hexdigest())
ISRR_TREE
)PY";
}
inline std::string initialSeedRepairBootID(Execution& e,uint128_t machine) {
  String bytes,why;
  require(e.command(machine,"cat /proc/sys/kernel/random/boot_id",&why,&bytes,10000),"repair boot identity observation unavailable");
  auto result=str(bytes); if(result.ends_with('\n'))result.pop_back();
  require(result.size()==36 && result.find_first_not_of("0123456789abcdef-")==std::string::npos,"repair boot identity invalid"); return result;
}
inline bool initialSeedRepairMaySubmitReboot(bool dispatched,const std::string& before,const std::string& current) {
  return !dispatched && !before.empty() && before==current;
}
inline void resolveInitialSeedRepairMachine(const MothershipProdigyCluster& cluster,
                                           MothershipTidesMigration::Machine& machine) {
  // Created cloud members are registered in the durable topology; the separate
  // adoption-intent list can be empty. Reuse the existing topology conversion
  // used by remote cloud runtime repair, without changing adoption resolution.
  const ClusterMachine *registered=nullptr;
  for(const auto& candidate:cluster.topology.machines) if(candidate.uuid==machine.uuid) {
    require(registered==nullptr,"ambiguous repair topology UUID");registered=&candidate;
  }
  require(registered && registered->isBrain && registered->source==ClusterMachineSource::created &&
          registered->backing==ClusterMachineBacking::cloud && !registered->cloud.cloudID.empty(),
          "repair member is not a registered created cloud Brain");
  require(str(registered->ssh.address)==machine.address && registered->ssh.port &&
          str(registered->ssh.user)=="root" && !registered->ssh.hostPublicKeyOpenSSH.empty(),
          "repair topology SSH authority differs or is incomplete");
  mothershipPopulateRemoveMachineFromTopology(*registered,machine.registered);
  machine.registered.uuid=registered->uuid;
}
inline bool runInitialSeedRuntimeRepair(const char *file,const char *action,InitialSeedRuntimeRepairHooks& hooks,String *failure=nullptr) {
  try {
    const bool prepare=std::strcmp(action,"prepare-initial-seed-runtime-repair")==0;
    require(prepare || std::strcmp(action,"recover-initial-seed-runtime-repair")==0,"invalid initial seed repair action");
    Plan plan=parse(file); require(plan.initialSeedRuntimeRepair && plan.schemaVersion==1 &&
        plan.statePath=="/var/lib/prodigy/state" && plan.secretsPath==plan.statePath+".secrets","initial seed repair paths or mode differ");
    for(const auto& live:{plan.runtimeRoot,plan.statePath,plan.secretsPath})
      require(!plan.operationRoot.starts_with(live+"/") && !live.starts_with(plan.operationRoot+"/") && live!=plan.operationRoot,
              "repair operation root overlaps a live runtime or database");
    plan.retainedRecovery=true;
    simdjson::dom::parser parser;simdjson::dom::element doc;auto raw=read(file);
    require(parser.parse(raw).get(doc)==simdjson::SUCCESS,"invalid repair plan");
    bool retained=false; require(doc["retainedRecoveryMode"].get_bool().get(retained)==simdjson::SUCCESS && retained,"explicit retained mode required");
    const auto manifestPath=field(doc,"repairManifestPath"); pathCheck(manifestPath); privateFile(manifestPath);
    const auto manifestSHA=field(doc,"repairManifestSHA256"); require(digest(manifestPath)==manifestSHA,"repair manifest digest mismatch");
    Execution e(std::move(plan)); e.initialize();
    { MothershipClusterRegistry registry(text(e.plan.registryRoot+"/clusters")); String why;
      require(registry.getClusterByIdentity(text(e.plan.identity),e.cluster,&why),"repair cluster registry unavailable"); }
    require(e.cluster.clusterUUID==e.plan.clusterUUID && e.cluster.nBrains==3 && e.cluster.topology.machines.size()==3 &&
            e.cluster.deploymentMode==MothershipClusterDeploymentMode::remote && e.cluster.provider==MothershipClusterProvider::vultr &&
            str(e.cluster.remoteProdigyPath)==e.plan.runtimeRoot,"repair registered fleet differs");
    for (auto& machine:e.plan.machines) { resolveInitialSeedRepairMachine(e.cluster,machine); e.machines.emplace(machine.uuid,&machine); }
    auto manifest=parseInitialSeedRepairManifest(manifestPath,e);
    repairSeal(fs::path(e.plan.operationRoot)/"repair-manifest.sha256",text(manifestSHA));
    for (const auto& db:e.receipt.databases) require(!db.swapped,"repair receipt contains a database swap");
    String why;
    if(!hooks.prepare(e,manifest.binding,&why)) {
      if(failure)failure->assign(why.empty() ? "repair provider/member authority preparation failed" : why.c_str());
      return false;
    }
    e.buildArtifactManifest();
    auto inventory=[&](MothershipTidesMigration::Machine& machine) {
      String observed; require(e.command(machine.uuid,initialSeedRepairPreflightInventoryProgram(manifest,machine.uuid),&why,&observed,30000),"repair container inventory differs from its admitted gateway-presence mode");
      const auto path=fs::path(e.plan.operationRoot)/(repairID(machine.uuid)+".gateway-inventory"); repairSeal(path,observed);
    };
    if(e.receipt.phase<MothershipTidesDBMigrationPhase::writersQuiesced) {
      e.stageAndPreflight();
      for(auto& machine:e.plan.machines) inventory(machine);
      if(e.receipt.phase<MothershipTidesDBMigrationPhase::preflighted) { e.receipt.phase=MothershipTidesDBMigrationPhase::preflighted; e.persist(e.receipt,nullptr); }
      e.quiesce();
    }
    auto preserved=[&]() {
      for(const auto& db:e.receipt.databases) {
        String observed; require(e.command(db.machineUUID,initialSeedRepairTreeProgram(str(db.livePath)),&why,&observed,60000),"repair database byte inventory failed");
        const auto sealed=fs::path(e.plan.operationRoot)/(repairID(db.machineUUID)+"."+str(db.label)+".tree-sha256");
        require(e.receipt.phase<MothershipTidesDBMigrationPhase::validated || fs::exists(sealed),"repair byte-preservation evidence missing");
        repairSeal(sealed,observed);
      }
    };
    if(!e.receipt.activationBoundaryCrossed) {
      // Original directories are never opened by a database reader. Only the
      // paired private copies below are decoded, without a save operation.
      preserved();
      if(e.receipt.phase<MothershipTidesDBMigrationPhase::validated) {
        for(auto& db:e.receipt.databases) {
          require(!e.exists(db,db.retainedV9Path) && !e.exists(db,db.preparedV10Path),"unexpected repair database replacement");
          if(!e.exists(db,db.copiedV9Path)) require(e.copySource(db,&why),"repair private database copy failed");
          String copied; require(e.command(db.machineUUID,initialSeedRepairTreeProgram(str(db.copiedV9Path)),&why,&copied,60000) &&
              str(copied)==read(fs::path(e.plan.operationRoot)/(repairID(db.machineUUID)+"."+str(db.label)+".tree-sha256")),"repair private copy differs from original");
        }
        for(auto& machine:e.plan.machines) {
          auto binding=manifest.binding; binding.localMachineUUID=machine.uuid; String encoded;
          if(manifest.populatedSeed) {
            PopulatedSeedRuntimeRepairRequest request;request.binding=binding;request.proof=manifest.populatedProof;
            require(BitseryEngine::serialize(encoded,request),"populated repair private request serialization failed");
          } else require(BitseryEngine::serialize(encoded,binding),"repair private request serialization failed");
          const auto request=e.plan.operationRoot+"/"+repairID(machine.uuid)+".repair-request";
          repairSeal(request,text(std::string(manifest.populatedSeed ? "ISRR2\n" : "ISRR1\n")+str(encoded)));
          e.upload(machine,request,e.remoteRoot+"/repair.request");
          // Database open may maintain metadata. Recreate only these operation-
          // private verification copies; the retained copies are never opened.
          const auto check=e.remoteRoot+"/state.check10";
          e.run(machine.uuid,"rm -rf -- "+quote(check)+" "+quote(check+".secrets")+
                "; cp -a --reflink=auto -- "+quote(e.remoteRoot+"/state.copy10")+" "+quote(check)+
                "; cp -a --reflink=auto -- "+quote(e.remoteRoot+"/state.copy10.secrets")+" "+quote(check+".secrets"));
          e.run(machine.uuid,"LD_LIBRARY_PATH="+quote(e.remoteRuntime+"/lib")+" "+quote(e.remoteRuntime+"/tools/mothership")+
                " prepareRetainedRecoveryLocal "+quote(e.remoteRoot+"/repair.request")+" "+quote(check)+" verify");
          if(manifest.populatedSeed) {
            String exported;
            require(e.command(machine.uuid,"cat "+quote(e.remoteRoot+"/repair.snapshot-proof"),&why,&exported,30000),
                    "populated repair snapshot proof export failed");
            const auto bytes=str(exported);const auto split=bytes.find("CANONICAL\n");
            require(bytes.starts_with("ISRR2_SCOPE ") && split!=std::string::npos && bytes.size()<65536,
                    "populated repair snapshot proof malformed");
            repairSeal(fs::path(e.plan.operationRoot)/(repairID(machine.uuid)+".snapshot-proof"),exported);
            // Every peer must retain the exact same sealed serving payloads;
            // their canonical observations and ordinary failure metadata can differ.
            repairSeal(fs::path(e.plan.operationRoot)/"populated-serving-proof",text(bytes.substr(0,split)));
          }
        }
        preserved(); e.receipt.phase=MothershipTidesDBMigrationPhase::validated; e.persist(e.receipt,nullptr);
      }
      if(manifest.populatedSeed) {
        const auto common=fs::path(e.plan.operationRoot)/"populated-serving-proof";privateFile(common,65536);
        for(const auto& machine:e.plan.machines) {
          const auto path=fs::path(e.plan.operationRoot)/(repairID(machine.uuid)+".snapshot-proof");privateFile(path,65536);
          const auto bytes=read(path);const auto split=bytes.find("CANONICAL\n");
          require(split!=std::string::npos && read(common)==bytes.substr(0,split),"populated repair snapshot proofs differ");
        }
      }
      if(prepare) return true;
      // Reentry may follow an uncertain controller exit. Reassert all durable
      // startup fences through their existing owner before any install/reboot.
      e.fenceWriters();
      for(auto& machine:e.plan.machines)
        e.run(machine.uuid,"test \"$(systemctl show -p MainPID --value prodigy)\" = 0");
      e.installRuntimes(); preserved();
      for(auto& machine:e.plan.machines) {
        const auto prefix=e.plan.operationRoot+"/"+repairID(machine.uuid);
        privateFile(prefix+".gateway-inventory"); simdjson::dom::parser ip;simdjson::dom::element inv;auto bytes=read(prefix+".gateway-inventory");
        require(ip.parse(bytes).get(inv)==simdjson::SUCCESS && field(inv,"linuxMachineID")==machine.linuxID,"repair original host identity differs");
        const auto before=field(inv,"bootID"),dispatched=prefix+".reboot-dispatched",observed=prefix+".reboot-observed";
        auto boot=initialSeedRepairBootID(e,machine.uuid);
        if(initialSeedRepairMaySubmitReboot(fs::exists(dispatched),before,boot)) {
          repairSeal(dispatched,text(e.plan.planSHA+"\n"+before+"\n"));
          // Persist dispatch before submitting. A timeout is reconciled only by
          // the pinned host's new boot ID; it never authorizes a second submit.
          hooks.reboot(e,machine.uuid,&why);
        }
        require(fs::exists(dispatched),"repair host rebooted before authorized dispatch");
        repairSeal(dispatched,text(e.plan.planSHA+"\n"+before+"\n"));
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::minutes(5);
        while(boot==before && std::chrono::steady_clock::now()<deadline) {
          std::this_thread::sleep_for(std::chrono::seconds(2));
          try { boot=initialSeedRepairBootID(e,machine.uuid); } catch(const std::exception&) {}
        }
        require(boot!=before,"repair reboot dispatch uncertain; observe the same host boot ID without resubmitting");
        repairSeal(observed,text(e.plan.planSHA+"\n"+before+"\n"+boot+"\n"));
        e.run(machine.uuid,"test \"$(cat "+quote(e.fencePath())+")\" = "+quote(e.plan.planSHA)+
              "; test \"$(systemctl show -p MainPID --value prodigy)\" = 0; "+e.observeContainers()+"test -z \"$(snapshot_containers)\"");
        e.run(machine.uuid,initialSeedRepairInventoryProgram(manifest,machine.uuid,false));
        e.verifyRuntime(machine,e.serviceRuntimeRoot());
      }
      preserved();
    } else require(!prepare,"cannot prepare a repair after activation");
    e.activate([&]() {
      require(e.receipt.phase==MothershipTidesDBMigrationPhase::validated,"repair activation requires const snapshot validation");
      preserved();
      for(auto& machine:e.plan.machines) {
        const auto path=e.plan.operationRoot+"/"+repairID(machine.uuid)+".reboot-observed";privateFile(path);
        const auto boot=initialSeedRepairBootID(e,machine.uuid);
        require(read(path).ends_with("\n"+boot+"\n"),"repair boot identity changed after observation");
        e.run(machine.uuid,initialSeedRepairInventoryProgram(manifest,machine.uuid,false));
      }
    });
    return true;
  } catch(const std::exception& error) { if(failure)failure->assign(error.what()); return false; }
}

inline bool runFile(const char *file,const char *action,String *failure=nullptr,const char *repairBundle=nullptr,const char *successorFile=nullptr) {
  try {
    require(std::strcmp(action,"recover")==0 || std::strcmp(action,"prepare")==0 || std::strcmp(action,"retire-extras")==0 || std::strcmp(action,"retire-extras-preactivation")==0 || std::strcmp(action,"check-conflicting-client-preactivation")==0 || std::strcmp(action,"retire-conflicting-client-preactivation")==0 || std::strcmp(action,"supersede-preactivation")==0 || std::strcmp(action,"contain-active")==0 || std::strcmp(action,"compact-contained")==0 || std::strcmp(action,"resume-compacted")==0,"invalid retained recovery action");
    Plan plan=parse(file);require(!plan.initialSeedRuntimeRepair,"initial seed repair requires its explicit action");plan.retainedRecovery=true;
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
      String expectedAuthority=text(e.plan.planSHA+"\n"+manifestSHA+"\n"+digest(e.plan.operationRoot+"/recovery.request")+"\n");
      const bool retiringOrphanedStatefulPredecessor=manifest.orphanedStatefulPredecessor.parameters.uuid!=0;
      if (retiringOrphanedStatefulPredecessor) {
        String machine={},container={}; machine.snprintf<"{itoh}"_ctv>(manifest.orphanedStatefulPredecessor.machineUUID);
        container.snprintf<"{itoh}"_ctv>(manifest.orphanedStatefulPredecessor.parameters.uuid);
        expectedAuthority.append("orphaned-stateful-predecessor ",30);
        expectedAuthority.append(machine.data(),machine.size()); expectedAuthority.append(" ",1);
        expectedAuthority.append(container.data(),container.size()); expectedAuthority.append(" ",1);
        expectedAuthority.append(manifest.orphanedStatefulPredecessor.operation.operationID.data(),
                                 manifest.orphanedStatefulPredecessor.operation.operationID.size());
        expectedAuthority.append("\n",1);
      }
      require(read(authority)==str(expectedAuthority),"retained extra authority differs");
      const auto started=e.plan.operationRoot+"/extras-retirement-started";
      const auto storageReceipt=e.plan.operationRoot+"/orphaned-stateful-predecessor-storage";
      if(!fs::exists(started)) {
        verify(InventoryMode::sealed);
        if (retiringOrphanedStatefulPredecessor) {
          String beforeStorage={},storageFailure={};
          require(e.command(manifest.orphanedStatefulPredecessor.machineUUID,
                            conflictingClientStorageProgram(e.remoteRoot+"/retained-manifest.json",
                                                            manifest.orphanedStatefulPredecessor.parameters.uuid,false),
                            &storageFailure,&beforeStorage,30'000),
                  "orphaned stateful predecessor storage is unavailable before retirement");
          durable(storageReceipt,beforeStorage);
        }
        durable(started,text(e.plan.planSHA+"\n"+manifestSHA+"\n"));
      }
      else require(read(started)==e.plan.planSHA+"\n"+manifestSHA+"\n","extra retirement marker differs");
      verify(InventoryMode::remaining); verify(InventoryMode::retire);
      if (retiringOrphanedStatefulPredecessor) {
        privateFile(storageReceipt,4096); String afterStorage={},storageFailure={};
        require(e.command(manifest.orphanedStatefulPredecessor.machineUUID,
                          conflictingClientStorageProgram(e.remoteRoot+"/retained-manifest.json",
                                                          manifest.orphanedStatefulPredecessor.parameters.uuid,true),
                          &storageFailure,&afterStorage,30'000) && str(afterStorage)==read(storageReceipt),
                "orphaned stateful predecessor storage changed during retirement");
      }
      verify(InventoryMode::canonical); e.acceptStoppedContainerBaseline(); durable(fs::path(e.plan.operationRoot)/"extras-retired",text(manifestSHA)); return true;
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
    ColdCanonicalSource coldCanonicalSource = {};
    String coldCanonicalBinding = {};
    const auto coldCanonicalAuthorityPath=e.plan.operationRoot+"/cold-canonical-source-authority";
    const auto coldCanonicalPayloadPath=e.plan.operationRoot+"/cold-canonical-source.payload";
    const auto coldCanonicalExtractionPath=e.plan.operationRoot+"/cold-canonical-extraction/state.copy10";
    auto validateColdCanonicalSource=[&]() {
      if (manifest.coldCanonicalSource.requestedContainerUUIDs.empty()) return;
      // The historical source is mode-preserved evidence and TidesDB's normal
      // reader can rotate its logs. Hash it first, then decode only a private,
      // disposable reflink copy. The original is never opened by this action.
      require(coldCanonicalStateAggregateDigest(manifest.coldCanonicalSource.statePath)==
                  manifest.coldCanonicalSource.aggregateSHA256,
              "cold canonical source aggregate differs from its sealed manifest");
      coldCanonicalSource = {};
      coldCanonicalSource.sourceStatePath.assign(manifest.coldCanonicalSource.statePath.c_str());
      coldCanonicalSource.sourceSnapshotSHA256=manifest.coldCanonicalSource.aggregateSHA256;
      coldCanonicalSource.requestedContainerUUIDs=manifest.coldCanonicalSource.requestedContainerUUIDs;
      if (!fs::exists(coldCanonicalPayloadPath)) {
        e.run(manifest.emptyRetainedInventoryMachineUUID,
              coldCanonicalExtractionProgram(manifest.coldCanonicalSource.statePath,coldCanonicalExtractionPath));
        try {
          require(coldCanonicalStateAggregateDigest(coldCanonicalExtractionPath)==
                      manifest.coldCanonicalSource.aggregateSHA256,
                  "cold canonical extraction differs from its sealed source");
          ColdCanonicalSource extracted=deriveColdCanonicalSource(manifest,manifest.emptyRetainedInventoryMachineUUID,
                                                                  nullptr,coldCanonicalExtractionPath);
          e.run(manifest.emptyRetainedInventoryMachineUUID,
                coldCanonicalExtractionCleanupProgram(coldCanonicalExtractionPath));
          durable(coldCanonicalPayloadPath,extracted.serializedStates);
        } catch (...) {
          String ignored = {};
          (void)e.command(manifest.emptyRetainedInventoryMachineUUID,
                          coldCanonicalExtractionCleanupProgram(coldCanonicalExtractionPath),&ignored);
          throw;
        }
      }
      privateFile(coldCanonicalPayloadPath);
      coldCanonicalSource.serializedStates=text(read(coldCanonicalPayloadPath));
      coldCanonicalSource.selectedStatesSHA256=coldCanonicalPayloadDigest(coldCanonicalSource.serializedStates);
      require(BitseryEngine::deserializeSafe(coldCanonicalSource.serializedStates,coldCanonicalSource.states) &&
                  coldCanonicalSource.states.size()==coldCanonicalSource.requestedContainerUUIDs.size(),
              "cold canonical payload is not a valid selected runtime set");
      for (uint32_t index=0;index<coldCanonicalSource.states.size();++index)
        require(coldCanonicalSource.states[index].machineUUID==manifest.emptyRetainedInventoryMachineUUID &&
                    coldCanonicalSource.states[index].plan.uuid==coldCanonicalSource.requestedContainerUUIDs[index],
                "cold canonical payload identity differs from sealed source");
      String storageFailure = {};
      require(e.command(manifest.emptyRetainedInventoryMachineUUID,
                        coldCanonicalStorageProgram(manifest.coldCanonicalSource),&storageFailure,nullptr,30'000),
              "cold canonical source storage or rootfs metadata differs");
      coldCanonicalBinding=text(e.plan.planSHA+"\n"+manifestSHA+"\n"+
                                str(coldCanonicalSource.sourceSnapshotSHA256)+"\n"+
                                str(coldCanonicalSource.selectedStatesSHA256)+"\n");
      for (uint128_t uuid : coldCanonicalSource.requestedContainerUUIDs) {
        String encoded = {}; encoded.snprintf<"{itoh}"_ctv>(uuid);
        coldCanonicalBinding.append(encoded.data(),encoded.size()); coldCanonicalBinding.append("\n",1);
      }
      if (!fs::exists(coldCanonicalAuthorityPath)) durable(coldCanonicalAuthorityPath,coldCanonicalBinding);
      else { privateFile(coldCanonicalAuthorityPath,4096); require(read(coldCanonicalAuthorityPath)==str(coldCanonicalBinding),
                                                                     "cold canonical source authority differs"); }
    };
    validateColdCanonicalSource();
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
    for(const auto& artifact:manifest.artifacts) {
      const std::string source=str(artifact.blobPath);
      privateFile(source);
      const std::string remote=e.remoteRoot+"/artifact-"+std::to_string(artifact.deploymentID)+".zst";
      for(auto& machine:e.plan.machines)e.upload(machine,source,remote);
    }
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
        Request priorCanonicalRequest = {};
        const Request *priorCanonicalRequestAuthority =
            loadPriorCanonicalRecoveryRequest(manifest,priorCanonicalRequest) ? &priorCanonicalRequest : nullptr;
        const bool retiringOrphanedStatefulPredecessor =
            manifest.orphanedStatefulPredecessor.parameters.uuid != 0;
        DeploymentPlan orphanedPredecessorHistoricalPlan = {};
        ContainerParameters orphanedPredecessorHistoricalParameters = {};
        if (retiringOrphanedStatefulPredecessor) {
          auto& orphan = manifest.orphanedStatefulPredecessor;
          auto successor = manifest.request.plans.find(orphan.operation.successorDeploymentID);
          require(successor != manifest.request.plans.end() && successor->second.isStateful &&
                      !successor->second.stateful.allMasters &&
                      successor->second.config.containerBlobSHA256.equals(orphan.operation.successorBlobSHA256),
                  "orphaned stateful predecessor does not bind a culled active deployment and approved successor");

          // The current snapshot correctly omits a process whose deployment was
          // culled. Bind that one process to the immutable prior sealed request
          // instead of recreating its obsolete deployment in current authority.
          const std::string priorRequestPath = str(manifest.orphanedStatefulPredecessorPriorRequestPath);
          const std::string priorManifestPath = str(manifest.orphanedStatefulPredecessorPriorManifestPath);
          privateFile(priorRequestPath); privateFile(priorManifestPath, UINT32_MAX);
          require(text(digest(priorRequestPath)) == orphan.priorRequestSHA256 &&
                      text(digest(priorManifestPath)) == orphan.priorManifestSHA256,
                  "orphaned stateful predecessor historical authority digest differs");
          Request priorRequest = {}; MothershipRetainedRecoveryMixedProof priorProof = {};
          uint128_t priorRetired = 0, priorEmptyMachine = 0; ColdCanonicalSource priorCold = {};
          ProdigyMaterializedStatefulRecoveryOperation priorOperation = {};
          require(decodeRequest(read(priorRequestPath), priorRequest, &priorProof, &priorRetired,
                                &priorEmptyMachine, &priorCold, &priorOperation) &&
                      priorRetired == 0 &&
                      partialHandoffsEqual(priorOperation, orphan.operation) &&
                      priorRequest.clusterUUID == manifest.request.clusterUUID,
                  "orphaned stateful predecessor historical request does not bind its operation");
          auto historicalPlan = priorRequest.plans.find(orphan.operation.activeDeploymentID);
          require(historicalPlan != priorRequest.plans.end() && historicalPlan->second.isStateful &&
                      !historicalPlan->second.stateful.allMasters,
                  "orphaned stateful predecessor historical active plan is unavailable");
          orphanedPredecessorHistoricalPlan = historicalPlan->second;
          auto retainedActivePlan = manifest.request.plans.find(orphan.operation.activeDeploymentID);
          require(retainedActivePlan == manifest.request.plans.end() ||
                      mothershipRetainedRecoveryPlansEqual(retainedActivePlan->second, historicalPlan->second),
                  "orphaned stateful predecessor retained active plan differs from historical authority");
          // Keep the validated old plan in the sealed request as proof-only.
          // `prepareLocal` compares each stopped copy against it, then erases
          // it from the reconstructed authority before generic recovery.
          uint32_t historicalMatches = 0;
          for (const MothershipRetainedRecoveryMachineInput& machine : priorRequest.machines) {
            for (const ContainerParameters& parameters : machine.parameters) {
              if (parameters.uuid != orphan.parameters.uuid) continue;
              ++historicalMatches;
              require(machine.machineUUID == orphan.machineUUID &&
                          parameters.deploymentID == orphan.operation.activeDeploymentID,
                      "orphaned stateful predecessor historical identity differs");
              orphanedPredecessorHistoricalParameters = parameters;
            }
          }
          require(historicalMatches == 1,
                  "orphaned stateful predecessor is absent or duplicated in historical authority");
        }
        validateColdCanonicalSource();
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
          const bool orphanTarget=retiringOrphanedStatefulPredecessor &&
              params.uuid==manifest.orphanedStatefulPredecessor.parameters.uuid &&
              r.machine==manifest.orphanedStatefulPredecessor.machineUUID;
          if (orphanTarget) {
            auto& orphan=manifest.orphanedStatefulPredecessor;
            // The compact startup wire omits CPU fields. Their owner is the
            // prior sealed active plan, used here only for identity binding.
            prodigyRestoreRetainedStartupCPUFields(bytes, orphanedPredecessorHistoricalPlan, params);
            require(!r.canonical && params.deploymentID==orphan.operation.activeDeploymentID &&
                        params.statefulMeshRoles.client==0 && params.statefulTopology.shardGroup==0 &&
                        params.statefulTopology.bridgeMode==StatefulTopologyBridgeMode::none &&
                        mothershipRetainedRecoveryOrphanedStatefulPredecessorParametersMatchHistorical(
                            params, orphanedPredecessorHistoricalParameters),
                    "orphaned stateful predecessor immutable parameters differ from sealed historical authority");
            orphan.parameters=std::move(params);
            continue;
          }
          const DeploymentPlan& deployment=bindCanonicalRecoveryPlan(
              manifest,priorCanonicalRequestAuthority,r,params.deploymentID);
          prodigyRestoreRetainedStartupCPUFields(bytes,deployment,params);
          if(!r.canonical) {require(!deployment.isStateful && deployment.config.type==ApplicationType::stateless,"extra retirement would affect a stateful container");continue;}
          for(auto& m:manifest.request.machines)if(m.machineUUID==r.machine) {m.parameters.push_back(std::move(params));m.observedCreatedAtMs.push_back(r.created);}
        }
        if (retiringOrphanedStatefulPredecessor) {
          auto& orphan = manifest.orphanedStatefulPredecessor;
          orphan.successorBootstraps.clear();
          for (const BrainReplicatedContainerRuntimeState& state : seed.masterAuthority.containerRuntimeStates) {
            if (state.plan.config.deploymentID() != orphan.operation.successorDeploymentID ||
                state.plan.state != ContainerState::healthy || !state.plan.runtimeReady) continue;
            bool requested = false;
            for (const MothershipRetainedRecoveryMachineInput& machine : manifest.request.machines)
              for (const ContainerParameters& parameters : machine.parameters)
                requested |= machine.machineUUID == state.machineUUID && parameters.uuid == state.plan.uuid;
            if (!requested) continue;
            NeuronContainerBootstrap bootstrap = {};
            bootstrap.plan = state.plan;
            bootstrap.metricPolicy = prodigyNeuronMetricPolicyForDeployment(
                manifest.request.plans.find(orphan.operation.successorDeploymentID)->second);
            String serialized = {}; BitseryEngine::serialize(serialized, bootstrap);
            orphan.successorBootstraps.push_back({state.machineUUID, std::move(serialized)});
          }
          std::sort(orphan.successorBootstraps.begin(), orphan.successorBootstraps.end(),
              [](const auto& lhs, const auto& rhs) { return lhs.machineUUID < rhs.machineUUID; });
        }
        require(!retiringOrphanedStatefulPredecessor ||
                    mothershipRetainedRecoveryOrphanedStatefulPredecessorValid(manifest.orphanedStatefulPredecessor),
                "orphaned stateful predecessor was not sealed from live parameters");
        validateRecoveryArtifacts(manifest,manifest.request,&coldCanonicalSource);
        validateColdCanonicalMissingRootfsArtifacts(manifest,manifest.request,coldCanonicalSource);
        String bytes=retiringOrphanedStatefulPredecessor ?
            encodeOrphanedStatefulPredecessorRequest(manifest.request,e.plan,manifest.orphanedStatefulPredecessor) :
            !manifest.partialHandoff.operationID.empty() ?
            encodePartialHandoffRequest(manifest.request,e.plan,manifest.emptyRetainedInventoryMachineUUID,coldCanonicalSource,manifest.partialHandoff) :
            manifest.coldCanonicalSource.requestedContainerUUIDs.empty() ?
            encodeRequest(manifest.request,e.plan,manifest.emptyRetainedInventoryMachineUUID) :
            encodeColdCanonicalSourceRequest(manifest.request,e.plan,manifest.emptyRetainedInventoryMachineUUID,coldCanonicalSource);
        if(!requestAlreadySealed) durable(requestPath,bytes);
        Request sealedRequest = {}; MothershipRetainedRecoveryMixedProof sealedProof = {};
        uint128_t sealedRetired=0, sealedEmptyMachine=0; ColdCanonicalSource sealedColdSource = {};
        ProdigyMaterializedStatefulRecoveryOperation sealedPartialHandoff = {};
        MothershipRetainedRecoveryOrphanedStatefulPredecessor sealedOrphan = {};
        require(decodeRequest(read(requestPath),sealedRequest,&sealedProof,&sealedRetired,&sealedEmptyMachine,&sealedColdSource,&sealedPartialHandoff,&sealedOrphan) &&
                    partialHandoffsEqual(sealedPartialHandoff,manifest.partialHandoff) &&
                    sealedRequest.clusterUUID==manifest.request.clusterUUID && sealedRetired==0 &&
                    sealedEmptyMachine==manifest.emptyRetainedInventoryMachineUUID,
                "sealed recovery request differs from cold canonical authority");
        if (retiringOrphanedStatefulPredecessor) {
          String sealedParameters = {}, observedParameters = {};
          BitseryEngine::serialize(sealedParameters, sealedOrphan.parameters);
          BitseryEngine::serialize(observedParameters, manifest.orphanedStatefulPredecessor.parameters);
          require(sealedOrphan.machineUUID==manifest.orphanedStatefulPredecessor.machineUUID &&
                      sealedOrphan.parameters.uuid==manifest.orphanedStatefulPredecessor.parameters.uuid &&
                      sealedParameters==observedParameters &&
                      mothershipRetainedRecoveryPartialHandoffEqual(sealedOrphan.operation,
                                                                      manifest.orphanedStatefulPredecessor.operation),
                  "sealed orphaned stateful predecessor differs from live authority");
        }
        if (!manifest.coldCanonicalSource.requestedContainerUUIDs.empty())
          require(sealedColdSource.sourceSnapshotSHA256==coldCanonicalSource.sourceSnapshotSHA256 &&
                      sealedColdSource.selectedStatesSHA256==coldCanonicalSource.selectedStatesSHA256 &&
                      coldCanonicalUUIDsEqual(sealedColdSource.requestedContainerUUIDs,coldCanonicalSource.requestedContainerUUIDs) &&
                      sealedColdSource.serializedStates==coldCanonicalSource.serializedStates &&
                      coldCanonicalPayloadDigest(sealedColdSource.serializedStates)==coldCanonicalSource.selectedStatesSHA256,
                  "sealed cold canonical source differs from preflight authority");
        if (!manifest.coldCanonicalSource.requestedContainerUUIDs.empty())
          validateColdCanonicalMissingRootfsArtifacts(manifest,sealedRequest,sealedColdSource);
        const auto requestDigest=digest(requestPath);
        String recoveryAuthority=text(e.plan.planSHA+"\n"+manifestSHA+"\n"+requestDigest+"\n");
        if (retiringOrphanedStatefulPredecessor) {
          String machine = {}, container = {};
          machine.snprintf<"{itoh}"_ctv>(manifest.orphanedStatefulPredecessor.machineUUID);
          container.snprintf<"{itoh}"_ctv>(manifest.orphanedStatefulPredecessor.parameters.uuid);
          recoveryAuthority.append("orphaned-stateful-predecessor ", 30);
          recoveryAuthority.append(machine.data(),machine.size()); recoveryAuthority.append(" ",1);
          recoveryAuthority.append(container.data(),container.size()); recoveryAuthority.append(" ",1);
          recoveryAuthority.append(manifest.orphanedStatefulPredecessor.operation.operationID.data(),
                                   manifest.orphanedStatefulPredecessor.operation.operationID.size());
          recoveryAuthority.append("\n",1);
        }
        durable(authorityPath,recoveryAuthority);
        if (!manifest.coldCanonicalSource.requestedContainerUUIDs.empty()) {
          const auto requestAuthority=e.plan.operationRoot+"/cold-canonical-request-authority";
          const String binding=text(str(coldCanonicalBinding)+requestDigest+"\n");
          if (!fs::exists(requestAuthority)) durable(requestAuthority,binding);
          else { privateFile(requestAuthority,4096); require(read(requestAuthority)==str(binding),
                                                              "cold canonical request authority differs"); }
        }
      }
      }
      const auto witnessPath=requestPath+".witnesses";
      if(!fs::exists(witnessPath)) {
        require(read("/etc/machine-id")==e.plan.machines[0].linuxID+"\n","witness sealing requires the selected seed");
        Request request; MothershipRetainedRecoveryMixedProof proof; uint128_t retiredConflictingClientUUID=0, emptyRetainedInventoryMachineUUID=0;
        ColdCanonicalSource coldCanonicalSource = {};
        ProdigyMaterializedStatefulRecoveryOperation partialHandoff = {};
        MothershipRetainedRecoveryOrphanedStatefulPredecessor orphanedPredecessor = {};
        require(decodeRequest(read(requestPath),request,&proof,&retiredConflictingClientUUID,
                              &emptyRetainedInventoryMachineUUID,&coldCanonicalSource,&partialHandoff,
                              &orphanedPredecessor),"sealed request unreadable");
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
                                                            emptyRetainedInventoryMachineUUID,coldCanonicalSource.states,
                                                        partialHandoff.operationID.empty()?nullptr:&partialHandoff,
                                                        orphanedPredecessor.parameters.uuid != 0 ? orphanedPredecessor.rejectedCandidateSHA256 : String{}),str(why).c_str());
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
        cmd+="if test -f "+quote(marker)+"; then test \"$(cat "+quote(marker)+")\" = "+quote(requestSHA)+"; "+invoke+" verify; else "+invoke+" prepare "+quote(e.plan.oldBundleSHA)+"; printf %s "+quote(requestSHA)+" > "+quote(marker)+"; sync -f "+quote(marker)+"; fi";
        for(const auto& artifact:manifest.artifacts) {
          const std::string remote=e.remoteRoot+"/artifact-"+std::to_string(artifact.deploymentID)+".zst";
          cmd+="; LD_LIBRARY_PATH="+quote(preparationRuntime+"/lib")+" "+quote(preparationRuntime+"/tools/mothership")+" prepareRetainedRecoveryArtifactLocal "+
              quote(e.remoteRoot+"/recovery.request")+" "+quote(e.remoteRoot+"/state.new10")+" "+
              std::to_string(artifact.deploymentID)+" "+quote(remote)+" prepare";
        }
        e.run(m.uuid,cmd);
      }
      verify(extrasRetired?InventoryMode::canonical:InventoryMode::sealed);e.receipt.phase=MothershipTidesDBMigrationPhase::validated;e.persist(e.receipt,nullptr);
    }
    if(std::strcmp(action,"prepare")==0) {require(!e.receipt.activationBoundaryCrossed,"recovery already activated");return true;}
    if(e.receipt.phase<MothershipTidesDBMigrationPhase::swapped) {
      publishPreparedPairedRecoveryDatabases(e.receipt.databases,
          [&](const auto& db,const auto& path) { return e.exists(db,path); },
          [&](auto& db,const auto& from,const auto& to,String *why) { return e.rename(db,from,to,why); },
          [&] { e.persist(e.receipt,nullptr); });
      e.receipt.phase=MothershipTidesDBMigrationPhase::swapped;e.persist(e.receipt,nullptr);
    }
    if(!e.receipt.activationBoundaryCrossed) {
      if (!manifest.coldCanonicalSource.requestedContainerUUIDs.empty()) {
        require(read("/etc/machine-id")==e.plan.machines[0].linuxID+"\n",
                "cold canonical source revalidation requires the selected seed");
        validateColdCanonicalSource();
        Request sealedRequest = {}; MothershipRetainedRecoveryMixedProof sealedProof = {};
        uint128_t sealedRetired=0, sealedEmpty=0; ColdCanonicalSource sealedCold = {};
        require(decodeRequest(read(requestPath),sealedRequest,&sealedProof,&sealedRetired,&sealedEmpty,&sealedCold) &&
                    sealedRetired==0 && sealedEmpty==manifest.emptyRetainedInventoryMachineUUID,
                "cold canonical sealed request is unreadable");
        validateColdCanonicalMissingRootfsArtifacts(manifest,sealedRequest,sealedCold);
        const auto requestAuthority=e.plan.operationRoot+"/cold-canonical-request-authority";
        privateFile(requestAuthority,4096);
        require(read(requestAuthority)==str(coldCanonicalBinding)+digest(requestPath)+"\n",
                "cold canonical source changed after preparation");
      }
      verify(extrasRetired?InventoryMode::canonical:InventoryMode::sealed);for(auto& m:e.plan.machines) {
        std::string verifyCommand="LD_LIBRARY_PATH="+quote(preparationRuntime+"/lib")+" "+quote(preparationRuntime+"/tools/mothership")+" prepareRetainedRecoveryLocal "+quote(e.remoteRoot+"/recovery.request")+" "+quote(e.plan.statePath)+" verify";
        for(const auto& artifact:manifest.artifacts) verifyCommand+="; LD_LIBRARY_PATH="+quote(preparationRuntime+"/lib")+" "+quote(preparationRuntime+"/tools/mothership")+" prepareRetainedRecoveryArtifactLocal "+
            quote(e.remoteRoot+"/recovery.request")+" "+quote(e.plan.statePath)+" "+std::to_string(artifact.deploymentID)+" "+
            quote(e.remoteRoot+"/artifact-"+std::to_string(artifact.deploymentID)+".zst")+" verify";
        e.run(m.uuid,verifyCommand);
      }
      e.installRuntimes();
    }
    e.activate();return true;
  } catch(const std::exception& error) {if(failure)failure->assign(error.what());return false;}
}
} // namespace MothershipRetainedRecovery
