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

int main(void)
{
  char directoryTemplate[] = "/tmp/prodigy-upgrade-admission-registry-XXXXXX";
  char *directory = ::mkdtemp(directoryTemplate);
  assert(directory != nullptr);
  struct ScopedTestDirectory {
    std::filesystem::path path;
    ~ScopedTestDirectory() { std::filesystem::remove_all(path); }
  } ownedDirectory {directory};
  String path(directory);
  MothershipClusterRegistry registry(path);
  MothershipUpgradeAdmissionRecord request = {};
  request.clusterUUID = uint128_t(0xA11);
  request.operationID = uint128_t(0xB22);
  request.sourceBundleSHA256 = digest('a');
  request.sourceContractSHA256 = digest('b');
  request.sourceReleaseID.assign("source-release"_ctv);
  request.sourceProdigySHA256 = digest('c');
  request.sourceMothershipSHA256 = digest('d');
  request.targetBundleSHA256 = digest('e');
  request.targetContractSHA256 = digest('f');
  request.authorityGeneration = 7;
  request.masterUUID = uint128_t(0xC33);
  request.masterBootNs = 8;
  request.semanticObservationSHA256 = digest('1');
  request.approvedPath = 1;
  request.observationReceiptVersion = 1;
  request.observationReportSHA256 = digest('2');
  request.plannerInputSHA256 = digest('3');
  request.firstStopGate.assign("fleet digest evidence unavailable"_ctv);

  MothershipUpgradeAdmissionRecord recorded = {};
  bool resumed = false;
  String failure = {};
  assert(registry.recordUpgradeAdmission(request, recorded, resumed, &failure));
  assert(!resumed && recorded.firstStopGate == request.firstStopGate);
  assert(registry.recordUpgradeAdmission(request, recorded, resumed, &failure));
  assert(resumed);
  request.observationReceiptVersion = 2;
  request.observationReportSHA256 = digest('4');
  request.plannerInputSHA256 = digest('5');
  assert(registry.recordUpgradeAdmission(request, recorded, resumed, &failure));
  assert(!resumed && recorded.rejectedObservations.size() == 1);
  MothershipUpgradeAdmissionRecord loaded = {};
  assert(registry.loadUpgradeAdmission(request.clusterUUID, request.operationID, loaded, &failure));
  assert(loaded.semanticObservationSHA256 == request.semanticObservationSHA256 &&
         loaded.authorityGeneration == request.authorityGeneration && loaded.masterUUID == request.masterUUID);
  request.targetBundleSHA256 = digest('6');
  assert(!registry.recordUpgradeAdmission(request, recorded, resumed, &failure));
  assert(failure == "upgrade admission operation identity conflicts with existing immutable record"_ctv);
  MothershipUpgradeAdmissionRecord incomplete = request;
  incomplete.operationID = uint128_t(0xE55);
  incomplete.masterUUID = 0;
  assert(!registry.recordUpgradeAdmission(incomplete, recorded, resumed, &failure));
  assert(failure == "upgrade admission record is invalid"_ctv);
  MothershipTestPairBoundaryRecord pair = {}, pairStored = {}, pairLoaded = {};
  pair.boundary.operationID = "0x0abc"_ctv;
  pair.boundary.sourceClusterUUID = "0x0a11"_ctv;
  pair.boundary.targetClusterUUID = "0x0a22"_ctv;
  pair.boundary.sourceWorkspace = "/tmp/source"_ctv;
  pair.boundary.targetWorkspace = "/tmp/target"_ctv;
  pair.boundary.sourceRuntimeIdentity = "1001"_ctv;
  pair.boundary.targetRuntimeIdentity = "1002"_ctv;
  pair.boundary.sourceParentNamespace = "pvd-p-1001"_ctv;
  pair.boundary.targetParentNamespace = "pvd-p-1002"_ctv;
  pair.boundary.sourceMachineIndex = pair.boundary.targetMachineIndex = 1;
  pair.boundary.sourceMachinePrivate4 = "10.0.0.10"_ctv;
  pair.boundary.targetMachinePrivate4 = "10.0.1.10"_ctv;
  pair.boundary.endpointIPv4 = "198.18.0.1"_ctv;
  pair.boundary.endpointPort = 19090;
  pair.sourceDeploymentID = 100;
  pair.targetDeploymentID = 200;
  pair.sourcePlanSHA256 = digest('a'); pair.targetPlanSHA256 = digest('b');
  pair.sourceBlobSHA256 = digest('c'); pair.targetBlobSHA256 = digest('c');
  assert(registry.admitTestPairBoundary(pair, pairStored, &failure));
  assert(registry.loadTestPairBoundary(pair.boundary.operationID, pairLoaded, &failure));
  assert(MothershipClusterRegistry::testPairBoundaryIdentityMatches(pair, pairLoaded));
  assert(registry.admitTestPairBoundary(pair, pairStored, &failure));
  auto changed = pair;
  changed.targetPlanSHA256 = digest('d');
  assert(!registry.admitTestPairBoundary(changed, pairStored, &failure));
  changed = pair; changed.boundary.operationID = "0x0abd"_ctv;
  assert(!registry.admitTestPairBoundary(changed, pairStored, &failure));
  changed = pair; changed.boundary.operationID = "0x000abc"_ctv;
  assert(!registry.admitTestPairBoundary(changed, pairStored, &failure));
  bool ownsBoundary = false;
  assert(registry.clusterHasOpenTestPairBoundary(uint128_t(0xa11), ownsBoundary, &failure) && ownsBoundary);
  assert(registry.clusterHasOpenTestPairBoundary(uint128_t(0xa22), ownsBoundary, &failure) && ownsBoundary);
  assert(!registry.clusterHasOpenTestPairBoundary(0, ownsBoundary, &failure) && !ownsBoundary &&
         failure == "test pair boundary cluster UUID is required"_ctv);
  assert(registry.advanceTestPairBoundary(pair, 1, false, pairStored, &failure));
  assert(!registry.advanceTestPairBoundary(pair, 1, false, pairLoaded, &failure)); // stale generation
  assert(!registry.advanceTestPairBoundary(pairStored, 0, false, pairLoaded, &failure));
  assert(registry.advanceTestPairBoundary(pairStored, 1, true, pairLoaded, &failure));
  assert(registry.clusterHasOpenTestPairBoundary(uint128_t(0xa11), ownsBoundary, &failure) && !ownsBoundary);
  assert(!registry.admitTestPairBoundary(pair, pairStored, &failure)); // closed ID cannot resurrect
  assert(!registry.advanceTestPairBoundary(pairLoaded, 1, false, pairStored, &failure));
  return 0;
}
