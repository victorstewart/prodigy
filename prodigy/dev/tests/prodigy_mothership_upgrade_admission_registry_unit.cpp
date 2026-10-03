#include <cassert>
#include <cstdio>
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
  String path = {};
  path.snprintf<"/tmp/prodigy-upgrade-admission-registry-{itoa}"_ctv>(uint64_t(getpid()));
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
  std::filesystem::remove_all(path.c_str());
  return 0;
}
