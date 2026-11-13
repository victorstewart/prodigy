#include <cassert>
#include <cstdio>
#include <filesystem>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include <prodigy/mothership/mothership.cluster.registry.h>
#include <enums/datacenter.h>
#include <networking/message.h>
#include <prodigy/cousin.session.h>

static String digest(char value)
{
  String result = {};
  for (uint32_t index = 0; index < 64; ++index) result.append(value);
  return result;
}

static MothershipNametagQualificationExecutionRecord::CousinRecoveryBinding cousinBinding()
{
  MothershipNametagQualificationExecutionRecord::CousinRecoveryBinding binding = {};
  auto& route = binding.route;
  route.routeUUID = 0x111; route.operationUUID = 0x201; route.pairUUID = 0x300;
  route.logicalWorkloadUUID = 0x301; route.logicalServiceUUID = 0x302;
  route.sourceClusterUUID = 0x100; route.destinationClusterUUID = 0x101;
  route.sourceApplicationID = 7; route.destinationApplicationID = 19;
  route.sourceCousinServicePrefix = MeshServices::generateStatefulService(7, 3);
  route.destinationCousinServicePrefix = MeshServices::generateStatefulService(19, 3);
  route.slots.insert(3); route.destinationRoutablePrefixUUID = 0x501;
  route.destinationPublicAddress = IPAddress("2001:db8::1", true); route.destinationTCPPort = 443;
  route.sourcePermissionUUID = 0x601; route.destinationPermissionUUID = 0x602;
  route.transportProtocol = IPPROTO_TCP; route.destinationCIDR = 32; route.pathMTU = 1500;
  route.generation = 1; route.issuedAtMs = 100; route.expiresAtMs = 2000000;
  route.keyEpoch = 1; route.rootGeneration = 1;
  auto& source = binding.sourcePermission;
  source.permissionUUID = route.sourcePermissionUUID; source.pairUUID = route.pairUUID;
  source.logicalWorkloadUUID = route.logicalWorkloadUUID; source.logicalServiceUUID = route.logicalServiceUUID;
  source.localClusterUUID = route.sourceClusterUUID; source.peerClusterUUID = route.destinationClusterUUID;
  source.localHalf = CousinRouteHalf::source; source.localApplicationID = route.sourceApplicationID;
  source.peerApplicationID = route.destinationApplicationID;
  source.localCousinServicePrefix = route.sourceCousinServicePrefix; source.peerCousinServicePrefix = route.destinationCousinServicePrefix;
  source.slots = route.slots; source.localDeploymentID = uint64_t(7) << 48 | 1;
  source.canonicalPlanSHA256 = digest('a'); source.artifactSHA256 = digest('b'); source.artifactBytes = 8192;
  source.generation = 1; source.acceptedAuthorityGeneration = 7;
  source.state = ProdigyLocalCousinServicePermissionState::active;
  auto& destination = binding.destinationPermission; destination = source;
  destination.permissionUUID = route.destinationPermissionUUID; destination.localHalf = CousinRouteHalf::destination;
  destination.localClusterUUID = route.destinationClusterUUID; destination.peerClusterUUID = route.sourceClusterUUID;
  destination.localApplicationID = route.destinationApplicationID; destination.peerApplicationID = route.sourceApplicationID;
  destination.localCousinServicePrefix = route.destinationCousinServicePrefix; destination.peerCousinServicePrefix = route.sourceCousinServicePrefix;
  destination.localDeploymentID = uint64_t(19) << 48 | 1;
  auto receipt = [&](CousinRouteHalf half) {
    CousinRouteApplyReceipt value = {}; value.routeUUID = route.routeUUID; value.generation = route.generation;
    assert(cousinRouteAuthorizationDigest(route, value.authorizationSHA256));
    value.localHalf = half; value.localClusterUUID = half == CousinRouteHalf::source ? route.sourceClusterUUID : route.destinationClusterUUID;
    value.keyEpoch = route.keyEpoch; value.localRuntimeRevision = 1; value.installedState = route.state; return value;
  };
  binding.sourceReceipt = receipt(CousinRouteHalf::source); binding.destinationReceipt = receipt(CousinRouteHalf::destination);
  binding.sourceAuthorityGeneration = 7; binding.destinationAuthorityGeneration = 8;
  return binding;
}

static DeploymentIdentityReport allMastersReceipt(uint128_t clusterUUID, uint64_t deploymentID,
    uint16_t applicationID, uint32_t groups, DeploymentIdentityStoreKind kind)
{
  DeploymentIdentityReport report = {};
  report.version = 3; report.found = report.live = report.isStateful = true;
  report.clusterUUID = clusterUUID; report.deploymentID = deploymentID; report.applicationID = applicationID;
  report.nShardGroups = groups; report.nTarget = report.nDeployed = report.nHealthy = groups * 3;
  report.statefulRuntimeCohortConverged = true;
  for (uint32_t group = 0; group < groups; ++group) for (uint32_t replica = 0; replica < 3; ++replica) {
    auto& member = report.statefulRuntimeCohort.emplace_back();
    member.storeKind = kind; member.shardGroup = group;
    member.clusterUUID = clusterUUID; member.machineUUID = 0xe000 + (clusterUUID - 0x100) * 10 + replica;
    member.replicaUUID = member.containerUUID = 0xf000 + uint64_t(clusterUUID) * 100 + group * 3 + replica;
    member.writable = member.clientServing = member.allMasters = true;
    member.siblingSessionUUID = member.containerUUID + 0x100; member.siblingSessionGeneration = 1;
    member.siblingSessionHealthy = true; member.seededFromClusterUUID = clusterUUID + 1;
    member.seededFromContainerUUID = member.containerUUID + 0x200; member.seedCatchupSHA256 = digest('b');
    member.seedCatchupGeneration = 1; member.replayWatermarkSHA256 = digest('c');
    member.catchupWatermarkSHA256 = digest('d');
    member.sourceContentWatermarkSHA256 = digest('e'); member.sourceCatchupWatermarkSHA256 = digest('f');
  }
  return report;
}

static MothershipNametagAllMastersRecord allMastersRecord()
{
  MothershipNametagAllMastersRecord record = {};
  record.requestSHA256 = digest('a');
  record.intent.operationUUID = 0xa110;
  for (uint32_t site = 0; site < 3; ++site)
  {
    auto& value = record.intent.sites.emplace_back();
    value.clusterUUID = 0x100 + site;
    value.pulseDeploymentID = 100 + site * 10;
    value.hotDeploymentID = 101 + site * 10;
    value.coldDeploymentID = 102 + site * 10;
    value.radarDeploymentID = 103 + site * 10;
    value.app6DeploymentID = 104 + site * 10;
    if (site == 0) value.truthDeploymentID = 105;
  }
  for (uint32_t left = 0; left < 3; ++left) for (uint32_t right = left + 1; right < 3; ++right)
  {
    for (uint32_t path = 0; path < 3; ++path) for (uint32_t direction = 0; direction < 2; ++direction)
    {
      const uint32_t local = direction == 0 ? left : right;
      const uint32_t peer = direction == 0 ? right : left;
      auto& authority = record.intent.directGatewayAuthorities.emplace_back();
      authority.state = CrossClusterMasqueGatewayState::active;
      authority.pairUUID = 0xc000 + left * 3 + right;
      authority.pairOperationUUID = 0xd000 + left * 3 + right;
      authority.localClusterUUID = record.intent.sites[local].clusterUUID;
      authority.peerClusterUUID = record.intent.sites[peer].clusterUUID;
      authority.localMachineUUID = 0xe000 + local * 10 + path;
      authority.peerMachineUUID = 0xe000 + peer * 10 + path;
      authority.tunnelSlot = uint8_t(path);
      authority.gatewaySlot = uint8_t(path);
      authority.generation = 1;
    }
  }

  assert(record.intent.sites.size() == 3 && record.intent.directGatewayAuthorities.size() == 18);
  for (const auto& authority : record.intent.directGatewayAuthorities) {
    uint32_t pairAuthorities = 0;
    for (const auto& candidate : record.intent.directGatewayAuthorities)
      if (candidate.pairUUID == authority.pairUUID) {
        assert(candidate.pairOperationUUID == authority.pairOperationUUID);
        ++pairAuthorities;
      }
    assert(pairAuthorities == 6);
  }

  Vector<DeploymentIdentityReport> pulse, hot, cold, radar;
  for (const auto& site : record.intent.sites) {
    pulse.push_back(allMastersReceipt(site.clusterUUID, site.pulseDeploymentID,
        MeshRegistry::Pulse::applicationID, 1, DeploymentIdentityStoreKind::graph));
    hot.push_back(allMastersReceipt(site.clusterUUID, site.hotDeploymentID,
        MeshRegistry::Hot::applicationID, 3, DeploymentIdentityStoreKind::kv));
    cold.push_back(allMastersReceipt(site.clusterUUID, site.coldDeploymentID,
        MeshRegistry::Cold::applicationID, 3, DeploymentIdentityStoreKind::kv));
    radar.push_back(allMastersReceipt(site.clusterUUID, site.radarDeploymentID,
        MeshRegistry::Radar::applicationID, 1, DeploymentIdentityStoreKind::graph));
  }
  assert(mothershipNametagAllMastersSeedPlacementsSynthesize(record.intent, pulse, hot, cold, radar,
      record.seedPlacements));
  assert(record.seedPlacements.size() == 48 && mothershipNametagAllMastersRecordValid(record));
  for (const auto& placement : record.seedPlacements) {
    assert(placement.site == 1 || placement.site == 2);
    assert(placement.sourceClusterUUID == record.intent.sites[0].clusterUUID);
    assert(placement.fixtureSHA256 == digest('b') && placement.expectedCatchupWatermarkSHA256 == digest('d'));
    assert(placement.sourceContentWatermarkSHA256 == digest('e') &&
        placement.sourceCatchupWatermarkSHA256 == digest('f'));
  }
  return record;
}

static std::string hex128(uint128_t value)
{
  String text;
  text.assignItoh(value);
  return std::string(text.c_str(), text.size());
}

static std::string allMastersPreparationJSON(const MothershipNametagAllMastersRecord& record)
{
  constexpr const char *siteNames[] = {"task-ewr", "task-ord", "retained-lan"};
  std::string json = "{\"schema\":\"mothership.nametag-all-masters.prepare.v2\",\"operationUUID\":\"" +
      hex128(record.intent.operationUUID) + "\",\"sites\":[";
  for (size_t index = 0; index < record.intent.sites.size(); ++index) {
    const auto& site = record.intent.sites[index];
    if (index) json += ',';
    json += std::string("{\"clusterName\":\"") + siteNames[index] + "\",\"pulseDeploymentID\":" +
        std::to_string(site.pulseDeploymentID) + ",\"hotDeploymentID\":" + std::to_string(site.hotDeploymentID) +
        ",\"coldDeploymentID\":" + std::to_string(site.coldDeploymentID) + ",\"radarDeploymentID\":" +
        std::to_string(site.radarDeploymentID) + ",\"truthDeploymentID\":" + std::to_string(site.truthDeploymentID) +
        ",\"app6DeploymentID\":" + std::to_string(site.app6DeploymentID) + '}';
  }
  json += "],\"pairOperationUUIDs\":[\"" + hex128(record.intent.directGatewayAuthorities[0].pairOperationUUID) +
      "\",\"" + hex128(record.intent.directGatewayAuthorities[6].pairOperationUUID) + "\",\"" +
      hex128(record.intent.directGatewayAuthorities[12].pairOperationUUID) + "\"]";
  return json + "}";
}

static bool parsesAllMastersPreparation(const std::string& json)
{
  simdjson::dom::parser parser; simdjson::dom::element document;
  MothershipNametagAllMastersPreparation output = {}; String failure = {};
  return parser.parse(json.data(), json.size()).get(document) == simdjson::SUCCESS &&
      mothershipParseNametagAllMastersPreparationJSON(document, output, failure);
}

static MothershipNametagQualificationIntent qualificationIntent(
    const MothershipNametagQualificationAdapter& adapter,
    const MothershipNametagAllMastersRecord& allMasters)
{
  MothershipNametagQualificationIntent intent = {};
  intent.runUUID = 0x1001; intent.row = adapter.row; intent.direction = adapter.direction;
  intent.executionGeneration = 7; intent.rowID.assign(adapter.rowID);
  intent.descriptor = mothershipNametagQualificationDescriptor(adapter.row);
  intent.allMastersOperationUUID = allMasters.intent.operationUUID;
  for (uint32_t site = 0; site < 3; ++site) {
    auto& target = intent.probeTargets.emplace_back();
    target.clusterUUID = allMasters.intent.sites[site].clusterUUID; target.probeDeploymentID = 0x700 + site;
  }
  if (intent.row == MothershipNametagQualificationRow::secondStreamHandoffFence ||
      intent.row == MothershipNametagQualificationRow::truthClaimPartition) {
    for (uint32_t site = 0; site < 3; ++site) for (uint32_t peer = 0; peer < 2; ++peer) {
      const uint32_t selected = (site + peer) % 3;
      ProdigyNametagQualificationApp6Route route = {};
      route.clusterUUID = allMasters.intent.sites[selected].clusterUUID;
      route.deploymentID = (uint64_t(6) << 48) | (selected + 1);
      route.containerUUID = uint128_t(0x6000 + selected); route.ipv6[0] = 0x20; route.ipv6[15] = uint8_t(selected + 1);
      route.port = 443; route.cidFixtureSHA256.assign("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv);
      for (uint32_t n = 0; n < (intent.row == MothershipNametagQualificationRow::truthClaimPartition ? 6 : 2); ++n) { String cid = {}; uint8_t byte = uint8_t(1 + site * 32 + peer * 16 + n); cid.append(&byte, 1); route.cids.push_back(std::move(cid)); }
      intent.app6Routes.push_back(std::move(route));
    }
  }
  intent.deadlineSeconds = adapter.deadlineSeconds; intent.convergenceSeconds = adapter.convergenceSeconds;
  intent.startedAtMilliseconds = 1'000'000;
  intent.deadlineAtMilliseconds = intent.startedAtMilliseconds + int64_t(intent.deadlineSeconds) * 1000;
  intent.convergenceDeadlineAtMilliseconds = intent.startedAtMilliseconds + int64_t(intent.convergenceSeconds) * 1000;
  if ((intent.row == MothershipNametagQualificationRow::secondTruthWriterFencing ||
       intent.row == MothershipNametagQualificationRow::mothershipRestartResume ||
       intent.row == MothershipNametagQualificationRow::truthClaimPartition ||
       intent.row == MothershipNametagQualificationRow::graphKvReplayReorder ||
       intent.row == MothershipNametagQualificationRow::permissionRevokeReinstall ||
       intent.row == MothershipNametagQualificationRow::cousinRouteSessionReconnect) &&
      intent.direction == MothershipNametagQualificationDirection::observation) {
    intent.priorInjectionRunUUID = intent.runUUID;
    intent.priorInjectionReceiptDigest = digest('8');
  }
  assert(mothershipNametagQualificationIntentValid(intent));
  return intent;
}

static MothershipNametagQualificationReceipt qualificationReceipt(
    const MothershipNametagQualificationIntent& intent)
{
  MothershipNametagQualificationReceipt receipt = {};
  Vector<ProdigyNametagQualificationApplicationReceipt> applications = {};
  for (uint32_t site = 0; site < intent.probeTargets.size(); ++site)
  {
    const auto& target = intent.probeTargets[site];
    auto& application = applications.emplace_back();
    application.runUUID = intent.runUUID; application.row = uint8_t(intent.row);
    application.direction = uint8_t(intent.direction); application.executionGeneration = intent.executionGeneration;
    application.rowID = intent.rowID; application.descriptor = intent.descriptor;
    application.localClusterUUID = target.clusterUUID; application.deploymentID = target.probeDeploymentID;
    application.localContainerUUID = 0xb000 + site;
    application.startedAtMilliseconds = intent.startedAtMilliseconds; application.deadlineAtMilliseconds = intent.deadlineAtMilliseconds;
    application.convergenceDeadlineAtMilliseconds = intent.convergenceDeadlineAtMilliseconds;
    application.observedAtMilliseconds = intent.convergenceDeadlineAtMilliseconds;
    application.witnessedResult = intent.descriptor.expectedWitness;
    if (intent.row == MothershipNametagQualificationRow::secondTruthWriterFencing) {
      application.participantRole = intent.direction == MothershipNametagQualificationDirection::injection && site == 0 ?
          ProdigyNametagQualificationParticipantRole::ewrSessionFence :
          ProdigyNametagQualificationParticipantRole::truthObserver;
      application.joinedWitnessDigest = digest('7');
    }
    application.canonicalWitnessReceipt.assign("row-specific-application-witness-v4"_ctv);
    application.witnessDigest = digest('b');
  }
  MothershipNametagQualificationExecutionRecord execution = {};
  if (intent.row == MothershipNametagQualificationRow::secondTruthWriterFencing &&
      intent.direction == MothershipNametagQualificationDirection::injection) {
    execution.intent = intent;
    execution.phase = MothershipNametagQualificationExecutionPhase::converging;
    execution.secondTruthWriterAdmission.sourceClusterUUID = intent.probeTargets[0].clusterUUID;
    execution.secondTruthWriterAdmission.candidateClusterUUID = intent.probeTargets[1].clusterUUID;
    execution.secondTruthWriterAdmission.retainedOwnerClusterUUID = intent.probeTargets[0].clusterUUID;
    execution.secondTruthWriterAdmission.retainedPlacementGeneration = 1;
    execution.secondTruthWriterAdmission.candidatePlanSHA256 = digest('6');
    execution.secondTruthWriterAdmission.fenced = true;
  }
  // A standalone row-sixteen observation is not a synthetic fixture: its
  // receipt requires the persisted injection receipt and exact digest. Tests
  // that exercise that join provide both explicitly below.
  assert(intent.row != MothershipNametagQualificationRow::secondTruthWriterFencing ||
      intent.direction != MothershipNametagQualificationDirection::observation);
  String topologyEvidence = {}, failure = {};
  topologyEvidence.assign("native-topology-evidence-v4"_ctv);
  bool built = mothershipNametagQualificationBuildReceipt(intent, applications, topologyEvidence,
      intent.convergenceDeadlineAtMilliseconds, receipt, &failure,
      intent.row == MothershipNametagQualificationRow::secondTruthWriterFencing &&
      intent.direction == MothershipNametagQualificationDirection::injection ? &execution : nullptr);
  if (!built) fprintf(stderr, "generic receipt fixture row=%u: %.*s\n", unsigned(intent.row), int(failure.size()), failure.data());
  assert(built);
  return receipt;
}

static void pathApplicationWitnessContract()
{
  for (auto row : {ProdigyNametagQualificationRow::sitePartitionLocalWrites,
                   ProdigyNametagQualificationRow::masqueSessionLossBgpRecovery,
                   ProdigyNametagQualificationRow::ewrOrdPathLoss}) {
    ProdigyNametagQualificationApplicationCommand command = {};
    command.protocolVersion = command.pathStageVersion;
    command.runUUID = 0x123; command.row = uint8_t(row); command.direction = 1;
    command.executionGeneration = 10; command.rowID.assign("path-test"_ctv);
    command.descriptor = prodigyNametagQualificationDescriptor(row);
    command.localClusterUUID = 1; command.canonicalClusterUUIDs = {1, 2, 3};
    command.deploymentID = uint64_t(11) << 48 | 1;
    command.startedAtMilliseconds = 1000; command.deadlineAtMilliseconds = 120000;
    command.convergenceDeadlineAtMilliseconds = 90000;
    command.pathStage = ProdigyNametagQualificationPathStage::localWork;
    command.pathFaultExpiresAtMilliseconds = 50000;
    assert(prodigyNametagQualificationApplicationCommandValid(command));
    auto wrong = command; wrong.direction = 2;
    assert(!prodigyNametagQualificationApplicationCommandValid(wrong));
    wrong = command; wrong.pathBatch = 2;
    assert(!prodigyNametagQualificationApplicationCommandValid(wrong));
    wrong = command; wrong.pathStage = ProdigyNametagQualificationPathStage::partitionRead;
    assert(prodigyNametagQualificationApplicationCommandValid(wrong) ==
           (row == ProdigyNametagQualificationRow::ewrOrdPathLoss));
    ProdigyNametagQualificationApplicationReceipt receipt = {};
    receipt.protocolVersion = receipt.pathStageVersion;
    receipt.runUUID = command.runUUID; receipt.row = command.row; receipt.direction = command.direction;
    receipt.executionGeneration = command.executionGeneration; receipt.rowID = command.rowID;
    receipt.descriptor = command.descriptor; receipt.localClusterUUID = command.localClusterUUID;
    receipt.deploymentID = command.deploymentID; receipt.localContainerUUID = 0x456;
    receipt.startedAtMilliseconds = command.startedAtMilliseconds;
    receipt.deadlineAtMilliseconds = command.deadlineAtMilliseconds;
    receipt.convergenceDeadlineAtMilliseconds = command.convergenceDeadlineAtMilliseconds;
    receipt.observedAtMilliseconds = 49999; receipt.witnessedResult = command.descriptor.expectedWitness;
    receipt.canonicalWitnessReceipt.assign("path-native-stores"_ctv);
    receipt.witnessDigest = digest('a'); receipt.joinedWitnessDigest = digest('b');
    receipt.pathStage = command.pathStage; receipt.pathFaultExpiresAtMilliseconds = command.pathFaultExpiresAtMilliseconds;
    assert(prodigyNametagQualificationPathReceiptMatchesCommand(command, receipt));
    auto late = receipt; ++late.observedAtMilliseconds;
    assert(!prodigyNametagQualificationApplicationReceiptValid(late));
    auto other = receipt; ++other.pathFaultExpiresAtMilliseconds;
    assert(!prodigyNametagQualificationPathReceiptMatchesCommand(command, other));
    other = receipt; ++other.pathBatch;
    assert(!prodigyNametagQualificationPathReceiptMatchesCommand(command, other));
    String encoded = {}; auto copy = receipt;
    assert(BitseryEngine::serialize(encoded, copy));
    ProdigyNametagQualificationApplicationReceipt decoded = {};
    assert(BitseryEngine::deserializeSafe(encoded, decoded) &&
           prodigyNametagQualificationPathReceiptMatchesCommand(command, decoded));
    command.direction = 2; command.pathStage = ProdigyNametagQualificationPathStage::final;
    command.startedAtMilliseconds = 60000;
    command.priorInjectionRunUUID = command.runUUID; command.priorInjectionReceiptDigest = digest('c');
    assert(prodigyNametagQualificationApplicationCommandValid(command));
    command.priorInjectionReceiptDigest.clear();
    assert(!prodigyNametagQualificationApplicationCommandValid(command));
  }
}

static void claimApplicationWitnessContract()
{
  const auto* adapter = mothershipNametagQualificationAdapter("nametagChaosTruthClaimPartition");
  assert(adapter);
  auto intent = qualificationIntent(*adapter, allMastersRecord());
  for (size_t i = 0; i < intent.probeTargets.size(); ++i)
    intent.probeTargets[i].probeDeploymentID = (uint64_t(11) << 48) | (i + 1);
  MothershipNametagQualificationSiteRequest site;
  site.protocolVersion = site.claimStageVersion; site.intent = intent;
  site.targetClusterUUID = intent.probeTargets[0].clusterUUID;
  site.targetProbeDeploymentID = intent.probeTargets[0].probeDeploymentID;
  site.targetApp6DeploymentID = intent.app6Routes[0].deploymentID;
  site.claimStage = ProdigyNametagQualificationClaimStage::prepare;
  ProdigyNametagQualificationApplicationCommand command;
  assert(mothershipNametagQualificationApplicationCommand(site, command));
  assert(command.protocolVersion == command.claimStageVersion && command.app6Routes.size() == 2);
  auto invalid = command; invalid.protocolVersion = invalid.version;
  assert(!prodigyNametagQualificationApplicationCommandValid(invalid));
  invalid = command; invalid.claimFaultExpiresAtMilliseconds = intent.startedAtMilliseconds + 20000;
  assert(!prodigyNametagQualificationApplicationCommandValid(invalid));
  invalid = command; invalid.app6Routes[0].cids.resize(2);
  assert(!prodigyNametagQualificationApplicationCommandValid(invalid));
  site.claimStage = ProdigyNametagQualificationClaimStage::contend;
  site.claimFaultExpiresAtMilliseconds = intent.startedAtMilliseconds + 60000;
  assert(mothershipNametagQualificationApplicationCommand(site, command));
  ProdigyNametagQualificationApplicationReceipt receipt;
  receipt.protocolVersion = receipt.claimStageVersion;
  receipt.runUUID = command.runUUID; receipt.row = command.row; receipt.direction = command.direction;
  receipt.executionGeneration = command.executionGeneration; receipt.rowID = command.rowID;
  receipt.descriptor = command.descriptor; receipt.localClusterUUID = command.localClusterUUID;
  receipt.deploymentID = command.deploymentID; receipt.localContainerUUID = 0x111;
  receipt.startedAtMilliseconds = command.startedAtMilliseconds; receipt.deadlineAtMilliseconds = command.deadlineAtMilliseconds;
  receipt.convergenceDeadlineAtMilliseconds = command.convergenceDeadlineAtMilliseconds;
  receipt.observedAtMilliseconds = site.claimFaultExpiresAtMilliseconds - 1;
  receipt.witnessedResult = command.descriptor.expectedWitness;
  receipt.canonicalWitnessReceipt.assign("normal-native-claim-response"_ctv);
  receipt.witnessDigest = digest('a'); receipt.joinedWitnessDigest = digest('b');
  receipt.claimStage = command.claimStage; receipt.claimFaultExpiresAtMilliseconds = command.claimFaultExpiresAtMilliseconds;
  receipt.claimResults[0] = {true, true}; receipt.claimResults[1] = {true, false}; receipt.claimResults[2] = {false, false};
  assert(prodigyNametagQualificationClaimReceiptMatchesCommand(command, receipt));
  auto badReceipt = receipt; badReceipt.claimResults[2].accepted = true;
  assert(!prodigyNametagQualificationApplicationReceiptValid(badReceipt));
  badReceipt = receipt; badReceipt.observedAtMilliseconds++;
  assert(!prodigyNametagQualificationApplicationReceiptValid(badReceipt));
  badReceipt = receipt; badReceipt.pathStage = ProdigyNametagQualificationPathStage::localWork;
  assert(!prodigyNametagQualificationApplicationReceiptValid(badReceipt));
  String bytes; auto copy = receipt;
  assert(BitseryEngine::serialize(bytes, copy));
  ProdigyNametagQualificationApplicationReceipt decoded;
  assert(BitseryEngine::deserializeSafe(bytes, decoded) && prodigyNametagQualificationClaimReceiptMatchesCommand(command, decoded));
  auto wrong = site; wrong.claimStage = ProdigyNametagQualificationClaimStage::settle;
  assert(!mothershipNametagQualificationSiteRequestValid(wrong));
  wrong.claimWinnerSites = {intent.probeTargets[0].clusterUUID, intent.probeTargets[2].clusterUUID, intent.probeTargets[0].clusterUUID};
  assert(mothershipNametagQualificationApplicationCommand(wrong, command));
  wrong.claimWinnerSites[2] = 0xff;
  assert(!mothershipNametagQualificationSiteRequestValid(wrong));
  MothershipNametagQualificationExecutionRecord partial = {};
  partial.protocolVersion = partial.claimVersion; partial.intent = intent;
  auto prepared = receipt; prepared.claimStage = ProdigyNametagQualificationClaimStage::prepare;
  prepared.claimFaultExpiresAtMilliseconds = 0; prepared.claimResults = {};
  partial.claimReceipts.push_back(prepared);
  assert(mothershipNametagQualificationExecutionRecordValid(partial));
  auto duplicateRecord = partial; duplicateRecord.claimReceipts.push_back(prepared);
  assert(!mothershipNametagQualificationExecutionRecordValid(duplicateRecord));
  auto premature = partial; premature.phase = MothershipNametagQualificationExecutionPhase::verified;
  assert(!mothershipNametagQualificationExecutionRecordValid(premature));
  String journalBytes; auto partialCopy = partial;
  assert(BitseryEngine::serialize(journalBytes, partialCopy));
  MothershipNametagQualificationExecutionRecord roundTrip = {};
  assert(BitseryEngine::deserializeSafe(journalBytes, roundTrip) &&
      roundTrip.protocolVersion == roundTrip.claimVersion && roundTrip.claimReceipts.size() == 1 &&
      mothershipNametagQualificationExecutionRecordValid(roundTrip));
  std::vector<int> dispatchOrder;
  assert(mothershipNametagQualificationDispatchSites([&](uint32_t site) { dispatchOrder.push_back(int(site)); return true; },
      [&](uint32_t site) { dispatchOrder.push_back(int(site) + 10); return true; }));
  assert((dispatchOrder == std::vector<int>{0, 1, 2, 10, 11, 12}));
  dispatchOrder.clear();
  assert(!mothershipNametagQualificationDispatchSites([&](uint32_t site) { dispatchOrder.push_back(int(site)); return site != 1; },
      [&](uint32_t site) { dispatchOrder.push_back(int(site) + 10); return true; }));
  assert((dispatchOrder == std::vector<int>{0, 1}));
  // Exercise the same journal gate used by the live executor across a
  // partially completed dispatch and a crash during path restoration.
  MothershipNametagQualificationExecutionRecord journal = {};
  auto addStage = [&](ProdigyNametagQualificationClaimStage stage, size_t count) {
    size_t previous = 0; for (const auto& r : journal.claimReceipts) if (r.claimStage == stage) ++previous;
    for (size_t i = 0; i < count; ++i) { ProdigyNametagQualificationApplicationReceipt r = {};
      r.claimStage = stage; r.localClusterUUID = previous + i + 1; journal.claimReceipts.push_back(r); }
  };
  assert(mothershipNametagQualificationClaimStageMayRecord(journal, ProdigyNametagQualificationClaimStage::prepare));
  addStage(ProdigyNametagQualificationClaimStage::prepare, 2);
  assert(!mothershipNametagQualificationClaimStageMayRecord(journal, ProdigyNametagQualificationClaimStage::arm));
  addStage(ProdigyNametagQualificationClaimStage::prepare, 1);
  assert(mothershipNametagQualificationClaimStageMayRecord(journal, ProdigyNametagQualificationClaimStage::arm));
  addStage(ProdigyNametagQualificationClaimStage::arm, 3);
  assert(!mothershipNametagQualificationClaimStageMayRecord(journal, ProdigyNametagQualificationClaimStage::contend));
  journal.pathFaults.resize(6);
  for (auto& fault : journal.pathFaults) fault.paused.response = true;
  assert(mothershipNametagQualificationClaimStageMayRecord(journal, ProdigyNametagQualificationClaimStage::contend));
  addStage(ProdigyNametagQualificationClaimStage::contend, 3);
  journal.protocolVersion = MothershipNametagQualificationExecutionRecord::claimVersion;
  assert(!mothershipNametagQualificationPathMayBeginRestore(journal, 0));
  journal.claimWinnerSites = {1, 2, 3};
  assert(mothershipNametagQualificationPathMayBeginRestore(journal, 0));
  journal.pathFaults[0].paused.response = false;
  assert(!mothershipNametagQualificationPathMayBeginRestore(journal, 0));
  journal.pathFaults[0].paused.response = true;
  assert(!mothershipNametagQualificationClaimStageMayRecord(journal, ProdigyNametagQualificationClaimStage::settle));
  journal.pathRestoringBatches = 1;
  for (size_t i = 0; i < 5; ++i) journal.pathFaults[i].restored.response = true;
  assert(!mothershipNametagQualificationClaimStageMayRecord(journal, ProdigyNametagQualificationClaimStage::contend));
  assert(!mothershipNametagQualificationClaimStageMayRecord(journal, ProdigyNametagQualificationClaimStage::settle));
  journal.pathFaults[5].restored.response = true;
  assert(mothershipNametagQualificationClaimStageMayRecord(journal, ProdigyNametagQualificationClaimStage::settle));
  addStage(ProdigyNametagQualificationClaimStage::settle, 3);
  assert(mothershipNametagQualificationClaimStageMayRecord(journal, ProdigyNametagQualificationClaimStage::final));
  journal.pathAborting = true;
  assert(!mothershipNametagQualificationClaimStageMayRecord(journal, ProdigyNametagQualificationClaimStage::final));
  const auto* observe = mothershipNametagQualificationAdapter("nametagObserveTruthClaimPartition");
  assert(observe);
  wrong.intent = qualificationIntent(*observe, allMastersRecord());
  for (size_t i = 0; i < wrong.intent.probeTargets.size(); ++i)
    wrong.intent.probeTargets[i].probeDeploymentID = (uint64_t(11) << 48) | (i + 1);
  wrong.claimStage = ProdigyNametagQualificationClaimStage::final;
  wrong.claimWinnerSites = {intent.probeTargets[0].clusterUUID, intent.probeTargets[2].clusterUUID, intent.probeTargets[0].clusterUUID};
  assert(mothershipNametagQualificationApplicationCommand(wrong, command));
  wrong.intent.priorInjectionReceiptDigest.clear();
  assert(!mothershipNametagQualificationSiteRequestValid(wrong));
}

static void seedReadbackSiteContract()
{
  const auto *adapter = mothershipNametagQualificationAdapter("nametagChaosSeedInterruptionResume");
  assert(adapter);
  auto allMasters = allMastersRecord();
  auto intent = qualificationIntent(*adapter, allMasters);
  for (size_t i = 0; i < intent.probeTargets.size(); ++i)
    intent.probeTargets[i].probeDeploymentID = (uint64_t(11) << 48) | (i + 1);
  MothershipNametagQualificationSiteRequest site = {};
  site.protocolVersion = site.seedReadbackVersion; site.intent = intent;
  site.targetClusterUUID = intent.probeTargets[0].clusterUUID;
  site.targetProbeDeploymentID = intent.probeTargets[0].probeDeploymentID;
  site.targetApp6DeploymentID = allMasters.intent.sites[0].app6DeploymentID;
  site.seedBaselineOperationUUID = 0x123;
  site.seedStoreDeploymentIDs = {(uint64_t(MeshRegistry::Hot::applicationID) << 48) | 1,
    (uint64_t(MeshRegistry::Cold::applicationID) << 48) | 1, (uint64_t(MeshRegistry::Radar::applicationID) << 48) | 1,
    (uint64_t(MeshRegistry::Pulse::applicationID) << 48) | 1, (uint64_t(MeshRegistry::Truth::applicationID) << 48) | 1};
  site.seedControlWitnessDigest = digest('a'); site.seedBaselineFixtureSHA256 = digest('b'); site.seedBaselineReadbackSHA256 = digest('c');
  String wire; auto copy = site; MothershipNametagQualificationSiteRequest decoded = {};
  assert(BitseryEngine::serialize(wire, copy) && BitseryEngine::deserializeSafe(wire, decoded));
  ProdigyNametagQualificationApplicationCommand command = {};
  assert(mothershipNametagQualificationApplicationCommand(decoded, command));
  assert(command.seedBaselineOperationUUID == site.seedBaselineOperationUUID && command.seedStoreDeploymentIDs == site.seedStoreDeploymentIDs &&
      command.seedControlWitnessDigest == site.seedControlWitnessDigest && command.seedBaselineFixtureSHA256 == site.seedBaselineFixtureSHA256 &&
      command.seedBaselineReadbackSHA256 == site.seedBaselineReadbackSHA256);
  ProdigyNametagQualificationApplicationReceipt receipt = {};
  receipt.protocolVersion = receipt.seedReadbackVersion; receipt.runUUID = command.runUUID; receipt.row = command.row;
  receipt.direction = command.direction; receipt.executionGeneration = command.executionGeneration; receipt.rowID = command.rowID;
  receipt.descriptor = command.descriptor; receipt.localClusterUUID = command.localClusterUUID; receipt.deploymentID = command.deploymentID;
  receipt.localContainerUUID = 0x111; receipt.startedAtMilliseconds = command.startedAtMilliseconds;
  receipt.deadlineAtMilliseconds = command.deadlineAtMilliseconds; receipt.convergenceDeadlineAtMilliseconds = command.convergenceDeadlineAtMilliseconds;
  receipt.observedAtMilliseconds = command.startedAtMilliseconds + 1; receipt.witnessedResult = command.descriptor.expectedWitness;
  receipt.canonicalWitnessReceipt.assign("native-seed-readback"_ctv); receipt.witnessDigest = digest('d'); receipt.joinedWitnessDigest = digest('e');
  receipt.seedControlWitnessDigest = command.seedControlWitnessDigest; receipt.seedBaselineReadbackSHA256 = command.seedBaselineReadbackSHA256;
  site.action = MothershipNametagQualificationSiteAction::query;
  MothershipNametagQualificationSiteResponse response = {}; response.protocolVersion = response.seedReadbackVersion;
  response.success = response.completed = true; response.applicationReceipt = receipt;
  assert(mothershipNametagQualificationSiteResponseValid(site, response));
  response.applicationReceipt.seedControlWitnessDigest = digest('f');
  assert(!mothershipNametagQualificationSiteResponseValid(site, response));
  // A seed execution binds the durable successors and each site's final receipt.
  intent.protocolVersion = intent.seedVersion; intent.seedInputSHA256 = digest('1');
  intent.seedSuccessorOperationUUIDs = {0x101, 0x102}; intent.seedChallengeUUIDs = {0x201, 0x202};
  assert(mothershipNametagQualificationIntentValid(intent));
  MothershipNametagQualificationExecutionRecord execution = {};
  execution.protocolVersion = execution.seedVersion; execution.intent = intent;
  assert(mothershipNametagQualificationExecutionRecordValid(execution));
  execution.seedSuccessors = {{0x101, digest('2')}, {0x102, digest('3')}};
  execution.seedBaselineOperationUUID = site.seedBaselineOperationUUID;
  execution.seedBaselineFixtureSHA256 = site.seedBaselineFixtureSHA256;
  execution.seedBaselineReadbackSHA256 = site.seedBaselineReadbackSHA256;
  assert(mothershipNametagQualificationSeedControlWitnessDigest(execution, execution.seedControlWitnessDigest));
  for (size_t i = 0; i < 3; ++i) {
    execution.seedStoreDeploymentIDs[i] = site.seedStoreDeploymentIDs;
    auto final = receipt; final.localClusterUUID = intent.probeTargets[i].clusterUUID;
    final.deploymentID = intent.probeTargets[i].probeDeploymentID;
    final.localContainerUUID += i;
    final.seedControlWitnessDigest = execution.seedControlWitnessDigest;
    execution.seedFinalReadbacks.push_back(final);
  }
  execution.phase = MothershipNametagQualificationExecutionPhase::converging;
  assert(mothershipNametagQualificationExecutionRecordValid(execution));
  String encodedExecution; auto executionCopy = execution; MothershipNametagQualificationExecutionRecord decodedExecution = {};
  assert(BitseryEngine::serialize(encodedExecution, executionCopy) && BitseryEngine::deserializeSafe(encodedExecution, decodedExecution));
  assert(mothershipNametagQualificationExecutionRecordValid(decodedExecution));
  decodedExecution.seedSuccessors[0].sha256 = digest('4');
  assert(!mothershipNametagQualificationExecutionRecordValid(decodedExecution));
  decodedExecution = execution; decodedExecution.seedFinalReadbacks[1].localClusterUUID = intent.probeTargets[0].clusterUUID;
  assert(!mothershipNametagQualificationExecutionRecordValid(decodedExecution));
  MothershipNametagQualificationReceipt seedReceipt = {}; String seedFailure;
  assert(mothershipNametagQualificationBuildReceipt(intent, execution.seedFinalReadbacks, String("topology"),
      intent.startedAtMilliseconds + 1, seedReceipt, &seedFailure, &execution));
  const auto seedRegistryRoot = std::filesystem::temp_directory_path() / "prodigy-seed-receipt-missing-execution-unit";
  std::filesystem::remove_all(seedRegistryRoot);
  {
    MothershipClusterRegistry seedRegistry{String(seedRegistryRoot.c_str())};
    assert(!seedRegistry.nametagQualificationSeedReceiptMatchesExecution(*adapter, intent, seedReceipt, &seedFailure));
  }
  std::filesystem::remove_all(seedRegistryRoot);
  auto badIntent = intent; badIntent.seedChallengeUUIDs[1] = badIntent.seedChallengeUUIDs[0];
  assert(!mothershipNametagQualificationIntentValid(badIntent));
  site.seedStoreDeploymentIDs[0] = site.seedStoreDeploymentIDs[1];
  assert(!mothershipNametagQualificationSiteRequestValid(site));
  site = decoded; site.protocolVersion = site.version;
  assert(!mothershipNametagQualificationSiteRequestValid(site));
}

static void replayWorkloadRoutingContract()
{
  assert(prodigyNametagQualificationReplayApplicationID(ProdigyNametagQualificationReplayStore::kv) == MeshRegistry::Hot::applicationID);
  assert(prodigyNametagQualificationReplayApplicationID(ProdigyNametagQualificationReplayStore::graph) == MeshRegistry::Pulse::applicationID);
  assert(prodigyNametagQualificationReplayApplicationID(ProdigyNametagQualificationReplayStore::none) == 0);
  // Two subscribers may share one advertiser; select the same exact session
  // regardless of arrival order, including when both containers match.
  assert(prodigyNametagQualificationReplaySessionLess(4, 7, 9, 4, 8, 1));
  assert(!prodigyNametagQualificationReplaySessionLess(4, 8, 1, 4, 7, 9));
  assert(prodigyNametagQualificationReplaySessionLess(4, 7, 2, 4, 7, 9));
  assert(!prodigyNametagQualificationReplaySessionLess(4, 7, 9, 4, 7, 2));
  String previous;
  for (uint32_t group = 0; group < 3; ++group) {
    String name, retry;
    assert(prodigyNametagQualificationReplayWorkloadName(17, ProdigyNametagQualificationReplayStore::kv, group, name));
    assert(prodigyNametagQualificationReplayWorkloadName(17, ProdigyNametagQualificationReplayStore::kv, group, retry));
    assert(name == retry && name.size() == 64 && name != previous);
    assert(statefulServiceGroupOwnerForSlot(jump_consistent_hash(name.data(), 16), 3) == group);
    previous = name;
  }
  String graph, other;
  assert(prodigyNametagQualificationReplayWorkloadName(17, ProdigyNametagQualificationReplayStore::graph, 0, graph));
  assert(prodigyNametagQualificationReplayWorkloadName(18, ProdigyNametagQualificationReplayStore::graph, 0, other));
  assert(graph != other && graph != previous);
  assert(!prodigyNametagQualificationReplayWorkloadName(0, ProdigyNametagQualificationReplayStore::kv, 0, other));
  assert(!prodigyNametagQualificationReplayWorkloadName(17, ProdigyNametagQualificationReplayStore::kv, 3, other));
  assert(!prodigyNametagQualificationReplayWorkloadName(17, ProdigyNametagQualificationReplayStore::graph, 1, other));
  ProdigyNametagQualificationReplay installed = {};
  installed.runUUID = 1; installed.challengeUUID = 2; installed.executionGeneration = 3;
  installed.deadlineAtMilliseconds = 1000; installed.direction = 1;
  installed.stage = ProdigyNametagQualificationReplayStage::arm;
  installed.store = ProdigyNametagQualificationReplayStore::kv; installed.applicationID = 3;
  installed.sourceAddress = 4; installed.workloadName = graph;
  auto& session = installed.session;
  session.pairUUID = 1; session.routeUUID = 2; session.sourcePermissionUUID = 3; session.destinationPermissionUUID = 4;
  session.sourceClusterUUID = 5; session.destinationClusterUUID = 6; session.sourceDeploymentID = 7; session.destinationDeploymentID = 8;
  session.sourceContainerUUID = 9; session.destinationContainerUUID = 10; session.sessionUUID = 11;
  session.sessionGeneration = session.routeGeneration = session.sourcePermissionAuthorityGeneration = 1;
  assert(prodigyNametagQualificationReplayValid(installed));
  auto release = installed; release.stage = ProdigyNametagQualificationReplayStage::release;
  assert(prodigyNametagQualificationReplayExpiredReleaseMatches(release, installed, true, 4, 4, 1001));
  assert(!prodigyNametagQualificationReplayExpiredReleaseMatches(release, installed, false, 4, 4, 1001));
  assert(!prodigyNametagQualificationReplayExpiredReleaseMatches(release, installed, true, 4, 5, 1001));
  assert(!prodigyNametagQualificationReplayExpiredReleaseMatches(release, installed, true, 4, 4, 61001));
  ++release.challengeUUID;
  assert(!prodigyNametagQualificationReplayExpiredReleaseMatches(release, installed, true, 4, 4, 1001));
  release = installed;
  assert(!prodigyNametagQualificationReplayRelayTimely(release, 1001));
}

int main()
{
  {
    ProdigyNametagQualificationMachineBoot request = {};
    request.runUUID = 1; request.challengeUUID = 2; request.clusterUUID = 3; request.machineUUID = 4;
    request.executionGeneration = 1; request.deadlineAtMilliseconds = 1000;
    assert(prodigyNametagQualificationMachineBootValid(request));
    auto receipt = request; receipt.response = receipt.ready = true;
    receipt.bootID.assign("01234567-89ab-cdef-0123-456789abcdef"_ctv);
    assert(prodigyNametagQualificationMachineBootMatches(request, receipt));
    auto forged = receipt; ++forged.machineUUID;
    assert(!prodigyNametagQualificationMachineBootMatches(request, forged));
    forged = receipt; forged.bootID.assign("not-a-kernel-boot-id"_ctv);
    assert(!prodigyNametagQualificationMachineBootValid(forged));
    String wire; auto copy = receipt; ProdigyNametagQualificationMachineBoot decoded = {};
    assert(BitseryEngine::serialize(wire, copy) && BitseryEngine::deserializeSafe(wire, decoded) &&
        prodigyNametagQualificationMachineBootMatches(request, decoded));
  }
  {
    ProdigyNametagQualificationWriterIsolation request = {};
    request.runUUID = 1; request.challengeUUID = 2; request.clusterUUID = 3;
    request.executionGeneration = 1; request.deploymentID = 4; request.deadlineAtMilliseconds = 1000;
    request.stage = ProdigyNametagQualificationWriterIsolationStage::isolate;
    request.applicationID = 3; request.validForMilliseconds = 500;
    request.targetContainerUUID = 5; request.targetMachineUUID = 6; request.targetAddress = 7;
    request.survivorContainerUUIDs = {8, 9}; request.survivorAddresses = {10, 11};
    assert(prodigyNametagQualificationWriterIsolationValid(request));
    auto receipt = request; receipt.response = receipt.ready = receipt.isolated = true;
    assert(prodigyNametagQualificationWriterIsolationResponseMatches(request, receipt));
    auto wrong = receipt; wrong.targetMachineUUID++;
    assert(!prodigyNametagQualificationWriterIsolationResponseMatches(request, wrong));
    wrong = receipt; wrong.survivorAddresses[0] = wrong.targetAddress;
    assert(!prodigyNametagQualificationWriterIsolationValid(wrong));
    wrong = request; wrong.validForMilliseconds = 60001;
    assert(!prodigyNametagQualificationWriterIsolationValid(wrong));
    wrong = receipt; wrong.stage = ProdigyNametagQualificationWriterIsolationStage::release;
    assert(!prodigyNametagQualificationWriterIsolationValid(wrong));
  }
  pathApplicationWitnessContract();
  claimApplicationWitnessContract();
  seedReadbackSiteContract();
  replayWorkloadRoutingContract();
  assert(std::size(mothershipNametagQualificationAdapters) == 34);
  for (const auto& candidate : mothershipNametagQualificationAdapters) {
    const auto descriptor = mothershipNametagQualificationDescriptor(candidate.row);
    assert(prodigyNametagQualificationDescriptorValid(descriptor));
    assert(descriptor.expectedWitness != ProdigyNametagQualificationWitness{});
  }
  for (auto row : {ProdigyNametagQualificationRow::sitePartitionLocalWrites,
                   ProdigyNametagQualificationRow::masqueSessionLossBgpRecovery}) {
    auto descriptor = prodigyNametagQualificationDescriptor(row);
    assert(descriptor.target == ProdigyNametagQualificationTarget::sitePaths &&
           descriptor.targetSite == ProdigyNametagQualificationSite::ord &&
           descriptor.peerSite == ProdigyNametagQualificationSite::all && descriptor.pathSlot == UINT8_MAX);
    descriptor.pathSlot = 0;
    assert(!prodigyNametagQualificationDescriptorValid(descriptor));
  }
  auto directPaths = prodigyNametagQualificationDescriptor(ProdigyNametagQualificationRow::ewrOrdPathLoss);
  assert(directPaths.target == ProdigyNametagQualificationTarget::ewrOrdPaths &&
         directPaths.targetSite == ProdigyNametagQualificationSite::ewr &&
         directPaths.peerSite == ProdigyNametagQualificationSite::ord && directPaths.pathSlot == UINT8_MAX);
  directPaths.pathSlot = 2;
  assert(!prodigyNametagQualificationDescriptorValid(directPaths));
  const auto root = std::filesystem::temp_directory_path() / "prodigy-nametag-qualification-unit";
  std::filesystem::remove_all(root);
  String path(root.c_str());
  auto registry = std::make_unique<MothershipClusterRegistry>(path);
  const auto *genericAdapter = mothershipNametagQualificationAdapter("nametagChaosSequentialUserKeyWrites");
  assert(genericAdapter);
  const auto& adapter = *genericAdapter;
  const MothershipNametagAllMastersRecord allMasters = allMastersRecord();
  {
    const auto& sites = allMasters.intent.sites;
    auto truth = allMastersReceipt(sites[0].clusterUUID, sites[0].truthDeploymentID,
        MeshRegistry::Truth::applicationID, 1, DeploymentIdentityStoreKind::truth);
    truth.version = 4;
    for (size_t i = 0; i < truth.statefulRuntimeCohort.size(); ++i) {
      truth.statefulRuntimeCohort[i].allMasters = false;
      truth.statefulRuntimeCohort[i].clientServing = i == 0;
    }
    const uint128_t writer = truth.statefulRuntimeCohort[0].containerUUID;
    Vector<DeploymentIdentityReport> app6;
    for (size_t i = 0; i < sites.size(); ++i) {
      auto& report = app6.emplace_back();
      report.version = 3; report.found = report.live = true;
      report.clusterUUID = sites[i].clusterUUID; report.deploymentID = sites[i].app6DeploymentID;
      report.applicationID = MeshRegistry::Nametag::applicationID;
      report.nTarget = report.nDeployed = report.nHealthy = 1;
      if (i != 0) {
        auto& receipt = report.app6TruthMeshReceipts.emplace_back();
        receipt.localClusterUUID = sites[i].clusterUUID; receipt.remoteClusterUUID = sites[0].clusterUUID;
        receipt.truthWriterContainerUUID = writer; receipt.sessionUUID = 0x1000 + i;
        receipt.commandGeneration = receipt.reconnectGeneration = 1;
        receipt.lastSuccessfulRequestWatermarkSHA256 = digest('a');
        receipt.reverseCarrierUUID = 0x2000 + i; receipt.healthy = true;
      }
    }
    assert(mothershipNametagApp6TruthMeshSetObserved(app6, sites, truth));
    auto wrongLocal = app6; ++wrongLocal[0].deploymentID;
    assert(!mothershipNametagApp6TruthMeshSetObserved(wrongLocal, sites, truth));
    auto unhealthyLocal = app6; unhealthyLocal[0].nHealthy = 0;
    assert(!mothershipNametagApp6TruthMeshSetObserved(unhealthyLocal, sites, truth));
    auto missingRemote = app6; missingRemote[1].app6TruthMeshReceipts.clear();
    // Exact identities admit native seeding before remote traffic exists,
    // but do not satisfy the post-seed completion gate.
    assert(mothershipNametagApp6IdentitySetObserved(missingRemote, sites));
    assert(!mothershipNametagApp6TruthMeshSetObserved(missingRemote, sites, truth));
    auto wrongRemote = missingRemote; ++wrongRemote[1].deploymentID;
    assert(!mothershipNametagApp6IdentitySetObserved(wrongRemote, sites));
    wrongRemote = missingRemote; ++wrongRemote[2].clusterUUID;
    assert(!mothershipNametagApp6IdentitySetObserved(wrongRemote, sites));
    wrongRemote = missingRemote; wrongRemote[1].applicationID = 3;
    assert(!mothershipNametagApp6IdentitySetObserved(wrongRemote, sites));
    wrongRemote = missingRemote; wrongRemote[1].live = false;
    assert(!mothershipNametagApp6IdentitySetObserved(wrongRemote, sites));
    auto privateReceipt = app6;
    privateReceipt[1].version = 6;
    auto& direct = privateReceipt[1].app6TruthMeshReceipts.front();
    direct.observationVersion = 2; direct.reverseCarrierUUID = 0;
    direct.localApplicationContainerUUID = 0x1234; direct.routeUUID = 0x5678; direct.routeGeneration = 1;
    assert(mothershipNametagApp6TruthMeshSetObserved(privateReceipt, sites, truth));
    {
      auto report = privateReceipt[1]; String bytes; DeploymentIdentityReport decoded = {};
      assert(BitseryEngine::serialize(bytes, report) && BitseryEngine::deserializeSafe(bytes, decoded));
      assert(decoded.version == 6 && decoded.app6TruthMeshReceipts.size() == 1 &&
             decoded.app6TruthMeshReceipts.front().routeUUID == direct.routeUUID &&
             decoded.app6TruthMeshReceipts.front().observationVersion == 2);
      auto legacy = app6[1]; bytes.clear(); decoded = {};
      assert(BitseryEngine::serialize(bytes, legacy) && BitseryEngine::deserializeSafe(bytes, decoded));
      assert(decoded.version == legacy.version && decoded.app6TruthMeshReceipts.size() == 1 &&
             decoded.app6TruthMeshReceipts.front().reverseCarrierUUID == legacy.app6TruthMeshReceipts.front().reverseCarrierUUID);
    }
    {
      ProdigyApp6TruthMeshReceipt receipt = {};
      receipt.protocolVersion = 2; receipt.localApplicationContainerUUID = 11; receipt.localClusterUUID = 12;
      receipt.remoteClusterUUID = 13; receipt.truthWriterContainerUUID = 14; receipt.sessionUUID = 15;
      receipt.commandGeneration = receipt.reconnectGeneration = 16; receipt.routeUUID = 17; receipt.routeGeneration = 18;
      receipt.lastSuccessfulRequestWatermarkSHA256 = digest('a'); receipt.live = true;
      ProdigyCousinSessionRecord session = {};
      session.protocolVersion = ProdigyCousinSessionPrivateContainerProtocolVersion;
      session.route.authorizedRoute.version = 3; session.route.authorizedRoute.endpointKind = CousinRouteEndpointKind::privateContainer;
      session.sessionUUID = 15; session.sourceContainerUUID = 11; session.sourcePermission.localClusterUUID = 12;
      session.destination.permission.localClusterUUID = 13; session.destination.containerUUID = 14;
      session.route.authorizedRoute.routeUUID = 17; session.route.authorizedRoute.generation = 18;
      assert(prodigyApp6PrivateTruthReceiptMatchesSession(receipt, session, 16));
      ++session.sessionUUID; assert(!prodigyApp6PrivateTruthReceiptMatchesSession(receipt, session, 16)); --session.sessionUUID;
      ++session.route.authorizedRoute.generation; assert(!prodigyApp6PrivateTruthReceiptMatchesSession(receipt, session, 16));
      --session.route.authorizedRoute.generation; assert(!prodigyApp6PrivateTruthReceiptMatchesSession(receipt, session, 17));
      for (uint32_t version : {1u, 2u}) {
        receipt.protocolVersion = version; receipt.reverseCarrierUUID = version == 1 ? 19 : 0;
        String bytes; ProdigyApp6TruthMeshReceipt decoded = {};
        assert(BitseryEngine::serialize(bytes, receipt) && BitseryEngine::deserializeSafe(bytes, decoded));
        assert(prodigyApp6TruthMeshReceiptValid(decoded) && decoded.protocolVersion == version &&
               decoded.sessionUUID == receipt.sessionUUID && decoded.reverseCarrierUUID == receipt.reverseCarrierUUID);
        if (version == 2) assert(decoded.routeUUID == receipt.routeUUID && decoded.routeGeneration == receipt.routeGeneration);
      }
    }
    direct.healthy = false;
    assert(mothershipNametagApp6IdentitySetObserved(privateReceipt, sites));
    assert(!mothershipNametagApp6TruthMeshSetObserved(privateReceipt, sites, truth));
    direct.healthy = true;
    direct.routeGeneration = 0;
    assert(!mothershipNametagApp6TruthMeshSetObserved(privateReceipt, sites, truth));
    direct.routeGeneration = 1; privateReceipt[1].version = 5;
    assert(!mothershipNametagApp6TruthMeshSetObserved(privateReceipt, sites, truth));
  }
  {
    const auto *pathAdapter = mothershipNametagQualificationAdapter("nametagChaosSitePartitionLocalWrites");
    assert(pathAdapter);
    MothershipNametagQualificationExecutionRecord path = {};
    path.protocolVersion = path.pathVersion; path.intent = qualificationIntent(*pathAdapter, allMasters);
    MothershipNametagQualificationExecutionRecord::PathFaultWitness witness = {};
    witness.request.action = ProdigyCrossClusterPathFaultGatewayAction::pause;
    auto& fault = witness.request.request;
    fault.protocolVersion = ProdigyCrossClusterPathFaultRequest::leaseVersion;
    fault.operationUUID = 0xabc; fault.authority = allMasters.intent.directGatewayAuthorities[0];
    auto& gateway = fault.authority;
    gateway.localDatacenterFragment = 1; gateway.peerDatacenterFragment = 2;
    gateway.localSitePrefix = prodigyContainerDatacenterSitePrefix(1);
    gateway.peerSitePrefix = prodigyContainerDatacenterSitePrefix(2);
    gateway.artifactSHA256 = gateway.localIdentitySHA256 = gateway.peerIdentitySHA256 = gateway.peerTrustSHA256 = digest('a');
    gateway.artifactBytes = 1; gateway.listenerPublicUDPEndpoint = IPAddress("2001:db8::1", true);
    gateway.listenerPublicUDPPort = 443; gateway.privateTunnelInterface = "mtbgp0"_ctv;
    gateway.privateTunnelLocalIPv6 = IPAddress("fd5a:4d53::1", true);
    gateway.privateTunnelPeerIPv6 = IPAddress("fd5a:4d53::2", true);
    gateway.privateLocalASN = 64512; gateway.privatePeerASN = 64513;
    gateway.privateLocalBGPID = 1; gateway.privatePeerBGPID = 2;
    gateway.privateSessionCredentialSHA256 = digest('b'); gateway.pairAuthorityGeneration = 7; gateway.keyGeneration = 1;
    assert(prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(gateway));
    fault.scope = prodigyCrossClusterPathFaultScope(fault.authority);
    prodigyCrossClusterPathFaultFlowIdentity(fault.scope, fault.flowIdentity);
    fault.expiresAtMilliseconds = uint64_t(path.intent.startedAtMilliseconds + 30000);
    path.pathFaults.push_back(witness);
    assert(mothershipNametagQualificationExecutionRecordValid(path));
    auto ordered = path;
    ordered.intent.row = MothershipNametagQualificationRow::ewrOrdPathLoss;
    using PathStage = ProdigyNametagQualificationPathStage;
    assert(mothershipNametagQualificationPathStageMayRecord(ordered, 0, PathStage::localWork));
    assert(!mothershipNametagQualificationPathStageMayRecord(ordered, 0, PathStage::partitionRead));
    for (uint32_t i = 0; i < 3; ++i) { ProdigyNametagQualificationApplicationReceipt r = {};
      r.pathStage = PathStage::localWork; ordered.pathWorkReceipts.push_back(r); }
    assert(mothershipNametagQualificationPathStageMayRecord(ordered, 0, PathStage::partitionRead));
    assert(!mothershipNametagQualificationPathStageMayRecord(ordered, 0, PathStage::final));
    for (uint32_t i = 0; i < 3; ++i) { ProdigyNametagQualificationApplicationReceipt r = {};
      r.pathStage = PathStage::partitionRead; ordered.pathWorkReceipts.push_back(r); }
    while (ordered.pathFaults.size() < 3) ordered.pathFaults.push_back(witness);
    for (auto& f : ordered.pathFaults) f.paused.response = true;
    assert(!mothershipNametagQualificationPathMayBeginRestore(ordered, 0));
    ordered.pathSurvivorsDuring.observedAtMilliseconds = 1;
    assert(mothershipNametagQualificationPathMayBeginRestore(ordered, 0));
    ordered.pathFaults[0].restored.response = true;
    assert(!mothershipNametagQualificationPathMayBeginRestore(ordered, 0));
    ordered.pathFaults[0].restored.response = false;
    ordered.pathRestoringBatches = 1;
    assert(!mothershipNametagQualificationPathStageMayRecord(ordered, 0, PathStage::localWork));
    assert(!mothershipNametagQualificationPathStageMayRecord(ordered, 0, PathStage::partitionRead));
    assert(mothershipNametagQualificationPathStageMayRecord(ordered, 0, PathStage::final));
    assert(!mothershipNametagQualificationPathStageMayRecord(ordered, 255, PathStage::final));
    auto complete = path;
    while (complete.pathFaults.size() < 6) complete.pathFaults.push_back(witness);
    for (auto& f : complete.pathFaults) { f.paused.response = true; f.restored.response = true; }
    for (uint32_t i = 0; i < 3; ++i) {
      ProdigyNametagQualificationApplicationReceipt work = {};
      work.pathStage = ProdigyNametagQualificationPathStage::localWork;
      complete.pathWorkReceipts.push_back(work);
      work.pathStage = ProdigyNametagQualificationPathStage::final;
      work.joinedWitnessDigest = digest('a'); complete.pathWorkReceipts.push_back(work);
    }
    assert(mothershipNametagQualificationPathExecutionComplete(complete));
    complete.pathWorkReceipts[1].joinedWitnessDigest = digest('b');
    assert(!mothershipNametagQualificationPathExecutionComplete(complete));
    complete.pathWorkReceipts[1].joinedWitnessDigest = digest('a');
    complete.pathFaults[5].restored.response = false;
    assert(!mothershipNametagQualificationPathExecutionComplete(complete));
    auto duplicate = witness; ++duplicate.request.request.operationUUID;
    path.pathFaults.push_back(duplicate);
    assert(!mothershipNametagQualificationExecutionRecordValid(path));
    path.pathFaults.pop_back();
    path.pathAborting = true;
    String bytes = {}; auto copy = path;
    assert(BitseryEngine::serialize(bytes, copy));
    MothershipNametagQualificationExecutionRecord decoded = {};
    assert(BitseryEngine::deserializeSafe(bytes, decoded) && decoded.pathAborting &&
           mothershipNametagQualificationExecutionRecordValid(decoded));
  }
  {
    const auto *writerAdapter = mothershipNametagQualificationAdapter("nametagChaosLocalWriterIsolation");
    assert(writerAdapter);
    auto intent = qualificationIntent(*writerAdapter, allMasters);
    for (uint32_t i = 0; i < intent.probeTargets.size(); ++i)
      intent.probeTargets[i].probeDeploymentID = (uint64_t(11) << 48) | (i + 1);
    MothershipNametagQualificationSiteRequest site = {};
    site.protocolVersion = MothershipNametagQualificationSiteRequest::writerStageVersion;
    site.intent = intent; site.targetClusterUUID = intent.probeTargets[0].clusterUUID;
    site.targetProbeDeploymentID = intent.probeTargets[0].probeDeploymentID;
    site.targetApp6DeploymentID = allMasters.intent.sites[0].app6DeploymentID;
    site.writerStage = ProdigyNametagQualificationWriterStage::survivorWrites;
    auto& w = site.writerIsolation; w.runUUID = intent.runUUID; w.challengeUUID = 0x42;
    w.clusterUUID = site.targetClusterUUID; w.executionGeneration = intent.executionGeneration;
    w.deploymentID = allMasters.intent.sites[0].hotDeploymentID; w.deadlineAtMilliseconds = intent.deadlineAtMilliseconds;
    w.stage = ProdigyNametagQualificationWriterIsolationStage::arm; w.applicationID = 3; w.validForMilliseconds = 5000;
    w.targetContainerUUID = 1; w.targetMachineUUID = 2; w.targetAddress = 3;
    w.survivorContainerUUIDs = {4, 5}; w.survivorAddresses = {6, 7};
    assert(mothershipNametagQualificationSiteRequestValid(site));
    ProdigyNametagQualificationApplicationCommand command = {};
    assert(mothershipNametagQualificationApplicationCommand(site, command));
    auto changed = site; changed.writerIsolation.survivorAddresses[1] = w.targetAddress;
    assert(!mothershipNametagQualificationSiteRequestValid(changed));
    changed = site; changed.writerIsolation.clusterUUID++;
    assert(!mothershipNametagQualificationSiteRequestValid(changed));
  }
  {
    const auto *recoveryAdapter = mothershipNametagQualificationAdapter("nametagChaosPermissionRevokeReinstall");
    assert(recoveryAdapter != nullptr);
    auto intent = qualificationIntent(*recoveryAdapter, allMasters);
    for (size_t site = 0; site < intent.probeTargets.size(); ++site)
      intent.probeTargets[site].probeDeploymentID = (uint64_t(11) << 48) | (site + 1);
    intent.protocolVersion = MothershipNametagQualificationIntent::cousinRecoveryVersion;
    MothershipNametagQualificationCousinRecovery recovery = {};
    recovery.routeUUID = 0x111; recovery.withdrawOperationUUID = 0x112;
    recovery.successorRouteUUID = 0x113; recovery.successorRouteOperationUUID = 0x114;
    recovery.successorPermissionUUID = 0x115;
    intent.cousinRecoveries.push_back(recovery);
    assert(mothershipNametagQualificationIntentValid(intent));
    auto binding = cousinBinding();
    assert(mothershipNametagQualificationCousinRecoveryBindingValid(intent, 0, binding));
    // Row ten retains the commissioned permission; owner readback carries an
    // acceptance generation, while an exact controller request must not.
    auto rowTenRequest = binding.sourcePermission;
    assert(!prodigyLocalCousinServicePermissionRequestAccepted(rowTenRequest, binding.sourcePermission));
    rowTenRequest.acceptedAuthorityGeneration = 0;
    assert(prodigyLocalCousinServicePermissionRequestAccepted(rowTenRequest, binding.sourcePermission));
    ++rowTenRequest.peerClusterUUID;
    assert(!prodigyLocalCousinServicePermissionRequestAccepted(rowTenRequest, binding.sourcePermission));
    MothershipNametagQualificationSiteRequest stageRequest = {};
    stageRequest.protocolVersion = MothershipNametagQualificationSiteRequest::cousinStageVersion;
    stageRequest.intent = intent; stageRequest.targetClusterUUID = intent.probeTargets[0].clusterUUID;
    stageRequest.targetProbeDeploymentID = intent.probeTargets[0].probeDeploymentID;
    stageRequest.targetApp6DeploymentID = allMasters.intent.sites[0].app6DeploymentID;
    stageRequest.cousinStage = ProdigyNametagQualificationCousinStage::faultObserved;
    ProdigyNametagQualificationCousinSession expected = {};
    expected.pairUUID = binding.route.pairUUID; expected.routeUUID = binding.route.routeUUID;
    expected.sourcePermissionUUID = binding.route.sourcePermissionUUID; expected.destinationPermissionUUID = binding.route.destinationPermissionUUID;
    expected.sourceClusterUUID = binding.route.sourceClusterUUID; expected.destinationClusterUUID = binding.route.destinationClusterUUID;
    expected.sourceDeploymentID = binding.sourcePermission.localDeploymentID; expected.destinationDeploymentID = binding.destinationPermission.localDeploymentID;
    expected.routeGeneration = binding.route.generation; expected.sourcePermissionAuthorityGeneration = binding.sourcePermission.acceptedAuthorityGeneration;
    expected.successorRouteUUID = recovery.successorRouteUUID; expected.successorSourcePermissionUUID = recovery.successorPermissionUUID;
    expected.successorRouteGeneration = 1;
    ProdigyNametagQualificationApplicationCommand stageCommand = {};
    assert(mothershipNametagQualificationSiteRequestValid(stageRequest) &&
           mothershipNametagQualificationApplicationCommand(stageRequest, stageCommand));
    auto badStage = stageRequest; badStage.cousinSessions.push_back(expected);
    assert(!mothershipNametagQualificationApplicationCommand(badStage, stageCommand));
    assert(mothershipNametagQualificationApplicationCommand(stageRequest, stageCommand));
    ProdigyNametagQualificationApplicationReceipt stageReceipt = {};
    stageReceipt.protocolVersion = ProdigyNametagQualificationApplicationReceipt::cousinStageVersion;
    stageReceipt.runUUID = stageCommand.runUUID; stageReceipt.row = stageCommand.row; stageReceipt.direction = stageCommand.direction;
    stageReceipt.executionGeneration = stageCommand.executionGeneration; stageReceipt.rowID = stageCommand.rowID;
    stageReceipt.descriptor = stageCommand.descriptor; stageReceipt.localClusterUUID = stageCommand.localClusterUUID;
    stageReceipt.deploymentID = stageCommand.deploymentID; stageReceipt.localContainerUUID = 0x777;
    stageReceipt.startedAtMilliseconds = stageCommand.startedAtMilliseconds; stageReceipt.deadlineAtMilliseconds = stageCommand.deadlineAtMilliseconds;
    stageReceipt.convergenceDeadlineAtMilliseconds = stageCommand.convergenceDeadlineAtMilliseconds;
    stageReceipt.observedAtMilliseconds = stageCommand.startedAtMilliseconds;
    stageReceipt.witnessedResult = stageCommand.descriptor.expectedWitness;
    stageReceipt.canonicalWitnessReceipt.assign("local-work"_ctv); stageReceipt.witnessDigest = digest('a');
    stageReceipt.joinedWitnessDigest = digest('b');
    stageReceipt.cousinStage = stageCommand.cousinStage; stageReceipt.cousinSessions = stageCommand.cousinSessions;
    expected.sourceContainerUUID = 0x701; expected.destinationContainerUUID = 0x702;
    expected.sessionUUID = 0x703; expected.sessionGeneration = 1;
    assert(prodigyNametagQualificationCousinReceiptMatchesCommand(stageCommand, stageReceipt));
    ProdigyNametagQualificationCousinTransport transport = {};
    transport.runUUID = intent.runUUID; transport.memberRequestUUID = 0x704; transport.executionGeneration = intent.executionGeneration;
    transport.deadlineAtMilliseconds = intent.deadlineAtMilliseconds;
    transport.stage = ProdigyNametagQualificationCousinStage::arm;
    transport.session = expected;
    auto observed = transport; observed.response = observed.ready = true; observed.session.healthy = true;
    assert(prodigyNametagQualificationCousinTransportResponseMatches(transport, observed));
    auto wrongTransport = observed; ++wrongTransport.session.routeUUID;
    assert(!prodigyNametagQualificationCousinTransportResponseMatches(transport, wrongTransport));
    wrongTransport = observed; ++wrongTransport.memberRequestUUID;
    assert(!prodigyNametagQualificationCousinTransportResponseMatches(transport, wrongTransport));
    transport.stage = ProdigyNametagQualificationCousinStage::faultObserved;
    observed = transport; observed.response = observed.ready = true;
    observed.session.transportClosedOrUnsendable = true;
    assert(prodigyNametagQualificationCousinTransportResponseMatches(transport, observed));
    observed.session.transportClosedOrUnsendable = false;
    assert(!prodigyNametagQualificationCousinTransportResponseMatches(transport, observed));
    MothershipNametagQualificationExecutionRecord native = {};
    native.protocolVersion = MothershipNametagQualificationExecutionRecord::cousinTransportVersion;
    native.intent = intent; native.cousinRecoveryBindings.push_back(binding);
    MothershipNametagQualificationExecutionRecord::CousinNativeWitness nativeWitness = {};
    transport.stage = ProdigyNametagQualificationCousinStage::arm;
    nativeWitness.challenge = transport; native.cousinNativeWitnesses.push_back(nativeWitness);
    assert(mothershipNametagQualificationExecutionRecordValid(native));
    native.phase = MothershipNametagQualificationExecutionPhase::faultApplied;
    assert(!mothershipNametagQualificationExecutionRecordValid(native));
    native.cousinNativeWitnesses[0].arm = transport;
    native.cousinNativeWitnesses[0].arm.response = native.cousinNativeWitnesses[0].arm.ready = true;
    native.cousinNativeWitnesses[0].arm.session.healthy = true;
    assert(mothershipNametagQualificationExecutionRecordValid(native));
    native.cousinNativeWitnesses[0].fault = transport;
    native.cousinNativeWitnesses[0].fault.stage = ProdigyNametagQualificationCousinStage::faultObserved;
    native.cousinNativeWitnesses[0].fault.response = native.cousinNativeWitnesses[0].fault.ready = true;
    native.cousinNativeWitnesses[0].fault.session.transportClosedOrUnsendable = true;
    native.phase = MothershipNametagQualificationExecutionPhase::workloadIssued;
    assert(!mothershipNametagQualificationExecutionRecordValid(native));
    native.cousinLocalWorkReceipt = stageReceipt;
    assert(mothershipNametagQualificationExecutionRecordValid(native));
    native.phase = MothershipNametagQualificationExecutionPhase::converging;
    assert(!mothershipNametagQualificationExecutionRecordValid(native));
    native.cousinNativeWitnesses[0].final = transport;
    auto& final = native.cousinNativeWitnesses[0].final;
    final.stage = ProdigyNametagQualificationCousinStage::final; final.response = final.ready = true;
    final.session.transportClosedOrUnsendable = final.session.healthy = true;
    final.session.successorSessionUUID = 0x705; final.session.successorSessionGeneration = 1;
    final.session.successorPermissionAuthorityGeneration = binding.sourcePermission.acceptedAuthorityGeneration + 1;
    assert(mothershipNametagQualificationExecutionRecordValid(native));
    final.session.successorSessionUUID = final.session.sessionUUID;
    assert(!mothershipNametagQualificationExecutionRecordValid(native));
    final.session.successorSessionUUID = 0x705;
    Vector<ProdigyNametagQualificationApplicationReceipt> injectionApps = {};
    for (size_t site = 0; site < intent.probeTargets.size(); ++site) {
      auto item = stageReceipt; item.cousinStage = ProdigyNametagQualificationCousinStage::final;
      item.localClusterUUID = intent.probeTargets[site].clusterUUID;
      item.deploymentID = intent.probeTargets[site].probeDeploymentID; item.localContainerUUID += site;
      injectionApps.push_back(item);
    }
    String topology = {}; topology.assign("native-topology"_ctv); String receiptFailure = {};
    MothershipNametagQualificationReceipt injectionReceipt = {};
    assert(mothershipNametagQualificationBuildReceipt(intent, injectionApps, topology,
        intent.convergenceDeadlineAtMilliseconds, injectionReceipt, &receiptFailure, &native));
    native.phase = MothershipNametagQualificationExecutionPhase::verified;
    if (intent.row == MothershipNametagQualificationRow::permissionRevokeReinstall) {
      uint128_t successor = 0;
      assert(mothershipNametagQualificationPermissionSuccessor(native, intent.cousinRecoveries[0].routeUUID, successor));
      assert(successor == intent.cousinRecoveries[0].successorRouteUUID);
      assert(!mothershipNametagQualificationPermissionSuccessor(native, 0, successor));
      assert(!mothershipNametagQualificationPermissionSuccessor(native, 0xffff, successor));
      auto incomplete = native; incomplete.phase = MothershipNametagQualificationExecutionPhase::converging;
      assert(!mothershipNametagQualificationPermissionSuccessor(incomplete, intent.cousinRecoveries[0].routeUUID, successor));
      auto corrupt = native; corrupt.cousinRecoveryBindings[0].sourceReceipt.generation++;
      assert(!mothershipNametagQualificationPermissionSuccessor(corrupt, intent.cousinRecoveries[0].routeUUID, successor));
    }
    const auto *observationAdapter = mothershipNametagQualificationAdapterForTuple(intent.row,
        MothershipNametagQualificationDirection::observation, intent.rowID, intent.deadlineSeconds, intent.convergenceSeconds);
    assert(observationAdapter);
    auto observation = qualificationIntent(*observationAdapter, allMasters);
    observation.probeTargets = intent.probeTargets;
    assert(mothershipNametagQualificationExecutionPhaseTransitionValid(
        MothershipNametagQualificationExecutionPhase::prepared,
        MothershipNametagQualificationExecutionPhase::workloadIssued, observation));
    assert(mothershipNametagQualificationExecutionPhaseTransitionValid(
        MothershipNametagQualificationExecutionPhase::workloadIssued,
        MothershipNametagQualificationExecutionPhase::converging, observation));
    observation.startedAtMilliseconds = intent.convergenceDeadlineAtMilliseconds;
    observation.deadlineAtMilliseconds = observation.startedAtMilliseconds + int64_t(observation.deadlineSeconds) * 1000;
    observation.convergenceDeadlineAtMilliseconds = observation.startedAtMilliseconds + int64_t(observation.convergenceSeconds) * 1000;
    assert(mothershipNametagQualificationReceiptDigest(injectionReceipt, observation.priorInjectionReceiptDigest));
    Vector<ProdigyNametagQualificationApplicationReceipt> observationApps = injectionApps;
    for (auto& item : observationApps) {
      item.direction = uint8_t(observation.direction); item.startedAtMilliseconds = observation.startedAtMilliseconds;
      item.deadlineAtMilliseconds = observation.deadlineAtMilliseconds;
      item.convergenceDeadlineAtMilliseconds = observation.convergenceDeadlineAtMilliseconds;
      item.observedAtMilliseconds = observation.startedAtMilliseconds;
    }
    MothershipNametagQualificationReceipt observationReceipt = {};
    assert(mothershipNametagQualificationBuildReceipt(observation, observationApps, topology,
        observation.startedAtMilliseconds, observationReceipt, &receiptFailure, nullptr, &injectionReceipt, &native));
    auto differentNative = native; ++differentNative.cousinNativeWitnesses[0].final.session.successorSessionGeneration;
    assert(!mothershipNametagQualificationBuildReceipt(observation, observationApps, topology,
        observation.startedAtMilliseconds, observationReceipt, &receiptFailure, nullptr, &injectionReceipt, &differentNative));
    auto missingPrior = observation; missingPrior.priorInjectionRunUUID = 0;
    assert(!mothershipNametagQualificationIntentValid(missingPrior));
    auto wrongJoin = observationApps; wrongJoin[1].joinedWitnessDigest = digest('c');
    assert(!mothershipNametagQualificationBuildReceipt(observation, wrongJoin, topology,
        observation.startedAtMilliseconds, observationReceipt, &receiptFailure, nullptr, &injectionReceipt, &native));
    auto badReceipt = stageReceipt; badReceipt.cousinStage = ProdigyNametagQualificationCousinStage::final;
    assert(!prodigyNametagQualificationCousinReceiptMatchesCommand(stageCommand, badReceipt));
    auto wrong = binding; wrong.destinationReceipt.generation++;
    assert(!mothershipNametagQualificationCousinRecoveryBindingValid(intent, 0, wrong));
    wrong = binding; wrong.sourcePermission.peerClusterUUID = 0x102;
    assert(!mothershipNametagQualificationCousinRecoveryBindingValid(intent, 0, wrong));
    wrong = binding; wrong.route.sourcePermissionUUID = 0x603;
    assert(!mothershipNametagQualificationCousinRecoveryBindingValid(intent, 0, wrong));
    MothershipNametagQualificationExecutionRecord bound = {};
    bound.protocolVersion = MothershipNametagQualificationExecutionRecord::cousinRecoveryVersion;
    bound.intent = intent; bound.cousinRecoveryBindings.push_back(binding); bound.cousinRecoveryAborting = true;
    String boundBytes = {}; MothershipNametagQualificationExecutionRecord boundCopy = {};
    assert(mothershipNametagQualificationExecutionRecordValid(bound) && BitseryEngine::serialize(boundBytes, bound) &&
           BitseryEngine::deserializeSafe(boundBytes, boundCopy) && boundCopy.cousinRecoveryAborting &&
           mothershipNametagQualificationExecutionRecordValid(boundCopy));
    MothershipNametagQualificationExecutionRecord unbound = {};
    unbound.intent = intent;
    assert(mothershipNametagQualificationExecutionRecordValid(unbound));
    unbound.phase = MothershipNametagQualificationExecutionPhase::faultApplied;
    assert(!mothershipNametagQualificationExecutionRecordValid(unbound));
    assert(!mothershipNametagQualificationExecutionPhaseTransitionValid(
        MothershipNametagQualificationExecutionPhase::prepared,
        MothershipNametagQualificationExecutionPhase::failed, intent));
    assert(!mothershipNametagQualificationExecutionPhaseTransitionValid(
        MothershipNametagQualificationExecutionPhase::faultApplied,
        MothershipNametagQualificationExecutionPhase::failed, intent));
    assert(!mothershipNametagQualificationExecutionPhaseTransitionValid(
        MothershipNametagQualificationExecutionPhase::workloadIssued,
        MothershipNametagQualificationExecutionPhase::failed, intent));
    assert(mothershipNametagQualificationExecutionPhaseTransitionValid(
        MothershipNametagQualificationExecutionPhase::faultRestored,
        MothershipNametagQualificationExecutionPhase::failed, intent));
    String bytes = {}; MothershipNametagQualificationIntent decoded = {};
    assert(BitseryEngine::serialize(bytes, intent) && BitseryEngine::deserializeSafe(bytes, decoded) &&
           mothershipNametagQualificationIntentValid(decoded) &&
           decoded.cousinRecoveries[0].successorPermissionUUID == recovery.successorPermissionUUID);
    decoded.cousinRecoveries[0].successorRouteUUID = recovery.routeUUID;
    assert(!mothershipNametagQualificationIntentValid(decoded));
    decoded = intent; decoded.cousinRecoveries[0].successorPermissionUUID = 0;
    assert(!mothershipNametagQualificationIntentValid(decoded));
    decoded = intent; decoded.protocolVersion = MothershipNametagQualificationIntent::version;
    assert(!mothershipNametagQualificationIntentValid(decoded));
    decoded = intent; decoded.cousinRecoveries.push_back(recovery);
    assert(!mothershipNametagQualificationIntentValid(decoded));
    const auto *routeAdapter = mothershipNametagQualificationAdapter("nametagChaosCousinRouteSessionReconnect");
    assert(routeAdapter != nullptr);
    decoded = qualificationIntent(*routeAdapter, allMasters);
    decoded.protocolVersion = MothershipNametagQualificationIntent::cousinRecoveryVersion;
    recovery.successorPermissionUUID = 0; decoded.cousinRecoveries.push_back(recovery);
    assert(mothershipNametagQualificationIntentValid(decoded));
    decoded.cousinRecoveries[0].successorPermissionUUID = 0x115;
    assert(!mothershipNametagQualificationIntentValid(decoded));
  }
  {
    const auto *restartAdapter = mothershipNametagQualificationAdapter("nametagChaosMothershipRestartResume");
    assert(restartAdapter);
    auto restart = qualificationIntent(*restartAdapter, allMasters);
    for (size_t i = 0; i < restart.probeTargets.size(); ++i)
      restart.probeTargets[i].probeDeploymentID = (uint64_t(11) << 48) | (i + 1);
    MothershipNametagQualificationSiteRequest request = {};
    request.protocolVersion = MothershipNametagQualificationSiteRequest::restartStageVersion;
    request.intent = restart; request.targetClusterUUID = restart.probeTargets[0].clusterUUID;
    request.targetProbeDeploymentID = restart.probeTargets[0].probeDeploymentID;
    request.targetApp6DeploymentID = (uint64_t(6) << 48) | 1;
    request.restartStage = ProdigyNametagQualificationRestartStage::beforeRestart;
    ProdigyNametagQualificationApplicationCommand command = {};
    assert(mothershipNametagQualificationSiteRequestValid(request) &&
           mothershipNametagQualificationApplicationCommand(request, command) &&
           command.protocolVersion == ProdigyNametagQualificationApplicationCommand::restartStageVersion &&
           command.restartStage == request.restartStage);
    auto wrong = request; wrong.restartStage = ProdigyNametagQualificationRestartStage::none;
    assert(!mothershipNametagQualificationSiteRequestValid(wrong));
    request.restartStage = ProdigyNametagQualificationRestartStage::afterRestart;
    assert(mothershipNametagQualificationApplicationCommand(request, command));
    request.restartStage = ProdigyNametagQualificationRestartStage::beforeRestart;
    assert(mothershipNametagQualificationApplicationCommand(request, command));
    ProdigyNametagQualificationApplicationReceipt local = {};
    local.protocolVersion = ProdigyNametagQualificationApplicationReceipt::restartStageVersion;
    local.runUUID = command.runUUID; local.row = command.row; local.direction = command.direction;
    local.executionGeneration = command.executionGeneration; local.rowID = command.rowID; local.descriptor = command.descriptor;
    local.localClusterUUID = command.localClusterUUID; local.deploymentID = command.deploymentID; local.localContainerUUID = 0x777;
    local.startedAtMilliseconds = command.startedAtMilliseconds; local.deadlineAtMilliseconds = command.deadlineAtMilliseconds;
    local.convergenceDeadlineAtMilliseconds = command.convergenceDeadlineAtMilliseconds; local.observedAtMilliseconds = command.startedAtMilliseconds;
    local.witnessedResult = command.descriptor.expectedWitness; local.restartStage = command.restartStage;
    local.canonicalWitnessReceipt.assign("before-restart"_ctv); local.witnessDigest = digest('a'); local.joinedWitnessDigest = digest('b');
    assert(prodigyNametagQualificationRestartReceiptMatchesCommand(command, local));
    auto wrongStage = local; wrongStage.restartStage = ProdigyNametagQualificationRestartStage::afterRestart;
    assert(!prodigyNametagQualificationRestartReceiptMatchesCommand(command, wrongStage));
    const auto *observe = mothershipNametagQualificationAdapterForTuple(restart.row,
        MothershipNametagQualificationDirection::observation, restart.rowID, restart.deadlineSeconds, restart.convergenceSeconds);
    assert(observe);
    auto observeIntent = qualificationIntent(*observe, allMasters); observeIntent.probeTargets = restart.probeTargets;
    auto observeRequest = request; observeRequest.intent = observeIntent;
    assert(!mothershipNametagQualificationSiteRequestValid(observeRequest));
    observeRequest.restartStage = ProdigyNametagQualificationRestartStage::afterRestart;
    assert(mothershipNametagQualificationApplicationCommand(observeRequest, command) &&
        command.priorInjectionRunUUID == restart.runUUID && command.priorInjectionReceiptDigest == digest('8'));
    MothershipNametagQualificationExecutionRecord proof = {};
    proof.protocolVersion = MothershipNametagQualificationExecutionRecord::restartVersion; proof.intent = restart;
    proof.restartNonce = 0x101; proof.restartLocalWorkReceipt = local;
    proof.restartBefore.pid = 123; proof.restartBefore.startTime = 456;
    proof.restartBefore.bootID.assign("boot"_ctv); proof.restartBefore.executableSHA256 = digest('c');
    assert(mothershipNametagQualificationExecutionRecordValid(proof));
    proof.restartAfter = proof.restartBefore;
    assert(!mothershipNametagQualificationExecutionRecordValid(proof));
    ++proof.restartAfter.startTime;
    assert(mothershipNametagQualificationExecutionRecordValid(proof));
    String proofBytes = {}; MothershipNametagQualificationExecutionRecord roundTrip = {};
    assert(BitseryEngine::serialize(proofBytes, proof) && BitseryEngine::deserializeSafe(proofBytes, roundTrip) &&
        mothershipNametagQualificationExecutionRecordValid(roundTrip) && roundTrip.restartNonce == proof.restartNonce &&
        roundTrip.restartBefore.pid == proof.restartBefore.pid && roundTrip.restartAfter.startTime == proof.restartAfter.startTime &&
        roundTrip.restartLocalWorkReceipt.joinedWitnessDigest == proof.restartLocalWorkReceipt.joinedWitnessDigest &&
        roundTrip.cousinNativeWitnesses.empty() && roundTrip.cousinRecoveryBindings.empty());
    proof.restartAfter.executableSHA256 = digest('d');
    assert(!mothershipNametagQualificationExecutionRecordValid(proof));
    proof.restartAfter.executableSHA256 = digest('c');
    proof.phase = MothershipNametagQualificationExecutionPhase::converging;
    Vector<ProdigyNametagQualificationApplicationReceipt> after = {};
    for (size_t i = 0; i < restart.probeTargets.size(); ++i) {
      auto item = local; item.restartStage = ProdigyNametagQualificationRestartStage::afterRestart;
      item.localClusterUUID = restart.probeTargets[i].clusterUUID;
      item.deploymentID = restart.probeTargets[i].probeDeploymentID; item.localContainerUUID += i;
      after.push_back(item);
    }
    String topology = {}; topology.assign("restart-topology"_ctv); String failure = {};
    MothershipNametagQualificationReceipt result = {};
    assert(mothershipNametagQualificationBuildReceipt(restart, after, topology,
        restart.startedAtMilliseconds, result, &failure, &proof));
    auto badAfter = after; badAfter[2].joinedWitnessDigest = digest('e');
    assert(!mothershipNametagQualificationBuildReceipt(restart, badAfter, topology,
        restart.startedAtMilliseconds, result, &failure, &proof));
    auto noAfterProcess = proof; noAfterProcess.restartAfter = {};
    assert(!mothershipNametagQualificationBuildReceipt(restart, after, topology,
        restart.startedAtMilliseconds, result, &failure, &noAfterProcess));
  }
  auto wrongGatewaySlot = allMasters.intent;
  wrongGatewaySlot.directGatewayAuthorities[0].gatewaySlot = 1;
  assert(!mothershipNametagAllMastersDirectGatewayTopologyValid(wrongGatewaySlot));
  auto splitPairAcrossSites = allMasters.intent;
  for (uint32_t direction = 0; direction < 2; ++direction) {
    std::swap(splitPairAcrossSites.directGatewayAuthorities[direction].pairUUID,
              splitPairAcrossSites.directGatewayAuthorities[6 + direction].pairUUID);
    std::swap(splitPairAcrossSites.directGatewayAuthorities[direction].pairOperationUUID,
              splitPairAcrossSites.directGatewayAuthorities[6 + direction].pairOperationUUID);
  }
  assert(!mothershipNametagAllMastersDirectGatewayTopologyValid(splitPairAcrossSites));
  const std::string allMastersJSON = allMastersPreparationJSON(allMasters);
  assert(parsesAllMastersPreparation(allMastersJSON));
  auto sourceCutJSON = allMastersJSON;
  sourceCutJSON.replace(sourceCutJSON.find("prepare.v2"), std::strlen("prepare.v2"), "prepare.v3");
  sourceCutJSON.insert(sourceCutJSON.find("\"operationUUID\":"), "\"sourceBaselineOperationUUID\":\"0xa112\",");
  assert(parsesAllMastersPreparation(sourceCutJSON));
  auto recoveryJSON = sourceCutJSON;
  recoveryJSON.replace(recoveryJSON.find("prepare.v3"), std::strlen("prepare.v3"), "prepare.v5");
  recoveryJSON.insert(recoveryJSON.size() - 1,
      ",\"seedRoutes\":[],\"predecessorOperationUUID\":\"0xa111\",\"predecessorRecordSHA256\":\"" + std::string(64, 'a') +
      "\",\"sourceRepairPlans\":[{\"applicationID\":3,\"plan\":\"@/task/hot.json\",\"artifact\":\"/task/hot.blob\"},"
      "{\"applicationID\":4,\"plan\":\"@/task/cold.json\",\"artifact\":\"/task/cold.blob\"}]");
  assert(parsesAllMastersPreparation(recoveryJSON));
  auto radarRecoveryJSON = recoveryJSON;
  radarRecoveryJSON.replace(radarRecoveryJSON.find("prepare.v5"), std::strlen("prepare.v5"), "prepare.v6");
  const std::string hotRepair = "{\"applicationID\":3,\"plan\":\"@/task/hot.json\",\"artifact\":\"/task/hot.blob\"},";
  const std::string coldRepair = "{\"applicationID\":4,\"plan\":\"@/task/cold.json\",\"artifact\":\"/task/cold.blob\"}";
  const size_t repairStart = radarRecoveryJSON.find(hotRepair);
  assert(repairStart != std::string::npos);
  radarRecoveryJSON.replace(repairStart, hotRepair.size() + coldRepair.size(),
      "{\"applicationID\":5,\"plan\":\"@/task/radar.json\",\"artifact\":\"/task/radar.blob\"}");
  assert(parsesAllMastersPreparation(radarRecoveryJSON));
  auto radarRepairExtra = radarRecoveryJSON;
  radarRepairExtra.replace(radarRepairExtra.find("\"artifact\":\"/task/radar.blob\"}"),
      std::strlen("\"artifact\":\"/task/radar.blob\"}"),
      "\"artifact\":\"/task/radar.blob\"},{\"applicationID\":3,\"plan\":\"@/task/hot.json\",\"artifact\":\"/task/hot.blob\"}");
  assert(!parsesAllMastersPreparation(radarRepairExtra));
  auto duplicateRepair = recoveryJSON;
  duplicateRepair.replace(duplicateRepair.find("\"applicationID\":4"), std::strlen("\"applicationID\":4"), "\"applicationID\":3");
  assert(!parsesAllMastersPreparation(duplicateRepair));
  auto legacyWithRecovery = recoveryJSON;
  legacyWithRecovery.replace(legacyWithRecovery.find("prepare.v5"), std::strlen("prepare.v5"), "prepare.v4");
  assert(!parsesAllMastersPreparation(legacyWithRecovery));
  auto missingBaseline = allMastersJSON;
  missingBaseline.replace(missingBaseline.find("prepare.v2"), std::strlen("prepare.v2"), "prepare.v3");
  assert(!parsesAllMastersPreparation(missingBaseline));
  {
    simdjson::dom::parser parser; simdjson::dom::element document;
    MothershipNametagAllMastersPreparation prepared; String parseFailure;
    assert(parser.parse(allMastersJSON.data(), allMastersJSON.size()).get(document) == simdjson::SUCCESS);
    assert(mothershipParseNametagAllMastersPreparationJSON(document, prepared, parseFailure));
    assert(parseFailure.empty() && prepared.intent.operationUUID == allMasters.intent.operationUUID &&
        prepared.intent.sites.size() == 3 && prepared.siteNames.size() == 3 && prepared.pairOperationUUIDs.size() == 3 &&
        prepared.intent.directGatewayAuthorities.empty());
    assert(prepared.siteNames[0].equal("task-ewr"_ctv) && prepared.siteNames[1].equal("task-ord"_ctv) &&
        prepared.siteNames[2].equal("retained-lan"_ctv));
    assert(prepared.intent.sites[0].truthDeploymentID == allMasters.intent.sites[0].truthDeploymentID &&
        prepared.intent.sites[1].truthDeploymentID == 0 && prepared.intent.sites[2].truthDeploymentID == 0);
    const std::string invalid = "{}";
    assert(parser.parse(invalid.data(), invalid.size()).get(document) == simdjson::SUCCESS);
    assert(prepared.siteNames[0].equal("task-ewr"_ctv) && prepared.siteNames[2].equal("retained-lan"_ctv));
    assert(!mothershipParseNametagAllMastersPreparationJSON(document, prepared, parseFailure));
    assert(!parseFailure.empty() && prepared.intent.operationUUID == 0 &&
        prepared.intent.sites.empty() && prepared.siteNames.empty() && prepared.pairOperationUUIDs.empty());
  }
  const auto rejectsPreparation = [&](const char *from, const char *to) {
    auto malformed = allMastersJSON;
    const size_t offset = malformed.find(from);
    assert(offset != std::string::npos);
    malformed.replace(offset, std::strlen(from), to);
    assert(!parsesAllMastersPreparation(malformed));
  };
  rejectsPreparation("mothership.nametag-all-masters.prepare.v2", "unknown");
  rejectsPreparation("\"operationUUID\":", "\"unknown\":");
  rejectsPreparation("\"operationUUID\":\"0x", "\"operationUUID\":\"bad");
  rejectsPreparation("\"pulseDeploymentID\":100,", "");
  rejectsPreparation("\"pulseDeploymentID\":100", "\"pulseDeploymentID\":100,\"pulseDeploymentID\":100");
  rejectsPreparation("\"pulseDeploymentID\":100", "\"pulseDeploymentID\":-1");
  rejectsPreparation("\"pulseDeploymentID\":100", "\"pulseDeploymentID\":1.5");
  rejectsPreparation("\"pulseDeploymentID\":100", "\"pulseDeploymentID\":true");
  rejectsPreparation("\"clusterName\":\"task-ewr\"", "\"clusterName\":\"\"");
  rejectsPreparation("\"clusterName\":\"task-ewr\"", "\"clusterUUID\":\"0x100\"");
  rejectsPreparation("\"pairOperationUUIDs\":", "\"gatewayAuthorities\":");
  rejectsPreparation("\"0xd001\"", "\"bad\"");
  rejectsPreparation("\"0xd001\"", "\"0x0\"");
  rejectsPreparation("\"0xd001\"", "\"0xd004\",\"0xd004\"");
  rejectsPreparation("\"truthDeploymentID\":0", "\"truthDeploymentID\":1");
  rejectsPreparation("\"operationUUID\":", "\"operationUUID\":\"0xa110\",\"operationUUID\":");
  simdjson::dom::parser mappingParser; simdjson::dom::element mappingDocument;
  MothershipNametagAllMastersPreparation preparedForMapping = {}; String mappingFailure = {};
  assert(mappingParser.parse(allMastersJSON.data(), allMastersJSON.size()).get(mappingDocument) == simdjson::SUCCESS);
  assert(mothershipParseNametagAllMastersPreparationJSON(mappingDocument, preparedForMapping, mappingFailure));
  for (uint32_t site = 0; site < 3; ++site) {
    MothershipProdigyCluster resolved = {};
    resolved.name.assign(preparedForMapping.siteNames[site]);
    resolved.clusterUUID = allMasters.intent.sites[site].clusterUUID;
    resolved.nBrains = 3;
    if (site < 2) {
      resolved.deploymentMode = MothershipClusterDeploymentMode::remote;
      resolved.provider = MothershipClusterProvider::vultr;
      if (site == 0) resolved.providerScope.assign("ewr"_ctv);
      else resolved.providerScope.assign("ord"_ctv);
    } else {
      resolved.deploymentMode = MothershipClusterDeploymentMode::local;
    }
    for (uint32_t machine = 0; machine < 3; ++machine) {
      auto& member = resolved.topology.machines.emplace_back();
      member.uuid = 0xe000 + site * 10 + machine; member.isBrain = true;
    }
    assert(mothershipNametagAllMastersPreparedSiteMatches(site, preparedForMapping.siteNames[site], resolved));
    resolved.topology.machines.pop_back();
    assert(!mothershipNametagAllMastersPreparedSiteMatches(site, preparedForMapping.siteNames[site], resolved));
  }
  const MothershipNametagQualificationIntent intent = qualificationIntent(adapter, allMasters);
  const MothershipNametagQualificationReceipt receipt = qualificationReceipt(intent);
  MothershipNametagQualificationIntent recordedIntent = {};
  MothershipNametagQualificationReceipt recordedReceipt = {};
  MothershipNametagAllMastersRecord recordedAllMasters = {};
  String failure = {}; bool resumed = false;

  // A v4 qualification cannot create or guess its global topology.
  assert(!registry->persistNametagQualificationIntent(adapter, intent, recordedIntent, resumed, &failure));
  assert(!registry->recordNametagQualificationReceipt(adapter, receipt, recordedReceipt, resumed, &failure));

  assert(registry->persistNametagAllMasters(allMasters, recordedAllMasters, resumed, &failure) && !resumed);
  assert(registry->loadNametagAllMasters(allMasters.intent.operationUUID, recordedAllMasters, &failure));
  assert(registry->persistNametagAllMasters(allMasters, recordedAllMasters, resumed, &failure) && resumed);
  {
    const auto *replay = mothershipNametagQualificationAdapter("nametagChaosGraphKvReplayReorder");
    assert(replay);
    MothershipNametagQualificationSiteRequest site = {};
    site.protocolVersion = site.replayStageVersion;
    site.intent = qualificationIntent(*replay, allMasters);
    for (size_t i = 0; i < site.intent.probeTargets.size(); ++i)
      site.intent.probeTargets[i].probeDeploymentID = (uint64_t(11) << 48) | (i + 1);
    site.targetClusterUUID = site.intent.probeTargets[0].clusterUUID;
    site.targetProbeDeploymentID = site.intent.probeTargets[0].probeDeploymentID;
    site.targetApp6DeploymentID = allMasters.intent.sites[0].app6DeploymentID;
    site.replayStage = ProdigyNametagQualificationReplayWorkStage::workload;
    for (uint16_t i = 0; i < 2; ++i) {
      ProdigyNametagQualificationReplay source = {};
      source.runUUID = site.intent.runUUID; source.challengeUUID = 100 + i;
      source.executionGeneration = site.intent.executionGeneration;
      source.deadlineAtMilliseconds = site.intent.deadlineAtMilliseconds;
      source.direction = 1; source.stage = ProdigyNametagQualificationReplayStage::arm;
      source.store = i ? ProdigyNametagQualificationReplayStore::graph : ProdigyNametagQualificationReplayStore::kv;
      source.applicationID = i ? 2 : 3; source.sourceAddress = 0x100 + i;
      source.workloadName.assign("row13-test"_ctv);
      auto& s = source.session;
      s.pairUUID = 1; s.routeUUID = 2; s.sourcePermissionUUID = 3; s.destinationPermissionUUID = 4;
      s.sourceClusterUUID = i ? site.targetClusterUUID : site.intent.probeTargets[1].clusterUUID;
      s.destinationClusterUUID = i ? site.intent.probeTargets[1].clusterUUID : site.targetClusterUUID;
      s.sourceDeploymentID = 5; s.destinationDeploymentID = 6; s.sourceContainerUUID = 7; s.destinationContainerUUID = 8;
      s.sessionUUID = 9; s.sessionGeneration = 1; s.routeGeneration = 1; s.sourcePermissionAuthorityGeneration = 1;
      site.replaySources.push_back(source);
    }
    assert(prodigyNametagQualificationReplayLocalHalf(ProdigyNametagQualificationReplayStore::kv, false) == CousinRouteHalf::destination);
    assert(prodigyNametagQualificationReplayLocalHalf(ProdigyNametagQualificationReplayStore::kv, true) == CousinRouteHalf::source);
    assert(prodigyNametagQualificationReplayLocalHalf(ProdigyNametagQualificationReplayStore::graph, false) == CousinRouteHalf::source);
    assert(prodigyNametagQualificationReplayLocalHalf(ProdigyNametagQualificationReplayStore::graph, true) == CousinRouteHalf::destination);
    auto wrongDirection = site;
    std::swap(wrongDirection.replaySources[0].session.sourceClusterUUID, wrongDirection.replaySources[0].session.destinationClusterUUID);
    assert(!mothershipNametagQualificationSiteRequestValid(wrongDirection));
    auto initial = site.replaySources[0];
    initial.challengeUUID = initial.sourceAddress = 0;
    initial.session.sourceContainerUUID = initial.session.destinationContainerUUID = 0;
    initial.session.sessionUUID = 0; initial.session.sessionGeneration = 0;
    assert(prodigyNametagQualificationReplayInitialValid(initial));
    auto invalidInitial = initial; invalidInitial.targetSide = true;
    assert(!prodigyNametagQualificationReplayInitialValid(invalidInitial));
    auto resolution = site.replaySources[0]; resolution.response = true;
    assert(prodigyNametagQualificationReplayResolutionMatches(initial, resolution));
    ++resolution.session.routeUUID;
    assert(!prodigyNametagQualificationReplayResolutionMatches(initial, resolution));
    ProdigyNametagQualificationApplicationCommand command = {};
    assert(mothershipNametagQualificationSiteRequestValid(site) &&
           mothershipNametagQualificationApplicationCommand(site, command) &&
           command.protocolVersion == command.replayStageVersion && command.replayStage == site.replayStage);
    String bytes = {}; auto encoded = site;
    assert(BitseryEngine::serialize(bytes, encoded));
    MothershipNametagQualificationSiteRequest decoded = {};
    assert(BitseryEngine::deserializeSafe(bytes, decoded) &&
           mothershipNametagQualificationSiteRequestValid(decoded) && decoded.replayStage == site.replayStage);
    decoded.replayStage = ProdigyNametagQualificationReplayWorkStage::none;
    assert(!mothershipNametagQualificationSiteRequestValid(decoded));
    decoded.replayStage = ProdigyNametagQualificationReplayWorkStage::prepare;
    decoded.replaySources.clear();
    assert(mothershipNametagQualificationSiteRequestValid(decoded) &&
           mothershipNametagQualificationApplicationCommand(decoded, command));
    decoded.intent.direction = MothershipNametagQualificationDirection::observation;
    assert(!mothershipNametagQualificationSiteRequestValid(decoded));
    MothershipNametagQualificationExecutionRecord record = {};
    record.protocolVersion = record.replayVersion; record.intent = site.intent;
    assert(mothershipNametagQualificationExecutionRecordValid(record));
    MothershipNametagQualificationExecutionRecord::ReplayWitness witness = {};
    witness.sourceChallenge = site.replaySources[0];
    witness.sourceCapture = witness.sourceChallenge;
    witness.sourceCapture.stage = ProdigyNametagQualificationReplayStage::query;
    witness.sourceCapture.response = witness.sourceCapture.ready = true;
    witness.sourceCapture.originUUID = 20; witness.sourceCapture.olderCommittedID = 21;
    witness.sourceCapture.delayedID = 22; witness.sourceCapture.committedID = 23;
    record.replayWitnesses.push_back(witness);
    assert(!mothershipNametagQualificationExecutionRecordValid(record)); // capture requires installed source arm
    record.replayWitnesses[0].sourceArm = witness.sourceChallenge;
    record.replayWitnesses[0].sourceArm.response = record.replayWitnesses[0].sourceArm.ready = true;
    assert(mothershipNametagQualificationExecutionRecordValid(record));
    auto alteredArm = record; ++alteredArm.replayWitnesses[0].sourceArm.challengeUUID;
    assert(!mothershipNametagQualificationExecutionRecordValid(alteredArm));
    record.replayWitnesses[0].sourceCapture.stage = ProdigyNametagQualificationReplayStage::arm;
    assert(!mothershipNametagQualificationExecutionRecordValid(record));
    record.replayWitnesses.clear();
    record.phase = MothershipNametagQualificationExecutionPhase::verified;
    assert(!mothershipNametagQualificationExecutionRecordValid(record));
    // Drive the actual durable owner through the complete ordered native
    // challenge, replay, release, and independent application readbacks.
    auto liveIntent = site.intent;
    liveIntent.runUUID += 0x9900; liveIntent.executionGeneration += 0x9900;
    liveIntent.startedAtMilliseconds = Time::now<TimeResolution::ms>() - 1000;
    liveIntent.deadlineAtMilliseconds = liveIntent.startedAtMilliseconds + int64_t(liveIntent.deadlineSeconds) * 1000;
    liveIntent.convergenceDeadlineAtMilliseconds = liveIntent.startedAtMilliseconds + int64_t(liveIntent.convergenceSeconds) * 1000;
    MothershipNametagQualificationIntent persisted = {}; MothershipNametagQualificationExecutionRecord live = {};
    bool resumedReplay = false; String replayFailure = {};
    assert(registry->persistNametagQualificationIntent(*replay, liveIntent, persisted, resumedReplay, &replayFailure));
    assert(registry->persistNametagQualificationExecutionPrepared(*replay, liveIntent, live, resumedReplay, &replayFailure));
    for (size_t i = 0; i < 2; ++i) {
      auto challenge = site.replaySources[i]; challenge.runUUID = liveIntent.runUUID;
      challenge.executionGeneration = liveIntent.executionGeneration; challenge.deadlineAtMilliseconds = liveIntent.deadlineAtMilliseconds;
      assert(registry->recordNametagQualificationReplayWitness(*replay, liveIntent, i, challenge, live, &replayFailure));
      auto prearm = challenge; prearm.targetSide = true; prearm.stage = ProdigyNametagQualificationReplayStage::prearm;
      assert(registry->recordNametagQualificationReplayWitness(*replay, liveIntent, i, prearm, live, &replayFailure));
      auto ack = prearm; ack.response = ack.ready = true;
      assert(registry->recordNametagQualificationReplayWitness(*replay, liveIntent, i, ack, live, &replayFailure));
      ack = challenge; ack.response = ack.ready = true;
      assert(registry->recordNametagQualificationReplayWitness(*replay, liveIntent, i, ack, live, &replayFailure));
    }
    auto app = [&](size_t i, ProdigyNametagQualificationReplayWorkStage stage) {
      ProdigyNametagQualificationApplicationReceipt r = {};
      r.protocolVersion = r.replayStageVersion; r.runUUID = liveIntent.runUUID; r.row = uint8_t(liveIntent.row);
      r.direction = uint8_t(liveIntent.direction); r.executionGeneration = liveIntent.executionGeneration;
      r.rowID = liveIntent.rowID; r.descriptor = liveIntent.descriptor; r.localClusterUUID = liveIntent.probeTargets[i].clusterUUID;
      r.deploymentID = liveIntent.probeTargets[i].probeDeploymentID; r.localContainerUUID = 0xb000 + i;
      r.startedAtMilliseconds = liveIntent.startedAtMilliseconds; r.deadlineAtMilliseconds = liveIntent.deadlineAtMilliseconds;
      r.convergenceDeadlineAtMilliseconds = liveIntent.convergenceDeadlineAtMilliseconds;
      r.observedAtMilliseconds = stage == ProdigyNametagQualificationReplayWorkStage::workload ?
          liveIntent.startedAtMilliseconds + 1 : Time::now<TimeResolution::ms>() + 1;
      r.witnessedResult = liveIntent.descriptor.expectedWitness; r.replayStage = stage;
      r.joinedWitnessDigest = digest('a'); r.witnessDigest = digest('b'); r.canonicalWitnessReceipt.assign("row13-native-test"_ctv);
      return r;
    };
    auto workload = app(0, ProdigyNametagQualificationReplayWorkStage::workload);
    assert(registry->recordNametagQualificationReplayReadback(*replay, liveIntent, workload, live, &replayFailure));
    for (size_t i = 0; i < 2; ++i) {
      auto capture = live.replayWitnesses[i].sourceChallenge; capture.stage = ProdigyNametagQualificationReplayStage::query;
      capture.response = capture.ready = true; capture.originUUID = 20 + i;
      capture.olderCommittedID = 21; capture.delayedID = 22; capture.committedID = 23; capture.catchupID = i ? 24 : 0;
      assert(registry->recordNametagQualificationReplayWitness(*replay, liveIntent, i, capture, live, &replayFailure));
      auto target = live.replayWitnesses[i].sourceChallenge; target.targetSide = true;
      target.originUUID = capture.originUUID; target.olderCommittedID = capture.olderCommittedID;
      target.delayedID = capture.delayedID; target.committedID = capture.committedID; target.catchupID = capture.catchupID;
      assert(registry->recordNametagQualificationReplayWitness(*replay, liveIntent, i, target, live, &replayFailure));
      auto ack = target; ack.response = ack.ready = true;
      assert(registry->recordNametagQualificationReplayWitness(*replay, liveIntent, i, ack, live, &replayFailure));
      auto prematureSource = live.replayWitnesses[i].sourceChallenge;
      prematureSource.stage = ProdigyNametagQualificationReplayStage::replay;
      prematureSource.response = prematureSource.ready = true;
      assert(!registry->recordNametagQualificationReplayWitness(*replay, liveIntent, i, prematureSource, live, &replayFailure));
      ack.stage = ProdigyNametagQualificationReplayStage::replay;
      assert(registry->recordNametagQualificationReplayWitness(*replay, liveIntent, i, ack, live, &replayFailure));
      auto source = live.replayWitnesses[i].sourceChallenge; source.stage = ProdigyNametagQualificationReplayStage::replay;
      source.response = source.ready = true;
      assert(registry->recordNametagQualificationReplayWitness(*replay, liveIntent, i, source, live, &replayFailure));
      source = capture;
      assert(registry->recordNametagQualificationReplayWitness(*replay, liveIntent, i, source, live, &replayFailure));
      ack.stage = ProdigyNametagQualificationReplayStage::query; ack.duplicateRejected = ack.staleRejected = true;
      ack.delayedApplied = !i; ack.delayedRejected = ack.catchupApplied = bool(i);
      assert(registry->recordNametagQualificationReplayWitness(*replay, liveIntent, i, ack, live, &replayFailure));
      ack = target; ack.stage = ProdigyNametagQualificationReplayStage::release; ack.response = ack.ready = true;
      assert(registry->recordNametagQualificationReplayWitness(*replay, liveIntent, i, ack, live, &replayFailure));
      source = live.replayWitnesses[i].sourceChallenge; source.stage = ProdigyNametagQualificationReplayStage::release;
      source.response = source.ready = true;
      assert(registry->recordNametagQualificationReplayWitness(*replay, liveIntent, i, source, live, &replayFailure));
    }
    assert(live.replayQueriesCompletedAtMilliseconds);
    for (size_t i = 0; i < 3; ++i) {
      auto final = app(i, ProdigyNametagQualificationReplayWorkStage::final);
      assert(registry->recordNametagQualificationReplayReadback(*replay, liveIntent, final, live, &replayFailure));
    }
    assert(mothershipNametagQualificationReplayExecutionComplete(live));
    const MothershipNametagQualificationExecutionPhase stages[] = {MothershipNametagQualificationExecutionPhase::prepared,
      MothershipNametagQualificationExecutionPhase::faultApplied, MothershipNametagQualificationExecutionPhase::workloadIssued,
      MothershipNametagQualificationExecutionPhase::faultRestored, MothershipNametagQualificationExecutionPhase::converging,
      MothershipNametagQualificationExecutionPhase::verified};
    for (size_t i = 0; i + 1 < std::size(stages); ++i)
      assert(registry->advanceNametagQualificationExecution(*replay, liveIntent, stages[i], stages[i + 1], live, resumedReplay, &replayFailure));
    assert(live.phase == MothershipNametagQualificationExecutionPhase::verified && mothershipNametagQualificationExecutionRecordValid(live));
  }
  // A source-cut operation is durable before network dispatch, and each
  // returned member challenge is fixed before any proof can be admitted.
  auto cuts = allMasters;
  cuts.protocolVersion = MothershipNametagAllMastersRecord::sourceCutVersion;
  cuts.intent.protocolVersion = MothershipNametagAllMastersIntent::seedRouteVersion;
  cuts.intent.operationUUID = 0xa111; cuts.intent.sourceBaselineOperationUUID = 0xa112;
  cuts.intent.sites[0].truthDeploymentID = (uint64_t(MeshRegistry::Truth::applicationID) << 48) | 1;
  cuts.seedPlacements.clear(); cuts.phase = MothershipNametagAllMastersRecord::Phase::sourceCutsPreparing;
  for (uint32_t site = 0; site < 3; ++site) {
    auto& value = cuts.intent.sites[site];
    value.pulseDeploymentID = (uint64_t(MeshRegistry::Pulse::applicationID) << 48) | (site + 1);
    value.hotDeploymentID = (uint64_t(MeshRegistry::Hot::applicationID) << 48) | (site + 1);
    value.coldDeploymentID = (uint64_t(MeshRegistry::Cold::applicationID) << 48) | (site + 1);
    value.radarDeploymentID = (uint64_t(MeshRegistry::Radar::applicationID) << 48) | (site + 1);
  }
  struct CutStore { uint16_t app; DeploymentIdentityStoreKind kind; uint32_t groups; uint64_t deployment; };
  const auto& ewr = cuts.intent.sites[0];
  const CutStore cutStores[] = {{MeshRegistry::Pulse::applicationID, DeploymentIdentityStoreKind::graph, 1, ewr.pulseDeploymentID},
      {MeshRegistry::Hot::applicationID, DeploymentIdentityStoreKind::kv, 3, ewr.hotDeploymentID},
      {MeshRegistry::Cold::applicationID, DeploymentIdentityStoreKind::kv, 3, ewr.coldDeploymentID},
      {MeshRegistry::Radar::applicationID, DeploymentIdentityStoreKind::graph, 1, ewr.radarDeploymentID}};
  for (const auto& store : cutStores) for (uint32_t group = 0; group < store.groups; ++group) {
    for (uint8_t site = 1; site < 3; ++site) {
      MothershipNametagSeedRouteReference route = {};
      route.site = site; route.applicationID = store.app; route.shardGroup = group;
      route.routeUUID = 0x7100 + cuts.intent.seedRoutes.size(); cuts.intent.seedRoutes.push_back(route);
    }
    auto& item = cuts.sourceCuts.emplace_back(); auto& request = item.request;
    request.operationUUID = cuts.intent.operationUUID; request.requestUUID = 0xb000 + cuts.sourceCuts.size();
    request.sourceClusterUUID = ewr.clusterUUID; request.sourceDeploymentID = store.deployment;
    request.sourceContainerUUID = 0xc000 + cuts.sourceCuts.size(); request.applicationID = store.app;
    request.storeKind = store.kind; request.shardGroup = group; request.nShardGroups = store.groups;
    request.retainUntilMilliseconds = Time::now<TimeResolution::ms>() + 60000;
  }
  assert(mothershipNametagAllMastersRecordValid(cuts));
  MothershipNametagAllMastersRecord checkpoint;
  assert(registry->persistNametagAllMasters(cuts, checkpoint, resumed, &failure) && !resumed);
  assert(registry->updateNametagAllMastersSourceCut(cuts.intent.operationUUID, 0, true, nullptr, checkpoint, &failure));
  assert(!registry->updateNametagAllMastersSourceCut(cuts.intent.operationUUID, 0, true, nullptr, checkpoint, &failure));
  assert(registry->loadNametagAllMasters(cuts.intent.operationUUID, checkpoint, &failure));
  assert(checkpoint.sourceCuts[0].dispatched && checkpoint.sourceCuts[0].request.memberRequestUUID == 0);
  auto pendingCut = checkpoint.sourceCuts[0].request; pendingCut.response = true; pendingCut.memberRequestUUID = 0xd001;
  assert(registry->updateNametagAllMastersSourceCut(cuts.intent.operationUUID, 0, false, &pendingCut, checkpoint, &failure));
  assert(registry->loadNametagAllMasters(cuts.intent.operationUUID, checkpoint, &failure));
  assert(checkpoint.sourceCuts[0].request.memberRequestUUID == 0xd001);
  auto forgedCut = pendingCut; ++forgedCut.memberRequestUUID;
  assert(!registry->updateNametagAllMastersSourceCut(cuts.intent.operationUUID, 0, false, &forgedCut, checkpoint, &failure));
  auto readyCut = pendingCut; readyCut.ready = true; readyCut.cutUUID = 0xe001; readyCut.cutGeneration = 1;
  readyCut.contentSHA256 = digest('b'); readyCut.headsSHA256 = digest('c');
  assert(registry->updateNametagAllMastersSourceCut(cuts.intent.operationUUID, 0, false, &readyCut, checkpoint, &failure));
  auto changedCut = readyCut; ++changedCut.cutGeneration;
  assert(!registry->updateNametagAllMastersSourceCut(cuts.intent.operationUUID, 0, false, &changedCut, checkpoint, &failure));
  auto prematureRelease = readyCut; prematureRelease.action = ProdigyStatefulStoreSourceCutAction::release;
  prematureRelease.ready = false; prematureRelease.released = true;
  prematureRelease.contentSHA256.clear(); prematureRelease.headsSHA256.clear();
  assert(!registry->updateNametagAllMastersSourceCut(cuts.intent.operationUUID, 0, false, &prematureRelease, checkpoint, &failure));
  // Build target placement only from the retained native cuts and bind every
  // subsequent receipt to the exact cut and baseline operation.
  auto readyRecord = cuts;
  for (auto& item : readyRecord.sourceCuts) {
    item.dispatched = true; item.request.memberRequestUUID = 0xd000 + item.request.requestUUID;
    item.proof = item.request; item.proof.response = true; item.proof.ready = true;
    item.proof.cutUUID = 0xe000 + item.request.requestUUID; item.proof.cutGeneration = 1;
    item.proof.contentSHA256 = digest('b'); item.proof.headsSHA256 = digest('c');
  }
  Vector<DeploymentIdentityReport> cutReports[4];
  for (uint32_t store = 0; store < 4; ++store) for (uint32_t site = 0; site < 3; ++site) {
    auto& report = cutReports[store].emplace_back(); report.version = 5;
    report.clusterUUID = readyRecord.intent.sites[site].clusterUUID;
    const auto& spec = cutStores[store];
    report.deploymentID = site == 0 ? spec.deployment : (uint64_t(spec.app) << 48) | (site + 1);
    for (uint32_t group = 0; group < spec.groups; ++group) for (uint32_t replica = 0; replica < 3; ++replica) {
      auto& member = report.statefulRuntimeCohort.emplace_back(); member.storeKind = spec.kind;
      member.shardGroup = group; member.containerUUID = 0x10000 + store * 1000 + site * 100 + group * 10 + replica;
    }
  }
  assert(mothershipNametagSourceCutPlacementsSynthesize(readyRecord, cutReports[0], cutReports[1], cutReports[2], cutReports[3], digest('f')));
  assert(mothershipNametagAllMastersRecordValid(readyRecord) && readyRecord.seedPlacements.size() == 48);
  // A successor names observed fresh targets while the 48 historical rows stay immutable.
  MothershipNametagSeedSuccessor successor = {};
  successor.operationUUID = 0xf001; successor.predecessorOperationUUID = readyRecord.intent.operationUUID;
  successor.qualificationRunUUID = 0xf002; successor.qualificationRow = uint8_t(MothershipNametagQualificationRow::seedInterruptionResume);
  successor.executionGeneration = 1; successor.predecessorSHA256 = digest('d');
  successor.kind = MothershipNametagSeedSuccessorKind::site; successor.site = 1;
  Vector<DeploymentIdentityReport> successorReports;
  for (uint32_t store = 0; store < 4; ++store) {
    auto report = cutReports[store][1]; report.found = report.live = true; report.applicationID = cutStores[store].app;
    ++report.deploymentID;
    for (auto& member : report.statefulRuntimeCohort) {
      member.containerUUID += 0x100000; member.clusterUUID = report.clusterUUID; member.machineUUID = 0x1234;
    }
    successorReports.push_back(std::move(report));
  }
  for (uint32_t i = 0; i < readyRecord.seedPlacements.size(); ++i) {
    const auto& old = readyRecord.seedPlacements[i]; if (old.site != 1) continue;
    MothershipNametagSeedSuccessorTarget target = {};
    target.predecessorIndex = i; target.targetDeploymentID = old.targetDeploymentID + 1; target.containerUUID = old.targetContainerUUID + 0x100000;
    target.machineUUID = 0x1234; target.routeUUID = 0x50000 + old.applicationID * 100 + old.shardGroup;
    if (old.storeKind == DeploymentIdentityStoreKind::kv && successor.heldTargetIndex == UINT32_MAX)
      successor.heldTargetIndex = successor.targets.size();
    successor.targets.push_back(target);
  }
  for (auto fresh : readyRecord.sourceCuts) {
    fresh.request.operationUUID = successor.operationUUID; fresh.request.requestUUID += 0x10000;
    fresh.request.memberRequestUUID += 0x10000; fresh.proof = fresh.request;
    fresh.proof.response = fresh.proof.ready = true; fresh.proof.cutUUID = 0x90000 + fresh.request.requestUUID;
    fresh.proof.cutGeneration = 2; fresh.proof.contentSHA256 = digest('b'); fresh.proof.headsSHA256 = digest('c');
    successor.sourceCuts.push_back(std::move(fresh));
  }
  MothershipNametagSeedSuccessorPlacementIntent placementIntent = {};
  placementIntent.operationUUID = successor.operationUUID; placementIntent.predecessorOperationUUID = successor.predecessorOperationUUID;
  placementIntent.qualificationRunUUID = successor.qualificationRunUUID; placementIntent.executionGeneration = successor.executionGeneration;
  placementIntent.predecessorSHA256 = successor.predecessorSHA256; placementIntent.qualificationRow = successor.qualificationRow; placementIntent.site = successor.site;
  for (const auto& target : successor.targets) {
    placementIntent.predecessorIndices.push_back(target.predecessorIndex);
    const auto& old = readyRecord.seedPlacements[target.predecessorIndex];
    if (std::none_of(placementIntent.plans.begin(), placementIntent.plans.end(), [&](const auto& plan) { return plan.applicationID == old.applicationID; })) {
      auto& plan = placementIntent.plans.emplace_back(); plan.applicationID = old.applicationID;
      plan.previousDeploymentID = old.targetDeploymentID; plan.successorDeploymentID = target.targetDeploymentID;
      plan.cancellationOperationUUID = 0x99000 + old.applicationID; plan.planSHA256 = digest('a'); plan.artifactSHA256 = digest('b');
    }
    auto plan = std::find_if(placementIntent.plans.begin(), placementIntent.plans.end(),
        [&](const auto& value) { return value.applicationID == old.applicationID; });
    plan->previousMembers.push_back({old.targetContainerUUID, 0x1234});
  }
  assert(mothershipNametagSeedSuccessorPlacementIntentValid(placementIntent, readyRecord));
  String placementBytes; auto placementCopy = placementIntent; MothershipNametagSeedSuccessorPlacementIntent decodedPlacement = {};
  assert(BitseryEngine::serialize(placementBytes, placementCopy) && BitseryEngine::deserializeSafe(placementBytes, decodedPlacement) &&
      mothershipNametagSeedSuccessorPlacementIntentValid(decodedPlacement, readyRecord));
  // Both the legacy placement codec and the new empty route-plan phase remain
  // readable; an incomplete fabricated binding must not become a plan.
  auto legacyPlacement = placementIntent;
  legacyPlacement.protocolVersion = MothershipNametagSeedSuccessorPlacementIntent::legacyVersion;
  String legacyBytes; MothershipNametagSeedSuccessorPlacementIntent decodedLegacy = {};
  assert(BitseryEngine::serialize(legacyBytes, legacyPlacement) && BitseryEngine::deserializeSafe(legacyBytes, decodedLegacy) &&
      decodedLegacy.protocolVersion == legacyPlacement.protocolVersion && decodedLegacy.routePlan.empty() &&
      mothershipNametagSeedSuccessorPlacementIntentValid(decodedLegacy, readyRecord));
  auto incompleteRoutePlan = placementIntent;
  incompleteRoutePlan.routePlan.emplace_back();
  assert(!mothershipNametagSeedSuccessorPlacementIntentValid(incompleteRoutePlan, readyRecord));
  decodedLegacy.routePlan.emplace_back();
  assert(!mothershipNametagSeedSuccessorPlacementIntentValid(decodedLegacy, readyRecord));
  auto plannedPlacement = placementIntent;
  for (const auto& ref : readyRecord.intent.seedRoutes) {
    if (ref.site != plannedPlacement.site) continue;
    auto p = std::find_if(plannedPlacement.plans.begin(), plannedPlacement.plans.end(), [&](const auto& v) { return v.applicationID == ref.applicationID; });
    assert(p != plannedPlacement.plans.end());
    auto fixture = cousinBinding(); auto& r = fixture.route;
    r.version = 3; r.endpointKind = CousinRouteEndpointKind::privateContainer; r.destinationRoutablePrefixUUID = 0; r.destinationCIDR = 128;
    r.issuedAtMs = Time::now<TimeResolution::ms>(); r.expiresAtMs = r.issuedAtMs + 600000;
    r.destinationPublicAddress = IPAddress("fd42::1", true); r.routeUUID = ref.routeUUID; r.operationUUID = ref.routeUUID + 0x1000;
    r.sourceClusterUUID = readyRecord.intent.sites[ref.site].clusterUUID; r.destinationClusterUUID = readyRecord.intent.sites[0].clusterUUID;
    r.sourceApplicationID = r.destinationApplicationID = ref.applicationID;
    r.sourceCousinServicePrefix = r.destinationCousinServicePrefix = prodigyRuntimeStatefulServicePrefix(ref.applicationID, 4);
    r.slots = {}; const uint16_t groups = ref.applicationID == 3 || ref.applicationID == 4 ? 3 : 1;
    uint16_t slot = 0; while (statefulServiceGroupOwnerForSlot(slot, groups) != ref.shardGroup) ++slot;
    r.slots.insert(slot); r.sourcePermissionUUID = ref.routeUUID + 0x2000; r.destinationPermissionUUID = ref.routeUUID + 0x3000;
    auto& a = fixture.sourcePermission; auto& b = fixture.destinationPermission;
    a.protocolVersion = b.protocolVersion = 3; a.permissionUUID = r.sourcePermissionUUID; b.permissionUUID = r.destinationPermissionUUID;
    a.localClusterUUID = b.peerClusterUUID = r.sourceClusterUUID; a.peerClusterUUID = b.localClusterUUID = r.destinationClusterUUID;
    a.localApplicationID = a.peerApplicationID = b.localApplicationID = b.peerApplicationID = ref.applicationID;
    a.localCousinServicePrefix = a.peerCousinServicePrefix = b.localCousinServicePrefix = b.peerCousinServicePrefix = r.sourceCousinServicePrefix;
    a.slots = b.slots = r.slots; a.localDeploymentID = b.peerDeploymentID = p->previousDeploymentID;
    const auto oldRow = std::find_if(readyRecord.seedPlacements.begin(), readyRecord.seedPlacements.end(), [&](const auto& row) {
      return row.site == ref.site && row.applicationID == ref.applicationID && row.shardGroup == ref.shardGroup;
    });
    assert(oldRow != readyRecord.seedPlacements.end()); b.localDeploymentID = a.peerDeploymentID = oldRow->sourceDeploymentID;
    a.peerCanonicalPlanSHA256 = b.canonicalPlanSHA256 = digest('c'); b.peerCanonicalPlanSHA256 = a.canonicalPlanSHA256 = digest('d');
    a.peerArtifactSHA256 = b.artifactSHA256 = digest('e'); b.peerArtifactSHA256 = a.artifactSHA256 = digest('f');
    a.peerArtifactBytes = b.artifactBytes = b.peerArtifactBytes = a.artifactBytes = 8192;
    a.baselineLogicalCores = b.baselineLogicalCores = 1; a.baselineMemoryMB = b.baselineMemoryMB = 100; a.baselineStorageMB = b.baselineStorageMB = 100;
    a.purpose = b.purpose = ProdigyCousinServicePurpose::seeding; a.destinationShardGroup = b.destinationShardGroup = ref.shardGroup;
    a.destinationShardGroups = b.destinationShardGroups = groups;
    a.authorizedService = b.authorizedService = MeshServices::constrainPrefixToGroup(r.destinationCousinServicePrefix, ref.shardGroup);
    auto& entry = plannedPlacement.routePlan.emplace_back(); entry.seeding = true; entry.previousRoute = r;
    entry.previousSource = a; entry.previousDestination = b; entry.desiredRoute = r;
    entry.desiredRoute.routeUUID += 0x4000; entry.desiredRoute.operationUUID += 0x5000;
    entry.desiredSource = a; entry.desiredDestination = b; entry.desiredSource.permissionUUID += 0x6000; entry.desiredDestination.permissionUUID += 0x7000;
    entry.desiredRoute.sourcePermissionUUID = entry.desiredSource.permissionUUID; entry.desiredRoute.destinationPermissionUUID = entry.desiredDestination.permissionUUID;
    entry.desiredSource.localDeploymentID = entry.desiredDestination.peerDeploymentID = p->successorDeploymentID;
    entry.desiredSource.canonicalPlanSHA256 = entry.desiredDestination.peerCanonicalPlanSHA256 = p->planSHA256;
    entry.desiredSource.artifactSHA256 = entry.desiredDestination.peerArtifactSHA256 = p->artifactSHA256;
    entry.desiredSource.acceptedAuthorityGeneration = entry.desiredDestination.acceptedAuthorityGeneration = 0;
    for (auto* v : {&entry.desiredSource, &entry.desiredDestination}) v->baselineLogicalCores = v->baselineMemoryMB = v->baselineStorageMB = 0;
    auto receipt = [&](CousinRouteHalf half) { CousinRouteApplyReceipt value = {}; value.routeUUID = r.routeUUID; value.generation = r.generation;
      assert(cousinRouteAuthorizationDigest(r, value.authorizationSHA256)); value.localHalf = half;
      value.localClusterUUID = half == CousinRouteHalf::source ? r.sourceClusterUUID : r.destinationClusterUUID;
      value.keyEpoch = r.keyEpoch; value.localRuntimeRevision = 1; value.installedState = r.state; return value; };
    entry.previousSourceReceipt = receipt(CousinRouteHalf::source); entry.previousDestinationReceipt = receipt(CousinRouteHalf::destination);
    assert(mothershipSeedSuccessorRoutePermissionPairValid(entry.previousRoute, entry.previousSource, entry.previousDestination, true));
    assert(mothershipSeedSuccessorRoutePermissionPairValid(entry.desiredRoute, entry.desiredSource, entry.desiredDestination, false));
    assert(cousinRouteApplyReceiptMatchesCurrentRoute(entry.previousSourceReceipt, entry.previousRoute));
    assert(cousinRouteApplyReceiptMatchesCurrentRoute(entry.previousDestinationReceipt, entry.previousRoute));
  }
  assert(plannedPlacement.routePlan.size() == 8 && mothershipNametagSeedSuccessorPlacementIntentValid(plannedPlacement, readyRecord));
  auto changedPeerBaseline = plannedPlacement;
  changedPeerBaseline.routePlan[0].desiredDestination.baselineLogicalCores = 2;
  changedPeerBaseline.routePlan[0].desiredDestination.baselineMemoryMB = 100;
  changedPeerBaseline.routePlan[0].desiredDestination.baselineStorageMB = 100;
  assert(!mothershipNametagSeedSuccessorPlacementIntentValid(changedPeerBaseline, readyRecord));
  auto changedRoutePlan = plannedPlacement; changedRoutePlan.routePlan[0].desiredSource.peerDeploymentID++;
  assert(!mothershipNametagSeedSuccessorPlacementIntentValid(changedRoutePlan, readyRecord));
  auto invalidProgress = placementIntent; invalidProgress.cancellationCompletedMask = 1;
  assert(!mothershipNametagSeedSuccessorPlacementIntentValid(invalidProgress, readyRecord));
  invalidProgress.cancellationDispatchedMask = 1;
  assert(!mothershipNametagSeedSuccessorPlacementIntentValid(invalidProgress, readyRecord));
  auto withReceipt = placementIntent; withReceipt.plans[0].cancellationOperationUUID = 1;
  withReceipt.cancellationDispatchedMask = withReceipt.cancellationCompletedMask = 1;
  auto& cancellation = withReceipt.cancellationReceipts.emplace_back();
  cancellation.success = true; cancellation.result = CancelDeploymentResult::completed; cancellation.phase = CancelDeploymentPhase::completed;
  cancellation.operationID.assign("00000000-0000-0000-0000-000000000001"_ctv); cancellation.durableGeneration = 1;
  cancellation.applicationID = withReceipt.plans[0].applicationID;
  cancellation.cancelledDeploymentID = withReceipt.plans[0].previousDeploymentID; cancellation.successorDeploymentID = withReceipt.plans[0].successorDeploymentID;
  cancellation.activeVersionID = cancellation.cancelledDeploymentID & ((uint64_t(1) << 48) - 1);
  cancellation.successorVersionID = cancellation.successorDeploymentID & ((uint64_t(1) << 48) - 1);
  assert(mothershipNametagSeedSuccessorPlacementIntentValid(withReceipt, readyRecord));
  ++withReceipt.cancellationReceipts[0].successorVersionID;
  assert(!mothershipNametagSeedSuccessorPlacementIntentValid(withReceipt, readyRecord));
  auto invalidPlacement = placementIntent; invalidPlacement.predecessorIndices[0] = invalidPlacement.predecessorIndices[1];
  assert(!mothershipNametagSeedSuccessorPlacementIntentValid(invalidPlacement, readyRecord));
  invalidPlacement = placementIntent; invalidPlacement.plans[0].successorDeploymentID = invalidPlacement.plans[0].previousDeploymentID;
  assert(!mothershipNametagSeedSuccessorPlacementIntentValid(invalidPlacement, readyRecord));
  assert(successor.targets.size() == 24 && mothershipNametagSeedSuccessorValid(successor, readyRecord, successorReports));
  String successorBytes; auto successorCopy = successor; MothershipNametagSeedSuccessor decodedSuccessor = {};
  assert(BitseryEngine::serialize(successorBytes, successorCopy) && BitseryEngine::deserializeSafe(successorBytes, decodedSuccessor) &&
      mothershipNametagSeedSuccessorValid(decodedSuccessor, readyRecord, successorReports));
  auto wrongDeployment = successor; wrongDeployment.targets[0].targetDeploymentID = readyRecord.seedPlacements[wrongDeployment.targets[0].predecessorIndex].targetDeploymentID;
  assert(!mothershipNametagSeedSuccessorValid(wrongDeployment, readyRecord, successorReports));
  auto wrongPredecessor = successor; ++wrongPredecessor.predecessorOperationUUID;
  assert(!mothershipNametagSeedSuccessorValid(wrongPredecessor, readyRecord, successorReports));
  auto missingRoute = successor; missingRoute.targets[0].routeUUID = 0;
  assert(!mothershipNametagSeedSuccessorValid(missingRoute, readyRecord, successorReports));
  auto wrongSuccessor = successor; wrongSuccessor.targets[1].containerUUID = wrongSuccessor.targets[0].containerUUID;
  assert(!mothershipNametagSeedSuccessorValid(wrongSuccessor, readyRecord, successorReports));
  wrongSuccessor = successor; ++wrongSuccessor.sourceCuts[0].proof.memberRequestUUID;
  assert(!mothershipNametagSeedSuccessorValid(wrongSuccessor, readyRecord, successorReports));
  wrongSuccessor = successor; wrongSuccessor.targets.pop_back();
  assert(!mothershipNametagSeedSuccessorValid(wrongSuccessor, readyRecord, successorReports));
  wrongSuccessor = successor; wrongSuccessor.sourceReboot.clusterUUID = readyRecord.intent.sites[0].clusterUUID;
  wrongSuccessor.sourceReboot.machineUUID = 0x111; wrongSuccessor.sourceReboot.dispatchUUID = 0x112;
  wrongSuccessor.sourceReboot.beforeBootID.assign("same"_ctv); wrongSuccessor.sourceReboot.afterBootID.assign("same"_ctv);
  wrongSuccessor.sourceReboot.dispatched = wrongSuccessor.sourceReboot.observed = true;
  assert(!mothershipNametagSeedSuccessorValid(wrongSuccessor, readyRecord, successorReports));
  auto rebootSuccessor = successor;
  rebootSuccessor.qualificationRow = uint8_t(MothershipNametagQualificationRow::brainHardRebootCatchup);
  rebootSuccessor.sourceReboot.clusterUUID = readyRecord.intent.sites[0].clusterUUID;
  rebootSuccessor.sourceReboot.machineUUID = 0x111; rebootSuccessor.sourceReboot.dispatchUUID = 0x112;
  rebootSuccessor.sourceReboot.beforeBootID.assign("01234567-89ab-cdef-0123-456789abcdef"_ctv);
  rebootSuccessor.sourceReboot.afterBootID.assign("11234567-89ab-cdef-0123-456789abcdef"_ctv);
  rebootSuccessor.sourceReboot.dispatched = rebootSuccessor.sourceReboot.observed = true;
  assert(!mothershipNametagSeedSuccessorValid(rebootSuccessor, readyRecord, successorReports));
  rebootSuccessor.sourceReboot.providerAccepted = true;
  assert(mothershipNametagSeedSuccessorValid(rebootSuccessor, readyRecord, successorReports));
  rebootSuccessor.sourceReboot.dispatched = false;
  assert(!mothershipNametagSeedSuccessorValid(rebootSuccessor, readyRecord, successorReports));
  auto replicaSuccessor = successor; replicaSuccessor.kind = MothershipNametagSeedSuccessorKind::replica;
  assert(mothershipNametagSeedSuccessorValid(replicaSuccessor, readyRecord, successorReports));
  auto heldSuccessor = replicaSuccessor;
  auto& heldTarget = heldSuccessor.targets[heldSuccessor.heldTargetIndex];
  const auto& selectedRow = readyRecord.seedPlacements[heldTarget.predecessorIndex];
  const auto retained = std::find_if(heldSuccessor.sourceCuts.begin(), heldSuccessor.sourceCuts.end(), [&](const auto& cut) {
    return cut.request.applicationID == selectedRow.applicationID && cut.request.shardGroup == selectedRow.shardGroup;
  });
  assert(retained != heldSuccessor.sourceCuts.end());
  auto& held = heldSuccessor.heldReceipt;
  held.runUUID = heldSuccessor.qualificationRunUUID; held.challengeUUID = 0xf003;
  held.executionGeneration = heldSuccessor.executionGeneration; held.deadlineAtMilliseconds = retained->request.retainUntilMilliseconds;
  held.stage = ProdigyNametagQualificationSeedFaultStage::query; held.response = held.ready = held.held = true;
  held.sessionUUID = 0xf004; held.sessionGeneration = 1; held.appliedFrames = 1;
  assert(mothershipNametagSeedSuccessorAuthority(heldSuccessor, readyRecord, heldSuccessor.heldTargetIndex,
      held.challengeUUID, held.deadlineAtMilliseconds, heldTarget.authority));
  heldTarget.deliveryDispatched = heldTarget.deliveryApplied = true; held.authority = heldTarget.authority;
  heldSuccessor.stage = MothershipNametagSeedSuccessorStage::held;
  assert(mothershipNametagSeedSuccessorValid(heldSuccessor, readyRecord, successorReports));
  auto invalidHeld = heldSuccessor; ++invalidHeld.heldReceipt.authority.cutGeneration;
  assert(!mothershipNametagSeedSuccessorValid(invalidHeld, readyRecord, successorReports));
  auto pendingSuccessor = replicaSuccessor;
  pendingSuccessor.sourceCuts[0].dispatched = false; pendingSuccessor.sourceCuts[0].request.memberRequestUUID = 0;
  pendingSuccessor.sourceCuts[0].proof = {};
  assert(mothershipNametagSeedSuccessorValid(pendingSuccessor, readyRecord, successorReports));
  pendingSuccessor.sourceCuts[0].request.memberRequestUUID = 99;
  assert(!mothershipNametagSeedSuccessorValid(pendingSuccessor, readyRecord, successorReports));

  auto makeNativeReceipt = [&](const ProdigyStatefulStoreSeedAuthority& a) {
    ProdigyStatefulStoreReceipt n = {};
    n.protocolVersion = ProdigyStatefulStoreReceipt::sourceCutVersion;
    n.localContainerUUID = a.targetContainerUUID; n.localClusterUUID = a.targetClusterUUID; n.deploymentID = a.targetDeploymentID;
    n.storeKind = a.storeKind; n.shardGroup = a.shardGroup; n.nShardGroups = a.nShardGroups;
    n.writable = true; n.siblingSessionUUID = 10; n.siblingSessionGeneration = 1; n.siblingSessionHealthy = true;
    n.seededFromClusterUUID = a.sourceClusterUUID; n.seededFromContainerUUID = a.sourceContainerUUID;
    n.seedGeneration = a.seedGeneration; n.seedFixtureSHA256 = a.fixtureSHA256; n.appliedWatermarkSHA256 = digest('a');
    n.sourceContentWatermarkSHA256 = n.materializedContentSHA256 = a.sourceContentWatermarkSHA256;
    n.sourceCatchupWatermarkSHA256 = n.materializedHeadsSHA256 = a.sourceCatchupWatermarkSHA256;
    n.operationUUID = a.operationUUID; n.sourceBaselineOperationUUID = a.sourceBaselineOperationUUID;
    n.sourceRequestUUID = a.sourceRequestUUID; n.sourceMemberRequestUUID = a.sourceMemberRequestUUID;
    n.sourceDeploymentID = a.sourceDeploymentID; n.cutUUID = a.cutUUID; n.cutGeneration = a.cutGeneration;
    n.seedRouteUUID = a.seedRouteUUID; n.sourceCutScope = a.sourceCutScope; n.retainUntilMilliseconds = a.retainUntilMilliseconds;
    n.cutMaterialized = n.committedHeadsDominateCut = true;
    return n;
  };
  auto completedSuccessor = heldSuccessor;
  completedSuccessor.releaseDispatched = true;
  completedSuccessor.releaseReceipt = completedSuccessor.heldReceipt;
  completedSuccessor.releaseReceipt.stage = ProdigyNametagQualificationSeedFaultStage::release;
  completedSuccessor.releaseReceipt.held = false; completedSuccessor.releaseReceipt.sessionUUID = 0;
  completedSuccessor.releaseReceipt.sessionGeneration = completedSuccessor.releaseReceipt.appliedFrames = 0;
  completedSuccessor.stage = MothershipNametagSeedSuccessorStage::resumed;
  for (size_t i = 0; i < completedSuccessor.targets.size(); ++i) {
    auto& target = completedSuccessor.targets[i];
    if (i != completedSuccessor.heldTargetIndex)
      assert(mothershipNametagSeedSuccessorAuthority(completedSuccessor, readyRecord, i, 0, 0, target.authority));
    target.deliveryDispatched = target.deliveryApplied = true;
    const auto& a = target.authority; auto& n = target.nativeReceipt;
    n = makeNativeReceipt(a);
    assert(prodigyStatefulStoreReceiptMatchesSourceCutAuthority(n, a));
  }
  assert(mothershipNametagSeedSuccessorNativeComplete(completedSuccessor));
  for (auto& cut : completedSuccessor.sourceCuts) {
    auto release = cut.request; release.action = ProdigyStatefulStoreSourceCutAction::release;
    release.cutUUID = cut.proof.cutUUID; release.cutGeneration = cut.proof.cutGeneration;
    release.response = release.released = true; cut.released = true;
    completedSuccessor.sourceCutReleaseReceipts.push_back(release);
  }
  completedSuccessor.sourceCutReleaseDispatchedMask = 0xff;
  completedSuccessor.stage = MothershipNametagSeedSuccessorStage::complete;
  assert(mothershipNametagSeedSuccessorValid(completedSuccessor, readyRecord, successorReports));
  auto incomplete = completedSuccessor; incomplete.targets[0].nativeReceipt.protocolVersion = 0;
  assert(!mothershipNametagSeedSuccessorValid(incomplete, readyRecord, successorReports));
  incomplete = completedSuccessor; incomplete.sourceCutReleaseReceipts.pop_back();
  assert(!mothershipNametagSeedSuccessorValid(incomplete, readyRecord, successorReports));
  incomplete = completedSuccessor; incomplete.releaseDispatched = false;
  assert(!mothershipNametagSeedSuccessorValid(incomplete, readyRecord, successorReports));
  auto current = readyRecord;
  assert(mothershipNametagSeedSuccessorProject(completedSuccessor, current));
  for (const auto& target : completedSuccessor.targets) {
    const auto& row = current.seedPlacements[target.predecessorIndex];
    assert(row.targetDeploymentID == target.targetDeploymentID && row.targetContainerUUID == target.containerUUID);
  }
  // The next operation starts from the projected live cohort, never the old
  // placement. Its predecessor link identifies the completed prior operation.
  auto next = successor; next.operationUUID += 0x100; next.qualificationRunUUID += 0x100;
  next.predecessorSuccessorUUID = completedSuccessor.operationUUID; next.predecessorSuccessorSHA256 = digest('e');
  auto nextReports = successorReports;
  for (auto& report : nextReports) {
    ++report.deploymentID;
    for (auto& member : report.statefulRuntimeCohort) member.containerUUID += 0x100000;
  }
  for (auto& target : next.targets) {
    const auto& row = current.seedPlacements[target.predecessorIndex];
    target.targetDeploymentID = row.targetDeploymentID + 1; target.containerUUID = row.targetContainerUUID + 0x100000;
    target.routeUUID += 0x10000;
  }
  for (auto& cut : next.sourceCuts) {
    cut.request.operationUUID = next.operationUUID; cut.request.requestUUID += 0x100000;
    cut.request.memberRequestUUID += 0x100000; cut.proof = cut.request;
    cut.proof.response = cut.proof.ready = true; cut.proof.cutUUID = 0x190000 + cut.request.requestUUID;
    cut.proof.cutGeneration = 3; cut.proof.contentSHA256 = digest('b'); cut.proof.headsSHA256 = digest('c');
  }
  assert(mothershipNametagSeedSuccessorValid(next, current, nextReports));
  auto staleNext = next;
  staleNext.targets[0].targetDeploymentID = readyRecord.seedPlacements[staleNext.targets[0].predecessorIndex].targetDeploymentID + 1;
  assert(!mothershipNametagSeedSuccessorValid(staleNext, current, nextReports));
  staleNext = next; staleNext.targets[0].containerUUID = completedSuccessor.targets[0].containerUUID;
  assert(!mothershipNametagSeedSuccessorValid(staleNext, current, nextReports));
  staleNext = next; staleNext.sourceCuts[0].request.requestUUID = completedSuccessor.sourceCuts[0].request.requestUUID;
  assert(!mothershipNametagSeedSuccessorValid(staleNext, current, nextReports));
  // Populate a separate closed registry through the existing serialized TidesDB
  // owner, then exercise the same durable recovery APIs used by Mothership.
  auto rootRecord = readyRecord;
  for (auto& row : rootRecord.seedPlacements) {
    ProdigyStatefulStoreSeedAuthority authority = {};
    assert(mothershipNametagSourceCutAuthority(rootRecord, row, authority));
    row.deliveryDispatched = row.deliveryApplied = row.catchupObserved = true;
    row.nativeSourceCutReceipt = makeNativeReceipt(authority);
  }
  rootRecord.phase = MothershipNametagAllMastersRecord::Phase::remoteSeeded;
  assert(mothershipNametagAllMastersRecordValid(rootRecord));
  String rootBytes, rootHash; auto rootCopy = rootRecord;
  assert(BitseryEngine::serialize(rootBytes, rootCopy) && prodigyComputeSHA256Hex(rootBytes, rootHash, &failure));
  auto chainView = rootRecord;
  Vector<MothershipNametagSeedSuccessor> links; Vector<String> linkBytes, linkHashes;
  for (uint32_t linkIndex = 0; linkIndex < 8; ++linkIndex) {
    auto link = completedSuccessor;
    link.operationUUID = 0x1000000 + linkIndex;
    link.qualificationRunUUID = 0x2000000 + (linkIndex == 1 ? 0 : linkIndex);
    link.kind = linkIndex == 0 ? MothershipNametagSeedSuccessorKind::replica : MothershipNametagSeedSuccessorKind::site;
    link.predecessorSHA256 = rootHash;
    link.predecessorSuccessorUUID = linkIndex ? links.back().operationUUID : 0;
    link.predecessorSuccessorSHA256 = linkIndex ? linkHashes.back() : String{};
    for (auto& target : link.targets) {
      const auto& prior = chainView.seedPlacements[target.predecessorIndex];
      target.targetDeploymentID = prior.targetDeploymentID + 1;
      target.containerUUID = prior.targetContainerUUID + 0x100000;
      target.routeUUID += uint128_t(linkIndex + 1) * 0x10000;
    }
    link.heldReceipt.challengeUUID = 0xf003 + linkIndex;
    link.releaseReceipt.challengeUUID = link.heldReceipt.challengeUUID;
    link.sourceCutReleaseReceipts.clear();
    for (auto& cut : link.sourceCuts) {
      cut.request.operationUUID = link.operationUUID;
      cut.request.requestUUID += uint128_t(linkIndex + 1) * 0x100000;
      cut.request.memberRequestUUID += uint128_t(linkIndex + 1) * 0x100000;
      cut.proof = cut.request; cut.proof.response = cut.proof.ready = true;
      cut.proof.cutUUID = 0x10000000 + cut.request.requestUUID; cut.proof.cutGeneration = linkIndex + 3;
      cut.proof.contentSHA256 = digest('b'); cut.proof.headsSHA256 = digest('c'); cut.released = true;
      auto release = cut.request; release.action = ProdigyStatefulStoreSourceCutAction::release;
      release.cutUUID = cut.proof.cutUUID; release.cutGeneration = cut.proof.cutGeneration;
      release.response = release.released = true; link.sourceCutReleaseReceipts.push_back(release);
    }
    for (uint32_t index = 0; index < link.targets.size(); ++index) {
      auto& target = link.targets[index]; const bool isHeld = index == link.heldTargetIndex;
      assert(mothershipNametagSeedSuccessorAuthority(link, chainView, index, isHeld ? link.heldReceipt.challengeUUID : 0,
          isHeld ? link.heldReceipt.deadlineAtMilliseconds : 0, target.authority));
      target.nativeReceipt = makeNativeReceipt(target.authority);
    }
    link.heldReceipt.runUUID = link.qualificationRunUUID;
    link.heldReceipt.authority = link.targets[link.heldTargetIndex].authority;
    link.releaseReceipt.runUUID = link.qualificationRunUUID;
    link.releaseReceipt.authority = link.heldReceipt.authority;
    assert(mothershipNametagSeedSuccessorValid(link, chainView, {}, false));
    assert(mothershipNametagSeedSuccessorProject(link, chainView));
    String bytes, hash; auto copy = link;
    assert(BitseryEngine::serialize(bytes, copy) && prodigyComputeSHA256Hex(bytes, hash, &failure));
    links.push_back(std::move(link)); linkBytes.push_back(std::move(bytes)); linkHashes.push_back(std::move(hash));
  }
  // A genuine two-successor seed receipt exercises the registry's execution
  // lookup and immutable chain validation, including after the database reopens.
  const auto* seedAdapter = mothershipNametagQualificationAdapter("nametagChaosSeedInterruptionResume");
  auto seedIntent = qualificationIntent(*seedAdapter, rootRecord);
  for (size_t i = 0; i < seedIntent.probeTargets.size(); ++i)
    seedIntent.probeTargets[i].probeDeploymentID = (uint64_t(11) << 48) | (i + 1);
  seedIntent.protocolVersion = seedIntent.seedVersion; seedIntent.runUUID = links[0].qualificationRunUUID;
  seedIntent.executionGeneration = links[0].executionGeneration; seedIntent.seedInputSHA256 = digest('a');
  seedIntent.seedSuccessorOperationUUIDs = {links[0].operationUUID, links[1].operationUUID};
  seedIntent.seedChallengeUUIDs = {links[0].heldReceipt.challengeUUID, links[1].heldReceipt.challengeUUID};
  // The two successor operations need distinct challenge identities.
  assert(seedIntent.seedChallengeUUIDs[0] != seedIntent.seedChallengeUUIDs[1]);
  MothershipNametagSourceBaselineRecord seedBaseline = {};
  auto& bc = seedBaseline.command; bc.operationUUID = rootRecord.intent.sourceBaselineOperationUUID;
  bc.ewrClusterUUID = rootRecord.intent.sites[0].clusterUUID; bc.probeDeploymentID = (uint64_t(11) << 48) | 1;
  bc.hotDeploymentID = rootRecord.intent.sites[0].hotDeploymentID; bc.coldDeploymentID = rootRecord.intent.sites[0].coldDeploymentID;
  bc.radarDeploymentID = rootRecord.intent.sites[0].radarDeploymentID; bc.pulseDeploymentID = rootRecord.intent.sites[0].pulseDeploymentID;
  bc.truthDeploymentID = rootRecord.intent.sites[0].truthDeploymentID; bc.fixtureManifestSHA256 = digest('a'); bc.deadlineAtMilliseconds = 100;
  auto& br = seedBaseline.receipt; br.operationUUID = bc.operationUUID; br.ewrClusterUUID = bc.ewrClusterUUID;
  br.probeDeploymentID = bc.probeDeploymentID; br.localContainerUUID = 0xc001; br.fixtureManifestSHA256 = bc.fixtureManifestSHA256;
  br.canonicalReadbackDigest = digest('b'); br.deadlineAtMilliseconds = 100; br.observedAtMilliseconds = 99;
  for (uint16_t app : {uint16_t(MeshRegistry::Hot::applicationID), uint16_t(MeshRegistry::Cold::applicationID)})
    for (uint32_t group = 0; group < 3; ++group) br.storeDigests.push_back({app, group, digest('c')});
  for (uint16_t app : {uint16_t(MeshRegistry::Pulse::applicationID), uint16_t(MeshRegistry::Radar::applicationID), uint16_t(MeshRegistry::Truth::applicationID)})
    br.storeDigests.push_back({app, 0, digest('c')});
  assert(mothershipNametagSourceBaselineRecordValid(seedBaseline));
  MothershipNametagQualificationExecutionRecord seedExecution = {};
  seedExecution.protocolVersion = seedExecution.seedVersion; seedExecution.intent = seedIntent;
  seedExecution.phase = MothershipNametagQualificationExecutionPhase::converging;
  seedExecution.seedSuccessors = {{links[0].operationUUID, linkHashes[0]}, {links[1].operationUUID, linkHashes[1]}};
  seedExecution.seedBaselineOperationUUID = bc.operationUUID; seedExecution.seedBaselineFixtureSHA256 = br.fixtureManifestSHA256;
  seedExecution.seedBaselineReadbackSHA256 = br.canonicalReadbackDigest;
  assert(mothershipNametagQualificationSeedControlWitnessDigest(seedExecution, seedExecution.seedControlWitnessDigest));
  auto seedCurrent = rootRecord;
  assert(mothershipNametagSeedSuccessorProject(links[0], seedCurrent));
  assert(mothershipNametagSeedSuccessorProject(links[1], seedCurrent));
  for (size_t i = 0; i < 3; ++i) {
    const auto& stores = seedCurrent.intent.sites[i];
    seedExecution.seedStoreDeploymentIDs[i] = {stores.hotDeploymentID, stores.coldDeploymentID, stores.radarDeploymentID,
      stores.pulseDeploymentID, seedCurrent.intent.sites[0].truthDeploymentID};
    ProdigyNametagQualificationApplicationReceipt r = {}; r.protocolVersion = r.seedReadbackVersion;
    r.runUUID = seedIntent.runUUID; r.row = uint8_t(seedIntent.row); r.direction = uint8_t(seedIntent.direction);
    r.executionGeneration = seedIntent.executionGeneration; r.rowID = seedIntent.rowID; r.descriptor = seedIntent.descriptor;
    r.localClusterUUID = seedIntent.probeTargets[i].clusterUUID; r.deploymentID = seedIntent.probeTargets[i].probeDeploymentID;
    r.localContainerUUID = 0x5500 + i; r.startedAtMilliseconds = seedIntent.startedAtMilliseconds;
    r.deadlineAtMilliseconds = seedIntent.deadlineAtMilliseconds; r.convergenceDeadlineAtMilliseconds = seedIntent.convergenceDeadlineAtMilliseconds;
    r.observedAtMilliseconds = r.startedAtMilliseconds + 1; r.witnessedResult = seedIntent.descriptor.expectedWitness;
    r.canonicalWitnessReceipt.assign("native-seed-readback"_ctv); r.witnessDigest = digest('d'); r.joinedWitnessDigest = digest('e');
    r.seedControlWitnessDigest = seedExecution.seedControlWitnessDigest; r.seedBaselineReadbackSHA256 = br.canonicalReadbackDigest;
    seedExecution.seedFinalReadbacks.push_back(r);
  }
  assert(mothershipNametagQualificationExecutionRecordValid(seedExecution));
  for (size_t i = 0; i < seedExecution.seedSuccessors.size(); ++i) {
    const auto& link = links[i]; const auto& ref = seedExecution.seedSuccessors[i];
    String checkHash; assert(prodigyComputeSHA256Hex(linkBytes[i], checkHash) && checkHash == ref.sha256);
    assert(link.operationUUID == ref.operationUUID && link.predecessorOperationUUID == seedIntent.allMastersOperationUUID &&
        link.predecessorSHA256 == rootHash && link.qualificationRunUUID == seedIntent.runUUID &&
        link.executionGeneration == seedIntent.executionGeneration && link.qualificationRow == uint8_t(seedIntent.row) &&
        link.site == 1 && link.stage == MothershipNametagSeedSuccessorStage::complete &&
        link.heldReceipt.challengeUUID == seedIntent.seedChallengeUUIDs[i]);
    assert(link.kind == (i == 0 ? MothershipNametagSeedSuccessorKind::replica : MothershipNametagSeedSuccessorKind::site));
    if (i) assert(link.predecessorSuccessorUUID == links[i-1].operationUUID && link.predecessorSuccessorSHA256 == linkHashes[i-1]);
  }
  MothershipNametagQualificationReceipt seedReceipt = {};
  assert(mothershipNametagQualificationBuildReceipt(seedIntent, seedExecution.seedFinalReadbacks, String("topology"),
      seedIntent.startedAtMilliseconds + 1, seedReceipt, &failure, &seedExecution));
  const auto durableRoot = std::filesystem::temp_directory_path() / "prodigy-seed-lineage-unit";
  std::filesystem::remove_all(durableRoot); String durablePath(durableRoot.c_str());
  { MothershipClusterRegistry initialize(durablePath); }
  auto head = placementIntent; head.predecessorSHA256 = rootHash; head.operationUUID = links.back().operationUUID;
  head.predecessorSuccessorUUID = links[6].operationUUID; head.predecessorSuccessorSHA256 = linkHashes[6];
  String headBytes; auto headCopy = head; assert(BitseryEngine::serialize(headBytes, headCopy));
  {
    TidesDB raw(durablePath, TidesDB::Durability::full); String key;
    String opKey; opKey.assignItoh(seedIntent.runUUID);
    String seedKey; seedKey.assign("nametagChaosSeedInterruptionResume/"_ctv); seedKey.append(opKey);
    String seedBytes; auto intentCopy = seedIntent; assert(BitseryEngine::serialize(seedBytes, intentCopy));
    assert(raw.write("nametag_qualification_intents"_ctv, seedKey, seedBytes, &failure));
    auto executionCopy = seedExecution; assert(BitseryEngine::serialize(seedBytes, executionCopy));
    assert(raw.write("nametag_qualification_executions"_ctv, seedKey, seedBytes, &failure));
    auto receiptCopy = seedReceipt; assert(BitseryEngine::serialize(seedBytes, receiptCopy));
    assert(raw.write("nametag_qualification_receipts"_ctv, seedKey, seedBytes, &failure));
    auto baselineCopy = seedBaseline; assert(BitseryEngine::serialize(seedBytes, baselineCopy));
    String baselineKey; baselineKey.assignItoh(bc.operationUUID);
    assert(raw.write("nametag_source_baseline_records"_ctv, baselineKey, seedBytes, &failure));
    key.assignItoh(rootRecord.intent.operationUUID); assert(raw.write("nametag_all_masters"_ctv, key, rootBytes, &failure));
    for (size_t i = 0; i < links.size(); ++i) {
      key.assign("seed-successor:"_ctv); String op; op.assignItoh(links[i].operationUUID); key.append(op);
      assert(raw.write("nametag_all_masters"_ctv, key, linkBytes[i], &failure));
    }
    // An unfinished, otherwise valid successor must remain resumable rather
    // than being mistaken for an immutable completion or corrupt data.
    auto unfinished = successor; unfinished.predecessorSHA256 = rootHash;
    assert(mothershipNametagSeedSuccessorValid(unfinished, rootRecord, successorReports));
    String unfinishedBytes; assert(BitseryEngine::serialize(unfinishedBytes, unfinished));
    key.assign("seed-successor:"_ctv); String unfinishedOp; unfinishedOp.assignItoh(unfinished.operationUUID); key.append(unfinishedOp);
    assert(raw.write("nametag_all_masters"_ctv, key, unfinishedBytes, &failure));
    key.assign("seed-successor:"_ctv); String corruptOp; corruptOp.assignItoh(uint128_t(0xf099)); key.append(corruptOp);
    assert(raw.write("nametag_all_masters"_ctv, key, String("invalid"), &failure));
    key.assign("seed-successor-head:"_ctv); String op; op.assignItoh(rootRecord.intent.operationUUID); key.append(op);
    assert(raw.write("nametag_all_masters"_ctv, key, headBytes, &failure));
    auto activeQualification = qualificationIntent(*mothershipNametagQualificationAdapter("nametagChaosSeedInterruptionResume"), rootRecord);
    activeQualification.runUUID = placementIntent.qualificationRunUUID; activeQualification.executionGeneration = placementIntent.executionGeneration;
    activeQualification.startedAtMilliseconds = Time::now<TimeResolution::ms>();
    activeQualification.deadlineAtMilliseconds = activeQualification.startedAtMilliseconds + int64_t(activeQualification.deadlineSeconds) * 1000;
    activeQualification.convergenceDeadlineAtMilliseconds = activeQualification.startedAtMilliseconds + int64_t(activeQualification.convergenceSeconds) * 1000;
    String qualificationBytes; assert(BitseryEngine::serialize(qualificationBytes, activeQualification));
    key.assign("nametagChaosSeedInterruptionResume/"_ctv); op.assignItoh(activeQualification.runUUID); key.append(op);
    assert(raw.write("nametag_qualification_intents"_ctv, key, qualificationBytes, &failure));
  }
  {
    MothershipClusterRegistry durable(durablePath); MothershipNametagAllMastersRecord loaded = {};
    MothershipNametagSeedSuccessor recoveredSuccessor; String recoveredDigest; bool completedFound = false;
    assert(durable.loadCompletedNametagSeedSuccessor(links[1].operationUUID, recoveredSuccessor, recoveredDigest, completedFound, &failure));
    assert(completedFound && recoveredSuccessor.operationUUID == links[1].operationUUID && recoveredDigest == linkHashes[1]);
    assert(durable.loadCompletedNametagSeedSuccessor(uint128_t(0xf098), recoveredSuccessor, recoveredDigest, completedFound, &failure));
    assert(!completedFound && recoveredDigest.empty());
    assert(durable.loadCompletedNametagSeedSuccessor(successor.operationUUID, recoveredSuccessor, recoveredDigest, completedFound, &failure));
    assert(!completedFound && recoveredDigest.empty());
    assert(!durable.loadCompletedNametagSeedSuccessor(uint128_t(0xf099), recoveredSuccessor, recoveredDigest, completedFound, &failure));
    MothershipNametagQualificationReceipt loadedSeed; bool seedFound = false, seedResumed = false;
    MothershipNametagSourceBaselineRecord durableBaseline; bool baselineFound = false;
    assert(durable.loadNametagSourceBaseline(bc.operationUUID, durableBaseline, baselineFound, &failure) && baselineFound);
    for (size_t i = 0; i < 2; ++i) {
      MothershipNametagAllMastersRecord durableView;
      assert(durable.loadNametagSeedSuccessorPrior(rootRecord.intent.operationUUID, rootHash,
          links[i].operationUUID, linkHashes[i], durableView, &failure));
      for (size_t j = 0; j < 3; ++j) {
        const auto& site = durableView.intent.sites[j];
        const std::array<uint64_t, 5> expected = {site.hotDeploymentID, site.coldDeploymentID, site.radarDeploymentID,
            site.pulseDeploymentID, durableView.intent.sites[0].truthDeploymentID};
        if (i == 1) assert(seedExecution.seedStoreDeploymentIDs[j] == expected);
      }
    }
    assert(durable.loadNametagQualificationReceipt(*seedAdapter, seedIntent.runUUID, loadedSeed, seedFound, &failure) && seedFound);
    auto forgedSeed = seedReceipt;
    forgedSeed.applicationReceipts[0].seedBaselineReadbackSHA256 = digest('f');
    assert(mothershipNametagQualificationReceiptValid(forgedSeed));
    assert(!durable.nametagQualificationSeedReceiptMatchesExecution(*seedAdapter, seedIntent, forgedSeed, &failure));
    assert(!durable.recordNametagQualificationReceipt(*seedAdapter, forgedSeed, loadedSeed, seedResumed, &failure));
    uint128_t latest = 0; String latestHash; uint32_t depth = 0;
    assert(durable.loadNametagAllMastersCurrentView(rootRecord.intent.operationUUID, loaded, latest, latestHash, &failure));
    assert(latest == links.back().operationUUID && latestHash == linkHashes.back());
    assert(durable.loadNametagSeedSuccessorPrior(rootRecord.intent.operationUUID, rootHash, latest, latestHash, loaded, &failure, &depth) && depth == 8);
    assert(!durable.loadNametagSeedSuccessorPrior(rootRecord.intent.operationUUID, rootHash, latest, digest('0'), loaded, &failure));
    auto ninth = placementIntent; ninth.operationUUID = 0x3000000; ninth.predecessorSHA256 = rootHash;
    ninth.predecessorSuccessorUUID = latest; ninth.predecessorSuccessorSHA256 = latestHash;
    for (auto& plan : ninth.plans) {
      plan.previousMembers.clear();
      for (const auto& row : chainView.seedPlacements) {
        if (row.site != ninth.site || row.applicationID != plan.applicationID) continue;
        plan.previousDeploymentID = row.targetDeploymentID;
        plan.successorDeploymentID = row.targetDeploymentID + 1;
        plan.previousMembers.push_back({row.targetContainerUUID, 0x1234});
      }
    }
    assert(mothershipNametagSeedSuccessorPlacementIntentValid(ninth, chainView));
    bool resumedNinth = false;
    assert(!durable.persistNametagSeedSuccessorPlacementIntent(ninth, resumedNinth, &failure));
    uint128_t stillLatest = 0; String stillHash;
    assert(durable.loadNametagAllMastersCurrentView(rootRecord.intent.operationUUID, loaded, stillLatest, stillHash, &failure) && stillLatest == latest && stillHash == latestHash);
  }
  {
    TidesDB raw(durablePath, TidesDB::Durability::full); String key, op;
    key.assign("nametagChaosSeedInterruptionResume/"_ctv); op.assignItoh(seedIntent.runUUID); key.append(op);
    auto wrong = seedExecution; wrong.seedSuccessors[0].sha256 = digest('0');
    assert(mothershipNametagQualificationSeedControlWitnessDigest(wrong, wrong.seedControlWitnessDigest));
    for (auto& r : wrong.seedFinalReadbacks) r.seedControlWitnessDigest = wrong.seedControlWitnessDigest;
    String bytes; assert(BitseryEngine::serialize(bytes, wrong));
    assert(raw.write("nametag_qualification_executions"_ctv, key, bytes, &failure));
  }
  {
    MothershipClusterRegistry durable(durablePath); MothershipNametagQualificationReceipt loadedSeed; bool found = false;
    assert(!durable.loadNametagQualificationReceipt(*seedAdapter, seedIntent.runUUID, loadedSeed, found, &failure));
  }
  std::filesystem::remove_all(durableRoot);
  const auto repairRoot = std::filesystem::temp_directory_path() / "prodigy-seed-head-repair-unit";
  std::filesystem::remove_all(repairRoot); String repairPath(repairRoot.c_str());
  { MothershipClusterRegistry initialize(repairPath); }
  auto repair = placementIntent; repair.predecessorSHA256 = rootHash;
  auto qualification = qualificationIntent(*mothershipNametagQualificationAdapter("nametagChaosSeedInterruptionResume"), rootRecord);
  qualification.runUUID = repair.qualificationRunUUID; qualification.executionGeneration = repair.executionGeneration;
  String repairBytes, qualificationBytes; auto repairCopy = repair; auto qualificationCopy = qualification;
  assert(BitseryEngine::serialize(repairBytes, repairCopy) && BitseryEngine::serialize(qualificationBytes, qualificationCopy));
  {
    TidesDB raw(repairPath, TidesDB::Durability::full); String key, op;
    key.assignItoh(rootRecord.intent.operationUUID); assert(raw.write("nametag_all_masters"_ctv, key, rootBytes, &failure));
    key.assign("seed-successor-head:"_ctv); op.assignItoh(rootRecord.intent.operationUUID); key.append(op);
    assert(raw.write("nametag_all_masters"_ctv, key, repairBytes, &failure));
    key.assign("nametagChaosSeedInterruptionResume/"_ctv); op.assignItoh(qualification.runUUID); key.append(op);
    assert(raw.write("nametag_qualification_intents"_ctv, key, qualificationBytes, &failure));
  }
  {
    MothershipClusterRegistry durable(repairPath); bool resumedRepair = false;
    assert(durable.persistNametagSeedSuccessorPlacementIntent(repair, resumedRepair, &failure));
    MothershipNametagSeedSuccessorPlacementIntent recovered = {};
    assert(durable.loadNametagSeedSuccessorPlacementIntent(repair.operationUUID, recovered, &failure));
    for (const auto& item : plannedPlacement.routePlan) {
      CousinRouteRecord recordedRoute = {}; CousinRouteApplyReceipt recordedReceipt = {}; bool resumedRoute = false;
      assert(durable.recordCousinRoute(item.previousRoute, recordedRoute, resumedRoute, &failure));
      assert(durable.recordCousinRouteApplyReceipt(item.previousSourceReceipt, recordedReceipt, resumedRoute, &failure));
      assert(durable.recordCousinRouteApplyReceipt(item.previousDestinationReceipt, recordedReceipt, resumedRoute, &failure));
    }
    assert(durable.installNametagSeedSuccessorRoutePlan(repair.operationUUID, plannedPlacement.routePlan, &failure));
    assert(durable.installNametagSeedSuccessorRoutePlan(repair.operationUUID, plannedPlacement.routePlan, &failure));
    assert(durable.loadNametagSeedSuccessorPlacementIntent(repair.operationUUID, recovered, &failure) && recovered.routePlan.size() == 8);
    auto conflictingRoutes = plannedPlacement.routePlan; ++conflictingRoutes[0].desiredRoute.operationUUID;
    assert(!durable.installNametagSeedSuccessorRoutePlan(repair.operationUUID, conflictingRoutes, &failure));
    assert(durable.persistNametagSeedSuccessorPlacementIntent(repair, resumedRepair, &failure) && resumedRepair);
    auto changed = repair; ++changed.plans[0].cancellationOperationUUID;
    assert(!durable.persistNametagSeedSuccessorPlacementIntent(changed, resumedRepair, &failure));
  }
  std::filesystem::remove_all(repairRoot);
  MothershipNametagSeedSuccessor persistedSuccessor = {}; bool successorResumed = false;
  // The predecessor in the registry is not complete and cannot authorize a successor.
  assert(!registry->persistNametagSeedSuccessor(replicaSuccessor, successorReports, persistedSuccessor, successorResumed, &failure));
  assert(!registry->loadNametagSeedSuccessor(replicaSuccessor.operationUUID, successorReports, persistedSuccessor, &failure));
  ProdigyStatefulStoreSeedAuthority cutAuthority = {};
  assert(mothershipNametagSourceCutAuthority(readyRecord, readyRecord.seedPlacements.front(), cutAuthority));
  assert(cutAuthority.sourceBaselineOperationUUID == readyRecord.intent.sourceBaselineOperationUUID &&
      cutAuthority.sourceMemberRequestUUID == readyRecord.sourceCuts.front().request.memberRequestUUID &&
      cutAuthority.expectedCatchupWatermarkSHA256.empty());
  auto markedRecord = readyRecord;
  markedRecord.protocolVersion = MothershipNametagAllMastersRecord::qualificationSeedFaultVersion;
  auto markedRow = std::find_if(markedRecord.seedPlacements.begin(), markedRecord.seedPlacements.end(),
      [](const auto& value) { return value.storeKind == DeploymentIdentityStoreKind::kv; });
  assert(markedRow != markedRecord.seedPlacements.end());
  markedRow->qualificationRunUUID = 0x701; markedRow->qualificationChallengeUUID = 0x702;
  markedRow->qualificationExecutionGeneration = 1; markedRow->qualificationDeadlineAtMilliseconds = Time::now<TimeResolution::ms>() + 30000;
  ProdigyStatefulStoreSeedAuthority markedAuthority = {};
  assert(mothershipNametagAllMastersRecordValid(markedRecord) &&
      mothershipNametagSourceCutAuthority(markedRecord, *markedRow, markedAuthority) &&
      markedAuthority.protocolVersion == ProdigyStatefulStoreSeedAuthority::qualificationSeedFaultVersion &&
      markedAuthority.qualificationChallengeUUID == 0x702);
  String markedBytes; auto markedCopy = markedRecord; MothershipNametagAllMastersRecord decodedMarked = {};
  assert(BitseryEngine::serialize(markedBytes, markedCopy) && BitseryEngine::deserializeSafe(markedBytes, decodedMarked) &&
      mothershipNametagAllMastersRecordValid(decodedMarked));
  auto malformedMarker = markedRecord;
  auto badRow = std::find_if(malformedMarker.seedPlacements.begin(), malformedMarker.seedPlacements.end(),
      [](const auto& value) { return value.qualificationChallengeUUID != 0; });
  badRow->qualificationRunUUID = 0;
  assert(!mothershipNametagAllMastersRecordValid(malformedMarker));
  auto alteredRecord = readyRecord; ++alteredRecord.seedPlacements.front().sourceContainerUUID;
  assert(!mothershipNametagAllMastersRecordValid(alteredRecord));
  auto fakeCompleted = readyRecord; fakeCompleted.seedPlacements.front().deliveryApplied = true;
  fakeCompleted.seedPlacements.front().catchupObserved = true;
  fakeCompleted.phase = MothershipNametagAllMastersRecord::Phase::remoteSeeding;
  assert(!mothershipNametagAllMastersRecordValid(fakeCompleted));
  for (uint32_t index = 1; index < checkpoint.sourceCuts.size(); ++index) {
    assert(registry->updateNametagAllMastersSourceCut(cuts.intent.operationUUID, index, true, nullptr, checkpoint, &failure));
    auto reply = checkpoint.sourceCuts[index].request; reply.response = reply.ready = true;
    reply.memberRequestUUID = 0xd100 + index; reply.cutUUID = 0xe100 + index; reply.cutGeneration = 1;
    reply.contentSHA256 = digest('b'); reply.headsSHA256 = digest('c');
    assert(registry->updateNametagAllMastersSourceCut(cuts.intent.operationUUID, index, false, &reply, checkpoint, &failure));
  }
  assert(registry->installNametagAllMastersSourceCutPlacements(cuts.intent.operationUUID, cutReports[0], cutReports[1],
      cutReports[2], cutReports[3], digest('f'), checkpoint, &failure));
  uint32_t faultIndex = 0;
  while (faultIndex < checkpoint.seedPlacements.size() && checkpoint.seedPlacements[faultIndex].storeKind != DeploymentIdentityStoreKind::kv) ++faultIndex;
  assert(faultIndex < checkpoint.seedPlacements.size());
  ProdigyNametagQualificationSeedFault seedFault = {};
  assert(mothershipNametagSourceCutAuthority(checkpoint, checkpoint.seedPlacements[faultIndex], seedFault.authority));
  seedFault.runUUID = 0x801; seedFault.challengeUUID = 0x802; seedFault.executionGeneration = 1;
  seedFault.deadlineAtMilliseconds = Time::now<TimeResolution::ms>() + 30000;
  seedFault.stage = ProdigyNametagQualificationSeedFaultStage::arm;
  seedFault.authority.protocolVersion = ProdigyStatefulStoreSeedAuthority::qualificationSeedFaultVersion;
  seedFault.authority.qualificationRunUUID = seedFault.runUUID;
  seedFault.authority.qualificationChallengeUUID = seedFault.challengeUUID;
  seedFault.authority.qualificationExecutionGeneration = seedFault.executionGeneration;
  seedFault.authority.qualificationDeadlineAtMilliseconds = seedFault.deadlineAtMilliseconds;
  assert(registry->recordNametagAllMastersSeedFault(cuts.intent.operationUUID, faultIndex, seedFault, checkpoint, &failure));
  assert(registry->recordNametagAllMastersSeedFault(cuts.intent.operationUUID, faultIndex, seedFault, checkpoint, &failure));
  auto changedFault = seedFault; ++changedFault.challengeUUID; ++changedFault.authority.qualificationChallengeUUID;
  assert(!registry->recordNametagAllMastersSeedFault(cuts.intent.operationUUID, faultIndex, changedFault, checkpoint, &failure));
  assert(registry->claimNametagAllMastersSeedDelivery(cuts.intent.operationUUID, faultIndex, checkpoint, &failure));
  assert(checkpoint.seedPlacements[faultIndex].deliveryDispatched &&
      checkpoint.seedPlacements[faultIndex].qualificationChallengeUUID == seedFault.challengeUUID);
  uint32_t claimedIndex = faultIndex + 1;
  while (claimedIndex < checkpoint.seedPlacements.size() && checkpoint.seedPlacements[claimedIndex].storeKind != DeploymentIdentityStoreKind::kv) ++claimedIndex;
  assert(claimedIndex < checkpoint.seedPlacements.size());
  assert(registry->claimNametagAllMastersSeedDelivery(cuts.intent.operationUUID, claimedIndex, checkpoint, &failure));
  auto lateFault = seedFault;
  assert(mothershipNametagSourceCutAuthority(checkpoint, checkpoint.seedPlacements[claimedIndex], lateFault.authority));
  lateFault.authority.protocolVersion = ProdigyStatefulStoreSeedAuthority::qualificationSeedFaultVersion;
  lateFault.authority.qualificationRunUUID = lateFault.runUUID;
  lateFault.authority.qualificationChallengeUUID = lateFault.challengeUUID;
  lateFault.authority.qualificationExecutionGeneration = lateFault.executionGeneration;
  lateFault.authority.qualificationDeadlineAtMilliseconds = lateFault.deadlineAtMilliseconds;
  assert(!registry->recordNametagAllMastersSeedFault(cuts.intent.operationUUID, claimedIndex, lateFault, checkpoint, &failure));
  assert(registry->claimNametagAllMastersSeedDelivery(cuts.intent.operationUUID, 0, checkpoint, &failure));
  auto row = checkpoint.seedPlacements.front();
  assert(registry->markNametagAllMastersSeedDelivered(cuts.intent.operationUUID, row, checkpoint, &failure));
  assert(mothershipNametagSourceCutAuthority(checkpoint, row, cutAuthority));
  ProdigyStatefulStoreReceipt native = {};
  native.protocolVersion = ProdigyStatefulStoreReceipt::sourceCutVersion;
  native.localContainerUUID = row.targetContainerUUID; native.localClusterUUID = row.targetClusterUUID;
  native.deploymentID = row.targetDeploymentID; native.storeKind = row.storeKind; native.shardGroup = row.shardGroup;
  native.nShardGroups = cutAuthority.nShardGroups; native.writable = true; native.siblingSessionUUID = 10;
  native.siblingSessionGeneration = 1; native.siblingSessionHealthy = true;
  native.seededFromClusterUUID = row.sourceClusterUUID; native.seededFromContainerUUID = row.sourceContainerUUID;
  native.seedGeneration = row.seedGeneration; native.seedFixtureSHA256 = row.fixtureSHA256; native.appliedWatermarkSHA256 = digest('a');
  native.sourceContentWatermarkSHA256 = row.sourceContentWatermarkSHA256; native.sourceCatchupWatermarkSHA256 = row.sourceCatchupWatermarkSHA256;
  native.operationUUID = cutAuthority.operationUUID; native.sourceBaselineOperationUUID = cutAuthority.sourceBaselineOperationUUID;
  native.sourceRequestUUID = cutAuthority.sourceRequestUUID; native.sourceMemberRequestUUID = cutAuthority.sourceMemberRequestUUID;
  native.sourceDeploymentID = cutAuthority.sourceDeploymentID; native.cutUUID = cutAuthority.cutUUID;
  native.seedRouteUUID = cutAuthority.seedRouteUUID; native.cutGeneration = cutAuthority.cutGeneration; native.retainUntilMilliseconds = cutAuthority.retainUntilMilliseconds;
  native.materializedContentSHA256 = row.sourceContentWatermarkSHA256; native.materializedHeadsSHA256 = row.sourceCatchupWatermarkSHA256;
  native.cutMaterialized = native.committedHeadsDominateCut = true;
  for (auto& member : cutReports[0][row.site].statefulRuntimeCohort)
    if (member.containerUUID == row.targetContainerUUID) member.nativeSourceCutReceipt = native;
  assert(registry->recordNametagAllMastersSeedObservations(cuts.intent.operationUUID, cutReports[0], cutReports[1], cutReports[2],
      cutReports[3], checkpoint, &failure));
  assert(checkpoint.seedPlacements.front().catchupObserved &&
      prodigyStatefulStoreReceiptMatchesSourceCutAuthority(checkpoint.seedPlacements.front().nativeSourceCutReceipt, cutAuthority));
  assert(registry->loadNametagAllMasters(cuts.intent.operationUUID, checkpoint, &failure) &&
      checkpoint.seedPlacements.front().nativeSourceCutReceipt.cutUUID == native.cutUUID);
  auto changedAllMasters = allMasters; changedAllMasters.requestSHA256 = digest('z');
  assert(!registry->persistNametagAllMasters(changedAllMasters, recordedAllMasters, resumed, &failure));

  auto reorderedTargets = intent; std::swap(reorderedTargets.probeTargets[0], reorderedTargets.probeTargets[1]);
  assert(!registry->persistNametagQualificationIntent(adapter, reorderedTargets, recordedIntent, resumed, &failure));
  auto wrongTarget = intent; wrongTarget.probeTargets[2].clusterUUID = 0x999;
  assert(!registry->persistNametagQualificationIntent(adapter, wrongTarget, recordedIntent, resumed, &failure));

  assert(registry->persistNametagQualificationIntent(adapter, intent, recordedIntent, resumed, &failure) && !resumed);
  assert(recordedIntent.allMastersOperationUUID == allMasters.intent.operationUUID);
  {
    const auto *faultAdapter = mothershipNametagQualificationAdapter("nametagChaosPermissionRevokeReinstall");
    assert(faultAdapter != nullptr);
    auto faultIntent = qualificationIntent(*faultAdapter, allMasters);
    faultIntent.runUUID += 0x901; faultIntent.protocolVersion = MothershipNametagQualificationIntent::cousinRecoveryVersion;
    const int64_t now = Time::now<TimeResolution::ms>();
    faultIntent.startedAtMilliseconds = now; faultIntent.deadlineAtMilliseconds = now + int64_t(faultIntent.deadlineSeconds) * 1000;
    faultIntent.convergenceDeadlineAtMilliseconds = now + int64_t(faultIntent.convergenceSeconds) * 1000;
    MothershipNametagQualificationCousinRecovery reference = {};
    reference.routeUUID = 0x111; reference.withdrawOperationUUID = 0x112; reference.successorRouteUUID = 0x113;
    reference.successorRouteOperationUUID = 0x114; reference.successorPermissionUUID = 0x115;
    faultIntent.cousinRecoveries.push_back(reference);
    assert(registry->persistNametagQualificationIntent(*faultAdapter, faultIntent, recordedIntent, resumed, &failure));
    MothershipNametagQualificationExecutionRecord faultExecution = {};
    assert(registry->persistNametagQualificationExecutionPrepared(*faultAdapter, faultIntent, faultExecution, resumed, &failure));
    assert(!registry->advanceNametagQualificationExecution(*faultAdapter, faultIntent,
        MothershipNametagQualificationExecutionPhase::prepared, MothershipNametagQualificationExecutionPhase::faultApplied,
        faultExecution, resumed, &failure));
    auto binding = cousinBinding(); binding.route.issuedAtMs = now - 1000; binding.route.expiresAtMs = now + 600000;
    for (auto *receipt : {&binding.sourceReceipt, &binding.destinationReceipt})
      assert(cousinRouteAuthorizationDigest(binding.route, receipt->authorizationSHA256));
    CousinRouteRecord route = {};
    assert(registry->recordCousinRoute(binding.route, route, resumed, &failure));
    CousinRouteApplyReceipt receipt = {};
    assert(registry->recordCousinRouteApplyReceipt(binding.sourceReceipt, receipt, resumed, &failure));
    assert(registry->recordCousinRouteApplyReceipt(binding.destinationReceipt, receipt, resumed, &failure));
    Vector<MothershipNametagQualificationExecutionRecord::CousinRecoveryBinding> bindings = {binding};
    assert(registry->recordNametagQualificationCousinRecoveryBindings(*faultAdapter, faultIntent, bindings,
        faultExecution, resumed, &failure) && !resumed);
    assert(registry->recordNametagQualificationCousinRecoveryBindings(*faultAdapter, faultIntent, bindings,
        faultExecution, resumed, &failure) && resumed);
    bindings[0].sourcePermission.canonicalPlanSHA256 = digest('f');
    assert(!registry->recordNametagQualificationCousinRecoveryBindings(*faultAdapter, faultIntent, bindings,
        faultExecution, resumed, &failure));
    ProdigyNametagQualificationCousinTransport challenge = {};
    challenge.runUUID = faultIntent.runUUID; challenge.memberRequestUUID = 0x741; challenge.executionGeneration = faultIntent.executionGeneration;
    challenge.deadlineAtMilliseconds = faultIntent.deadlineAtMilliseconds; challenge.stage = ProdigyNametagQualificationCousinStage::arm;
    auto& session = challenge.session;
    session.pairUUID = binding.route.pairUUID; session.routeUUID = binding.route.routeUUID;
    session.sourcePermissionUUID = binding.sourcePermission.permissionUUID; session.destinationPermissionUUID = binding.destinationPermission.permissionUUID;
    session.sourceClusterUUID = binding.route.sourceClusterUUID; session.destinationClusterUUID = binding.route.destinationClusterUUID;
    session.sourceDeploymentID = binding.sourcePermission.localDeploymentID; session.destinationDeploymentID = binding.destinationPermission.localDeploymentID;
    session.sourceContainerUUID = 0x742; session.destinationContainerUUID = 0x743; session.sessionUUID = 0x744; session.sessionGeneration = 1;
    session.routeGeneration = binding.route.generation; session.sourcePermissionAuthorityGeneration = binding.sourcePermission.acceptedAuthorityGeneration;
    session.successorRouteUUID = reference.successorRouteUUID; session.successorRouteGeneration = 1;
    session.successorSourcePermissionUUID = reference.successorPermissionUUID;
    assert(registry->recordNametagQualificationCousinNativeWitness(*faultAdapter, faultIntent, 0, challenge, faultExecution, &failure));
    assert(registry->recordNametagQualificationCousinNativeWitness(*faultAdapter, faultIntent, 0, challenge, faultExecution, &failure));
    auto conflict = challenge; ++conflict.memberRequestUUID;
    assert(!registry->recordNametagQualificationCousinNativeWitness(*faultAdapter, faultIntent, 0, conflict, faultExecution, &failure));
    assert(!registry->advanceNametagQualificationExecution(*faultAdapter, faultIntent,
        MothershipNametagQualificationExecutionPhase::prepared, MothershipNametagQualificationExecutionPhase::faultApplied,
        faultExecution, resumed, &failure));
    auto armed = challenge; armed.response = armed.ready = true; armed.session.healthy = true;
    assert(registry->recordNametagQualificationCousinNativeWitness(*faultAdapter, faultIntent, 0, armed, faultExecution, &failure));
    assert(registry->markNametagQualificationCousinRecoveryAborting(*faultAdapter, faultIntent, faultExecution, &failure));
    auto withdrawn = binding.route; withdrawn.operationUUID = reference.withdrawOperationUUID; withdrawn.generation++;
    withdrawn.state = CousinRouteState::withdrawn; withdrawn.withdrawalGeneration = withdrawn.generation;
    withdrawn.withdrawnAtMs = faultIntent.startedAtMilliseconds;
    assert(registry->recordCousinRoute(withdrawn, route, resumed, &failure));
    assert(!registry->finishNametagQualificationCousinRecoveryAbort(*faultAdapter, faultIntent, faultExecution, &failure));
    auto successor = binding.route; successor.routeUUID = reference.successorRouteUUID;
    successor.operationUUID = reference.successorRouteOperationUUID;
    assert(registry->recordCousinRoute(successor, route, resumed, &failure));
    auto sourceReceipt = binding.sourceReceipt, destinationReceipt = binding.destinationReceipt;
    for (auto *side : {&sourceReceipt, &destinationReceipt}) {
      side->routeUUID = successor.routeUUID;
      assert(cousinRouteAuthorizationDigest(successor, side->authorizationSHA256));
      assert(registry->recordCousinRouteApplyReceipt(*side, receipt, resumed, &failure));
    }
    assert(!registry->finishNametagQualificationCousinRecoveryAbort(*faultAdapter, faultIntent, faultExecution, &failure));
    auto withdrawnSource = binding.sourceReceipt, withdrawnDestination = binding.destinationReceipt;
    for (auto *side : {&withdrawnSource, &withdrawnDestination}) {
      side->generation = withdrawn.generation; side->installedState = withdrawn.state; side->localRuntimeRevision++;
      assert(cousinRouteAuthorizationDigest(withdrawn, side->authorizationSHA256));
      assert(registry->recordCousinRouteApplyReceipt(*side, receipt, resumed, &failure));
    }
    assert(registry->finishNametagQualificationCousinRecoveryAbort(*faultAdapter, faultIntent, faultExecution, &failure));
    assert(faultExecution.phase == MothershipNametagQualificationExecutionPhase::failed && faultExecution.cousinRecoveryAborting);
  }
  // The execution owner is separate from the completed receipt but embeds the
  // exact v4 intent. A nonfault row reaches verified as its terminal phase;
  // faultRestored is not fabricated from generic healthy evidence.
  const auto *nonfaultAdapter = std::find_if(std::begin(mothershipNametagQualificationAdapters),
      std::end(mothershipNametagQualificationAdapters), [](const auto& value) {
        return value.direction == MothershipNametagQualificationDirection::injection &&
            mothershipNametagQualificationDescriptor(value.row).fault == ProdigyNametagQualificationFault::none;
      });
  assert(nonfaultAdapter != std::end(mothershipNametagQualificationAdapters));
  auto phaseIntent = qualificationIntent(*nonfaultAdapter, allMasters);
  phaseIntent.runUUID += 0x400; phaseIntent.executionGeneration += 0x400;
  assert(registry->persistNametagQualificationIntent(*nonfaultAdapter, phaseIntent, recordedIntent, resumed, &failure));
  MothershipNametagQualificationExecutionRecord execution = {};
  assert(registry->persistNametagQualificationExecutionPrepared(*nonfaultAdapter, phaseIntent, execution, resumed, &failure) && !resumed);
  assert(execution.phase == MothershipNametagQualificationExecutionPhase::prepared);
  auto changedExecutionIntent = phaseIntent; ++changedExecutionIntent.executionGeneration;
  assert(!registry->persistNametagQualificationExecutionPrepared(*nonfaultAdapter, changedExecutionIntent, execution, resumed, &failure));
  assert(!registry->advanceNametagQualificationExecution(*nonfaultAdapter, phaseIntent,
      MothershipNametagQualificationExecutionPhase::prepared,
      MothershipNametagQualificationExecutionPhase::faultApplied, execution, resumed, &failure));
  assert(registry->advanceNametagQualificationExecution(*nonfaultAdapter, phaseIntent,
      MothershipNametagQualificationExecutionPhase::prepared,
      MothershipNametagQualificationExecutionPhase::workloadIssued, execution, resumed, &failure));
  assert(!resumed && execution.phase == MothershipNametagQualificationExecutionPhase::workloadIssued);
  assert(registry->advanceNametagQualificationExecution(*nonfaultAdapter, phaseIntent,
      MothershipNametagQualificationExecutionPhase::workloadIssued,
      MothershipNametagQualificationExecutionPhase::converging, execution, resumed, &failure));
  assert(!registry->advanceNametagQualificationExecution(*nonfaultAdapter, phaseIntent,
      MothershipNametagQualificationExecutionPhase::converging,
      MothershipNametagQualificationExecutionPhase::faultRestored, execution, resumed, &failure));
  assert(registry->advanceNametagQualificationExecution(*nonfaultAdapter, phaseIntent,
      MothershipNametagQualificationExecutionPhase::converging,
      MothershipNametagQualificationExecutionPhase::verified, execution, resumed, &failure));
  assert(mothershipNametagQualificationExecutionPhaseTerminal(execution.phase, phaseIntent));
  assert(!registry->advanceNametagQualificationExecution(*nonfaultAdapter, phaseIntent,
      MothershipNametagQualificationExecutionPhase::verified,
      MothershipNametagQualificationExecutionPhase::workloadIssued, execution, resumed, &failure));

  // Row two carries a precise fencing fault descriptor, but App11 owns the
  // injection.  It follows the ordinary application execution path and can
  // never manufacture Mothership fault-applied/restored phases.
  const auto *handoffAdapter = std::find_if(std::begin(mothershipNametagQualificationAdapters),
      std::end(mothershipNametagQualificationAdapters), [](const auto& value) {
        return value.row == MothershipNametagQualificationRow::secondStreamHandoffFence &&
            value.direction == MothershipNametagQualificationDirection::injection;
      });
  assert(handoffAdapter != std::end(mothershipNametagQualificationAdapters));
  assert(!mothershipNametagQualificationRequiresExternalFaultOwnership(handoffAdapter->row));
  auto handoffIntent = qualificationIntent(*handoffAdapter, allMasters);
  assert(mothershipNametagQualificationIntentValid(handoffIntent));
  auto duplicateCID = handoffIntent; duplicateCID.app6Routes[5].cids[0] = duplicateCID.app6Routes[0].cids[0];
  assert(!mothershipNametagQualificationIntentValid(duplicateCID));
  auto wrongIncumbent = handoffIntent; std::swap(wrongIncumbent.app6Routes[0], wrongIncumbent.app6Routes[1]);
  assert(!mothershipNametagQualificationIntentValid(wrongIncumbent));
  String handoffWire = {}; auto handoffCopy = handoffIntent; MothershipNametagQualificationIntent handoffDecoded = {};
  assert(BitseryEngine::serialize(handoffWire, handoffCopy) && BitseryEngine::deserializeSafe(handoffWire, handoffDecoded));
  assert(mothershipNametagQualificationIntentValid(handoffDecoded) && handoffDecoded.app6Routes.size() == 6 &&
      handoffDecoded.app6Routes[5].cids[1] == handoffIntent.app6Routes[5].cids[1]);
  auto dispatchIntent = handoffIntent;
  for (uint32_t i = 0; i < 3; ++i) dispatchIntent.probeTargets[i].probeDeploymentID = (uint64_t(11) << 48) | (i + 1);
  MothershipNametagQualificationSiteRequest siteRequest = {}; siteRequest.intent = dispatchIntent;
  siteRequest.targetClusterUUID = dispatchIntent.probeTargets[1].clusterUUID;
  siteRequest.targetProbeDeploymentID = dispatchIntent.probeTargets[1].probeDeploymentID;
  siteRequest.targetApp6DeploymentID = dispatchIntent.app6Routes[2].deploymentID;
  ProdigyNametagQualificationApplicationCommand siteCommand = {};
  assert(mothershipNametagQualificationApplicationCommand(siteRequest, siteCommand));
  assert(siteCommand.app6Routes.size() == 2 && siteCommand.app6Routes[0].clusterUUID == siteRequest.targetClusterUUID &&
      siteCommand.app6Routes[1].clusterUUID == dispatchIntent.app6Routes[3].clusterUUID);
  ++siteRequest.targetApp6DeploymentID;
  assert(!mothershipNametagQualificationApplicationCommand(siteRequest, siteCommand));
  handoffIntent.runUUID += 0x500; handoffIntent.executionGeneration += 0x500;
  assert(registry->persistNametagQualificationIntent(*handoffAdapter, handoffIntent, recordedIntent, resumed, &failure));
  MothershipNametagQualificationExecutionRecord handoffExecution = {};
  assert(registry->persistNametagQualificationExecutionPrepared(*handoffAdapter, handoffIntent,
      handoffExecution, resumed, &failure) && !resumed);
  assert(!registry->advanceNametagQualificationExecution(*handoffAdapter, handoffIntent,
      MothershipNametagQualificationExecutionPhase::prepared,
      MothershipNametagQualificationExecutionPhase::faultApplied, handoffExecution, resumed, &failure));
  assert(registry->advanceNametagQualificationExecution(*handoffAdapter, handoffIntent,
      MothershipNametagQualificationExecutionPhase::prepared,
      MothershipNametagQualificationExecutionPhase::workloadIssued, handoffExecution, resumed, &failure));
  assert(registry->advanceNametagQualificationExecution(*handoffAdapter, handoffIntent,
      MothershipNametagQualificationExecutionPhase::workloadIssued,
      MothershipNametagQualificationExecutionPhase::converging, handoffExecution, resumed, &failure));
  assert(registry->advanceNametagQualificationExecution(*handoffAdapter, handoffIntent,
      MothershipNametagQualificationExecutionPhase::converging,
      MothershipNametagQualificationExecutionPhase::verified, handoffExecution, resumed, &failure));
  assert(mothershipNametagQualificationExecutionPhaseTerminal(handoffExecution.phase, handoffIntent));
  assert(!registry->advanceNametagQualificationExecution(*handoffAdapter, handoffIntent,
      MothershipNametagQualificationExecutionPhase::verified,
      MothershipNametagQualificationExecutionPhase::faultRestored, handoffExecution, resumed, &failure));

  // Row sixteen records only a real singleton-policy rejection: the retained
  // EWR owner, distinct ORD candidate, and retained plan digest are immutable
  // across retry.  A malformed or conflicting observation cannot pass.
  const auto *truthFenceAdapter = std::find_if(std::begin(mothershipNametagQualificationAdapters),
      std::end(mothershipNametagQualificationAdapters), [](const auto& value) {
        return value.row == MothershipNametagQualificationRow::secondTruthWriterFencing &&
            value.direction == MothershipNametagQualificationDirection::injection;
      });
  assert(truthFenceAdapter != std::end(mothershipNametagQualificationAdapters));
  auto truthFenceIntent = qualificationIntent(*truthFenceAdapter, allMasters);
  truthFenceIntent.runUUID += 0x540; truthFenceIntent.executionGeneration += 0x540;
  assert(registry->persistNametagQualificationIntent(*truthFenceAdapter, truthFenceIntent,
      recordedIntent, resumed, &failure));
  MothershipNametagQualificationExecutionRecord truthFenceExecution = {};
  assert(registry->persistNametagQualificationExecutionPrepared(*truthFenceAdapter, truthFenceIntent,
      truthFenceExecution, resumed, &failure) && !resumed);
  auto truthFenceReceipt = MothershipNametagQualificationExecutionRecord::SecondTruthWriterAdmissionReceipt{};
  truthFenceReceipt.sourceClusterUUID = allMasters.intent.sites[0].clusterUUID;
  truthFenceReceipt.candidateClusterUUID = allMasters.intent.sites[1].clusterUUID;
  truthFenceReceipt.retainedOwnerClusterUUID = truthFenceReceipt.sourceClusterUUID;
  truthFenceReceipt.retainedPlacementGeneration = 1;
  truthFenceReceipt.candidatePlanSHA256 = digest('9');
  truthFenceReceipt.fenced = true;
  assert(mothershipNametagQualificationSecondTruthWriterAdmissionValid(truthFenceReceipt));
  MothershipApplicationPlacement retainedTruthPlacement = {};
  assert(registry->admitTruthPlacement(truthFenceReceipt.sourceClusterUUID, digest('6'),
      retainedTruthPlacement, resumed, &failure) && !resumed);
  assert(!registry->admitTruthPlacement(truthFenceReceipt.candidateClusterUUID, digest('5'),
      retainedTruthPlacement, resumed, &failure));
  assert(registry->loadTruthPlacement(retainedTruthPlacement, &failure) &&
      retainedTruthPlacement.ownerClusterUUID == truthFenceReceipt.sourceClusterUUID &&
      retainedTruthPlacement.generation == truthFenceReceipt.retainedPlacementGeneration);
  MothershipNametagQualificationExecutionRecord legacyTruthFenceExecution = {};
  legacyTruthFenceExecution.protocolVersion = 1;
  legacyTruthFenceExecution.intent = truthFenceIntent;
  String legacyTruthFenceBytes = {};
  assert(BitseryEngine::serialize(legacyTruthFenceBytes, legacyTruthFenceExecution));
  MothershipNametagQualificationExecutionRecord decodedLegacyTruthFenceExecution = {};
  assert(BitseryEngine::deserializeSafe(legacyTruthFenceBytes, decodedLegacyTruthFenceExecution) &&
      decodedLegacyTruthFenceExecution.protocolVersion == 1 &&
      mothershipNametagQualificationExecutionRecordValid(decodedLegacyTruthFenceExecution));
  decodedLegacyTruthFenceExecution.protocolVersion = MothershipNametagQualificationExecutionRecord::version;
  decodedLegacyTruthFenceExecution.secondTruthWriterAdmission = truthFenceReceipt;
  String upgradedTruthFenceBytes = {};
  assert(BitseryEngine::serialize(upgradedTruthFenceBytes, decodedLegacyTruthFenceExecution));
  MothershipNametagQualificationExecutionRecord decodedUpgradedTruthFenceExecution = {};
  assert(BitseryEngine::deserializeSafe(upgradedTruthFenceBytes, decodedUpgradedTruthFenceExecution) &&
      decodedUpgradedTruthFenceExecution.protocolVersion == 2 &&
      mothershipNametagQualificationSecondTruthWriterAdmissionMatchesIntent(
          truthFenceIntent, decodedUpgradedTruthFenceExecution.secondTruthWriterAdmission));
  auto malformedTruthFenceReceipt = truthFenceReceipt;
  malformedTruthFenceReceipt.candidateClusterUUID = malformedTruthFenceReceipt.sourceClusterUUID;
  assert(!registry->recordNametagQualificationSecondTruthWriterAdmission(*truthFenceAdapter, truthFenceIntent,
      malformedTruthFenceReceipt, truthFenceExecution, resumed, &failure));
  auto wrongSiteTruthFenceReceipt = truthFenceReceipt;
  wrongSiteTruthFenceReceipt.candidateClusterUUID = allMasters.intent.sites[2].clusterUUID;
  assert(!mothershipNametagQualificationSecondTruthWriterAdmissionMatchesIntent(
      truthFenceIntent, wrongSiteTruthFenceReceipt));
  assert(!registry->recordNametagQualificationSecondTruthWriterAdmission(*truthFenceAdapter, truthFenceIntent,
      wrongSiteTruthFenceReceipt, truthFenceExecution, resumed, &failure));
  assert(registry->recordNametagQualificationSecondTruthWriterAdmission(*truthFenceAdapter, truthFenceIntent,
      truthFenceReceipt, truthFenceExecution, resumed, &failure) && !resumed);
  assert(truthFenceExecution.secondTruthWriterAdmission.fenced);
  // Row sixteen joins one EWR stale-session witness with two read-only
  // observers, and cannot promote either set without the durable admission
  // rejection that precedes the App11 work.
  auto truthFenceApplications = qualificationReceipt(truthFenceIntent).applicationReceipts;
  auto truthFenceJoinExecution = truthFenceExecution;
  truthFenceJoinExecution.phase = MothershipNametagQualificationExecutionPhase::converging;
  MothershipNametagQualificationReceipt truthFenceJoinedReceipt = {};
  String truthFenceTopology("native-topology-evidence-v4", Copy::yes);
  assert(!mothershipNametagQualificationBuildReceipt(truthFenceIntent, truthFenceApplications,
      truthFenceTopology, truthFenceIntent.convergenceDeadlineAtMilliseconds,
      truthFenceJoinedReceipt, &failure));
  assert(mothershipNametagQualificationBuildReceipt(truthFenceIntent, truthFenceApplications,
      truthFenceTopology, truthFenceIntent.convergenceDeadlineAtMilliseconds,
      truthFenceJoinedReceipt, &failure, &truthFenceJoinExecution));
  const auto persistedTruthFenceInjectionReceipt = truthFenceJoinedReceipt;
  auto changedTruthAdmission = truthFenceJoinExecution;
  changedTruthAdmission.secondTruthWriterAdmission.candidatePlanSHA256 = digest('5');
  MothershipNametagQualificationReceipt changedTruthAdmissionReceipt = {};
  assert(mothershipNametagQualificationBuildReceipt(truthFenceIntent, truthFenceApplications,
      truthFenceTopology, truthFenceIntent.convergenceDeadlineAtMilliseconds,
      changedTruthAdmissionReceipt, &failure, &changedTruthAdmission));
  assert(changedTruthAdmissionReceipt.witnessDigest != truthFenceJoinedReceipt.witnessDigest);
  auto verifiedTruthExecution = truthFenceJoinExecution;
  verifiedTruthExecution.phase = MothershipNametagQualificationExecutionPhase::verified;
  MothershipNametagQualificationReceipt resumedTruthReceipt = {};
  assert(mothershipNametagQualificationBuildReceipt(truthFenceIntent, truthFenceApplications,
      truthFenceTopology, truthFenceIntent.convergenceDeadlineAtMilliseconds,
      resumedTruthReceipt, &failure, &verifiedTruthExecution));
  assert(resumedTruthReceipt.witnessDigest == truthFenceJoinedReceipt.witnessDigest);
  auto wrongTruthExecutionRun = truthFenceJoinExecution;
  ++wrongTruthExecutionRun.intent.runUUID;
  assert(!mothershipNametagQualificationBuildReceipt(truthFenceIntent, truthFenceApplications,
      truthFenceTopology, truthFenceIntent.convergenceDeadlineAtMilliseconds,
      truthFenceJoinedReceipt, &failure, &wrongTruthExecutionRun));
  auto wrongTruthExecutionPhase = truthFenceJoinExecution;
  wrongTruthExecutionPhase.phase = MothershipNametagQualificationExecutionPhase::faultApplied;
  assert(!mothershipNametagQualificationBuildReceipt(truthFenceIntent, truthFenceApplications,
      truthFenceTopology, truthFenceIntent.convergenceDeadlineAtMilliseconds,
      truthFenceJoinedReceipt, &failure, &wrongTruthExecutionPhase));
  auto wrongTruthObserver = truthFenceApplications;
  wrongTruthObserver[1].participantRole = ProdigyNametagQualificationParticipantRole::ewrSessionFence;
  assert(!mothershipNametagQualificationBuildReceipt(truthFenceIntent, wrongTruthObserver,
      truthFenceTopology, truthFenceIntent.convergenceDeadlineAtMilliseconds,
      truthFenceJoinedReceipt, &failure, &truthFenceJoinExecution));
  auto mismatchedTruthPostState = truthFenceApplications;
  mismatchedTruthPostState[2].joinedWitnessDigest = digest('8');
  assert(!mothershipNametagQualificationBuildReceipt(truthFenceIntent, mismatchedTruthPostState,
      truthFenceTopology, truthFenceIntent.convergenceDeadlineAtMilliseconds,
      truthFenceJoinedReceipt, &failure, &truthFenceJoinExecution));
  const auto *truthFenceObservationAdapter = std::find_if(
      std::begin(mothershipNametagQualificationAdapters),
      std::end(mothershipNametagQualificationAdapters), [](const auto& value) {
        return value.row == MothershipNametagQualificationRow::secondTruthWriterFencing &&
            value.direction == MothershipNametagQualificationDirection::observation;
      });
  assert(truthFenceObservationAdapter != std::end(mothershipNametagQualificationAdapters));
  auto truthFenceObservationIntent = qualificationIntent(*truthFenceObservationAdapter, allMasters);
  truthFenceObservationIntent.runUUID = truthFenceIntent.runUUID;
  truthFenceObservationIntent.priorInjectionRunUUID = truthFenceIntent.runUUID;
  truthFenceObservationIntent.startedAtMilliseconds = persistedTruthFenceInjectionReceipt.observedAtMilliseconds + 1;
  truthFenceObservationIntent.deadlineAtMilliseconds = truthFenceObservationIntent.startedAtMilliseconds +
      int64_t(truthFenceObservationIntent.deadlineSeconds) * 1000;
  truthFenceObservationIntent.convergenceDeadlineAtMilliseconds = truthFenceObservationIntent.startedAtMilliseconds +
      int64_t(truthFenceObservationIntent.convergenceSeconds) * 1000;
  assert(mothershipNametagQualificationReceiptDigest(
      persistedTruthFenceInjectionReceipt, truthFenceObservationIntent.priorInjectionReceiptDigest));
  auto truthFenceObservationApplications = truthFenceApplications;
  for (auto& application : truthFenceObservationApplications) {
    application.direction = uint8_t(truthFenceObservationIntent.direction);
    application.executionGeneration = truthFenceObservationIntent.executionGeneration;
    application.participantRole = ProdigyNametagQualificationParticipantRole::truthObserver;
    application.startedAtMilliseconds = truthFenceObservationIntent.startedAtMilliseconds;
    application.deadlineAtMilliseconds = truthFenceObservationIntent.deadlineAtMilliseconds;
    application.convergenceDeadlineAtMilliseconds = truthFenceObservationIntent.convergenceDeadlineAtMilliseconds;
    application.observedAtMilliseconds = truthFenceObservationIntent.convergenceDeadlineAtMilliseconds;
  }
  MothershipNametagQualificationReceipt truthFenceObservationReceipt = {};
  assert(mothershipNametagQualificationBuildReceipt(truthFenceObservationIntent,
      truthFenceObservationApplications, truthFenceTopology,
      truthFenceObservationIntent.convergenceDeadlineAtMilliseconds,
      truthFenceObservationReceipt, &failure, nullptr, &persistedTruthFenceInjectionReceipt));
  for (const auto& application : truthFenceObservationReceipt.applicationReceipts)
    assert(application.participantRole == ProdigyNametagQualificationParticipantRole::truthObserver &&
        application.joinedWitnessDigest == persistedTruthFenceInjectionReceipt.applicationReceipts[0].joinedWitnessDigest);
  auto wrongPriorDigestIntent = truthFenceObservationIntent;
  wrongPriorDigestIntent.priorInjectionReceiptDigest = digest('9');
  assert(!mothershipNametagQualificationBuildReceipt(wrongPriorDigestIntent,
      truthFenceObservationApplications, truthFenceTopology,
      wrongPriorDigestIntent.convergenceDeadlineAtMilliseconds,
      truthFenceObservationReceipt, &failure, nullptr, &persistedTruthFenceInjectionReceipt));
  auto wrongObservedPostState = truthFenceObservationApplications;
  wrongObservedPostState[0].joinedWitnessDigest = digest('9');
  assert(!mothershipNametagQualificationBuildReceipt(truthFenceObservationIntent,
      wrongObservedPostState, truthFenceTopology,
      truthFenceObservationIntent.convergenceDeadlineAtMilliseconds,
      truthFenceObservationReceipt, &failure, nullptr, &persistedTruthFenceInjectionReceipt));
  auto wrongPriorCluster = persistedTruthFenceInjectionReceipt;
  ++wrongPriorCluster.applicationReceipts[2].localClusterUUID;
  const auto recanonicalizePrior = [&](MothershipNametagQualificationReceipt& prior) {
    String applicationBytes = {}, applicationDigest = {};
    for (const auto& application : prior.applicationReceipts) {
      auto copy = application;
      String encoded = {};
      assert(BitseryEngine::serialize(encoded, copy) && !encoded.empty());
      applicationBytes.append(encoded);
    }
    assert(prodigyComputeSHA256Hex(applicationBytes, applicationDigest));
    prior.canonicalConvergenceWitness.assign("nametag-qualification-v4:"_ctv);
    prior.canonicalConvergenceWitness.append(prior.rowID);
    prior.canonicalConvergenceWitness.append(":"_ctv);
    prior.canonicalConvergenceWitness.append(applicationDigest);
    prior.canonicalConvergenceWitness.append(":"_ctv);
    prior.canonicalConvergenceWitness.append(truthFenceTopology);
    assert(prodigyComputeSHA256Hex(prior.canonicalConvergenceWitness, prior.witnessDigest));
    assert(mothershipNametagQualificationReceiptValid(prior));
  };
  recanonicalizePrior(wrongPriorCluster);
  const auto assertBoundPriorRejected = [&](const MothershipNametagQualificationReceipt& prior) {
    auto reboundIntent = truthFenceObservationIntent;
    assert(mothershipNametagQualificationReceiptDigest(prior, reboundIntent.priorInjectionReceiptDigest));
    assert(!mothershipNametagQualificationBuildReceipt(reboundIntent,
        truthFenceObservationApplications, truthFenceTopology,
        reboundIntent.convergenceDeadlineAtMilliseconds,
        truthFenceObservationReceipt, &failure, nullptr, &prior));
  };
  assertBoundPriorRejected(wrongPriorCluster);
  auto wrongPriorDeployment = persistedTruthFenceInjectionReceipt;
  ++wrongPriorDeployment.applicationReceipts[2].deploymentID;
  recanonicalizePrior(wrongPriorDeployment);
  assertBoundPriorRejected(wrongPriorDeployment);
  auto wrongPriorRole = persistedTruthFenceInjectionReceipt;
  wrongPriorRole.applicationReceipts[1].participantRole = ProdigyNametagQualificationParticipantRole::ewrSessionFence;
  recanonicalizePrior(wrongPriorRole);
  assertBoundPriorRejected(wrongPriorRole);
  auto wrongPriorJoin = persistedTruthFenceInjectionReceipt;
  wrongPriorJoin.applicationReceipts[2].joinedWitnessDigest = digest('4');
  recanonicalizePrior(wrongPriorJoin);
  assertBoundPriorRejected(wrongPriorJoin);
  auto earlyObservationIntent = truthFenceObservationIntent;
  earlyObservationIntent.startedAtMilliseconds = persistedTruthFenceInjectionReceipt.observedAtMilliseconds - 1;
  earlyObservationIntent.deadlineAtMilliseconds = earlyObservationIntent.startedAtMilliseconds +
      int64_t(earlyObservationIntent.deadlineSeconds) * 1000;
  earlyObservationIntent.convergenceDeadlineAtMilliseconds = earlyObservationIntent.startedAtMilliseconds +
      int64_t(earlyObservationIntent.convergenceSeconds) * 1000;
  assert(mothershipNametagQualificationIntentValid(earlyObservationIntent));
  assert(!mothershipNametagQualificationRowSixteenWitnessesValid(earlyObservationIntent,
      truthFenceObservationApplications, nullptr, &persistedTruthFenceInjectionReceipt));
  failure.assign("prior failure must clear on an idempotent replay"_ctv);
  assert(registry->recordNametagQualificationSecondTruthWriterAdmission(*truthFenceAdapter, truthFenceIntent,
      truthFenceReceipt, truthFenceExecution, resumed, &failure) && resumed && failure.empty());
  auto conflictingTruthFenceReceipt = truthFenceReceipt;
  conflictingTruthFenceReceipt.candidatePlanSHA256 = digest('8');
  assert(!registry->recordNametagQualificationSecondTruthWriterAdmission(*truthFenceAdapter, truthFenceIntent,
      conflictingTruthFenceReceipt, truthFenceExecution, resumed, &failure));

  DeploymentPlan retainedTruthPlan = {};
  retainedTruthPlan.config.applicationID = MeshRegistry::Truth::applicationID;
  retainedTruthPlan.config.versionID = 0x42;
  retainedTruthPlan.config.type = ApplicationType::stateful;
  retainedTruthPlan.isStateful = true;
  retainedTruthPlan.stateful.writerMode = StatefulWriterMode::localSingleWriter;
  DeploymentIdentityReport retainedTruthIdentity = {};
  retainedTruthIdentity.version = 4; retainedTruthIdentity.found = retainedTruthIdentity.live = true;
  retainedTruthIdentity.applicationID = MeshRegistry::Truth::applicationID;
  retainedTruthIdentity.clusterUUID = allMasters.intent.sites[0].clusterUUID;
  retainedTruthIdentity.deploymentID = retainedTruthPlan.config.deploymentID();
  assert(BitseryEngine::serialize(retainedTruthIdentity.normalizedDeploymentPlan, retainedTruthPlan));
  assert(prodigyComputeSHA256Hex(retainedTruthIdentity.normalizedDeploymentPlan,
      retainedTruthIdentity.canonicalPlanSHA256));
  retainedTruthIdentity.isStateful = true;
  DeploymentPlan decodedTruthPlan = {};
  assert(mothershipNametagQualificationSecondTruthWriterCandidatePlan(
      retainedTruthIdentity, decodedTruthPlan, &failure));
  assert(decodedTruthPlan.config.deploymentID() == retainedTruthIdentity.deploymentID);
  auto unavailableTruthIdentity = retainedTruthIdentity;
  unavailableTruthIdentity.live = false;
  assert(!mothershipNametagQualificationSecondTruthWriterCandidatePlan(
      unavailableTruthIdentity, decodedTruthPlan, &failure));
  unavailableTruthIdentity = retainedTruthIdentity;
  unavailableTruthIdentity.found = false;
  assert(!mothershipNametagQualificationSecondTruthWriterCandidatePlan(
      unavailableTruthIdentity, decodedTruthPlan, &failure));
  auto mismatchedTruthIdentity = retainedTruthIdentity;
  mismatchedTruthIdentity.canonicalPlanSHA256 = digest('7');
  assert(!mothershipNametagQualificationSecondTruthWriterCandidatePlan(
      mismatchedTruthIdentity, decodedTruthPlan, &failure));
  mismatchedTruthIdentity = retainedTruthIdentity;
  mismatchedTruthIdentity.normalizedDeploymentPlan.assign("not-a-plan"_ctv);
  assert(!mothershipNametagQualificationSecondTruthWriterCandidatePlan(
      mismatchedTruthIdentity, decodedTruthPlan, &failure));

  // Row three's Hot commutative increment/list workload is likewise an App11
  // workload: no provider fault phase may stand in for its exact multiset.
  const auto *sharedAdapter = std::find_if(std::begin(mothershipNametagQualificationAdapters),
      std::end(mothershipNametagQualificationAdapters), [](const auto& value) {
        return value.row == MothershipNametagQualificationRow::sharedKeyCommutativeWrites &&
            value.direction == MothershipNametagQualificationDirection::injection;
      });
  assert(sharedAdapter != std::end(mothershipNametagQualificationAdapters));
  assert(!mothershipNametagQualificationRequiresExternalFaultOwnership(sharedAdapter->row));
  auto sharedIntent = qualificationIntent(*sharedAdapter, allMasters);
  sharedIntent.runUUID += 0x580; sharedIntent.executionGeneration += 0x580;
  assert(registry->persistNametagQualificationIntent(*sharedAdapter, sharedIntent, recordedIntent, resumed, &failure));
  MothershipNametagQualificationExecutionRecord sharedExecution = {};
  assert(registry->persistNametagQualificationExecutionPrepared(*sharedAdapter, sharedIntent,
      sharedExecution, resumed, &failure) && !resumed);
  assert(!registry->advanceNametagQualificationExecution(*sharedAdapter, sharedIntent,
      MothershipNametagQualificationExecutionPhase::prepared,
      MothershipNametagQualificationExecutionPhase::faultApplied, sharedExecution, resumed, &failure));
  assert(registry->advanceNametagQualificationExecution(*sharedAdapter, sharedIntent,
      MothershipNametagQualificationExecutionPhase::prepared,
      MothershipNametagQualificationExecutionPhase::workloadIssued, sharedExecution, resumed, &failure));
  assert(registry->advanceNametagQualificationExecution(*sharedAdapter, sharedIntent,
      MothershipNametagQualificationExecutionPhase::workloadIssued,
      MothershipNametagQualificationExecutionPhase::converging, sharedExecution, resumed, &failure));
  assert(registry->advanceNametagQualificationExecution(*sharedAdapter, sharedIntent,
      MothershipNametagQualificationExecutionPhase::converging,
      MothershipNametagQualificationExecutionPhase::verified, sharedExecution, resumed, &failure));
  assert(mothershipNametagQualificationExecutionPhaseTerminal(sharedExecution.phase, sharedIntent));
  assert(!registry->advanceNametagQualificationExecution(*sharedAdapter, sharedIntent,
      MothershipNametagQualificationExecutionPhase::verified,
      MothershipNametagQualificationExecutionPhase::faultRestored, sharedExecution, resumed, &failure));

  // Row fourteen has the same narrow App11 ownership: directed Radar
  // mutation evidence advances only through the application lifecycle and
  // cannot fabricate provider fault phases.
  const auto *radarAdapter = std::find_if(std::begin(mothershipNametagQualificationAdapters),
      std::end(mothershipNametagQualificationAdapters), [](const auto& value) {
        return value.row == MothershipNametagQualificationRow::radarDirectedMutations &&
            value.direction == MothershipNametagQualificationDirection::injection;
      });
  assert(radarAdapter != std::end(mothershipNametagQualificationAdapters));
  assert(!mothershipNametagQualificationRequiresExternalFaultOwnership(radarAdapter->row));
  auto radarIntent = qualificationIntent(*radarAdapter, allMasters);
  radarIntent.runUUID += 0x600; radarIntent.executionGeneration += 0x600;
  assert(registry->persistNametagQualificationIntent(*radarAdapter, radarIntent, recordedIntent, resumed, &failure));
  MothershipNametagQualificationExecutionRecord radarExecution = {};
  assert(registry->persistNametagQualificationExecutionPrepared(*radarAdapter, radarIntent,
      radarExecution, resumed, &failure) && !resumed);
  assert(!registry->advanceNametagQualificationExecution(*radarAdapter, radarIntent,
      MothershipNametagQualificationExecutionPhase::prepared,
      MothershipNametagQualificationExecutionPhase::faultApplied, radarExecution, resumed, &failure));
  assert(registry->advanceNametagQualificationExecution(*radarAdapter, radarIntent,
      MothershipNametagQualificationExecutionPhase::prepared,
      MothershipNametagQualificationExecutionPhase::workloadIssued, radarExecution, resumed, &failure));
  assert(registry->advanceNametagQualificationExecution(*radarAdapter, radarIntent,
      MothershipNametagQualificationExecutionPhase::workloadIssued,
      MothershipNametagQualificationExecutionPhase::converging, radarExecution, resumed, &failure));
  assert(!registry->advanceNametagQualificationExecution(*radarAdapter, radarIntent,
      MothershipNametagQualificationExecutionPhase::converging,
      MothershipNametagQualificationExecutionPhase::faultRestored, radarExecution, resumed, &failure));
  assert(registry->advanceNametagQualificationExecution(*radarAdapter, radarIntent,
      MothershipNametagQualificationExecutionPhase::converging,
      MothershipNametagQualificationExecutionPhase::verified, radarExecution, resumed, &failure));
  assert(mothershipNametagQualificationExecutionPhaseTerminal(radarExecution.phase, radarIntent));
  assert(!registry->advanceNametagQualificationExecution(*radarAdapter, radarIntent,
      MothershipNametagQualificationExecutionPhase::verified,
      MothershipNametagQualificationExecutionPhase::faultRestored, radarExecution, resumed, &failure));

  // Row fifteen's Pulse commutative merge is likewise App11-owned and must
  // finish through workload convergence without provider fault transitions.
  const auto *pulseAdapter = std::find_if(std::begin(mothershipNametagQualificationAdapters),
      std::end(mothershipNametagQualificationAdapters), [](const auto& value) {
        return value.row == MothershipNametagQualificationRow::pulseFixedMatrixDedup &&
            value.direction == MothershipNametagQualificationDirection::injection;
      });
  assert(pulseAdapter != std::end(mothershipNametagQualificationAdapters));
  assert(!mothershipNametagQualificationRequiresExternalFaultOwnership(pulseAdapter->row));
  auto pulseIntent = qualificationIntent(*pulseAdapter, allMasters);
  pulseIntent.runUUID += 0x700; pulseIntent.executionGeneration += 0x700;
  assert(registry->persistNametagQualificationIntent(*pulseAdapter, pulseIntent, recordedIntent, resumed, &failure));
  MothershipNametagQualificationExecutionRecord pulseExecution = {};
  assert(registry->persistNametagQualificationExecutionPrepared(*pulseAdapter, pulseIntent,
      pulseExecution, resumed, &failure) && !resumed);
  assert(!registry->advanceNametagQualificationExecution(*pulseAdapter, pulseIntent,
      MothershipNametagQualificationExecutionPhase::prepared,
      MothershipNametagQualificationExecutionPhase::faultApplied, pulseExecution, resumed, &failure));
  assert(registry->advanceNametagQualificationExecution(*pulseAdapter, pulseIntent,
      MothershipNametagQualificationExecutionPhase::prepared,
      MothershipNametagQualificationExecutionPhase::workloadIssued, pulseExecution, resumed, &failure));
  assert(registry->advanceNametagQualificationExecution(*pulseAdapter, pulseIntent,
      MothershipNametagQualificationExecutionPhase::workloadIssued,
      MothershipNametagQualificationExecutionPhase::converging, pulseExecution, resumed, &failure));
  assert(!registry->advanceNametagQualificationExecution(*pulseAdapter, pulseIntent,
      MothershipNametagQualificationExecutionPhase::converging,
      MothershipNametagQualificationExecutionPhase::faultRestored, pulseExecution, resumed, &failure));
  assert(registry->advanceNametagQualificationExecution(*pulseAdapter, pulseIntent,
      MothershipNametagQualificationExecutionPhase::converging,
      MothershipNametagQualificationExecutionPhase::verified, pulseExecution, resumed, &failure));
  assert(mothershipNametagQualificationExecutionPhaseTerminal(pulseExecution.phase, pulseIntent));
  assert(!registry->advanceNametagQualificationExecution(*pulseAdapter, pulseIntent,
      MothershipNametagQualificationExecutionPhase::verified,
      MothershipNametagQualificationExecutionPhase::faultRestored, pulseExecution, resumed, &failure));

  // A different disruptive row is still infrastructure-owned and remains
  // unable to bypass faultApplied/faultRestored via the application path.
  for (const auto& candidate : mothershipNametagQualificationAdapters) {
    if (candidate.direction != MothershipNametagQualificationDirection::injection) continue;
    const bool faultBearing =
        mothershipNametagQualificationDescriptor(candidate.row).fault != ProdigyNametagQualificationFault::none;
    const bool app11Owned = candidate.row == MothershipNametagQualificationRow::secondStreamHandoffFence ||
        candidate.row == MothershipNametagQualificationRow::sharedKeyCommutativeWrites ||
        candidate.row == MothershipNametagQualificationRow::radarDirectedMutations ||
        candidate.row == MothershipNametagQualificationRow::pulseFixedMatrixDedup;
    assert(mothershipNametagQualificationRequiresExternalFaultOwnership(candidate.row) ==
        (faultBearing && !app11Owned));
    const bool nativeOwner = candidate.row == MothershipNametagQualificationRow::permissionRevokeReinstall ||
        candidate.row == MothershipNametagQualificationRow::cousinRouteSessionReconnect ||
        candidate.row == MothershipNametagQualificationRow::secondTruthWriterFencing ||
        candidate.row == MothershipNametagQualificationRow::mothershipRestartResume ||
        candidate.row == MothershipNametagQualificationRow::truthClaimPartition ||
        candidate.row == MothershipNametagQualificationRow::localWriterIsolation ||
        candidate.row == MothershipNametagQualificationRow::graphKvReplayReorder ||
        candidate.row == MothershipNametagQualificationRow::seedInterruptionResume ||
        candidate.row == MothershipNametagQualificationRow::brainHardRebootCatchup ||
        candidate.row == MothershipNametagQualificationRow::sitePartitionLocalWrites ||
        candidate.row == MothershipNametagQualificationRow::masqueSessionLossBgpRecovery ||
        candidate.row == MothershipNametagQualificationRow::ewrOrdPathLoss;
    assert(mothershipNametagQualificationImplemented(candidate.row) == (!faultBearing || app11Owned || nativeOwner));
  }
  assert(String(mothershipNametagQualificationFaultOwnerUnavailableReason(
      MothershipNametagQualificationRow::permissionRevokeReinstall)) ==
      "qualification all-masters record has no exact cousin permission identities"_ctv);
  assert(String(mothershipNametagQualificationFaultOwnerUnavailableReason(
      MothershipNametagQualificationRow::cousinRouteSessionReconnect)) ==
      "qualification all-masters record has no exact cousin route generation identities"_ctv);
  assert(String(mothershipNametagQualificationFaultOwnerUnavailableReason(
      MothershipNametagQualificationRow::masqueSessionLossBgpRecovery)) ==
      "MASQUE path-fault lifecycle has no Mothership-to-gateway session-control operation"_ctv);
  assert(String(mothershipNametagQualificationFaultOwnerUnavailableReason(
      MothershipNametagQualificationRow::ewrOrdPathLoss)) ==
      "EWR-ORD path fault only exposes a sealed physical-provider operation"_ctv);
  assert(String(mothershipNametagQualificationFaultOwnerUnavailableReason(
      MothershipNametagQualificationRow::sitePartitionLocalWrites)) ==
      "qualification has no typed site-partition lifecycle owner"_ctv);
  assert(String(mothershipNametagQualificationFaultOwnerUnavailableReason(
      MothershipNametagQualificationRow::secondTruthWriterFencing)) ==
      "second Truth-writer admission is fenced, but row lacks the App11 stale-session witness"_ctv);
  const auto disruptiveDescriptor = mothershipNametagQualificationDescriptor(
      MothershipNametagQualificationRow::localWriterIsolation);
  assert(disruptiveDescriptor.fault != ProdigyNametagQualificationFault::none);
  const auto *disruptiveAdapter = std::find_if(std::begin(mothershipNametagQualificationAdapters),
      std::end(mothershipNametagQualificationAdapters), [](const auto& value) {
        return value.row == MothershipNametagQualificationRow::localWriterIsolation &&
            value.direction == MothershipNametagQualificationDirection::injection;
      });
  assert(disruptiveAdapter != std::end(mothershipNametagQualificationAdapters));
  const auto disruptiveIntent = qualificationIntent(*disruptiveAdapter, allMasters);
  assert(!mothershipNametagQualificationExecutionPhaseTransitionValid(
      MothershipNametagQualificationExecutionPhase::prepared,
      MothershipNametagQualificationExecutionPhase::workloadIssued,
      disruptiveIntent));

  // A path phase cannot advance on the state-machine shape alone: the exact
  // fault, application, and restoration witnesses must first be durable.
  const auto *masqueAdapter = std::find_if(std::begin(mothershipNametagQualificationAdapters),
      std::end(mothershipNametagQualificationAdapters), [](const auto& value) {
        return value.row == MothershipNametagQualificationRow::masqueSessionLossBgpRecovery &&
            value.direction == MothershipNametagQualificationDirection::injection;
      });
  assert(masqueAdapter != std::end(mothershipNametagQualificationAdapters));
  auto masqueIntent = qualificationIntent(*masqueAdapter, allMasters);
  masqueIntent.runUUID += 0x800; masqueIntent.executionGeneration += 0x800;
  assert(registry->persistNametagQualificationIntent(*masqueAdapter, masqueIntent,
      recordedIntent, resumed, &failure));
  MothershipNametagQualificationExecutionRecord masqueExecution = {};
  assert(registry->persistNametagQualificationExecutionPrepared(*masqueAdapter, masqueIntent,
      masqueExecution, resumed, &failure) && !resumed);
  assert(!registry->advanceNametagQualificationExecution(*masqueAdapter, masqueIntent,
      MothershipNametagQualificationExecutionPhase::prepared,
      MothershipNametagQualificationExecutionPhase::faultApplied, masqueExecution, resumed, &failure));
  assert(!mothershipNametagQualificationExecutionPhaseTransitionValid(
      MothershipNametagQualificationExecutionPhase::workloadIssued,
      MothershipNametagQualificationExecutionPhase::converging, masqueIntent));
  bool intentFound = false;
  MothershipNametagQualificationIntent resumedIntent = {};
  assert(registry->loadNametagQualificationIntent(adapter, intent.runUUID, resumedIntent, intentFound, &failure) && intentFound);
  assert(resumedIntent.executionGeneration == intent.executionGeneration &&
         resumedIntent.startedAtMilliseconds == intent.startedAtMilliseconds &&
         prodigyNametagQualificationDescriptorEqual(resumedIntent.descriptor, intent.descriptor));
  auto corruptIntent = intent;
  corruptIntent.executionGeneration = 0;
  assert(!registry->persistNametagQualificationIntent(adapter, corruptIntent, recordedIntent, resumed, &failure));
  assert(registry->persistNametagQualificationIntent(adapter, intent, recordedIntent, resumed, &failure) && resumed);
  bool found = true;
  assert(registry->loadNametagQualificationReceipt(adapter, intent.runUUID, recordedReceipt, found, &failure) && !found);
  auto wrongReceiptAuthority = receipt; ++wrongReceiptAuthority.allMastersOperationUUID;
  assert(!registry->recordNametagQualificationReceipt(adapter, wrongReceiptAuthority, recordedReceipt, resumed, &failure));
  auto wrongReceiptTarget = receipt; ++wrongReceiptTarget.applicationReceipts[1].deploymentID;
  assert(!registry->recordNametagQualificationReceipt(adapter, wrongReceiptTarget, recordedReceipt, resumed, &failure));
  assert(registry->recordNametagQualificationReceipt(adapter, receipt, recordedReceipt, resumed, &failure) && !resumed);
  assert(recordedReceipt.applicationReceipts.size() == 3);
  assert(registry->recordNametagQualificationReceipt(adapter, receipt, recordedReceipt, resumed, &failure) && resumed);
  const auto *observationAdapter = std::find_if(std::begin(mothershipNametagQualificationAdapters),
      std::end(mothershipNametagQualificationAdapters), [&](const auto& value) {
        return value.row == adapter.row && value.direction == MothershipNametagQualificationDirection::observation;
      });
  assert(observationAdapter != std::end(mothershipNametagQualificationAdapters));
  intentFound = true;
  assert(registry->loadNametagQualificationIntent(*observationAdapter, intent.runUUID, resumedIntent, intentFound, &failure) &&
         !intentFound);
  // Observation has a separate immutable direction and may not promote an
  // injection receipt into an observed qualification result.
  assert(!registry->recordNametagQualificationReceipt(*observationAdapter, receipt, recordedReceipt, resumed, &failure));
  auto changedReceipt = receipt; changedReceipt.canonicalConvergenceWitness.assign("changed-proof"_ctv);
  assert(!registry->recordNametagQualificationReceipt(adapter, changedReceipt, recordedReceipt, resumed, &failure));

  // Old broad pass payloads cannot be promoted: the generation, exact row
  // descriptor, and selected witness are all immutable receipt identity.
  auto noGeneration = receipt; noGeneration.executionGeneration = 0;
  assert(!mothershipNametagQualificationReceiptValid(noGeneration));
  auto genericDescriptor = receipt; genericDescriptor.descriptor = {};
  assert(!mothershipNametagQualificationReceiptValid(genericDescriptor));
  auto wrongDescriptor = receipt;
  wrongDescriptor.descriptor = mothershipNametagQualificationDescriptor(
      MothershipNametagQualificationRow::truthClaimPartition);
  assert(!mothershipNametagQualificationReceiptValid(wrongDescriptor));
  auto wrongWitness = receipt;
  wrongWitness.witnessedResult = ProdigyNametagQualificationWitness::uniqueEwrTruthWinner;
  assert(!mothershipNametagQualificationReceiptValid(wrongWitness));
  auto emptyApplicationWitness = receipt;
  emptyApplicationWitness.applicationReceipts[0].canonicalWitnessReceipt.clear();
  assert(!mothershipNametagQualificationReceiptValid(emptyApplicationWitness));
  auto observationIntent = qualificationIntent(*observationAdapter, allMasters);
  observationIntent.runUUID += 0x100; observationIntent.executionGeneration += 0x100;
  auto injectionApplications = qualificationReceipt(intent).applicationReceipts;
  MothershipNametagQualificationReceipt observationReceipt = {};
  String topologyEvidence = {}; topologyEvidence.assign("native-topology-evidence-v4"_ctv);
  assert(!mothershipNametagQualificationBuildReceipt(observationIntent, injectionApplications, topologyEvidence,
      observationIntent.convergenceDeadlineAtMilliseconds, observationReceipt, &failure));

  // A legacy broad digest/flag is never an alternative witness. Every row
  // must retain the immutable descriptor/generation and exact typed App11 set.
  for (uint32_t row = 1; row <= 17; ++row) {
    const auto rowValue = MothershipNametagQualificationRow(row);
    // These rows require their explicit native execution proof, not generic App11 receipts.
    if (rowValue == MothershipNametagQualificationRow::mothershipRestartResume ||
        rowValue == MothershipNametagQualificationRow::graphKvReplayReorder ||
        prodigyNametagQualificationSeedReadbackRow(uint8_t(rowValue)) ||
        rowValue == MothershipNametagQualificationRow::truthClaimPartition ||
        rowValue == MothershipNametagQualificationRow::localWriterIsolation ||
        prodigyNametagQualificationPathRow(uint8_t(rowValue))) continue;
    const auto *rowAdapter = std::find_if(std::begin(mothershipNametagQualificationAdapters),
        std::end(mothershipNametagQualificationAdapters), [&](const auto& value) {
          return value.row == rowValue && value.direction == MothershipNametagQualificationDirection::injection;
        });
    assert(rowAdapter != std::end(mothershipNametagQualificationAdapters));
    auto rowIntent = qualificationIntent(*rowAdapter, allMasters);
    rowIntent.runUUID += row; rowIntent.executionGeneration += row;
    auto generic = qualificationReceipt(rowIntent);
    generic.canonicalFiveStoreReceipt.assign("generic-five-store-pass"_ctv); generic.healthyTopology = true;
    generic.applicationReceipts[0].canonicalWitnessReceipt.clear();
    assert(!mothershipNametagQualificationReceiptValid(generic));
    generic = qualificationReceipt(rowIntent);
    ++generic.applicationReceipts[0].executionGeneration;
    assert(!mothershipNametagQualificationReceiptValid(generic));
    generic = qualificationReceipt(rowIntent);
    generic.applicationReceipts[0].descriptor = mothershipNametagQualificationDescriptor(
        rowValue == MothershipNametagQualificationRow::sequentialUserKeyWrites ?
            MothershipNametagQualificationRow::truthClaimPartition :
            MothershipNametagQualificationRow::sequentialUserKeyWrites);
    assert(!mothershipNametagQualificationReceiptValid(generic));
  }

  // Source population is deliberately outside the row matrix.  It admits an
  // empty-but-ready EWR cohort, then persists only the authenticated App11
  // readback under its immutable operation tuple.
  auto emptySource = allMastersReceipt(0x100, (uint64_t(MeshRegistry::Hot::applicationID) << 48) | 1,
      MeshRegistry::Hot::applicationID, 3, DeploymentIdentityStoreKind::kv);
  emptySource.version = 4;
  for (auto& member : emptySource.statefulRuntimeCohort) {
    member.sourceContentWatermarkSHA256.clear(); member.sourceCatchupWatermarkSHA256.clear();
  }
  assert(mothershipNametagAllMastersDeploymentReadyForSeedSelection(emptySource, 0x100,
      emptySource.deploymentID, MeshRegistry::Hot::applicationID, 3, DeploymentIdentityStoreKind::kv));
  auto notReady = emptySource; notReady.statefulRuntimeCohort.pop_back();
  assert(!mothershipNametagAllMastersDeploymentReadyForSeedSelection(notReady, 0x100,
      emptySource.deploymentID, MeshRegistry::Hot::applicationID, 3, DeploymentIdentityStoreKind::kv));
  ProdigyNametagSourceBaselineCommand baseline = {};
  baseline.operationUUID = 0xba51; baseline.ewrClusterUUID = 0x100;
  baseline.probeDeploymentID = (uint64_t(11) << 48) | 1;
  baseline.hotDeploymentID = (uint64_t(MeshRegistry::Hot::applicationID) << 48) | 2;
  baseline.coldDeploymentID = (uint64_t(MeshRegistry::Cold::applicationID) << 48) | 3;
  baseline.radarDeploymentID = (uint64_t(MeshRegistry::Radar::applicationID) << 48) | 4;
  baseline.pulseDeploymentID = (uint64_t(MeshRegistry::Pulse::applicationID) << 48) | 5;
  baseline.truthDeploymentID = (uint64_t(MeshRegistry::Truth::applicationID) << 48) | 6;
  // Source-baseline fields are SHA-256 hex digests, not arbitrary fixtures.
  baseline.fixtureManifestSHA256 = digest('a'); baseline.deadlineAtMilliseconds = 100;
  assert(prodigyNametagSourceBaselineCommandValid(baseline));
  auto wrongAppBaseline = baseline;
  wrongAppBaseline.probeDeploymentID = (uint64_t(MeshRegistry::Nametag::applicationID) << 48) | 1;
  assert(!prodigyNametagSourceBaselineCommandValid(wrongAppBaseline));
  auto malformedBaseline = baseline; malformedBaseline.fixtureManifestSHA256.clear();
  assert(!prodigyNametagSourceBaselineCommandValid(malformedBaseline));
  MothershipNametagSourceBaselineExchange baselineRequest = {}; baselineRequest.command = baseline;
  assert(mothershipNametagSourceBaselineExchangeRequestValid(baselineRequest));
  // Exercise the same framing and decoding used by the Mothership and Brain.
  String baselineRequestBytes = {};
  assert(BitseryEngine::serialize(baselineRequestBytes, baselineRequest));
  String baselineWire = {};
  Message::construct(baselineWire, MothershipTopic::nametagSourceBaseline, baselineRequestBytes);
  Message *baselineMessage = reinterpret_cast<Message *>(baselineWire.data());
  assert(baselineMessage->topic == uint16_t(MothershipTopic::nametagSourceBaseline));
  uint8_t *baselineArgs = baselineMessage->args;
  String baselinePayload = {};
  Message::extractToStringView(baselineArgs, baselinePayload);
  assert(baselineArgs == baselineMessage->terminal());
  MothershipNametagSourceBaselineExchange decodedBaselineRequest = {};
  assert(BitseryEngine::deserializeSafe(baselinePayload, decodedBaselineRequest));
  assert(mothershipNametagSourceBaselineExchangeRequestValid(decodedBaselineRequest));
  ProdigyNametagSourceBaselineEnvelope decodedExecute = {};
  decodedExecute.direction = ProdigyNametagSourceBaselineDirection::execute;
  decodedExecute.command = decodedBaselineRequest.command;
  assert(prodigyNametagSourceBaselineEnvelopeValid(decodedExecute));
  ProdigyNametagSourceBaselineReceipt baselineReceipt = {};
  baselineReceipt.operationUUID = baseline.operationUUID; baselineReceipt.ewrClusterUUID = baseline.ewrClusterUUID;
  baselineReceipt.localContainerUUID = 0xc001; baselineReceipt.probeDeploymentID = baseline.probeDeploymentID;
  baselineReceipt.fixtureManifestSHA256 = baseline.fixtureManifestSHA256; baselineReceipt.canonicalReadbackDigest = digest('b');
  baselineReceipt.deadlineAtMilliseconds = baseline.deadlineAtMilliseconds; baselineReceipt.observedAtMilliseconds = 99;
  for (uint16_t applicationID : {uint16_t(MeshRegistry::Hot::applicationID), uint16_t(MeshRegistry::Cold::applicationID)})
    for (uint32_t group = 0; group < 3; ++group) baselineReceipt.storeDigests.push_back({applicationID, group, digest('c')});
  for (uint16_t applicationID : {uint16_t(MeshRegistry::Pulse::applicationID), uint16_t(MeshRegistry::Radar::applicationID), uint16_t(MeshRegistry::Truth::applicationID)})
    baselineReceipt.storeDigests.push_back({applicationID, 0, digest('c')});
  assert(prodigyNametagSourceBaselineReceiptValid(baselineReceipt));
  auto duplicateGroup = baselineReceipt; duplicateGroup.storeDigests[1].shardGroup = 0;
  assert(!prodigyNametagSourceBaselineReceiptValid(duplicateGroup));
  auto staleReceipt = baselineReceipt; staleReceipt.observedAtMilliseconds = 101;
  assert(!prodigyNametagSourceBaselineReceiptValid(staleReceipt));
  MothershipNametagSourceBaselineExchange baselineResponse = {};
  baselineRequest.command.action = ProdigyNametagSourceBaselineAction::query;
  baselineResponse.command = baselineRequest.command; baselineResponse.success = baselineResponse.completed = true; baselineResponse.receipt = baselineReceipt;
  assert(mothershipNametagSourceBaselineExchangeResponseValid(baselineRequest, baselineResponse));
  baselineResponse.receipt.fixtureManifestSHA256 = digest('d');
  assert(!mothershipNametagSourceBaselineExchangeResponseValid(baselineRequest, baselineResponse));
  baselineResponse.receipt = baselineReceipt;
  ++baselineResponse.command.coldDeploymentID;
  assert(!mothershipNametagSourceBaselineExchangeResponseValid(baselineRequest, baselineResponse));
  ProdigyNametagSourceBaselineEnvelope baselineEnvelope = {};
  baselineEnvelope.direction = ProdigyNametagSourceBaselineDirection::receipt;
  baselineEnvelope.command = baseline; baselineEnvelope.receipt = baselineReceipt;
  assert(prodigyNametagSourceBaselineEnvelopeValid(baselineEnvelope));
  // Query is a direction change, not permission to alter the durable tuple.
  auto baselineQuery = baseline; baselineQuery.action = ProdigyNametagSourceBaselineAction::query;
  assert(prodigyNametagSourceBaselineCommandSameOperation(baseline, baselineQuery));
  auto changedStoreQuery = baselineQuery; ++changedStoreQuery.hotDeploymentID;
  assert(!prodigyNametagSourceBaselineCommandSameOperation(baseline, changedStoreQuery));
  baselineEnvelope.command = baseline;
  baselineEnvelope.direction = ProdigyNametagSourceBaselineDirection::execute;
  baselineEnvelope.receipt = {};
  assert(prodigyNametagSourceBaselineEnvelopeValid(baselineEnvelope));
  baselineEnvelope.receipt = baselineReceipt;
  assert(!prodigyNametagSourceBaselineEnvelopeValid(baselineEnvelope));
  baselineEnvelope.receipt = {};
  baselineEnvelope.command.action = ProdigyNametagSourceBaselineAction::query;
  assert(!prodigyNametagSourceBaselineEnvelopeValid(baselineEnvelope));
  MothershipNametagSourceBaselineIntent baselineIntent = {}; baselineIntent.ewrClusterName.assign("task-ewr"_ctv); baselineIntent.deadlineSeconds = 60;
  baselineIntent.command = baseline; MothershipNametagSourceBaselineIntent recordedBaselineIntent = {};
  assert(registry->persistNametagSourceBaselineIntent(baselineIntent, recordedBaselineIntent, resumed, &failure) && !resumed);
  assert(registry->persistNametagSourceBaselineIntent(baselineIntent, recordedBaselineIntent, resumed, &failure) && resumed);
  auto replayConflict = baselineIntent; replayConflict.command.deadlineAtMilliseconds++;
  assert(!registry->persistNametagSourceBaselineIntent(replayConflict, recordedBaselineIntent, resumed, &failure));
  MothershipNametagSourceBaselineRecord baselineRecord = {};
  baselineRecord.command = baseline; baselineRecord.receipt = baselineReceipt;
  MothershipNametagSourceBaselineRecord recordedBaseline = {};
  assert(registry->recordNametagSourceBaseline(baselineRecord, recordedBaseline, resumed, &failure) && !resumed);
  assert(registry->recordNametagSourceBaseline(baselineRecord, recordedBaseline, resumed, &failure) && resumed);
  baselineRecord.receipt.canonicalReadbackDigest = digest('e');
  assert(!registry->recordNametagSourceBaseline(baselineRecord, recordedBaseline, resumed, &failure));

  // The initial remote cohort is frozen against the actual durable baseline
  // before any authority install or deployment dispatch.
  auto initialIntent = cuts.intent;
  initialIntent.operationUUID = 0xa113;
  initialIntent.sourceBaselineOperationUUID = baseline.operationUUID;
  auto& baselineSite = initialIntent.sites[0];
  baselineSite.pulseDeploymentID = baseline.pulseDeploymentID;
  baselineSite.hotDeploymentID = baseline.hotDeploymentID;
  baselineSite.coldDeploymentID = baseline.coldDeploymentID;
  baselineSite.radarDeploymentID = baseline.radarDeploymentID;
  baselineSite.truthDeploymentID = baseline.truthDeploymentID;
  MothershipNametagInitialSeedRecord initial = {};
  initial.operationUUID = initialIntent.operationUUID;
  initial.baselineOperationUUID = baseline.operationUUID;
  assert(BitseryEngine::serialize(initial.intentBytes, initialIntent));
  assert(prodigyComputeSHA256Hex(initial.intentBytes, initial.intentSHA256));
  String baselineReceiptBytes;
  assert(BitseryEngine::serialize(baselineReceiptBytes, baselineReceipt));
  assert(prodigyComputeSHA256Hex(baselineReceiptBytes, initial.baselineReceiptSHA256));
  for (uint8_t site = 1; site <= 2; ++site) {
    const auto& target = initialIntent.sites[site];
    for (uint16_t app : {uint16_t(2), uint16_t(3), uint16_t(4), uint16_t(5)}) {
      auto& item = initial.plans.emplace_back();
      item.site = site; item.applicationID = app;
      item.deploymentID = app == 2 ? target.pulseDeploymentID : app == 3 ? target.hotDeploymentID :
          app == 4 ? target.coldDeploymentID : target.radarDeploymentID;
      item.nShardGroups = app == 3 || app == 4 ? 3 : 1;
      item.artifactPath.assign("/task/initial-seed.blob"_ctv);
      item.artifactSHA256 = digest('a'); item.artifactBytes = 8192;
      DeploymentPlan plan = {};
      plan.isStateful = true; plan.stateful.writerMode = StatefulWriterMode::allMasters;
      plan.config.type = ApplicationType::stateful; plan.config.applicationID = app;
      plan.config.versionID = item.deploymentID & UINT64_C(0x0000ffffffffffff);
      plan.config.containerBlobSHA256 = item.artifactSHA256; plan.config.containerBlobBytes = item.artifactBytes;
      assert(BitseryEngine::serialize(item.normalizedPlan, plan));
      assert(prodigyComputeSHA256Hex(item.normalizedPlan, item.planSHA256));
    }
  }
  assert(mothershipNametagInitialSeedRecordValid(initial));
  auto wrongInitialBaseline = initial; wrongInitialBaseline.baselineReceiptSHA256 = digest('f');
  assert(!registry->persistNametagInitialSeed(wrongInitialBaseline, resumed, &failure));
  assert(registry->persistNametagInitialSeed(initial, resumed, &failure) && !resumed);
  assert(registry->persistNametagInitialSeed(initial, resumed, &failure) && resumed);
  assert(!registry->updateNametagInitialSeedProgress(initial.operationUUID, 0, true, &failure));
  assert(!registry->updateNametagInitialSeedProgress(initial.operationUUID, 8, false, &failure));
  assert(registry->updateNametagInitialSeedProgress(initial.operationUUID, 0, false, &failure));
  assert(registry->updateNametagInitialSeedProgress(initial.operationUUID, 0, false, &failure));
  assert(registry->updateNametagInitialSeedProgress(initial.operationUUID, 0, true, &failure));
  MothershipNametagInitialSeedRecord loadedInitial = {};
  assert(registry->loadNametagInitialSeed(initial.operationUUID, loadedInitial, &failure));
  assert(loadedInitial.dispatchMask == 1 && loadedInitial.completedMask == 1);
  assert(registry->persistNametagInitialSeed(initial, resumed, &failure) && resumed);
  auto changedInitial = initial; DeploymentPlan changedPlan = {};
  assert(BitseryEngine::deserializeSafe(changedInitial.plans[0].normalizedPlan, changedPlan));
  changedPlan.config.containerBlobSHA256 = digest('b');
  changedInitial.plans[0].artifactSHA256 = changedPlan.config.containerBlobSHA256;
  changedInitial.plans[0].normalizedPlan.clear();
  assert(BitseryEngine::serialize(changedInitial.plans[0].normalizedPlan, changedPlan));
  assert(prodigyComputeSHA256Hex(changedInitial.plans[0].normalizedPlan, changedInitial.plans[0].planSHA256));
  assert(mothershipNametagInitialSeedRecordValid(changedInitial));
  assert(!registry->persistNametagInitialSeed(changedInitial, resumed, &failure));

  // An expired cut can only lead to one hash-linked management run. Its
  // native operation remains the exact immutable remote bootstrap identity.
  {
    auto rootIntent = initialIntent; rootIntent.operationUUID = 0xa114;
    auto bootstrap = initial; bootstrap.operationUUID = rootIntent.operationUUID;
    bootstrap.intentBytes.clear();
    assert(BitseryEngine::serialize(bootstrap.intentBytes, rootIntent));
    assert(prodigyComputeSHA256Hex(bootstrap.intentBytes, bootstrap.intentSHA256));
    assert(registry->persistNametagInitialSeed(bootstrap, resumed, &failure) && !resumed);
    auto expired = cuts; expired.intent = rootIntent;
    const auto expiredAt = Time::now<TimeResolution::ms>() - 1;
    for (auto& item : expired.sourceCuts) {
      item.request.operationUUID = rootIntent.operationUUID; item.request.retainUntilMilliseconds = expiredAt;
      item.request.sourceDeploymentID = item.request.applicationID == 2 ? rootIntent.sites[0].pulseDeploymentID :
          item.request.applicationID == 3 ? rootIntent.sites[0].hotDeploymentID :
          item.request.applicationID == 4 ? rootIntent.sites[0].coldDeploymentID : rootIntent.sites[0].radarDeploymentID;
    }
    auto digestOf = [](auto value) { String bytes, hash; assert(BitseryEngine::serialize(bytes, value));
      assert(prodigyComputeSHA256Hex(bytes, hash)); return hash; };
    expired.requestSHA256 = digestOf(expired.intent);
    assert(registry->persistNametagAllMasters(expired, checkpoint, resumed, &failure) && !resumed);
    auto recovery = rootIntent; recovery.protocolVersion = recovery.expiredCutRecoveryVersion;
    recovery.operationUUID = 0xa115; recovery.sourceBaselineOperationUUID = 0xa116;
    recovery.predecessorOperationUUID = rootIntent.operationUUID;
    recovery.predecessorRecordSHA256 = digestOf(expired);
    recovery.predecessorBaselineSHA256 = digestOf(recordedBaseline);
    for (uint16_t app : {uint16_t(3), uint16_t(4)}) {
      MothershipNametagSourceRepairPlan plan; plan.applicationID = app;
      plan.previousDeploymentID = app == 3 ? rootIntent.sites[0].hotDeploymentID : rootIntent.sites[0].coldDeploymentID;
      plan.successorDeploymentID = plan.previousDeploymentID + 10;
      auto& observed = plan.predecessor; observed.version = 6; observed.found = observed.live = observed.isStateful = true;
      observed.clusterUUID = rootIntent.sites[0].clusterUUID; observed.applicationID = app;
      observed.deploymentID = plan.previousDeploymentID; observed.nShardGroups = 3;
      observed.nTarget = observed.nDeployed = observed.nHealthy = 9;
      DeploymentPlan before; before.isStateful = before.stateful.allowUpdateInPlace = true; before.stateful.writerMode = StatefulWriterMode::allMasters;
      before.config.type = ApplicationType::stateful; before.config.applicationID = app;
      before.config.versionID = plan.previousDeploymentID & UINT64_C(0x0000ffffffffffff);
      before.config.containerBlobSHA256 = digest('a'); before.config.containerBlobBytes = 8192;
      observed.containerBlobSHA256 = before.config.containerBlobSHA256; observed.containerBlobBytes = before.config.containerBlobBytes;
      assert(BitseryEngine::serialize(observed.normalizedDeploymentPlan, before));
      observed.canonicalPlanSHA256 = digestOf(before);
      for (uint32_t group = 0; group < 3; ++group) for (uint32_t replica = 0; replica < 3; ++replica) {
        const auto old = std::find_if(expired.sourceCuts.begin(), expired.sourceCuts.end(), [&](const auto& cut) {
          return cut.request.applicationID == app && cut.request.shardGroup == group; });
        assert(old != expired.sourceCuts.end());
        auto& member = observed.statefulRuntimeCohort.emplace_back(); member.storeKind = DeploymentIdentityStoreKind::kv;
        member.clusterUUID = observed.clusterUUID; member.shardGroup = group; member.machineUUID = 0x900 + replica;
        member.containerUUID = old->request.sourceContainerUUID + replica * 0x1000;
        member.replicaUUID = member.containerUUID; member.allMasters = true;
      }
      auto next = before; next.config.versionID += 10; next.config.containerBlobSHA256 = digest('b'); next.config.containerBlobBytes = 9000;
      plan.artifactSHA256 = next.config.containerBlobSHA256; plan.artifactBytes = next.config.containerBlobBytes;
      assert(BitseryEngine::serialize(plan.normalizedPlan, next)); plan.planSHA256 = digestOf(next);
      assert(mothershipNametagSourceRepairPlanValid(plan));
      auto wrong = plan; next.config.storageMB += 1; wrong.normalizedPlan.clear();
      assert(BitseryEngine::serialize(wrong.normalizedPlan, next)); wrong.planSHA256 = digestOf(next);
      assert(!mothershipNametagSourceRepairPlanValid(wrong));
      if (app == 3) recovery.sites[0].hotDeploymentID = plan.successorDeploymentID;
      else recovery.sites[0].coldDeploymentID = plan.successorDeploymentID;
      recovery.sourceRepairPlans.push_back(std::move(plan));
    }
    recovery.initialSeedRecordSHA256 = digestOf(bootstrap);
    assert(mothershipNametagAllMastersIntentValid(recovery));

    // v8 repairs only the expired Radar predecessor and preserves every remote
    // plan and gateway binding from the original all-masters admission.
    auto radarRecovery = rootIntent;
    radarRecovery.protocolVersion = radarRecovery.radarExpiredCutRecoveryVersion;
    radarRecovery.operationUUID = 0xa117; radarRecovery.sourceBaselineOperationUUID = 0xa118;
    radarRecovery.predecessorOperationUUID = rootIntent.operationUUID;
    radarRecovery.predecessorRecordSHA256 = digestOf(expired);
    radarRecovery.predecessorBaselineSHA256 = digestOf(recordedBaseline);
    radarRecovery.initialSeedRecordSHA256 = digestOf(bootstrap);
    MothershipNametagSourceRepairPlan radarPlan = {};
    radarPlan.applicationID = MeshRegistry::Radar::applicationID;
    radarPlan.previousDeploymentID = rootIntent.sites[0].radarDeploymentID;
    radarPlan.successorDeploymentID = radarPlan.previousDeploymentID + 10;
    auto& radarObserved = radarPlan.predecessor;
    radarObserved.version = 6; radarObserved.found = radarObserved.live = radarObserved.isStateful = true;
    radarObserved.clusterUUID = rootIntent.sites[0].clusterUUID;
    radarObserved.applicationID = MeshRegistry::Radar::applicationID;
    radarObserved.deploymentID = radarPlan.previousDeploymentID; radarObserved.nShardGroups = 1;
    radarObserved.nTarget = radarObserved.nDeployed = radarObserved.nHealthy = 3;
    DeploymentPlan radarBefore = {}; radarBefore.isStateful = radarBefore.stateful.allowUpdateInPlace = true; radarBefore.stateful.writerMode = StatefulWriterMode::allMasters;
    radarBefore.config.type = ApplicationType::stateful; radarBefore.config.applicationID = MeshRegistry::Radar::applicationID;
    radarBefore.config.versionID = radarPlan.previousDeploymentID & UINT64_C(0x0000ffffffffffff);
    radarBefore.config.containerBlobSHA256 = digest('a'); radarBefore.config.containerBlobBytes = 8192;
    radarObserved.containerBlobSHA256 = radarBefore.config.containerBlobSHA256; radarObserved.containerBlobBytes = radarBefore.config.containerBlobBytes;
    assert(BitseryEngine::serialize(radarObserved.normalizedDeploymentPlan, radarBefore));
    radarObserved.canonicalPlanSHA256 = digestOf(radarBefore);
    const auto radarCut = std::find_if(expired.sourceCuts.begin(), expired.sourceCuts.end(), [](const auto& cut) {
      return cut.request.applicationID == MeshRegistry::Radar::applicationID && cut.request.shardGroup == 0;
    });
    assert(radarCut != expired.sourceCuts.end());
    for (uint32_t replica = 0; replica < 3; ++replica) {
      auto& radarMember = radarObserved.statefulRuntimeCohort.emplace_back();
      radarMember.storeKind = DeploymentIdentityStoreKind::graph; radarMember.clusterUUID = radarObserved.clusterUUID;
      radarMember.shardGroup = 0; radarMember.machineUUID = 0x901 + replica;
      radarMember.containerUUID = radarCut->request.sourceContainerUUID + replica * 0x1000;
      radarMember.replicaUUID = radarMember.containerUUID; radarMember.allMasters = true;
    }
    auto radarNext = radarBefore; radarNext.config.versionID += 10; radarNext.config.containerBlobSHA256 = digest('b'); radarNext.config.containerBlobBytes = 9000;
    radarPlan.artifactSHA256 = radarNext.config.containerBlobSHA256; radarPlan.artifactBytes = radarNext.config.containerBlobBytes;
    assert(BitseryEngine::serialize(radarPlan.normalizedPlan, radarNext)); radarPlan.planSHA256 = digestOf(radarNext);
    assert(mothershipNametagSourceRepairPlanValid(radarPlan));
    radarRecovery.sites[0].radarDeploymentID = radarPlan.successorDeploymentID;
    radarRecovery.sourceRepairPlans.push_back(radarPlan);
    assert(mothershipNametagAllMastersIntentValid(radarRecovery));
    assert(!registry->persistNametagExpiredCutRecoveryPreparation(recovery, resumed, &failure));
    for (uint32_t i = 0; i < 8; ++i) {
      assert(registry->updateNametagInitialSeedProgress(bootstrap.operationUUID, i, false, &failure));
      assert(registry->updateNametagInitialSeedProgress(bootstrap.operationUUID, i, true, &failure));
    }
    assert(registry->loadNametagInitialSeed(bootstrap.operationUUID, bootstrap, &failure));
    recovery.initialSeedRecordSHA256 = digestOf(bootstrap);
    assert(mothershipNametagExpiredCutRecoveryMatches(recovery, expired, bootstrap, expiredAt + 1));
    radarRecovery.initialSeedRecordSHA256 = digestOf(bootstrap);
    MothershipNametagAllMastersIntent decodedRadarRecovery; String radarRecoveryBytes;
    assert(BitseryEngine::serialize(radarRecoveryBytes, radarRecovery) &&
           BitseryEngine::deserializeSafe(radarRecoveryBytes, decodedRadarRecovery));
    assert(mothershipNametagAllMastersIntentValid(decodedRadarRecovery) && digestOf(decodedRadarRecovery) == digestOf(radarRecovery));
    assert(mothershipNametagExpiredCutRecoveryMatches(radarRecovery, expired, bootstrap, expiredAt + 1));
    auto radarUnboundSource = radarRecovery; ++radarUnboundSource.sourceRepairPlans[0].predecessor.statefulRuntimeCohort[0].containerUUID;
    assert(!mothershipNametagExpiredCutRecoveryMatches(radarUnboundSource, expired, bootstrap, expiredAt + 1));
    auto radarSourceUnrelatedChanged = radarRecovery; ++radarSourceUnrelatedChanged.sites[0].hotDeploymentID;
    assert(!mothershipNametagExpiredCutRecoveryMatches(radarSourceUnrelatedChanged, expired, bootstrap, expiredAt + 1));
    auto radarRemotePlanChanged = radarRecovery; ++radarRemotePlanChanged.sites[1].radarDeploymentID;
    assert(!mothershipNametagExpiredCutRecoveryMatches(radarRemotePlanChanged, expired, bootstrap, expiredAt + 1));
    auto radarGatewayChanged = radarRecovery; radarGatewayChanged.directGatewayAuthorities.emplace_back();
    assert(!mothershipNametagExpiredCutRecoveryMatches(radarGatewayChanged, expired, bootstrap, expiredAt + 1));
    auto radarChallengeMissing = expired; radarChallengeMissing.sourceCuts[7].dispatched = true; radarChallengeMissing.sourceCuts[7].request.memberRequestUUID = 0;
    assert(!mothershipNametagExpiredCutRecoveryMatches(radarRecovery, radarChallengeMissing, bootstrap, expiredAt + 1));
    auto radarAlreadySeeded = expired; radarAlreadySeeded.phase = MothershipNametagAllMastersRecord::Phase::remoteSeeding;
    assert(!mothershipNametagExpiredCutRecoveryMatches(radarRecovery, radarAlreadySeeded, bootstrap, expiredAt + 1));
    auto radarNotExpired = expired; radarNotExpired.sourceCuts[7].request.retainUntilMilliseconds = expiredAt + 1000;
    assert(!mothershipNametagExpiredCutRecoveryMatches(radarRecovery, radarNotExpired, bootstrap, expiredAt + 1));
    auto notExpired = expired; notExpired.sourceCuts[7].request.retainUntilMilliseconds += 1000;
    assert(!mothershipNametagExpiredCutRecoveryMatches(recovery, notExpired, bootstrap, expiredAt + 1));
    auto ambiguous = expired; ambiguous.sourceCuts[1].dispatched = true;
    assert(!mothershipNametagExpiredCutRecoveryMatches(recovery, ambiguous, bootstrap, expiredAt + 1));
    auto wrongTarget = recovery; ++wrongTarget.sites[1].hotDeploymentID;
    assert(!mothershipNametagExpiredCutRecoveryMatches(wrongTarget, expired, bootstrap, expiredAt + 1));
    auto wrongApp = recovery; ++wrongApp.sites[0].app6DeploymentID;
    assert(!mothershipNametagExpiredCutRecoveryMatches(wrongApp, expired, bootstrap, expiredAt + 1));
    auto wrongHash = recovery; wrongHash.predecessorRecordSHA256 = digest('f');
    assert(!registry->persistNametagExpiredCutRecoveryPreparation(wrongHash, resumed, &failure));
    assert(registry->persistNametagExpiredCutRecoveryPreparation(recovery, resumed, &failure) && !resumed);
    assert(registry->persistNametagExpiredCutRecoveryPreparation(recovery, resumed, &failure) && resumed);
    auto second = recovery; ++second.operationUUID;
    assert(!registry->persistNametagExpiredCutRecoveryPreparation(second, resumed, &failure));
    assert(!registry->updateNametagAllMastersSourceCut(expired.intent.operationUUID, 0, true, nullptr, checkpoint, &failure));
    assert(registry->loadNametagAllMasters(expired.intent.operationUUID, checkpoint, &failure));
    assert(digestOf(checkpoint) == recovery.predecessorRecordSHA256);
    MothershipNametagAllMastersIntent decodedRecovery; String recoveryBytes;
    assert(BitseryEngine::serialize(recoveryBytes, recovery) && BitseryEngine::deserializeSafe(recoveryBytes, decodedRecovery));
    assert(mothershipNametagAllMastersIntentValid(decodedRecovery) && digestOf(decodedRecovery) == digestOf(recovery));
    auto run = expired; run.intent = recovery; run.requestSHA256 = digestOf(recovery);
    for (auto& item : run.sourceCuts) {
      item.request.requestUUID += 0x50000; item.request.retainUntilMilliseconds = expiredAt + 60000;
      if (item.request.applicationID == 3 || item.request.applicationID == 4) {
        item.request.sourceDeploymentID = item.request.applicationID == 3 ? recovery.sites[0].hotDeploymentID : recovery.sites[0].coldDeploymentID;
        item.request.sourceContainerUUID += 0x100000;
      }
    }
    assert(mothershipNametagAllMastersRecordValid(run));
    assert(mothershipNametagSeedOperationUUID(run) == bootstrap.operationUUID && run.intent.operationUUID != bootstrap.operationUUID);
    Vector<DeploymentIdentityReport> repairedReports[4] = {cutReports[0], cutReports[1], cutReports[2], cutReports[3]};
    for (const auto& plan : bootstrap.plans) {
      auto& observed = repairedReports[plan.applicationID - 2][plan.site];
      observed.deploymentID = plan.deploymentID; observed.normalizedDeploymentPlan = plan.normalizedPlan;
      observed.canonicalPlanSHA256 = plan.planSHA256; observed.containerBlobSHA256 = plan.artifactSHA256;
      observed.containerBlobBytes = plan.artifactBytes;
    }
    for (const auto& plan : recovery.sourceRepairPlans) {
      auto& observed = repairedReports[plan.applicationID - 2][0]; observed = plan.predecessor;
      observed.deploymentID = plan.successorDeploymentID; observed.normalizedDeploymentPlan = plan.normalizedPlan;
      observed.canonicalPlanSHA256 = plan.planSHA256; observed.containerBlobSHA256 = plan.artifactSHA256;
      observed.containerBlobBytes = plan.artifactBytes;
    }
    assert(mothershipNametagExpiredCutRecoveryReportsMatch(recovery, bootstrap, repairedReports[0], repairedReports[1], repairedReports[2], repairedReports[3]));
    repairedReports[1][1].containerBlobSHA256 = digest('f');
    assert(!mothershipNametagExpiredCutRecoveryReportsMatch(recovery, bootstrap, repairedReports[0], repairedReports[1], repairedReports[2], repairedReports[3]));
    repairedReports[1][1].containerBlobSHA256 = bootstrap.plans[1].artifactSHA256;
    Vector<DeploymentIdentityReport> radarRepairedReports[4] = {cutReports[0], cutReports[1], cutReports[2], cutReports[3]};
    for (const auto& plan : bootstrap.plans) {
      auto& observed = radarRepairedReports[plan.applicationID - 2][plan.site];
      observed.deploymentID = plan.deploymentID; observed.normalizedDeploymentPlan = plan.normalizedPlan;
      observed.canonicalPlanSHA256 = plan.planSHA256; observed.containerBlobSHA256 = plan.artifactSHA256;
      observed.containerBlobBytes = plan.artifactBytes;
    }
    auto& repairedRadar = radarRepairedReports[MeshRegistry::Radar::applicationID - 2][0];
    repairedRadar = radarPlan.predecessor; repairedRadar.deploymentID = radarPlan.successorDeploymentID;
    repairedRadar.normalizedDeploymentPlan = radarPlan.normalizedPlan; repairedRadar.canonicalPlanSHA256 = radarPlan.planSHA256;
    repairedRadar.containerBlobSHA256 = radarPlan.artifactSHA256; repairedRadar.containerBlobBytes = radarPlan.artifactBytes;
    assert(mothershipNametagExpiredCutRecoveryReportsMatch(radarRecovery, bootstrap, radarRepairedReports[0], radarRepairedReports[1], radarRepairedReports[2], radarRepairedReports[3]));
    const auto savedRadarRemote = radarRepairedReports[3][1];
    radarRepairedReports[3][1].containerBlobSHA256 = digest('e');
    assert(!mothershipNametagExpiredCutRecoveryReportsMatch(radarRecovery, bootstrap, radarRepairedReports[0], radarRepairedReports[1], radarRepairedReports[2], radarRepairedReports[3]));
    radarRepairedReports[3][1] = savedRadarRemote;
    auto readyRecovery = run;
    for (auto& cut : readyRecovery.sourceCuts) {
      cut.dispatched = true; cut.request.memberRequestUUID = cut.request.requestUUID + 0x100;
      cut.proof = cut.request; cut.proof.response = cut.proof.ready = true;
      cut.proof.cutUUID = cut.request.requestUUID + 0x200; cut.proof.cutGeneration = 1;
      cut.proof.contentSHA256 = digest('b'); cut.proof.headsSHA256 = digest('c');
    }
    assert(mothershipNametagSourceCutPlacementsSynthesize(readyRecovery, repairedReports[0], repairedReports[1], repairedReports[2], repairedReports[3], digest('f')));
    assert(mothershipNametagAllMastersRecordValid(readyRecovery));
    ProdigyStatefulStoreSeedAuthority recoveryAuthority;
    assert(mothershipNametagSourceCutAuthority(readyRecovery, readyRecovery.seedPlacements.front(), recoveryAuthority));
    assert(recoveryAuthority.operationUUID == bootstrap.operationUUID && recoveryAuthority.sourceBaselineOperationUUID == recovery.sourceBaselineOperationUUID &&
        recoveryAuthority.sourceRequestUUID == run.sourceCuts.front().request.requestUUID);
    assert(!registry->persistNametagAllMasters(run, checkpoint, resumed, &failure)); // fresh baseline still absent
    auto freshBaseline = recordedBaseline; freshBaseline.command.operationUUID = recovery.sourceBaselineOperationUUID;
    freshBaseline.command.hotDeploymentID = recovery.sites[0].hotDeploymentID;
    freshBaseline.command.coldDeploymentID = recovery.sites[0].coldDeploymentID;
    freshBaseline.receipt.operationUUID = freshBaseline.command.operationUUID;
    MothershipNametagSourceBaselineRecord storedFresh;
    assert(registry->recordNametagSourceBaseline(freshBaseline, storedFresh, resumed, &failure));
    assert(registry->persistNametagAllMasters(run, checkpoint, resumed, &failure) && !resumed);
    auto retry = run; for (auto& cut : retry.sourceCuts) ++cut.request.requestUUID;
    assert(registry->persistNametagAllMasters(retry, checkpoint, resumed, &failure) && resumed);
    assert(checkpoint.sourceCuts[0].request.requestUUID == run.sourceCuts[0].request.requestUUID);
    auto reused = run; reused.sourceCuts[0].request.requestUUID = expired.sourceCuts[0].request.requestUUID;
    assert(!registry->persistNametagAllMasters(reused, checkpoint, resumed, &failure));
    assert(registry->updateNametagAllMastersSourceCut(run.intent.operationUUID, 0, true, nullptr, checkpoint, &failure));
    auto pending = checkpoint.sourceCuts[0].request; pending.response = true; pending.memberRequestUUID = 0x333333;
    assert(registry->updateNametagAllMastersSourceCut(run.intent.operationUUID, 0, false, &pending, checkpoint, &failure));
    assert(registry->persistNametagAllMasters(retry, checkpoint, resumed, &failure) && resumed);
    assert(checkpoint.sourceCuts[0].request.memberRequestUUID == pending.memberRequestUUID);
    assert(registry->loadNametagAllMasters(expired.intent.operationUUID, checkpoint, &failure) && digestOf(checkpoint) == recovery.predecessorRecordSHA256);
    assert(registry->loadNametagInitialSeed(bootstrap.operationUUID, bootstrap, &failure) && digestOf(bootstrap) == recovery.initialSeedRecordSHA256);
    MothershipNametagSourceBaselineRecord unchangedBaseline; bool unchangedFound = false;
    assert(registry->loadNametagSourceBaseline(rootIntent.sourceBaselineOperationUUID, unchangedBaseline, unchangedFound, &failure) && unchangedFound &&
        digestOf(unchangedBaseline) == recovery.predecessorBaselineSHA256);
  }

  registry.reset();
  {
    MothershipClusterRegistry reopened(path);
    MothershipNametagInitialSeedRecord reopenedInitial = {};
    assert(reopened.loadNametagInitialSeed(initial.operationUUID, reopenedInitial, &failure));
    assert(reopenedInitial.dispatchMask == 1 && reopenedInitial.completedMask == 1);
    MothershipNametagAllMastersIntent reopenedRecovery; bool recoveryFound = false;
    assert(reopened.loadNametagExpiredCutRecoveryPreparation(0xa114, reopenedRecovery, recoveryFound, &failure) && recoveryFound && reopenedRecovery.operationUUID == 0xa115);
    MothershipNametagAllMastersRecord reopenedRun;
    assert(reopened.loadNametagAllMasters(0xa115, reopenedRun, &failure) && reopenedRun.sourceCuts[0].request.memberRequestUUID == 0x333333 &&
        mothershipNametagSeedOperationUUID(reopenedRun) == 0xa114);
    assert(reopened.loadNametagAllMasters(allMasters.intent.operationUUID, recordedAllMasters, &failure));
    assert(reopened.loadNametagQualificationIntent(adapter, intent.runUUID, resumedIntent, intentFound, &failure) && intentFound);
    assert(resumedIntent.executionGeneration == intent.executionGeneration &&
           resumedIntent.deadlineAtMilliseconds == intent.deadlineAtMilliseconds);
    assert(reopened.loadNametagQualificationReceipt(adapter, intent.runUUID, recordedReceipt, found, &failure));
    assert(found && recordedReceipt.allMastersOperationUUID == allMasters.intent.operationUUID &&
           recordedReceipt.applicationReceipts.size() == 3);
    bool executionFound = false;
    MothershipNametagQualificationExecutionRecord reopenedExecution = {};
    assert(reopened.loadNametagQualificationExecution(*nonfaultAdapter, phaseIntent, reopenedExecution, executionFound, &failure) &&
           executionFound && reopenedExecution.phase == MothershipNametagQualificationExecutionPhase::verified &&
           mothershipNametagQualificationExecutionPhaseTerminal(reopenedExecution.phase, phaseIntent));
  }
  std::filesystem::remove_all(root);
  std::puts("PASS: nametag qualification v4 row-specific witness linkage");
  return 0;
}
