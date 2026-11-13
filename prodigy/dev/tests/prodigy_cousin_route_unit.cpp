#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>

#include <prodigy/cousin.route.h>
#include <prodigy/cross.cluster.mesh.route.h>
#include <prodigy/cross.cluster.path.fault.h>
#include <prodigy/neuron/private.tunnel.bgp.runtime.h>
#include <prodigy/cousin.discovery.h>
#include <prodigy/mothership/mothership.cluster.registry.h>
#include <prodigy/mothership/mothership.cousin.route.h>
#include <prodigy/mothership/mothership.pair.control.boundary.h>
#include <prodigy/mothership/mothership.cousin.permission.h>
#include <prodigy/mothership/mothership.nametag.all.masters.h>

class TestSuite {
public:
  int failures = 0;

  bool require(bool condition, const char *name)
  {
    if (condition)
    {
      std::printf("PASS: %s\n", name);
      return true;
    }
    std::fprintf(stderr, "FAIL: %s\n", name);
    ++failures;
    return false;
  }
};

static String digest(char value)
{
  String result = {};
  for (uint32_t index = 0; index < 64; ++index) result.append(value);
  return result;
}

static ProdigyLocalCousinServicePermission validLocalCousinPermission(bool accepted = true)
{
  ProdigyLocalCousinServicePermission permission = {};
  permission.permissionUUID = 0x601;
  permission.pairUUID = 0x300;
  permission.logicalWorkloadUUID = 0x301;
  permission.logicalServiceUUID = 0x302;
  permission.localClusterUUID = 0x401;
  permission.peerClusterUUID = 0x402;
  permission.localHalf = CousinRouteHalf::source;
  permission.localApplicationID = 7;
  permission.peerApplicationID = 19;
  permission.localCousinServicePrefix = MeshServices::generateStatefulService(7, 3);
  permission.peerCousinServicePrefix = MeshServices::generateStatefulService(19, 3);
  permission.slots.insert(3);
  permission.slots.insert(1001);
  permission.localDeploymentID = 0x7000000000001;
  permission.canonicalPlanSHA256 = digest('a');
  permission.artifactSHA256 = digest('b');
  permission.artifactBytes = 8192;
  permission.generation = 1;
  permission.acceptedAuthorityGeneration = accepted ? 7 : 0;
  permission.state = ProdigyLocalCousinServicePermissionState::active;
  return permission;
}

// Frozen pre-v3 codec, independent of the production version switch.
struct LegacyPermissionWire { ProdigyLocalCousinServicePermission value; };
template <typename S> static void serialize(S&& s, LegacyPermissionWire& wire)
{
  auto& p = wire.value;
  s.value4b(p.protocolVersion); s.value16b(p.permissionUUID); s.value16b(p.pairUUID);
  s.value16b(p.logicalWorkloadUUID); s.value16b(p.logicalServiceUUID); s.value16b(p.localClusterUUID); s.value16b(p.peerClusterUUID);
  s.value1b(p.localHalf); s.value2b(p.localApplicationID); s.value2b(p.peerApplicationID);
  s.value8b(p.localCousinServicePrefix); s.value8b(p.peerCousinServicePrefix); s.object(p.slots); s.value8b(p.localDeploymentID);
  s.text1b(p.canonicalPlanSHA256, 64); s.text1b(p.artifactSHA256, 64); s.value8b(p.artifactBytes);
  s.value8b(p.generation); s.value8b(p.acceptedAuthorityGeneration); s.value1b(p.state);
  if (p.protocolVersion == 2) { s.value4b(p.baselineLogicalCores); s.value4b(p.baselineMemoryMB); s.value4b(p.baselineStorageMB); }
}

static ProdigyLocalCousinServicePermission purposePermission(ProdigyCousinServicePurpose purpose, bool accepted = true,
    uint16_t destinationApp = 10, uint16_t group = 0, uint16_t groups = 1)
{
  auto p = validLocalCousinPermission(accepted);
  p.protocolVersion = 3; p.purpose = purpose;
  p.localApplicationID = purpose == ProdigyCousinServicePurpose::clientAuthority ? 6 : 2;
  p.peerApplicationID = purpose == ProdigyCousinServicePurpose::clientAuthority ? destinationApp : 2;
  p.localCousinServicePrefix = purpose == ProdigyCousinServicePurpose::clientAuthority ? MeshServices::generateStatefulService(6, 1) :
      purpose == ProdigyCousinServicePurpose::sibling ? MeshRegistry::Pulse::siblings : MeshRegistry::Pulse::seeding;
  p.peerCousinServicePrefix = purpose == ProdigyCousinServicePurpose::clientAuthority ? prodigyCousinClientAuthorityPrefix(destinationApp) : p.localCousinServicePrefix;
  p.localDeploymentID = uint64_t(p.localApplicationID) << 48 | 1;
  p.peerDeploymentID = uint64_t(p.peerApplicationID) << 48 | 2;
  p.peerCanonicalPlanSHA256 = digest('c'); p.peerArtifactSHA256 = digest('d'); p.peerArtifactBytes = 4096;
  p.destinationShardGroup = group; p.destinationShardGroups = groups;
  p.authorizedService = MeshServices::constrainPrefixToGroup(p.peerCousinServicePrefix, group);
  p.slots = {};
  for (uint16_t slot = 0; slot < CousinRouteSlotBitmap::slotCount; ++slot)
    if (statefulServiceGroupOwnerForSlot(slot, groups) == group) { p.slots.insert(slot); break; }
  if (accepted) { p.baselineLogicalCores = 2; p.baselineMemoryMB = 1024; p.baselineStorageMB = 4096; }
  return p;
}

static std::string purposePermissionJSON(ProdigyLocalCousinServicePermission p)
{
  uint16_t slot = 0; prodigyCousinServicePermissionSingleSlot(p, slot);
  return std::string("{\"permissionUUID\":\"0x0601\",\"pairUUID\":\"0x0300\",\"logicalWorkloadUUID\":\"0x0301\",\"logicalServiceUUID\":\"0x0302\",\"localClusterUUID\":\"0x0401\",\"peerClusterUUID\":\"0x0402\",\"localHalf\":\"source\",\"localApplicationID\":") +
      std::to_string(p.localApplicationID) + ",\"peerApplicationID\":" + std::to_string(p.peerApplicationID) +
      ",\"localCousinServicePrefix\":" + std::to_string(p.localCousinServicePrefix) + ",\"peerCousinServicePrefix\":" + std::to_string(p.peerCousinServicePrefix) +
      ",\"slots\":[" + std::to_string(slot) + "],\"localDeploymentID\":" + std::to_string(p.localDeploymentID) +
      ",\"canonicalPlanSHA256\":\"" + p.canonicalPlanSHA256.c_str() + "\",\"artifactSHA256\":\"" + p.artifactSHA256.c_str() +
      "\",\"artifactBytes\":" + std::to_string(p.artifactBytes) + ",\"protocolVersion\":3,\"purpose\":\"" + prodigyCousinServicePurposeName(p.purpose) +
      "\",\"peerDeploymentID\":" + std::to_string(p.peerDeploymentID) + ",\"peerCanonicalPlanSHA256\":\"" + p.peerCanonicalPlanSHA256.c_str() +
      "\",\"peerArtifactSHA256\":\"" + p.peerArtifactSHA256.c_str() + "\",\"peerArtifactBytes\":" + std::to_string(p.peerArtifactBytes) +
      ",\"authorizedService\":" + std::to_string(p.authorizedService) + ",\"transportSourcePolicy\":\"exact\",\"destinationShardGroup\":" +
      std::to_string(p.destinationShardGroup) + ",\"destinationShardGroups\":" + std::to_string(p.destinationShardGroups) + "}";
}

static bool parseLocalCousinPermissionJSON(const String& json,
                                           ProdigyLocalCousinServicePermission& permission,
                                           String& failure)
{
  simdjson::dom::parser parser;
  simdjson::dom::element document;
  return parser.parse(json.data(), json.size()).get(document) == simdjson::SUCCESS &&
         mothershipParseLocalCousinPermissionJSON(document, permission, failure);
}

static bool parseCousinRouteIntentJSON(const String& json, MothershipCousinRouteIntent& intent,
                                       String& failure)
{
  simdjson::dom::parser parser;
  simdjson::dom::element document;
  return parser.parse(json.data(), json.size()).get(document) == simdjson::SUCCESS &&
         mothershipParseCousinRouteIntentJSON(document, intent, failure);
}

static ProdigyCousinCounterpart validCousinCounterpart()
{
  ProdigyCousinCounterpart counterpart = {};
  counterpart.permission = validLocalCousinPermission();
  counterpart.permission.localHalf = CousinRouteHalf::destination;
  counterpart.permission.localClusterUUID = 0x402;
  counterpart.permission.peerClusterUUID = 0x401;
  counterpart.permission.localApplicationID = 19;
  counterpart.permission.peerApplicationID = 7;
  counterpart.permission.localCousinServicePrefix = MeshServices::generateStatefulService(19, 3);
  counterpart.permission.peerCousinServicePrefix = MeshServices::generateStatefulService(7, 3);
  counterpart.permission.localDeploymentID = 0x13000000000001;
  counterpart.containerUUID = 0x701;
  counterpart.nodeUUID = 0x702;
  counterpart.containerID = 99;
  counterpart.shardGroups = 3;
  counterpart.shardGroup = statefulServiceGroupOwnerForSlot(3, counterpart.shardGroups);
  counterpart.service = MeshServices::constrainPrefixToGroup(
      counterpart.permission.localCousinServicePrefix, counterpart.shardGroup);
  counterpart.servicePort = 8443;
  for (uint16_t slot = 0; slot < nStatefulServiceGroupSlots; ++slot)
    if (counterpart.permission.slots.contains(slot) &&
        statefulServiceGroupOwnerForSlot(slot, counterpart.shardGroups) == counterpart.shardGroup)
      counterpart.ownedSlots.insert(slot);
  counterpart.routablePrefixUUID = 0x703;
  counterpart.publicAddress = IPAddress("fd42:4242:4242:2::44", true);
  counterpart.publicTCPPort = 443;
  counterpart.wormholeRevision = digest('c');
  return counterpart;
}

static ProdigyCousinDiscoverySnapshot validCousinDiscoverySnapshot()
{
  ProdigyCousinDiscoverySnapshot snapshot = {};
  snapshot.pairUUID = 0x300;
  snapshot.sourceClusterUUID = 0x402;
  snapshot.peerClusterUUID = 0x401;
  snapshot.rootGeneration = 7;
  snapshot.keyEpoch = 11;
  snapshot.authorityGeneration = 12;
  snapshot.records.push_back(validCousinCounterpart());
  return snapshot;
}

static CousinRouteRecord validRoute(uint128_t routeUUID = 0x101, uint128_t operationUUID = 0x201)
{
  CousinRouteRecord route = {};
  route.routeUUID = routeUUID;
  route.operationUUID = operationUUID;
  route.pairUUID = 0x300;
  route.logicalWorkloadUUID = 0x301;
  route.logicalServiceUUID = 0x302;
  route.sourceClusterUUID = 0x401;
  route.sourceApplicationID = 7;
  route.sourceCousinServicePrefix = MeshServices::generateStatefulService(7, 3);
  route.destinationClusterUUID = 0x402;
  route.destinationApplicationID = 19;
  route.destinationCousinServicePrefix = MeshServices::generateStatefulService(19, 3);
  route.slots.insert(3);
  route.slots.insert(1001);
  route.destinationRoutablePrefixUUID = 0x501;
  route.destinationPublicAddress = IPAddress("2001:db8::1", true);
  route.destinationTCPPort = 443;
  route.sourcePermissionUUID = 0x601;
  route.destinationPermissionUUID = 0x602;
  route.transportProtocol = IPPROTO_TCP;
  route.destinationCIDR = 32;
  route.pathMTU = 1500;
  route.generation = 1;
  route.issuedAtMs = 100;
  route.expiresAtMs = 200;
  route.keyEpoch = 1;
  route.rootGeneration = 1;
  return route;
}

static CousinRouteApplyReceipt validReceipt(const CousinRouteRecord& route, CousinRouteHalf half, uint64_t revision)
{
  CousinRouteApplyReceipt receipt = {};
  receipt.routeUUID = route.routeUUID;
  receipt.generation = route.generation;
  cousinRouteAuthorizationDigest(route, receipt.authorizationSHA256);
  receipt.localHalf = half;
  receipt.localClusterUUID = half == CousinRouteHalf::source ? route.sourceClusterUUID : route.destinationClusterUUID;
  receipt.keyEpoch = route.keyEpoch;
  receipt.localRuntimeRevision = revision;
  receipt.installedState = route.state;
  return receipt;
}

static CousinRouteSlotBitmap slotsOwnedBy(uint16_t group, uint16_t groupCount, const CousinRouteSlotBitmap& routeSlots)
{
  CousinRouteSlotBitmap result = {};
  for (uint16_t slot = 0; slot < nStatefulServiceGroupSlots; ++slot)
    if (routeSlots.contains(slot) && statefulServiceGroupOwnerForSlot(slot, groupCount) == group) result.insert(slot);
  return result;
}

static bool slotCoverageIsExact(const CousinRouteSlotBitmap& routeSlots, uint16_t groupCount)
{
  for (uint16_t slot = 0; slot < nStatefulServiceGroupSlots; ++slot)
  {
    if (!routeSlots.contains(slot)) continue;
    uint32_t owners = 0;
    for (uint16_t group = 0; group < groupCount; ++group)
      if (slotsOwnedBy(group, groupCount, routeSlots).contains(slot)) ++owners;
    if (owners != 1) return false;
  }
  return true;
}

static ClusterPairControlEndpoint validPairEndpoint(uint128_t clusterUUID, uint128_t nodeUUID, uint8_t lastByte)
{
  ClusterPairControlEndpoint endpoint = {};
  endpoint.clusterUUID = clusterUUID;
  endpoint.nodeUUID = nodeUUID;
  endpoint.role = ClusterPairControlNodeRole::switchboard;
  endpoint.address = IPAddress(clusterUUID == 0x902 ? "fd42:4242:4242:1::" : "fd42:4242:4242:2::", true);
  endpoint.address.v6[15] = lastByte;
  endpoint.port = mothershipPairControlBoundaryPort;
  return endpoint;
}

static MothershipClusterPairEnrollmentIntent validPairEnrollmentIntent(uint128_t operationUUID = 0x900)
{
  MothershipClusterPairEnrollmentIntent intent = {};
  intent.pairUUID = 0x901;
  intent.operationUUID = operationUUID;
  intent.firstClusterUUID = 0x902;
  intent.secondClusterUUID = 0x903;
  intent.firstObservedAuthorityGeneration = 7;
  intent.secondObservedAuthorityGeneration = 11;
  for (uint32_t index = 0; index < sizeof(intent.root); ++index) intent.root[index] = uint8_t(index + 1);
  intent.firstEndpoints.push_back(validPairEndpoint(intent.firstClusterUUID, 0x904, 4));
  intent.secondEndpoints.push_back(validPairEndpoint(intent.secondClusterUUID, 0x905, 5));
  return intent;
}

static MothershipPairControlBoundaryDescriptor validPairControlBoundary(
    const MothershipClusterPairEnrollmentIntent& intent)
{
  MothershipPairControlBoundaryDescriptor boundary = {};
  boundary.operationUUID = intent.operationUUID;
  boundary.firstClusterUUID = intent.firstClusterUUID;
  boundary.secondClusterUUID = intent.secondClusterUUID;
  boundary.firstWorkspace = "/tmp/prodigy-control-first"_ctv;
  boundary.secondWorkspace = "/tmp/prodigy-control-second"_ctv;
  boundary.firstRuntimeIdentity = "4701"_ctv;
  boundary.secondRuntimeIdentity = "4702"_ctv;
  boundary.firstPrivateIPv6Subnet = "fd42:4242:4242:1::/64"_ctv;
  boundary.secondPrivateIPv6Subnet = "fd42:4242:4242:2::/64"_ctv;
  boundary.firstEndpoints = intent.firstEndpoints;
  boundary.secondEndpoints = intent.secondEndpoints;
  boundary.port = mothershipPairControlBoundaryPort;
  return boundary;
}

static MothershipPairControlServiceTransit validPairControlServiceTransit(
    const MothershipClusterPairEnrollmentIntent& intent)
{
  MothershipPairControlServiceTransit transit = {};
  transit.sourceClusterUUID = intent.firstClusterUUID;
  transit.destinationClusterUUID = intent.secondClusterUUID;
  transit.sourceDeploymentID = (uint64_t(7) << 48) | 1;
  transit.destinationDeploymentID = (uint64_t(19) << 48) | 1;
  transit.sourcePermissionUUID = 0x906;
  transit.destinationPermissionUUID = 0x907;
  transit.sourceSlot = 0;
  transit.sourceWhiteholeAddress = IPAddress("2001:db8:100:1::2", true);
  transit.sourceTCPPort = 42001;
  transit.destinationWormholeAddress = IPAddress("2001:db8:100:2::3", true);
  transit.destinationTCPPort = 9443;
  transit.sourceIngressPrivate6 = intent.firstEndpoints.front().address;
  transit.destinationIngressPrivate6 = intent.secondEndpoints.front().address;
  return transit;
}

int main(void)
{
  TestSuite suite;
#ifdef __linux__
  if (std::getenv("PRODIGY_TEST_PRIVATE_BGP_HOP_LIMIT_ONLY") != nullptr)
  {
    int fd = ::socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int hopLimit = 0; socklen_t length = sizeof(hopLimit);
    const bool configured = fd >= 0 && bgpConfigurePrivateMasqueHopLimit(fd) &&
        ::getsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hopLimit, &length) == 0;
    suite.require(configured && hopLimit == 2 && BGP_PRIVATE_MASQUE_HOP_LIMIT == 2,
        "private_bgp_hop_limit_survives_one_connect_ip_forward");
    if (fd >= 0) ::close(fd);
    return suite.failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
  }
#endif
  static_assert(MeshRegistry::Pulse::seeding == MeshServices::generateStatefulService(2, 4));
  static_assert(MeshRegistry::Radar::seeding == MeshServices::generateStatefulService(5, 4));
  static_assert(MeshRegistry::Pulse::seeders == MeshRegistry::Pulse::seeding);
  for (uint16_t app : {2, 5}) {
    const uint64_t canonical = app == 2 ? MeshRegistry::Pulse::seeding : MeshRegistry::Radar::seeding;
    const uint64_t legacy = app == 2 ? MeshRegistry::Pulse::legacySeedingSlot3 : MeshRegistry::Radar::legacySeedingSlot3;
    const String name = app == 2 ? String("MeshRegistry::Pulse::seeding"_ctv) : String("MeshRegistry::Radar::seeding"_ctv);
    const auto mapping = MeshRegistry::serviceMappings.find(name);
    StatefulDeploymentPlan plan = {}; plan.seedingPrefix = prodigyRuntimeStatefulServicePrefix(app, 4);
    const auto roles = StatefulMeshRoles::forShardGroup(plan, app, 0);
    suite.require(mapping != MeshRegistry::serviceMappings.end() && mapping->second == canonical &&
        roles.seeding == MeshServices::constrainPrefixToGroup(canonical, 0) && canonical != legacy,
        "graph_symbolic_seeding_mapping_matches_canonical_plan_role_not_legacy_slot3");
  }
  for (uint32_t version : {1u, 2u}) {
    auto old = validLocalCousinPermission(); old.protocolVersion = version;
    if (version == 2) { old.baselineLogicalCores = 2; old.baselineMemoryMB = 1024; old.baselineStorageMB = 4096; }
    LegacyPermissionWire frozen = {old}; String expected = {}, actual = {};
    ProdigyLocalCousinServicePermission decoded = {};
    suite.require(BitseryEngine::serialize(expected, frozen) && BitseryEngine::serialize(actual, old) && actual == expected &&
        BitseryEngine::deserializeSafe(expected, decoded) && prodigyLocalCousinServicePermissionEqual(old, decoded),
        version == 1 ? "permission_v1_frozen_wire_bytes_unchanged" : "permission_v2_frozen_wire_bytes_unchanged");
    old.transportSourcePolicy = ProdigyCousinTransportSourcePolicy::authenticatedNAT;
    suite.require(!prodigyLocalCousinServicePermissionValid(old), "legacy_permission_never_authorizes_nat");
  }
  for (auto purpose : {ProdigyCousinServicePurpose::clientAuthority, ProdigyCousinServicePurpose::sibling, ProdigyCousinServicePurpose::seeding}) {
    auto source = purposePermission(purpose);
    auto destination = source; destination.localHalf = CousinRouteHalf::destination; ++destination.permissionUUID;
    std::swap(destination.localClusterUUID, destination.peerClusterUUID);
    std::swap(destination.localApplicationID, destination.peerApplicationID);
    std::swap(destination.localCousinServicePrefix, destination.peerCousinServicePrefix);
    std::swap(destination.localDeploymentID, destination.peerDeploymentID);
    std::swap(destination.canonicalPlanSHA256, destination.peerCanonicalPlanSHA256);
    std::swap(destination.artifactSHA256, destination.peerArtifactSHA256);
    std::swap(destination.artifactBytes, destination.peerArtifactBytes);
    auto counterpart = validCousinCounterpart(); counterpart.permission = destination;
    counterpart.shardGroup = 0; counterpart.shardGroups = 1; counterpart.service = source.authorizedService;
    counterpart.ownedSlots = source.slots;
    suite.require(prodigyLocalCousinServicePermissionValid(source) && prodigyLocalCousinServicePermissionValid(destination) &&
        prodigyCousinCounterpartMatchesPermission(counterpart, source, 0), "v3_exact_purpose_peer_deployment_discovery");
    if (purpose == ProdigyCousinServicePurpose::seeding) {
      auto privatePeer = counterpart; privatePeer.routablePrefixUUID = 0; privatePeer.wormholeRevision.clear();
      privatePeer.publicTCPPort = privatePeer.servicePort;
      CousinRouteRecord privateRoute = {}; privateRoute.version = 3;
      privateRoute.endpointKind = CousinRouteEndpointKind::privateContainer; privateRoute.destinationCIDR = 128;
      privateRoute.destinationPublicAddress = privatePeer.publicAddress; privateRoute.destinationTCPPort = privatePeer.publicTCPPort;
      MothershipNametagAllMastersSeedPlacement row = {}; row.applicationID = destination.localApplicationID;
      row.storeKind = DeploymentIdentityStoreKind::kv; row.shardGroup = privatePeer.shardGroup;
      row.sourceClusterUUID = destination.localClusterUUID; row.sourceDeploymentID = destination.localDeploymentID;
      row.sourceContainerUUID = privatePeer.containerUUID;
      ProdigyStatefulStoreSeedAuthority authority = {}; authority.sourceClusterUUID = row.sourceClusterUUID;
      authority.sourceDeploymentID = row.sourceDeploymentID; authority.sourceContainerUUID = row.sourceContainerUUID;
      authority.applicationID = row.applicationID; authority.storeKind = row.storeKind;
      authority.shardGroup = row.shardGroup; authority.nShardGroups = privatePeer.shardGroups;
      DeploymentIdentityReport report = {}; report.version = 4; report.found = report.live = report.isStateful = true;
      // An initial source has no remote seed receipt and need not be converged.
      report.statefulRuntimeCohortConverged = false; report.clusterUUID = row.sourceClusterUUID;
      report.deploymentID = row.sourceDeploymentID; report.applicationID = row.applicationID;
      report.nShardGroups = authority.nShardGroups; report.nHealthy = report.nDeployed = report.nTarget = 3;
      DeploymentIdentityStatefulMember member = {}; member.containerUUID = member.replicaUUID = row.sourceContainerUUID;
      member.clusterUUID = row.sourceClusterUUID; member.machineUUID = privatePeer.nodeUUID;
      member.shardGroup = row.shardGroup; member.storeKind = row.storeKind; member.allMasters = true;
      report.statefulRuntimeCohort.push_back(member);
      auto sibling = member; ++sibling.containerUUID; ++sibling.replicaUUID; report.statefulRuntimeCohort.push_back(sibling);
      ++sibling.containerUUID; ++sibling.replicaUUID; report.statefulRuntimeCohort.push_back(sibling);
      auto matches = [&] { return mothershipNametagPrivateSeedCounterpartMatches(row, authority, privateRoute,
          source, destination, 0, report, privatePeer); };
      suite.require(matches(), "private_seed_route_accepts_exact_live_source_counterpart");
      ++privatePeer.containerUUID; suite.require(!matches(), "private_seed_route_rejects_other_container"); --privatePeer.containerUUID;
      ++report.statefulRuntimeCohort[0].machineUUID; suite.require(!matches(), "private_seed_route_rejects_other_machine"); --report.statefulRuntimeCohort[0].machineUUID;
      privateRoute.destinationPublicAddress = IPAddress("fd42:4242:4242:2::45", true);
      suite.require(!matches(), "private_seed_route_rejects_other_address");
      privateRoute.destinationPublicAddress = privatePeer.publicAddress; ++privateRoute.destinationTCPPort;
      suite.require(!matches(), "private_seed_route_rejects_other_port"); --privateRoute.destinationTCPPort;
      report.live = false; suite.require(!matches(), "private_seed_route_rejects_stale_report"); report.live = true;
      ++authority.sourceContainerUUID; suite.require(!matches(), "private_seed_route_rejects_other_cut_source"); --authority.sourceContainerUUID;
      ++privatePeer.permission.permissionUUID; suite.require(!matches(), "private_seed_route_rejects_other_permission"); --privatePeer.permission.permissionUUID;
      privateRoute.destinationRoutablePrefixUUID = 1; suite.require(!matches(), "private_seed_route_rejects_prefix_claim");
    }
    auto wrong = source; wrong.peerCanonicalPlanSHA256[0] = 'e';
    suite.require(!prodigyCousinCounterpartMatchesPermission(counterpart, wrong, 0), "v3_rejects_peer_plan_substitution");
    wrong = source; ++wrong.peerDeploymentID;
    suite.require(!prodigyCousinCounterpartMatchesPermission(counterpart, wrong, 0), "v3_rejects_peer_deployment_substitution");
    wrong = source; wrong.slots.insert(1);
    suite.require(!prodigyLocalCousinServicePermissionValid(wrong), "v3_nonlegacy_rejects_extra_logical_group");
    counterpart.shardGroups = 2;
    suite.require(!prodigyCousinCounterpartValid(counterpart), "v3_nonlegacy_rejects_multigroup_destination");
    auto ingress = purposePermission(purpose, false); auto json = purposePermissionJSON(ingress);
    ProdigyLocalCousinServicePermission parsed = {}; String failure = {}, bytes = {};
    suite.require(parseLocalCousinPermissionJSON(String(json.c_str()), parsed, failure) &&
        prodigyLocalCousinServicePermissionIdentityScopeMatches(ingress, parsed) &&
        prodigyLocalCousinServicePermissionRequestAccepted(parsed, source), "v3_strict_parser_accepts_exact_owner_baseline_enrichment");
    auto malformed = json; malformed.replace(malformed.find("\"exact\""), 7, "\"anything\"");
    suite.require(!parseLocalCousinPermissionJSON(String(malformed.c_str()), parsed, failure), "v3_parser_rejects_unknown_transport_policy");
    malformed = json; malformed.erase(malformed.find(",\"transportSourcePolicy\"")); malformed += "}";
    suite.require(!parseLocalCousinPermissionJSON(String(malformed.c_str()), parsed, failure), "v3_parser_rejects_partial_extension");
    malformed = json; malformed.insert(malformed.size() - 1, ",\"purpose\":\"sibling\"");
    suite.require(!parseLocalCousinPermissionJSON(String(malformed.c_str()), parsed, failure), "v3_parser_rejects_duplicate_purpose");
    suite.require(BitseryEngine::serialize(bytes, source) && BitseryEngine::deserializeSafe(bytes, parsed) &&
        prodigyLocalCousinServicePermissionEqual(source, parsed), "v3_permission_wire_roundtrip_binds_full_scope");
    DeploymentPlan plan = {}; plan.config.applicationID = source.localApplicationID; plan.config.versionID = 1;
    plan.config.containerBlobSHA256 = source.artifactSHA256; plan.config.containerBlobBytes = source.artifactBytes;
    plan.isStateful = purpose != ProdigyCousinServicePurpose::clientAuthority;
    plan.config.type = plan.isStateful ? ApplicationType::stateful : ApplicationType::stateless;
    Whitehole declaration = {}; plan.whiteholes.push_back(declaration);
    plan.stateful.neverShard = true;
    plan.stateful.clientPrefix = MeshRegistry::Pulse::clients;
    plan.stateful.siblingPrefix = MeshRegistry::Pulse::siblings; plan.stateful.seedingPrefix = MeshRegistry::Pulse::seeding;
    plan.subscriptions.emplace_back(MeshRegistry::Truth::clients, ContainerState::healthy, ContainerState::destroying, SubscriptionNature::all);
    suite.require(prodigyCousinPermissionPlanServiceMatches(source, plan), "v3_live_plan_declares_exact_purpose_service");
    plan.whiteholes.clear();
    suite.require(prodigyCousinPermissionPlanServiceMatches(source, plan),
        "private_purpose_plan_requires_no_public_source_allocation");
    plan.useHostNetworkNamespace = true;
    suite.require(!prodigyCousinPermissionPlanServiceMatches(source, plan),
        "private_purpose_plan_never_admits_host_namespace");
    plan.useHostNetworkNamespace = false;
    plan.whiteholes.push_back(declaration);
    StatefulTopology catchup = {}; catchup.servingMode = StatefulTopologyServingMode::catchupOnly;
    suite.require(prodigyCousinSourceContainerStateEligible(source, ContainerState::scheduled, true, catchup),
        "purpose_source_can_start_before_healthy_when_runtime_ready");
    suite.require(!prodigyCousinSourceContainerStateEligible(source, ContainerState::scheduled, false, catchup),
        "graph_seed_requires_runtime_ready_even_before_healthy");
    catchup.servingMode = StatefulTopologyServingMode::serve;
    suite.require(prodigyCousinSourceContainerStateEligible(source, ContainerState::scheduled, true, catchup) ==
        (purpose == ProdigyCousinServicePurpose::clientAuthority),
        "prehealthy_writer_cannot_bypass_graph_source_gate");
    if (purpose == ProdigyCousinServicePurpose::clientAuthority) {
      suite.require(prodigyCousinSourceContainerStateEligible(source, ContainerState::crashedRestarting, true, catchup),
          "client_authority_runtime_ready_restart_is_eligible");
      suite.require(!prodigyCousinSourceContainerStateEligible(source, ContainerState::destroying, true, catchup),
          "client_authority_destroying_is_ineligible");
      auto invalidSource = source; invalidSource.localHalf = CousinRouteHalf::destination;
      suite.require(!prodigyCousinSourceContainerStateEligible(invalidSource, ContainerState::scheduled, true, catchup),
          "client_authority_destination_cannot_bootstrap_as_source");
      invalidSource = source; invalidSource.protocolVersion = 1;
      suite.require(!prodigyCousinSourceContainerStateEligible(invalidSource, ContainerState::scheduled, true, catchup),
          "legacy_client_authority_cannot_bootstrap_as_source");
      plan.subscriptions.clear();
      suite.require(!prodigyCousinPermissionPlanServiceMatches(source, plan), "client_authority_requires_exact_truth_subscription");
      plan.subscriptions.emplace_back(MeshRegistry::Hot::clients, ContainerState::healthy, ContainerState::destroying, SubscriptionNature::all);
      suite.require(!prodigyCousinPermissionPlanServiceMatches(source, plan), "client_authority_rejects_other_database_subscription");
    } else {
      plan.stateful.neverShard = false;
      suite.require(!prodigyCousinPermissionPlanServiceMatches(source, plan), "graph_permission_requires_one_group_plan");
    }
    plan.whiteholes.push_back(declaration);
    suite.require(!prodigyCousinAutomaticWhiteholePlanValid(plan.whiteholes), "automatic_permission_rejects_ambiguous_source_bindings");
  }
  for (uint16_t app : {2, 3, 4, 5, 10}) {
    const bool sharded = app == 3 || app == 4;
    for (uint16_t group : {uint16_t(0), uint16_t(sharded ? 2 : 0)}) {
      const uint16_t groups = sharded ? 4 : 1;
      auto source = purposePermission(ProdigyCousinServicePurpose::clientAuthority, true, app, group, groups);
      auto destination = source; destination.localHalf = CousinRouteHalf::destination; ++destination.permissionUUID;
      std::swap(destination.localClusterUUID, destination.peerClusterUUID);
      std::swap(destination.localApplicationID, destination.peerApplicationID);
      std::swap(destination.localCousinServicePrefix, destination.peerCousinServicePrefix);
      std::swap(destination.localDeploymentID, destination.peerDeploymentID);
      std::swap(destination.canonicalPlanSHA256, destination.peerCanonicalPlanSHA256);
      std::swap(destination.artifactSHA256, destination.peerArtifactSHA256);
      std::swap(destination.artifactBytes, destination.peerArtifactBytes);
      uint16_t slot = 0;
      suite.require(prodigyCousinServicePermissionSingleSlot(source, slot) &&
          prodigyLocalCousinServicePermissionValid(source) && prodigyLocalCousinServicePermissionValid(destination),
          "client_authority_all_five_databases_bind_one_exact_shard_and_owned_slot");
      auto counterpart = validCousinCounterpart(); counterpart.permission = destination;
      counterpart.shardGroup = group; counterpart.shardGroups = groups; counterpart.service = source.authorizedService;
      counterpart.ownedSlots = source.slots;
      suite.require(prodigyCousinCounterpartMatchesPermission(counterpart, source, slot),
          "client_authority_discovery_accepts_exact_retained_or_nonzero_sharded_topology");
      auto changed = counterpart; ++changed.shardGroups;
      suite.require(!prodigyCousinCounterpartValid(changed), "client_authority_discovery_rejects_changed_group_count");
      auto wrong = source; ++wrong.destinationShardGroup;
      suite.require(!prodigyLocalCousinServicePermissionValid(wrong), "client_authority_rejects_group_service_mismatch");
      wrong = source; wrong.peerCousinServicePrefix = MeshRegistry::Truth::siblings;
      wrong.authorizedService = MeshServices::constrainPrefixToGroup(wrong.peerCousinServicePrefix, group);
      suite.require(!prodigyLocalCousinServicePermissionValid(wrong), "client_authority_rejects_wrong_database_role_prefix");
      wrong = source; wrong.peerApplicationID = 11; wrong.peerDeploymentID = uint64_t(11) << 48 | 2;
      suite.require(!prodigyLocalCousinServicePermissionValid(wrong), "client_authority_rejects_wrong_peer_application");
      wrong = source; wrong.localApplicationID = 7; wrong.localDeploymentID = uint64_t(7) << 48 | 1;
      wrong.localCousinServicePrefix = MeshServices::generateStatefulService(7, 1);
      suite.require(!prodigyLocalCousinServicePermissionValid(wrong), "client_authority_source_is_only_app6_authentication_prefix");
      auto ingress = purposePermission(ProdigyCousinServicePurpose::clientAuthority, false, app, group, groups);
      auto json = purposePermissionJSON(ingress); ProdigyLocalCousinServicePermission parsed = {}; String failure = {}, bytes = {};
      suite.require(parseLocalCousinPermissionJSON(String(json.c_str()), parsed, failure) &&
          prodigyLocalCousinServicePermissionIdentityScopeMatches(ingress, parsed) &&
          BitseryEngine::serialize(bytes, source) && BitseryEngine::deserializeSafe(bytes, parsed) &&
          prodigyLocalCousinServicePermissionEqual(source, parsed), "client_authority_parser_and_wire_bind_exact_destination_topology");
      auto malformed = json; malformed.insert(malformed.size() - 1, ",\"destinationShardGroup\":0");
      suite.require(!parseLocalCousinPermissionJSON(String(malformed.c_str()), parsed, failure),
          "client_authority_parser_rejects_duplicate_topology_field");
      DeploymentPlan plan = {}; plan.config.applicationID = 6; plan.config.versionID = 1;
      plan.config.type = ApplicationType::stateless; plan.config.containerBlobSHA256 = source.artifactSHA256;
      plan.config.containerBlobBytes = source.artifactBytes; plan.whiteholes.push_back(Whitehole{});
      plan.subscriptions.emplace_back(source.peerCousinServicePrefix, ContainerState::healthy, ContainerState::destroying, SubscriptionNature::all);
      suite.require(prodigyCousinPermissionPlanServiceMatches(source, plan), "app6_plan_requires_selected_database_clients_prefix");
      auto exactOnly = plan; exactOnly.subscriptions.front().service = source.authorizedService;
      suite.require(!prodigyCousinPermissionPlanServiceMatches(source, exactOnly), "full_app6_plan_requires_prefix_not_ad_hoc_exact_service");
      ContainerPlan materialized = {}; materialized.config = plan.config; materialized.state = ContainerState::healthy;
      materialized.runtimeReady = true; materialized.whiteholes = plan.whiteholes;
      materialized.subscriptions.emplace(source.peerCousinServicePrefix, plan.subscriptions.front());
      const uint64_t sourceService = MeshServices::constrainPrefixToGroup(source.localCousinServicePrefix, 0);
      suite.require(prodigyCousinPermissionContainerPlanMatches(source, materialized, sourceService),
          "materialized_app6_plan_accepts_exact_declared_database_prefix");
      materialized.state = ContainerState::scheduled;
      suite.require(!prodigyCousinPermissionContainerPlanMatches(source, materialized, sourceService),
          "scheduled_client_requires_subscription_active_before_healthy");
      materialized.subscriptions.at(source.peerCousinServicePrefix).startAt = ContainerState::scheduled;
      suite.require(prodigyCousinPermissionContainerPlanMatches(source, materialized, sourceService),
          "scheduled_client_accepts_exact_active_subscription");
      materialized.runtimeReady = false;
      suite.require(!prodigyCousinPermissionContainerPlanMatches(source, materialized, sourceService),
          "scheduled_client_requires_runtime_ready");
      materialized.runtimeReady = true; materialized.state = ContainerState::healthy;
      materialized.whiteholes.clear();
      suite.require(prodigyCousinPermissionContainerPlanMatches(source, materialized, sourceService),
          "private_materialized_app6_uses_exact_subscription_without_public_source_allocation");
      materialized.subscriptions.clear(); auto exact = plan.subscriptions.front(); exact.service = source.authorizedService;
      materialized.subscriptions.emplace(exact.service, exact);
      suite.require(prodigyCousinPermissionContainerPlanMatches(source, materialized, sourceService),
          "materialized_app6_plan_accepts_only_selected_exact_shard_under_prefix");
      materialized.subscriptions.clear(); exact.service = MeshServices::constrainPrefixToGroup(source.peerCousinServicePrefix, group + 1);
      materialized.subscriptions.emplace(exact.service, exact);
      suite.require(!prodigyCousinPermissionContainerPlanMatches(source, materialized, sourceService),
          "materialized_app6_plan_rejects_other_shard_under_same_prefix");
      if (app == 10) {
        auto probe = source; probe.localApplicationID = 11;
        probe.localDeploymentID = uint64_t(11) << 48 | 1;
        probe.localCousinServicePrefix = MeshServices::generateStatefulService(11, 1);
        suite.require(prodigyLocalCousinServicePermissionValid(probe), "probe_client_authority_identity_is_valid");
        auto wrongProbe = probe; wrongProbe.localCousinServicePrefix = MeshServices::generateStatefulService(6, 1);
        suite.require(!prodigyLocalCousinServicePermissionValid(wrongProbe), "probe_rejects_other_source_identity");
        auto probePlan = plan; probePlan.config.applicationID = 11; probePlan.whiteholes.clear();
        Whitehole quic = {}; quic.transport = ExternalAddressTransport::quic;
        for (uint32_t i = 0; i < 16; ++i) probePlan.whiteholes.push_back(quic);
        suite.require(prodigyCousinPermissionPlanServiceMatches(probe, probePlan),
            "probe_plan_accepts_private_client_authority_with_quic_whiteholes");
        ContainerPlan probeContainer = {}; probeContainer.config = probePlan.config;
        probeContainer.state = ContainerState::scheduled; probeContainer.runtimeReady = true;
        probeContainer.whiteholes = probePlan.whiteholes;
        auto scheduledSubscription = probePlan.subscriptions.front(); scheduledSubscription.startAt = ContainerState::scheduled;
        probeContainer.subscriptions.emplace(scheduledSubscription.service, scheduledSubscription);
        const uint64_t probeService = MeshServices::constrainPrefixToGroup(probe.localCousinServicePrefix, 0);
        suite.require(prodigyCousinPermissionContainerPlanMatches(probe, probeContainer, probeService, true),
            "probe_private_session_accepts_sixteen_quic_whiteholes");
        suite.require(!prodigyCousinPermissionContainerPlanMatches(probe, probeContainer, probeService),
            "probe_public_session_rejects_quic_whiteholes");
        probeContainer.config.applicationID = 6;
        suite.require(!prodigyCousinPermissionContainerPlanMatches(probe, probeContainer, probeService, true),
            "probe_private_session_rejects_wrong_application_identity");
      }
      DeploymentPlan peer = {}; peer.config.applicationID = app; peer.config.versionID = 2; peer.config.type = ApplicationType::stateful;
      peer.config.containerBlobSHA256 = destination.artifactSHA256; peer.config.containerBlobBytes = destination.artifactBytes;
      peer.isStateful = true; peer.stateful.neverShard = !sharded; peer.stateful.clientPrefix = destination.localCousinServicePrefix;
      suite.require(prodigyCousinPermissionPlanServiceMatches(destination, peer), "destination_plan_matches_exact_database_client_role_and_group");
      ContainerPlan peerPlan = {}; peerPlan.config = peer.config; peerPlan.isStateful = true; peerPlan.state = ContainerState::healthy;
      peerPlan.runtimeReady = true; peerPlan.shardGroup = group; peerPlan.nShardGroups = groups;
      peerPlan.statefulMeshRoles = StatefulMeshRoles::forShardGroup(peer.stateful, app, group);
      peerPlan.statefulTopology.servingMode = StatefulTopologyServingMode::serve;
      suite.require(prodigyCousinPermissionContainerPlanMatches(destination, peerPlan, source.authorizedService),
          "destination_materialized_plan_matches_exact_authoritative_shard");
      peerPlan.nShardGroups += 65536;
      suite.require(!prodigyCousinPermissionContainerPlanMatches(destination, peerPlan, source.authorizedService),
          "destination_topology_validation_never_truncates_group_count");
      peerPlan.nShardGroups = groups; peerPlan.statefulTopology.servingMode = StatefulTopologyServingMode::catchupOnly;
      suite.require(!prodigyCousinPermissionContainerPlanMatches(destination, peerPlan, source.authorizedService),
          "destination_client_authority_rejects_nonwriter_catchup_only");
      if (!sharded) {
        wrong = source; wrong.destinationShardGroups = 2;
        suite.require(!prodigyLocalCousinServicePermissionValid(wrong), "retained_databases_reject_multiple_groups");
      }
    }
  }
  for (uint16_t app : {3, 4}) {
    auto permission = purposePermission(ProdigyCousinServicePurpose::sibling);
    permission.purpose = ProdigyCousinServicePurpose::statefulCousin;
    permission.localApplicationID = permission.peerApplicationID = app;
    permission.localDeploymentID = uint64_t(app) << 48 | 1;
    permission.peerDeploymentID = uint64_t(app) << 48 | 2;
    permission.localCousinServicePrefix = permission.peerCousinServicePrefix =
        app == 3 ? MeshServices::generateStatefulService(3, 3) : MeshServices::generateStatefulService(4, 3);
    permission.authorizedService = MeshServices::constrainPrefixToGroup(permission.peerCousinServicePrefix, 0);
    permission.destinationShardGroup = permission.destinationShardGroups = 0;
    suite.require(prodigyLocalCousinServicePermissionValid(permission), "private_kv_permission_preserves_purpose_scope");
    DeploymentPlan plan = {};
    plan.config.applicationID = app; plan.config.versionID = 1; plan.config.type = ApplicationType::stateful;
    plan.config.containerBlobSHA256 = permission.artifactSHA256; plan.config.containerBlobBytes = permission.artifactBytes;
    plan.isStateful = true; plan.stateful.cousinPrefix = permission.localCousinServicePrefix;
    for (auto half : {CousinRouteHalf::source, CousinRouteHalf::destination}) {
      permission.localHalf = half;
      suite.require(prodigyCousinPermissionPlanServiceMatches(permission, plan),
          "private_kv_plan_accepts_both_halves_without_public_allocations");
      plan.useHostNetworkNamespace = true;
      suite.require(!prodigyCousinPermissionPlanServiceMatches(permission, plan), "private_kv_plan_rejects_host_namespace");
      plan.useHostNetworkNamespace = false;
      ++plan.stateful.cousinPrefix;
      suite.require(!prodigyCousinPermissionPlanServiceMatches(permission, plan), "private_kv_plan_rejects_wrong_cousin_service");
      --plan.stateful.cousinPrefix;
    }
  }
  for (auto purpose : {ProdigyCousinServicePurpose::sibling, ProdigyCousinServicePurpose::seeding}) {
    for (uint16_t app : {2, 5}) {
      auto graph = purposePermission(purpose);
      graph.localApplicationID = graph.peerApplicationID = app;
      graph.localDeploymentID = uint64_t(app) << 48 | 1; graph.peerDeploymentID = uint64_t(app) << 48 | 2;
      graph.localCousinServicePrefix = graph.peerCousinServicePrefix = purpose == ProdigyCousinServicePurpose::sibling ?
          (app == 2 ? MeshRegistry::Pulse::siblings : MeshRegistry::Radar::siblings) :
          (app == 2 ? MeshRegistry::Pulse::seeding : MeshRegistry::Radar::seeding);
      graph.authorizedService = MeshServices::constrainPrefixToGroup(graph.peerCousinServicePrefix, 0);
      suite.require(prodigyLocalCousinServicePermissionValid(graph), "graph_sibling_and_seeding_are_exact_one_group_nonclient_roles");
      auto wrong = graph; wrong.localCousinServicePrefix = wrong.peerCousinServicePrefix = prodigyCousinClientAuthorityPrefix(app);
      wrong.authorizedService = MeshServices::constrainPrefixToGroup(wrong.peerCousinServicePrefix, 0);
      suite.require(!prodigyLocalCousinServicePermissionValid(wrong), "graph_nonclient_purpose_cannot_authorize_clients");
      wrong = graph; wrong.purpose = purpose == ProdigyCousinServicePurpose::sibling ? ProdigyCousinServicePurpose::seeding : ProdigyCousinServicePurpose::sibling;
      suite.require(!prodigyLocalCousinServicePermissionValid(wrong), "graph_purpose_cannot_authorize_another_nonclient_role");
      wrong = graph; wrong.destinationShardGroups = 2;
      suite.require(!prodigyLocalCousinServicePermissionValid(wrong), "graph_nonclient_purposes_remain_one_group_only");
      if (purpose == ProdigyCousinServicePurpose::seeding) {
        wrong = graph; wrong.localCousinServicePrefix = wrong.peerCousinServicePrefix =
            app == 2 ? MeshRegistry::Pulse::legacySeedingSlot3 : MeshRegistry::Radar::legacySeedingSlot3;
        wrong.authorizedService = MeshServices::constrainPrefixToGroup(wrong.peerCousinServicePrefix, 0);
        suite.require(!prodigyLocalCousinServicePermissionValid(wrong), "graph_seeding_permission_rejects_legacy_slot3_identity");
      }
    }
  }
  for (uint16_t app : {3, 4}) for (uint16_t group = 0; group < 3; ++group) {
    auto seed = purposePermission(ProdigyCousinServicePurpose::seeding, true, app, group, 3);
    seed.localApplicationID = seed.peerApplicationID = app;
    seed.localDeploymentID = (uint64_t(app) << 48) | 1; seed.peerDeploymentID = (uint64_t(app) << 48) | 2;
    seed.localCousinServicePrefix = seed.peerCousinServicePrefix = app == 3 ? MeshRegistry::Hot::seeding : MeshRegistry::Cold::seeding;
    seed.authorizedService = MeshServices::constrainPrefixToGroup(seed.peerCousinServicePrefix, group);
    suite.require(prodigyLocalCousinServicePermissionValid(seed) &&
        prodigyCousinServicePermissionGroupValid(seed, group, 3), "kv_seed_permission_binds_exact_shard_group");
    suite.require(!prodigyCousinServicePermissionGroupValid(seed, (group + 1) % 3, 3), "kv_seed_permission_rejects_other_group");
    auto wrong = seed; wrong.peerApplicationID = app == 3 ? 4 : 3;
    wrong.peerDeploymentID = (uint64_t(wrong.peerApplicationID) << 48) | 2;
    suite.require(!prodigyLocalCousinServicePermissionValid(wrong), "kv_seed_permission_rejects_other_application");
  }
  ProdigyLocalCousinServicePermission permission = validLocalCousinPermission();
  suite.require(prodigyLocalCousinServicePermissionValid(permission),
                "local_cousin_permission_accepts_asymmetric_application_mapping");
  auto requestedPermission = validLocalCousinPermission(false);
  auto acceptedV2Permission = requestedPermission;
  acceptedV2Permission.protocolVersion = 2;
  acceptedV2Permission.baselineLogicalCores = 1;
  acceptedV2Permission.baselineMemoryMB = 64;
  acceptedV2Permission.baselineStorageMB = 64;
  acceptedV2Permission.acceptedAuthorityGeneration = 8;
  suite.require(prodigyLocalCousinServicePermissionRequestAccepted(requestedPermission, acceptedV2Permission),
                "local_cousin_permission_receipt_accepts_only_server_v1_to_v2_baseline_enrichment");
  auto exactV1Permission = requestedPermission;
  exactV1Permission.acceptedAuthorityGeneration = 8;
  suite.require(prodigyLocalCousinServicePermissionRequestAccepted(requestedPermission, exactV1Permission),
                "local_cousin_permission_receipt_accepts_exact_legacy_v1_record");
  auto requestedV2Revoke = acceptedV2Permission;
  requestedV2Revoke.acceptedAuthorityGeneration = 0;
  requestedV2Revoke.state = ProdigyLocalCousinServicePermissionState::revoked;
  requestedV2Revoke.generation = 2;
  auto acceptedV2Revoke = requestedV2Revoke;
  acceptedV2Revoke.acceptedAuthorityGeneration = 9;
  suite.require(prodigyLocalCousinServicePermissionRequestAccepted(requestedV2Revoke, acceptedV2Revoke),
                "local_cousin_permission_receipt_requires_exact_v2_revoke_baseline");
  auto requestedV2Permission = acceptedV2Permission;
  requestedV2Permission.acceptedAuthorityGeneration = 0;
  auto alteredReceipt = acceptedV2Permission; ++alteredReceipt.baselineMemoryMB;
  suite.require(!prodigyLocalCousinServicePermissionRequestAccepted(requestedV2Permission, alteredReceipt),
                "local_cousin_permission_receipt_rejects_altered_v2_baseline");
  alteredReceipt = acceptedV2Permission; ++alteredReceipt.logicalServiceUUID;
  suite.require(!prodigyLocalCousinServicePermissionRequestAccepted(requestedPermission, alteredReceipt),
                "local_cousin_permission_receipt_rejects_identity_change");
  alteredReceipt = acceptedV2Permission; alteredReceipt.state = ProdigyLocalCousinServicePermissionState::revoked; alteredReceipt.generation = 2;
  suite.require(!prodigyLocalCousinServicePermissionRequestAccepted(requestedPermission, alteredReceipt),
                "local_cousin_permission_receipt_rejects_state_generation_change");
  auto malformedV1Request = requestedPermission; malformedV1Request.baselineMemoryMB = 64;
  auto invalidV2Receipt = acceptedV2Permission; invalidV2Receipt.baselineLogicalCores = 0;
  suite.require(!prodigyLocalCousinServicePermissionRequestAccepted(malformedV1Request, acceptedV2Permission) &&
                    !prodigyLocalCousinServicePermissionRequestAccepted(requestedPermission, invalidV2Receipt),
                "local_cousin_permission_receipt_rejects_malformed_v1_or_invalid_v2_record");
  ProdigyCousinDiscoverySnapshot discovery = validCousinDiscoverySnapshot();
  ProdigyClusterPairEnrollmentResponse capability = {};
  capability.protocolVersion = ProdigyClusterPairEnrollmentResponse::capabilityVersion;
  capability.privateDiscoverySupported = true;
  String capabilityBytes = {}; ProdigyClusterPairEnrollmentResponse decodedCapability = {};
  suite.require(BitseryEngine::serialize(capabilityBytes, capability) &&
                BitseryEngine::deserializeSafe(capabilityBytes, decodedCapability) &&
                decodedCapability.protocolVersion == ProdigyClusterPairEnrollmentResponse::capabilityVersion &&
                decodedCapability.privateDiscoverySupported, "pair_enrollment_capability_v2_roundtrip");
  capability.protocolVersion = ProdigyClusterPairEnrollmentResponse::version;
  capability.privateDiscoverySupported = false;
  capabilityBytes.clear(); decodedCapability = {};
  suite.require(BitseryEngine::serialize(capabilityBytes, capability) &&
                BitseryEngine::deserializeSafe(capabilityBytes, decodedCapability) &&
                !decodedCapability.privateDiscoverySupported, "pair_enrollment_capability_legacy_defaults_false");
  suite.require(prodigyCousinDiscoverySnapshotValid(discovery),
                "cousin_discovery_accepts_exact_destination_counterpart_slots");
  auto privateDiscovery = discovery;
  privateDiscovery.records[0].routablePrefixUUID = 0;
  privateDiscovery.records[0].wormholeRevision.clear();
  privateDiscovery.records[0].publicTCPPort = privateDiscovery.records[0].servicePort;
  suite.require(!prodigyCousinDiscoverySnapshotValid(privateDiscovery), "legacy_discovery_rejects_private_endpoint");
  privateDiscovery.protocolVersion = ProdigyCousinDiscoverySnapshot::privateContainerVersion;
  suite.require(prodigyCousinDiscoverySnapshotValid(privateDiscovery), "private_discovery_requires_v2");
  privateDiscovery.records[0].publicTCPPort++;
  suite.require(!prodigyCousinDiscoverySnapshotValid(privateDiscovery), "private_discovery_requires_service_port");
  suite.require(prodigyCousinCounterpartMatchesPermission(discovery.records[0], permission, 3),
                "cousin_discovery_matches_asymmetric_source_permission_at_owned_slot");
  auto malformedCounterpart = discovery.records[0];
  malformedCounterpart.ownedSlots.insert(4);
  suite.require(!prodigyCousinCounterpartValid(malformedCounterpart),
                "cousin_discovery_rejects_sender_chosen_slot_subset_or_extra_slot");
  malformedCounterpart = discovery.records[0];
  malformedCounterpart.permission.state = ProdigyLocalCousinServicePermissionState::revoked;
  malformedCounterpart.permission.generation = 2;
  suite.require(!prodigyCousinCounterpartValid(malformedCounterpart),
                "cousin_discovery_rejects_revoked_destination_permission");
  malformedCounterpart = discovery.records[0];
  malformedCounterpart.service = MeshServices::constrainPrefixToGroup(
      malformedCounterpart.permission.localCousinServicePrefix, malformedCounterpart.shardGroup + 1);
  suite.require(!prodigyCousinCounterpartValid(malformedCounterpart),
                "cousin_discovery_rejects_wrong_exact_shard_service");
  discovery.records.push_back(discovery.records[0]);
  suite.require(!prodigyCousinDiscoverySnapshotValid(discovery),
                "cousin_discovery_rejects_duplicate_container_permission_descriptor");
  discovery.records.pop_back();
  String discoveryBytes = {};
  BitseryEngine::serialize(discoveryBytes, discovery);
  ProdigyCousinDiscoverySnapshot decodedDiscovery = {};
  suite.require(discoveryBytes.size() <= ProdigyCousinDiscoveryMaximumBytes &&
                    BitseryEngine::deserializeSafe(discoveryBytes, decodedDiscovery) &&
                    prodigyCousinDiscoverySnapshotValid(decodedDiscovery),
                "cousin_discovery_roundtrips_bounded_snapshot_codec");
  ProdigyCousinDiscoveryQuery discoveryQuery = {};
  discoveryQuery.permissionUUID = permission.permissionUUID;
  discoveryQuery.slot = 3;
  suite.require(prodigyCousinDiscoveryQueryValid(discoveryQuery),
                "cousin_discovery_query_accepts_bounded_permission_slot");
  ProdigyCousinDiscoveryPublication malformedPublication = {};
  malformedPublication.nodeUUID = 0x704;
  malformedPublication.projectionGeneration = 12;
  malformedPublication.snapshot = decodedDiscovery;
  malformedPublication.snapshot.records[0].permission.acceptedAuthorityGeneration = 13;
  suite.require(!prodigyCousinDiscoveryPublicationValid(malformedPublication),
                "cousin_discovery_rejects_record_authority_after_snapshot_authority");
  ProdigyCousinDiscoveryReceipt malformedReceipt = {};
  malformedReceipt.localEndpoint = validPairEndpoint(0x401, 0x705, 7);
  malformedReceipt.remoteEndpoint = validPairEndpoint(0x402, 0x706, 8);
  malformedReceipt.wireEpoch = decodedDiscovery.keyEpoch;
  malformedReceipt.projectionGeneration = 12;
  malformedReceipt.connectionID = 1;
  malformedReceipt.sequence = 1;
  malformedReceipt.snapshot = decodedDiscovery;
  suite.require(prodigyCousinDiscoveryReceiptValid(malformedReceipt),
                "cousin_discovery_receipt_accepts_exact_authenticated_snapshot_binding");
  malformedReceipt.sequence = 0;
  suite.require(!prodigyCousinDiscoveryReceiptValid(malformedReceipt),
                "cousin_discovery_receipt_rejects_replayable_zero_sequence");
  suite.require(prodigyLocalCousinServicePermissionsValid(
                    Vector<ProdigyLocalCousinServicePermission> {permission}, 0x401, 7),
                "local_cousin_permission_vector_is_sorted_and_authority_bounded");
  Vector<ProdigyLocalCousinServicePermission> unsortedPermissions = {permission, permission};
  unsortedPermissions[1].permissionUUID = permission.permissionUUID - 1;
  suite.require(!prodigyLocalCousinServicePermissionsValid(unsortedPermissions, 0x401, 7),
                "local_cousin_permission_vector_rejects_unsorted_identifiers");
  Vector<ProdigyLocalCousinServicePermission> overBoundPermissions = {};
  for (uint32_t index = 0; index <= ProdigyLocalCousinServicePermissionMaximumRecords; ++index)
  {
    ProdigyLocalCousinServicePermission candidate = permission;
    candidate.permissionUUID = uint128_t(index) + 1;
    overBoundPermissions.push_back(std::move(candidate));
  }
  suite.require(!prodigyLocalCousinServicePermissionsValid(overBoundPermissions, 0x401, 7),
                "local_cousin_permission_vector_rejects_more_than_256_records");
  ProdigyLocalCousinServicePermission revokedPermission = permission;
  revokedPermission.generation = 2;
  revokedPermission.state = ProdigyLocalCousinServicePermissionState::revoked;
  suite.require(prodigyLocalCousinServicePermissionValid(revokedPermission) &&
                    prodigyLocalCousinServicePermissionScopeMatches(permission, revokedPermission) &&
                    !prodigyLocalCousinServicePermissionEqual(permission, revokedPermission),
                "local_cousin_permission_retains_immutable_scope_for_tombstone");
  ProdigyLocalCousinServicePermission invalidPermission = permission;
  invalidPermission.peerApplicationID = 20;
  suite.require(!prodigyLocalCousinServicePermissionValid(invalidPermission),
                "local_cousin_permission_rejects_prefix_application_mismatch");
  invalidPermission = permission;
  invalidPermission.generation = 2;
  suite.require(!prodigyLocalCousinServicePermissionValid(invalidPermission),
                "local_cousin_permission_rejects_active_generation_two");
  invalidPermission = permission;
  invalidPermission.acceptedAuthorityGeneration = 0;
  suite.require(!prodigyLocalCousinServicePermissionValid(invalidPermission) &&
                    prodigyLocalCousinServicePermissionValid(invalidPermission, false),
                "local_cousin_permission_distinguishes_ingress_from_owner_record");

  // UUID text uses the existing assignItoh whole-byte canonical encoding.
  const String validPermissionJSON = R"json({"permissionUUID":"0x0601","pairUUID":"0x0300","logicalWorkloadUUID":"0x0301","logicalServiceUUID":"0x0302","localClusterUUID":"0x0401","peerClusterUUID":"0x0402","localHalf":"source","localApplicationID":7,"peerApplicationID":19,"localCousinServicePrefix":1973623371858943,"peerCousinServicePrefix":5351323092386815,"slots":[3,1001],"localDeploymentID":1970324836974593,"canonicalPlanSHA256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifactSHA256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","artifactBytes":8192})json";
  ProdigyLocalCousinServicePermission parsedPermission = {};
  String parseFailure = {};
  suite.require(parseLocalCousinPermissionJSON(validPermissionJSON, parsedPermission, parseFailure) &&
                    prodigyLocalCousinServicePermissionValid(parsedPermission, false) &&
                    parsedPermission.localApplicationID != parsedPermission.peerApplicationID &&
                    parsedPermission.slots.contains(3) && parsedPermission.slots.contains(1001),
                "mothership_local_cousin_permission_parser_accepts_asymmetric_policy");
  auto parserRejects = [&](const std::string& malformed, const char *name) {
    suite.require(!parseLocalCousinPermissionJSON(String(malformed.c_str()), parsedPermission, parseFailure), name);
  };
  const std::string validPermissionText(reinterpret_cast<const char *>(validPermissionJSON.data()), validPermissionJSON.size());
  std::string malformed = validPermissionText;
  malformed.replace(malformed.size() - 1, 1, ",\"unexpected\":1}");
  parserRejects(std::move(malformed), "mothership_local_cousin_permission_parser_rejects_unknown_field");
  malformed = validPermissionText;
  malformed.replace(malformed.size() - 1, 1, ",\"permissionUUID\":\"0x0601\"}");
  parserRejects(std::move(malformed), "mothership_local_cousin_permission_parser_rejects_duplicate_field");
  malformed = validPermissionText;
  malformed.replace(malformed.size() - 1, 1, ",\"acceptedAuthorityGeneration\":1}");
  parserRejects(std::move(malformed), "mothership_local_cousin_permission_parser_rejects_owner_field_injection");
  malformed = validPermissionText;
  malformed.replace(malformed.find("[3,1001]"), 8, "[3,3]");
  parserRejects(std::move(malformed), "mothership_local_cousin_permission_parser_rejects_duplicate_slot");
  malformed = validPermissionText;
  malformed.replace(malformed.find("\"localApplicationID\":7"), 22, "\"localApplicationID\":-7");
  parserRejects(std::move(malformed), "mothership_local_cousin_permission_parser_rejects_negative_numeric");
  malformed = validPermissionText;
  malformed.replace(malformed.find("0x0601"), 6, "0x601");
  parserRejects(std::move(malformed), "mothership_local_cousin_permission_parser_rejects_noncanonical_uuid");

  const String validRouteJSON = R"json({"routeUUID":"0x0101","operationUUID":"0x0201","logicalWorkloadUUID":"0x0301","logicalServiceUUID":"0x0302","sourcePermissionUUID":"0x0601","destinationPermissionUUID":"0x0602","slots":[3,1001],"destinationRoutablePrefixUUID":"0x0501","destinationPublicAddress":"2001:db8::1","transportProtocol":"TCP","destinationCIDR":32,"destinationTCPPort":443,"pathMTU":1500,"generation":1,"issuedAtMs":100,"expiresAtMs":200,"state":"active"})json";
  MothershipCousinRouteIntent parsedRouteIntent = {};
  suite.require(parseCousinRouteIntentJSON(validRouteJSON, parsedRouteIntent, parseFailure) &&
                parsedRouteIntent.transportProtocol == IPPROTO_TCP && parsedRouteIntent.destinationCIDR == 32 &&
                parsedRouteIntent.pathMTU == 1500,
                "mothership_cousin_route_parser_accepts_exact_tcp_cidr_mtu_profile");
  auto routeParserRejects = [&](const std::string& malformedRoute, const char *name) {
    suite.require(!parseCousinRouteIntentJSON(String(malformedRoute.c_str()), parsedRouteIntent, parseFailure), name);
  };
  const std::string validRouteText(reinterpret_cast<const char *>(validRouteJSON.data()), validRouteJSON.size());
  std::string malformedRoute = validRouteText;
  malformedRoute.replace(malformedRoute.find("\"TCP\""), 5, "\"UDP\"");
  routeParserRejects(malformedRoute, "mothership_cousin_route_parser_rejects_non_tcp_transport");
  malformedRoute = validRouteText;
  malformedRoute.replace(malformedRoute.find("\"destinationCIDR\":32"), 20, "\"destinationCIDR\":129");
  routeParserRejects(malformedRoute, "mothership_cousin_route_parser_rejects_invalid_cidr");
  malformedRoute = validRouteText;
  malformedRoute.replace(malformedRoute.find("\"pathMTU\":1500"), 14, "\"pathMTU\":1279");
  routeParserRejects(malformedRoute, "mothership_cousin_route_parser_rejects_small_mtu");
  malformedRoute = validRouteText;
  malformedRoute.replace(malformedRoute.size() - 1, 1, ",\"pathMTU\":1500}");
  routeParserRejects(malformedRoute, "mothership_cousin_route_parser_rejects_duplicate_mtu");

  String encodedPermission = {};
  ProdigyLocalCousinServicePermission permissionToEncode = permission;
  BitseryEngine::serialize(encodedPermission, permissionToEncode);
  ProdigyLocalCousinServicePermission decodedPermission = {};
  suite.require(BitseryEngine::deserializeSafe(encodedPermission, decodedPermission) &&
                    prodigyLocalCousinServicePermissionEqual(permission, decodedPermission),
                "local_cousin_permission_binary_round_trip_preserves_owner_record");
  ProdigyMasterAuthorityRuntimeState permissionRuntime = {};
  permissionRuntime.generation = 7;
  permissionRuntime.localCousinServicePermissions.push_back(permission);
  String encodedRuntime = {};
  BitseryEngine::serialize(encodedRuntime, permissionRuntime);
  ProdigyMasterAuthorityRuntimeState decodedRuntime = {};
  suite.require(BitseryEngine::deserializeSafe(encodedRuntime, decodedRuntime) &&
                    prodigyLocalCousinServicePermissionsEqual(permissionRuntime.localCousinServicePermissions,
                                                              decodedRuntime.localCousinServicePermissions),
                "local_cousin_permission_runtime_v15_round_trip");
  suite.require(prodigyLocalCousinServicePermissionsValid({}, 0, 0),
                "local_cousin_permission_empty_legacy_vector_remains_valid");

  CousinRouteRecord route = validRoute();
  suite.require(cousinRouteStructurallyValid(route), "route_structural_validation_accepts_unequal_application_mapping");

  CrossClusterMasqueGatewayAuthority gateway = {};
  gateway.pairUUID = route.pairUUID;
  gateway.pairOperationUUID = 0x2201;
  gateway.localClusterUUID = route.sourceClusterUUID;
  gateway.peerClusterUUID = route.destinationClusterUUID;
  gateway.localMachineUUID = 0x2202;
  gateway.peerMachineUUID = 0x2203;
  gateway.localDatacenterFragment = 1;
  gateway.peerDatacenterFragment = 2;
  gateway.localSitePrefix = prodigyContainerDatacenterSitePrefix(1);
  gateway.peerSitePrefix = prodigyContainerDatacenterSitePrefix(2);
  gateway.artifactSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv;
  gateway.localIdentitySHA256 = gateway.artifactSHA256;
  gateway.peerIdentitySHA256 = gateway.artifactSHA256;
  gateway.peerTrustSHA256 = gateway.artifactSHA256;
  gateway.artifactBytes = 1;
  gateway.listenerPublicUDPEndpoint = IPAddress("2001:db8::1", true);
  gateway.listenerPublicUDPPort = 443;
  gateway.tunnelSlot = 0;
  gateway.privateTunnelInterface = "mtbgp0"_ctv;
  gateway.privateTunnelLocalIPv6 = IPAddress("fd5a:4d53::1", true);
  gateway.privateTunnelPeerIPv6 = IPAddress("fd5a:4d53::2", true);
  gateway.privateLocalASN = 64512; gateway.privatePeerASN = 64513;
  gateway.privateLocalBGPID = 1; gateway.privatePeerBGPID = 2;
  String privateSessionKey = {};
  privateSessionKey.assign("0123456789abcdef0123456789abcdef"_ctv);
  suite.require(prodigyComputeSHA256Hex(privateSessionKey, gateway.privateSessionCredentialSHA256),
                "private_tunnel_bgp_fixture_hashes_delivered_vault_secret");
  gateway.localRole = CrossClusterMasqueGatewayRole::listener;
  gateway.generation = 13;
  gateway.pairAuthorityGeneration = 7;
  gateway.keyGeneration = route.keyEpoch;
  Vector<Wormhole> gatewayWormholes = {};
  suite.require(prodigyCrossClusterMasqueGatewayWormholes(gateway, gatewayWormholes) &&
                    gatewayWormholes.size() == 1 &&
                    gatewayWormholes[0].externalAddress.is6 &&
                    std::memcmp(gatewayWormholes[0].externalAddress.v6, gateway.listenerPublicUDPEndpoint.v6, 16) == 0 &&
                    gatewayWormholes[0].externalPort == 443 && gatewayWormholes[0].containerPort == 443 &&
                    gatewayWormholes[0].layer4 == IPPROTO_UDP && !gatewayWormholes[0].isQuic &&
                    prodigyCrossClusterMasqueGatewayWormholesMatch(gateway, gatewayWormholes),
                "masque_listener_publishes_exact_single_tuple_routed_udp_endpoint");
  auto alteredGatewayWormholes = gatewayWormholes;
  alteredGatewayWormholes[0].containerPort++;
  suite.require(!prodigyCrossClusterMasqueGatewayWormholesMatch(gateway, alteredGatewayWormholes),
                "masque_listener_rejects_wrong_target_port");
  alteredGatewayWormholes = gatewayWormholes;
  alteredGatewayWormholes[0].externalAddress = IPAddress("2001:db8::2", true);
  suite.require(!prodigyCrossClusterMasqueGatewayWormholesMatch(gateway, alteredGatewayWormholes),
                "masque_listener_rejects_wrong_public_authority");
  alteredGatewayWormholes = gatewayWormholes;
  alteredGatewayWormholes[0].externalPort++;
  suite.require(!prodigyCrossClusterMasqueGatewayWormholesMatch(gateway, alteredGatewayWormholes),
                "masque_listener_rejects_wrong_public_port");
  alteredGatewayWormholes = gatewayWormholes;
  alteredGatewayWormholes[0].isQuic = true;
  suite.require(!prodigyCrossClusterMasqueGatewayWormholesMatch(gateway, alteredGatewayWormholes),
                "masque_listener_rejects_cid_routing");
  alteredGatewayWormholes = gatewayWormholes;
  alteredGatewayWormholes.push_back(gatewayWormholes[0]);
  suite.require(!prodigyCrossClusterMasqueGatewayWormholesMatch(gateway, alteredGatewayWormholes),
                "masque_listener_rejects_multiple_targets");
  auto connectorGateway = gateway;
  connectorGateway.localRole = CrossClusterMasqueGatewayRole::connector;
  suite.require(prodigyCrossClusterMasqueGatewayWormholes(connectorGateway, gatewayWormholes) &&
                    gatewayWormholes.empty() && prodigyCrossClusterMasqueGatewayWormholesMatch(connectorGateway, gatewayWormholes),
                "masque_connector_does_not_publish_listener");
  auto ipv4Gateway = gateway;
  ipv4Gateway.listenerPublicUDPEndpoint = IPAddress("198.51.100.20", false);
  suite.require(prodigyCrossClusterMasqueGatewayWormholes(ipv4Gateway, gatewayWormholes) &&
                    gatewayWormholes.size() == 1 && !gatewayWormholes[0].externalAddress.is6 &&
                    gatewayWormholes[0].externalAddress.v4 == ipv4Gateway.listenerPublicUDPEndpoint.v4 &&
                    prodigyCrossClusterMasqueGatewayWormholesMatch(ipv4Gateway, gatewayWormholes),
                "masque_listener_publishes_ipv4_authority");
  Vector<Whitehole> gatewaySources = {};
  suite.require(prodigyCrossClusterMasqueGatewayWhiteholesValid(gateway, gatewaySources) &&
                    !prodigyCrossClusterMasqueGatewayWhiteholesValid(connectorGateway, gatewaySources),
                "masque_listener_needs_no_source_and_connector_requires_one");
  Whitehole source = {};
  source.transport = ExternalAddressTransport::quic;
  source.family = ExternalAddressFamily::ipv6;
  source.source = ExternalAddressSource::hostPublicAddress;
  source.hasAddress = true;
  source.address = IPAddress("2001:db8::99", true);
  source.sourcePort = 49152;
  source.bindingNonce = 1;
  gatewaySources.push_back(source);
  suite.require(prodigyCrossClusterMasqueGatewayWhiteholesValid(connectorGateway, gatewaySources) &&
                    !prodigyCrossClusterMasqueGatewayWhiteholesValid(gateway, gatewaySources),
                "masque_connector_accepts_resolved_host_source_and_listener_rejects_it");
  gatewaySources[0].family = ExternalAddressFamily::ipv4;
  gatewaySources[0].address = IPAddress("198.51.100.99", false);
  suite.require(!prodigyCrossClusterMasqueGatewayWhiteholesValid(connectorGateway, gatewaySources),
                "masque_connector_rejects_source_family_mismatch");
  auto ipv4Connector = ipv4Gateway;
  ipv4Connector.localRole = CrossClusterMasqueGatewayRole::connector;
  suite.require(prodigyCrossClusterMasqueGatewayWhiteholesValid(ipv4Connector, gatewaySources),
                "masque_connector_accepts_resolved_ipv4_source");
  gatewaySources[0].hasAddress = false;
  suite.require(!prodigyCrossClusterMasqueGatewayWhiteholesValid(ipv4Connector, gatewaySources),
                "masque_connector_rejects_unresolved_source");
  gatewaySources[0].hasAddress = true;
  gatewaySources[0].source = ExternalAddressSource::registeredRoutablePrefix;
  suite.require(!prodigyCrossClusterMasqueGatewayWhiteholesValid(ipv4Connector, gatewaySources),
                "masque_connector_rejects_non_host_source");
  gatewaySources[0].source = ExternalAddressSource::hostPublicAddress;
  gatewaySources[0].transport = ExternalAddressTransport::tcp;
  suite.require(!prodigyCrossClusterMasqueGatewayWhiteholesValid(ipv4Connector, gatewaySources),
                "masque_connector_rejects_non_quic_source");
  auto invalidGateway = gateway;
  invalidGateway.listenerPublicUDPPort = 0;
  suite.require(!prodigyCrossClusterMasqueGatewayWormholes(invalidGateway, gatewayWormholes) && gatewayWormholes.empty(),
                "masque_listener_rejects_invalid_authority");
  invalidGateway = gateway;
  invalidGateway.state = CrossClusterMasqueGatewayState::withdrawn;
  suite.require(!prodigyCrossClusterMasqueGatewayWormholes(invalidGateway, gatewayWormholes) && gatewayWormholes.empty(),
                "masque_listener_withdrawal_has_no_publication");

  ProdigyCrossClusterMeshRoute mesh = {};
  suite.require(prodigyBuildCrossClusterMeshRoute(gateway, mesh) &&
                    prodigyCrossClusterMeshRouteValid(mesh),
                "cross_cluster_mesh_projection_accepts_current_gateway_authority");

  ProdigyCrossClusterMasqueGatewayReadiness gatewayReadiness = {};
  gatewayReadiness.pairUUID = gateway.pairUUID;
  gatewayReadiness.localClusterUUID = gateway.localClusterUUID;
  gatewayReadiness.localMachineUUID = gateway.localMachineUUID;
  gatewayReadiness.keyEpoch = gateway.keyGeneration;
  gatewayReadiness.authorityGeneration = gateway.pairAuthorityGeneration;
  gatewayReadiness.gatewayGeneration = gateway.generation;
  gatewayReadiness.authenticatedMasqueQUICReady = true;
  ProdigyCrossClusterSiteBGPRoutePlan bgpPlan = {};
  suite.require(prodigyBuildCrossClusterSiteBGPRoutePlan(gateway, &gatewayReadiness, false, bgpPlan) &&
                    bgpPlan.localSitePrefix.equals(gateway.localSitePrefix) &&
                    bgpPlan.localSitePrefix.cidr == 96 &&
                    bgpPlan.action == BGPIPv6UnicastAdvertisementAction::announce,
                "cross_cluster_bgp_announces_only_ready_local_site_96");
  suite.require(prodigyBuildCrossClusterSiteBGPRoutePlan(gateway, &gatewayReadiness, true, bgpPlan) &&
                    bgpPlan.action == BGPIPv6UnicastAdvertisementAction::none,
                "cross_cluster_bgp_ready_site_reconciliation_is_idempotent");
  gatewayReadiness.authenticatedMasqueQUICReady = false;
  suite.require(prodigyBuildCrossClusterSiteBGPRoutePlan(gateway, &gatewayReadiness, true, bgpPlan) &&
                    bgpPlan.action == BGPIPv6UnicastAdvertisementAction::withdraw,
                "cross_cluster_bgp_withdraws_site_96_on_gateway_readiness_loss");
  gatewayReadiness.authenticatedMasqueQUICReady = true;
  ++gatewayReadiness.gatewayGeneration;
  suite.require(prodigyBuildCrossClusterSiteBGPRoutePlan(gateway, &gatewayReadiness, true, bgpPlan) &&
                    bgpPlan.action == BGPIPv6UnicastAdvertisementAction::withdraw,
                "cross_cluster_bgp_rejects_stale_gateway_readiness");
  gatewayReadiness.gatewayGeneration = gateway.generation;
  auto withdrawnForBGP = gateway;
  withdrawnForBGP.state = CrossClusterMasqueGatewayState::withdrawn;
  suite.require(prodigyBuildCrossClusterSiteBGPRoutePlan(withdrawnForBGP, &gatewayReadiness, true, bgpPlan) &&
                    bgpPlan.action == BGPIPv6UnicastAdvertisementAction::withdraw,
                "cross_cluster_bgp_withdraws_site_96_on_authority_withdrawal");

  ProdigyCrossClusterPrivateTunnelBGPDesiredState privateBGP = {};
  privateBGP.pairUUID = gateway.pairUUID;
  privateBGP.pairOperationUUID = gateway.pairOperationUUID;
  privateBGP.localMachineUUID = gateway.localMachineUUID;
  privateBGP.peerMachineUUID = gateway.peerMachineUUID;
  privateBGP.keyEpoch = gateway.keyGeneration;
  privateBGP.authorityGeneration = gateway.pairAuthorityGeneration;
  privateBGP.gatewayGeneration = gateway.generation;
  privateBGP.gatewaySlot = gateway.gatewaySlot;
  privateBGP.localSitePrefix = gateway.localSitePrefix;
  privateBGP.peerSitePrefix = gateway.peerSitePrefix;
  privateBGP.tunnelInterface = gateway.privateTunnelInterface;
  privateBGP.localGatewayInjectionIPv6 = IPAddress("fd00:1:2:3::fc", true);
  privateBGP.localGatewaySourceIPv6 = IPAddress("fd00:1:2:3::", true);
  privateBGP.localGatewayInjectionFragment = prodigyCrossClusterMasqueGatewayRuntimeFragmentFirst;
  privateBGP.localInsideIPv6 = gateway.privateTunnelLocalIPv6;
  privateBGP.peerInsideIPv6 = gateway.privateTunnelPeerIPv6;
  privateBGP.localASN = gateway.privateLocalASN;
  privateBGP.peerASN = gateway.privatePeerASN;
  privateBGP.localBGPID = gateway.privateLocalBGPID;
  privateBGP.sessionKey = privateSessionKey;
  privateBGP.masqueReady = true;
  BGPPeer openBuilder;
  Buffer localOpen, peerOpen, providerOpen;
  localOpen.need(128); peerOpen.need(128); providerOpen.need(128);
  openBuilder.fillOpenMesage(localOpen, gateway.privateLocalBGPID, true, gateway.privateLocalASN);
  openBuilder.fillOpenMesage(peerOpen, gateway.privatePeerBGPID, true, gateway.privatePeerASN);
  openBuilder.fillOpenMesage(providerOpen, gateway.privateLocalBGPID, true, openBuilder.localASN);
  suite.require(BGPPeer::openASNMatches(localOpen.data(), localOpen.size(), gateway.privateLocalASN) &&
                    BGPPeer::openASNMatches(peerOpen.data(), peerOpen.size(), gateway.privatePeerASN) &&
                    !BGPPeer::openASNMatches(localOpen.data(), localOpen.size(), gateway.privatePeerASN) &&
                    !BGPPeer::openASNMatches(peerOpen.data(), peerOpen.size(), gateway.privateLocalASN) &&
                    BGPPeer::openASNMatches(providerOpen.data(), providerOpen.size(), 35'870),
                "private_bgp_reciprocal_open_uses_local_asn_and_provider_default");
  String localUpdate = {}, peerUpdate = {}, providerUpdate = {};
  openBuilder.localASN = gateway.privateLocalASN;
  openBuilder.fillAnnouncePrefixMessage(localUpdate, gateway.localSitePrefix, gateway.privateTunnelLocalIPv6, false);
  openBuilder.localASN = gateway.privatePeerASN;
  openBuilder.fillAnnouncePrefixMessage(peerUpdate, gateway.peerSitePrefix, gateway.privateTunnelPeerIPv6, false);
  openBuilder.localASN = 35'870;
  openBuilder.fillAnnouncePrefixMessage(providerUpdate, gateway.localSitePrefix, gateway.privateTunnelLocalIPv6, false);
  auto emittedPathASN = [](const String& update, uint16_t expected) {
    return update.size() >= 34 && update.data()[27] == 0x40 && update.data()[28] == 0x02 &&
        update.data()[29] == 0x04 && update.data()[30] == 0x02 && update.data()[31] == 0x01 &&
        (uint16_t(update.data()[32]) << 8 | uint16_t(update.data()[33])) == expected;
  };
  suite.require(emittedPathASN(localUpdate, gateway.privateLocalASN) &&
                    emittedPathASN(peerUpdate, gateway.privatePeerASN) &&
                    emittedPathASN(providerUpdate, 35'870),
                "private_bgp_updates_advertise_exact_local_asn_and_provider_default");
  auto wrongLocalASN = privateBGP;
  wrongLocalASN.localASN = gateway.privatePeerASN;
  suite.require(!prodigyCrossClusterPrivateTunnelBGPMatchesAuthority(gateway, &gatewayReadiness, wrongLocalASN),
                "private_bgp_rejects_wrong_local_asn");
  suite.require(prodigyCrossClusterPrivateTunnelBGPMatchesAuthority(gateway, &gatewayReadiness, privateBGP),
                "private_tunnel_bgp_binds_exact_authority_and_masque_readiness");
  suite.require(prodigyCrossClusterPrivateTunnelBGPImportAllowed(privateBGP, privateBGP.peerInsideIPv6,
                                                                  gateway.peerSitePrefix, false),
                "private_tunnel_bgp_imports_only_enrolled_peer_96");
  auto wrongPrivatePrefix = privateBGP;
  wrongPrivatePrefix.peerSitePrefix = gateway.localSitePrefix;
  suite.require(!prodigyCrossClusterPrivateTunnelBGPDesiredStateValid(wrongPrivatePrefix) &&
                    !prodigyCrossClusterPrivateTunnelBGPImportAllowed(privateBGP, privateBGP.peerInsideIPv6,
                                                                       gateway.localSitePrefix, false),
                "private_tunnel_bgp_rejects_wrong_prefix_tag");
  auto wrongPrivatePeer = privateBGP;
  wrongPrivatePeer.peerInsideIPv6 = IPAddress("fd5a:4d53::3", true);
  suite.require(!prodigyCrossClusterPrivateTunnelBGPImportAllowed(privateBGP, wrongPrivatePeer.peerInsideIPv6,
                                                                   gateway.peerSitePrefix, false),
                "private_tunnel_bgp_rejects_wrong_peer");
  auto stalePrivateGeneration = privateBGP;
  ++stalePrivateGeneration.gatewayGeneration;
  suite.require(!prodigyCrossClusterPrivateTunnelBGPMatchesAuthority(gateway, &gatewayReadiness,
                                                                      stalePrivateGeneration),
                "private_tunnel_bgp_rejects_stale_gateway_generation");
  auto wrongPrivateOperation = privateBGP;
  ++wrongPrivateOperation.pairOperationUUID;
  suite.require(!prodigyCrossClusterPrivateTunnelBGPMatchesAuthority(gateway, &gatewayReadiness,
                                                                      wrongPrivateOperation),
                "private_tunnel_bgp_rejects_wrong_pair_operation");
  ProdigyCrossClusterPrivateTunnelBGPPath privatePath = {};
  privatePath.state = privateBGP;
  privatePath.localPrefixAnnounced = true;
  privatePath.sessionEstablished = true;
  privatePath.peerPrefixImported = true;
  SwitchboardOverlayMachineRoute privateFallback = {};
  suite.require(prodigyBuildCrossClusterPrivateTunnelSwitchboardFallback(gateway, privatePath, privateFallback) &&
                    privateFallback.machineFragment == switchboardMakeOverlayDatacenterRouteKey(gateway.peerDatacenterFragment) &&
                    privateFallback.nextHop.equals(privateBGP.localGatewayInjectionIPv6) &&
                    privateFallback.sourceAddress.equals(privateBGP.localGatewaySourceIPv6) &&
                    privateFallback.localContainerRedirectFragment == prodigyCrossClusterMasqueGatewayRuntimeFragmentFirst &&
                    !privateFallback.nextHop.equals(privateBGP.peerInsideIPv6) &&
                    !privateFallback.sourceAddress.equals(privateBGP.localInsideIPv6),
                "private_tunnel_bgp_programs_peer_96_fallback_to_local_gateway_veth_not_private_bgp_tuple");
  Vector<ProdigyCrossClusterPrivateTunnelBGPPath> privatePaths = {};
  privatePaths.push_back(privatePath);
  auto secondPrivatePath = privatePath; secondPrivatePath.state.pairUUID += 1; secondPrivatePath.state.gatewaySlot = 1;
  auto thirdPrivatePath = privatePath; thirdPrivatePath.state.pairUUID += 2; thirdPrivatePath.state.gatewaySlot = 2;
  privatePaths.push_back(secondPrivatePath); privatePaths.push_back(thirdPrivatePath);
  ProdigyCrossClusterPrivateTunnelBGPPath selectedPrivatePath = {};
  suite.require(prodigySelectCrossClusterPrivateTunnelBGPPath(privatePaths, 2, selectedPrivatePath) &&
                    selectedPrivatePath.state.peerSitePrefix.equals(gateway.peerSitePrefix),
                "private_tunnel_bgp_supports_three_authorized_ecmp_paths");
  auto duplicatePairPaths = privatePaths;
  duplicatePairPaths[1].state.pairUUID = duplicatePairPaths[0].state.pairUUID;
  suite.require(!prodigySelectCrossClusterPrivateTunnelBGPPath(duplicatePairPaths, 2, selectedPrivatePath),
                "private_tunnel_bgp_rejects_duplicate_pair_candidate");
  privatePaths[1].sessionEstablished = false;
  privatePaths[2].peerPrefixImported = false;
  suite.require(prodigySelectCrossClusterPrivateTunnelBGPPath(privatePaths, 2, selectedPrivatePath) &&
                    selectedPrivatePath.state.localInsideIPv6.equals(privateBGP.localInsideIPv6),
                "private_tunnel_bgp_fails_over_when_two_paths_withdraw");
  privatePath.peerPrefixImported = false;
  suite.require(!prodigyBuildCrossClusterPrivateTunnelSwitchboardFallback(gateway, privatePath, privateFallback),
                "private_tunnel_bgp_withdraws_switchboard_fallback_on_nlri_loss");
  privatePath.peerPrefixImported = true;
  ProdigyCrossClusterPrivateBGPReadiness privateReadiness = {};
  suite.require(prodigyObserveCrossClusterPrivateBGPReadiness(
                    gateway, &privatePath, true, privateReadiness) &&
                    prodigyCrossClusterPrivateBGPReady(privateReadiness) &&
                    prodigyCrossClusterPrivateBGPReadinessMatchesAuthority(privateReadiness, gateway),
                "private_tunnel_bgp_observation_binds_announcement_import_and_installed_peer_96");
  suite.require(prodigyObserveCrossClusterPrivateBGPReadiness(
                    gateway, &privatePath, false, privateReadiness) &&
                    !prodigyCrossClusterPrivateBGPReady(privateReadiness),
                "private_tunnel_bgp_observation_rejects_unprogrammed_switchboard_fallback");
  suite.require(prodigyObserveCrossClusterPrivateBGPReadiness(
                    gateway, &privatePath, true, privateReadiness),
                "private_tunnel_bgp_restores_fixture_readiness_for_path_fault_contract");
  ProdigyCrossClusterPathFaultRequest pathFault = {};
  pathFault.operationUUID = 0x2401; pathFault.authority = gateway;
  pathFault.scope = prodigyCrossClusterPathFaultScope(gateway);
  prodigyCrossClusterPathFaultFlowIdentity(pathFault.scope, pathFault.flowIdentity);
  suite.require(prodigyCrossClusterPathFaultRequestValid(pathFault),
                "cross_cluster_path_fault_derives_canonical_scope_flow_identity");
  auto leasedPathFault = pathFault;
  leasedPathFault.protocolVersion = ProdigyCrossClusterPathFaultRequest::leaseVersion;
  leasedPathFault.expiresAtMilliseconds = 123456;
  ProdigyCrossClusterPathFaultControl faultControl = {}, decodedFaultControl = {};
  faultControl.action = ProdigyCrossClusterPathFaultGatewayAction::pause;
  faultControl.request = leasedPathFault;
  String faultControlWire = {};
  suite.require(prodigyCrossClusterPathFaultControlValid(faultControl) &&
                BitseryEngine::serialize(faultControlWire, faultControl) &&
                BitseryEngine::deserializeSafe(faultControlWire, decodedFaultControl) &&
                prodigyCrossClusterPathFaultControlValid(decodedFaultControl) &&
                prodigyCrossClusterPathFaultRequestEqual(decodedFaultControl.request, leasedPathFault),
                "cross_cluster_path_fault_control_roundtrip_preserves_exact_lease");
  decodedFaultControl.accepted = true;
  suite.require(!prodigyCrossClusterPathFaultControlValid(decodedFaultControl),
                "cross_cluster_path_fault_request_cannot_claim_acknowledgement");
  decodedFaultControl.response = true;
  suite.require(prodigyCrossClusterPathFaultControlValid(decodedFaultControl),
                "cross_cluster_path_fault_acknowledgement_requires_response_direction");
  auto resumeRequest = faultControl;
  resumeRequest.action = ProdigyCrossClusterPathFaultGatewayAction::resume;
  auto resumeResponse = resumeRequest; resumeResponse.response = true;
  suite.require(!prodigyCrossClusterPathFaultRetryRejectedObservation(resumeRequest, false, resumeResponse) &&
                prodigyCrossClusterPathFaultRetryRejectedObservation(resumeRequest, true, resumeResponse),
                "cross_cluster_path_fault_retries_completed_negative_but_preserves_pending");
  auto mismatchedResume = resumeResponse; ++mismatchedResume.request.operationUUID;
  suite.require(!prodigyCrossClusterPathFaultRetryRejectedObservation(resumeRequest, true, mismatchedResume),
                "cross_cluster_path_fault_retry_rejects_different_lease");
  resumeResponse.accepted = resumeResponse.sessionReady = resumeResponse.bgpReady = true;
  suite.require(!prodigyCrossClusterPathFaultRetryRejectedObservation(resumeRequest, true, resumeResponse),
                "cross_cluster_path_fault_retains_positive_autorestoration_observation");
  auto pauseRequest = faultControl, pauseResponse = faultControl; pauseResponse.response = true;
  suite.require(!prodigyCrossClusterPathFaultRetryRejectedObservation(pauseRequest, true, pauseResponse),
                "cross_cluster_path_fault_retry_never_replays_pause");
  ProdigyCrossClusterPathFaultGatewayControlPayload leaseCommand = {}, leaseResponse = {};
  String leaseFrame = {};
  suite.require(prodigyCrossClusterPathFaultGatewayLeasePayload(leasedPathFault,
                    ProdigyCrossClusterPathFaultGatewayAction::pause, leaseCommand) &&
                prodigyEncodeCrossClusterPathFaultGatewayControlFrame(leaseCommand, leaseFrame) &&
                leaseFrame.size() == 108 &&
                prodigyDecodeCrossClusterPathFaultGatewayControlFrame(
                    reinterpret_cast<const uint8_t *>(leaseFrame.data()), uint32_t(leaseFrame.size()), leaseResponse),
                "cross_cluster_path_fault_fixed_lease_roundtrip");
  leaseResponse.fromGateway = true; leaseResponse.accepted = true;
  suite.require(prodigyCrossClusterPathFaultGatewayLeaseResponseMatches(leaseCommand, leaseResponse),
                "cross_cluster_path_fault_fixed_lease_response_matches");
  ++leaseResponse.gatewayGeneration;
  suite.require(!prodigyCrossClusterPathFaultGatewayLeaseResponseMatches(leaseCommand, leaseResponse),
                "cross_cluster_path_fault_fixed_lease_rejects_replaced_gateway");
  ProdigyCrossClusterPathFaultGatewayLifecycleRecord lifecycle = {};
  lifecycle.request = pathFault;
  lifecycle.admittedPlan.kind = SystemContainerKind::crossClusterMasqueGateway;
  lifecycle.admittedPlan.artifact.sha256 = gateway.artifactSHA256;
  lifecycle.admittedPlan.artifact.bytes = gateway.artifactBytes;
  lifecycle.admittedPlan.gatewayPairUUID = gateway.pairUUID;
  lifecycle.admittedPlan.gatewayLocalClusterUUID = gateway.localClusterUUID;
  lifecycle.admittedPlan.gatewayLocalMachineUUID = gateway.localMachineUUID;
  lifecycle.admittedPlan.gatewayKeyEpoch = gateway.keyGeneration;
  lifecycle.admittedPlan.gatewayAuthorityGeneration = gateway.pairAuthorityGeneration;
  lifecycle.admittedPlan.gatewayGeneration = gateway.generation;
  lifecycle.admittedPlan.gatewayTunnelInterface = gateway.privateTunnelInterface;
  lifecycle.admittedPlan.egress.peerIsIPv6 = true; lifecycle.admittedPlan.egress.protocol = IPPROTO_UDP;
  lifecycle.admittedPlan.egress.port = gateway.listenerPublicUDPPort;
  std::memcpy(lifecycle.admittedPlan.egress.address6, gateway.listenerPublicUDPEndpoint.v6, sizeof(lifecycle.admittedPlan.egress.address6));
  lifecycle.admittedPlan.egress.allowIngressFromPeer = true;
  ClusterMachine::renderIPAddressLiteral(gateway.listenerPublicUDPEndpoint, lifecycle.admittedPlan.gatewayEndpoint);
  lifecycle.admittedPlan.gatewayLocalIdentity = gateway.localIdentitySHA256;
  lifecycle.admittedPlan.gatewayPeerIdentity = gateway.peerIdentitySHA256;
  lifecycle.admittedPlan.gatewayPeerTrust = gateway.peerTrustSHA256;
  lifecycle.retiringContainerUUID = 0x2410;
  lifecycle.admittedLaunchGeneration = 9;
  suite.require(prodigyCrossClusterPathFaultGatewayLifecycleRecordValid(lifecycle),
                "cross_cluster_path_fault_write_ahead_lifecycle_binds_exact_admitted_gateway_plan");
  auto driftedLifecycle = lifecycle;
  driftedLifecycle.admittedPlan.artifact.sha256 =
      "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"_ctv;
  suite.require(!prodigyCrossClusterPathFaultGatewayLifecycleRecordValid(driftedLifecycle),
                "cross_cluster_path_fault_write_ahead_lifecycle_rejects_artifact_drift");
  driftedLifecycle = lifecycle;
  ++driftedLifecycle.admittedPlan.gatewayGeneration;
  suite.require(!prodigyCrossClusterPathFaultGatewayLifecycleRecordValid(driftedLifecycle),
                "cross_cluster_path_fault_write_ahead_lifecycle_rejects_generation_drift");
  ProdigyCrossClusterPathFaultGatewayControlPayload gatewayControlPayload = {};
  gatewayControlPayload.action = ProdigyCrossClusterPathFaultGatewayAction::pause;
  gatewayControlPayload.request = pathFault;
  String gatewayControlFrame = {};
  ProdigyCrossClusterPathFaultGatewayControlPayload decodedGatewayControl = {};
  suite.require(prodigyEncodeCrossClusterPathFaultGatewayControlFrame(gatewayControlPayload, gatewayControlFrame) &&
                    prodigyDecodeCrossClusterPathFaultGatewayControlFrame(
                        reinterpret_cast<const uint8_t *>(gatewayControlFrame.data()), uint32_t(gatewayControlFrame.size()),
                        decodedGatewayControl) && !decodedGatewayControl.fromGateway &&
                    decodedGatewayControl.action == ProdigyCrossClusterPathFaultGatewayAction::pause,
                "cross_cluster_path_fault_gateway_control_uses_one_exact_bidirectional_payload");
  gatewayControlPayload.fromGateway = true; gatewayControlPayload.accepted = true;
  gatewayControlPayload.authenticatedReady = false;
  suite.require(prodigyEncodeCrossClusterPathFaultGatewayControlFrame(gatewayControlPayload, gatewayControlFrame) &&
                    prodigyDecodeCrossClusterPathFaultGatewayControlFrame(
                        reinterpret_cast<const uint8_t *>(gatewayControlFrame.data()), uint32_t(gatewayControlFrame.size()),
                        decodedGatewayControl),
                "cross_cluster_path_fault_gateway_control_accepts_authenticated_down_receipt");
  gatewayControlPayload.fromGateway = false; gatewayControlPayload.accepted = true;
  suite.require(!prodigyEncodeCrossClusterPathFaultGatewayControlFrame(gatewayControlPayload, gatewayControlFrame),
                "cross_cluster_path_fault_gateway_control_rejects_command_state_claim");
  suite.require(prodigyCrossClusterPathFaultControlAuthenticated(pathFault, gateway.localIdentitySHA256) &&
                    !prodigyCrossClusterPathFaultControlAuthenticated(pathFault,
                        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_ctv),
                "cross_cluster_path_fault_control_requires_pinned_authenticated_identity");
  ProdigyCrossClusterPathFaultInMemorySessionControl pathFaultControl = {};
  bool fakeMasqueReady = true;
  suite.require(pathFaultControl.pause(pathFault) && pathFaultControl.pause(pathFault) &&
                    pathFaultControl.query(pathFault, fakeMasqueReady) && !fakeMasqueReady &&
                    pathFaultControl.resume(pathFault) && pathFaultControl.resume(pathFault) &&
                    pathFaultControl.query(pathFault, fakeMasqueReady) &&
                    fakeMasqueReady,
                "cross_cluster_path_fault_in_memory_session_control_is_exact_and_idempotent");
  auto driftedPathFault = pathFault;
  ++driftedPathFault.scope.gatewayGeneration;
  suite.require(!pathFaultControl.pause(driftedPathFault),
                "cross_cluster_path_fault_in_memory_session_control_rejects_scope_generation_drift");
  driftedPathFault = pathFault;
  ++driftedPathFault.authority.peerMachineUUID;
  suite.require(!pathFaultControl.query(driftedPathFault, fakeMasqueReady),
                "cross_cluster_path_fault_in_memory_session_control_rejects_peer_drift");
  auto survivingGateway = gateway; ++survivingGateway.pairUUID;
  Vector<CrossClusterMasqueGatewayAuthority> admittedPathAuthorities = {};
  admittedPathAuthorities.push_back(gateway); admittedPathAuthorities.push_back(survivingGateway);
  ProdigyCrossClusterPathFaultSurvivorReceipt survivor = {};
  survivor.scope = prodigyCrossClusterPathFaultScope(survivingGateway);
  survivor.masque = gatewayReadiness; survivor.masque.pairUUID = survivingGateway.pairUUID;
  survivor.privateBGP = privateReadiness; survivor.privateBGP.scope.pairUUID = survivingGateway.pairUUID;
  ProdigyCrossClusterPathFaultReceipt pathFaultReceipt = {};
  pathFaultReceipt.request = pathFault;
  pathFaultReceipt.selectedMasqueSessionDown = true;
  pathFaultReceipt.selectedPrivateBGPDown = true;
  pathFaultReceipt.selectedRouteWithdrawn = true;
  pathFaultReceipt.selectedMasque = gatewayReadiness;
  pathFaultReceipt.selectedMasque.authenticatedMasqueQUICReady = false;
  pathFaultReceipt.selectedPrivateBGP = privateReadiness;
  pathFaultReceipt.selectedPrivateBGP.sessionEstablished = false;
  pathFaultReceipt.selectedPrivateBGP.peerSitePrefixImported = false;
  pathFaultReceipt.selectedPrivateBGP.switchboardFallbackInstalled = false;
  pathFaultReceipt.surviving.push_back(survivor);
  suite.require(prodigyCrossClusterPathFaultReceiptValid(pathFault, pathFaultReceipt,
                                                          admittedPathAuthorities),
                "cross_cluster_path_fault_active_receipt_proves_exact_down_path_and_ready_survivor");
  pathFaultReceipt.phase = ProdigyCrossClusterPathFaultPhase::restored;
  pathFaultReceipt.selectedMasqueSessionDown = false;
  pathFaultReceipt.selectedPrivateBGPDown = false;
  pathFaultReceipt.selectedRouteWithdrawn = false;
  pathFaultReceipt.selectedMasque = gatewayReadiness;
  pathFaultReceipt.selectedPrivateBGP = privateReadiness;
  suite.require(prodigyCrossClusterPathFaultReceiptValid(pathFault, pathFaultReceipt,
                                                          admittedPathAuthorities),
                "cross_cluster_path_fault_restored_receipt_requires_masque_and_exact_peer_96_bgp");
  auto retargetedPathFault = pathFault;
  ++retargetedPathFault.authority.peerMachineUUID;
  suite.require(!prodigyCrossClusterPathFaultReceiptValid(retargetedPathFault, pathFaultReceipt,
                                                           admittedPathAuthorities),
                "cross_cluster_path_fault_rejects_retargeted_authority_receipt");
  NeuronPrivateTunnelBGPRuntime privateRuntime = {};
  suite.require(!privateRuntime.reconcile(gateway, &gatewayReadiness, &privateBGP, -1) &&
                    privateRuntime.desiredPaths().empty(),
                "private_tunnel_bgp_requires_delivered_vault_secret_before_runtime_creation");
  ProdigyPairPrivateBGPSecretDeliveryResponse deliveredSecret = {};
  deliveredSecret.accepted = true; deliveredSecret.scope.pairUUID = gateway.pairUUID;
  deliveredSecret.scope.operationUUID = gateway.pairOperationUUID;
  deliveredSecret.scope.keyEpoch = gateway.keyGeneration; deliveredSecret.scope.tunnelSlot = gateway.tunnelSlot;
  deliveredSecret.scope.clusterUUID = gateway.localClusterUUID; deliveredSecret.scope.machineUUID = gateway.localMachineUUID;
  deliveredSecret.scope.authorityGeneration = gateway.pairAuthorityGeneration;
  deliveredSecret.scope.gatewayGeneration = gateway.generation; deliveredSecret.credential = privateSessionKey;
  suite.require(privateRuntime.installDeliveredSecret(deliveredSecret),
                "private_tunnel_bgp_admits_exact_delivered_vault_secret");
  gatewayReadiness.authenticatedMasqueQUICReady = false;
  suite.require(!privateRuntime.reconcile(gateway, &gatewayReadiness, &privateBGP, -1) &&
                    privateRuntime.desiredPaths().empty(),
                "private_tunnel_bgp_withdraws_on_readiness_loss");
  gatewayReadiness.authenticatedMasqueQUICReady = true;

  ProdigyCrossClusterAuthenticatedOverlayUnderlay underlay = {};
  underlay.pairUUID = mesh.pairUUID;
  underlay.localMachineUUID = mesh.localMachineUUID;
  underlay.peerMachineUUID = mesh.peerMachineUUID;
  underlay.keyEpoch = mesh.keyEpoch;
  underlay.authorityGeneration = mesh.authorityGeneration;
  underlay.gatewayGeneration = mesh.gatewayGeneration;
  underlay.nextHop = IPAddress("2001:db8:feed::2", true);
  underlay.sourceAddress = IPAddress("2001:db8:feed::1", true);
  SwitchboardOverlayMachineRoute remoteMachineRoute = {};
  suite.require(prodigyBuildCrossClusterOverlayMachineRoute(mesh, underlay, 0x112233u, remoteMachineRoute) &&
                    remoteMachineRoute.machineFragment == switchboardMakeOverlayMachineIdentity(2, 0x112233u),
                "cross_cluster_mesh_projection_builds_datacenter_fenced_remote_machine_route");
  const uint32_t remoteMachineIdentity = switchboardMakeOverlayMachineIdentity(2, 0x445566u);
  SwitchboardOverlayMachineRoute selectedRoute = {};
  suite.require(prodigySelectCrossClusterOverlayRoute(remoteMachineIdentity, nullptr, mesh, underlay, selectedRoute) &&
                    selectedRoute.machineFragment == switchboardMakeOverlayDatacenterRouteKey(2) &&
                    selectedRoute.nextHop.equals(underlay.nextHop),
                "cross_cluster_mesh_projection_uses_authenticated_peer_site_as_remote_96_fallback");
  SwitchboardOverlayMachineRoute exactRoute = remoteMachineRoute;
  exactRoute.machineFragment = remoteMachineIdentity;
  exactRoute.nextHop = IPAddress("2001:db8:face::2", true);
  suite.require(prodigySelectCrossClusterOverlayRoute(remoteMachineIdentity, &exactRoute, mesh, underlay, selectedRoute) &&
                    selectedRoute.nextHop.equals(exactRoute.nextHop),
                "cross_cluster_mesh_projection_prefers_exact_dc_machine_route_over_site_fallback");
  suite.require(!prodigySelectCrossClusterOverlayRoute(0, nullptr, mesh, underlay, selectedRoute) &&
                    !prodigySelectCrossClusterOverlayRoute(switchboardMakeOverlayMachineIdentity(3, 1), nullptr, mesh, underlay, selectedRoute),
                "cross_cluster_mesh_projection_rejects_default_88_and_unenrolled_datacenter");

  auto withdrawnGateway = gateway;
  withdrawnGateway.state = CrossClusterMasqueGatewayState::withdrawn;
  ProdigyCrossClusterMeshRoute staleMesh = {};
  suite.require(!prodigyBuildCrossClusterMeshRoute(withdrawnGateway, staleMesh),
                "cross_cluster_mesh_projection_rejects_withdrawn_gateway");
  underlay.nextHop = underlay.sourceAddress;
  suite.require(!prodigyBuildCrossClusterOverlayMachineRoute(mesh, underlay, 0x112233u, remoteMachineRoute),
                "cross_cluster_mesh_projection_refuses_underlay_loop");
  underlay.nextHop = IPAddress("2001:db8:feed::2", true);
  underlay.authorityGeneration++;
  suite.require(!prodigyBuildCrossClusterOverlayMachineRoute(mesh, underlay, 0x112233u, remoteMachineRoute),
                "cross_cluster_mesh_projection_rejects_stale_underlay_authority");
  underlay.authorityGeneration = mesh.authorityGeneration;
  underlay.gatewayGeneration++;
  suite.require(!prodigyBuildCrossClusterOverlayMachineRoute(mesh, underlay, 0x112233u, remoteMachineRoute),
                "cross_cluster_mesh_projection_rejects_stale_gateway_generation");
  underlay.gatewayGeneration = mesh.gatewayGeneration;
  mesh.peerDatacenterFragment = 1;
  suite.require(!prodigyBuildCrossClusterOverlayMachineRoute(mesh, underlay, 0x112233u, remoteMachineRoute),
                "cross_cluster_mesh_projection_rejects_datacenter_collision");
  String routeDigest = {};
  suite.require(cousinRouteAuthorizationDigest(route, routeDigest), "route_digest_constructs");
  suite.require(routeDigest.size() == 64, "route_digest_is_sha256");
  ProdigyCousinRouteRequest routeRequest = {};
  routeRequest.expectedAuthorityGeneration = 7;
  routeRequest.expectedMasterUUID = 0x701;
  routeRequest.expectedMasterBootNs = 100;
  routeRequest.localHalf = CousinRouteHalf::source;
  routeRequest.route = route;
  String routeRequestBytes = {};
  ProdigyCousinRouteRequest decodedRouteRequest = {};
  BitseryEngine::serialize(routeRequestBytes, routeRequest);
  suite.require(prodigyCousinRouteRequestValid(routeRequest) &&
                BitseryEngine::deserializeSafe(routeRequestBytes, decodedRouteRequest) &&
                prodigyCousinRouteRequestValid(decodedRouteRequest),
                "route_brain_request_round_trip_binds_current_half_and_authority");
  ProdigyCousinRouteQuery routeQuery = {};
  routeQuery.routeUUID = route.routeUUID;
  suite.require(prodigyCousinRouteQueryValid(routeQuery), "route_brain_query_requires_route_identity");
  CousinRouteRecord changedBinding = route;
  changedBinding.pairUUID++;
  String changedDigest = {};
  suite.require(cousinRouteAuthorizationDigest(changedBinding, changedDigest) && changedDigest != routeDigest &&
                !cousinRouteScopeMatches(route, changedBinding), "route_pair_identity_is_bound");
  changedBinding = route;
  changedBinding.logicalServiceUUID++;
  suite.require(cousinRouteAuthorizationDigest(changedBinding, changedDigest) && changedDigest != routeDigest &&
                !cousinRouteScopeMatches(route, changedBinding), "route_canonical_service_identity_is_bound");
  changedBinding = route;
  changedBinding.sourcePermissionUUID++;
  suite.require(cousinRouteAuthorizationDigest(changedBinding, changedDigest) && changedDigest != routeDigest &&
                !cousinRouteScopeMatches(route, changedBinding), "route_source_permission_is_bound");
  changedBinding = route;
  changedBinding.destinationPermissionUUID++;
  suite.require(cousinRouteAuthorizationDigest(changedBinding, changedDigest) && changedDigest != routeDigest &&
                !cousinRouteScopeMatches(route, changedBinding), "route_destination_permission_is_bound");
  changedBinding = route;
  changedBinding.pathMTU++;
  suite.require(cousinRouteAuthorizationDigest(changedBinding, changedDigest) && changedDigest != routeDigest &&
                !cousinRouteScopeMatches(route, changedBinding), "route_path_mtu_is_bound");
  changedBinding = route;
  changedBinding.destinationCIDR = 48;
  suite.require(cousinRouteAuthorizationDigest(changedBinding, changedDigest) && changedDigest != routeDigest &&
                !cousinRouteScopeMatches(route, changedBinding), "route_destination_cidr_is_bound");
  changedBinding = route;
  changedBinding.rootGeneration++;
  suite.require(cousinRouteAuthorizationDigest(changedBinding, changedDigest) && changedDigest != routeDigest &&
                !cousinRouteKeyEpochTransitionValid(route, changedBinding), "route_root_rotation_requires_new_key_epoch");
  changedBinding.keyEpoch++;
  suite.require(cousinRouteKeyEpochTransitionValid(route, changedBinding), "route_root_rotation_accepts_new_key_epoch");
  CousinRouteRecord transition = route;
  transition.operationUUID = 0x220;
  transition.generation = 2;
  transition.issuedAtMs = 120;
  transition.expiresAtMs = 300;
  transition.keyEpoch = 2;
  transition.rootGeneration = 2;
  suite.require(cousinRouteTransitionAllowed(route, transition), "route_transition_helper_accepts_ordered_exact_scope_update");
  transition.state = CousinRouteState::draining;
  suite.require(cousinRouteTransitionAllowed(route, transition), "route_transition_helper_accepts_ordered_drain");
  CousinRouteRecord reviveTransition = transition;
  reviveTransition.operationUUID = 0x221;
  reviveTransition.generation = 3;
  reviveTransition.issuedAtMs = 140;
  reviveTransition.expiresAtMs = 320;
  reviveTransition.state = CousinRouteState::active;
  suite.require(!cousinRouteTransitionAllowed(transition, reviveTransition), "route_transition_helper_rejects_drain_revival");

  // The route carries logical slots. Each cluster independently maps them to
  // its own physical group count, so unequal application/group mappings remain
  // valid and no group number is persisted in the route.
  uint16_t sourceOwner = statefulServiceGroupOwnerForSlot(3, 2);
  uint16_t destinationOwner = statefulServiceGroupOwnerForSlot(3, 3);
  CousinRouteSlotBitmap sourceGroupSlots = slotsOwnedBy(sourceOwner, 2, route.slots);
  CousinRouteSlotBitmap destinationGroupSlots = slotsOwnedBy(destinationOwner, 3, route.slots);
  suite.require(sourceGroupSlots.contains(3), "source_slot_maps_to_current_local_group");
  suite.require(destinationGroupSlots.contains(3), "destination_slot_maps_to_independent_local_group");
  suite.require(route.slots.contains(3) && route.slots.contains(1001), "route_retains_logical_slots");
  CousinRouteSlotBitmap allSlots = {};
  for (uint16_t slot = 0; slot < nStatefulServiceGroupSlots; ++slot) allSlots.insert(slot);
  suite.require(slotCoverageIsExact(allSlots, 1), "all_slots_assign_once_with_one_group");
  suite.require(slotCoverageIsExact(allSlots, 2), "all_slots_assign_once_with_two_groups");
  suite.require(slotCoverageIsExact(allSlots, 3), "all_slots_assign_once_with_three_groups");
  suite.require(slotCoverageIsExact(allSlots, 7), "all_slots_assign_once_with_seven_groups");

  CousinRouteRecord prefixMismatch = route;
  CousinRouteRecord privateRoute = route;
  privateRoute.version = 3;
  privateRoute.endpointKind = CousinRouteEndpointKind::privateContainer;
  privateRoute.destinationRoutablePrefixUUID = 0;
  privateRoute.destinationCIDR = 128;
  String privateBytes = {};
  CousinRouteRecord decodedPrivate = {};
  suite.require(cousinRouteStructurallyValid(privateRoute) &&
                BitseryEngine::serialize(privateBytes, privateRoute) &&
                BitseryEngine::deserializeSafe(privateBytes, decodedPrivate) &&
                cousinRouteExactMatches(privateRoute, decodedPrivate), "private_route_v3_roundtrip");
  decodedPrivate.destinationRoutablePrefixUUID = 1;
  suite.require(!cousinRouteStructurallyValid(decodedPrivate), "private_route_rejects_external_prefix");
  decodedPrivate = privateRoute;
  decodedPrivate.endpointKind = CousinRouteEndpointKind::externalWormhole;
  suite.require(!cousinRouteStructurallyValid(decodedPrivate), "private_route_requires_explicit_endpoint_kind");
  prefixMismatch.sourceApplicationID = 8;
  suite.require(!cousinRouteStructurallyValid(prefixMismatch), "source_prefix_must_encode_source_application");
  CousinRouteRecord missingPermission = route;
  missingPermission.sourcePermissionUUID = 0;
  suite.require(!cousinRouteStructurallyValid(missingPermission), "route_current_contract_requires_source_permission");
  CousinRouteRecord wrongTransport = route;
  wrongTransport.transportProtocol = IPPROTO_UDP;
  suite.require(!cousinRouteStructurallyValid(wrongTransport), "route_current_contract_accepts_tcp_only");
  IPPrefix matchingDestinationRange("2001:db8::", true, 32);
  IPPrefix foreignDestinationRange("2001:db9::", true, 32);
  suite.require(cousinRouteDestinationRangeContainsAddress(route, matchingDestinationRange) &&
                !cousinRouteDestinationRangeContainsAddress(route, foreignDestinationRange),
                "route_current_contract_binds_destination_address_to_registered_cidr");
  CousinRouteRecord invalidCIDR = route;
  invalidCIDR.destinationCIDR = 129;
  suite.require(!cousinRouteStructurallyValid(invalidCIDR), "route_current_contract_rejects_invalid_destination_cidr");
  CousinRouteRecord tooSmallMTU = route;
  tooSmallMTU.pathMTU = cousinRouteMinimumPathMTU - 1;
  suite.require(!cousinRouteStructurallyValid(tooSmallMTU), "route_current_contract_rejects_small_path_mtu");
  CousinRouteRecord legacyRoute = route;
  legacyRoute.version = 1;
  legacyRoute.sourcePermissionUUID = 0;
  legacyRoute.destinationPermissionUUID = 0;
  legacyRoute.transportProtocol = 0;
  legacyRoute.destinationCIDR = 0;
  legacyRoute.pathMTU = 0;
  String legacyBytes = {};
  BitseryEngine::serialize(legacyBytes, legacyRoute);
  CousinRouteRecord decodedLegacyRoute = {};
  suite.require(BitseryEngine::deserializeSafe(legacyBytes, decodedLegacyRoute) &&
                decodedLegacyRoute.version == 1 && cousinRouteStructurallyValid(decodedLegacyRoute) &&
                !cousinRouteCurrentContract(decodedLegacyRoute), "route_v1_wire_remains_decodable_but_not_current");
  CousinRouteRecord operationHistory = route;
  operationHistory.priorOperationUUIDs.push_back(0x202);
  suite.require(cousinRouteStructurallyValid(operationHistory), "route_accepts_distinct_prior_operation_identity");
  suite.require(cousinRouteOperationUUIDWasUsed(operationHistory, 0x202), "route_remembers_prior_operation_identity");
  operationHistory.priorOperationUUIDs.push_back(0x202);
  suite.require(!cousinRouteStructurallyValid(operationHistory), "route_rejects_duplicate_prior_operation_identity");
  CousinRouteRecord operationHistoryCap = route;
  for (uint32_t index = 0; index < cousinRouteMaximumPriorOperationUUIDs; ++index)
    operationHistoryCap.priorOperationUUIDs.push_back(0x1000 + index);
  suite.require(cousinRouteStructurallyValid(operationHistoryCap), "route_accepts_bounded_operation_history");
  operationHistoryCap.priorOperationUUIDs.push_back(0x2000);
  suite.require(!cousinRouteStructurallyValid(operationHistoryCap), "route_rejects_operation_history_over_cap");
  CousinRouteRecord overlong = route;
  overlong.expiresAtMs = overlong.issuedAtMs + cousinRouteMaximumLifetimeMs + 1;
  suite.require(!cousinRouteStructurallyValid(overlong), "route_lifetime_has_finite_maximum");
  CousinRouteRecord draining = route;
  draining.state = CousinRouteState::draining;
  suite.require(!cousinRouteAllowsNewAdmissionAt(draining, 150), "draining_route_rejects_new_admission");
  suite.require(cousinRouteAllowsExistingFlowAt(draining, 150), "draining_route_allows_existing_flow");

  char directoryTemplate[] = "/tmp/prodigy-cousin-route-unit-XXXXXX";
  char *directory = ::mkdtemp(directoryTemplate);
  if (!suite.require(directory != nullptr, "registry_test_directory_created")) return 1;
  struct ScopedDirectory {
    std::filesystem::path path;
    ~ScopedDirectory() { std::filesystem::remove_all(path); }
  } ownedDirectory {directory};

  CousinRouteRecord recorded = {}, loaded = {};
  String failure = {};
  bool resumed = false;
  CousinRouteApplyReceipt sourceReceipt = validReceipt(route, CousinRouteHalf::source, 1);
  CousinRouteApplyReceipt destinationReceipt = validReceipt(route, CousinRouteHalf::destination, 1);
  CousinRouteApplyReceipt recordedReceipt = {}, loadedReceipt = {};
  ProdigyCousinRouteResponse routeResponse = {};
  routeResponse.success = true;
  routeResponse.found = true;
  routeResponse.qualified = true;
  routeResponse.localClusterUUID = route.sourceClusterUUID;
  routeResponse.currentAuthorityGeneration = 7;
  routeResponse.currentMasterUUID = 0x701;
  routeResponse.currentMasterBootNs = 100;
  routeResponse.route = route;
  routeResponse.applyReceipt = sourceReceipt;
  suite.require(prodigyCousinRouteResponseValid(routeResponse),
                "route_brain_response_binds_exact_current_half_receipt");
  routeResponse.localClusterUUID = route.destinationClusterUUID;
  suite.require(!prodigyCousinRouteResponseValid(routeResponse),
                "route_brain_response_rejects_wrong_half_cluster_binding");
  routeResponse.qualified = false;
  suite.require(!prodigyCousinRouteResponseValid(routeResponse),
                "route_brain_response_rejects_wrong_half_cluster_when_unqualified");
  {
    MothershipClusterRegistry registry {String(directory)};
    suite.require(!registry.recordCousinRoute(legacyRoute, recorded, resumed, &failure),
                  "registry_rejects_new_legacy_route_admission");
    suite.require(registry.recordCousinRoute(route, recorded, resumed, &failure), "registry_writes_initial_route");
    suite.require(!resumed && cousinRouteExactMatches(route, recorded), "registry_initial_write_is_not_resume");
    suite.require(registry.recordCousinRoute(route, recorded, resumed, &failure), "registry_retries_exact_operation");
    suite.require(resumed, "registry_marks_exact_retry_resumed");
    suite.require(registry.recordCousinRouteApplyReceipt(sourceReceipt, recordedReceipt, resumed, &failure),
                  "registry_writes_source_apply_receipt");
  }
  // A new registry instance must decode the persisted record rather than reuse
  // process memory from the writer instance.
  MothershipClusterRegistry registry {String(directory)};
  suite.require(registry.loadCousinRoute(route.routeUUID, loaded, &failure), "registry_cold_reopen_loads_route");
  suite.require(cousinRouteExactMatches(route, loaded), "registry_cold_reopen_preserves_exact_route");
  suite.require(registry.loadUsableCousinRoute(route.routeUUID, 150, loaded, &failure), "registry_loads_new_admission_route");
  suite.require(!registry.recordCousinRoute(operationHistory, recorded, resumed, &failure),
                "registry_rejects_caller_owned_operation_history");

  suite.require(registry.loadCousinRouteApplyReceipt(route.routeUUID, CousinRouteHalf::source, loadedReceipt, &failure) &&
                cousinRouteApplyReceiptExactMatches(sourceReceipt, loadedReceipt),
                "registry_cold_reopen_preserves_apply_receipt");
  bool acknowledged = true;
  suite.require(registry.cousinRouteAcknowledgedAt(route.routeUUID, 150, acknowledged, &failure) && !acknowledged,
                "registry_one_half_receipt_is_not_acknowledged");
  CousinRouteRecord prematureReplacement = route;
  prematureReplacement.operationUUID = 0x202;
  prematureReplacement.generation = 2;
  prematureReplacement.issuedAtMs = 120;
  prematureReplacement.expiresAtMs = 300;
  prematureReplacement.keyEpoch = 2;
  prematureReplacement.rootGeneration = 2;
  suite.require(!registry.recordCousinRoute(prematureReplacement, recorded, resumed, &failure),
                "registry_rejects_generation_advance_before_both_prior_receipts");
  suite.require(registry.recordCousinRouteApplyReceipt(destinationReceipt, recordedReceipt, resumed, &failure),
                "registry_records_destination_apply_receipt");
  suite.require(registry.cousinRouteAcknowledgedAt(route.routeUUID, 150, acknowledged, &failure) && acknowledged,
                "registry_both_current_receipts_are_acknowledged");
  suite.require(registry.recordCousinRouteApplyReceipt(destinationReceipt, recordedReceipt, resumed, &failure) && resumed,
                "registry_retries_exact_apply_receipt");
  CousinRouteApplyReceipt sourceReceiptRevision2 = sourceReceipt;
  sourceReceiptRevision2.localRuntimeRevision = 2;
  suite.require(registry.recordCousinRouteApplyReceipt(sourceReceiptRevision2, recordedReceipt, resumed, &failure) && !resumed,
                "registry_advances_per_half_local_revision");
  suite.require(!registry.recordCousinRouteApplyReceipt(sourceReceipt, recordedReceipt, resumed, &failure),
                "registry_rejects_stale_per_half_local_revision");
  suite.require(registry.loadCousinRouteApplyReceipt(route.routeUUID, CousinRouteHalf::source, loadedReceipt, &failure) &&
                cousinRouteApplyReceiptExactMatches(sourceReceiptRevision2, loadedReceipt),
                "registry_loads_apply_receipt");
  CousinRouteApplyReceipt wrongCluster = sourceReceipt;
  wrongCluster.localRuntimeRevision = 2;
  wrongCluster.localClusterUUID = route.destinationClusterUUID;
  suite.require(!registry.recordCousinRouteApplyReceipt(wrongCluster, recordedReceipt, resumed, &failure),
                "registry_rejects_receipt_wrong_cluster");
  CousinRouteApplyReceipt wrongRole = sourceReceiptRevision2;
  wrongRole.localRuntimeRevision = 3;
  wrongRole.localHalf = CousinRouteHalf::destination;
  suite.require(!registry.recordCousinRouteApplyReceipt(wrongRole, recordedReceipt, resumed, &failure),
                "registry_rejects_receipt_wrong_role_binding");
  CousinRouteApplyReceipt wrongDigest = sourceReceipt;
  wrongDigest.localRuntimeRevision = 2;
  wrongDigest.authorizationSHA256 = digest('f');
  suite.require(!registry.recordCousinRouteApplyReceipt(wrongDigest, recordedReceipt, resumed, &failure),
                "registry_rejects_receipt_wrong_digest");
  CousinRouteApplyReceipt wrongEpoch = sourceReceiptRevision2;
  wrongEpoch.localRuntimeRevision = 3;
  wrongEpoch.keyEpoch = 2;
  suite.require(!registry.recordCousinRouteApplyReceipt(wrongEpoch, recordedReceipt, resumed, &failure),
                "registry_rejects_receipt_wrong_credential_epoch");
  CousinRouteApplyReceipt staleRevision = sourceReceipt;
  staleRevision.localRuntimeRevision = 0;
  suite.require(!registry.recordCousinRouteApplyReceipt(staleRevision, recordedReceipt, resumed, &failure),
                "registry_rejects_receipt_nonpositive_local_revision");

  CousinRouteRecord sameOperationChanged = route;
  sameOperationChanged.expiresAtMs = 250;
  suite.require(!registry.recordCousinRoute(sameOperationChanged, recorded, resumed, &failure), "registry_rejects_changed_same_operation");

  CousinRouteRecord equalGenerationConflict = route;
  equalGenerationConflict.operationUUID = 0x202;
  equalGenerationConflict.destinationTCPPort = 8443;
  suite.require(!registry.recordCousinRoute(equalGenerationConflict, recorded, resumed, &failure), "registry_rejects_equal_generation_conflict");

  CousinRouteRecord duplicatePeerRange = validRoute(0x10f, 0x210);
  suite.require(!registry.recordCousinRoute(duplicatePeerRange, recorded, resumed, &failure),
                "registry_rejects_duplicate_permission_bound_peer_range_under_new_route_uuid");
  CousinRouteRecord distinctRange = validRoute(0x110, 0x211);
  distinctRange.destinationCIDR = 48;
  distinctRange.destinationPublicAddress = IPAddress("2001:db8:1::1", true);
  suite.require(cousinRoutePeerRangeScopeMatches(route, distinctRange) == false &&
                registry.recordCousinRoute(distinctRange, recorded, resumed, &failure),
                "registry_allows_distinct_destination_peer_range_records");

  CousinRouteRecord replacement = route;
  replacement.operationUUID = 0x203;
  replacement.generation = 2;
  replacement.issuedAtMs = 120;
  replacement.expiresAtMs = 300;
  replacement.destinationPublicAddress.v6[15] = 2;
  replacement.keyEpoch = 2;
  replacement.rootGeneration = 2;
  suite.require(registry.recordCousinRoute(replacement, recorded, resumed, &failure), "registry_allows_higher_generation_endpoint_credential_update");
  suite.require(!resumed && recorded.generation == 2, "registry_records_higher_generation");
  suite.require(recorded.priorOperationUUIDs.size() == 1 && recorded.priorOperationUUIDs[0] == route.operationUUID,
                "registry_persists_prior_operation_identity");
  suite.require(registry.cousinRouteAcknowledgedAt(route.routeUUID, 150, acknowledged, &failure) && !acknowledged,
                "registry_new_generation_invalidates_prior_apply_receipts");
  CousinRouteApplyReceipt staleRouteReceipt = sourceReceipt;
  staleRouteReceipt.localRuntimeRevision = 2;
  suite.require(!registry.recordCousinRouteApplyReceipt(staleRouteReceipt, recordedReceipt, resumed, &failure),
                "registry_rejects_stale_route_receipt");
  CousinRouteApplyReceipt replacementSourceReceipt = validReceipt(replacement, CousinRouteHalf::source, 3);
  CousinRouteApplyReceipt replacementDestinationReceipt = validReceipt(replacement, CousinRouteHalf::destination, 2);
  suite.require(registry.recordCousinRouteApplyReceipt(replacementSourceReceipt, recordedReceipt, resumed, &failure) &&
                registry.recordCousinRouteApplyReceipt(replacementDestinationReceipt, recordedReceipt, resumed, &failure),
                "registry_acknowledges_both_replacement_halves_before_terminal_transition");

  CousinRouteRecord credentialRegression = replacement;
  credentialRegression.operationUUID = 0x204;
  credentialRegression.generation = 3;
  credentialRegression.issuedAtMs = 130;
  credentialRegression.expiresAtMs = 310;
  credentialRegression.keyEpoch = 1;

  suite.require(!cousinRouteKeyEpochTransitionValid(replacement, credentialRegression),
                "route_rejects_credential_epoch_regression");
  suite.require(!registry.recordCousinRoute(credentialRegression, recorded, resumed, &failure),
                "registry_rejects_credential_epoch_regression");

  CousinRouteRecord rootRegression = replacement;
  rootRegression.operationUUID = 0x20d;
  rootRegression.generation = 3;
  rootRegression.rootGeneration = 1;
  rootRegression.keyEpoch = 3;
  suite.require(!registry.recordCousinRoute(rootRegression, recorded, resumed, &failure),
                "registry_rejects_root_generation_regression_even_with_new_key_epoch");

  CousinRouteRecord reusedOperation = replacement;
  reusedOperation.operationUUID = route.operationUUID;
  reusedOperation.generation = 3;
  reusedOperation.issuedAtMs = 130;
  reusedOperation.expiresAtMs = 310;
  reusedOperation.keyEpoch = 3;

  suite.require(!registry.recordCousinRoute(reusedOperation, recorded, resumed, &failure),
                "registry_rejects_operation_identity_reuse_after_supersession");

  CousinRouteRecord stale = route;
  stale.operationUUID = 0x205;
  suite.require(!registry.recordCousinRoute(stale, recorded, resumed, &failure), "registry_rejects_lower_generation");

  CousinRouteRecord changedMapping = replacement;
  changedMapping.operationUUID = 0x206;
  changedMapping.generation = 3;
  changedMapping.sourceApplicationID = 8;
  suite.require(!registry.recordCousinRoute(changedMapping, recorded, resumed, &failure), "registry_rejects_mapping_change_under_same_route_uuid");

  CousinRouteRecord revoked = replacement;
  revoked.operationUUID = 0x207;
  revoked.generation = 3;
  revoked.state = CousinRouteState::revoked;
  revoked.withdrawalGeneration = 3;
  revoked.withdrawnAtMs = 130;
  suite.require(registry.recordCousinRoute(revoked, recorded, resumed, &failure), "registry_persists_terminal_tombstone");
  suite.require(!registry.loadUsableCousinRoute(route.routeUUID, 140, loaded, &failure), "registry_terminal_route_is_not_new_admission_usable");
  CousinRouteApplyReceipt revokedSourceReceipt = validReceipt(revoked, CousinRouteHalf::source, 4);
  CousinRouteApplyReceipt revokedDestinationReceipt = validReceipt(revoked, CousinRouteHalf::destination, 3);
  suite.require(registry.recordCousinRouteApplyReceipt(revokedSourceReceipt, recordedReceipt, resumed, &failure) &&
                registry.recordCousinRouteApplyReceipt(revokedDestinationReceipt, recordedReceipt, resumed, &failure),
                "registry_accepts_terminal_desired_state_receipts");
  suite.require(registry.cousinRouteAcknowledgedAt(route.routeUUID, 140, acknowledged, &failure) && !acknowledged,
                "registry_terminal_receipts_are_not_current_admission_acknowledgement");
  CousinRouteRecord futureTerminalFloor = revoked;
  futureTerminalFloor.withdrawalGeneration = 4;
  suite.require(!cousinRouteStructurallyValid(futureTerminalFloor), "route_rejects_deferred_terminal_generation_floor");

  CousinRouteRecord staleRevive = replacement;
  staleRevive.operationUUID = 0x208;
  staleRevive.generation = 4;
  staleRevive.issuedAtMs = 140;
  staleRevive.expiresAtMs = 400;
  suite.require(!registry.recordCousinRoute(staleRevive, recorded, resumed, &failure), "registry_rejects_terminal_tombstone_revival");
  CousinRouteRecord terminalReplacement = validRoute(0x111, 0x212);
  suite.require(registry.recordCousinRoute(terminalReplacement, recorded, resumed, &failure) && !resumed,
                "registry_allows_fresh_route_uuid_for_peer_range_after_terminal_tombstone");

  CousinRouteRecord expired = validRoute(0x102, 0x209);
  expired.destinationRoutablePrefixUUID = 0x502;
  expired.destinationPublicAddress = IPAddress("2001:db8:2::1", true);
  expired.destinationCIDR = 48;
  expired.expiresAtMs = 150;
  suite.require(registry.recordCousinRoute(expired, recorded, resumed, &failure), "registry_persists_finite_expiry_route");
  suite.require(!registry.loadUsableCousinRoute(expired.routeUUID, 150, loaded, &failure), "registry_expiry_rejects_new_admission_after_cold_load");

  CousinRouteRecord invalid = validRoute(0x103, 0x20a);
  invalid.expiresAtMs = invalid.issuedAtMs;
  suite.require(!cousinRouteStructurallyValid(invalid), "route_rejects_non_finite_lifetime");
  suite.require(!registry.recordCousinRoute(invalid, recorded, resumed, &failure), "registry_rejects_invalid_route");

  CousinRouteRecord drainingRoute = validRoute(0x104, 0x20b);
  drainingRoute.destinationRoutablePrefixUUID = 0x503;
  drainingRoute.destinationPublicAddress = IPAddress("2001:db8:3::1", true);
  drainingRoute.destinationCIDR = 48;
  suite.require(registry.recordCousinRoute(drainingRoute, recorded, resumed, &failure), "registry_persists_draining_route_initial_generation");
  CousinRouteApplyReceipt drainingInitialSource = validReceipt(drainingRoute, CousinRouteHalf::source, 1);
  CousinRouteApplyReceipt drainingInitialDestination = validReceipt(drainingRoute, CousinRouteHalf::destination, 1);
  suite.require(registry.recordCousinRouteApplyReceipt(drainingInitialSource, recordedReceipt, resumed, &failure) &&
                registry.recordCousinRouteApplyReceipt(drainingInitialDestination, recordedReceipt, resumed, &failure),
                "registry_acknowledges_both_initial_halves_before_draining_transition");
  CousinRouteRecord drainingGeneration = drainingRoute;
  drainingGeneration.operationUUID = 0x20c;
  drainingGeneration.generation = 2;
  drainingGeneration.issuedAtMs = 120;
  drainingGeneration.expiresAtMs = 300;
  drainingGeneration.state = CousinRouteState::draining;
  suite.require(registry.recordCousinRoute(drainingGeneration, recorded, resumed, &failure), "registry_persists_draining_desired_state");
  CousinRouteApplyReceipt drainingSourceReceipt = validReceipt(drainingGeneration, CousinRouteHalf::source, 2);
  CousinRouteApplyReceipt drainingDestinationReceipt = validReceipt(drainingGeneration, CousinRouteHalf::destination, 2);
  suite.require(registry.recordCousinRouteApplyReceipt(drainingSourceReceipt, recordedReceipt, resumed, &failure) &&
                registry.recordCousinRouteApplyReceipt(drainingDestinationReceipt, recordedReceipt, resumed, &failure),
                "registry_accepts_draining_desired_state_receipts");
  suite.require(registry.cousinRouteAcknowledgedAt(drainingRoute.routeUUID, 150, acknowledged, &failure) && !acknowledged,
                "registry_draining_receipts_are_not_current_admission_acknowledgement");

  // Pair enrollment roots are Mothership-private retry material.  Reopening
  // the registry must preserve the original root even if a caller supplied a
  // fresh random candidate for the same immutable operation.
  // Keep this database separate from the still-live route registry above:
  // TidesDB takes an exclusive process-local open on a database path, and the
  // test below intentionally opens the pair registry twice to prove a cold
  // reopen.
  char pairDirectoryTemplate[] = "/tmp/prodigy-pair-enrollment-unit-XXXXXX";
  char *pairDirectory = ::mkdtemp(pairDirectoryTemplate);
  if (!suite.require(pairDirectory != nullptr, "pair_enrollment_registry_test_directory_created")) return 1;
  ScopedDirectory ownedPairDirectory {pairDirectory};
  MothershipClusterPairEnrollmentIntent pairIntent = validPairEnrollmentIntent();
  MothershipClusterPairEnrollmentIntent pairRecorded = {}, pairLoaded = {};
  bool pairResumed = false;
  {
    MothershipClusterRegistry pairRegistry {String(pairDirectory)};
    suite.require(pairRegistry.recordClusterPairEnrollmentIntent(pairIntent, pairIntent, pairResumed, &failure) && !pairResumed &&
                  pairIntent.pairUUID != 0 && mothershipClusterPairEnrollmentIntentRootValid(pairIntent),
                  "pair_enrollment_registry_alias_safe_initial_private_intent");
    pairRecorded = pairIntent;
    MothershipClusterPairEnrollmentIntent retry = pairIntent;
    retry.pairUUID = 0x9ff;
    for (uint32_t index = 0; index < sizeof(retry.root); ++index) retry.root[index] = uint8_t(0xa0 + index);
    suite.require(pairRegistry.recordClusterPairEnrollmentIntent(retry, pairRecorded, pairResumed, &failure) && pairResumed &&
                  pairRecorded.pairUUID == pairIntent.pairUUID && CRYPTO_memcmp(pairRecorded.root, pairIntent.root, sizeof(pairRecorded.root)) == 0,
                  "pair_enrollment_same_operation_reuses_original_private_root");
  }
  {
    MothershipClusterRegistry pairRegistry {String(pairDirectory)};
    suite.require(pairRegistry.loadClusterPairEnrollmentIntent(pairIntent.operationUUID, pairLoaded, &failure) &&
                  pairLoaded.pairUUID == pairIntent.pairUUID &&
                  CRYPTO_memcmp(pairLoaded.root, pairIntent.root, sizeof(pairLoaded.root)) == 0,
                  "pair_enrollment_cold_reopen_preserves_root_and_identity");
    MothershipClusterPairEnrollmentIntent conflictingScope = pairIntent;
    conflictingScope.secondEndpoints[0].port++;
    suite.require(!pairRegistry.recordClusterPairEnrollmentIntent(conflictingScope, pairRecorded, pairResumed, &failure),
                  "pair_enrollment_rejects_same_operation_changed_roster");
    MothershipClusterPairEnrollmentIntent conflictingClusters = validPairEnrollmentIntent(pairIntent.operationUUID + 1);
    suite.require(!pairRegistry.recordClusterPairEnrollmentIntent(conflictingClusters, pairRecorded, pairResumed, &failure),
                  "pair_enrollment_rejects_second_operation_for_same_cluster_pair");
    suite.require(pairRegistry.recordClusterPairEnrollmentCompletion(pairIntent.operationUUID, 8, 12, true, false, false, false,
                  pairRecorded, &failure) && pairRecorded.firstInitialProjectionDelivered &&
                  pairRecorded.firstEnrolledAuthorityGeneration == 8 && pairRecorded.secondEnrolledAuthorityGeneration == 12,
                  "pair_enrollment_records_monotonic_admission_receipt");
  }

  MothershipPairControlBoundaryDescriptor controlBoundary = validPairControlBoundary(pairIntent);
  MothershipPairControlServiceTransit serviceTransit = validPairControlServiceTransit(pairIntent);
  MothershipPairControlServiceTransit reverseTransit = serviceTransit;
  std::swap(reverseTransit.sourceClusterUUID, reverseTransit.destinationClusterUUID);
  std::swap(reverseTransit.sourceDeploymentID, reverseTransit.destinationDeploymentID);
  std::swap(reverseTransit.sourcePermissionUUID, reverseTransit.destinationPermissionUUID);
  std::swap(reverseTransit.sourceIngressPrivate6, reverseTransit.destinationIngressPrivate6);
  reverseTransit.sourceWhiteholeAddress = IPAddress("2001:db8:200:2::2", true);
  reverseTransit.destinationWormholeAddress = IPAddress("2001:db8:200:1::3", true);
  reverseTransit.sourceTCPPort = 42002;
  Vector<MothershipPairControlServiceTransit> transits = {serviceTransit, reverseTransit};
  suite.require(mothershipPairControlServiceTransitsValid(transits, pairIntent.firstClusterUUID, pairIntent.secondClusterUUID),
                "pair_control_transits_allow_both_exact_directions");
  Vector<MothershipPairControlServiceTransit> invalidTransits = {serviceTransit, serviceTransit};
  suite.require(!mothershipPairControlServiceTransitsValid(invalidTransits, pairIntent.firstClusterUUID, pairIntent.secondClusterUUID),
                "pair_control_transits_reject_duplicate_direction");
  invalidTransits = {reverseTransit, serviceTransit};
  suite.require(mothershipPairControlServiceTransitsValid(invalidTransits, pairIntent.firstClusterUUID, pairIntent.secondClusterUUID),
                "pair_control_transits_preserve_any_admission_order");
  invalidTransits = transits; invalidTransits.push_back(serviceTransit);
  suite.require(!mothershipPairControlServiceTransitsValid(invalidTransits, pairIntent.firstClusterUUID, pairIntent.secondClusterUUID),
                "pair_control_transits_reject_duplicate_flow");
  auto concurrentTransit = serviceTransit; ++concurrentTransit.sourceTCPPort;
  Vector<MothershipPairControlServiceTransit> concurrentTransits = {serviceTransit, reverseTransit, concurrentTransit};
  suite.require(mothershipPairControlServiceTransitsValid(concurrentTransits, pairIntent.firstClusterUUID, pairIntent.secondClusterUUID),
                "pair_control_transits_allow_distinct_concurrent_source_bindings");
  String concurrentReceipt;
  for (const auto& transit : concurrentTransits) {
    String line; mothershipPairControlBoundaryPreparedReceipt(controlBoundary, line, &transit); concurrentReceipt.append(line);
  }
  suite.require(mothershipPairControlBoundaryPreparedReceiptValid(controlBoundary, concurrentReceipt, concurrentTransits) &&
                !mothershipPairControlBoundaryPreparedReceiptValid(controlBoundary, concurrentReceipt, transits),
                "pair_control_receipt_requires_every_exact_admitted_flow");
  Vector<ClusterPairControlEndpoint> numericOrder = controlBoundary.firstEndpoints;
  numericOrder.push_back(validPairEndpoint(pairIntent.firstClusterUUID, 0x906, 16));
  String endpointCSV = {};
  suite.require(mothershipPairControlBoundaryEndpointCSV(numericOrder, endpointCSV) &&
                endpointCSV == "fd42:4242:4242:1::4,fd42:4242:4242:1::10"_ctv,
                "pair_control_boundary_endpoint_csv_uses_numeric_ipv6_order");
  Vector<ClusterPairControlEndpoint> duplicateAddress = numericOrder;
  ClusterPairControlEndpoint duplicate = numericOrder[0];
  duplicate.nodeUUID++;
  duplicateAddress.push_back(duplicate);
  suite.require(!mothershipPairControlBoundaryEndpointCSV(duplicateAddress, endpointCSV),
                "pair_control_boundary_endpoint_csv_rejects_duplicate_address");
  suite.require(!mothershipPairControlBoundaryPreparedReceiptValid(controlBoundary, "mismatched receipt"_ctv),
                "pair_control_boundary_rejects_mismatched_prepared_receipt");
  MothershipPairControlFault fault = {};
  fault.delayMilliseconds = 125;
  fault.durationMilliseconds = 1000;
  Vector<String> faultArguments = {};
  suite.require(mothershipPairControlFaultValid(fault) &&
                mothershipPairControlFaultArguments(controlBoundary, fault, faultArguments, &failure) &&
                faultArguments.size() == 16 && faultArguments[0] == "--pair-control-action"_ctv &&
                faultArguments[1] == "fault"_ctv && faultArguments[2] == "0x0900"_ctv &&
                faultArguments[11] == "fd42:4242:4242:1::4"_ctv &&
                faultArguments[12] == "fd42:4242:4242:2::5"_ctv && faultArguments[13] == "315"_ctv &&
                faultArguments[14] == "125"_ctv && faultArguments[15] == "1000"_ctv,
                "pair_control_fault_encodes_only_the_admitted_boundary_and_bounded_window");
  MothershipPairControlFault parsedFault = {};
  suite.require(mothershipPairControlFaultParse("0"_ctv, "1"_ctv, parsedFault, &failure) &&
                parsedFault.delayMilliseconds == 0 && parsedFault.durationMilliseconds == 1,
                "pair_control_fault_accepts_zero_delay_and_positive_duration");
  suite.require(!mothershipPairControlFaultParse("01"_ctv, "1"_ctv, parsedFault, &failure) &&
                !mothershipPairControlFaultParse("1"_ctv, "0"_ctv, parsedFault, &failure) &&
                !mothershipPairControlFaultParse("30001"_ctv, "1"_ctv, parsedFault, &failure) &&
                !mothershipPairControlFaultParse("1"_ctv, "60001"_ctv, parsedFault, &failure),
                "pair_control_fault_rejects_noncanonical_or_unbounded_windows");
  String firstDirection = "first-to-second"_ctv;
  suite.require(mothershipPairControlFaultParse("125"_ctv, "1000"_ctv, &firstDirection, parsedFault, &failure) &&
                parsedFault.direction == MothershipPairControlFaultDirection::firstToSecond &&
                mothershipPairControlFaultArguments(controlBoundary, parsedFault, faultArguments, &failure) &&
                faultArguments.size() == 17 && faultArguments[16] == "first-to-second"_ctv,
                "pair_control_fault_encodes_one_admitted_direction_only");
  String receipt = {};
  suite.require(mothershipPairControlFaultReceipt(controlBoundary, fault, 1'000'000ULL, 1'001'000'000ULL, receipt) &&
                mothershipPairControlFaultReceiptValid(controlBoundary, fault, receipt) &&
                receipt == "PAIR_CONTROL_FAULT operationID=0x0900 clock=CLOCK_BOOTTIME delayMs=125 durationMs=1000 beginNs=1000000 endNs=1001000000\n"_ctv,
                "pair_control_fault_preserves_exact_legacy_both_receipt");
  suite.require(!mothershipPairControlFaultReceiptValid(controlBoundary, fault,
                    "PAIR_CONTROL_FAULT operationID=0x0900 clock=CLOCK_BOOTTIME delayMs=125 durationMs=1000 direction=both beginNs=1000000 endNs=1001000000\n"_ctv),
                "pair_control_fault_rejects_extra_legacy_receipt_field");
  suite.require(mothershipPairControlFaultReceipt(controlBoundary, parsedFault, 1'000'000ULL, 1'001'000'000ULL, receipt) &&
                mothershipPairControlFaultReceiptValid(controlBoundary, parsedFault, receipt) &&
                receipt == "PAIR_CONTROL_FAULT operationID=0x0900 clock=CLOCK_BOOTTIME delayMs=125 durationMs=1000 direction=first-to-second installRule=first0-to-second0-DROP restoreRule=first0-to-second0-ABSENT beginNs=1000000 endNs=1001000000\n"_ctv &&
                !mothershipPairControlFaultReceiptValid(controlBoundary, parsedFault,
                    "PAIR_CONTROL_FAULT operationID=0x0900 clock=CLOCK_BOOTTIME delayMs=125 durationMs=1000 direction=first-to-second installRule=second0-to-first0-DROP restoreRule=second0-to-first0-ABSENT beginNs=1000000 endNs=1001000000\n"_ctv),
                "pair_control_fault_receipt_binds_selected_wire_install_and_restore");
  String invalidDirection = "second-to-firstx"_ctv;
  MothershipPairControlFault invalidFault = {};
  invalidFault.delayMilliseconds = 1; invalidFault.durationMilliseconds = 1;
  invalidFault.direction = static_cast<MothershipPairControlFaultDirection>(99);
  suite.require(!mothershipPairControlFaultParse("1"_ctv, "1"_ctv, &invalidDirection, parsedFault, &failure) &&
                !mothershipPairControlFaultValid(invalidFault),
                "pair_control_fault_rejects_unknown_direction");
  String secondDirection = "second-to-first"_ctv;
  suite.require(mothershipPairControlFaultParse("0"_ctv, "1000"_ctv, &secondDirection, parsedFault, &failure) &&
                mothershipPairControlFaultReceipt(controlBoundary, parsedFault, 1'000'000ULL, 1'001'000'000ULL, receipt) &&
                mothershipPairControlFaultReceiptValid(controlBoundary, parsedFault, receipt) &&
                receipt == "PAIR_CONTROL_FAULT operationID=0x0900 clock=CLOCK_BOOTTIME delayMs=0 durationMs=1000 direction=second-to-first installRule=second0-to-first0-DROP restoreRule=second0-to-first0-ABSENT beginNs=1000000 endNs=1001000000\n"_ctv,
                "pair_control_fault_accepts_exact_second_direction_witness");
  suite.require(!mothershipPairControlFaultReceiptValid(controlBoundary, invalidFault, receipt) &&
                !mothershipPairControlFaultReceipt(controlBoundary, parsedFault, 0, 1'001'000'000ULL, receipt) &&
                !mothershipPairControlFaultReceipt(controlBoundary, parsedFault, 1'000'000ULL, 1'000'999'999ULL, receipt) &&
                !mothershipPairControlFaultReceipt(controlBoundary, parsedFault, 1'000'000ULL, 6'001'000'001ULL, receipt),
                "pair_control_fault_rejects_missing_short_or_unbounded_intervals");
  MothershipPairControlBoundaryDescriptor faultChangedBoundary = controlBoundary;
  faultChangedBoundary.firstRuntimeIdentity = controlBoundary.secondRuntimeIdentity;
  suite.require(!mothershipPairControlFaultArguments(faultChangedBoundary, fault, faultArguments, &failure),
                "pair_control_fault_rejects_non_distinct_boundary_identity");
  suite.require(mothershipPairControlFaultParse("delay"_ctv, "0"_ctv, "1000"_ctv, "17"_ctv,
                    "0"_ctv, "12345"_ctv, "first-to-second"_ctv, parsedFault, &failure) &&
                parsedFault.kind == MothershipPairControlFaultKind::delay && parsedFault.latencyMilliseconds == 17 &&
                parsedFault.seed == 12345 &&
                mothershipPairControlFaultArguments(controlBoundary, parsedFault, faultArguments, &failure) &&
                faultArguments.size() == 21 && faultArguments[14] == "delay"_ctv && faultArguments[15] == "0"_ctv &&
                faultArguments[16] == "1000"_ctv && faultArguments[17] == "17"_ctv && faultArguments[18] == "0"_ctv &&
                faultArguments[19] == "12345"_ctv && faultArguments[20] == "first-to-second"_ctv &&
                mothershipPairControlFaultReceipt(controlBoundary, parsedFault, 1'000'000ULL, 1'001'000'000ULL, receipt) &&
                mothershipPairControlFaultReceiptValid(controlBoundary, parsedFault, receipt) &&
                receipt == "PAIR_CONTROL_FAULT operationID=0x0900 clock=CLOCK_BOOTTIME kind=delay onsetMs=0 durationMs=1000 latencyMs=17 percentageBps=0 seed=12345 direction=first-to-second installQdisc=second0:7d02:netem restoreQdisc=second0:7d02:ABSENT beginNs=1000000 endNs=1001000000\n"_ctv,
                "pair_control_netem_delay_binds_exact_tuple_egress_and_receipt");
  MothershipPairControlFault changedFault = parsedFault;
  changedFault.seed++;
  suite.require(!mothershipPairControlFaultReceiptValid(controlBoundary, changedFault, receipt),
                "pair_control_netem_receipt_rejects_changed_seed");
  changedFault = parsedFault; changedFault.direction = MothershipPairControlFaultDirection::secondToFirst;
  suite.require(!mothershipPairControlFaultReceiptValid(controlBoundary, changedFault, receipt),
                "pair_control_netem_receipt_rejects_wrong_egress");
  const char *receiptMutations[][2] = {
    {"operationID=0x0900", "operationID=0x0901"}, {"kind=delay", "kind=loss"},
    {"onsetMs=0", "onsetMs=1"}, {"durationMs=1000", "durationMs=999"},
    {"latencyMs=17", "latencyMs=18"}, {"percentageBps=0", "percentageBps=1"},
    {"seed=12345", "seed=12346"}, {"second0:7d02:netem", "first0:7d02:netem"},
    {"second0:7d02:ABSENT", "second0:7d02:netem"}, {"endNs=1001000000", "endNs=1000999999"},
  };
  bool rejectedReceipts = true;
  for (const auto& mutation : receiptMutations)
  {
    std::string text = receipt.c_str(); const size_t at = text.find(mutation[0]);
    if (at == std::string::npos) { rejectedReceipts = false; continue; }
    text.replace(at, std::strlen(mutation[0]), mutation[1]);
    rejectedReceipts = !mothershipPairControlFaultReceiptValid(controlBoundary, parsedFault, String(text.c_str())) && rejectedReceipts;
  }
  suite.require(rejectedReceipts, "pair_control_netem_receipt_binds_every_parameter_install_restore_and_interval");
  suite.require(mothershipPairControlFaultParse("loss"_ctv, "30000"_ctv, "60000"_ctv, "0"_ctv,
                    "10000"_ctv, "4294967295"_ctv, "both"_ctv, parsedFault, &failure) &&
                mothershipPairControlFaultReceipt(controlBoundary, parsedFault, 1'000'000ULL, 60'001'000'000ULL, receipt) &&
                mothershipPairControlFaultReceiptValid(controlBoundary, parsedFault, receipt) &&
                mothershipPairControlFaultParse("reorder"_ctv, "0"_ctv, "1"_ctv, "30000"_ctv,
                    "1"_ctv, "1"_ctv, "second-to-first"_ctv, parsedFault, &failure),
                "pair_control_netem_accepts_exact_inclusive_bounds");
  const char *badTuples[][7] = {
    {"drop","0","1","0","0","1","both"}, {"DELAY","0","1","1","0","1","both"},
    {"delay","01","1","1","0","1","both"}, {"delay","30001","1","1","0","1","both"},
    {"delay","0","0","1","0","1","both"}, {"delay","0","60001","1","0","1","both"},
    {"delay","0","1","0","0","1","both"}, {"delay","0","1","30001","0","1","both"},
    {"delay","0","1","1","1","1","both"}, {"delay","0","1","1","0","0","both"},
    {"delay","0","1","1","0","4294967296","both"}, {"delay","0","1","1","0","01","both"},
    {"loss","0","1","1","1","1","both"}, {"loss","0","1","0","0","1","both"},
    {"loss","0","1","0","10001","1","both"}, {"reorder","0","1","0","1","1","both"},
    {"reorder","0","1","1","0","1","both"}, {"reorder","0","1","1","1","1","forward"},
  };
  bool rejectedTuples = true;
  for (const auto& tuple : badTuples)
    rejectedTuples = !mothershipPairControlFaultParse(String(tuple[0]), String(tuple[1]), String(tuple[2]),
        String(tuple[3]), String(tuple[4]), String(tuple[5]), String(tuple[6]), parsedFault, &failure) && rejectedTuples;
  suite.require(rejectedTuples, "pair_control_netem_rejects_noncanonical_inapplicable_or_unbounded_parameters");
  suite.require(mothershipPairControlFaultParse("0"_ctv, "1"_ctv, parsedFault, &failure) &&
                parsedFault.kind == MothershipPairControlFaultKind::drop && parsedFault.seed == 0 &&
                parsedFault.latencyMilliseconds == 0 && parsedFault.percentageBasisPoints == 0 &&
                mothershipPairControlFaultArguments(controlBoundary, parsedFault, faultArguments, &failure) &&
                faultArguments.size() == 16,
                "pair_control_legacy_parse_resets_extended_parameters_and_keeps_old_argv");
  auto unresolvedTransit = serviceTransit; unresolvedTransit.sourceIngressPrivate6 = {};
  suite.require(!mothershipPairControlServiceTransitValid(unresolvedTransit, pairIntent.firstClusterUUID, pairIntent.secondClusterUUID),
                "pair_control_service_transit_rejects_unresolved_ingress_owner");
  Vector<String> serviceArguments = {};
  suite.require(mothershipPairControlServiceTransitValid(serviceTransit, pairIntent.firstClusterUUID,
                                                          pairIntent.secondClusterUUID) &&
                mothershipPairControlServiceTransitArguments(controlBoundary, serviceTransit, serviceArguments, &failure) &&
                serviceArguments.size() == 27 && serviceArguments[0] == "--pair-control-action"_ctv &&
                serviceArguments[1] == "service"_ctv && serviceArguments[14] == "0x0902"_ctv &&
                serviceArguments[24] == "9443"_ctv &&
                serviceArguments[25] == "fd42:4242:4242:1::4"_ctv &&
                serviceArguments[26] == "fd42:4242:4242:2::5"_ctv,
                "pair_control_service_transit_encodes_one_exact_provider_tuple");
  String serviceReceipt = {};
  String serviceReceiptUUID = {};
  serviceReceipt.append("PAIR_CONTROL operationID=");
  serviceReceiptUUID.assignItoh(controlBoundary.operationUUID);
  serviceReceipt.append(serviceReceiptUUID);
  serviceReceipt.append(" firstClusterUUID=");
  serviceReceiptUUID.assignItoh(controlBoundary.firstClusterUUID);
  serviceReceipt.append(serviceReceiptUUID);
  serviceReceipt.append(" secondClusterUUID=");
  serviceReceiptUUID.assignItoh(controlBoundary.secondClusterUUID);
  serviceReceipt.append(serviceReceiptUUID);
  serviceReceipt.append(" firstRuntimeIdentity=");
  serviceReceipt.append(controlBoundary.firstRuntimeIdentity);
  serviceReceipt.append(" secondRuntimeIdentity=");
  serviceReceipt.append(controlBoundary.secondRuntimeIdentity);
  serviceReceipt.append(" firstPrivate6Subnet=");
  serviceReceipt.append(controlBoundary.firstPrivateIPv6Subnet);
  serviceReceipt.append(" secondPrivate6Subnet=");
  serviceReceipt.append(controlBoundary.secondPrivateIPv6Subnet);
  String reverseReceipt = serviceReceipt;
  serviceReceipt.append(" port=315 phase=prepared service=1 source=2001:db8:100:1::2:42001 destination=2001:db8:100:2::3:9443 sourceIngress=fd42:4242:4242:1::4 destinationIngress=fd42:4242:4242:2::5\n"_ctv);
  suite.require(mothershipPairControlBoundaryPreparedReceiptValid(controlBoundary, serviceReceipt, &serviceTransit),
                "pair_control_service_transit_receipt_binds_exact_source_and_destination_tuples");
  reverseReceipt.append(" port=315 phase=prepared service=1 source=2001:db8:200:2::2:42002 destination=2001:db8:200:1::3:9443 sourceIngress=fd42:4242:4242:2::5 destinationIngress=fd42:4242:4242:1::4\n"_ctv);
  String bothReceipts = serviceReceipt; bothReceipts.append(reverseReceipt);
  suite.require(mothershipPairControlBoundaryPreparedReceiptValid(controlBoundary, bothReceipts, transits),
                "pair_control_receipt_requires_both_admitted_directions");
  suite.require(!mothershipPairControlBoundaryPreparedReceiptValid(controlBoundary, serviceReceipt, transits),
                "pair_control_receipt_rejects_missing_reverse_direction");
  String badReceipts = bothReceipts; badReceipts.append(reverseReceipt);
  suite.require(!mothershipPairControlBoundaryPreparedReceiptValid(controlBoundary, badReceipts, transits),
                "pair_control_receipt_rejects_extra_direction_receipt");
  badReceipts = reverseReceipt; badReceipts.append(serviceReceipt);
  suite.require(mothershipPairControlBoundaryPreparedReceiptValid(controlBoundary, badReceipts, transits),
                "pair_control_receipt_accepts_exact_flows_in_any_admission_order");
  MothershipPairControlServiceTransit receiptChangedTransit = serviceTransit;
  receiptChangedTransit.sourceTCPPort++;
  suite.require(!mothershipPairControlBoundaryPreparedReceiptValid(controlBoundary, serviceReceipt, &receiptChangedTransit),
                "pair_control_service_transit_receipt_rejects_changed_source_tuple");

  {
    MothershipClusterRegistry pairRegistry {String(pairDirectory)};
    suite.require(!pairRegistry.recordClusterPairTestControlBoundary(controlBoundary, false, pairRecorded, &failure),
                  "pair_control_boundary_rejects_admission_before_both_deliveries_and_qualification");
    suite.require(pairRegistry.recordClusterPairEnrollmentCompletion(pairIntent.operationUUID, 8, 12, true, true, true, true,
                  pairRecorded, &failure) && pairRecorded.firstQualified && pairRecorded.secondQualified &&
                  pairRecorded.firstInitialProjectionDelivered && pairRecorded.secondInitialProjectionDelivered,
                  "pair_control_boundary_completes_qualified_delivered_enrollment");
    suite.require(pairRegistry.recordClusterPairTestControlBoundary(controlBoundary, false, pairRecorded, &failure) &&
                  pairRecorded.testControlBoundaryAdmitted && !pairRecorded.testControlBoundaryClosed,
                  "pair_control_boundary_accepts_exact_qualified_delivered_rosters");
    MothershipPairControlBoundaryDescriptor changedRuntime = controlBoundary;
    changedRuntime.firstRuntimeIdentity = "4703"_ctv;
    suite.require(!pairRegistry.recordClusterPairTestControlBoundary(changedRuntime, false, pairRecorded, &failure),
                  "pair_control_boundary_rejects_changed_runtime_identity");
    MothershipPairControlBoundaryDescriptor changedRoster = controlBoundary;
    changedRoster.firstEndpoints[0].nodeUUID++;
    suite.require(!pairRegistry.recordClusterPairTestControlBoundary(changedRoster, false, pairRecorded, &failure),
                  "pair_control_boundary_rejects_changed_delivered_roster");
    suite.require(pairRegistry.recordClusterPairTestControlServiceTransit(pairIntent.operationUUID, serviceTransit,
                                                                            pairRecorded, &failure) &&
                  !pairRecorded.testControlServiceTransits.empty() &&
                  mothershipPairControlServiceTransitEqual(pairRecorded.testControlServiceTransits[0], serviceTransit),
                  "pair_control_service_transit_records_open_exact_qualified_boundary");
    suite.require(pairRegistry.recordClusterPairTestControlServiceTransit(pairIntent.operationUUID, serviceTransit,
                                                                            pairRecorded, &failure),
                  "pair_control_service_transit_exact_retry_is_idempotent");
    MothershipPairControlServiceTransit changedServiceTransit = serviceTransit;
    changedServiceTransit.sourcePermissionUUID++;
    suite.require(!pairRegistry.recordClusterPairTestControlServiceTransit(pairIntent.operationUUID, changedServiceTransit,
                                                                             pairRecorded, &failure),
                  "pair_control_service_transit_rejects_changed_immutable_tuple");
    suite.require(pairRegistry.recordClusterPairTestControlServiceTransit(pairIntent.operationUUID, reverseTransit, pairRecorded, &failure) &&
                  pairRecorded.testControlServiceTransits.size() == 2 &&
                  mothershipPairControlServiceTransitEqual(pairRecorded.testControlServiceTransits[1], reverseTransit),
                  "pair_control_service_transit_admits_reverse_without_replacing_original");
    suite.require(pairRegistry.recordClusterPairTestControlServiceTransit(pairIntent.operationUUID, reverseTransit, pairRecorded, &failure) &&
                  pairRecorded.testControlServiceTransits.size() == 2,
                  "pair_control_service_transit_reverse_retry_preserves_both_directions");
    changedServiceTransit = reverseTransit; changedServiceTransit.sourcePermissionUUID++;
    suite.require(!pairRegistry.recordClusterPairTestControlServiceTransit(pairIntent.operationUUID, changedServiceTransit, pairRecorded, &failure),
                  "pair_control_service_transit_rejects_reverse_permission_change");
    changedServiceTransit = reverseTransit; changedServiceTransit.sourceClusterUUID++;
    suite.require(!pairRegistry.recordClusterPairTestControlServiceTransit(pairIntent.operationUUID, changedServiceTransit, pairRecorded, &failure),
                  "pair_control_service_transit_rejects_foreign_source_cluster");

  }
  {
    MothershipClusterRegistry pairRegistry {String(pairDirectory)};
    suite.require(pairRegistry.recordClusterPairTestControlBoundary(controlBoundary, false, pairRecorded, &failure) &&
                  pairRecorded.testControlBoundaryAdmitted && !pairRecorded.testControlBoundaryClosed &&
                  !pairRecorded.testControlServiceTransits.empty() &&
                  pairRecorded.testControlServiceTransits.size() == 2 &&
                  mothershipPairControlServiceTransitEqual(pairRecorded.testControlServiceTransits[0], serviceTransit) &&
                  mothershipPairControlServiceTransitEqual(pairRecorded.testControlServiceTransits[1], reverseTransit),
                  "pair_control_boundary_cold_reopen_preserves_both_exact_directions");
    // Construct the historical V3 tail independently of the new vector codec.
    // The V2 prefix is unchanged, followed by its old admitted byte and one
    // standalone service-transit object.
    MothershipClusterPairEnrollmentIntent oldPrefix = pairRecorded;
    oldPrefix.protocolVersion = 2; oldPrefix.testControlServiceTransits.clear();
    String oldBytes, transitBytes;
    BitseryEngine::serialize(oldBytes, oldPrefix);
    oldBytes[0] = 3;
    oldBytes.append(uint8_t(1));
    BitseryEngine::serialize(transitBytes, serviceTransit);
    oldBytes.append(transitBytes);
    MothershipClusterPairEnrollmentIntent oldDecoded = {};
    suite.require(BitseryEngine::deserializeSafe(oldBytes, oldDecoded) && mothershipClusterPairEnrollmentIntentValid(oldDecoded) &&
                  oldDecoded.protocolVersion == 3 && oldDecoded.testControlServiceTransits.size() == 1 &&
                  mothershipPairControlServiceTransitEqual(oldDecoded.testControlServiceTransits[0], serviceTransit),
                  "pair_control_v3_wire_loads_only_original_direction");
    MothershipClusterPairEnrollmentIntent invalidIntent = pairRecorded;
    invalidIntent.protocolVersion = 3;
    suite.require(!mothershipClusterPairEnrollmentIntentValid(invalidIntent),
                  "pair_control_v3_cannot_encode_two_directions");
    invalidIntent = pairRecorded; invalidIntent.testControlBoundaryAdmitted = false;
    suite.require(!mothershipClusterPairEnrollmentIntentValid(invalidIntent),
                  "pair_control_service_set_requires_admitted_boundary");
    String currentBytes; BitseryEngine::serialize(currentBytes, pairRecorded);
    for (uint32_t cut : {uint32_t(currentBytes.size()-1), uint32_t(currentBytes.size()/2)})
    {
      MothershipClusterPairEnrollmentIntent truncated = {};
      String bytes = currentBytes.substr(0, cut, Copy::yes);
      suite.require(!BitseryEngine::deserializeSafe(bytes, truncated), "pair_control_service_set_rejects_truncated_wire");
    }
    suite.require(pairRegistry.recordClusterPairTestControlServiceTransit(pairIntent.operationUUID, concurrentTransit, pairRecorded, &failure) &&
                  pairRecorded.testControlServiceTransits.size() == 3 &&
                  mothershipPairControlServiceTransitEqual(pairRecorded.testControlServiceTransits[0], serviceTransit),
                  "pair_control_source_pool_admission_preserves_original_flow");
    suite.require(pairRegistry.recordClusterPairTestControlServiceTransit(pairIntent.operationUUID, concurrentTransit, pairRecorded, &failure) &&
                  pairRecorded.testControlServiceTransits.size() == 3,
                  "pair_control_source_pool_retry_is_idempotent");
    currentBytes[0] = 255;
    MothershipClusterPairEnrollmentIntent unsupported = {};
    suite.require(!BitseryEngine::deserializeSafe(currentBytes, unsupported) || !mothershipClusterPairEnrollmentIntentValid(unsupported),
                  "pair_control_service_set_rejects_unknown_wire_version");
    bool guardOpen = false;
    suite.require(pairRegistry.clusterHasOpenTestPairControlBoundary(pairIntent.firstClusterUUID, guardOpen, &failure) && guardOpen &&
                  pairRegistry.clusterHasOpenTestPairBoundary(pairIntent.secondClusterUUID, guardOpen, &failure) && guardOpen,
                  "pair_control_boundary_open_guard_blocks_cluster_removal");
    suite.require(pairRegistry.recordClusterPairTestControlBoundary(controlBoundary, true, pairRecorded, &failure) &&
                  pairRecorded.testControlBoundaryClosed && !pairRecorded.testControlServiceTransits.empty(),
                  "pair_control_boundary_closes_durable_guard");
    suite.require(pairRegistry.clusterHasOpenTestPairBoundary(pairIntent.firstClusterUUID, guardOpen, &failure) && !guardOpen,
                  "pair_control_boundary_closed_guard_no_longer_blocks_removal");
    suite.require(!pairRegistry.recordClusterPairTestControlBoundary(controlBoundary, false, pairRecorded, &failure),
                  "pair_control_boundary_closed_descriptor_cannot_reopen");
    suite.require(!pairRegistry.recordClusterPairTestControlServiceTransit(pairIntent.operationUUID, serviceTransit, pairRecorded, &failure) &&
                  !pairRegistry.recordClusterPairTestControlServiceTransit(pairIntent.operationUUID, reverseTransit, pairRecorded, &failure),
                  "pair_control_closed_boundary_rejects_both_service_retries");

  }

  char legacyPairDirectoryTemplate[] = "/tmp/prodigy-pair-enrollment-v1-unit-XXXXXX";
  char *legacyPairDirectory = ::mkdtemp(legacyPairDirectoryTemplate);
  if (!suite.require(legacyPairDirectory != nullptr, "pair_enrollment_v1_registry_test_directory_created")) return 1;
  ScopedDirectory ownedLegacyPairDirectory {legacyPairDirectory};
  MothershipClusterPairEnrollmentIntent legacyIntent = validPairEnrollmentIntent(0x910);
  legacyIntent.protocolVersion = 1;
  MothershipClusterPairEnrollmentIntent legacyRecorded = {}, legacyLoaded = {};
  bool legacyResumed = false;
  {
    MothershipClusterRegistry pairRegistry {String(legacyPairDirectory)};
    suite.require(pairRegistry.recordClusterPairEnrollmentIntent(legacyIntent, legacyRecorded, legacyResumed, &failure) && !legacyResumed &&
                  legacyRecorded.protocolVersion == 1,
                  "pair_control_boundary_persists_legacy_v1_enrollment_wire");
  }
  {
    MothershipClusterRegistry pairRegistry {String(legacyPairDirectory)};
    suite.require(pairRegistry.loadClusterPairEnrollmentIntent(legacyIntent.operationUUID, legacyLoaded, &failure) &&
                  legacyLoaded.protocolVersion == 1,
                  "pair_control_boundary_cold_loads_legacy_v1_enrollment_wire");
    suite.require(pairRegistry.recordClusterPairEnrollmentCompletion(legacyIntent.operationUUID, 8, 12, true, true, true, true,
                  legacyRecorded, &failure),
                  "pair_control_boundary_completes_legacy_enrollment_before_upgrade");
    const MothershipPairControlBoundaryDescriptor legacyBoundary = validPairControlBoundary(legacyIntent);
    suite.require(pairRegistry.recordClusterPairTestControlBoundary(legacyBoundary, false, legacyRecorded, &failure) &&
                  legacyRecorded.protocolVersion == MothershipClusterPairEnrollmentIntent::version &&
                  legacyRecorded.testControlBoundaryAdmitted,
                  "pair_control_boundary_upgrades_legacy_wire_on_admission");
  }

  return suite.failures == 0 ? 0 : 1;
}
