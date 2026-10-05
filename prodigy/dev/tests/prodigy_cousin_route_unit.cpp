#include <cstdio>
#include <cstdlib>
#include <filesystem>

#include <prodigy/cousin.route.h>
#include <prodigy/mothership/mothership.cluster.registry.h>
#include <prodigy/mothership/mothership.pair.control.boundary.h>

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
  route.destinationPublicAddress.is6 = true;
  route.destinationPublicAddress.v6[0] = 0x20;
  route.destinationPublicAddress.v6[1] = 0x01;
  route.destinationPublicAddress.v6[15] = 1;
  route.destinationTCPPort = 443;
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

int main(void)
{
  TestSuite suite;
  CousinRouteRecord route = validRoute();
  suite.require(cousinRouteStructurallyValid(route), "route_structural_validation_accepts_unequal_application_mapping");
  String routeDigest = {};
  suite.require(cousinRouteAuthorizationDigest(route, routeDigest), "route_digest_constructs");
  suite.require(routeDigest.size() == 64, "route_digest_is_sha256");
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
  changedBinding.rootGeneration++;
  suite.require(cousinRouteAuthorizationDigest(changedBinding, changedDigest) && changedDigest != routeDigest &&
                !cousinRouteKeyEpochTransitionValid(route, changedBinding), "route_root_rotation_requires_new_key_epoch");
  changedBinding.keyEpoch++;
  suite.require(cousinRouteKeyEpochTransitionValid(route, changedBinding), "route_root_rotation_accepts_new_key_epoch");

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
  prefixMismatch.sourceApplicationID = 8;
  suite.require(!cousinRouteStructurallyValid(prefixMismatch), "source_prefix_must_encode_source_application");
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
  {
    MothershipClusterRegistry registry {String(directory)};
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
  CousinRouteApplyReceipt revokedSourceReceipt = validReceipt(revoked, CousinRouteHalf::source, 3);
  CousinRouteApplyReceipt revokedDestinationReceipt = validReceipt(revoked, CousinRouteHalf::destination, 2);
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

  CousinRouteRecord expired = validRoute(0x102, 0x209);
  expired.expiresAtMs = 150;
  suite.require(registry.recordCousinRoute(expired, recorded, resumed, &failure), "registry_persists_finite_expiry_route");
  suite.require(!registry.loadUsableCousinRoute(expired.routeUUID, 150, loaded, &failure), "registry_expiry_rejects_new_admission_after_cold_load");

  CousinRouteRecord invalid = validRoute(0x103, 0x20a);
  invalid.expiresAtMs = invalid.issuedAtMs;
  suite.require(!cousinRouteStructurallyValid(invalid), "route_rejects_non_finite_lifetime");
  suite.require(!registry.recordCousinRoute(invalid, recorded, resumed, &failure), "registry_rejects_invalid_route");

  CousinRouteRecord drainingRoute = validRoute(0x104, 0x20b);
  suite.require(registry.recordCousinRoute(drainingRoute, recorded, resumed, &failure), "registry_persists_draining_route_initial_generation");
  CousinRouteRecord drainingGeneration = drainingRoute;
  drainingGeneration.operationUUID = 0x20c;
  drainingGeneration.generation = 2;
  drainingGeneration.issuedAtMs = 120;
  drainingGeneration.expiresAtMs = 300;
  drainingGeneration.state = CousinRouteState::draining;
  suite.require(registry.recordCousinRoute(drainingGeneration, recorded, resumed, &failure), "registry_persists_draining_desired_state");
  CousinRouteApplyReceipt drainingSourceReceipt = validReceipt(drainingGeneration, CousinRouteHalf::source, 1);
  CousinRouteApplyReceipt drainingDestinationReceipt = validReceipt(drainingGeneration, CousinRouteHalf::destination, 1);
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
  }
  {
    MothershipClusterRegistry pairRegistry {String(pairDirectory)};
    suite.require(pairRegistry.recordClusterPairTestControlBoundary(controlBoundary, false, pairRecorded, &failure) &&
                  pairRecorded.testControlBoundaryAdmitted && !pairRecorded.testControlBoundaryClosed,
                  "pair_control_boundary_cold_reopen_preserves_exact_open_descriptor");
    bool guardOpen = false;
    suite.require(pairRegistry.clusterHasOpenTestPairControlBoundary(pairIntent.firstClusterUUID, guardOpen, &failure) && guardOpen &&
                  pairRegistry.clusterHasOpenTestPairBoundary(pairIntent.secondClusterUUID, guardOpen, &failure) && guardOpen,
                  "pair_control_boundary_open_guard_blocks_cluster_removal");
    suite.require(pairRegistry.recordClusterPairTestControlBoundary(controlBoundary, true, pairRecorded, &failure) &&
                  pairRecorded.testControlBoundaryClosed,
                  "pair_control_boundary_closes_durable_guard");
    suite.require(pairRegistry.clusterHasOpenTestPairBoundary(pairIntent.firstClusterUUID, guardOpen, &failure) && !guardOpen,
                  "pair_control_boundary_closed_guard_no_longer_blocks_removal");
    suite.require(!pairRegistry.recordClusterPairTestControlBoundary(controlBoundary, false, pairRecorded, &failure),
                  "pair_control_boundary_closed_descriptor_cannot_reopen");
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
