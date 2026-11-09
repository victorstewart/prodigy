#include <networking/includes.h>
#include <cstdio>
#include <string>
#include <services/debug.h>

#include <prodigy/bundle.upgrade.h>

class UpgradeContractSuite {
public:
  int failed = 0;
  void expect(bool value, const char *name)
  {
    basics_log("%s: %s\n", value ? "PASS" : "FAIL", name);
    if (!value) { std::fprintf(stderr, "FAIL: %s\n", name); ++failed; }
  }
};

static MothershipUpgradeEnvelope validEnvelope(const String& contractBytes)
{
  MothershipUpgradeEnvelope e;
  e.approvedByBundleOwner = true;
  e.approvedBundleSHA256 = "7777777777777777777777777777777777777777777777777777777777777777"_ctv;
  prodigyComputeSHA256Hex(contractBytes, e.contractSHA256);
  e.prodigySHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"_ctv;
  e.mothershipSHA256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"_ctv;
  return e;
}

static String validContractJSON(void)
{
  String json;
  json.assign(R"json({"manifestVersion":1,"releaseID":"combined","prodigySHA256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","mothershipSHA256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","architecture":"aarch64","binaryVersion":"20","disposition":"same-cluster-rollout","compatibility":{"wire":"compatible","persistentState":"compatible","authorityState":"compatible","transportTrust":"compatible","containerProtocol":"compatible","dataPlane":"compatible","appState":"compatible"},"supportedSourceReleaseIDs":["live19b"],"sourceContracts":[{"releaseID":"live19b","contractSHA256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","prodigySHA256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","mothershipSHA256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}],"minimumHealthyBrains":2,"requiredFreeBytes":1024,"rollbackMode":"forward-only","transportIdentityMode":"preserveClusterIdentity","migrationProtocolVersion":"1"})json"_ctv);
  return json;
}

static String contractWithIdentityMode(const char *mode)
{
  const String valid = validContractJSON();
  std::string bytes(reinterpret_cast<const char *>(valid.data()), valid.size());
  const std::string field = "\"transportIdentityMode\":\"preserveClusterIdentity\",";
  const size_t position = bytes.find(field);
  const std::string replacement = mode == nullptr ? "" :
      std::string("\"transportIdentityMode\":\"") + mode + "\",";
  bytes.replace(position, field.size(), replacement);
  String result = {};
  result.assign(bytes.data(), bytes.size());
  return result;
}

static String cohortRecoveryContractJSON(void)
{
  const String valid = validContractJSON();
  std::string bytes(reinterpret_cast<const char *>(valid.data()), valid.size());
  bytes.replace(bytes.find("same-cluster-rollout"), std::strlen("same-cluster-rollout"), "same-cluster-cohort-recovery");
  bytes.replace(bytes.find("\"wire\":\"compatible\""), std::strlen("\"wire\":\"compatible\""), "\"wire\":\"incompatible\"");
  bytes.replace(bytes.find("\"minimumHealthyBrains\":2"), std::strlen("\"minimumHealthyBrains\":2"), "\"minimumHealthyBrains\":3");
  String result = {};
  result.assign(bytes.data(), bytes.size());
  return result;
}

static String unsupportedContractJSON(void)
{
  String json;
  json.assign(R"json({"manifestVersion":1,"releaseID":"local-build-unqualified","prodigySHA256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","mothershipSHA256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","architecture":"aarch64","binaryVersion":"unknown","disposition":"unsupported","compatibility":{"wire":"unknown","persistentState":"unknown","authorityState":"unknown","transportTrust":"unknown","containerProtocol":"unknown","dataPlane":"unknown","appState":"unknown"},"supportedSourceReleaseIDs":[],"sourceContracts":[],"minimumHealthyBrains":1,"requiredFreeBytes":0,"rollbackMode":"unsupported","transportIdentityMode":"unsupported","migrationProtocolVersion":"none"})json"_ctv);
  return json;
}

static MothershipUpgradePlannerInput validInput(void)
{
  MothershipUpgradePlannerInput i;
  i.envelope = validEnvelope(validContractJSON());
  i.observedSource.releaseID = "live19b"_ctv;
  i.observedSource.contractSHA256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"_ctv;
  i.observedSource.prodigySHA256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"_ctv;
  i.observedSource.mothershipSHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_ctv;
  i.observedTargetArchitecture = "aarch64"_ctv;
  i.sourceClusterUUID = 17; i.targetClusterUUID = 17;
  i.currentUpdaterSupportsSerialFollowers = true; i.sourceQuorumHealthy = true; i.targetQuorumHealthy = true;
  i.overlapCapacityAvailable = true; i.trustRootsAndUUIDBindingsMatch = true; i.publicBaselineHealthy = true;
  i.healthyBrains = 3; i.freeBytes = 4096;
  MothershipUpgradeWorkloadInput w; w.applicationID = "web"_ctv; w.migrationEligible = true; w.endpointStrategyAvailable = true; w.observedPublicContinuity = true;
  i.workloads.push_back(w);
  return i;
}

int main(void)
{
  UpgradeContractSuite suite;
  char capacityDirectory[] = "/tmp/prodigy-upgrade-capacity-XXXXXX";
  char *capacityRoot = ::mkdtemp(capacityDirectory);
  suite.expect(capacityRoot != nullptr, "capacity_probe_fixture_directory");
  if (capacityRoot != nullptr)
  {
    String stage = {}, install = {}, absent = {}, capacityFailure = {};
    stage.assign(capacityRoot); stage.append("/incoming.bundle"_ctv);
    install.assign(capacityRoot); install.append("/prodigy"_ctv);
    absent.assign(capacityRoot); absent.append("/missing/prodigy"_ctv);
    uint64_t available = 0;
    suite.expect(prodigyMeasureBundleUpdateFilesystemAvailabilityAtPaths(stage, install, available, &capacityFailure) && available > 0,
                 "capacity_probe_measures_actual_stage_and_replacement_parent_filesystems");
    suite.expect(!prodigyMeasureBundleUpdateFilesystemAvailabilityAtPaths(stage, absent, available, &capacityFailure) && available == 0,
                 "capacity_probe_rejects_unavailable_install_parent");
    suite.expect(!prodigyMeasureBundleUpdateFilesystemAvailabilityAtPaths(absent, install, available, &capacityFailure) && available == 0,
                 "capacity_probe_rejects_unavailable_staging_parent");
    ::rmdir(capacityRoot);
  }
  String encoded = {};
  mothershipUpgradeAppendField(encoded, "a|b"_ctv);
  mothershipUpgradeAppendUInt(encoded, 256);
  suite.expect(encoded.equals("3:a|b|256|"_ctv), "canonical_plan_encoding_uses_decimal_lengths_and_integers");

  MothershipUpgradeContract contract; String failure;
  const String json = validContractJSON();
  const MothershipUpgradeEnvelope envelope = validEnvelope(json);
  suite.expect(mothershipParseUpgradeContract(json, envelope, contract, &failure), "parse_authenticated_explicit_contract");
  suite.expect(contract.containerRetirementJournalVersion == 0, "missing_retirement_reader_is_legacy_unsupported");
  for (const char *version : {"0", "1", "2", "3", "4", "5", "-1", "\"1\""})
  {
    std::string modified(reinterpret_cast<const char *>(json.data()), json.size());
    modified.insert(modified.rfind('}'), std::string(",\"containerRetirementJournalVersion\":") + version);
    String declared = {}; declared.assign(modified.data(), modified.size());
    MothershipUpgradeContract reader = {};
    const bool accepted = mothershipParseUpgradeContract(declared, validEnvelope(declared), reader, &failure);
    const bool valid = std::string(version) == "0" || std::string(version) == "1" ||
                       std::string(version) == "2" || std::string(version) == "3" || std::string(version) == "4";
    suite.expect(accepted == valid && (!accepted || reader.containerRetirementJournalVersion == uint32_t(version[0] - '0')),
                 "retirement_reader_version_is_explicit_and_bounded");
  }
  MothershipUpgradeEnvelope wrong = envelope; wrong.contractSHA256 = "1111111111111111111111111111111111111111111111111111111111111111"_ctv;
  suite.expect(!mothershipParseUpgradeContract(json, wrong, contract, &failure), "reject_envelope_contract_digest_mismatch");
  String changedBytes = json; changedBytes.append(' ');
  suite.expect(!mothershipParseUpgradeContract(changedBytes, envelope, contract, &failure), "reject_changed_contract_artifact_bytes");
  suite.expect(!mothershipParseUpgradeContract("{}"_ctv, validEnvelope("{}"_ctv), contract, &failure), "reject_missing_contract_fields");
  const char *invalidIdentityModes[] = {nullptr, "unsupported", "rotateCA", "unknown"};
  for (const char *mode : invalidIdentityModes)
  {
    const String invalidIdentity = contractWithIdentityMode(mode);
    suite.expect(!mothershipParseUpgradeContract(invalidIdentity, validEnvelope(invalidIdentity), contract, &failure),
                 "reject_missing_or_unqualified_transport_identity_contract");
  }
  mothershipParseUpgradeContract(json, envelope, contract, &failure);
  const String unsupportedJSON = unsupportedContractJSON();
  MothershipUpgradeContract unsupported;
  suite.expect(mothershipParseUpgradeContract(unsupportedJSON, validEnvelope(unsupportedJSON), unsupported, &failure), "parse_unsupported_unknown_axes_empty_sources");
  suite.expect(!mothershipPlanUpgrade(unsupported, validInput()).eligible, "reject_unsupported_unknown_contract");

  const String cohortJSON = cohortRecoveryContractJSON();
  MothershipUpgradeContract cohort;
  const MothershipUpgradeEnvelope cohortEnvelope = validEnvelope(cohortJSON);
  suite.expect(mothershipParseUpgradeContract(cohortJSON, cohortEnvelope, cohort, &failure) &&
                   cohort.disposition == MothershipUpgradeDisposition::sameClusterCohortRecovery &&
                   cohort.compatibility.wire == MothershipUpgradeCompatibilityState::incompatible,
               "parse_qualified_same_cluster_cohort_recovery_contract");
  std::string insufficientCohortBytes(reinterpret_cast<const char *>(cohortJSON.data()), cohortJSON.size());
  insufficientCohortBytes.replace(insufficientCohortBytes.find("\"minimumHealthyBrains\":3"),
                                  std::strlen("\"minimumHealthyBrains\":3"), "\"minimumHealthyBrains\":2");
  String insufficientCohort = {};
  insufficientCohort.assign(insufficientCohortBytes.data(), insufficientCohortBytes.size());
  MothershipUpgradeContract rejectedCohort;
  suite.expect(!mothershipParseUpgradeContract(insufficientCohort, validEnvelope(insufficientCohort), rejectedCohort, &failure),
               "reject_cohort_recovery_contract_without_three_brains");

  MothershipUpgradePlannerInput input = validInput();
  MothershipUpgradePlan plan = mothershipPlanUpgrade(contract, input);
  suite.expect(plan.eligible && plan.path == MothershipUpgradePath::sameLogicalRollout && prodigyIsSHA256HexDigest(plan.inputSHA256), "select_same_cluster_serial_rollout");
  suite.expect(mothershipPlanUpgrade(contract, input).inputSHA256 == plan.inputSHA256, "stable_plan_input_hash_for_identical_inputs");
  MothershipUpgradePlannerInput changedInput = input; changedInput.freeBytes += 1;
  suite.expect(mothershipPlanUpgrade(contract, changedInput).eligible &&
                   mothershipPlanUpgrade(contract, changedInput).inputSHA256 == plan.inputSHA256,
               "input_hash_normalizes_sufficient_capacity_evidence");
  changedInput = input; changedInput.freeBytes = contract.requiredFreeBytes - 1;
  suite.expect(!mothershipPlanUpgrade(contract, changedInput).eligible &&
                   mothershipPlanUpgrade(contract, changedInput).inputSHA256 != plan.inputSHA256,
               "input_hash_binds_insufficient_capacity_evidence");
  changedInput = input; changedInput.workloads[0].observedPublicContinuity = false;
  suite.expect(mothershipPlanUpgrade(contract, changedInput).inputSHA256 != plan.inputSHA256, "input_hash_binds_workload_evidence");
  changedInput = input; changedInput.noManagedPublicWorkloads = true;
  suite.expect(mothershipPlanUpgrade(contract, changedInput).inputSHA256 != plan.inputSHA256,
               "input_hash_binds_no_managed_public_workloads_receipt");
  changedInput = input; changedInput.operatorAcceptedActiveWorkloadInterruption = true;
  suite.expect(mothershipPlanUpgrade(contract, changedInput).inputSHA256 != plan.inputSHA256,
               "input_hash_binds_operator_accepted_active_workload_interruption");
  changedInput = input; changedInput.observedTargetArchitecture = "x86_64"_ctv;
  suite.expect(mothershipPlanUpgrade(contract, changedInput).inputSHA256 != plan.inputSHA256,
               "input_hash_binds_observed_target_architecture");
  MothershipUpgradeContract changedContract = contract;
  changedContract.rollbackMode = "canary-rollback"_ctv;
  suite.expect(mothershipPlanUpgrade(changedContract, input).inputSHA256 != plan.inputSHA256,
               "input_hash_binds_target_rollback_policy");
  changedContract = contract;
  changedContract.transportIdentityMode = "unsupported"_ctv;
  suite.expect(!mothershipPlanUpgrade(changedContract, input).eligible &&
                   mothershipPlanUpgrade(changedContract, input).inputSHA256 != plan.inputSHA256,
               "reject_unqualified_identity_mode_and_bind_it_in_plan_hash");
  changedContract = contract;
  changedContract.migrationProtocolVersion = "2"_ctv;
  suite.expect(mothershipPlanUpgrade(changedContract, input).inputSHA256 != plan.inputSHA256,
               "input_hash_binds_target_migration_protocol");
  input = validInput(); input.observedTargetArchitecture.clear();
  suite.expect(!mothershipPlanUpgrade(contract, input).eligible, "reject_missing_observed_target_architecture");
  input = validInput(); input.observedTargetArchitecture = "x86_64"_ctv;
  suite.expect(!mothershipPlanUpgrade(contract, input).eligible, "reject_mismatched_observed_target_architecture");
  input.currentUpdaterSupportsSerialFollowers = false;
  suite.expect(!mothershipPlanUpgrade(contract, input).eligible, "reject_live19b_style_nonserial_updater");
  input = validInput(); input.sourceClusterUUID = 0;
  suite.expect(!mothershipPlanUpgrade(contract, input).eligible, "reject_missing_cluster_identity");
  input = validInput(); input.overlapCapacityAvailable = false;
  suite.expect(!mothershipPlanUpgrade(contract, input).eligible, "reject_insufficient_overlap_capacity");
  input = validInput(); input.publicBaselineHealthy = false; input.workloads.clear();
  suite.expect(!mothershipPlanUpgrade(contract, input).eligible,
               "empty_production_cluster_still_requires_public_baseline_policy");
  input.noManagedPublicWorkloads = true;
  suite.expect(mothershipPlanUpgrade(contract, input).eligible,
               "explicit_no_managed_public_workloads_receipt_qualifies_empty_production_cluster");
  input.workloads = validInput().workloads;
  suite.expect(!mothershipPlanUpgrade(contract, input).eligible,
               "no_managed_public_workloads_receipt_rejects_workload_claim");
  input = validInput(); input.publicBaselineHealthy = false; input.workloads.clear();
  input.operatorAcceptedActiveWorkloadInterruption = true;
  suite.expect(mothershipPlanUpgrade(contract, input).eligible,
               "operator_acceptance_qualifies_serial_same_cluster_disposable_workload_interruption");
  input.workloads = validInput().workloads;
  suite.expect(!mothershipPlanUpgrade(contract, input).eligible,
               "operator_interruption_acceptance_rejects_continuity_workload_claims");
  input.workloads.clear(); input.requestProviderRelocation = true;
  suite.expect(!mothershipPlanUpgrade(contract, input).eligible,
               "operator_interruption_acceptance_rejects_relocation");
  input.workloads.clear(); input.noManagedPublicWorkloads = false;
  input.operatorAcceptedActiveWorkloadInterruption = false;
  input.requestProviderRelocation = false;
  input.emptyIsolatedTestCluster = true;
  suite.expect(mothershipPlanUpgrade(contract, input).eligible,
               "explicit_empty_isolated_test_profile_has_no_public_workload_baseline");
  input.workloads = validInput().workloads;
  suite.expect(!mothershipPlanUpgrade(contract, input).eligible,
               "empty_test_profile_cannot_skip_workload_continuity_checks");
  MothershipUpgradeContract incompatible = contract; incompatible.compatibility.dataPlane = MothershipUpgradeCompatibilityState::incompatible;
  suite.expect(!mothershipPlanUpgrade(incompatible, validInput()).eligible, "reject_incompatible_data_plane_axis");
  input = validInput(); input.observedSource.releaseID = "unknown"_ctv;
  suite.expect(!mothershipPlanUpgrade(contract, input).eligible, "reject_undeclared_exact_source_identity");

  ProdigyApprovedUpgradeBundle approved = {};
  approved.bundleSHA256 = envelope.approvedBundleSHA256;
  approved.envelope = envelope;
  approved.contract = contract;
  String releaseFailure = {};

  ProdigyApprovedUpgradeBundle cohortApproved = {};
  cohortApproved.bundleSHA256 = cohortEnvelope.approvedBundleSHA256;
  cohortApproved.envelope = cohortEnvelope;
  suite.expect(mothershipParseUpgradeContract(cohortJSON, cohortEnvelope, cohortApproved.contract, &failure),
               "reparse_cohort_recovery_contract_for_runtime_policy");
  suite.expect(!prodigyValidateSameClusterUpgradeTarget(
                   cohortApproved, "aarch64"_ctv, 17, &releaseFailure) &&
                   releaseFailure == "approved target release requires same-cluster cohort recovery"_ctv,
               "ordinary_same_cluster_target_rejects_cohort_only_disposition");
  suite.expect(prodigyValidateRuntimeRecoveryTarget(
                   cohortApproved, "aarch64"_ctv, 17, &releaseFailure) &&
                   mothershipUpgradeDeclaredSource(cohortApproved.contract, cohortApproved.contract.sources.front()),
               "runtime_recovery_target_accepts_exact_cohort_policy_and_external_source_binding");
  cohortApproved.contract.compatibility.authorityState = MothershipUpgradeCompatibilityState::incompatible;
  suite.expect(!prodigyValidateRuntimeRecoveryTarget(cohortApproved, "aarch64"_ctv, 17, &releaseFailure),
               "runtime_recovery_target_rejects_incompatible_retained_authority_axis");
  cohortApproved.contract.compatibility = cohort.compatibility;
  MothershipUpgradePlannerInput cohortInput = validInput();
  cohortInput.envelope = cohortEnvelope;
  cohortInput.currentUpdaterSupportsSerialFollowers = false;
  cohortInput.publicBaselineHealthy = false;
  cohortInput.workloads.clear();
  cohortInput.operatorAcceptedActiveWorkloadInterruption = true;
  plan = mothershipPlanUpgrade(cohortApproved.contract, cohortInput);
  suite.expect(plan.eligible && plan.path == MothershipUpgradePath::sameLogicalCohortRecovery &&
                   plan.requiredPreconditions.size() == 2,
               "select_same_logical_cohort_recovery_without_serial_updater_claim");
  cohortInput.operatorAcceptedActiveWorkloadInterruption = false;
  suite.expect(!mothershipPlanUpgrade(cohortApproved.contract, cohortInput).eligible,
               "cohort_recovery_requires_explicit_active_workload_interruption_acceptance");
  cohortInput.operatorAcceptedActiveWorkloadInterruption = true;
  cohortInput.requestProviderRelocation = true;
  suite.expect(!mothershipPlanUpgrade(cohortApproved.contract, cohortInput).eligible,
               "cohort_recovery_rejects_provider_relocation_path");
  MothershipUpgradeIdentity observedSource = contract.sources.front();
  suite.expect(prodigyValidateSameClusterUpgradeRelease(
                   approved, "aarch64"_ctv, 17, &observedSource, true, &releaseFailure),
               "validate_same_cluster_release_accepts_declared_complete_source");
  MothershipUpgradeIdentity undeclaredSource = observedSource;
  undeclaredSource.prodigySHA256[0] = '0';
  suite.expect(!prodigyValidateSameClusterUpgradeRelease(
                   approved, "aarch64"_ctv, 17, &undeclaredSource, true, &releaseFailure) &&
                   releaseFailure == "observed source release identity is not declared by approved target contract"_ctv,
               "validate_same_cluster_release_rejects_undeclared_source_identity");
  MothershipUpgradeContract unknownAxis = contract;
  unknownAxis.compatibility.transportTrust = MothershipUpgradeCompatibilityState::unknown;
  approved.contract = unknownAxis;
  suite.expect(!prodigyValidateSameClusterUpgradeRelease(
                   approved, "aarch64"_ctv, 17, &observedSource, true, &releaseFailure) &&
                   releaseFailure == "approved target release lacks full same-cluster compatibility"_ctv,
               "validate_same_cluster_release_rejects_unknown_compatibility_axis");
  approved.contract = contract;
  approved.contract.transportIdentityMode = "unsupported"_ctv;
  suite.expect(!prodigyValidateSameClusterUpgradeRelease(
                   approved, "aarch64"_ctv, 17, &observedSource, true, &releaseFailure) &&
                   releaseFailure == "approved target release does not preserve cluster transport identity"_ctv,
               "validate_same_cluster_release_rejects_unqualified_identity_mode");
  MothershipUpgradeContract newClusterTarget = contract;
  newClusterTarget.disposition = MothershipUpgradeDisposition::newClusterRequired;
  approved.contract = newClusterTarget;
  suite.expect(!prodigyValidateSameClusterUpgradeRelease(
                   approved, "aarch64"_ctv, 17, &observedSource, true, &releaseFailure) &&
                   releaseFailure == "approved target release requires independent-cluster migration"_ctv,
               "validate_same_cluster_release_rejects_new_cluster_contract");
  approved.envelope = validEnvelope(unsupportedJSON);
  approved.bundleSHA256 = approved.envelope.approvedBundleSHA256;
  approved.contract = unsupported;
  suite.expect(!prodigyValidateSameClusterUpgradeRelease(
                   approved, "aarch64"_ctv, 17, &observedSource, true, &releaseFailure) &&
                   releaseFailure == "approved target release declares upgrades unsupported"_ctv,
               "validate_same_cluster_release_rejects_unsupported_contract");
  approved.envelope = envelope;
  approved.bundleSHA256 = envelope.approvedBundleSHA256;
  approved.contract = contract;

  suite.expect(prodigyValidateRuntimeRecoveryDriver(approved,contract.mothershipSHA256,
                   observedSource,"aarch64"_ctv,17,&releaseFailure),
               "recovery_driver_accepts_exact_declared_target_and_executing_controller");
  suite.expect(prodigyValidateRuntimeRecoveryDriver(cohortApproved, cohortApproved.contract.mothershipSHA256,
                   cohortApproved.contract.sources.front(), "aarch64"_ctv, 17, &releaseFailure),
               "recovery_driver_accepts_exact_declared_cohort_recovery_target");
  suite.expect(!prodigyValidateRuntimeRecoveryDriver(approved,observedSource.mothershipSHA256,
                   observedSource,"aarch64"_ctv,17,&releaseFailure),
               "recovery_driver_rejects_executable_outside_approved_bundle");
  suite.expect(!prodigyValidateRuntimeRecoveryDriver(approved,contract.mothershipSHA256,
                   undeclaredSource,"aarch64"_ctv,17,&releaseFailure),
               "recovery_driver_rejects_substituted_admitted_target");
  suite.expect(!prodigyValidateRuntimeRecoveryDriver(approved,contract.mothershipSHA256,
                   observedSource,"x86_64"_ctv,17,&releaseFailure),
               "recovery_driver_rejects_architecture_change");
  approved.contract.compatibility.authorityState=MothershipUpgradeCompatibilityState::incompatible;
  suite.expect(!prodigyValidateRuntimeRecoveryDriver(approved,contract.mothershipSHA256,
                   observedSource,"aarch64"_ctv,17,&releaseFailure),
               "recovery_driver_rejects_incompatible_authority_state");
  approved.contract=contract;

  String preflightFailure = {};
  suite.expect(!prodigyPreflightLegacySameClusterUpdate(
                   approved, "aarch64"_ctv, 17, nullptr, false, &preflightFailure) &&
                   preflightFailure == "observed source release identity is unavailable; typed Brain report is required"_ctv,
               "legacy_update_rejects_missing_observed_source_identity");
  suite.expect(!prodigyPreflightLegacySameClusterUpdate(
                   approved, "aarch64"_ctv, 17, &observedSource, false, &preflightFailure) &&
                   preflightFailure == "current updater serial-follower capability is unqualified; typed Brain report is required"_ctv,
               "legacy_update_rejects_unqualified_serial_capability");
  suite.expect(!prodigyPreflightLegacySameClusterUpdate(
                   approved, "aarch64"_ctv, 17, &observedSource, true, &preflightFailure) &&
                   preflightFailure == "legacy updateProdigy requires a persisted typed admission record before dispatch"_ctv,
               "legacy_update_requires_durable_typed_admission");
  MothershipUpgradeContract newCluster = contract;
  newCluster.disposition = MothershipUpgradeDisposition::newClusterRequired;
  approved.contract = newCluster;
  suite.expect(!prodigyPreflightLegacySameClusterUpdate(
                   approved, "aarch64"_ctv, 17, &observedSource, true, &preflightFailure) &&
                   preflightFailure == "approved target release requires independent-cluster migration"_ctv,
               "legacy_update_rejects_new_cluster_required_contract");
  approved.envelope = validEnvelope(unsupportedJSON);
  approved.bundleSHA256 = approved.envelope.approvedBundleSHA256;
  approved.contract = unsupported;
  suite.expect(!prodigyPreflightLegacySameClusterUpdate(
                   approved, "aarch64"_ctv, 17, nullptr, false, &preflightFailure) &&
                   preflightFailure == "approved target release declares upgrades unsupported"_ctv,
               "legacy_update_rejects_unsupported_contract");
  approved.envelope = envelope;
  approved.bundleSHA256 = envelope.approvedBundleSHA256;
  approved.contract = contract;

  input = validInput(); input.requestProviderRelocation = true; input.providerGatewayScopedL3L4 = true; input.providerGatewayAvoidsHostNetworkMutation = true;
  plan = mothershipPlanUpgrade(contract, input);
  suite.expect(plan.eligible && plan.path == MothershipUpgradePath::logicalClusterRelocation && plan.orderedIntentReceipts.size() == 4, "select_same_identity_provider_relocation");
  input.providerGatewayScopedL3L4 = false;
  suite.expect(!mothershipPlanUpgrade(contract, input).eligible, "reject_unscoped_provider_gateway");

  MothershipUpgradeContract separate = contract; separate.disposition = MothershipUpgradeDisposition::newClusterRequired;
  separate.compatibility.wire = MothershipUpgradeCompatibilityState::incompatible;
  separate.compatibility.dataPlane = MothershipUpgradeCompatibilityState::incompatible;
  input = validInput(); input.requestSeparateCluster = true; input.targetClusterUUID = 18; input.workloads[0].bridgeProtocolAvailable = true;
  plan = mothershipPlanUpgrade(separate, input);
  suite.expect(plan.eligible && plan.path == MothershipUpgradePath::separateClusterMigration, "select_breaking_separate_cluster_bridge");
  input.workloads[0].stateful = true; input.workloads[0].fencingAvailable = false;
  suite.expect(!mothershipPlanUpgrade(separate, input).eligible, "reject_stateful_bridge_without_fencing");
  return suite.failed == 0 ? 0 : 1;
}
