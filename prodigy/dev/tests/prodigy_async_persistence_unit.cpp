#include <includes.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/multiplexer.h>
#include <networking/ring.h>
#include <networking/time.h>
#include <prodigy/artifact.io.h>
#include <prodigy/persistent.state.h>
#include <prodigy/persistent.writer.h>

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <stdexcept>
#include <thread>
#include <unistd.h>
#include <vector>

#include <prodigy/dev/tests/persistence_fixture.h>

static ProdigyPersistentBootState bootState(const char *user)
{
  ProdigyPersistentBootState state = {};
  state.bootstrapSshUser.assign(user);
  return state;
}

static constexpr uint64_t bootRequestBytes = 4 * sizeof(ProdigyPersistentBootState) + 4096;
static constexpr uint64_t snapshotRequestBytes = 4 * sizeof(ProdigyPersistentBrainSnapshot) + bootRequestBytes;

static String persistenceView(String& backing)
{
  return String(const_cast<uint8_t *>(backing.data()), backing.size(), Copy::no, backing.size());
}

static void corruptPersistenceBacking(String& backing)
{
  std::memset(const_cast<uint8_t *>(backing.data()), '!', backing.size());
}

static void testPersistentWriterOwnsVersionedAuthorityState(TestSuite& suite)
{
  String witnessBootstrap = {}; witnessBootstrap.assign("witness-bootstrap"_ctv);
  String noticeName = {}; noticeName.assign("credential-name"_ctv);
  String noticeProvider = {}; noticeProvider.assign("credential-provider"_ctv);
  String deploymentBlob = {}; deploymentBlob.assign("deployment-blob-sha"_ctv);
  String failedReason = {}; failedReason.assign("terminal-failure"_ctv);
  String scalerName = {}; scalerName.assign("terminal-scaler"_ctv);
  String cancellationOperationID = {}; cancellationOperationID.assign("00000000-0000-4000-8000-000000000001"_ctv);
  String recoveryOperationID = {}; recoveryOperationID.assign("00000000-0000-4000-8000-000000000002"_ctv);
  String recoveryBlob = {}; recoveryBlob.assign("recovery-blob"_ctv);
  String retryBlob = {}; retryBlob.assign("retry-blob"_ctv);
  String reservedName = {}; reservedName.assign("reserved-name"_ctv);
  String reservedValue = {}; reservedValue.assign("reserved-value"_ctv);

  ProdigyPersistentBrainSnapshot snapshot = {};
  snapshot.brainConfig.clusterUUID = 0xa551;
  snapshot.masterAuthority.runtimeState.generation = 9;
  ProdigyPersistentUpdateSelfMachineRecoveryWitness witness = {};
  witness.machineUUID = 0xa552;
  witness.containerBootstraps.push_back(persistenceView(witnessBootstrap));
  snapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses.push_back(std::move(witness));
  ApiCredentialExpiryNotice notice = {};
  notice.stableID = 7;
  notice.applicationID = 91;
  notice.name = persistenceView(noticeName);
  notice.provider = persistenceView(noticeProvider);
  snapshot.masterAuthority.runtimeState.apiCredentialExpiryNotices.push_back(std::move(notice));
  DeploymentPlan plan = {};
  plan.config.applicationID = 91;
  plan.config.versionID = 1;
  plan.config.containerBlobSHA256 = persistenceView(deploymentBlob);
  snapshot.masterAuthority.deploymentPlans.insert_or_assign(0x5b000000000001ULL, std::move(plan));
  FailedDeploymentRecord failed = {};
  failed.reason = persistenceView(failedReason);
  failed.applicationID = 91;
  failed.deploymentID = (uint64_t(91) << 48) | 1;
  failed.hasTerminalReport = true;
  ScalerState scaler = {};
  scaler.name = persistenceView(scalerName);
  failed.terminalReport.lastScalerStates.push_back(std::move(scaler));
  failed.hasOperatorCancellation = true;
  failed.operationID = persistenceView(cancellationOperationID);
  failed.successorDeploymentID = (uint64_t(91) << 48) | 2;
  failed.cancellationPhase = CancelDeploymentPhase::accepted;
  failed.cancellationGeneration = 1;
  snapshot.masterAuthority.failedDeployments.insert_or_assign(failed.deploymentID, std::move(failed));
  ProdigyMaterializedStatefulRecoveryOperation recovery = {};
  recovery.operationID = persistenceView(recoveryOperationID);
  recovery.activeDeploymentID = (uint64_t(91) << 48) | 3;
  recovery.successorDeploymentID = (uint64_t(91) << 48) | 4;
  recovery.successorBlobSHA256 = persistenceView(recoveryBlob);
  snapshot.masterAuthority.runtimeState.materializedStatefulRecoveryOperations.push_back(std::move(recovery));
  ProdigyMaterializedStatefulRecoveryRetry retry = {};
  retry.operationID = persistenceView(recoveryOperationID);
  retry.activeDeploymentID = (uint64_t(91) << 48) | 3;
  retry.failedSuccessorDeploymentID = (uint64_t(91) << 48) | 4;
  retry.replacementSuccessorDeploymentID = (uint64_t(91) << 48) | 5;
  retry.failedSuccessorBlobSHA256 = persistenceView(recoveryBlob);
  retry.replacementSuccessorBlobSHA256 = persistenceView(retryBlob);
  snapshot.masterAuthority.runtimeState.materializedStatefulRecoveryRetries.push_back(std::move(retry));
  snapshot.masterAuthority.reservedApplicationIDsByName.insert_or_assign(persistenceView(reservedName), 91);
  snapshot.masterAuthority.reservedApplicationNamesByID.insert_or_assign(91, persistenceView(reservedValue));

  ProdigyPersistentBrainSnapshot emptySnapshot = {};
  const uint64_t emptyBytes = ProdigyPersistentStateWriter::retainedBytesFor(emptySnapshot);
  const uint64_t richBytes = ProdigyPersistentStateWriter::retainedBytesFor(snapshot);
  const bool detached = ProdigyPersistentStateWriter::detach(snapshot);
  corruptPersistenceBacking(witnessBootstrap);
  corruptPersistenceBacking(noticeName);
  corruptPersistenceBacking(noticeProvider);
  corruptPersistenceBacking(deploymentBlob);
  corruptPersistenceBacking(failedReason);
  corruptPersistenceBacking(scalerName);
  corruptPersistenceBacking(cancellationOperationID);
  corruptPersistenceBacking(recoveryOperationID);
  corruptPersistenceBacking(recoveryBlob);
  corruptPersistenceBacking(retryBlob);
  corruptPersistenceBacking(reservedName);
  corruptPersistenceBacking(reservedValue);

  const auto planIt = snapshot.masterAuthority.deploymentPlans.find(0x5b000000000001ULL);
  const auto failedIt = snapshot.masterAuthority.failedDeployments.find((uint64_t(91) << 48) | 1);
  const auto reservedIDIt = snapshot.masterAuthority.reservedApplicationIDsByName.find("reserved-name"_ctv);
  const auto reservedNameIt = snapshot.masterAuthority.reservedApplicationNamesByID.find(91);
  const bool owned = detached && richBytes > emptyBytes && richBytes <= ProdigyPersistentStateWriter::maximumRetainedBytes &&
      snapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses.size() == 1 &&
      snapshot.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[0].containerBootstraps[0].equals("witness-bootstrap"_ctv) &&
      snapshot.masterAuthority.runtimeState.apiCredentialExpiryNotices.size() == 1 &&
      snapshot.masterAuthority.runtimeState.apiCredentialExpiryNotices[0].name.equals("credential-name"_ctv) &&
      snapshot.masterAuthority.runtimeState.apiCredentialExpiryNotices[0].provider.equals("credential-provider"_ctv) &&
      planIt != snapshot.masterAuthority.deploymentPlans.end() && planIt->second.config.containerBlobSHA256.equals("deployment-blob-sha"_ctv) &&
      failedIt != snapshot.masterAuthority.failedDeployments.end() && failedIt->second.reason.equals("terminal-failure"_ctv) &&
      failedIt->second.terminalReport.lastScalerStates.size() == 1 &&
      failedIt->second.terminalReport.lastScalerStates[0].name.equals("terminal-scaler"_ctv) &&
      failedIt->second.operationID.equals("00000000-0000-4000-8000-000000000001"_ctv) &&
      snapshot.masterAuthority.runtimeState.materializedStatefulRecoveryOperations.size() == 1 &&
      snapshot.masterAuthority.runtimeState.materializedStatefulRecoveryOperations[0].successorBlobSHA256.equals("recovery-blob"_ctv) &&
      snapshot.masterAuthority.runtimeState.materializedStatefulRecoveryRetries.size() == 1 &&
      snapshot.masterAuthority.runtimeState.materializedStatefulRecoveryRetries[0].replacementSuccessorBlobSHA256.equals("retry-blob"_ctv) &&
      reservedIDIt != snapshot.masterAuthority.reservedApplicationIDsByName.end() && reservedIDIt->second == 91 &&
      reservedNameIt != snapshot.masterAuthority.reservedApplicationNamesByID.end() && reservedNameIt->second.equals("reserved-value"_ctv);
  suite.expect(owned, "async_persistence_writer_owns_versioned_authority_fields_and_sorted_maps");

  PersistenceRing ring;
  ScopedPersistentRoot root;
  ProdigyPersistentStateStore store(root.path);
  auto io = ProdigyArtifactIO::startOwned();
  bool completed = false;
  bool durable = false;
  ProdigyPersistentBrainSnapshot recovered = {};
  String failure = {};
  bool admitted = false;
  if (io)
  {
    ProdigyPersistentStateWriter writer(store, *io);
    admitted = writer.submitSnapshot(snapshot, {}, richBytes, [&](auto&& result) {
      durable = result.durable && result.snapshotDurable && result.bootStateDurable;
      completed = true;
      Ring::exit = true;
    });
    ring.armDeadline(1000);
    Ring::start();
    suite.expect(!ring.timedOut && admitted && completed && durable && writer.drainForExec(),
                 "async_persistence_versioned_authority_writer_completes_durable_snapshot");
    io->stop();
    ring.drainStoppedIO();
  }
  store.close();
  ProdigyPersistentStateStore reopened(root.path);
  const bool recoveredOK = owned && io != nullptr && admitted && completed && durable &&
      reopened.loadBrainSnapshot(recovered, &failure);
  const auto recoveredPlan = recovered.masterAuthority.deploymentPlans.find(0x5b000000000001ULL);
  const auto recoveredFailed = recovered.masterAuthority.failedDeployments.find((uint64_t(91) << 48) | 1);
  const auto recoveredReservedID = recovered.masterAuthority.reservedApplicationIDsByName.find("reserved-name"_ctv);
  const auto recoveredReservedName = recovered.masterAuthority.reservedApplicationNamesByID.find(91);
  suite.expect(recoveredOK && recovered.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses.size() == 1 &&
                   recovered.masterAuthority.runtimeState.updateSelf.machineRecoveryWitnesses[0].containerBootstraps[0].equals("witness-bootstrap"_ctv) &&
                   recovered.masterAuthority.runtimeState.apiCredentialExpiryNotices.size() == 1 &&
                   recovered.masterAuthority.runtimeState.apiCredentialExpiryNotices[0].name.equals("credential-name"_ctv) &&
                   recoveredPlan != recovered.masterAuthority.deploymentPlans.end() &&
                   recoveredPlan->second.config.containerBlobSHA256.equals("deployment-blob-sha"_ctv) &&
                   recoveredFailed != recovered.masterAuthority.failedDeployments.end() &&
                   recoveredFailed->second.reason.equals("terminal-failure"_ctv) &&
                   recoveredFailed->second.terminalReport.lastScalerStates.size() == 1 &&
                   recoveredFailed->second.terminalReport.lastScalerStates[0].name.equals("terminal-scaler"_ctv) &&
                   recoveredFailed->second.operationID.equals("00000000-0000-4000-8000-000000000001"_ctv) &&
                   recovered.masterAuthority.runtimeState.materializedStatefulRecoveryOperations.size() == 1 &&
                   recovered.masterAuthority.runtimeState.materializedStatefulRecoveryOperations[0].successorBlobSHA256.equals("recovery-blob"_ctv) &&
                   recovered.masterAuthority.runtimeState.materializedStatefulRecoveryRetries.size() == 1 &&
                   recovered.masterAuthority.runtimeState.materializedStatefulRecoveryRetries[0].replacementSuccessorBlobSHA256.equals("retry-blob"_ctv) &&
                   recoveredReservedID != recovered.masterAuthority.reservedApplicationIDsByName.end() &&
                   recoveredReservedName != recovered.masterAuthority.reservedApplicationNamesByID.end() &&
                   recoveredReservedName->second.equals("reserved-value"_ctv),
               "async_persistence_versioned_authority_fields_survive_private_tidesdb_reopen");
  reopened.close();
}

static uint64_t p95(const std::vector<uint64_t>& samples)
{
  if (samples.empty()) return 0;
  std::vector<uint64_t> sorted = samples;
  std::sort(sorted.begin(), sorted.end());
  return sorted[(sorted.size() * 95 + 99) / 100 - 1];
}

static void runUpdateBundleWriterMeasurement(TestSuite& suite, const char *bundlePath)
{
  if (bundlePath == nullptr || bundlePath[0] == '\0') return;
  String bundle = {};
  Filesystem::openReadAtClose(-1, String(bundlePath), bundle);
  String expectedDigest = {};
  String failure = {};
  suite.expect(bundle.empty() == false && prodigyComputeSHA256Hex(bundle, expectedDigest, &failure),
               "async_persistence_bundle_measurement_reads_and_hashes_runtime_bundle");
  if (bundle.empty() || expectedDigest.empty()) return;

  PersistenceRing ring;
  ScopedPersistentRoot root;
  ProdigyPersistentStateStore store(root.path);
  auto io = ProdigyArtifactIO::startOwned();
  suite.expect(io != nullptr, "async_persistence_bundle_measurement_starts_writer");
  if (!io) return;
  ProdigyPersistentStateWriter writer(store, *io);
  std::vector<uint64_t> submissionUs = {};
  std::vector<uint64_t> completionUs = {};
  std::vector<uint64_t> timerUs = {};
  uint32_t completed = 0;
  bool durable = true;
  // Budget the detached payload, public-state copy, and serialized buffers.
  const uint64_t retainedBytes = 4 * uint64_t(bundle.size()) + snapshotRequestBytes;
  std::chrono::steady_clock::time_point previousTick = std::chrono::steady_clock::now();
  std::function<void()> submitNext = {};
  submitNext = [&] {
    const auto started = std::chrono::steady_clock::now();
    ProdigyPersistentBrainSnapshot snapshot = {};
    snapshot.brainConfig.clusterUUID = 0xA51CULL;
    snapshot.masterAuthority.runtimeState.generation = uint64_t(completed + 1);
    snapshot.masterAuthority.runtimeState.updateSelf.bundleBlob = bundle;
    snapshot.masterAuthority.runtimeState.updateSelf.workerExpectedBundleSHA256 = expectedDigest;
    const bool admitted = writer.submitSnapshot(std::move(snapshot), bootState("bundle-measurement"), retainedBytes,
        [&, started](auto&& result) {
          const auto finished = std::chrono::steady_clock::now();
          completionUs.push_back(uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(finished - started).count()));
          durable = durable && result.durable && result.snapshotDurable && result.bootStateDurable;
          ++completed;
          if (completed < 10) submitNext();
          else if (timerUs.size() >= 30) Ring::exit = true;
        });
    const auto submitted = std::chrono::steady_clock::now();
    submissionUs.push_back(uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(submitted - started).count()));
    durable = durable && admitted;
    if (!admitted) Ring::exit = true;
  };
  ring.tickAction = [&] {
    const auto now = std::chrono::steady_clock::now();
    timerUs.push_back(uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(now - previousTick).count()));
    previousTick = now;
    if (completed == 10 && timerUs.size() >= 30) Ring::exit = true;
    else ring.armTick(2);
  };
  submitNext();
  ring.armTick(2);
  ring.armDeadline(10'000);
  Ring::start();
  uint64_t maxSubmissionUs = 0;
  uint64_t maxTimerUs = 0;
  for (uint64_t sample : submissionUs) maxSubmissionUs = std::max(maxSubmissionUs, sample);
  for (uint64_t sample : timerUs) maxTimerUs = std::max(maxTimerUs, sample);
  dprintf(STDERR_FILENO, "async_persistence_bundle bytes=%llu submission_us=", (unsigned long long)bundle.size());
  for (uint64_t sample : submissionUs) dprintf(STDERR_FILENO, "%llu,", (unsigned long long)sample);
  dprintf(STDERR_FILENO, " completion_us=");
  for (uint64_t sample : completionUs) dprintf(STDERR_FILENO, "%llu,", (unsigned long long)sample);
  dprintf(STDERR_FILENO, " timer_us=");
  for (uint64_t sample : timerUs) dprintf(STDERR_FILENO, "%llu,", (unsigned long long)sample);
  dprintf(STDERR_FILENO, " timer_p95_us=%llu timer_max_us=%llu\n", (unsigned long long)p95(timerUs), (unsigned long long)maxTimerUs);
  ProdigyPersistentBrainSnapshot loaded = {};
  String loadedDigest = {};
  failure.clear();
  const bool readback = store.loadBrainSnapshot(loaded, &failure) &&
      prodigyComputeSHA256Hex(loaded.masterAuthority.runtimeState.updateSelf.bundleBlob, loadedDigest, &failure) &&
      loadedDigest.equals(expectedDigest);
  suite.expect(!ring.timedOut && completed == 10 && durable && completionUs.size() == 10 && timerUs.size() >= 30 &&
                   p95(timerUs) <= 10'000 && maxTimerUs < 50'000 && maxSubmissionUs < 10'000 && readback,
               "async_persistence_bundle_measurement_durable_writer_latency_contract");
  suite.expect(writer.drainForExec(), "async_persistence_bundle_measurement_drains_writer");
  io->stop();
  ring.drainStoppedIO();
}

int main()
{
  TestSuite suite;

  testPersistentWriterOwnsVersionedAuthorityState(suite);
  runUpdateBundleWriterMeasurement(suite, std::getenv("PRODIGY_TEST_RUNTIME_BUNDLE"));

  // The actual TidesDB owner remains private to the state store.  This proves
  // the default commit crosses ArtifactIO and only reports durable completion
  // after both snapshot and boot records can be reopened.
  {
    PersistenceRing ring;
    ScopedPersistentRoot root;
    ProdigyPersistentStateStore store(root.path);
    auto io = ProdigyArtifactIO::startOwned();
    ProdigyPersistentBrainSnapshot snapshot = {};
    snapshot.brainConfig.clusterUUID = 0xA51CULL;
    bool complete = false;
    bool drainedInsideCompletion = true;
    bool releasedBudgetInsideCompletion = true;
    ProdigyPersistentStateWriter::Result result = {};
    suite.expect(io != nullptr && root.path.size() > 0, "async_persistence_starts_real_tidesdb_owner");
    if (io && root.path.size() > 0)
    {
      ProdigyPersistentStateWriter writer(store, *io);
      suite.expect(writer.submitSnapshot(std::move(snapshot), bootState("async-writer"), snapshotRequestBytes, [&](auto&& completed) {
                     result = std::move(completed);
                     releasedBudgetInsideCompletion = writer.submitBootState(
                         bootState("reentrant-budget"), ProdigyPersistentStateWriter::maximumRetainedBytes,
                         [](auto&&) {});
                     drainedInsideCompletion = writer.drainForExec();
                     complete = true;
                     Ring::exit = true;
                   }),
                   "async_persistence_admits_real_snapshot");
      ring.armDeadline(1000);
      Ring::start();
      ProdigyPersistentBrainSnapshot loadedSnapshot = {};
      ProdigyPersistentBootState loadedBoot = {};
      String failure = {};
      suite.expect(!ring.timedOut && complete && result.durable && result.snapshotDurable && result.bootStateDurable &&
                       store.loadBrainSnapshot(loadedSnapshot, &failure) && store.loadBootState(loadedBoot, &failure) &&
                       loadedSnapshot.brainConfig.clusterUUID == 0xA51CULL && loadedBoot.bootstrapSshUser.equals("async-writer"_ctv),
                   "async_persistence_completion_follows_durable_tidesdb_readback");
      suite.expect(!drainedInsideCompletion && writer.drainForExec(),
                   "async_persistence_writer_drains_only_after_completion_returns");
      suite.expect(!releasedBudgetInsideCompletion,
                   "async_persistence_callback_retains_active_payload_budget_until_return");
      io->stop();
      ring.drainStoppedIO();
    }
  }

  // A deliberately blocked commit must leave the Ring free to run thirty timer
  // turns, and completion may not leak before the worker is released.
  {
    PersistenceRing ring;
    ScopedPersistentRoot root;
    ProdigyPersistentStateStore store(root.path);
    auto io = ProdigyArtifactIO::startOwned();
    std::atomic<bool> entered = false;
    std::atomic<bool> release = false;
    bool completed = false;
    bool completedBeforeRelease = false;
    uint32_t ticksWhileBlocked = 0;
    suite.expect(io != nullptr, "async_persistence_starts_blocked_writer");
    if (io)
    {
      ProdigyPersistentStateWriter writer(store, *io, [&](auto&, auto& request) {
        entered = true;
        while (!release) std::this_thread::yield();
        request.result.snapshotDurable = true;
        request.result.bootStateDurable = true;
        request.result.durable = true;
      });
      suite.expect(writer.submitSnapshot({}, bootState("blocked"), snapshotRequestBytes, [&](auto&& result) {
                     completedBeforeRelease = !release;
                     completed = result.durable;
                     Ring::exit = true;
                   }),
                   "async_persistence_admits_blocked_commit");
      suite.expect(writer.drainForExec() == false,
                   "async_persistence_exec_drain_refuses_while_worker_commit_is_pending");
      ring.tickAction = [&] {
        if (entered && !release) ++ticksWhileBlocked;
        if (ticksWhileBlocked >= 30) release = true;
        if (!Ring::exit) ring.armTick(2);
      };
      ring.armTick(2);
      ring.armDeadline(1200);
      Ring::start();
      suite.expect(!ring.timedOut && ticksWhileBlocked >= 30 && !completedBeforeRelease && completed,
                   "async_persistence_blocked_save_keeps_ring_timers_progressing_before_completion");
      release = true;
      if (!completed)
      {
        ring.timedOut = false;
        Ring::exit = false;
        ring.armDeadline(300);
        Ring::start();
      }
      suite.expect(writer.drainForExec(), "async_persistence_drain_waits_until_blocked_commit_completes");
      io->stop();
      ring.drainStoppedIO();
    }
  }

  // One active ArtifactIO job plus seven FIFO reservations is the persistence
  // backpressure contract.  All completion callbacks remain Ring ordered.
  {
    PersistenceRing ring;
    ScopedPersistentRoot root;
    ProdigyPersistentStateStore store(root.path);
    auto io = ProdigyArtifactIO::startOwned();
    std::vector<uint64_t> completions = {};
    suite.expect(io != nullptr, "async_persistence_starts_fifo_writer");
    if (io)
    {
      ProdigyPersistentStateWriter writer(store, *io, [](auto&, auto& request) {
        request.result.bootStateDurable = true;
        request.result.durable = true;
      });
      bool admitted = true;
      for (uint32_t index = 0; index < ProdigyArtifactIO::maximumJobs; ++index)
      {
        admitted = admitted && writer.submitBootState(bootState("fifo"), ProdigyArtifactIO::maximumBytes / ProdigyArtifactIO::maximumJobs, [&](auto&& result) {
          completions.push_back(result.sequence);
          if (completions.size() == ProdigyArtifactIO::maximumJobs) Ring::exit = true;
        });
      }
      suite.expect(admitted && writer.hasPending() &&
                       writer.submitBootState(bootState("overflow"), ProdigyArtifactIO::maximumBytes / ProdigyArtifactIO::maximumJobs, [](auto&&) {}) == false,
                   "async_persistence_fifo_reserves_bounded_queue_and_rejects_backpressure");
      ring.armDeadline(1200);
      Ring::start();
      bool ordered = completions.size() == ProdigyArtifactIO::maximumJobs;
      for (uint64_t index = 0; ordered && index < completions.size(); ++index) ordered = completions[index] == index + 1;
      suite.expect(!ring.timedOut && ordered && !writer.hasPending(), "async_persistence_fifo_completes_in_sequence_order");
      suite.expect(writer.drainForExec(), "async_persistence_fifo_drains_after_queue_completion");
      io->stop();
      ring.drainStoppedIO();
    }
  }

  // Snapshot failure, failed boot follow-up, and a throwing follow-up all
  // fence later writes. A snapshot already committed remains durable.
  for (unsigned failureMode = 0; failureMode != 3; ++failureMode)
  {
    PersistenceRing ring;
    ScopedPersistentRoot root;
    ProdigyPersistentStateStore store(root.path);
    auto io = ProdigyArtifactIO::startOwned();
    std::vector<ProdigyPersistentStateWriter::Result> results = {};
    std::atomic<uint32_t> commits = 0;
    std::atomic<bool> workerPassedDependent = false;
    suite.expect(io != nullptr, "async_persistence_starts_failure_writer");
    if (io)
    {
      ProdigyPersistentStateWriter writer(store, *io, [failureMode, &commits](auto&, auto& request) {
        ++commits;
        request.result.snapshotDurable = failureMode != 0;
        request.result.durable = failureMode != 0;
        if (failureMode == 2) throw std::runtime_error("injected boot follow-up exception");
        request.result.failure.assign("injected persistent snapshot failure"_ctv);
      });
      suite.expect(writer.submitSnapshot({}, bootState("failed"), snapshotRequestBytes, [&](auto&& result) {
                     results.push_back(std::move(result));
                     if (results.size() == 2) Ring::exit = true;
                   }) &&
                       writer.submitBootState(bootState("dependent"), bootRequestBytes, [&](auto&& result) {
                         results.push_back(std::move(result));
                         if (results.size() == 2) Ring::exit = true;
                       }),
                   "async_persistence_admits_dependent_before_snapshot_failure_is_known");
      suite.expect(io->submit(1, [&] { workerPassedDependent = true; }, [] {}, [](std::exception_ptr) {}),
                   "async_persistence_queues_post_dependent_worker_marker");
      const auto workerDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
      while (!workerPassedDependent && std::chrono::steady_clock::now() < workerDeadline) std::this_thread::yield();
      suite.expect(workerPassedDependent && commits == 1,
                   "async_persistence_worker_fences_dependent_before_any_ring_receipt");
      ring.armDeadline(1000);
      Ring::start();
      const bool fenced = results.size() == 2 && results[0].durable == (failureMode != 0) &&
                          results[0].snapshotDurable == (failureMode != 0) && !results[0].bootStateDurable &&
                          !results[1].durable && results[0].failure.size() > 0 && results[1].failure.size() > 0;
      suite.expect(!ring.timedOut && fenced && writer.submitBootState(bootState("after-failure"), bootRequestBytes, [](auto&&) {}) == false,
                   "async_persistence_snapshot_failure_fences_dependents_and_latches_admission");
      suite.expect(writer.drainForExec(), "async_persistence_failure_queue_drains_before_exec");
      io->stop();
      ring.drainStoppedIO();
    }
  }

  // A continuation chained by one persistence receipt must not consume an
  // independently submitted writer job that was already accepted by
  // ArtifactIO.
  {
    PersistenceRing ring;
    ScopedPersistentRoot root;
    ProdigyPersistentStateStore store(root.path);
    auto io = ProdigyArtifactIO::startOwned();
    uint32_t firstCallbacks = 0;
    uint32_t secondCallbacks = 0;
    bool continuationConsumed = false;
    uint32_t continuations = 0;
    bool secondDurable = false;
    suite.expect(io != nullptr, "async_persistence_starts_independent_continuation_writer");
    if (io)
    {
      ProdigyPersistentStateWriter writer(store, *io, [](auto&, auto& request) {
        request.result.bootStateDurable = true;
        request.result.durable = true;
      });
      suite.expect(writer.submitBootState(bootState("first"), bootRequestBytes, [&](auto&&) {
                     ++firstCallbacks;
                     continuationConsumed = io->continueWith([] {}, [&] {
                       ++continuations;
                       if (secondCallbacks == 1) Ring::exit = true;
                     }, [](std::exception_ptr) { Ring::exit = true; });
                   }) &&
                       writer.submitBootState(bootState("second"), bootRequestBytes, [&](auto&& result) {
                         ++secondCallbacks;
                         secondDurable = result.durable;
                         if (continuations == 1) Ring::exit = true;
                       }),
                   "async_persistence_admits_independent_continuation_fixture");
      ring.armDeadline(1000);
      Ring::start();
      suite.expect(!ring.timedOut && continuationConsumed && continuations == 1 && firstCallbacks == 1 && secondCallbacks == 1 && secondDurable &&
                       !writer.hasPending() && writer.drainForExec(),
                   "async_persistence_continuation_preserves_independent_writer_receipt");
      io->stop();
      ring.drainStoppedIO();
    }
  }

  // Existing ArtifactIO pressure is a clean admission failure: it must not
  // run the request, invoke its completion, or poison later writer admission.
  {
    PersistenceRing ring;
    ScopedPersistentRoot root;
    ProdigyPersistentStateStore store(root.path);
    auto io = ProdigyArtifactIO::startOwned();
    std::atomic<bool> release = false;
    std::atomic<uint32_t> completedWorkers = 0;
    bool writerCallback = false;
    suite.expect(io != nullptr, "async_persistence_starts_capacity_rejection_writer");
    if (io)
    {
      ProdigyPersistentStateWriter writer(store, *io);
      bool saturated = true;
      for (uint32_t index = 0; index < ProdigyArtifactIO::maximumJobs; ++index)
      {
        saturated = saturated && io->submit(1, [&] {
          while (!release) std::this_thread::yield();
        }, [&] {
          ++completedWorkers;
          if (completedWorkers == ProdigyArtifactIO::maximumJobs) Ring::exit = true;
        }, [](std::exception_ptr) {});
      }
      suite.expect(saturated && writer.submitBootState(bootState("contended"), bootRequestBytes, [&](auto&&) { writerCallback = true; }) == false &&
                       !writer.hasPending() && writer.drainForExec(),
                   "async_persistence_artifact_capacity_rejection_is_clean_writer_backpressure");
      release = true;
      ring.armDeadline(1200);
      Ring::start();
      suite.expect(!ring.timedOut && completedWorkers == ProdigyArtifactIO::maximumJobs && !writerCallback,
                   "async_persistence_capacity_rejection_never_runs_or_callbacks_writer_request");
      io->stop();
      ring.drainStoppedIO();
    }
  }

  // Publishing a received artifact retains its ArtifactIO lease through this
  // Ring completion.  Its durable snapshot must still be admitted and only
  // then permit the peer ACK; treating the active artifact lease as global
  // writer backpressure silently leaves the deployment unacknowledged.
  {
    PersistenceRing ring;
    ScopedPersistentRoot root;
    ProdigyPersistentStateStore store(root.path);
    auto io = ProdigyArtifactIO::startOwned();
    bool artifactPublished = false;
    bool snapshotAdmitted = false;
    bool snapshotDurable = false;
    suite.expect(io != nullptr, "async_persistence_starts_artifact_publish_receipt_writer");
    if (io)
    {
      ProdigyPersistentStateWriter writer(store, *io);
      suite.expect(io->submit(1, [] {}, [&] {
                     artifactPublished = true;
                     ProdigyPersistentBrainSnapshot snapshot = {};
                     snapshot.brainConfig.clusterUUID = 0xA51DULL;
                     snapshotAdmitted = writer.submitSnapshot(std::move(snapshot), bootState("artifact-publish"), snapshotRequestBytes,
                         [&](auto&& result) {
                           snapshotDurable = result.durable && result.snapshotDurable && result.bootStateDurable;
                           Ring::exit = true;
                         });
                     if (!snapshotAdmitted) Ring::exit = true;
                   }, [](std::exception_ptr) { Ring::exit = true; }),
                   "async_persistence_queues_artifact_publish_receipt_fixture");
      ring.armDeadline(1000);
      Ring::start();
      suite.expect(!ring.timedOut && artifactPublished && snapshotAdmitted && snapshotDurable && writer.drainForExec(),
                   "async_persistence_artifact_publish_completion_admits_durable_snapshot_receipt");
      io->stop();
      ring.drainStoppedIO();
    }
  }

  return suite.failed == 0 ? 0 : 1;
}
