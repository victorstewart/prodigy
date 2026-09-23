// Included after TestBrain and TestSuite.
class AsyncCleanupBrain final : public TestBrain {
public:
  uint32_t synchronousWrites = 0;
  uint32_t asynchronousWrites = 0;
  std::deque<PersistenceCompletion> receipts;

  bool persistLocalRuntimeState() override
  {
    synchronousWrites += 1;
    return true;
  }

  void persistLocalRuntimeStateAsync(PersistenceCompletion completion = {}) override
  {
    asynchronousWrites += 1;
    receipts.push_back(completion ? std::move(completion) : PersistenceCompletion([](bool) {}));
  }

  void finishCleanupReceipt(bool durable)
  {
    if (receipts.empty()) return;
    auto completion = std::move(receipts.front());
    receipts.pop_front();
    completion(durable);
  }
};

static void testAsyncFailedDeploymentCleanupPersistence(TestSuite& suite)
{
  AsyncCleanupBrain brain;
  const uint64_t deploymentID = 0x6c65616eULL;
  FailedDeploymentRecord failed = {};
  failed.deploymentID = deploymentID;
  failed.applicationID = 61;
  failed.failedAtMs = 1;
  brain.failedDeployments.insert_or_assign(deploymentID, failed);

  const uint32_t expired = brain.expireFailedDeployments(
      int64_t(prodigyBrainFailedDeploymentCleanerIntervalMs) + 1);
  suite.expect(expired == 1 && brain.failedDeployments.empty() &&
                   brain.asynchronousWrites == 1 && brain.synchronousWrites == 0 &&
                   brain.receipts.size() == 1,
               "failed_cleanup_uses_held_async_persistence_after_removal");
  brain.finishCleanupReceipt(true);
  suite.expect(brain.asynchronousWrites == 1 && brain.synchronousWrites == 0 &&
                   brain.receipts.empty(),
               "failed_cleanup_receipt_completes_without_repeating_cleanup_write");
}
