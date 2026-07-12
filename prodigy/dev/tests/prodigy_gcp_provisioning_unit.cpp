#include <networking/includes.h>
#include <prodigy/iaas/gcp/gcp.provisioning.h>
#include <cstdio>

class TestSuite
{
public:

  uint32_t failed = 0;

  void expect(bool condition, const char *name)
  {
    if (condition == false)
    {
      std::fprintf(stderr, "FAIL: %s\n", name);
    }
    failed += condition ? 0 : 1;
  }
};

class ScriptedHttpClient
{
public:

  using Operation = ProdigyHostHttpOperation;

  struct Response
  {
    MultiCurlClient::Status status = MultiCurlClient::Status::success;
    long statusCode = 200;
    String body;
    bool inlineCompletion = false;
  };

  Vector<Response> responses;
  Vector<Operation::Request> requests;
  Vector<Operation::Callback> callbacks;
  Vector<Operation::Ticket> tickets;
  Vector<uint8_t> pending;
  uint32_t nextResponse = 0;
  uint32_t cancellations = 0;
  uint32_t active = 0;
  uint32_t maximumActive = 0;

  static Operation::Ticket submit(void *context,
                                  Operation::Request&& request,
                                  Operation::Callback callback)
  {
    ScriptedHttpClient& client = *static_cast<ScriptedHttpClient *>(context);
    const uint32_t responseIndex = client.nextResponse++;
    client.requests.push_back(std::move(request));
    if (responseIndex >= client.responses.size())
    {
      return {};
    }
    const Operation::Ticket ticket {uint64_t(responseIndex) + 1, 23};
    client.callbacks.push_back(callback);
    client.tickets.push_back(ticket);
    client.pending.push_back(1);
    ++client.active;
    client.maximumActive = std::max(client.maximumActive, client.active);
    if (client.responses[responseIndex].inlineCompletion)
    {
      Operation::Result result = client.result(responseIndex);
      client.pending.back() = 0;
      --client.active;
      callback.function(callback.context, ticket, std::move(result));
    }
    return ticket;
  }

  static bool cancel(void *context, Operation::Ticket ticket)
  {
    ScriptedHttpClient& client = *static_cast<ScriptedHttpClient *>(context);
    for (uint32_t index = 0; index < client.tickets.size(); ++index)
    {
      if (client.pending[index] &&
          client.tickets[index].identifier == ticket.identifier &&
          client.tickets[index].generation == ticket.generation)
      {
        client.pending[index] = 0;
        --client.active;
        ++client.cancellations;
        Operation::Result result;
        result.status = MultiCurlClient::Status::canceled;
        client.callbacks[index].function(client.callbacks[index].context,
                                         ticket,
                                         std::move(result));
        return true;
      }
    }
    return false;
  }

  Operation::Submission submission(void)
  {
    return {this, submit, cancel};
  }

  void add(MultiCurlClient::Status status,
           long statusCode,
           const String& body,
           bool inlineCompletion = false)
  {
    responses.push_back({status, statusCode, body, inlineCompletion});
  }

  bool completeOne(void)
  {
    for (uint32_t index = 0; index < pending.size(); ++index)
    {
      if (pending[index])
      {
        pending[index] = 0;
        --active;
        Operation::Result completed = result(index);
        callbacks[index].function(callbacks[index].context,
                                  tickets[index],
                                  std::move(completed));
        return true;
      }
    }
    return false;
  }

private:

  Operation::Result result(uint32_t index) const
  {
    Operation::Result result;
    result.status = responses[index].status;
    result.statusCode = responses[index].statusCode;
    result.body = responses[index].body;
    return result;
  }
};

class ScriptedDelayQueue
{
public:

  TimeoutPacket *pending = nullptr;
  Vector<uint64_t> delays;

  static void queue(void *context, TimeoutPacket *packet)
  {
    ScriptedDelayQueue& delay = *static_cast<ScriptedDelayQueue *>(context);
    delay.pending = packet;
    delay.delays.push_back(uint64_t(packet->timeout.tv_sec) * 1'000'000 +
                           uint64_t(packet->timeout.tv_nsec) / 1000);
  }

  static void cancel(void *context, TimeoutPacket *packet)
  {
    ScriptedDelayQueue& delay = *static_cast<ScriptedDelayQueue *>(context);
    if (delay.pending == packet)
    {
      delay.pending = nullptr;
      packet->dispatcher->dispatchTimeout(packet);
    }
  }

  ProdigyHostDelayOperation::Submission submission(void)
  {
    return {this, queue, cancel};
  }

  bool complete(void)
  {
    if (pending == nullptr)
    {
      return false;
    }
    TimeoutPacket *packet = pending;
    pending = nullptr;
    packet->dispatcher->dispatchTimeout(packet);
    return true;
  }
};

static bool contains(const String& value, const String& fragment)
{
  if (fragment.size() > value.size())
  {
    return false;
  }
  for (uint32_t offset = 0; offset <= value.size() - fragment.size(); ++offset)
  {
    bool equal = true;
    for (uint32_t index = 0; index < fragment.size(); ++index)
    {
      equal = equal && value[offset + index] == fragment[index];
    }
    if (equal)
    {
      return true;
    }
  }
  return false;
}

static bool hasHeader(const MultiCurlClient::Request& request,
                      const String& name,
                      const String& value)
{
  for (const MultiCurlClient::Header& header : request.headers)
  {
    if (header.name == name && header.value == value)
    {
      return true;
    }
  }
  return false;
}

static bool drive(CoroutineStack& stack,
                  ScriptedHttpClient& http,
                  ScriptedDelayQueue& delay,
                  uint32_t maximumSteps = 10'000)
{
  for (uint32_t step = 0; step < maximumSteps && stack.hasSuspendedCoroutines(); ++step)
  {
    if (http.completeOne() || delay.complete())
    {
      continue;
    }
    return false;
  }
  return stack.hasSuspendedCoroutines() == false && delay.pending == nullptr;
}

static GcpMachineProvisioningTransaction::Spec spec(const String& name)
{
  GcpMachineProvisioningTransaction::Spec value;
  value.name = name;
  value.body.snprintf<"{\"name\":\"{}\"}"_ctv>(name);
  return value;
}

static GcpMachineProvisioningTransaction transaction(ScriptedHttpClient& http,
                                                      ScriptedDelayQueue& delay,
                                                      MultiCurlClient::TimePoint deadline =
                                                          MultiCurlClient::Clock::now() + std::chrono::minutes(1))
{
  return {http.submission(),
          delay.submission(),
          "project /+"_ctv,
          "zone /+"_ctv,
          "secret"_ctv,
          deadline};
}

static void testBuildSpec(TestSuite& suite)
{
  GcpMachineProvisioningTransaction::Spec value;
  String failure;
  Vault::SSHKeyPackage hostKey;
  suite.expect(GcpMachineProvisioningTransaction::buildSpec(
                   "machine"_ctv,
                   "us-central1-a"_ctv,
                   "projects/images/image\""_ctv,
                   "c3-standard-4"_ctv,
                   "Intel Sapphire Rapids"_ctv,
                   UINT32_MAX,
                   true,
                   "cluster"_ctv,
                   "prodigy"_ctv,
                   {} /* bootstrap public key */,
                   hostKey,
                   value,
                   failure) && failure.empty(),
               "gcp_provisioning_builds_complete_spec_without_storage_overflow");
  suite.expect(contains(value.body, "\"diskSizeGb\":4194304"_ctv) &&
                   contains(value.body, "\"machineType\":\"zones/us-central1-a/machineTypes/c3-standard-4\""_ctv) &&
                   contains(value.body, "\"minCpuPlatform\":\"Intel Sapphire Rapids\""_ctv) &&
                   contains(value.body, "\"brain\":\"true\""_ctv) &&
                   contains(value.body, "projects/images/image\\\""_ctv),
               "gcp_provisioning_spec_has_exact_disk_machine_labels_and_json_escaping");
  simdjson::dom::parser parser;
  simdjson::dom::element document;
  String body = value.body;
  suite.expect(parser.parse(body.c_str(), body.size()).get(document) == simdjson::SUCCESS,
               "gcp_provisioning_complete_spec_is_valid_json");

  GcpMachineProvisioningTransaction::Spec bootstrap;
  suite.expect(GcpMachineProvisioningTransaction::buildSpec(
                   "bootstrap"_ctv,
                   "us-central1-a"_ctv,
                   "projects/images/image"_ctv,
                   "c3-standard-4"_ctv,
                   {} /* CPU platform */,
                   20 * 1024,
                   false,
                   {} /* cluster UUID */,
                   "prodigy"_ctv,
                   "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest prodigy"_ctv,
                   hostKey,
                   bootstrap,
                   failure),
               "gcp_provisioning_builds_bootstrap_metadata_spec");
  body = bootstrap.body;
  suite.expect(parser.parse(body.c_str(), body.size()).get(document) == simdjson::SUCCESS &&
                   contains(body, "\"key\":\"startup-script\""_ctv),
               "gcp_provisioning_startup_script_spec_is_valid_json");
}

static void testFanoutObservation(TestSuite& suite)
{
  ScriptedHttpClient http;
  http.add(MultiCurlClient::Status::success, 200, R"json({"name":"create-0"})json"_ctv, true);
  http.add(MultiCurlClient::Status::success, 200, R"json({"name":"create-1"})json"_ctv);
  http.add(MultiCurlClient::Status::success, 200, R"json({"id":"one"})json"_ctv, true);
  http.add(MultiCurlClient::Status::success, 404, {});
  http.add(MultiCurlClient::Status::success, 200, R"json({"status":"RUNNING"})json"_ctv, true);
  http.add(MultiCurlClient::Status::success, 200, R"json({"id":"two"})json"_ctv, true);
  ScriptedDelayQueue delay;
  CoroutineStack stack;
  Vector<GcpMachineProvisioningTransaction::Spec> specs;
  specs.push_back(spec("machine-0"_ctv));
  specs.push_back(spec("machine-1"_ctv));
  Vector<uint8_t> ready;
  ready.resize(2, 0);
  String failure;
  auto provisioning = transaction(http, delay);

  provisioning.run(&stack, "template /+"_ctv, specs,
                   [&](uint32_t index, const String& body, String&) -> bool {
                     ready[index] = contains(body, "\"id\""_ctv);
                     return ready[index];
                   },
                   failure);
  suite.expect(stack.hasSuspendedCoroutines() && http.requests.size() == 2,
               "gcp_provisioning_submits_all_creates_before_waiting");
  suite.expect(drive(stack, http, delay) && failure.empty() && ready[0] && ready[1],
               "gcp_provisioning_mixed_inline_deferred_fanout_reaches_ready");
  suite.expect(http.requests.size() == 6 &&
                   http.requests[0].method == MultiCurlClient::Method::post &&
                   http.requests[1].method == MultiCurlClient::Method::post &&
                   http.requests[2].method == MultiCurlClient::Method::get &&
                   http.requests[4].url ==
                       "https://compute.googleapis.com/compute/v1/projects/project%20%2F%2B/zones/zone%20%2F%2B/operations/create-1?fields=status,error,httpErrorStatusCode,httpErrorMessage,statusMessage"_ctv &&
                   delay.delays.size() == 1 &&
                   delay.delays[0] == GcpMachineProvisioningTransaction::pollDelayUs,
               "gcp_provisioning_observes_instances_and_operations_with_ring_delay");
  bool policy = true;
  for (const MultiCurlClient::Request& request : http.requests)
  {
    policy = policy && request.resolveHost == "compute.googleapis.com"_ctv &&
             request.originPolicy.requiredScheme == "https"_ctv &&
             request.originPolicy.requiredHost == "compute.googleapis.com"_ctv &&
             request.connectTimeout == std::chrono::seconds(3) &&
             request.responseBytes == GcpMachineProvisioningTransaction::responseBytes &&
             hasHeader(request, "Authorization"_ctv, "Bearer secret"_ctv);
  }
  suite.expect(policy && contains(http.requests[0].url, "template%20%2F%2B"_ctv),
               "gcp_provisioning_enforces_exact_origin_bounds_auth_and_encoding");
}

static void testCollisionCleanupOwnership(TestSuite& suite)
{
  ScriptedHttpClient http;
  http.add(MultiCurlClient::Status::success, 200, R"json({"name":"create-0"})json"_ctv, true);
  http.add(MultiCurlClient::Status::success, 409,
           R"json({"error":{"message":"already exists"}})json"_ctv, true);
  http.add(MultiCurlClient::Status::success, 200, R"json({"status":"RUNNING"})json"_ctv, true);
  http.add(MultiCurlClient::Status::success, 200,
           R"json({"status":"DONE","statusMessage":"create completed"})json"_ctv,
           true);
  http.add(MultiCurlClient::Status::success, 200, R"json({"name":"delete-0"})json"_ctv, true);
  http.add(MultiCurlClient::Status::success, 200,
           R"json({"status":"DONE","statusMessage":"delete completed"})json"_ctv,
           true);
  ScriptedDelayQueue delay;
  CoroutineStack stack;
  Vector<GcpMachineProvisioningTransaction::Spec> specs;
  specs.push_back(spec("owned"_ctv));
  specs.push_back(spec("foreign-collision"_ctv));
  String failure;
  auto provisioning = transaction(http, delay);
  provisioning.run(&stack, "template"_ctv, specs,
                   [](uint32_t, const String&, String&) -> bool { return false; },
                   failure);

  suite.expect(drive(stack, http, delay) && stack.hasSuspendedCoroutines() == false,
               "gcp_provisioning_collision_cleanup_completes_on_ring");
  suite.expect(failure == "already exists"_ctv,
               "gcp_provisioning_collision_preserves_original_failure_after_rollback");
  suite.expect(http.requests.size() == 6 &&
                   delay.delays.size() == 1 &&
                   http.requests[2].method == MultiCurlClient::Method::get &&
                   contains(http.requests[2].url, "/operations/create-0"_ctv),
               "gcp_provisioning_cleanup_waits_for_accepted_create_before_delete");
  suite.expect(http.requests[4].method == MultiCurlClient::Method::delete_ &&
                   contains(http.requests[4].url, "/instances/owned"_ctv) &&
                   !contains(http.requests[4].url, "foreign-collision"_ctv),
               "gcp_provisioning_never_deletes_rejected_name_collision");
}

static void testAdmissionAlignedWaves(TestSuite& suite)
{
  ScriptedHttpClient http;
  Vector<GcpMachineProvisioningTransaction::Spec> specs;
  specs.reserve(GcpMachineProvisioningTransaction::maximumMachines);
  for (uint32_t index = 0; index < GcpMachineProvisioningTransaction::maximumMachines; ++index)
  {
    String name;
    name.snprintf<"wave-{itoa}"_ctv>(index);
    specs.push_back(spec(name));
    String operation;
    operation.snprintf<"{\"name\":\"create-{itoa}\"}"_ctv>(index);
    http.add(MultiCurlClient::Status::success, 200, operation);
  }
  for (uint32_t index = 0; index < GcpMachineProvisioningTransaction::maximumMachines; ++index)
  {
    String instance;
    instance.snprintf<"{\"id\":\"{itoa}\"}"_ctv>(index);
    http.add(MultiCurlClient::Status::success, 200, instance);
  }

  ScriptedDelayQueue delay;
  CoroutineStack stack;
  String failure;
  auto provisioning = transaction(http, delay);
  provisioning.run(&stack, "template"_ctv, specs,
                   [](uint32_t, const String&, String&) -> bool { return true; },
                   failure);

  suite.expect(stack.hasSuspendedCoroutines() &&
                   http.requests.size() == GcpMachineProvisioningTransaction::maximumRequestsPerWave,
               "gcp_provisioning_submits_only_one_admission_capacity_wave_before_waiting");
  suite.expect(drive(stack, http, delay) && failure.empty() &&
                   http.requests.size() == 2 * GcpMachineProvisioningTransaction::maximumMachines,
               "gcp_provisioning_completes_full_256_machine_create_and_observation");
  suite.expect(http.maximumActive == GcpMachineProvisioningTransaction::maximumRequestsPerWave &&
                   http.active == 0,
               "gcp_provisioning_never_exceeds_shared_admission_capacity");
  suite.expect(http.requests[GcpMachineProvisioningTransaction::maximumRequestsPerWave].overallDeadline >=
                   http.requests[0].overallDeadline &&
                   http.requests[3 * GcpMachineProvisioningTransaction::maximumRequestsPerWave].overallDeadline >=
                       http.requests[2 * GcpMachineProvisioningTransaction::maximumRequestsPerWave].overallDeadline,
               "gcp_provisioning_assigns_each_wave_a_fresh_bounded_transfer_deadline");
}

static void testAmbiguousAndPreflightFailures(TestSuite& suite)
{
  ScriptedHttpClient ambiguousHttp;
  ambiguousHttp.add(MultiCurlClient::Status::transportFailure, 0, {}, true);
  ScriptedDelayQueue ambiguousDelay;
  CoroutineStack ambiguousStack;
  Vector<GcpMachineProvisioningTransaction::Spec> specs;
  specs.push_back(spec("ambiguous"_ctv));
  String failure;
  auto ambiguous = transaction(ambiguousHttp, ambiguousDelay);
  ambiguous.run(&ambiguousStack, "template"_ctv, specs,
                [](uint32_t, const String&, String&) -> bool { return false; },
                failure);
  suite.expect(failure ==
                   "gcp provisioning create transport failed; gcp provisioning cloud state may be partial for: ambiguous"_ctv &&
                   ambiguousHttp.requests.size() == 1,
               "gcp_provisioning_reports_ambiguous_create_without_unsafe_delete");

  ScriptedHttpClient invalidHttp;
  ScriptedDelayQueue invalidDelay;
  CoroutineStack invalidStack;
  specs.push_back(spec("ambiguous"_ctv));
  auto invalid = transaction(invalidHttp, invalidDelay);
  invalid.run(&invalidStack, "template"_ctv, specs,
              [](uint32_t, const String&, String&) -> bool { return false; },
              failure);
  suite.expect(failure == "gcp provisioning contains invalid or duplicate spec"_ctv &&
                   invalidHttp.requests.empty(),
               "gcp_provisioning_rejects_duplicate_specs_before_mutation");

  ScriptedHttpClient deadlineHttp;
  ScriptedDelayQueue deadlineDelay;
  CoroutineStack deadlineStack;
  specs.resize(1);
  auto expired = transaction(deadlineHttp, deadlineDelay, MultiCurlClient::Clock::now());
  expired.run(&deadlineStack, "template"_ctv, specs,
              [](uint32_t, const String&, String&) -> bool { return false; },
              failure);
  suite.expect(failure == "gcp provisioning deadline exceeded"_ctv && deadlineHttp.requests.empty(),
               "gcp_provisioning_rejects_expired_transaction_before_mutation");

  ScriptedHttpClient cappedHttp;
  cappedHttp.add(MultiCurlClient::Status::responseTooLarge, 0, {}, true);
  ScriptedDelayQueue cappedDelay;
  CoroutineStack cappedStack;
  auto capped = transaction(cappedHttp, cappedDelay);
  capped.run(&cappedStack, "template"_ctv, specs,
             [](uint32_t, const String&, String&) -> bool { return false; },
             failure);
  suite.expect(failure ==
                   "gcp provisioning response exceeds 1 MiB; gcp provisioning cloud state may be partial for: ambiguous"_ctv,
               "gcp_provisioning_reports_oversize_mutation_as_partial_cloud_state");
}

static void testOperationAndCleanupFailures(TestSuite& suite)
{
  Vector<GcpMachineProvisioningTransaction::Spec> one;
  one.push_back(spec("owned"_ctv));

  ScriptedHttpClient malformedHttp;
  malformedHttp.add(MultiCurlClient::Status::success, 200, R"json({"name":"create"})json"_ctv, true);
  malformedHttp.add(MultiCurlClient::Status::success, 404, {}, true);
  malformedHttp.add(MultiCurlClient::Status::success, 200, R"json({})json"_ctv, true);
  malformedHttp.add(MultiCurlClient::Status::success, 200, R"json({"status":"DONE"})json"_ctv, true);
  malformedHttp.add(MultiCurlClient::Status::success, 404, {}, true);
  ScriptedDelayQueue malformedDelay;
  CoroutineStack malformedStack;
  String failure;
  auto malformed = transaction(malformedHttp, malformedDelay);
  malformed.run(&malformedStack, "template"_ctv, one,
                [](uint32_t, const String&, String&) -> bool { return false; },
                failure);
  suite.expect(failure == "gcp compute operation poll response missing status"_ctv &&
                   malformedHttp.requests.size() == 5 &&
                   malformedHttp.requests.back().method == MultiCurlClient::Method::delete_,
               "gcp_provisioning_preserves_malformed_operation_failure_and_rolls_back");

  ScriptedHttpClient failedHttp;
  failedHttp.add(MultiCurlClient::Status::success, 200, R"json({"name":"create"})json"_ctv, true);
  failedHttp.add(MultiCurlClient::Status::success, 404, {}, true);
  failedHttp.add(MultiCurlClient::Status::success, 200,
                 R"json({"status":"DONE","error":{"errors":[{"message":"create failed"}]}})json"_ctv,
                 true);
  failedHttp.add(MultiCurlClient::Status::success, 200, R"json({"status":"DONE"})json"_ctv, true);
  failedHttp.add(MultiCurlClient::Status::success, 404, {}, true);
  ScriptedDelayQueue failedDelay;
  CoroutineStack failedStack;
  auto failed = transaction(failedHttp, failedDelay);
  failed.run(&failedStack, "template"_ctv, one,
             [](uint32_t, const String&, String&) -> bool { return false; },
             failure);
  suite.expect(failure == "create failed"_ctv,
               "gcp_provisioning_preserves_terminal_operation_error_through_rollback");

  ScriptedHttpClient delete404Http;
  delete404Http.add(MultiCurlClient::Status::success, 200, R"json({"name":"create"})json"_ctv, true);
  delete404Http.add(MultiCurlClient::Status::success, 409,
                    R"json({"error":{"message":"collision"}})json"_ctv, true);
  delete404Http.add(MultiCurlClient::Status::success, 200, R"json({"status":"DONE"})json"_ctv, true);
  delete404Http.add(MultiCurlClient::Status::success, 404, {}, true);
  ScriptedDelayQueue delete404Delay;
  CoroutineStack delete404Stack;
  Vector<GcpMachineProvisioningTransaction::Spec> collision;
  collision.push_back(spec("owned"_ctv));
  collision.push_back(spec("foreign"_ctv));
  auto delete404 = transaction(delete404Http, delete404Delay);
  delete404.run(&delete404Stack, "template"_ctv, collision,
                [](uint32_t, const String&, String&) -> bool { return false; },
                failure);
  suite.expect(failure == "collision"_ctv && delete404Http.requests.size() == 4,
               "gcp_provisioning_accepts_cleanup_delete_404_as_confirmed_absence");

  ScriptedHttpClient deleteFailureHttp;
  deleteFailureHttp.add(MultiCurlClient::Status::success, 200, R"json({"name":"create"})json"_ctv, true);
  deleteFailureHttp.add(MultiCurlClient::Status::success, 409,
                        R"json({"error":{"message":"collision"}})json"_ctv, true);
  deleteFailureHttp.add(MultiCurlClient::Status::success, 200, R"json({"status":"DONE"})json"_ctv, true);
  deleteFailureHttp.add(MultiCurlClient::Status::transportFailure, 0, {}, true);
  deleteFailureHttp.add(MultiCurlClient::Status::success, 200, R"json({"id":"still-present"})json"_ctv, true);
  ScriptedDelayQueue deleteFailureDelay;
  CoroutineStack deleteFailureStack;
  auto deleteFailure = transaction(deleteFailureHttp, deleteFailureDelay);
  deleteFailure.run(&deleteFailureStack, "template"_ctv, collision,
                    [](uint32_t, const String&, String&) -> bool { return false; },
                    failure);
  suite.expect(failure ==
                   "collision; gcp provisioning cloud state may be partial for: owned"_ctv,
               "gcp_provisioning_reports_cleanup_delete_failure_as_partial_cloud_state");
}

int main(void)
{
  TestSuite suite;
  testBuildSpec(suite);
  testFanoutObservation(suite);
  testAdmissionAlignedWaves(suite);
  testCollisionCleanupOwnership(suite);
  testAmbiguousAndPreflightFailures(suite);
  testOperationAndCleanupFailures(suite);
  return suite.failed == 0 ? 0 : 1;
}
