#include <networking/includes.h>
#include <prodigy/iaas/gcp/gcp.lifecycle.h>
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
      ++failed;
    }
  }
};

class ScriptedHttpClient
{
public:

  using Operation = ProdigyHostHttpOperation;

  class Response
  {
  public:

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

  static Operation::Ticket submit(void *context,
                                  Operation::Request&& request,
                                  Operation::Callback callback)
  {
    ScriptedHttpClient& client = *static_cast<ScriptedHttpClient *>(context);
    const uint32_t index = client.nextResponse++;
    client.requests.push_back(std::move(request));
    if (index >= client.responses.size())
    {
      return {};
    }
    const Operation::Ticket ticket {uint64_t(index) + 1, 31};
    client.callbacks.push_back(callback);
    client.tickets.push_back(ticket);
    client.pending.push_back(1);
    if (client.responses[index].inlineCompletion)
    {
      client.pending.back() = 0;
      Operation::Result result = client.result(index);
      callback.function(callback.context, ticket, std::move(result));
    }
    return ticket;
  }

  static bool cancel(void *context, Operation::Ticket ticket)
  {
    ScriptedHttpClient& client = *static_cast<ScriptedHttpClient *>(context);
    for (uint32_t index = 0; index < client.tickets.size(); ++index)
    {
      if (client.pending[index] && client.tickets[index].identifier == ticket.identifier &&
          client.tickets[index].generation == ticket.generation)
      {
        client.pending[index] = 0;
        Operation::Result result;
        result.status = MultiCurlClient::Status::canceled;
        client.callbacks[index].function(client.callbacks[index].context, ticket, std::move(result));
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
        Operation::Result completed = result(index);
        callbacks[index].function(callbacks[index].context, tickets[index], std::move(completed));
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
    ScriptedDelayQueue& owner = *static_cast<ScriptedDelayQueue *>(context);
    owner.pending = packet;
    owner.delays.push_back(uint64_t(packet->timeout.tv_sec) * 1'000'000 +
                           uint64_t(packet->timeout.tv_nsec) / 1000);
  }

  static void cancel(void *context, TimeoutPacket *packet)
  {
    ScriptedDelayQueue& owner = *static_cast<ScriptedDelayQueue *>(context);
    if (owner.pending == packet)
    {
      owner.pending = nullptr;
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
  for (uint64_t offset = 0; offset <= value.size() - fragment.size(); ++offset)
  {
    bool equal = true;
    for (uint64_t index = 0; index < fragment.size(); ++index)
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

static GcpMachineLifecycleTransaction transaction(ScriptedHttpClient& http,
                                                   ScriptedDelayQueue& delay)
{
  return {http.submission(),
          delay.submission(),
          "project /+"_ctv,
          "zone /+"_ctv,
          "secret"_ctv,
          MultiCurlClient::Clock::now() + std::chrono::minutes(1)};
}

static void testReset(TestSuite& suite)
{
  ScriptedHttpClient http;
  http.add(MultiCurlClient::Status::success, 200,
           R"json({"items":[{"id":"123","name":"machine /+"}]})json"_ctv);
  http.add(MultiCurlClient::Status::success, 200, R"json({"id":"123"})json"_ctv, true);
  http.add(MultiCurlClient::Status::success, 200, R"json({"name":"reset-op"})json"_ctv, true);
  http.add(MultiCurlClient::Status::success, 200, R"json({"status":"RUNNING"})json"_ctv, true);
  http.add(MultiCurlClient::Status::success, 200,
           R"json({"status":"DONE","statusMessage":"reset completed"})json"_ctv,
           true);
  ScriptedDelayQueue delay;
  CoroutineStack stack;
  String failure;
  auto lifecycle = transaction(http, delay);

  lifecycle.run(&stack, GcpMachineLifecycleTransaction::Action::reset, "123"_ctv, failure);
  suite.expect(stack.hasSuspendedCoroutines() && http.requests.size() == 1,
               "gcp_lifecycle_reset_suspends_across_filtered_identity_request");
  suite.expect(drive(stack, http, delay) && failure.empty(),
               "gcp_lifecycle_reset_completes_after_operation_done");
  suite.expect(http.requests.size() == 5 &&
                   contains(http.requests[0].url, "maxResults=2&filter=id%3D123"_ctv) &&
                   http.requests[2].method == MultiCurlClient::Method::post &&
                   http.requests[2].url ==
                       "https://compute.googleapis.com/compute/v1/projects/project%20%2F%2B/zones/zone%20%2F%2B/instances/machine%20%2F%2B/reset"_ctv &&
                   delay.delays.size() == 1 &&
                   delay.delays[0] == GcpMachineLifecycleTransaction::pollDelayUs,
               "gcp_lifecycle_reset_uses_exact_id_filter_encoded_target_and_ring_poll_delay");

  bool exactPolicy = true;
  for (const MultiCurlClient::Request& request : http.requests)
  {
    exactPolicy = exactPolicy && request.resolveHost == "compute.googleapis.com"_ctv &&
                  request.authority == "compute.googleapis.com"_ctv &&
                  request.requireTls && request.caSource == MultiCurlClient::CaSource::system &&
                  request.connectTimeout == std::chrono::seconds(3) &&
                  request.responseBytes == GcpMachineLifecycleTransaction::responseBytes &&
                  hasHeader(request, "Authorization"_ctv, "Bearer secret"_ctv) &&
                  request.originPolicy.requiredHost == "compute.googleapis.com"_ctv;
  }
  suite.expect(exactPolicy, "gcp_lifecycle_requests_enforce_exact_origin_tls_auth_and_bounds");
}

static void testDestroy(TestSuite& suite)
{
  ScriptedHttpClient http;
  http.add(MultiCurlClient::Status::success, 200,
           R"json({"items":[{"id":"123","name":"machine"}]})json"_ctv,
           true);
  http.add(MultiCurlClient::Status::success, 200, R"json({"id":"123"})json"_ctv, true);
  http.add(MultiCurlClient::Status::success, 200, R"json({"name":"delete-op"})json"_ctv, true);
  http.add(MultiCurlClient::Status::success, 200, R"json({"status":"DONE"})json"_ctv, true);
  http.add(MultiCurlClient::Status::success, 200, R"json({"id":"123"})json"_ctv, true);
  http.add(MultiCurlClient::Status::success, 404, {}, true);
  ScriptedDelayQueue delay;
  CoroutineStack stack;
  String failure;
  auto lifecycle = transaction(http, delay);

  lifecycle.run(&stack, GcpMachineLifecycleTransaction::Action::destroy, "123"_ctv, failure);
  suite.expect(stack.hasSuspendedCoroutines(), "gcp_lifecycle_destroy_waits_for_visibility");
  suite.expect(drive(stack, http, delay) && failure.empty() && http.requests.size() == 6 &&
                   http.requests[2].method == MultiCurlClient::Method::delete_ &&
                   delay.delays.size() == 1,
               "gcp_lifecycle_destroy_polls_operation_and_verifies_absence");
}

static void testIdempotenceAndIdentity(TestSuite& suite)
{
  ScriptedHttpClient absentHttp;
  absentHttp.add(MultiCurlClient::Status::success, 200, "{}"_ctv, true);
  ScriptedDelayQueue absentDelay;
  CoroutineStack absentStack;
  String failure;
  auto absent = transaction(absentHttp, absentDelay);
  absent.run(&absentStack, GcpMachineLifecycleTransaction::Action::destroy, "123"_ctv, failure);
  suite.expect(failure.empty() && absentHttp.requests.size() == 1,
               "gcp_lifecycle_destroy_missing_target_is_idempotent_success");

  ScriptedHttpClient resetHttp;
  resetHttp.add(MultiCurlClient::Status::success, 200, "{}"_ctv, true);
  ScriptedDelayQueue resetDelay;
  CoroutineStack resetStack;
  auto reset = transaction(resetHttp, resetDelay);
  reset.run(&resetStack, GcpMachineLifecycleTransaction::Action::reset, "123"_ctv, failure);
  suite.expect(failure == "gcp machine lifecycle target not found"_ctv && resetHttp.requests.size() == 1,
               "gcp_lifecycle_reset_missing_target_fails_without_mutation");

  ScriptedHttpClient changedHttp;
  changedHttp.add(MultiCurlClient::Status::success, 200,
                  R"json({"items":[{"id":"123","name":"machine"}]})json"_ctv,
                  true);
  changedHttp.add(MultiCurlClient::Status::success, 200, R"json({"id":"456"})json"_ctv, true);
  ScriptedDelayQueue changedDelay;
  CoroutineStack changedStack;
  auto changed = transaction(changedHttp, changedDelay);
  changed.run(&changedStack, GcpMachineLifecycleTransaction::Action::destroy, "123"_ctv, failure);
  suite.expect(failure == "gcp machine lifecycle target identity changed before mutation"_ctv &&
                   changedHttp.requests.size() == 2,
               "gcp_lifecycle_revalidates_identity_before_mutation");
}

static void testFailureContracts(TestSuite& suite)
{
  ScriptedHttpClient ambiguousHttp;
  ambiguousHttp.add(MultiCurlClient::Status::success, 200,
                    R"json({"items":[{"id":"123","name":"machine"}]})json"_ctv,
                    true);
  ambiguousHttp.add(MultiCurlClient::Status::success, 200, R"json({"id":"123"})json"_ctv, true);
  ambiguousHttp.add(MultiCurlClient::Status::transportFailure, 0, {}, true);
  ScriptedDelayQueue ambiguousDelay;
  CoroutineStack ambiguousStack;
  String failure;
  auto ambiguous = transaction(ambiguousHttp, ambiguousDelay);
  ambiguous.run(&ambiguousStack, GcpMachineLifecycleTransaction::Action::reset, "123"_ctv, failure);
  suite.expect(failure ==
                   "gcp machine reset transport failed; gcp machine lifecycle cloud state may be partial for: machine"_ctv,
               "gcp_lifecycle_reports_ambiguous_mutation_state");

  ScriptedHttpClient operationHttp;
  operationHttp.add(MultiCurlClient::Status::success, 200,
                    R"json({"items":[{"id":"123","name":"machine"}]})json"_ctv,
                    true);
  operationHttp.add(MultiCurlClient::Status::success, 200, R"json({"id":"123"})json"_ctv, true);
  operationHttp.add(MultiCurlClient::Status::success, 200, R"json({"name":"reset-op"})json"_ctv, true);
  operationHttp.add(MultiCurlClient::Status::success, 200,
                    R"json({"status":"DONE","error":{"errors":[{"message":"quota"}]}})json"_ctv,
                    true);
  ScriptedDelayQueue operationDelay;
  CoroutineStack operationStack;
  auto operation = transaction(operationHttp, operationDelay);
  operation.run(&operationStack, GcpMachineLifecycleTransaction::Action::reset, "123"_ctv, failure);
  suite.expect(failure == "quota"_ctv,
               "gcp_lifecycle_surfaces_terminal_operation_error_without_optional_field_exception");

  ScriptedHttpClient malformedHttp;
  malformedHttp.add(MultiCurlClient::Status::success, 200,
                    R"json({"nextPageToken":7})json"_ctv,
                    true);
  ScriptedDelayQueue malformedDelay;
  CoroutineStack malformedStack;
  auto malformed = transaction(malformedHttp, malformedDelay);
  malformed.run(&malformedStack, GcpMachineLifecycleTransaction::Action::destroy, "123"_ctv, failure);
  suite.expect(failure == "gcp compute instance list page token malformed"_ctv &&
                   malformedHttp.requests.size() == 1,
               "gcp_lifecycle_fails_closed_on_malformed_filtered_inventory");

  ScriptedHttpClient nonObjectHttp;
  nonObjectHttp.add(MultiCurlClient::Status::success, 200, "[]"_ctv, true);
  ScriptedDelayQueue nonObjectDelay;
  CoroutineStack nonObjectStack;
  auto nonObject = transaction(nonObjectHttp, nonObjectDelay);
  nonObject.run(&nonObjectStack, GcpMachineLifecycleTransaction::Action::destroy, "123"_ctv, failure);
  suite.expect(failure == "gcp compute instance list response parse failed"_ctv,
               "gcp_lifecycle_fails_closed_on_non_object_filtered_inventory");

  ScriptedHttpClient duplicateHttp;
  duplicateHttp.add(MultiCurlClient::Status::success, 200,
                    R"json({"items":[{"id":"123","name":"one"},{"id":"123","name":"two"}]})json"_ctv,
                    true);
  ScriptedDelayQueue duplicateDelay;
  CoroutineStack duplicateStack;
  auto duplicate = transaction(duplicateHttp, duplicateDelay);
  duplicate.run(&duplicateStack, GcpMachineLifecycleTransaction::Action::destroy, "123"_ctv, failure);
  suite.expect(failure == "gcp compute cloud id resolves to multiple instances"_ctv,
               "gcp_lifecycle_rejects_ambiguous_filtered_identity");

  ScriptedHttpClient invalidIDHttp;
  ScriptedDelayQueue invalidIDDelay;
  CoroutineStack invalidIDStack;
  auto invalidID = transaction(invalidIDHttp, invalidIDDelay);
  invalidID.run(&invalidIDStack, GcpMachineLifecycleTransaction::Action::destroy, "not-numeric"_ctv, failure);
  suite.expect(failure == "gcp compute instance id must be a decimal uint64"_ctv &&
                   invalidIDHttp.requests.empty(),
               "gcp_lifecycle_rejects_non_numeric_cloud_id_before_request");
}

int main(void)
{
  TestSuite suite;
  testReset(suite);
  testDestroy(suite);
  testIdempotenceAndIdentity(suite);
  testFailureContracts(suite);
  return suite.failed == 0 ? 0 : 1;
}
