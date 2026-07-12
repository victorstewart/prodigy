#include <networking/includes.h>
#include <prodigy/iaas/gcp/gcp.labels.h>
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
    const Operation::Ticket ticket {uint64_t(index) + 1, 37};
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
        Operation::Result result = this->result(index);
        callbacks[index].function(callbacks[index].context, tickets[index], std::move(result));
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

static GcpInstanceLabelsTransaction transaction(ScriptedHttpClient& http,
                                                ScriptedDelayQueue& delay)
{
  return {http.submission(),
          delay.submission(),
          "project /+"_ctv,
          "zone /+"_ctv,
          "secret"_ctv,
          MultiCurlClient::Clock::now() + std::chrono::minutes(1)};
}

static bool exactMergedBody(const String& body,
                            const String& fingerprint,
                            const String& keep,
                            const String& clusterUUID)
{
  simdjson::dom::parser parser;
  simdjson::dom::element document;
  String text = body;
  if (parser.parse(text.c_str(), text.size()).get(document))
  {
    return false;
  }
  String parsedFingerprint;
  String parsedKeep;
  String app;
  String cluster;
  return prodigyJSONString(document["labelFingerprint"], parsedFingerprint) == simdjson::SUCCESS &&
         prodigyJSONString(document["labels"]["keep"], parsedKeep) == simdjson::SUCCESS &&
         prodigyJSONString(document["labels"]["app"], app) == simdjson::SUCCESS &&
         prodigyJSONString(document["labels"]["prodigy_cluster_uuid"], cluster) == simdjson::SUCCESS &&
         parsedFingerprint == fingerprint && parsedKeep == keep && app == "prodigy"_ctv &&
         cluster == clusterUUID;
}

static void testMergeAndPoll(TestSuite& suite)
{
  ScriptedHttpClient http;
  http.add(MultiCurlClient::Status::success, 200,
           R"json({"items":[{"id":"123","name":"machine /+"}]})json"_ctv,
           true);
  http.add(MultiCurlClient::Status::success, 200,
           R"json({"id":"123","labelFingerprint":"fp /+","labels":{"keep":"yes","app":"old","prodigy_cluster_uuid":"old"}})json"_ctv);
  http.add(MultiCurlClient::Status::success, 200, R"json({"name":"labels-op"})json"_ctv, true);
  http.add(MultiCurlClient::Status::success, 200, R"json({"status":"RUNNING"})json"_ctv, true);
  http.add(MultiCurlClient::Status::success, 200, R"json({"status":"DONE"})json"_ctv, true);
  ScriptedDelayQueue delay;
  CoroutineStack stack;
  String failure;
  auto labels = transaction(http, delay);

  labels.run(&stack, "123"_ctv, "123abc"_ctv, failure);
  suite.expect(stack.hasSuspendedCoroutines() && http.requests.size() == 2,
               "gcp_labels_suspends_across_deferred_instance_fetch");
  suite.expect(drive(stack, http, delay) && failure.empty(),
               "gcp_labels_merge_reaches_terminal_operation_success");
  suite.expect(http.requests.size() == 5 &&
                   http.requests[2].method == MultiCurlClient::Method::post &&
                   http.requests[2].url ==
                       "https://compute.googleapis.com/compute/v1/projects/project%20%2F%2B/zones/zone%20%2F%2B/instances/machine%20%2F%2B/setLabels"_ctv &&
                   exactMergedBody(http.requests[2].body, "fp /+"_ctv, "yes"_ctv, "123abc"_ctv) &&
                   hasHeader(http.requests[2], "Content-Type"_ctv, "application/json"_ctv) &&
                   hasHeader(http.requests[2], "Authorization"_ctv, "Bearer secret"_ctv) &&
                   delay.delays.size() == 1 && delay.delays[0] == GcpComputeTransaction::pollDelayUs,
               "gcp_labels_preserves_unrelated_labels_and_uses_exact_bounded_request");
}

static void testNoop(TestSuite& suite)
{
  ScriptedHttpClient http;
  http.add(MultiCurlClient::Status::success, 200,
           R"json({"items":[{"id":"123","name":"machine"}]})json"_ctv,
           true);
  http.add(MultiCurlClient::Status::success, 200,
           R"json({"id":"123","labelFingerprint":"fp","labels":{"app":"prodigy","prodigy_cluster_uuid":"abc123","keep":"yes"}})json"_ctv,
           true);
  ScriptedDelayQueue delay;
  CoroutineStack stack;
  String failure;
  auto labels = transaction(http, delay);
  labels.run(&stack, "123"_ctv, "abc123"_ctv, failure);
  suite.expect(failure.empty() && http.requests.size() == 2 && delay.delays.empty(),
               "gcp_labels_noop_avoids_mutation_when_both_labels_match");
}

static void testFingerprintRetry(TestSuite& suite)
{
  ScriptedHttpClient http;
  http.add(MultiCurlClient::Status::success, 200,
           R"json({"items":[{"id":"123","name":"machine"}]})json"_ctv,
           true);
  http.add(MultiCurlClient::Status::success, 200,
           R"json({"id":"123","labelFingerprint":"fp1","labels":{"keep":"one"}})json"_ctv,
           true);
  http.add(MultiCurlClient::Status::success, 412,
           R"json({"error":{"message":"conditionNotMet"}})json"_ctv,
           true);
  http.add(MultiCurlClient::Status::success, 200,
           R"json({"id":"123","labelFingerprint":"fp2","labels":{"keep":"two","concurrent":"preserved"}})json"_ctv,
           true);
  http.add(MultiCurlClient::Status::success, 200, R"json({"name":"labels-op"})json"_ctv, true);
  http.add(MultiCurlClient::Status::success, 200, R"json({"status":"DONE"})json"_ctv, true);
  ScriptedDelayQueue delay;
  CoroutineStack stack;
  String failure;
  auto labels = transaction(http, delay);
  labels.run(&stack, "123"_ctv, "abc123"_ctv, failure);
  suite.expect(stack.hasSuspendedCoroutines() && drive(stack, http, delay) && failure.empty() &&
                   http.requests.size() == 6 && delay.delays.size() == 1 &&
                   exactMergedBody(http.requests[4].body, "fp2"_ctv, "two"_ctv, "abc123"_ctv),
               "gcp_labels_refetches_and_remerges_after_fingerprint_conflict");

  simdjson::dom::parser parser;
  simdjson::dom::element body;
  String text = http.requests[4].body;
  String concurrent;
  suite.expect(parser.parse(text.c_str(), text.size()).get(body) == simdjson::SUCCESS &&
                   prodigyJSONString(body["labels"]["concurrent"], concurrent) == simdjson::SUCCESS &&
                   concurrent == "preserved"_ctv,
               "gcp_labels_retry_preserves_concurrent_unrelated_label");
}

static void testFailures(TestSuite& suite)
{
  ScriptedHttpClient expiredHttp;
  ScriptedDelayQueue expiredDelay;
  CoroutineStack expiredStack;
  String failure;
  GcpInstanceLabelsTransaction expired(expiredHttp.submission(),
                                       expiredDelay.submission(),
                                       "project"_ctv,
                                       "zone"_ctv,
                                       "token"_ctv,
                                       MultiCurlClient::Clock::now());
  expired.run(&expiredStack, "123"_ctv, "abc123"_ctv, failure);
  suite.expect(failure == "gcp instance labels deadline exceeded"_ctv && expiredHttp.requests.empty(),
               "gcp_labels_rejects_expired_deadline_before_request");

  ScriptedHttpClient invalidHttp;
  ScriptedDelayQueue invalidDelay;
  CoroutineStack invalidStack;
  auto invalid = transaction(invalidHttp, invalidDelay);
  invalid.run(&invalidStack, "123"_ctv, "INVALID"_ctv, failure);
  suite.expect(failure == "gcp instance labels require cloudID and valid cluster UUID label"_ctv &&
                   invalidHttp.requests.empty(),
               "gcp_labels_rejects_invalid_input_before_request");

  ScriptedHttpClient changedHttp;
  changedHttp.add(MultiCurlClient::Status::success, 200,
                  R"json({"items":[{"id":"123","name":"machine"}]})json"_ctv,
                  true);
  changedHttp.add(MultiCurlClient::Status::success, 200,
                  R"json({"id":"replacement","labelFingerprint":"fp","labels":{}})json"_ctv,
                  true);
  ScriptedDelayQueue changedDelay;
  CoroutineStack changedStack;
  auto changed = transaction(changedHttp, changedDelay);
  changed.run(&changedStack, "123"_ctv, "abc123"_ctv, failure);
  suite.expect(failure == "gcp instance labels target identity changed before mutation"_ctv &&
                   changedHttp.requests.size() == 2,
               "gcp_labels_revalidates_cloud_identity_before_mutation");

  ScriptedHttpClient ambiguousHttp;
  ambiguousHttp.add(MultiCurlClient::Status::success, 200,
                    R"json({"items":[{"id":"123","name":"machine"}]})json"_ctv,
                    true);
  ambiguousHttp.add(MultiCurlClient::Status::success, 200,
                    R"json({"id":"123","labelFingerprint":"fp","labels":{}})json"_ctv,
                    true);
  ambiguousHttp.add(MultiCurlClient::Status::transportFailure, 0, {}, true);
  ScriptedDelayQueue ambiguousDelay;
  CoroutineStack ambiguousStack;
  auto ambiguous = transaction(ambiguousHttp, ambiguousDelay);
  ambiguous.run(&ambiguousStack, "123"_ctv, "abc123"_ctv, failure);
  suite.expect(failure ==
                   "gcp instance labels mutation transport failed; gcp compute cloud state may be partial for: machine"_ctv,
               "gcp_labels_reports_ambiguous_mutation_state");

  ScriptedHttpClient operationHttp;
  operationHttp.add(MultiCurlClient::Status::success, 200,
                    R"json({"items":[{"id":"123","name":"machine"}]})json"_ctv,
                    true);
  operationHttp.add(MultiCurlClient::Status::success, 200,
                    R"json({"id":"123","labelFingerprint":"fp","labels":{}})json"_ctv,
                    true);
  operationHttp.add(MultiCurlClient::Status::success, 200, R"json({"name":"labels-op"})json"_ctv, true);
  operationHttp.add(MultiCurlClient::Status::success, 200,
                    R"json({"status":"DONE","error":{"errors":[{"message":"denied"}]}})json"_ctv,
                    true);
  ScriptedDelayQueue operationDelay;
  CoroutineStack operationStack;
  auto operation = transaction(operationHttp, operationDelay);
  operation.run(&operationStack, "123"_ctv, "abc123"_ctv, failure);
  suite.expect(failure == "denied"_ctv,
               "gcp_labels_surfaces_terminal_operation_error_without_optional_field_exception");
}

int main(void)
{
  TestSuite suite;
  testMergeAndPoll(suite);
  testNoop(suite);
  testFingerprintRetry(suite);
  testFailures(suite);
  return suite.failed == 0 ? 0 : 1;
}
