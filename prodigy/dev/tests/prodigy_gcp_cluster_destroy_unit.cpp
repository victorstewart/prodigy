#include <networking/includes.h>
#include <prodigy/iaas/gcp/gcp.cluster.destroy.h>
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
  uint32_t active = 0;
  uint32_t maximumActive = 0;

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
    const Operation::Ticket ticket {uint64_t(index) + 1, 41};
    client.callbacks.push_back(callback);
    client.tickets.push_back(ticket);
    client.pending.push_back(1);
    ++client.active;
    client.maximumActive = std::max(client.maximumActive, client.active);
    if (client.responses[index].inlineCompletion)
    {
      client.pending.back() = 0;
      --client.active;
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
        --client.active;
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

static bool drive(CoroutineStack& stack,
                  ScriptedHttpClient& http,
                  ScriptedDelayQueue& delay,
                  uint32_t maximumSteps = 100'000)
{
  for (uint32_t step = 0; step < maximumSteps && stack.hasSuspendedCoroutines(); ++step)
  {
    if (http.completeOne() || delay.complete())
    {
      continue;
    }
    return false;
  }
  return stack.hasSuspendedCoroutines() == false && http.active == 0 && delay.pending == nullptr;
}

static GcpClusterDestroyTransaction transaction(ScriptedHttpClient& http,
                                                ScriptedDelayQueue& delay)
{
  return {http.submission(),
          delay.submission(),
          "project /+"_ctv,
          "zone /+"_ctv,
          "secret"_ctv,
          MultiCurlClient::Clock::now() + std::chrono::minutes(1)};
}

static String matchingList(uint32_t count, const String& clusterUUID)
{
  String body;
  body.assign("{\"items\":["_ctv);
  for (uint32_t index = 0; index < count; ++index)
  {
    if (index)
    {
      body.append(',');
    }
    body.snprintf_add<"{\"id\":\"{itoa}\",\"name\":\"machine-{itoa}\",\"labels\":{\"app\":\"prodigy\",\"prodigy_cluster_uuid\":\"{}\"}}"_ctv>(uint64_t(index) + 1000,
                                                                                                                                                      index,
                                                                                                                                                         clusterUUID);
  }
  body.append("]}"_ctv);
  return body;
}

static String ownership(uint32_t index, const String& clusterUUID)
{
  String body;
  body.snprintf<"{\"id\":\"{itoa}\",\"labels\":{\"app\":\"prodigy\",\"prodigy_cluster_uuid\":\"{}\"}}"_ctv>(uint64_t(index) + 1000,
                                                                                                                       clusterUUID);
  return body;
}

static void testAdmissionAlignedFanout(TestSuite& suite)
{
  constexpr uint32_t targets = GcpClusterDestroyTransaction::maximumRequestsPerWave + 1;
  ScriptedHttpClient http;
  http.add(MultiCurlClient::Status::success, 200, matchingList(targets, "abc123"_ctv), true);
  for (uint32_t offset = 0; offset < targets;
       offset += GcpClusterDestroyTransaction::maximumRequestsPerWave)
  {
    const uint32_t count = std::min<uint32_t>(
        GcpClusterDestroyTransaction::maximumRequestsPerWave,
        targets - offset);
    for (uint32_t index = 0; index < count; ++index)
    {
      http.add(MultiCurlClient::Status::success,
               200,
               ownership(offset + index, "abc123"_ctv));
    }
    for (uint32_t index = 0; index < count; ++index)
    {
      String operation;
      operation.snprintf<"{\"name\":\"delete-{itoa}\"}"_ctv>(offset + index);
      http.add(MultiCurlClient::Status::success, 200, operation);
    }
  }
  for (uint32_t index = 0; index < targets; ++index)
  {
    http.add(MultiCurlClient::Status::success, 200, "{\"status\":\"DONE\"}"_ctv);
  }
  for (uint32_t index = 0; index < targets; ++index)
  {
    http.add(MultiCurlClient::Status::success, 404, {});
  }
  ScriptedDelayQueue delay;
  CoroutineStack stack;
  uint32_t destroyed = 0;
  String failure;
  auto destroy = transaction(http, delay);

  destroy.run(&stack, "abc123"_ctv, destroyed, failure);
  suite.expect(stack.hasSuspendedCoroutines() &&
                   http.requests.size() == 1 + GcpClusterDestroyTransaction::maximumRequestsPerWave,
               "gcp_cluster_destroy_starts_one_admission_aligned_preflight_wave");
  suite.expect(drive(stack, http, delay) && failure.empty() && destroyed == targets,
               "gcp_cluster_destroy_confirms_every_target_absent");
  suite.expect(http.maximumActive == GcpClusterDestroyTransaction::maximumRequestsPerWave &&
                   http.requests.size() == 1 + 4 * targets,
               "gcp_cluster_destroy_never_exceeds_shared_admission_capacity");
  const uint32_t firstDelete = 1 + GcpClusterDestroyTransaction::maximumRequestsPerWave;
  const uint32_t secondPreflight = firstDelete +
      GcpClusterDestroyTransaction::maximumRequestsPerWave;
  suite.expect(http.requests[firstDelete].method == MultiCurlClient::Method::delete_ &&
                   contains(http.requests[firstDelete].url, "/instances/machine-0"_ctv) &&
                   http.requests[secondPreflight].method == MultiCurlClient::Method::get &&
                   contains(http.requests[secondPreflight].url, "/instances/machine-64"_ctv) &&
                   contains(http.requests.back().url, "fields=id,labels"_ctv),
               "gcp_cluster_destroy_preflights_and_deletes_each_wave_before_the_next");
}

static void testLaterWaveFailureSettlesEarlierMutations(TestSuite& suite)
{
  constexpr uint32_t settled = GcpClusterDestroyTransaction::maximumRequestsPerWave;
  constexpr uint32_t targets = settled + 1;
  ScriptedHttpClient http;
  http.add(MultiCurlClient::Status::success, 200, matchingList(targets, "abc123"_ctv), true);
  for (uint32_t index = 0; index < settled; ++index)
  {
    http.add(MultiCurlClient::Status::success, 200, ownership(index, "abc123"_ctv));
  }
  for (uint32_t index = 0; index < settled; ++index)
  {
    String operation;
    operation.snprintf<"{\"name\":\"delete-{itoa}\"}"_ctv>(index);
    http.add(MultiCurlClient::Status::success, 200, operation);
  }
  http.add(MultiCurlClient::Status::success, 500, {});
  for (uint32_t index = 0; index < settled; ++index)
  {
    http.add(MultiCurlClient::Status::success, 200, "{\"status\":\"DONE\"}"_ctv);
  }
  for (uint32_t index = 0; index < settled; ++index)
  {
    http.add(MultiCurlClient::Status::success, 404, {});
  }

  ScriptedDelayQueue delay;
  CoroutineStack stack;
  uint32_t destroyed = 0;
  String failure;
  auto destroy = transaction(http, delay);
  destroy.run(&stack, "abc123"_ctv, destroyed, failure);

  const bool completed = drive(stack, http, delay);
  uint32_t untouchedRequests = 0;
  for (const MultiCurlClient::Request& request : http.requests)
  {
    untouchedRequests += contains(request.url, "/instances/machine-64"_ctv);
  }
  suite.expect(completed && destroyed == settled &&
                   contains(failure, "ownership preflight failed with HTTP 500"_ctv) &&
                   contains(failure, "cloud state may be partial for: machine-64"_ctv),
               "gcp_cluster_destroy_settles_earlier_wave_after_later_preflight_failure");
  suite.expect(http.requests.size() == 2 + 4 * settled && untouchedRequests == 1 &&
                   delay.delays.empty(),
               "gcp_cluster_destroy_does_not_mutate_or_poll_untouched_later_wave");
}

static void testExactLabelsDeduplicationAndDelete404(TestSuite& suite)
{
  ScriptedHttpClient http;
  http.add(MultiCurlClient::Status::success,
           200,
           R"json({"items":[
             {"id":"foreign-app","name":"foreign-app","labels":{"app":"other","prodigy_cluster_uuid":"abc123"}},
             {"id":"foreign-cluster","name":"foreign-cluster","labels":{"app":"prodigy","prodigy_cluster_uuid":"other"}},
             {"id":"100","name":"owned","labels":{"app":"prodigy","prodigy_cluster_uuid":"abc123"}},
             {"id":"100","name":"owned","labels":{"app":"prodigy","prodigy_cluster_uuid":"abc123"}}
           ]})json"_ctv,
           true);
  http.add(MultiCurlClient::Status::success,
           200,
           R"json({"id":"100","labels":{"app":"prodigy","prodigy_cluster_uuid":"abc123"}})json"_ctv,
           true);
  http.add(MultiCurlClient::Status::success, 404, {}, true);
  ScriptedDelayQueue delay;
  CoroutineStack stack;
  uint32_t destroyed = 0;
  String failure;
  auto destroy = transaction(http, delay);

  destroy.run(&stack, "abc123"_ctv, destroyed, failure);
  suite.expect(failure.empty() && destroyed == 1 && http.requests.size() == 3,
               "gcp_cluster_destroy_matches_both_labels_deduplicates_and_accepts_delete_404");
  suite.expect(http.requests[2].method == MultiCurlClient::Method::delete_ &&
                   contains(http.requests[0].url,
                            "filter=%28labels.app%20%3D%20prodigy%29%20%28labels.prodigy_cluster_uuid%20%3D%20abc123%29"_ctv),
               "gcp_cluster_destroy_uses_server_filter_but_validates_exact_labels_locally");
}

static void testMalformedLabels(TestSuite& suite)
{
  ScriptedHttpClient discoveryHttp;
  discoveryHttp.add(MultiCurlClient::Status::success,
                    200,
                    R"json({"items":[{"id":"100","name":"owned","labels":[]}]})json"_ctv,
                    true);
  ScriptedDelayQueue discoveryDelay;
  CoroutineStack discoveryStack;
  uint32_t destroyed = 0;
  String failure;
  auto discovery = transaction(discoveryHttp, discoveryDelay);
  discovery.run(&discoveryStack, "abc123"_ctv, destroyed, failure);
  suite.expect(destroyed == 0 && discoveryHttp.requests.size() == 1 &&
                   failure == "gcp cluster destroy instance list labels malformed"_ctv,
               "gcp_cluster_destroy_rejects_malformed_discovery_labels");

  ScriptedHttpClient ownershipHttp;
  ownershipHttp.add(MultiCurlClient::Status::success,
                    200,
                    matchingList(1, "abc123"_ctv),
                    true);
  ownershipHttp.add(MultiCurlClient::Status::success,
                    200,
                    R"json({"id":"1000","labels":"malformed"})json"_ctv,
                    true);
  ScriptedDelayQueue ownershipDelay;
  CoroutineStack ownershipStack;
  auto ownershipTransaction = transaction(ownershipHttp, ownershipDelay);
  ownershipTransaction.run(&ownershipStack, "abc123"_ctv, destroyed, failure);
  suite.expect(destroyed == 0 && ownershipHttp.requests.size() == 2 &&
                   failure == "gcp cluster destroy instance ownership response malformed"_ctv,
               "gcp_cluster_destroy_rejects_malformed_preflight_labels_before_delete");
}

static void testCopiedLabelAndOperationPolling(TestSuite& suite)
{
  ScriptedHttpClient http;
  http.add(MultiCurlClient::Status::success, 200, matchingList(1, "abc123"_ctv), true);
  http.add(MultiCurlClient::Status::success, 200, ownership(0, "abc123"_ctv), true);
  http.add(MultiCurlClient::Status::success, 200, "{\"name\":\"delete\"}"_ctv, true);
  http.add(MultiCurlClient::Status::success, 200, "{\"status\":\"RUNNING\"}"_ctv, true);
  http.add(MultiCurlClient::Status::success,
           200,
           "{\"status\":\"DONE\",\"statusMessage\":\"completed normally\"}"_ctv,
           true);
  http.add(MultiCurlClient::Status::success, 404, {}, true);
  ScriptedDelayQueue delay;
  CoroutineStack stack;
  uint32_t destroyed = 0;
  String failure;
  String clusterUUID;
  clusterUUID.assign("abc123"_ctv);
  auto destroy = transaction(http, delay);

  destroy.run(&stack, clusterUUID, destroyed, failure);
  suite.expect(stack.hasSuspendedCoroutines() && delay.pending != nullptr,
               "gcp_cluster_destroy_waits_on_ring_for_pending_operation");
  clusterUUID.assign("changed"_ctv);
  suite.expect(drive(stack, http, delay) && failure.empty() && destroyed == 1 &&
                   delay.delays.size() == 1 &&
                   delay.delays[0] == GcpComputeTransaction::pollDelayUs,
               "gcp_cluster_destroy_owns_cluster_label_across_suspension");
}

static void testPartialReplacementAndBounds(TestSuite& suite)
{
  ScriptedHttpClient partialHttp;
  partialHttp.add(MultiCurlClient::Status::success, 200, matchingList(1, "abc123"_ctv), true);
  partialHttp.add(MultiCurlClient::Status::success, 200, ownership(0, "abc123"_ctv), true);
  partialHttp.add(MultiCurlClient::Status::transportFailure, 0, {}, true);
  partialHttp.add(MultiCurlClient::Status::success,
                  200,
                  R"json({"id":"999","labels":{"app":"prodigy","prodigy_cluster_uuid":"abc123"}})json"_ctv,
                  true);
  ScriptedDelayQueue partialDelay;
  CoroutineStack partialStack;
  uint32_t destroyed = 0;
  String failure;
  auto partial = transaction(partialHttp, partialDelay);
  partial.run(&partialStack, "abc123"_ctv, destroyed, failure);
  suite.expect(destroyed == 0 && contains(failure, "deletion transport failed"_ctv) &&
                   contains(failure, "cloud state may be partial for: machine-0"_ctv),
               "gcp_cluster_destroy_reports_ambiguous_mutation_and_protects_replacement");

  ScriptedHttpClient rejectedHttp;
  rejectedHttp.add(MultiCurlClient::Status::success, 200, matchingList(1, "abc123"_ctv), true);
  rejectedHttp.add(MultiCurlClient::Status::success, 200, ownership(0, "abc123"_ctv), true);
  rejectedHttp.add(MultiCurlClient::Status::success, 403, {}, true);
  ScriptedDelayQueue rejectedDelay;
  CoroutineStack rejectedStack;
  auto rejected = transaction(rejectedHttp, rejectedDelay);
  rejected.run(&rejectedStack, "abc123"_ctv, destroyed, failure);
  suite.expect(destroyed == 0 && rejectedHttp.requests.size() == 3 && rejectedDelay.delays.empty() &&
                   contains(failure, "deletion failed with HTTP 403"_ctv) &&
                   contains(failure, "cloud state may be partial for: machine-0"_ctv),
               "gcp_cluster_destroy_does_not_poll_definitively_rejected_deletion");

  ScriptedHttpClient invalidHttp;
  ScriptedDelayQueue invalidDelay;
  CoroutineStack invalidStack;
  auto invalid = transaction(invalidHttp, invalidDelay);
  invalid.run(&invalidStack, "INVALID"_ctv, destroyed, failure);
  suite.expect(destroyed == 0 && invalidHttp.requests.empty() &&
                   contains(failure, "valid project, zone, token, and cluster UUID label"_ctv),
               "gcp_cluster_destroy_rejects_invalid_cluster_label_before_io");

  String oversizedToken;
  oversizedToken.reserve(GcpComputeTransaction::maximumPageTokenBytes + 1);
  for (uint32_t index = 0; index <= GcpComputeTransaction::maximumPageTokenBytes; ++index)
  {
    oversizedToken.append('x');
  }
  String page;
  page.assign("{\"nextPageToken\":\""_ctv);
  page.append(oversizedToken);
  page.append("\"}"_ctv);
  ScriptedHttpClient tokenHttp;
  tokenHttp.add(MultiCurlClient::Status::success, 200, page, true);
  ScriptedDelayQueue tokenDelay;
  CoroutineStack tokenStack;
  auto token = transaction(tokenHttp, tokenDelay);
  token.run(&tokenStack, "abc123"_ctv, destroyed, failure);
  suite.expect(destroyed == 0 && failure == "gcp cluster destroy page token exceeds 2048 bytes"_ctv,
               "gcp_cluster_destroy_bounds_page_tokens_before_followup_io");

  ScriptedHttpClient malformedHttp;
  malformedHttp.add(MultiCurlClient::Status::success,
                    200,
                    "{\"nextPageToken\":7}"_ctv,
                    true);
  ScriptedDelayQueue malformedDelay;
  CoroutineStack malformedStack;
  auto malformed = transaction(malformedHttp, malformedDelay);
  malformed.run(&malformedStack, "abc123"_ctv, destroyed, failure);
  suite.expect(destroyed == 0 && failure == "gcp cluster destroy page token malformed"_ctv,
               "gcp_cluster_destroy_fails_closed_on_wrong_typed_page_token");

  ScriptedHttpClient shapeHttp;
  shapeHttp.add(MultiCurlClient::Status::success, 200, "[]"_ctv, true);
  ScriptedDelayQueue shapeDelay;
  CoroutineStack shapeStack;
  auto shape = transaction(shapeHttp, shapeDelay);
  shape.run(&shapeStack, "abc123"_ctv, destroyed, failure);
  suite.expect(destroyed == 0 &&
                   failure == "gcp cluster destroy instance list response parse failed"_ctv,
               "gcp_cluster_destroy_fails_closed_on_non_object_list_response");
}

int main(void)
{
  TestSuite suite;
  testAdmissionAlignedFanout(suite);
  testLaterWaveFailureSettlesEarlierMutations(suite);
  testExactLabelsDeduplicationAndDelete404(suite);
  testMalformedLabels(suite);
  testCopiedLabelAndOperationPolling(suite);
  testPartialReplacementAndBounds(suite);
  return suite.failed == 0 ? 0 : 1;
}
