#include <networking/includes.h>
#include <prodigy/iaas/gcp/gcp.elastic.address.h>
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
  };

  Vector<Response> responses;
  Vector<Operation::Request> requests;
  Vector<Operation::Callback> callbacks;
  Vector<Operation::Ticket> tickets;
  Vector<uint8_t> pending;
  uint32_t next = 0;

  static Operation::Ticket submit(void *context,
                                  Operation::Request&& request,
                                  Operation::Callback callback)
  {
    ScriptedHttpClient& client = *static_cast<ScriptedHttpClient *>(context);
    const uint32_t index = client.next++;
    client.requests.push_back(std::move(request));
    if (index >= client.responses.size())
    {
      return {};
    }
    const Operation::Ticket ticket {uint64_t(index) + 1, 73};
    client.callbacks.push_back(callback);
    client.tickets.push_back(ticket);
    client.pending.push_back(1);
    return ticket;
  }

  static bool cancel(void *context, Operation::Ticket ticket)
  {
    ScriptedHttpClient& client = *static_cast<ScriptedHttpClient *>(context);
    for (uint32_t index = 0; index < client.pending.size(); ++index)
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

  void add(long statusCode, const String& body)
  {
    responses.push_back({MultiCurlClient::Status::success, statusCode, body});
  }

  void add(MultiCurlClient::Status status, long statusCode, const String& body)
  {
    responses.push_back({status, statusCode, body});
  }

  bool completeOne(void)
  {
    for (uint32_t index = 0; index < pending.size(); ++index)
    {
      if (pending[index])
      {
        pending[index] = 0;
        Operation::Result result;
        result.status = responses[index].status;
        result.statusCode = responses[index].statusCode;
        result.body = responses[index].body;
        callbacks[index].function(callbacks[index].context, tickets[index], std::move(result));
        return true;
      }
    }
    return false;
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

static GcpElasticAddressTransaction transaction(ScriptedHttpClient& http,
                                                ScriptedDelayQueue& delay)
{
  return {http.submission(),
          delay.submission(),
          "project"_ctv,
          "zone-a"_ctv,
          "region"_ctv,
          "secret"_ctv,
          MultiCurlClient::Clock::now() + std::chrono::seconds(110),
          uint128_t(0x1234)};
}

static String target(const String& address,
                     const String& tier = "STANDARD"_ctv,
                     const String& id = "42"_ctv,
                     const String& config = "External NAT"_ctv)
{
  String body;
  body.snprintf<"{\"id\":\"{}\",\"networkInterfaces\":[{\"name\":\"nic0\",\"accessConfigs\":[{\"name\":\"{}\",\"natIP\":\"{}\",\"networkTier\":\"{}\"}]}]}"_ctv>(id,
                                                                                                                                                                                     config,
                                                                                                                                                                                     address,
                                                                                                                                                                                     tier);
  return body;
}

static String targetWithoutConfig(const String& id = "42"_ctv)
{
  String body;
  body.snprintf<"{\"id\":\"{}\",\"networkInterfaces\":[{\"name\":\"nic0\"}]}"_ctv>(id);
  return body;
}

static String address(const String& name,
                      const String& value,
                      const String& tier = "PREMIUM"_ctv,
                      const String& users = "[]"_ctv,
                      const String& cloudID = "77"_ctv,
                      const String& ipCollection = String())
{
  String collection;
  if (ipCollection.empty() == false)
  {
    collection.assign(",\"ipCollection\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(collection, ipCollection);
  }
  String body;
  body.snprintf<"{\"id\":\"{}\",\"name\":\"{}\",\"address\":\"{}\",\"addressType\":\"EXTERNAL\",\"ipVersion\":\"IPV4\",\"region\":\"https://www.googleapis.com/compute/v1/projects/project/regions/region\",\"networkTier\":\"{}\"{},\"users\":{}}"_ctv>(cloudID,
                                                                                                                                                                                                                                                                name,
                                                                                                                                                                                                                                                                value,
                                                                                                                                                                                                                                                                tier,
                                                                                                                                                                                                                                                                collection,
                                                                                                                                                                                                                                                                users);
  return body;
}

static String associationToken(const String& allocation = "allocated"_ctv)
{
  String token;
  token.snprintf<"{\"v\":1,\"project\":\"project\",\"region\":\"region\",\"zone\":\"zone-a\",\"targetId\":\"42\",\"instance\":\"target\",\"nic\":\"nic0\",\"config\":\"External NAT\",\"address\":\"34.1.2.3\",\"networkTier\":\"PREMIUM\",\"allocation\":\"{}\",\"allocationId\":\"77\"}"_ctv>(allocation);
  return token;
}

static ProviderElasticAddressRequest request(void)
{
  ProviderElasticAddressRequest request;
  request.cloudID.assign("42"_ctv);
  request.family = ExternalAddressFamily::ipv4;
  request.intent = ElasticPrefixIntent::any;
  request.requestedAddress.assign("34.1.2.3"_ctv);
  request.deliveryPrefix.network = IPAddress("10.0.0.4", false);
  request.deliveryPrefix.cidr = 32;
  return request;
}

static bool contains(const String& text, const char *needle)
{
  const String needleView(reinterpret_cast<uint8_t *>(const_cast<char *>(needle)), strlen(needle), Copy::no);
  return GcpComputeTransaction::find(text, needleView) != GcpComputeTransaction::notFound;
}

static bool hasVersion4RequestID(const String& url)
{
  const String text = GcpComputeTransaction::view(url);
  const uint64_t marker = GcpComputeTransaction::find(text, "requestId="_ctv);
  if (marker == GcpComputeTransaction::notFound || text.size() < marker + 10 + 36)
  {
    return false;
  }
  const String id = GcpComputeTransaction::slice(text, marker + 10, 36);
  return id[8] == '-' && id[13] == '-' && id[18] == '-' && id[23] == '-' && id[14] == '4' &&
         (id[19] == '8' || id[19] == '9' || id[19] == 'a' || id[19] == 'b');
}

static String requestID(const String& url)
{
  const String text = GcpComputeTransaction::view(url);
  const uint64_t marker = GcpComputeTransaction::find(text, "requestId="_ctv);
  if (marker == GcpComputeTransaction::notFound || text.size() < marker + 10 + 36)
  {
    return {};
  }
  return GcpComputeTransaction::slice(text, marker + 10, 36);
}

static void testDurablePlanAndStableMutationIDs(TestSuite& suite)
{
  ScriptedHttpClient prepareHttp;
  ScriptedDelayQueue prepareDelay;
  prepareHttp.add(200, "{\"items\":[{\"id\":\"42\",\"name\":\"target\"}]}"_ctv);
  prepareHttp.add(200, targetWithoutConfig());
  String lookup;
  lookup.assign("{\"items\":["_ctv);
  lookup.append(address("allocated"_ctv, "34.1.2.3"_ctv));
  lookup.append("]}"_ctv);
  prepareHttp.add(200, lookup);
  GcpElasticAddressTransaction prepareTx = transaction(prepareHttp, prepareDelay);
  ProviderElasticAddressPlan plan;
  String failure;
  CoroutineStack prepareStack;
  ProviderElasticAddressRequest input = request();
  prepareTx.prepare(&prepareStack, input, plan, failure);
  suite.expect(drive(prepareStack, prepareHttp, prepareDelay) && failure.empty() &&
                   plan.opaque.empty() == false && prepareHttp.requests.size() == 3,
               "durable_prepare_is_read_only_and_captures_plan");

  GcpElasticAddressPlanV1 decoded;
  String expectedProject = "project"_ctv;
  String expectedRegion = "region"_ctv;
  String expectedZone = "zone-a"_ctv;
  suite.expect(GcpElasticAddressTransaction::decodePlan(plan, decoded,
                                                       &expectedProject,
                                                       &expectedRegion,
                                                       &expectedZone) &&
                   decoded.targetID == "42"_ctv && decoded.desiredAllocationID == "77"_ctv,
               "durable_plan_binds_immutable_target_and_allocation");

  ProviderElasticAddressRequest mismatched = input;
  suite.expect(GcpElasticAddressTransaction::planMatchesRequest(decoded, input, uint128_t(0x1234)),
               "durable_plan_matches_exact_request");
  mismatched.cloudID.assign("43"_ctv);
  suite.expect(GcpElasticAddressTransaction::planMatchesRequest(decoded, mismatched,
                                                                uint128_t(0x1234)) == false,
               "durable_plan_rejects_target_mismatch");
  mismatched = input;
  mismatched.deliveryPrefix.network = IPAddress("10.0.0.5", false);
  suite.expect(GcpElasticAddressTransaction::planMatchesRequest(decoded, mismatched,
                                                                uint128_t(0x1234)) == false,
               "durable_plan_rejects_delivery_mismatch");
  mismatched = input;
  mismatched.requestedAddress.assign("34.1.2.4"_ctv);
  suite.expect(GcpElasticAddressTransaction::planMatchesRequest(decoded, mismatched,
                                                                uint128_t(0x1234)) == false,
               "durable_plan_rejects_requested_address_mismatch");
  mismatched = input;
  mismatched.providerPool.assign("https://compute.googleapis.com/compute/v1/projects/project/regions/region/publicDelegatedPrefixes/pool"_ctv);
  suite.expect(GcpElasticAddressTransaction::planMatchesRequest(decoded, mismatched,
                                                                uint128_t(0x1234)) == false,
               "durable_plan_rejects_provider_pool_mismatch");
  mismatched = input;
  mismatched.intent = ElasticPrefixIntent::anyOrCreate;
  suite.expect(GcpElasticAddressTransaction::planMatchesRequest(decoded, mismatched,
                                                                uint128_t(0x1234)) == false,
               "durable_plan_rejects_intent_mismatch");
  suite.expect(GcpElasticAddressTransaction::planMatchesRequest(decoded, input,
                                                                uint128_t(0x1235)) == false,
               "durable_plan_rejects_nonce_mismatch");

  String bindingDigest;
  suite.expect(prodigyComputeElasticAddressPlanBindingDigest(plan, input, uint128_t(0x1234),
                                                             bindingDigest) &&
                   prodigyValidateElasticAddressPlanBinding(plan, input, uint128_t(0x1234),
                                                            bindingDigest),
               "durable_provider_neutral_binding_matches_exact_envelope");
  suite.expect(prodigyValidateElasticAddressPlanBinding(plan, mismatched, uint128_t(0x1234),
                                                        bindingDigest) == false,
               "durable_provider_neutral_binding_rejects_semantic_mismatch");

  auto applyPlan = [&](ScriptedHttpClient& http,
                       ScriptedDelayQueue& delay,
                       ProviderElasticAddressAssignment& assignment,
                       String& error) -> bool {
    http.add(200, address("allocated"_ctv, "34.1.2.3"_ctv));
    http.add(200, targetWithoutConfig());
    http.add(200, "{\"name\":\"attach\"}"_ctv);
    http.add(200, "{\"status\":\"DONE\"}"_ctv);
    http.add(200, target("34.1.2.3"_ctv, "PREMIUM"_ctv));
    GcpElasticAddressTransaction tx = transaction(http, delay);
    CoroutineStack stack;
    tx.apply(&stack, plan, assignment, error);
    return drive(stack, http, delay);
  };

  ScriptedHttpClient firstApplyHttp;
  ScriptedDelayQueue firstApplyDelay;
  ProviderElasticAddressAssignment firstAssignment;
  String firstFailure;
  suite.expect(applyPlan(firstApplyHttp, firstApplyDelay, firstAssignment, firstFailure) &&
                   firstFailure.empty() && firstAssignment.allocationID == "allocated"_ctv &&
                   hasVersion4RequestID(firstApplyHttp.requests[2].url),
               "durable_apply_observes_exact_postcondition");

  ScriptedHttpClient secondApplyHttp;
  ScriptedDelayQueue secondApplyDelay;
  ProviderElasticAddressAssignment secondAssignment;
  String secondFailure;
  suite.expect(applyPlan(secondApplyHttp, secondApplyDelay, secondAssignment, secondFailure) &&
                   secondFailure.empty() &&
                   requestID(firstApplyHttp.requests[2].url) == requestID(secondApplyHttp.requests[2].url),
               "durable_apply_request_id_is_stable_across_replay");

  ScriptedHttpClient compensationHttp;
  ScriptedDelayQueue compensationDelay;
  compensationHttp.add(200, address("allocated"_ctv, "34.1.2.3"_ctv));
  compensationHttp.add(200, target("34.1.2.3"_ctv, "PREMIUM"_ctv));
  compensationHttp.add(200, "{\"name\":\"detach\"}"_ctv);
  compensationHttp.add(200, "{\"status\":\"DONE\"}"_ctv);
  compensationHttp.add(200, targetWithoutConfig());
  GcpElasticAddressTransaction compensationTx = transaction(compensationHttp, compensationDelay);
  String compensationFailure;
  CoroutineStack compensationStack;
  compensationTx.compensate(&compensationStack, plan, compensationFailure);
  suite.expect(drive(compensationStack, compensationHttp, compensationDelay) &&
                   compensationFailure.empty() &&
                   hasVersion4RequestID(compensationHttp.requests[2].url) &&
                   requestID(compensationHttp.requests[2].url) != requestID(firstApplyHttp.requests[2].url),
               "durable_compensation_uses_distinct_stable_step_id");

  ScriptedHttpClient createPrepareHttp;
  ScriptedDelayQueue createPrepareDelay;
  createPrepareHttp.add(200, "{\"items\":[{\"id\":\"42\",\"name\":\"target\"}]}"_ctv);
  createPrepareHttp.add(200, targetWithoutConfig());
  createPrepareHttp.add(404, "{}"_ctv);
  GcpElasticAddressTransaction createPrepareTx = transaction(createPrepareHttp, createPrepareDelay);
  ProviderElasticAddressRequest createInput = request();
  createInput.intent = ElasticPrefixIntent::create;
  createInput.requestedAddress.clear();
  ProviderElasticAddressPlan createPlan;
  String createPrepareFailure;
  CoroutineStack createPrepareStack;
  createPrepareTx.prepare(&createPrepareStack, createInput, createPlan, createPrepareFailure);
  suite.expect(drive(createPrepareStack, createPrepareHttp, createPrepareDelay) &&
                   createPrepareFailure.empty() && createPlan.opaque.empty() == false,
               "durable_create_prepare_captures_absent_marked_allocation");

  ScriptedHttpClient noMutationHttp;
  ScriptedDelayQueue noMutationDelay;
  noMutationHttp.add(404, "{}"_ctv);
  noMutationHttp.add(200, targetWithoutConfig());
  GcpElasticAddressTransaction noMutationTx = transaction(noMutationHttp, noMutationDelay);
  String noMutationFailure;
  CoroutineStack noMutationStack;
  noMutationTx.compensate(&noMutationStack, createPlan, noMutationFailure);
  bool onlyReads = true;
  suite.expect(drive(noMutationStack, noMutationHttp, noMutationDelay),
               "durable_compensation_before_apply_drives");
  for (const MultiCurlClient::Request& request : noMutationHttp.requests)
  {
    onlyReads = onlyReads && request.method == MultiCurlClient::Method::get;
  }
  suite.expect(noMutationFailure.empty() && noMutationHttp.requests.size() == 2 && onlyReads,
               "durable_compensation_before_apply_never_creates_resource");
}

static void testRelease(TestSuite& suite)
{
  ScriptedHttpClient http;
  ScriptedDelayQueue delay;
  http.add(200, address("allocated"_ctv,
                        "34.1.2.3"_ctv,
                        "PREMIUM"_ctv,
                        "[\"https://www.googleapis.com/compute/v1/projects/project/zones/zone-a/instances/target\"]"_ctv));
  http.add(200, target("34.1.2.3"_ctv, "PREMIUM"_ctv));
  http.add(200, "{\"name\":\"detach-op\"}"_ctv);
  http.add(200, "{\"status\":\"DONE\"}"_ctv);
  http.add(200, targetWithoutConfig());
  http.add(200, address("allocated"_ctv, "34.1.2.3"_ctv));
  http.add(200, "{\"name\":\"delete-op\"}"_ctv);
  http.add(200, "{\"status\":\"DONE\"}"_ctv);
  http.add(404, "{}"_ctv);

  ProviderElasticAddressRelease release;
  release.transactionNonce = uint128_t(0x1234);
  release.kind = RoutablePrefixKind::elastic;
  release.assignedPrefix.network = IPAddress("34.1.2.3", false);
  release.assignedPrefix.cidr = 32;
  release.allocationID.assign("allocated"_ctv);
  release.associationID = associationToken();
  release.releaseOnRemove = true;

  GcpElasticAddressTransaction tx = transaction(http, delay);
  String failure;
  CoroutineStack stack;
  tx.release(&stack, release, failure);
  release.associationID.assign("changed"_ctv);
  suite.expect(drive(stack, http, delay) && failure.empty() && http.requests.size() == 9 &&
                   contains(http.requests[2].url, "requestId=") &&
                   contains(http.requests[6].url, "requestId="),
               "release_owned_token_detaches_then_deletes_unused_allocation");

  const String detachRequestID = requestID(http.requests[2].url);
  const String deleteRequestID = requestID(http.requests[6].url);
  ScriptedHttpClient replayHttp;
  ScriptedDelayQueue replayDelay;
  replayHttp.add(200, address("allocated"_ctv,
                              "34.1.2.3"_ctv,
                              "PREMIUM"_ctv,
                              "[\"https://www.googleapis.com/compute/v1/projects/project/zones/zone-a/instances/target\"]"_ctv));
  replayHttp.add(200, target("34.1.2.3"_ctv, "PREMIUM"_ctv));
  replayHttp.add(200, "{\"name\":\"detach-op\"}"_ctv);
  replayHttp.add(200, "{\"status\":\"DONE\"}"_ctv);
  replayHttp.add(200, targetWithoutConfig());
  replayHttp.add(200, address("allocated"_ctv, "34.1.2.3"_ctv));
  replayHttp.add(200, "{\"name\":\"delete-op\"}"_ctv);
  replayHttp.add(200, "{\"status\":\"DONE\"}"_ctv);
  replayHttp.add(404, "{}"_ctv);
  release.associationID = associationToken();
  GcpElasticAddressTransaction replayTx = transaction(replayHttp, replayDelay);
  String replayFailure;
  CoroutineStack replayStack;
  replayTx.release(&replayStack, release, replayFailure);
  suite.expect(drive(replayStack, replayHttp, replayDelay) && replayFailure.empty() &&
                   requestID(replayHttp.requests[2].url) == detachRequestID &&
                   requestID(replayHttp.requests[6].url) == deleteRequestID &&
                   detachRequestID != deleteRequestID,
               "release_retry_reuses_stable_labelled_request_ids");
}

static void testReleaseAba(TestSuite& suite)
{
  ScriptedHttpClient http;
  ScriptedDelayQueue delay;
  http.add(200, address("allocated"_ctv,
                        "34.1.2.3"_ctv,
                        "PREMIUM"_ctv,
                        "[\"https://www.googleapis.com/compute/v1/projects/project/zones/zone-a/instances/target\"]"_ctv));
  http.add(200, target("34.9.9.9"_ctv, "PREMIUM"_ctv));
  ProviderElasticAddressRelease release;
  release.transactionNonce = uint128_t(0x1234);
  release.assignedPrefix.network = IPAddress("34.1.2.3", false);
  release.assignedPrefix.cidr = 32;
  release.allocationID.assign("allocated"_ctv);
  release.associationID = associationToken();
  GcpElasticAddressTransaction tx = transaction(http, delay);
  String failure;
  CoroutineStack stack;
  tx.release(&stack, release, failure);
  suite.expect(drive(stack, http, delay) && contains(failure, "changed target association") &&
                   http.requests.size() == 2,
               "release_rejects_aba_without_mutation");
}

static void testAlreadySatisfiedCompensationIsNoMutation(TestSuite& suite)
{
  ScriptedHttpClient prepareHttp;
  ScriptedDelayQueue prepareDelay;
  prepareHttp.add(200, "{\"items\":[{\"id\":\"42\",\"name\":\"target\"}]}"_ctv);
  prepareHttp.add(200, target("34.1.2.3"_ctv, "PREMIUM"_ctv));
  String users;
  users.assign("[\"https://www.googleapis.com/compute/v1/projects/project/zones/zone-a/instances/target\"]"_ctv);
  String lookup;
  lookup.assign("{\"items\":["_ctv);
  lookup.append(address("allocated"_ctv, "34.1.2.3"_ctv, "PREMIUM"_ctv, users));
  lookup.append("]}"_ctv);
  prepareHttp.add(200, lookup);
  prepareHttp.add(200, target("34.1.2.3"_ctv, "PREMIUM"_ctv));
  GcpElasticAddressTransaction prepareTx = transaction(prepareHttp, prepareDelay);
  ProviderElasticAddressPlan plan;
  String prepareFailure;
  CoroutineStack prepareStack;
  ProviderElasticAddressRequest input = request();
  prepareTx.prepare(&prepareStack, input, plan, prepareFailure);
  suite.expect(drive(prepareStack, prepareHttp, prepareDelay) && prepareFailure.empty(),
               "already_satisfied_prepare_drives");

  GcpElasticAddressPlanV1 decoded;
  suite.expect(GcpElasticAddressTransaction::decodePlan(plan, decoded) && decoded.alreadySatisfied,
               "already_satisfied_plan_persists_no_mutation_invariant");
  decoded.alreadySatisfied = false;
  ProviderElasticAddressPlan malformedPlan;
  BitseryEngine::serialize(malformedPlan.opaque, decoded);
  suite.expect(GcpElasticAddressTransaction::decodePlan(malformedPlan, decoded) == false,
               "already_satisfied_plan_rejects_missing_no_mutation_invariant");
  ScriptedHttpClient compensationHttp;
  ScriptedDelayQueue compensationDelay;
  GcpElasticAddressTransaction compensationTx = transaction(compensationHttp, compensationDelay);
  String compensationFailure;
  CoroutineStack compensationStack;
  compensationTx.compensate(&compensationStack, plan, compensationFailure);
  suite.expect(drive(compensationStack, compensationHttp, compensationDelay) &&
                   compensationFailure.empty() && compensationHttp.requests.empty(),
               "already_satisfied_compensation_never_detaches_preexisting_attachment");
}

static void testCompensationRequiresExactDesiredAccessConfig(TestSuite& suite)
{
  GcpElasticAddressPlanV1 decoded;
  decoded.nonce = uint128_t(0x1234);
  decoded.project.assign("project"_ctv);
  decoded.region.assign("region"_ctv);
  decoded.targetZone.assign("zone-a"_ctv);
  decoded.targetID.assign("42"_ctv);
  decoded.targetName.assign("target"_ctv);
  decoded.targetNic.assign("nic0"_ctv);
  decoded.desiredName.assign("allocated"_ctv);
  decoded.desiredAllocationID.assign("77"_ctv);
  decoded.desiredAddress.assign("34.1.2.3"_ctv);
  decoded.desiredTier.assign("PREMIUM"_ctv);
  decoded.requestedAddress.assign("34.1.2.3"_ctv);
  decoded.deliveryPrefix.network = IPAddress("10.0.0.4", false);
  decoded.deliveryPrefix.cidr = 32;
  decoded.intent = ElasticPrefixIntent::any;
  ProviderElasticAddressPlan plan;
  BitseryEngine::serialize(plan.opaque, decoded);

  auto compensate = [&](const String& config, const String& addressValue,
                        const String& tier, String& failure, uint32_t& requests) {
    ScriptedHttpClient http;
    ScriptedDelayQueue delay;
    http.add(200, address("allocated"_ctv, "34.1.2.3"_ctv));
    http.add(200, target(addressValue, tier, "42"_ctv, config));
    GcpElasticAddressTransaction tx = transaction(http, delay);
    CoroutineStack stack;
    tx.compensate(&stack, plan, failure);
    const bool completed = drive(stack, http, delay);
    requests = http.requests.size();
    return completed;
  };

  String nameFailure;
  uint32_t nameRequests = 0;
  suite.expect(compensate("Replacement NAT"_ctv, "34.1.2.3"_ctv, "PREMIUM"_ctv,
                          nameFailure, nameRequests) &&
                   contains(nameFailure, "target changed") && nameRequests == 2,
               "compensation_rejects_desired_access_config_name_change_before_detach");

  String addressFailure;
  uint32_t addressRequests = 0;
  suite.expect(compensate("External NAT"_ctv, "34.9.9.9"_ctv, "PREMIUM"_ctv,
                          addressFailure, addressRequests) &&
                   contains(addressFailure, "target changed") && addressRequests == 2,
               "compensation_rejects_desired_access_config_address_change_before_detach");

  String tierFailure;
  uint32_t tierRequests = 0;
  suite.expect(compensate("External NAT"_ctv, "34.1.2.3"_ctv, "STANDARD"_ctv,
                          tierFailure, tierRequests) &&
                   contains(tierFailure, "target changed") && tierRequests == 2,
               "compensation_rejects_desired_access_config_tier_change_before_detach");
}

static void testFullCompensationRestoresPriorAndSource(TestSuite& suite)
{
  GcpElasticAddressPlanV1 decoded;
  decoded.nonce = uint128_t(0x1234);
  decoded.project.assign("project"_ctv);
  decoded.region.assign("region"_ctv);
  decoded.targetZone.assign("zone-a"_ctv);
  decoded.targetID.assign("42"_ctv);
  decoded.targetName.assign("target"_ctv);
  decoded.targetNic.assign("nic0"_ctv);
  decoded.targetPriorName.assign("External NAT"_ctv);
  decoded.targetPriorAddress.assign("35.1.1.1"_ctv);
  decoded.targetPriorTier.assign("STANDARD"_ctv);
  decoded.targetPriorAllocationName.assign("prior"_ctv);
  decoded.targetPriorAllocationID.assign("88"_ctv);
  decoded.desiredName.assign("allocated"_ctv);
  decoded.desiredAllocationID.assign("77"_ctv);
  decoded.desiredAddress.assign("34.1.2.3"_ctv);
  decoded.desiredTier.assign("PREMIUM"_ctv);
  decoded.requestedAddress.assign("34.1.2.3"_ctv);
  decoded.sourceProject.assign("project"_ctv);
  decoded.sourceZone.assign("zone-b"_ctv);
  decoded.sourceInstance.assign("source"_ctv);
  decoded.sourceID.assign("99"_ctv);
  decoded.sourceNic.assign("nic0"_ctv);
  decoded.sourceConfig.assign("External NAT"_ctv);
  decoded.deliveryPrefix.network = IPAddress("10.0.0.4", false);
  decoded.deliveryPrefix.cidr = 32;
  decoded.intent = ElasticPrefixIntent::any;
  ProviderElasticAddressPlan plan;
  BitseryEngine::serialize(plan.opaque, decoded);

  ScriptedHttpClient http;
  ScriptedDelayQueue delay;
  http.add(200, address("allocated"_ctv, "34.1.2.3"_ctv));
  http.add(200, target("34.1.2.3"_ctv, "PREMIUM"_ctv));
  http.add(200, "{\"name\":\"target-detach\"}"_ctv);
  http.add(200, "{\"status\":\"DONE\"}"_ctv);
  http.add(200, targetWithoutConfig());
  http.add(200, address("prior"_ctv, "35.1.1.1"_ctv, "STANDARD"_ctv, "[]"_ctv, "88"_ctv));
  http.add(200, "{\"name\":\"target-restore\"}"_ctv);
  http.add(200, "{\"status\":\"DONE\"}"_ctv);
  http.add(200, target("35.1.1.1"_ctv, "STANDARD"_ctv));
  http.add(200, targetWithoutConfig("99"_ctv));
  http.add(200, "{\"name\":\"source-restore\"}"_ctv);
  http.add(200, "{\"status\":\"DONE\"}"_ctv);
  http.add(200, target("34.1.2.3"_ctv, "PREMIUM"_ctv, "99"_ctv));
  GcpElasticAddressTransaction tx = transaction(http, delay);
  String failure;
  CoroutineStack stack;
  tx.compensate(&stack, plan, failure);
  suite.expect(drive(stack, http, delay) && failure.empty() && http.requests.size() == 13 &&
                   contains(http.requests[2].url, "requestId=") &&
                   contains(http.requests[6].url, "requestId=") &&
                   contains(http.requests[10].url, "requestId="),
               "full_compensation_detaches_desired_and_restores_target_and_source");
}

static void testReleaseAbsentAndIdentityMismatch(TestSuite& suite)
{
  ProviderElasticAddressRelease release;
  release.transactionNonce = uint128_t(0x1234);
  release.assignedPrefix.network = IPAddress("34.1.2.3", false);
  release.assignedPrefix.cidr = 32;
  release.allocationID.assign("allocated"_ctv);
  release.associationID = associationToken();

  ScriptedHttpClient absentHttp;
  ScriptedDelayQueue absentDelay;
  absentHttp.add(404, "{}"_ctv);
  GcpElasticAddressTransaction absent = transaction(absentHttp, absentDelay);
  String absentFailure;
  CoroutineStack absentStack;
  absent.release(&absentStack, release, absentFailure);
  suite.expect(drive(absentStack, absentHttp, absentDelay) && absentFailure.empty() &&
                   absentHttp.requests.size() == 1,
               "release_absent_target_is_idempotent");

  ScriptedHttpClient mismatchHttp;
  ScriptedDelayQueue mismatchDelay;
  mismatchHttp.add(200, address("allocated"_ctv,
                                "34.1.2.3"_ctv,
                                "PREMIUM"_ctv,
                                "[\"https://www.googleapis.com/compute/v1/projects/project/zones/zone-a/instances/target\"]"_ctv));
  mismatchHttp.add(200, target("34.1.2.3"_ctv, "PREMIUM"_ctv, "43"_ctv));
  GcpElasticAddressTransaction mismatch = transaction(mismatchHttp, mismatchDelay);
  String mismatchFailure;
  CoroutineStack mismatchStack;
  mismatch.release(&mismatchStack, release, mismatchFailure);
  suite.expect(drive(mismatchStack, mismatchHttp, mismatchDelay) && contains(mismatchFailure, "identity") &&
                   mismatchHttp.requests.size() == 2,
               "release_numeric_identity_mismatch_never_mutates");
}

static void testReleasePreflightAndPartialState(TestSuite& suite)
{
  ProviderElasticAddressRelease release;
  release.transactionNonce = uint128_t(0x1234);
  release.assignedPrefix.network = IPAddress("34.1.2.3", false);
  release.assignedPrefix.cidr = 32;
  release.allocationID.assign("allocated"_ctv);
  release.associationID = associationToken();

  ScriptedHttpClient noIoHttp;
  ScriptedDelayQueue noIoDelay;
  GcpElasticAddressTransaction noIo = transaction(noIoHttp, noIoDelay);
  ProviderElasticAddressRelease malformed = release;
  malformed.assignedPrefix.cidr = 24;
  String malformedFailure;
  CoroutineStack malformedStack;
  noIo.release(&malformedStack, malformed, malformedFailure);
  suite.expect(drive(malformedStack, noIoHttp, noIoDelay) && contains(malformedFailure, "prefix malformed") &&
                   noIoHttp.requests.empty(),
               "release_rejects_malformed_prefix_before_io");

  ProviderElasticAddressRelease missingNonce = release;
  missingNonce.transactionNonce = 0;
  String missingNonceFailure;
  CoroutineStack missingNonceStack;
  noIo.release(&missingNonceStack, missingNonce, missingNonceFailure);
  suite.expect(drive(missingNonceStack, noIoHttp, noIoDelay) &&
                   contains(missingNonceFailure, "transaction nonce") && noIoHttp.requests.empty(),
               "release_rejects_missing_durable_nonce_before_io");

  ProviderElasticAddressRelease missingToken = release;
  missingToken.associationID.clear();
  missingToken.releaseOnRemove = true;
  String missingTokenFailure;
  CoroutineStack missingTokenStack;
  noIo.release(&missingTokenStack, missingToken, missingTokenFailure);
  suite.expect(drive(missingTokenStack, noIoHttp, noIoDelay) &&
                   contains(missingTokenFailure, "immutable association token") && noIoHttp.requests.empty(),
               "owned_release_requires_immutable_token_before_io");

  String user;
  user.assign("[\"https://www.googleapis.com/compute/v1/projects/project/zones/zone-a/instances/target\"]"_ctv);
  ScriptedHttpClient idHttp;
  ScriptedDelayQueue idDelay;
  idHttp.add(200, address("allocated"_ctv, "34.1.2.3"_ctv, "PREMIUM"_ctv, user, "78"_ctv));
  GcpElasticAddressTransaction idTx = transaction(idHttp, idDelay);
  String idFailure;
  CoroutineStack idStack;
  idTx.release(&idStack, release, idFailure);
  suite.expect(drive(idStack, idHttp, idDelay) && contains(idFailure, "allocation identity changed") &&
                   idHttp.requests.size() == 1,
               "release_rejects_immutable_allocation_id_aba");

  ScriptedHttpClient tierHttp;
  ScriptedDelayQueue tierDelay;
  tierHttp.add(200, address("allocated"_ctv, "34.1.2.3"_ctv, "PREMIUM"_ctv, user));
  tierHttp.add(200, target("34.1.2.3"_ctv, "STANDARD"_ctv));
  GcpElasticAddressTransaction tierTx = transaction(tierHttp, tierDelay);
  String tierFailure;
  CoroutineStack tierStack;
  tierTx.release(&tierStack, release, tierFailure);
  suite.expect(drive(tierStack, tierHttp, tierDelay) && contains(tierFailure, "changed target association") &&
                   tierHttp.requests.size() == 2,
               "release_rejects_access_config_tier_aba");

  ScriptedHttpClient vanishedHttp;
  ScriptedDelayQueue vanishedDelay;
  vanishedHttp.add(200, address("allocated"_ctv, "34.1.2.3"_ctv, "PREMIUM"_ctv, user));
  vanishedHttp.add(200, target("34.1.2.3"_ctv, "PREMIUM"_ctv));
  vanishedHttp.add(200, "{\"name\":\"detach\"}"_ctv);
  vanishedHttp.add(200, "{\"status\":\"DONE\"}"_ctv);
  vanishedHttp.add(404, "{}"_ctv);
  GcpElasticAddressTransaction vanishedTx = transaction(vanishedHttp, vanishedDelay);
  String vanishedFailure;
  CoroutineStack vanishedStack;
  vanishedTx.release(&vanishedStack, release, vanishedFailure);
  suite.expect(drive(vanishedStack, vanishedHttp, vanishedDelay) && vanishedFailure.empty() &&
                   vanishedHttp.requests.size() == 5,
               "release_target_disappearing_after_detach_is_idempotent");

  ScriptedHttpClient partialHttp;
  ScriptedDelayQueue partialDelay;
  partialHttp.add(200, address("allocated"_ctv, "34.1.2.3"_ctv, "PREMIUM"_ctv, user));
  partialHttp.add(200, target("34.1.2.3"_ctv, "PREMIUM"_ctv));
  partialHttp.add(MultiCurlClient::Status::deadlineExceeded, 0, String());
  partialHttp.add(MultiCurlClient::Status::deadlineExceeded, 0, String());
  GcpElasticAddressTransaction partialTx = transaction(partialHttp, partialDelay);
  String partialFailure;
  CoroutineStack partialStack;
  partialTx.release(&partialStack, release, partialFailure);
  suite.expect(drive(partialStack, partialHttp, partialDelay) && contains(partialFailure, "partial for: target") &&
                   partialHttp.requests.size() == 4,
               "ambiguous_release_failure_names_partial_association_identity");

  ScriptedHttpClient changedAddressHttp;
  ScriptedDelayQueue changedAddressDelay;
  changedAddressHttp.add(200, address("allocated"_ctv, "34.1.2.3"_ctv, "PREMIUM"_ctv, user));
  changedAddressHttp.add(200, target("34.1.2.3"_ctv, "PREMIUM"_ctv));
  changedAddressHttp.add(200, "{\"name\":\"detach\"}"_ctv);
  changedAddressHttp.add(200, "{\"status\":\"DONE\"}"_ctv);
  changedAddressHttp.add(200, targetWithoutConfig());
  changedAddressHttp.add(200, address("allocated"_ctv, "34.9.9.9"_ctv));
  ProviderElasticAddressRelease ownedRelease = release;
  ownedRelease.releaseOnRemove = true;
  GcpElasticAddressTransaction changedAddressTx = transaction(changedAddressHttp, changedAddressDelay);
  String changedAddressFailure;
  CoroutineStack changedAddressStack;
  changedAddressTx.release(&changedAddressStack, ownedRelease, changedAddressFailure);
  bool issuedDelete = false;
  suite.expect(drive(changedAddressStack, changedAddressHttp, changedAddressDelay),
               "changed_allocation_address_release_drives");
  for (const MultiCurlClient::Request& request : changedAddressHttp.requests)
  {
    issuedDelete = issuedDelete || request.method == MultiCurlClient::Method::delete_;
  }
  suite.expect(contains(changedAddressFailure, "allocation identity changed") &&
                   contains(changedAddressFailure, "partial for: allocated") &&
                   contains(changedAddressFailure, "partial for: target") && issuedDelete == false &&
                   changedAddressHttp.requests.size() == 6,
               "changed_allocation_address_never_deletes_and_names_partial_state");
}

int main(void)
{
  TestSuite suite;
  testDurablePlanAndStableMutationIDs(suite);
  testAlreadySatisfiedCompensationIsNoMutation(suite);
  testCompensationRequiresExactDesiredAccessConfig(suite);
  testFullCompensationRestoresPriorAndSource(suite);
  testRelease(suite);
  testReleaseAba(suite);
  testReleaseAbsentAndIdentityMismatch(suite);
  testReleasePreflightAndPartialState(suite);
  if (suite.failed)
  {
    std::fprintf(stderr, "%u gcp elastic address unit checks failed\n", suite.failed);
    return 1;
  }
  std::printf("gcp elastic address unit checks passed\n");
  return 0;
}
