#include <networking/includes.h>
#include <prodigy/types.h>
#include <prodigy/iaas/gcp/gcp.managed.template.h>
#include <prodigy/mothership/mothership.gcp.managed.template.plan.h>
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
   Vector<MultiCurlClient::TimePoint> submissionTimes;
   Operation::Callback callback = {};
   Operation::Ticket ticket = {};
   uint32_t nextResponse = 0;
   uint32_t cancellations = 0;
   bool pending = false;

   static Operation::Ticket submit(void *context,
                                   Operation::Request&& request,
                                   Operation::Callback callback)
   {
      ScriptedHttpClient& client = *static_cast<ScriptedHttpClient *>(context);
      const uint32_t responseIndex = client.nextResponse++;
      client.submissionTimes.push_back(MultiCurlClient::Clock::now());
      client.requests.push_back(std::move(request));
      if (responseIndex >= client.responses.size())
      {
         return {};
      }

      client.ticket = {uint64_t(responseIndex) + 1, 1};
      if (client.responses[responseIndex].inlineCompletion)
      {
         Operation::Result result = client.result(responseIndex);
         callback.function(callback.context, client.ticket, std::move(result));
      }
      else
      {
         client.callback = callback;
         client.pending = true;
      }
      return client.ticket;
   }

   static bool cancel(void *context, Operation::Ticket ticket)
   {
      ScriptedHttpClient& client = *static_cast<ScriptedHttpClient *>(context);
      if (!client.pending || ticket.identifier != client.ticket.identifier ||
          ticket.generation != client.ticket.generation)
      {
         return false;
      }
      client.pending = false;
      client.cancellations += 1;
      return true;
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
      Response response = {};
      response.status = status;
      response.statusCode = statusCode;
      response.body = body;
      response.inlineCompletion = inlineCompletion;
      responses.push_back(std::move(response));
   }

   bool complete(void)
   {
      if (!pending)
      {
         return false;
      }
      const uint32_t responseIndex = nextResponse - 1;
      pending = false;
      Operation::Callback completion = callback;
      Operation::Ticket completedTicket = ticket;
      Operation::Result completedResult = result(responseIndex);
      completion.function(completion.context, completedTicket, std::move(completedResult));
      return true;
   }

private:

   Operation::Result result(uint32_t index) const
   {
      Operation::Result result = {};
      result.status = responses[index].status;
      result.statusCode = responses[index].statusCode;
      result.body = responses[index].body;
      return result;
   }
};

class ScriptedDelayQueue
{
public:

   Vector<uint64_t> delays;
   TimeoutPacket *pending = nullptr;
   uint32_t inlineCompletions = 0;
   uint32_t deferredCompletions = 0;
   uint32_t cancellations = 0;
   bool completeInline = false;

   static void queue(void *context, TimeoutPacket *packet)
   {
      ScriptedDelayQueue& delay = *static_cast<ScriptedDelayQueue *>(context);
      delay.delays.push_back(uint64_t(packet->timeout.tv_sec) * 1'000'000 +
                             uint64_t(packet->timeout.tv_nsec) / 1000);
      if (delay.completeInline)
      {
         delay.inlineCompletions += 1;
         packet->dispatcher->dispatchTimeout(packet);
      }
      else
      {
         delay.pending = packet;
      }
   }

   static void cancel(void *context, TimeoutPacket *packet)
   {
      ScriptedDelayQueue& delay = *static_cast<ScriptedDelayQueue *>(context);
      if (delay.pending == packet)
      {
         delay.pending = nullptr;
         delay.cancellations += 1;
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
      deferredCompletions += 1;
      packet->dispatcher->dispatchTimeout(packet);
      return true;
   }
};

static GcpManagedTemplateTransaction::Spec spec(const String& name, const String& marker)
{
   GcpManagedTemplateTransaction::Spec value = {};
   value.name = name;
   value.body.snprintf<"{\"name\":\"{}\",\"marker\":\"{}\"}"_ctv>(name, marker);
   return value;
}

static bool drive(CoroutineStack& stack,
                  ScriptedHttpClient& http,
                  ScriptedDelayQueue& delay,
                  uint32_t maximumSteps = 10'000)
{
   for (uint32_t step = 0; step < maximumSteps && stack.hasSuspendedCoroutines(); ++step)
   {
      if (http.complete() || delay.complete())
      {
         continue;
      }
      return false;
   }
   return !stack.hasSuspendedCoroutines() && !http.pending && delay.pending == nullptr;
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

static bool contains(const String& value, const String& fragment)
{
   if (fragment.empty())
   {
      return true;
   }
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

static void testBuildSpec(TestSuite& suite)
{
   MachineConfig config = {};
   config.providerMachineType = "c3-standard-4"_ctv;
   config.vmImageURI = "projects/project/global/images/image"_ctv;
   config.cpu.cpuPlatform = "Intel Sapphire Rapids"_ctv;
   GcpManagedTemplateTransaction::Spec standard = {};
   GcpManagedTemplateTransaction::Spec spot = {};
   String failure = {};

   suite.expect(GcpManagedTemplateTransaction::buildSpec(
                    "standard"_ctv,
                    "prodigy@project.iam.gserviceaccount.com"_ctv,
                    "global/networks/network"_ctv,
                    "regions/region/subnetworks/subnetwork"_ctv,
                    config,
                    false,
                    standard,
                    failure) && failure.empty(),
                "gcp_managed_template_builds_standard_spec");
   suite.expect(standard.name == "standard"_ctv &&
                    contains(standard.body, "\"machineType\":\"c3-standard-4\""_ctv) &&
                    contains(standard.body, "\"minCpuPlatform\":\"Intel Sapphire Rapids\""_ctv) &&
                    contains(standard.body, "\"labels\":{\"app\":\"prodigy\",\"brain\":\"false\"}"_ctv) &&
                    contains(standard.body, "\"email\":\"prodigy@project.iam.gserviceaccount.com\""_ctv) &&
                    contains(standard.body, "\"network\":\"global/networks/network\""_ctv) &&
                    contains(standard.body, "\"subnetwork\":\"regions/region/subnetworks/subnetwork\""_ctv) &&
                    contains(standard.body, "\"sourceImage\":\"projects/project/global/images/image\""_ctv) &&
                    !contains(standard.body, "\"provisioningModel\":\"SPOT\""_ctv),
                "gcp_managed_template_standard_body_has_required_fields_without_spot_policy");
   suite.expect(GcpManagedTemplateTransaction::buildSpec(
                    "spot"_ctv,
                    "prodigy@project.iam.gserviceaccount.com"_ctv,
                    "global/networks/network"_ctv,
                    {} /* subnetwork */,
                    config,
                    true,
                    spot,
                    failure) &&
                    contains(spot.body,
                             "\"scheduling\":{\"provisioningModel\":\"SPOT\",\"instanceTerminationAction\":\"DELETE\",\"automaticRestart\":false}"_ctv),
                "gcp_managed_template_spot_body_has_exact_scheduling_policy");

   config.providerMachineType.reset();
   config.providerMachineType.reserve(16);
   config.providerMachineType.append("machine\"\\\n"_ctv);
   config.providerMachineType.append('\b');
   config.providerMachineType.append('\f');
   config.providerMachineType.append(uint8_t(1));
   suite.expect(GcpManagedTemplateTransaction::buildSpec(
                    "escaped"_ctv,
                    "prodigy@project.iam.gserviceaccount.com"_ctv,
                    "global/networks/network"_ctv,
                    {} /* subnetwork */,
                    config,
                    false,
                    standard,
                    failure) &&
                    contains(standard.body, "\"machineType\":\"machine\\\"\\\\\\n\\b\\f\\u0001\""_ctv),
                "gcp_managed_template_reuses_shared_json_string_escaping");
}

static MothershipProdigyClusterMachineSchema planSchema(const String& name,
                                                        MachineLifetime lifetime,
                                                        uint32_t budget)
{
   MothershipProdigyClusterMachineSchema schema = {};
   schema.schema = name;
   schema.lifetime = lifetime;
   schema.budget = budget;
   schema.vmImageURI = "projects/project/global/images/image"_ctv;
   schema.providerMachineType = "c3-standard-4"_ctv;
   schema.gcpInstanceTemplate.snprintf<"{}-standard"_ctv>(name);
   schema.gcpInstanceTemplateSpot.snprintf<"{}-spot"_ctv>(name);
   return schema;
}

static void testMothershipPlan(TestSuite& suite)
{
   MothershipProdigyCluster cluster = {};
   cluster.gcp.serviceAccountEmail = "prodigy@project.iam.gserviceaccount.com"_ctv;
   cluster.gcp.network = "global/networks/network"_ctv;
   cluster.machineSchemas.push_back(planSchema("ignored"_ctv, MachineLifetime::reserved, 0));
   cluster.machineSchemas.push_back(planSchema("standard"_ctv, MachineLifetime::reserved, 1));
   cluster.machineSchemas.push_back(planSchema("spot"_ctv, MachineLifetime::spot, 1));
   MothershipGcpManagedTemplatePlan plan = {};
   String failure = {};
   suite.expect(MothershipGcpManagedTemplatePlan::build(cluster, plan, failure) &&
                    failure.empty() && plan.specs.size() == 2 &&
                    plan.specs[0].name == "standard-standard"_ctv &&
                    plan.specs[1].name == "spot-spot"_ctv &&
                    !contains(plan.specs[0].body, "\"provisioningModel\":\"SPOT\""_ctv) &&
                    contains(plan.specs[1].body, "\"provisioningModel\":\"SPOT\""_ctv) &&
                    plan.timeout() == std::chrono::minutes(45),
                "mothership_gcp_template_plan_orders_standard_then_spot_and_selects_45m");

   MothershipProdigyCluster spotOnly = cluster;
   spotOnly.machineSchemas.clear();
   spotOnly.machineSchemas.push_back(planSchema("spot-only"_ctv, MachineLifetime::spot, 1));
   suite.expect(MothershipGcpManagedTemplatePlan::build(spotOnly, plan, failure) &&
                    plan.specs.size() == 1 && plan.specs[0].name == "spot-only-spot"_ctv &&
                    plan.timeout() == std::chrono::minutes(25),
                "mothership_gcp_template_plan_supports_spot_only_and_selects_25m");

   MothershipProdigyCluster invalid = cluster;
   invalid.machineSchemas[2].gcpInstanceTemplateSpot.clear();
   suite.expect(MothershipGcpManagedTemplatePlan::build(invalid, plan, failure) == false &&
                    plan.specs.empty() &&
                    failure == "gcp managed instance template name required"_ctv,
                "mothership_gcp_template_plan_is_transactional_when_second_spec_is_invalid");
}

static void testAbsentCreateMixedCompletion(TestSuite& suite)
{
   ScriptedHttpClient http = {};
   http.add(MultiCurlClient::Status::success, 404, {}, true);
   http.add(MultiCurlClient::Status::success, 200, R"json({"name":"create-op"})json"_ctv);
   http.add(MultiCurlClient::Status::success, 200,
            R"json({"status":"DONE","statusMessage":"template created"})json"_ctv,
            true);
   ScriptedDelayQueue delay = {};
   CoroutineStack stack = {};
   Vector<GcpManagedTemplateTransaction::Spec> specs = {};
   specs.push_back(spec("standard"_ctv, "one"_ctv));
   String failure = {};
   GcpManagedTemplateTransaction transaction(http.submission(), delay.submission(),
                                             "project"_ctv, "token"_ctv,
                                             MultiCurlClient::Clock::now() + std::chrono::minutes(1));

   transaction.run(&stack, specs, failure);
   suite.expect(stack.hasSuspendedCoroutines() && drive(stack, http, delay) && failure.empty(),
                "gcp_managed_template_absent_create_supports_inline_and_deferred_http");
   suite.expect(http.requests.size() == 3 && delay.delays.empty() &&
                    http.requests[0].method == MultiCurlClient::Method::get &&
                    http.requests[1].method == MultiCurlClient::Method::post &&
                    http.requests[2].method == MultiCurlClient::Method::get,
                "gcp_managed_template_absent_create_uses_probe_create_poll_order");
}

static void testExistingDeletePollCreate(TestSuite& suite)
{
   ScriptedHttpClient http = {};
   http.add(MultiCurlClient::Status::success, 200, "{}"_ctv);
   http.add(MultiCurlClient::Status::success, 200, R"json({"name":"delete-op"})json"_ctv, true);
   http.add(MultiCurlClient::Status::success, 200, R"json({"status":"RUNNING"})json"_ctv);
   http.add(MultiCurlClient::Status::success, 200, R"json({"status":"DONE"})json"_ctv, true);
   http.add(MultiCurlClient::Status::success, 200, R"json({"name":"create-op"})json"_ctv);
   http.add(MultiCurlClient::Status::success, 200, R"json({"status":"DONE"})json"_ctv, true);
   ScriptedDelayQueue delay = {};
   CoroutineStack stack = {};
   Vector<GcpManagedTemplateTransaction::Spec> specs = {};
   specs.push_back(spec("existing"_ctv, "replace"_ctv));
   String failure = {};
   GcpManagedTemplateTransaction transaction(http.submission(), delay.submission(),
                                             "project"_ctv, "token"_ctv,
                                             MultiCurlClient::Clock::now() + std::chrono::minutes(1));

   transaction.run(&stack, specs, failure);
   suite.expect(drive(stack, http, delay) && failure.empty(),
                "gcp_managed_template_existing_delete_poll_create_completes");
   suite.expect(http.requests.size() == 6 &&
                    http.requests[0].method == MultiCurlClient::Method::get &&
                    http.requests[1].method == MultiCurlClient::Method::delete_ &&
                    http.requests[2].method == MultiCurlClient::Method::get &&
                    http.requests[3].method == MultiCurlClient::Method::get &&
                    http.requests[4].method == MultiCurlClient::Method::post &&
                    http.requests[5].method == MultiCurlClient::Method::get,
                "gcp_managed_template_existing_uses_exact_mutation_order");
   suite.expect(delay.delays.size() == 1 &&
                    delay.delays[0] == GcpManagedTemplateTransaction::pollDelayUs &&
                    delay.deferredCompletions == 1,
                "gcp_managed_template_running_operation_uses_deferred_ring_delay");
   suite.expect(http.requests[1].overallDeadline <=
                    http.submissionTimes[1] + std::chrono::seconds(8) &&
                    http.requests[1].overallDeadline >
                    http.submissionTimes[1] + std::chrono::seconds(7),
                "gcp_managed_template_delete_uses_eight_second_mutation_clamp");
}

static void testDeleteNotFoundRace(TestSuite& suite)
{
   ScriptedHttpClient http = {};
   http.add(MultiCurlClient::Status::success, 200, "{}"_ctv, true);
   http.add(MultiCurlClient::Status::success, 404, {}, true);
   http.add(MultiCurlClient::Status::success, 200, R"json({"name":"create-op"})json"_ctv, true);
   http.add(MultiCurlClient::Status::success, 200, R"json({"status":"RUNNING"})json"_ctv, true);
   http.add(MultiCurlClient::Status::success, 200, R"json({"status":"DONE"})json"_ctv, true);
   ScriptedDelayQueue delay = {};
   delay.completeInline = true;
   CoroutineStack stack = {};
   Vector<GcpManagedTemplateTransaction::Spec> specs = {};
   specs.push_back(spec("raced"_ctv, "replace"_ctv));
   String failure = {};
   GcpManagedTemplateTransaction transaction(http.submission(), delay.submission(),
                                             "project"_ctv, "token"_ctv,
                                             MultiCurlClient::Clock::now() + std::chrono::minutes(1));

   transaction.run(&stack, specs, failure);
   suite.expect(!stack.hasSuspendedCoroutines() && failure.empty() && http.requests.size() == 5 &&
                    http.requests[1].method == MultiCurlClient::Method::delete_ &&
                    http.requests[2].method == MultiCurlClient::Method::post &&
                    delay.inlineCompletions == 1 &&
                    delay.delays.size() == 1 &&
                    delay.delays[0] == GcpManagedTemplateTransaction::pollDelayUs,
                "gcp_managed_template_delete_404_race_continues_to_create");
}

static void testAcceptedDeleteThenRejectedCreate(TestSuite& suite)
{
   ScriptedHttpClient http = {};
   http.add(MultiCurlClient::Status::success, 200, "{}"_ctv, true);
   http.add(MultiCurlClient::Status::success, 200, R"json({"name":"delete-op"})json"_ctv, true);
   http.add(MultiCurlClient::Status::success, 200, R"json({"status":"DONE"})json"_ctv, true);
   http.add(MultiCurlClient::Status::success, 409,
            R"json({"error":{"message":"create rejected"}})json"_ctv, true);
   ScriptedDelayQueue delay = {};
   CoroutineStack stack = {};
   Vector<GcpManagedTemplateTransaction::Spec> specs = {};
   specs.push_back(spec("existing"_ctv, "replace"_ctv));
   String failure = {};
   GcpManagedTemplateTransaction transaction(http.submission(), delay.submission(),
                                             "project"_ctv, "token"_ctv,
                                             MultiCurlClient::Clock::now() + std::chrono::minutes(1));

   transaction.run(&stack, specs, failure);
   suite.expect(failure ==
                    "gcp managed template cloud state may be partial after accepted mutation of 'existing': create rejected"_ctv &&
                    http.requests.size() == 4 &&
                    http.requests[1].method == MultiCurlClient::Method::delete_ &&
                    http.requests[3].method == MultiCurlClient::Method::post,
                "gcp_managed_template_completed_delete_then_rejected_create_reports_partial_state");
}

static void testOrderedStandardSpotPartialFailure(TestSuite& suite)
{
   ScriptedHttpClient http = {};
   http.add(MultiCurlClient::Status::success, 404, {}, true);
   http.add(MultiCurlClient::Status::success, 200, R"json({"name":"standard-create"})json"_ctv, true);
   http.add(MultiCurlClient::Status::success, 200, R"json({"status":"DONE"})json"_ctv, true);
   http.add(MultiCurlClient::Status::success, 404, {}, true);
   http.add(MultiCurlClient::Status::success, 409,
            R"json({"error":{"message":"spot rejected"}})json"_ctv, true);
   ScriptedDelayQueue delay = {};
   CoroutineStack stack = {};
   Vector<GcpManagedTemplateTransaction::Spec> specs = {};
   specs.push_back(spec("standard-template"_ctv, "standard"_ctv));
   specs.push_back(spec("spot-template"_ctv, "spot"_ctv));
   String failure = {};
   GcpManagedTemplateTransaction transaction(http.submission(), delay.submission(),
                                             "project"_ctv, "token"_ctv,
                                             MultiCurlClient::Clock::now() + std::chrono::minutes(1));

   transaction.run(&stack, specs, failure);
   suite.expect(failure == "gcp managed template cloud state is partial after prior template completion: spot rejected"_ctv &&
                    http.requests.size() == 5,
                "gcp_managed_template_spot_failure_reports_partial_cloud_mutation");
   suite.expect(http.requests[0].url ==
                    "https://compute.googleapis.com/compute/v1/projects/project/global/instanceTemplates/standard-template"_ctv &&
                    http.requests[1].body == specs[0].body &&
                    http.requests[3].url ==
                    "https://compute.googleapis.com/compute/v1/projects/project/global/instanceTemplates/spot-template"_ctv &&
                    http.requests[4].body == specs[1].body,
                "gcp_managed_template_runs_standard_fully_before_spot");
}

static void testDuplicatePrevalidation(TestSuite& suite)
{
   ScriptedHttpClient http = {};
   ScriptedDelayQueue delay = {};
   CoroutineStack stack = {};
   Vector<GcpManagedTemplateTransaction::Spec> specs = {};
   specs.push_back(spec("duplicate"_ctv, "standard"_ctv));
   specs.push_back(spec("duplicate"_ctv, "spot"_ctv));
   String failure = {};
   GcpManagedTemplateTransaction transaction(http.submission(), delay.submission(),
                                             "project"_ctv, "token"_ctv,
                                             MultiCurlClient::Clock::now() + std::chrono::minutes(1));

   transaction.run(&stack, specs, failure);
   suite.expect(failure == "gcp managed template transaction requires distinct template names"_ctv &&
                    http.requests.empty() && delay.delays.empty() && !stack.hasSuspendedCoroutines(),
                "gcp_managed_template_duplicate_names_fail_before_requests");

   ScriptedHttpClient invalidHttp = {};
   ScriptedDelayQueue invalidDelay = {};
   CoroutineStack invalidStack = {};
   Vector<GcpManagedTemplateTransaction::Spec> invalidSpecs = {};
   invalidSpecs.push_back(spec("standard"_ctv, "valid"_ctv));
   GcpManagedTemplateTransaction::Spec invalidSpot = {};
   invalidSpot.name = "spot"_ctv;
   invalidSpecs.push_back(std::move(invalidSpot));
   failure.clear();
   GcpManagedTemplateTransaction invalidTransaction(
       invalidHttp.submission(), invalidDelay.submission(), "project"_ctv, "token"_ctv,
       MultiCurlClient::Clock::now() + std::chrono::minutes(1));
   invalidTransaction.run(&invalidStack, invalidSpecs, failure);
   suite.expect(failure == "gcp managed template transaction contains invalid template"_ctv &&
                    invalidHttp.requests.empty() && invalidDelay.delays.empty(),
                "gcp_managed_template_invalid_second_spec_fails_before_requests");
}

static String runSingleFailure(ScriptedHttpClient& http)
{
   ScriptedDelayQueue delay = {};
   delay.completeInline = true;
   CoroutineStack stack = {};
   Vector<GcpManagedTemplateTransaction::Spec> specs = {};
   specs.push_back(spec("template"_ctv, "failure"_ctv));
   String failure = {};
   GcpManagedTemplateTransaction transaction(http.submission(), delay.submission(),
                                             "project"_ctv, "token"_ctv,
                                             MultiCurlClient::Clock::now() + std::chrono::minutes(1));
   transaction.run(&stack, specs, failure);
   drive(stack, http, delay);
   return failure;
}

static String acceptedMutationFailure(const String& detail)
{
   String failure = {};
   failure.assign("gcp managed template cloud state may be partial after accepted mutation of 'template': "_ctv);
   failure.append(detail);
   return failure;
}

static void testMalformedOperationData(TestSuite& suite)
{
   {
      ScriptedHttpClient http = {};
      http.add(MultiCurlClient::Status::success, 404, {}, true);
      http.add(MultiCurlClient::Status::success, 200, "{"_ctv, true);
      suite.expect(runSingleFailure(http) == acceptedMutationFailure(
                       "gcp compute operation response parse failed"_ctv),
                   "gcp_managed_template_rejects_malformed_mutation_operation");
   }
   {
      ScriptedHttpClient http = {};
      http.add(MultiCurlClient::Status::success, 404, {}, true);
      http.add(MultiCurlClient::Status::success, 200, "{}"_ctv, true);
      suite.expect(runSingleFailure(http) == acceptedMutationFailure(
                       "gcp compute operation response missing name"_ctv),
                   "gcp_managed_template_rejects_missing_mutation_operation_name");
   }
   {
      ScriptedHttpClient http = {};
      http.add(MultiCurlClient::Status::success, 404, {}, true);
      http.add(MultiCurlClient::Status::success, 200, R"json({"name":"operation"})json"_ctv, true);
      http.add(MultiCurlClient::Status::success, 200, "{"_ctv, true);
      suite.expect(runSingleFailure(http) == acceptedMutationFailure(
                       "gcp compute operation poll response parse failed"_ctv),
                   "gcp_managed_template_rejects_malformed_poll_operation");
   }
   {
      ScriptedHttpClient http = {};
      http.add(MultiCurlClient::Status::success, 404, {}, true);
      http.add(MultiCurlClient::Status::success, 200, R"json({"name":"operation"})json"_ctv, true);
      http.add(MultiCurlClient::Status::success, 200, "{}"_ctv, true);
      suite.expect(runSingleFailure(http) == acceptedMutationFailure(
                       "gcp compute operation poll response missing status"_ctv),
                   "gcp_managed_template_rejects_missing_poll_status");
   }
   {
      ScriptedHttpClient http = {};
      http.add(MultiCurlClient::Status::success, 404, {}, true);
      http.add(MultiCurlClient::Status::success, 200, R"json({"name":"operation"})json"_ctv, true);
      http.add(MultiCurlClient::Status::success, 200,
               R"json({"status":"DONE","error":{"errors":[{"message":"operation rejected"}]}})json"_ctv,
               true);
      suite.expect(runSingleFailure(http) == acceptedMutationFailure("operation rejected"_ctv),
                   "gcp_managed_template_propagates_nested_operation_failure");
   }
   {
      ScriptedHttpClient http = {};
      http.add(MultiCurlClient::Status::success, 404, {}, true);
      http.add(MultiCurlClient::Status::success, 200, R"json({"name":"operation"})json"_ctv, true);
      http.add(MultiCurlClient::Status::success, 200, R"json({"status":"UNKNOWN"})json"_ctv, true);
      suite.expect(runSingleFailure(http) == acceptedMutationFailure(
                       "gcp compute operation poll response has invalid status"_ctv),
                   "gcp_managed_template_rejects_unknown_poll_status");
   }
}

static void testRequestFailuresAndDeadline(TestSuite& suite)
{
   {
      ScriptedHttpClient http = {};
      http.add(MultiCurlClient::Status::success, 403,
               R"json({"error":{"message":"permission denied"}})json"_ctv, true);
      suite.expect(runSingleFailure(http) == "permission denied"_ctv,
                   "gcp_managed_template_propagates_api_failure");
   }
   {
      ScriptedHttpClient http = {};
      http.add(MultiCurlClient::Status::transportFailure, 0, {}, true);
      suite.expect(runSingleFailure(http) == "gcp managed template probe transport failed"_ctv,
                   "gcp_managed_template_reports_transport_failure");
   }
   {
      ScriptedHttpClient http = {};
      http.add(MultiCurlClient::Status::responseTooLarge, 0, {}, true);
      suite.expect(runSingleFailure(http) == "gcp managed template response exceeds 1 MiB"_ctv,
                   "gcp_managed_template_reports_response_cap");
   }
   {
      ScriptedHttpClient http = {};
      http.add(MultiCurlClient::Status::deadlineExceeded, 0, {}, true);
      suite.expect(runSingleFailure(http) == "gcp managed template deadline exceeded"_ctv,
                   "gcp_managed_template_reports_request_deadline");
   }
   {
      ScriptedHttpClient http = {};
      ScriptedDelayQueue delay = {};
      CoroutineStack stack = {};
      Vector<GcpManagedTemplateTransaction::Spec> specs = {};
      specs.push_back(spec("template"_ctv, "expired"_ctv));
      String failure = {};
      GcpManagedTemplateTransaction transaction(http.submission(), delay.submission(),
                                                "project"_ctv, "token"_ctv,
                                                MultiCurlClient::Clock::now() - std::chrono::milliseconds(1));
      transaction.run(&stack, specs, failure);
      suite.expect(failure == "gcp managed template deadline exceeded"_ctv &&
                       http.requests.empty(),
                   "gcp_managed_template_expired_transaction_makes_no_request");
   }
   {
      ScriptedHttpClient http = {};
      http.add(MultiCurlClient::Status::success, 404, {}, true);
      http.add(MultiCurlClient::Status::success, 200, R"json({"name":"operation"})json"_ctv, true);
      http.add(MultiCurlClient::Status::success, 200, R"json({"status":"RUNNING"})json"_ctv, true);
      ScriptedDelayQueue delay = {};
      delay.completeInline = true;
      CoroutineStack stack = {};
      Vector<GcpManagedTemplateTransaction::Spec> specs = {};
      specs.push_back(spec("template"_ctv, "near-deadline"_ctv));
      String failure = {};
      GcpManagedTemplateTransaction transaction(
          http.submission(), delay.submission(), "project"_ctv, "token"_ctv,
          MultiCurlClient::Clock::now() +
              std::chrono::microseconds(GcpManagedTemplateTransaction::pollDelayUs - 1));
      transaction.run(&stack, specs, failure);
      suite.expect(failure == acceptedMutationFailure(
                                  "gcp managed template operation deadline exceeded"_ctv) &&
                       http.requests.size() == 3 && delay.delays.empty() &&
                       !stack.hasSuspendedCoroutines(),
                   "gcp_managed_template_near_deadline_refuses_unfinishable_poll_delay");
   }
}

static void testEncodedPathsAndRequestPolicy(TestSuite& suite)
{
   ScriptedHttpClient http = {};
   http.add(MultiCurlClient::Status::success, 404, {}, true);
   http.add(MultiCurlClient::Status::success, 200, R"json({"name":"operation /+"})json"_ctv, true);
   http.add(MultiCurlClient::Status::success, 200, R"json({"status":"DONE"})json"_ctv, true);
   ScriptedDelayQueue delay = {};
   CoroutineStack stack = {};
   Vector<GcpManagedTemplateTransaction::Spec> specs = {};
   specs.push_back(spec("template /+"_ctv, "encoded"_ctv));
   String failure = {};
   const MultiCurlClient::TimePoint transactionDeadline =
       MultiCurlClient::Clock::now() + std::chrono::seconds(30);
   GcpManagedTemplateTransaction transaction(http.submission(), delay.submission(),
                                             "project /+"_ctv, "secret"_ctv,
                                             transactionDeadline);

   transaction.run(&stack, specs, failure);
   suite.expect(failure.empty() && http.requests.size() == 3 &&
                    http.requests[0].url ==
                    "https://compute.googleapis.com/compute/v1/projects/project%20%2F%2B/global/instanceTemplates/template%20%2F%2B"_ctv &&
                    http.requests[1].url ==
                    "https://compute.googleapis.com/compute/v1/projects/project%20%2F%2B/global/instanceTemplates"_ctv &&
                    http.requests[2].url ==
                    "https://compute.googleapis.com/compute/v1/projects/project%20%2F%2B/global/operations/operation%20%2F%2B?fields=status,error,httpErrorStatusCode,httpErrorMessage,statusMessage"_ctv,
                "gcp_managed_template_percent_encodes_project_template_and_operation_paths");

   bool policyValid = true;
   for (uint32_t index = 0; index < http.requests.size(); ++index)
   {
      const MultiCurlClient::Request& request = http.requests[index];
      const std::chrono::seconds timeout =
          request.method == MultiCurlClient::Method::get ? std::chrono::seconds(3) :
                                                          std::chrono::seconds(8);
      policyValid = policyValid && request.resolveHost == "compute.googleapis.com"_ctv &&
                    request.authority == "compute.googleapis.com"_ctv &&
                    request.family == AsyncDnsResolver::Family::ipv4 &&
                    request.caSource == MultiCurlClient::CaSource::system && request.requireTls &&
                    request.connectTimeout == std::chrono::seconds(3) &&
                    request.responseBytes == GcpManagedTemplateTransaction::responseBytes &&
                    request.overallDeadline <= transactionDeadline &&
                    request.overallDeadline <= http.submissionTimes[index] + timeout &&
                    request.overallDeadline > http.submissionTimes[index] &&
                    request.originPolicy.accepts("https"_ctv,
                                                 "compute.googleapis.com"_ctv,
                                                 "compute.googleapis.com"_ctv,
                                                 "443"_ctv,
                                                 "compute.googleapis.com"_ctv) &&
                    !request.originPolicy.accepts("https"_ctv,
                                                  "evil.googleapis.com"_ctv,
                                                  "compute.googleapis.com"_ctv,
                                                  "443"_ctv,
                                                  "compute.googleapis.com"_ctv) &&
                    hasHeader(request, "Authorization"_ctv, "Bearer secret"_ctv);
   }
   suite.expect(policyValid,
                "gcp_managed_template_requests_enforce_exact_origin_timeouts_and_1mib_cap");
   suite.expect(http.requests[0].method == MultiCurlClient::Method::get &&
                    http.requests[1].method == MultiCurlClient::Method::post &&
                    http.requests[2].method == MultiCurlClient::Method::get &&
                    hasHeader(http.requests[1], "Content-Type"_ctv, "application/json"_ctv) &&
                    !hasHeader(http.requests[0], "Content-Type"_ctv, "application/json"_ctv),
                "gcp_managed_template_requests_use_exact_methods_and_content_header");
}

static void testPollLimit(TestSuite& suite)
{
   ScriptedHttpClient http = {};
   http.add(MultiCurlClient::Status::success, 404, {}, true);
   http.add(MultiCurlClient::Status::success, 200, R"json({"name":"long-operation"})json"_ctv, true);
   for (uint32_t poll = 0; poll < GcpManagedTemplateTransaction::maximumPolls; ++poll)
   {
      http.add(MultiCurlClient::Status::success, 200, R"json({"status":"RUNNING"})json"_ctv, true);
   }
   ScriptedDelayQueue delay = {};
   CoroutineStack stack = {};
   Vector<GcpManagedTemplateTransaction::Spec> specs = {};
   specs.push_back(spec("template"_ctv, "long"_ctv));
   String failure = {};
   GcpManagedTemplateTransaction transaction(http.submission(), delay.submission(),
                                             "project"_ctv, "token"_ctv,
                                             MultiCurlClient::Clock::now() + std::chrono::minutes(20));

   transaction.run(&stack, specs, failure);
   suite.expect(drive(stack, http, delay) &&
                    failure == acceptedMutationFailure(
                                   "gcp managed template operation poll limit exceeded"_ctv),
                "gcp_managed_template_caps_operation_poll_observations");
   suite.expect(http.requests.size() == GcpManagedTemplateTransaction::maximumPolls + 2 &&
                    delay.delays.size() == GcpManagedTemplateTransaction::maximumPolls - 1,
                "gcp_managed_template_poll_cap_has_exact_request_and_delay_counts");
}

int main(void)
{
   TestSuite suite = {};
   testBuildSpec(suite);
   testMothershipPlan(suite);
   testAbsentCreateMixedCompletion(suite);
   testExistingDeletePollCreate(suite);
   testDeleteNotFoundRace(suite);
   testAcceptedDeleteThenRejectedCreate(suite);
   testOrderedStandardSpotPartialFailure(suite);
   testDuplicatePrevalidation(suite);
   testMalformedOperationData(suite);
   testRequestFailuresAndDeadline(suite);
   testEncodedPathsAndRequestPolicy(suite);
   testPollLimit(suite);
   return suite.failed == 0 ? 0 : 1;
}
