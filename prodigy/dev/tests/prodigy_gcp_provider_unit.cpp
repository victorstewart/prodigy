#include <networking/includes.h>
#include <services/debug.h>
#include <prodigy/iaas/gcp/gcp.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

class TestSuite {
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    if (condition == false)
    {
      std::fprintf(stderr, "FAIL: %s\n", name);
      failed += 1;
    }
  }
};

class ScriptedGcpMetadataClient {
public:

  using Operation = ProdigyHostHttpOperation;
  Operation::Callback callback = {};
  Operation::Ticket ticket = {};
  Vector<Operation::Request> requests;
  Vector<String> urls;
  Vector<String> inlineBodies;
  String inlineBody = {};
  MultiCurlClient::Status inlineStatus = MultiCurlClient::Status::success;
  long inlineStatusCode = 200;
  bool completeInline = false;
  bool invalidTicket = false;

  static Operation::Ticket submit(void *context, Operation::Request&& request, Operation::Callback callback)
  {
    ScriptedGcpMetadataClient& client = *static_cast<ScriptedGcpMetadataClient *>(context);
    client.ticket = {client.ticket.identifier + 1, 1};
    client.callback = callback;
    client.urls.push_back(request.url);
    client.requests.push_back(std::move(request));
    if (client.completeInline)
    {
      const size_t index = client.urls.size() - 1;
      client.complete(client.inlineStatus, client.inlineStatusCode,
                      index < client.inlineBodies.size() ? client.inlineBodies[index] : client.inlineBody);
    }
    if (client.invalidTicket)
    {
      return {};
    }
    return client.ticket;
  }

  static bool cancel(void *, Operation::Ticket)
  {
    return true;
  }

  Operation::Submission submission(void)
  {
    return {this, submit, cancel};
  }

  void complete(MultiCurlClient::Status status, long statusCode, const String& body)
  {
    Operation::Result result = {};
    result.status = status;
    result.statusCode = statusCode;
    result.body = body;
    Operation::Callback completion = callback;
    completion.function(completion.context, ticket, std::move(result));
  }
};

class TestableGcpBrainIaaS : public GcpBrainIaaS {
private:

  ScriptedGcpMetadataClient *client = nullptr;

protected:

  ProdigyHostHttpOperation::Submission hostHttpSubmission(void) override
  {
    return client ? client->submission() : ProdigyHostHttpOperation::Submission {};
  }

public:

  void useClient(ScriptedGcpMetadataClient& requestedClient)
  {
    client = &requestedClient;
  }

  bool parseMetadataTokenForTest(const String& response, String& failure)
  {
    return parseMetadataAccessToken(response, &failure);
  }

  void ensureTokenAsyncForTest(CoroutineStack *coro,
                               bool& success,
                               String& failure,
                               MultiCurlClient::TimePoint deadline)
  {
    ensureTokenAsync(coro, success, &failure, deadline);
  }
};

static bool stringContains(const String& haystack, const char *needle);

static bool stringContains(const String& haystack, const char *needle)
{
  size_t needleLength = std::strlen(needle);
  if (needleLength == 0)
  {
    return true;
  }

  return std::search(haystack.data(),
                     haystack.data() + haystack.size(),
                     needle,
                     needle + needleLength) != (haystack.data() + haystack.size());
}

static String gcpValidationProjectPermissions(void)
{
  return String(
      "{\"permissions\":["
      "\"compute.disks.create\",\"compute.disks.delete\","
      "\"compute.instanceTemplates.create\",\"compute.instanceTemplates.delete\","
      "\"compute.instanceTemplates.get\",\"compute.instanceTemplates.useReadOnly\","
      "\"compute.instances.create\",\"compute.instances.delete\",\"compute.instances.get\","
      "\"compute.instances.list\",\"compute.instances.setLabels\",\"compute.instances.setMetadata\","
      "\"compute.instances.setServiceAccount\",\"compute.machineTypes.get\",\"compute.networks.get\","
      "\"compute.subnetworks.get\",\"compute.subnetworks.use\",\"compute.subnetworks.useExternalIp\","
      "\"compute.zones.get\"]}"_ctv);
}

int main(void)
{
  TestSuite suite = {};

  {
    ScriptedGcpMetadataClient client = {};
    CoroutineStack stack = {};
    String metro = {};
    gcpReadNeuronStartupMetro(client.submission(), &stack, metro);
    suite.expect(stack.hasSuspendedCoroutines() && client.urls.size() == 1 &&
                     client.urls[0] == "http://169.254.169.254/computeMetadata/v1/instance/zone"_ctv,
                 "gcp_neuron_startup_suspends_for_numeric_zone_metadata");
    client.complete(MultiCurlClient::Status::success, 200,
                    "projects/test-project/zones/us-central1-a"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() == false && client.urls.size() == 1 && metro == "us-central1-a"_ctv,
                 "gcp_neuron_startup_resumes_with_zone_without_dead_role_request");
  }

  {
    ScriptedGcpMetadataClient client = {};
    client.completeInline = true;
    client.inlineBody = "projects/test-project/zones/us-east1-b"_ctv;
    CoroutineStack stack = {};
    String metro = {};
    gcpReadNeuronStartupMetro(client.submission(), &stack, metro);
    suite.expect(stack.hasSuspendedCoroutines() == false && client.urls.size() == 1 && metro == "us-east1-b"_ctv,
                 "gcp_neuron_startup_accepts_inline_metadata_completion");
  }

  {
    ScriptedGcpMetadataClient client = {};
    CoroutineStack stack = {};
    String metro = {};
    gcpReadNeuronStartupMetro(client.submission(), &stack, metro);
    client.complete(MultiCurlClient::Status::transportFailure, 200,
                    "projects/test-project/zones/ignored"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() == false && client.urls.size() == 1 && metro.size() == 0,
                 "gcp_neuron_startup_rejects_transport_failure");
  }

  {
    ScriptedGcpMetadataClient client = {};
    client.invalidTicket = true;
    CoroutineStack stack = {};
    String metro = {};
    gcpReadNeuronStartupMetro(client.submission(), &stack, metro);
    suite.expect(stack.hasSuspendedCoroutines() == false && client.urls.size() == 1 && metro.size() == 0,
                 "gcp_neuron_startup_rejects_invalid_submission_inline");
  }

  {
    const auto now = MultiCurlClient::Clock::now();
    MultiCurlClient::Request request = GcpBrainIaaS::metadataRequest("/computeMetadata/v1/project/project-id"_ctv, now);
    suite.expect(request.url == "http://169.254.169.254/computeMetadata/v1/project/project-id"_ctv, "gcp_spot_metadata_numeric_url");
    suite.expect(request.resolveHost == "169.254.169.254"_ctv && request.authority == "metadata.google.internal"_ctv, "gcp_spot_metadata_connect_authority_split");
    suite.expect(request.httpPolicy == MultiCurlClient::HttpPolicy::requireHttp1 && request.family == AsyncDnsResolver::Family::ipv4 && request.requireTls == false, "gcp_spot_metadata_http1_ipv4_cleartext");
    suite.expect(request.connectTimeout == std::chrono::seconds(3) && request.overallDeadline == now + std::chrono::seconds(3) && request.responseBytes == GcpBrainIaaS::metadataResponseBytes, "gcp_spot_metadata_bounded_request");
    suite.expect(request.headers.size() == 1 && request.headers[0].name == "Metadata-Flavor"_ctv && request.headers[0].value == "Google"_ctv, "gcp_spot_metadata_flavor_header");
    suite.expect(request.originPolicy.accepts("http"_ctv, "169.254.169.254"_ctv, "metadata.google.internal"_ctv, "80"_ctv, "169.254.169.254"_ctv), "gcp_spot_metadata_exact_origin_accepts");
    suite.expect(request.originPolicy.accepts("http"_ctv, "metadata.google.internal"_ctv, "metadata.google.internal"_ctv, "80"_ctv, "169.254.169.254"_ctv) == false, "gcp_spot_metadata_exact_origin_rejects_named_url");
    suite.expect(stringContains(request.url, "metadata.google.internal") == false && request.resolveHost == request.originPolicy.requiredResolveHost && request.resolveHost == "169.254.169.254"_ctv, "gcp_spot_metadata_dns_identity_is_numeric_only");
  }

  {
    const auto now = MultiCurlClient::Clock::now();
    const auto operationDeadline = now + std::chrono::seconds(1);
    MultiCurlClient::Request request = GcpBrainIaaS::spotInstancesRequest("test-project"_ctv, "us-central1-a"_ctv, "secret-token"_ctv, "next page/+"_ctv, now, operationDeadline);
    suite.expect(request.url == "https://compute.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/instances?filter=labels.app%3Aprodigy&maxResults=500&fields=items(id,labels,scheduling(preemptible,provisioningModel),status),nextPageToken&pageToken=next%20page%2F%2B"_ctv, "gcp_spot_compute_url_and_encoded_page");
    suite.expect(request.family == AsyncDnsResolver::Family::ipv4 && request.caSource == MultiCurlClient::CaSource::system && request.requireTls, "gcp_spot_compute_ipv4_system_ca_tls");
    suite.expect(request.connectTimeout == std::chrono::seconds(3) && request.overallDeadline == operationDeadline && request.responseBytes == GcpBrainIaaS::spotPageResponseBytes, "gcp_spot_compute_bounded_request");
    suite.expect(request.headers.size() == 1 && request.headers[0].name == "Authorization"_ctv && request.headers[0].value == "Bearer secret-token"_ctv, "gcp_spot_compute_bearer_header");
    suite.expect(request.originPolicy.accepts("https"_ctv, "compute.googleapis.com"_ctv, "compute.googleapis.com"_ctv, "443"_ctv, "compute.googleapis.com"_ctv), "gcp_spot_compute_exact_origin_accepts");
    suite.expect(request.originPolicy.accepts("https"_ctv, "evil.googleapis.com"_ctv, "compute.googleapis.com"_ctv, "443"_ctv, "compute.googleapis.com"_ctv) == false, "gcp_spot_compute_exact_origin_rejects_host");
  }

  {
    const auto now = MultiCurlClient::Clock::now();
    const auto deadline = now + std::chrono::seconds(2);
    MultiCurlClient::Request request = GcpBrainIaaS::inventoryInstancesRequest(
        "test-project"_ctv, "us-central1-a"_ctv, "inventory-token"_ctv,
        "next page/+"_ctv, now, deadline);
    suite.expect(stringContains(request.url, "maxResults=500") &&
                     stringContains(request.url, "resourceStatus(physicalHost,physicalHostTopology(cluster,block,subblock))") &&
                     stringContains(request.url, "pageToken=next%20page%2F%2B"),
                 "gcp_inventory_uses_exact_bounded_fields_and_encoded_page");
    suite.expect(stringContains(request.url, ",physicalHost,") == false,
                 "gcp_inventory_does_not_request_invalid_top_level_physical_host");
    suite.expect(request.resolveHost == "compute.googleapis.com"_ctv &&
                     request.authority == "compute.googleapis.com"_ctv &&
                     request.family == AsyncDnsResolver::Family::ipv4 &&
                     request.caSource == MultiCurlClient::CaSource::system && request.requireTls,
                 "gcp_inventory_uses_exact_tls_compute_origin");
    suite.expect(request.connectTimeout == std::chrono::seconds(3) &&
                     request.overallDeadline == deadline &&
                     request.responseBytes == GcpBrainIaaS::inventoryPageResponseBytes,
                 "gcp_inventory_request_has_subdeadline_and_response_cap");
    suite.expect(request.headers.size() == 1 &&
                     request.headers[0].name == "Authorization"_ctv &&
                     request.headers[0].value == "Bearer inventory-token"_ctv,
                 "gcp_inventory_uses_bearer_header");

    bytell_hash_set<String> requestedPageTokens = {};
    requestedPageTokens.insert("repeated"_ctv);
    suite.expect(GcpBrainIaaS::canRequestInventoryPage(0, 0, String(), requestedPageTokens),
                 "gcp_inventory_first_page_allowed");
    suite.expect(GcpBrainIaaS::canRequestInventoryPage(1, 1, "repeated"_ctv, requestedPageTokens) == false,
                 "gcp_inventory_repeated_page_rejected");
    suite.expect(GcpBrainIaaS::canRequestInventoryPage(GcpBrainIaaS::inventoryMaxPages, 0, "new"_ctv, requestedPageTokens) == false &&
                     GcpBrainIaaS::canRequestInventoryPage(0, GcpBrainIaaS::inventoryMaxInstances, "new"_ctv, requestedPageTokens) == false,
                 "gcp_inventory_page_and_result_counts_capped");
    String oversizedToken = {};
    oversizedToken.reserve(GcpBrainIaaS::inventoryPageTokenBytes + 1);
    for (size_t index = 0; index <= GcpBrainIaaS::inventoryPageTokenBytes; ++index)
    {
      oversizedToken.append('x');
    }
    suite.expect(GcpBrainIaaS::canRequestInventoryPage(0, 0, oversizedToken, requestedPageTokens) == false,
                 "gcp_inventory_page_token_capped");
  }

  {
    const MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now();
    const MultiCurlClient::TimePoint getDeadline = now + std::chrono::seconds(1);
    MultiCurlClient::Request compute = GcpBrainIaaS::computeValidationRequest(
        "https://compute.googleapis.com/compute/v1/projects/p/zones/z"_ctv,
        "token"_ctv, now, getDeadline);
    suite.expect(compute.connectTimeout == std::chrono::seconds(3) &&
                     compute.overallDeadline == getDeadline &&
                     compute.responseBytes == GcpBrainIaaS::validationResponseBytes &&
                     compute.method == MultiCurlClient::Method::get,
                 "gcp_validation_compute_get_deadline_and_caps");
    String body = "{}"_ctv;
    MultiCurlClient::Request iam = GcpBrainIaaS::iamValidationRequest(
        "https://iam.googleapis.com/v1/projects/p/serviceAccounts/a:testIamPermissions"_ctv,
        "iam.googleapis.com"_ctv, "token"_ctv, body, now,
        now + std::chrono::seconds(30));
    suite.expect(iam.connectTimeout == std::chrono::seconds(3) &&
                     iam.overallDeadline == now + std::chrono::seconds(8) &&
                     iam.responseBytes == GcpBrainIaaS::validationResponseBytes &&
                     iam.method == MultiCurlClient::Method::post,
                 "gcp_validation_iam_post_deadline_and_caps");
  }

  {
    ScriptedGcpMetadataClient client = {};
    client.completeInline = true;
    client.inlineBodies.push_back(R"json({"name":"n2-standard-2","architecture":"X86_64"})json"_ctv);
    client.inlineBodies.push_back(R"json({"availableCpuPlatforms":["Intel Cascade Lake"]})json"_ctv);
    client.inlineBodies.push_back(R"json({"name":"c3-standard-4","architecture":"X86_64"})json"_ctv);
    TestableGcpBrainIaaS brain = {};
    brain.useClient(client);
    ProdigyRuntimeEnvironmentConfig runtime = {};
    runtime.kind = ProdigyEnvironmentKind::gcp;
    runtime.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
    runtime.providerCredentialMaterial = "validation-token"_ctv;
    brain.configureRuntimeEnvironment(runtime);

    CoroutineStack stack = {};
    MachineConfig config = {};
    config.providerMachineType = "n2-standard-2"_ctv;
    MachineSchemaCpuCapability capability = {};
    String failure = {};
    brain.inferMachineSchemaCpuCapability(&stack, config, capability, failure);
    suite.expect(failure.empty() && capability.architecture == MachineCpuArchitecture::x86_64 &&
                     capability.provenance == MachineSchemaCpuCapabilityProvenance::providerAuthoritative,
                 "gcp_validation_inference_inline_success");
    suite.expect(client.requests.size() == 2 &&
                     stringContains(client.requests[0].url, "/machineTypes/n2-standard-2?fields=name,architecture") &&
                     stringContains(client.requests[1].url, "/zones/us-central1-a?fields=availableCpuPlatforms"),
                 "gcp_validation_inference_fetches_machine_and_zone_once");

    capability = {};
    brain.inferMachineSchemaCpuCapability(&stack, config, capability, failure);
    suite.expect(failure.empty() && client.requests.size() == 2,
                 "gcp_validation_inference_deduplicates_machine_type");
    config.providerMachineType = "c3-standard-4"_ctv;
    brain.inferMachineSchemaCpuCapability(&stack, config, capability, failure);
    suite.expect(failure.empty() && client.requests.size() == 3 &&
                     stringContains(client.requests[2].url, "/machineTypes/c3-standard-4?fields=name,architecture"),
                 "gcp_validation_inference_reuses_single_zone_fetch_for_distinct_type");
    suite.expect(client.requests[0].method == MultiCurlClient::Method::get &&
                     client.requests[0].responseBytes == GcpBrainIaaS::validationResponseBytes &&
                     client.requests[0].originPolicy.accepts("https"_ctv, "compute.googleapis.com"_ctv,
                                                             "compute.googleapis.com"_ctv, "443"_ctv,
                                                             "compute.googleapis.com"_ctv),
                 "gcp_validation_compute_request_exact_origin_and_cap");
  }

  {
    ScriptedGcpMetadataClient client = {};
    client.completeInline = true;
    client.inlineBodies.push_back(gcpValidationProjectPermissions());
    client.inlineBodies.push_back(R"json({"permissions":["iam.serviceAccounts.actAs"]})json"_ctv);
    TestableGcpBrainIaaS brain = {};
    brain.useClient(client);
    ProdigyProviderServices services = {};
    services.operationDeadline = MultiCurlClient::Clock::now() + std::chrono::seconds(30);
    brain.configureProviderServices(services);
    ProdigyRuntimeEnvironmentConfig runtime = {};
    runtime.kind = ProdigyEnvironmentKind::gcp;
    runtime.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
    runtime.providerCredentialMaterial = "validation-token"_ctv;
    brain.configureRuntimeEnvironment(runtime);

    BrainIaaSClusterCreatePreflight preflight = {};
    preflight.gcpServiceAccountEmail = "prodigy@test-project.iam.gserviceaccount.com"_ctv;
    MachineConfig config = {};
    config.kind = MachineConfig::MachineKind::vm;
    config.vmImageURI = "projects/debian-cloud/global/images/family/debian-12"_ctv;
    config.providerMachineType = "n2-standard-2"_ctv;
    preflight.configs.push_back(config);
    CoroutineStack stack = {};
    String failure = {};
    brain.preflightClusterCreate(&stack, preflight, failure);
    suite.expect(failure.empty() && client.requests.size() == 2,
                 "gcp_validation_preflight_inline_success");
    suite.expect(client.requests[0].method == MultiCurlClient::Method::post &&
                     client.requests[0].responseBytes == GcpBrainIaaS::validationResponseBytes &&
                     client.requests[0].originPolicy.requiredHost == "cloudresourcemanager.googleapis.com"_ctv &&
                     stringContains(client.requests[0].body, "compute.instances.create"),
                 "gcp_validation_project_iam_exact_origin_method_cap_and_body");
    suite.expect(client.requests[1].method == MultiCurlClient::Method::post &&
                     client.requests[1].originPolicy.requiredHost == "iam.googleapis.com"_ctv &&
                     stringContains(client.requests[1].url, "prodigy%40test-project.iam.gserviceaccount.com:testIamPermissions") &&
                     stringContains(client.requests[1].body, "iam.serviceAccounts.actAs"),
                 "gcp_validation_service_account_iam_exact_origin_and_encoding");
  }

  {
    ScriptedGcpMetadataClient client = {};
    TestableGcpBrainIaaS brain = {};
    brain.useClient(client);
    ProdigyRuntimeEnvironmentConfig runtime = {};
    runtime.kind = ProdigyEnvironmentKind::gcp;
    runtime.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
    runtime.providerCredentialMaterial = "validation-token"_ctv;
    brain.configureRuntimeEnvironment(runtime);
    CoroutineStack stack = {};
    MachineConfig config = {};
    config.providerMachineType = "n2-standard-2"_ctv;
    MachineSchemaCpuCapability capability = {};
    String failure = {};
    brain.inferMachineSchemaCpuCapability(&stack, config, capability, failure);
    suite.expect(stack.hasSuspendedCoroutines() && client.requests.size() == 1,
                 "gcp_validation_inference_deferred_machine_suspends");
    client.complete(MultiCurlClient::Status::success, 200,
                    R"json({"name":"n2-standard-2","architecture":"X86_64"})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() && client.requests.size() == 2 &&
                     capability.architecture == MachineCpuArchitecture::unknown,
                 "gcp_validation_inference_defers_publication_until_zone_success");
    client.complete(MultiCurlClient::Status::deadlineExceeded, 0, String());
    suite.expect(stack.hasSuspendedCoroutines() == false &&
                     failure == "gcp validation deadline exceeded"_ctv &&
                     capability.architecture == MachineCpuArchitecture::unknown,
                 "gcp_validation_inference_deadline_failure_is_transactional");
  }

  {
    ScriptedGcpMetadataClient client = {};
    TestableGcpBrainIaaS brain = {};
    brain.useClient(client);
    ProdigyProviderServices services = {};
    services.operationDeadline = MultiCurlClient::Clock::now();
    brain.configureProviderServices(services);
    ProdigyRuntimeEnvironmentConfig runtime = {};
    runtime.kind = ProdigyEnvironmentKind::gcp;
    runtime.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
    runtime.providerCredentialMaterial = "validation-token"_ctv;
    brain.configureRuntimeEnvironment(runtime);
    CoroutineStack stack = {};
    MachineConfig config = {};
    config.providerMachineType = "n2-standard-2"_ctv;
    MachineSchemaCpuCapability capability = {};
    String failure = {};
    brain.inferMachineSchemaCpuCapability(&stack, config, capability, failure);
    suite.expect(client.requests.empty() && failure == "gcp validation deadline exceeded"_ctv,
                 "gcp_validation_expired_job_deadline_fails_before_submit");
  }

  {
    ScriptedGcpMetadataClient client = {};
    client.completeInline = true;
    client.inlineBodies.push_back(R"json({"name":"n2-standard-2","architecture":"X86_64"})json"_ctv);
    client.inlineBodies.push_back("{"_ctv);
    TestableGcpBrainIaaS brain = {};
    brain.useClient(client);
    ProdigyRuntimeEnvironmentConfig runtime = {};
    runtime.kind = ProdigyEnvironmentKind::gcp;
    runtime.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
    runtime.providerCredentialMaterial = "validation-token"_ctv;
    brain.configureRuntimeEnvironment(runtime);
    CoroutineStack stack = {};
    MachineConfig config = {};
    config.providerMachineType = "n2-standard-2"_ctv;
    MachineSchemaCpuCapability capability = {};
    String failure = {};
    brain.inferMachineSchemaCpuCapability(&stack, config, capability, failure);
    suite.expect(failure == "gcp zone cpu platform response parse failed"_ctv &&
                     capability.architecture == MachineCpuArchitecture::unknown,
                 "gcp_validation_malformed_zone_response_is_transactional");
  }

  {
    ScriptedGcpMetadataClient client = {};
    client.completeInline = true;
    client.inlineBodies.push_back(R"json({"permissions":["compute.disks.create"]})json"_ctv);
    client.inlineBodies.push_back(R"json({"permissions":[]})json"_ctv);
    TestableGcpBrainIaaS brain = {};
    brain.useClient(client);
    ProdigyRuntimeEnvironmentConfig runtime = {};
    runtime.kind = ProdigyEnvironmentKind::gcp;
    runtime.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
    runtime.providerCredentialMaterial = "validation-token"_ctv;
    brain.configureRuntimeEnvironment(runtime);
    BrainIaaSClusterCreatePreflight preflight = {};
    preflight.gcpServiceAccountEmail = "prodigy@test-project.iam.gserviceaccount.com"_ctv;
    MachineConfig config = {};
    config.kind = MachineConfig::MachineKind::vm;
    config.vmImageURI = "projects/debian-cloud/global/images/family/debian-12"_ctv;
    config.providerMachineType = "n2-standard-2"_ctv;
    preflight.configs.push_back(config);
    CoroutineStack stack = {};
    String failure = {};
    brain.preflightClusterCreate(&stack, preflight, failure);
    suite.expect(client.requests.size() == 2 &&
                     stringContains(failure, "compute.instanceTemplates.create") &&
                     stringContains(failure, "iam.serviceAccounts.actAs"),
                 "gcp_validation_preflight_aggregates_project_and_service_account_denials");
  }

  {
    ScriptedGcpMetadataClient client = {};
    CoroutineStack stack = {};
    String failure = {};
    size_t staged = 0;
    auto visit = [&](simdjson::dom::element) -> bool { ++staged; return true; };
    GcpBrainIaaS::readInventoryPages(client.submission(), &stack, "project"_ctv, "zone"_ctv,
                                     "token"_ctv, MultiCurlClient::Clock::now() + std::chrono::seconds(5),
                                     visit, failure);
    client.complete(MultiCurlClient::Status::success, 200,
                    R"json({"items":[{"labels":{"app":"prodigy"}}],"nextPageToken":"two"})json"_ctv);
    suite.expect(staged == 1 && failure.size() == 0 && stack.hasSuspendedCoroutines(),
                 "gcp_inventory_stages_page_one_before_page_two");
    client.complete(MultiCurlClient::Status::transportFailure, 0, String());
    suite.expect(staged == 1 && failure == "gcp inventory request failed"_ctv &&
                     stack.hasSuspendedCoroutines() == false,
                 "gcp_inventory_page_two_transport_failure_is_incomplete");
  }

  {
    ScriptedGcpMetadataClient client = {};
    CoroutineStack stack = {};
    String failure = {};
    size_t staged = 0;
    auto visit = [&](simdjson::dom::element) -> bool { ++staged; return true; };
    GcpBrainIaaS::readInventoryPages(client.submission(), &stack, "project"_ctv, "zone"_ctv,
                                     "token"_ctv, MultiCurlClient::Clock::now() + std::chrono::seconds(5),
                                     visit, failure);
    client.complete(MultiCurlClient::Status::success, 200,
                    R"json({"items":[{"labels":{"app":"prodigy"}}],"nextPageToken":"repeat"})json"_ctv);
    client.complete(MultiCurlClient::Status::success, 200,
                    R"json({"items":[{"labels":{"app":"prodigy"}}],"nextPageToken":"repeat"})json"_ctv);
    suite.expect(staged == 2 && failure == "gcp inventory repeated page token"_ctv,
                 "gcp_inventory_repeated_token_marks_partial_pages_incomplete");
  }

  {
    ScriptedGcpMetadataClient client = {};
    client.completeInline = true;
    for (size_t index = 0; index < GcpBrainIaaS::inventoryMaxPages; ++index)
    {
      String body = {};
      body.snprintf<"{\"nextPageToken\":\"page-{itoa}\"}"_ctv>(uint64_t(index + 1));
      client.inlineBodies.push_back(std::move(body));
    }
    CoroutineStack stack = {};
    String failure = {};
    auto visit = [](simdjson::dom::element) -> bool { return true; };
    GcpBrainIaaS::readInventoryPages(client.submission(), &stack, "project"_ctv, "zone"_ctv,
                                     "token"_ctv, MultiCurlClient::Clock::now() + std::chrono::seconds(5),
                                     visit, failure);
    suite.expect(client.urls.size() == GcpBrainIaaS::inventoryMaxPages &&
                     failure == "gcp inventory result limit exceeded"_ctv,
                 "gcp_inventory_page_cap_marks_continuation_incomplete");
  }

  {
    ScriptedGcpMetadataClient client = {};
    CoroutineStack stack = {};
    String failure = {};
    auto visit = [](simdjson::dom::element) -> bool { return true; };
    GcpBrainIaaS::readInventoryPages(client.submission(), &stack, "project"_ctv, "zone"_ctv,
                                     "token"_ctv, MultiCurlClient::Clock::now(), visit, failure);
    suite.expect(client.urls.empty() && failure == "gcp inventory deadline exceeded"_ctv,
                 "gcp_inventory_expired_absolute_deadline_fails_before_submit");
  }

  {
    ScriptedGcpMetadataClient client = {};
    client.completeInline = true;
    client.inlineBody = R"json({"items":{},"nextPageToken":"x"})json"_ctv;
    CoroutineStack stack = {};
    String failure = {};
    auto visit = [](simdjson::dom::element) -> bool { return true; };
    GcpBrainIaaS::readInventoryPages(client.submission(), &stack, "project"_ctv, "zone"_ctv,
                                     "token"_ctv, MultiCurlClient::Clock::now() + std::chrono::seconds(5),
                                     visit, failure);
    suite.expect(failure == "gcp inventory items field invalid"_ctv,
                 "gcp_inventory_rejects_present_non_array_items");

    ScriptedGcpMetadataClient tokenClient = {};
    tokenClient.completeInline = true;
    tokenClient.inlineBody = R"json({"nextPageToken":7})json"_ctv;
    failure.clear();
    GcpBrainIaaS::readInventoryPages(tokenClient.submission(), &stack, "project"_ctv, "zone"_ctv,
                                     "token"_ctv, MultiCurlClient::Clock::now() + std::chrono::seconds(5),
                                     visit, failure);
    suite.expect(failure == "gcp inventory page token invalid"_ctv,
                 "gcp_inventory_rejects_wrong_type_page_token");
  }

  {
    String page = R"json({"items":[
      {"id":"spot-terminated","labels":{"app":"prodigy"},"scheduling":{"provisioningModel":"SPOT"},"status":"TERMINATED"},
      {"id":"preemptible-terminated","labels":{"app":"prodigy"},"scheduling":{"preemptible":true},"status":"TERMINATED"},
      {"id":"spot-running","labels":{"app":"prodigy"},"scheduling":{"provisioningModel":"SPOT"},"status":"RUNNING"},
      {"id":"durable-terminated","labels":{"app":"prodigy"},"status":"TERMINATED"},
      {"id":"foreign-terminated","labels":{"app":"other"},"scheduling":{"provisioningModel":"SPOT"},"status":"TERMINATED"}
    ],"nextPageToken":"page-two"})json";
    Vector<String> decommissioned = {};
    String nextPage = {};
    suite.expect(GcpBrainIaaS::parseSpotTerminationPage(page, decommissioned, nextPage), "gcp_spot_page_parses");
    suite.expect(decommissioned.size() == 2 && decommissioned[0] == "spot-terminated"_ctv && decommissioned[1] == "preemptible-terminated"_ctv, "gcp_spot_page_selects_only_terminated_prodigy_spot_instances");
    suite.expect(nextPage == "page-two"_ctv, "gcp_spot_page_preserves_pagination");
    suite.expect(GcpBrainIaaS::parseSpotTerminationPage("{"_ctv, decommissioned, nextPage) == false && decommissioned.size() == 2, "gcp_spot_malformed_page_preserves_partial_results");

    Vector<String> capped = {};
    suite.expect(GcpBrainIaaS::parseSpotTerminationPage(page, capped, nextPage, 1) == false && capped.size() == 1, "gcp_spot_page_caps_decommissioned_ids");
  }

  {
    bytell_hash_set<String> requestedPageTokens = {};
    suite.expect(GcpBrainIaaS::canRequestSpotPage(0, 0, String(), requestedPageTokens), "gcp_spot_first_page_allowed");
    requestedPageTokens.insert("repeated"_ctv);
    suite.expect(GcpBrainIaaS::canRequestSpotPage(1, 0, "repeated"_ctv, requestedPageTokens) == false, "gcp_spot_repeated_page_token_rejected");
    suite.expect(GcpBrainIaaS::canRequestSpotPage(GcpBrainIaaS::spotCheckMaxPages, 0, "new"_ctv, requestedPageTokens) == false, "gcp_spot_page_count_capped");
    suite.expect(GcpBrainIaaS::canRequestSpotPage(0, GcpBrainIaaS::spotCheckMaxDecommissionedIDs, "new"_ctv, requestedPageTokens) == false, "gcp_spot_result_count_capped");
    String oversizedToken = {};
    oversizedToken.reserve(GcpBrainIaaS::spotPageTokenBytes + 1);
    for (size_t index = 0; index <= GcpBrainIaaS::spotPageTokenBytes; ++index)
    {
      oversizedToken.append('x');
    }
    suite.expect(GcpBrainIaaS::canRequestSpotPage(0, 0, oversizedToken, requestedPageTokens) == false, "gcp_spot_page_token_bytes_capped");
  }

  {
    MultiCurlClient::Result result = {};
    result.status = MultiCurlClient::Status::success;
    result.statusCode = 204;
    suite.expect(GcpBrainIaaS::successfulResponse(result), "gcp_spot_transport_and_2xx_accepted");
    result.statusCode = 300;
    suite.expect(GcpBrainIaaS::successfulResponse(result) == false, "gcp_spot_non_2xx_rejected");
    result.status = MultiCurlClient::Status::transportFailure;
    result.statusCode = 200;
    suite.expect(GcpBrainIaaS::successfulResponse(result) == false, "gcp_spot_transport_failure_rejected");
  }

  {
    TestableGcpBrainIaaS tokenParser = {};
    String failure = {};
    suite.expect(tokenParser.parseMetadataTokenForTest("{\"access_token\":\"metadata-token\",\"expires_in\":3600}"_ctv, failure), "gcp_spot_metadata_token_valid");
    suite.expect(tokenParser.parseMetadataTokenForTest("{\"access_token\":\"\",\"expires_in\":3600}"_ctv, failure) == false, "gcp_spot_metadata_token_rejects_empty_access_token");
    suite.expect(tokenParser.parseMetadataTokenForTest("{\"access_token\":\"metadata-token\",\"expires_in\":18446744073709551615}"_ctv, failure) == false, "gcp_spot_metadata_token_rejects_expiry_overflow");
    suite.expect(tokenParser.parseMetadataTokenForTest("{\"access_token\":\"metadata-token\",\"expires_in\":30}"_ctv, failure) == false, "gcp_spot_metadata_token_rejects_expired_lifetime");
  }

  GcpBrainIaaS gcpBrain = {};
  BrainIaaS& brain = gcpBrain;

  ProdigyRuntimeEnvironmentConfig runtimeEnvironment = {};
  runtimeEnvironment.kind = ProdigyEnvironmentKind::gcp;
  runtimeEnvironment.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
  runtimeEnvironment.providerCredentialMaterial = "test-token"_ctv;
  brain.configureRuntimeEnvironment(runtimeEnvironment);
  brain.configureBootstrapSSHAccess("root"_ctv, {}, {}, ""_ctv);

  suite.expect(brain.supportedMachineKindsMask() == 2u, "gcp_supports_vm_only");
  suite.expect(brain.supportsAutoProvision(), "gcp_supports_auto_provision");
  suite.expect(GcpBrainIaaS::parseRFC3339Ms("2026-03-21T15:16:37.741-07:00") == 1'774'131'397'741LL, "gcp_parse_rfc3339_ms_negative_offset");
  suite.expect(GcpBrainIaaS::parseRFC3339Ms("2026-03-21T15:16:37.741-07:00") == GcpBrainIaaS::parseRFC3339Ms("2026-03-21T22:16:37.741Z"), "gcp_parse_rfc3339_ms_equivalent_zulu");
  suite.expect(GcpBrainIaaS::parseRFC3339Ms("2026-03-22T00:16:37.741+02:00") == GcpBrainIaaS::parseRFC3339Ms("2026-03-21T22:16:37.741Z"), "gcp_parse_rfc3339_ms_positive_offset");
  {
    MachineCpuArchitecture architecture = MachineCpuArchitecture::unknown;
    suite.expect(GcpBrainIaaS::resolveMachineArchitecture("e2-medium"_ctv, {} /* architectureText */, architecture), "gcp_resolve_machine_architecture_defaults_missing_field");
    suite.expect(architecture == MachineCpuArchitecture::x86_64, "gcp_resolve_machine_architecture_defaults_to_x86_64");
    suite.expect(GcpBrainIaaS::resolveMachineArchitecture("t2a-standard-4"_ctv, "arm64"_ctv, architecture), "gcp_resolve_machine_architecture_accepts_explicit_text");
    suite.expect(architecture == MachineCpuArchitecture::aarch64, "gcp_resolve_machine_architecture_parses_explicit_text");
  }

  MachineConfig managedConfig = {};
  managedConfig.kind = MachineConfig::MachineKind::vm;
  managedConfig.slug = "gcp-managed"_ctv;
  managedConfig.vmImageURI = "projects/test-project/global/images/prodigy"_ctv;
  managedConfig.providerMachineType = "e2-medium"_ctv;

  String failure = {};
  GcpManagedTemplateTransaction::Spec managedSpec = {};
  suite.expect(GcpManagedTemplateTransaction::buildSpec("prodigy-template"_ctv, {} /* serviceAccountEmail */, "global/networks/default"_ctv, {} /* subnetwork */, managedConfig, false, managedSpec, failure) == false, "gcp_managed_template_requires_service_account");
  suite.expect(failure == "gcp managed instance template requires serviceAccountEmail"_ctv, "gcp_managed_template_requires_service_account_reason");

  managedConfig.providerMachineType.clear();
  suite.expect(GcpManagedTemplateTransaction::buildSpec("prodigy-template"_ctv, "prodigy@test-project.iam.gserviceaccount.com"_ctv, "global/networks/default"_ctv, {} /* subnetwork */, managedConfig, false, managedSpec, failure) == false, "gcp_managed_template_requires_machine_type");
  suite.expect(failure == "gcp managed instance template requires providerMachineType"_ctv, "gcp_managed_template_requires_machine_type_reason");

  managedConfig.providerMachineType = "e2-medium"_ctv;
  managedConfig.vmImageURI.clear();
  suite.expect(GcpManagedTemplateTransaction::buildSpec("prodigy-template"_ctv, "prodigy@test-project.iam.gserviceaccount.com"_ctv, "global/networks/default"_ctv, {} /* subnetwork */, managedConfig, true, managedSpec, failure) == false, "gcp_managed_template_requires_vm_image");
  suite.expect(failure == "gcp managed instance template requires vmImageURI"_ctv, "gcp_managed_template_requires_vm_image_reason");

  {
    ScriptedGcpMetadataClient client = {};
    TestableGcpBrainIaaS brain = {};
    brain.useClient(client);
    ProdigyRuntimeEnvironmentConfig runtime = {};
    runtime.kind = ProdigyEnvironmentKind::gcp;
    runtime.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
    brain.configureRuntimeEnvironment(runtime);
    CoroutineStack stack = {};
    bool tokenReady = false;
    failure.clear();
    const MultiCurlClient::TimePoint deadline = MultiCurlClient::Clock::now() + std::chrono::seconds(2);
    brain.ensureTokenAsyncForTest(&stack, tokenReady, failure, deadline);
    suite.expect(stack.hasSuspendedCoroutines() && client.requests.size() == 1,
                 "gcp_metadata_token_fetch_is_async");
    if (client.requests.size() == 1)
    {
      const MultiCurlClient::Request& tokenRequest = client.requests[0];
      suite.expect(tokenRequest.url ==
                       "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"_ctv &&
                       tokenRequest.headers.size() == 1 &&
                       tokenRequest.headers[0].name == "Metadata-Flavor"_ctv &&
                       tokenRequest.headers[0].value == "Google"_ctv &&
                       tokenRequest.overallDeadline == deadline,
                   "gcp_metadata_token_request_has_flavor_header_and_deadline");
    }
    client.complete(MultiCurlClient::Status::success,
                    200,
                    "{\"access_token\":\"metadata-token\",\"expires_in\":3600}"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() == false && tokenReady && failure.empty(),
                 "gcp_metadata_token_async_completion_parsed");
  }

  {
    ScriptedGcpMetadataClient client = {};
    TestableGcpBrainIaaS brain = {};
    brain.useClient(client);
    ProdigyProviderServices services = {};
    services.operationDeadline = MultiCurlClient::Clock::now() + std::chrono::minutes(1);
    brain.configureProviderServices(services);
    ProdigyRuntimeEnvironmentConfig runtime = {};
    runtime.kind = ProdigyEnvironmentKind::gcp;
    runtime.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
    runtime.providerCredentialMaterial = "provisioning-token"_ctv;
    brain.configureRuntimeEnvironment(runtime);
    MachineConfig config = {};
    config.kind = MachineConfig::MachineKind::vm;
    config.slug = "worker"_ctv;
    config.vmImageURI = "projects/test-project/global/images/image"_ctv;
    config.providerMachineType = "c3-standard-4"_ctv;
    config.gcpInstanceTemplate = "worker-standard"_ctv;
    CoroutineStack stack = {};
    bytell_hash_set<Machine *> machines = {};
    String failure = {};

    brain.spinMachines(&stack,
                       MachineLifetime::reserved,
                       config,
                       1,
                       machines,
                       failure);
    suite.expect(stack.hasSuspendedCoroutines() && brain.hasActiveControlOperations() &&
                     machines.empty() && client.requests.size() == 1,
                 "gcp_provisioning_provider_suspends_with_active_lifetime_guard");
    client.complete(MultiCurlClient::Status::success, 200,
                    R"json({"name":"create-operation"})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() && machines.empty() && client.requests.size() == 2,
                 "gcp_provisioning_provider_stages_before_instance_observation");
    client.complete(
        MultiCurlClient::Status::success,
        200,
        R"json({"id":"123456789","labels":{"app":"prodigy","brain":"false"},"networkInterfaces":[{"networkIP":"10.0.0.7","accessConfigs":[]}],"zone":"projects/test-project/zones/us-central1-a","scheduling":{"provisioningModel":"STANDARD"}})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() == false &&
                     brain.hasActiveControlOperations() == false && failure.empty() &&
                     machines.size() == 1 && (*machines.begin())->cloudID == "123456789"_ctv,
                 "gcp_provisioning_provider_publishes_only_after_transaction_success");
    for (Machine *machine : machines)
    {
      delete machine;
    }
  }

  {
    ScriptedGcpMetadataClient client = {};
    TestableGcpBrainIaaS brain = {};
    brain.useClient(client);
    ProdigyProviderServices services = {};
    services.operationDeadline = MultiCurlClient::Clock::now() + std::chrono::minutes(1);
    brain.configureProviderServices(services);
    ProdigyRuntimeEnvironmentConfig runtime = {};
    runtime.kind = ProdigyEnvironmentKind::gcp;
    runtime.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
    runtime.providerCredentialMaterial = "lifecycle-token"_ctv;
    brain.configureRuntimeEnvironment(runtime);
    CoroutineStack stack;
    String failure;

    brain.destroyMachine(&stack, "123456789"_ctv, failure);
    suite.expect(stack.hasSuspendedCoroutines() && brain.hasActiveControlOperations() &&
                     client.requests.size() == 1,
                 "gcp_lifecycle_provider_suspends_with_active_lifetime_guard");
    client.complete(MultiCurlClient::Status::success, 200,
                    R"json({"items":[{"id":"123456789","name":"machine"}]})json"_ctv);
    client.complete(MultiCurlClient::Status::success, 200,
                    R"json({"id":"123456789"})json"_ctv);
    client.complete(MultiCurlClient::Status::success, 200,
                    R"json({"name":"delete-operation"})json"_ctv);
    client.complete(MultiCurlClient::Status::success, 200,
                    R"json({"status":"DONE"})json"_ctv);
    client.complete(MultiCurlClient::Status::success, 404, {});
    suite.expect(stack.hasSuspendedCoroutines() == false &&
                     brain.hasActiveControlOperations() == false && failure.empty() &&
                     client.requests.size() == 5 &&
                     client.requests[2].method == MultiCurlClient::Method::delete_,
                 "gcp_lifecycle_provider_completes_destroy_and_releases_guard");
  }

  {
    ScriptedGcpMetadataClient client = {};
    TestableGcpBrainIaaS brain = {};
    brain.useClient(client);
    ProdigyProviderServices services = {};
    services.operationDeadline = MultiCurlClient::Clock::now() + std::chrono::minutes(1);
    brain.configureProviderServices(services);
    ProdigyRuntimeEnvironmentConfig runtime = {};
    runtime.kind = ProdigyEnvironmentKind::gcp;
    runtime.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
    runtime.providerCredentialMaterial = "cluster-destroy-token"_ctv;
    brain.configureRuntimeEnvironment(runtime);
    CoroutineStack stack;
    String clusterUUID = "cluster-a"_ctv;
    uint32_t destroyed = 99;
    String failure;

    brain.destroyClusterMachines(&stack, clusterUUID, destroyed, failure);
    clusterUUID.reset();
    suite.expect(stack.hasSuspendedCoroutines() && brain.hasActiveControlOperations() &&
                     destroyed == 0 && client.requests.size() == 1 &&
                     stringContains(client.requests[0].url,
                                    "filter=%28labels.app%20%3D%20prodigy%29%20%28labels.prodigy_cluster_uuid%20%3D%20cluster-a%29") &&
                     stringContains(client.requests[0].url, "fields=items(id,name,labels),nextPageToken"),
                 "gcp_cluster_destroy_provider_owns_label_and_uses_exact_filtered_discovery");
    client.complete(
        MultiCurlClient::Status::success,
        200,
        R"json({"items":[{"id":"123456789","name":"machine","labels":{"app":"prodigy","prodigy_cluster_uuid":"cluster-a"}}]})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() && brain.hasActiveControlOperations() &&
                     client.requests.size() == 2 &&
                     stringContains(client.requests[1].url, "/instances/machine?fields=id,labels"),
                 "gcp_cluster_destroy_provider_rechecks_ownership_before_mutation");
    client.complete(
        MultiCurlClient::Status::success,
        200,
        R"json({"id":"123456789","labels":{"app":"prodigy","prodigy_cluster_uuid":"cluster-a"}})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() && brain.hasActiveControlOperations() &&
                     client.requests.size() == 3 &&
                     client.requests[2].method == MultiCurlClient::Method::delete_ &&
                     stringContains(client.requests[2].url, "/instances/machine"),
                 "gcp_cluster_destroy_provider_deletes_only_after_ownership_preflight");
    client.complete(MultiCurlClient::Status::success, 200,
                    R"json({"name":"delete-operation"})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() && brain.hasActiveControlOperations() &&
                     client.requests.size() == 4 &&
                     stringContains(client.requests[3].url, "/operations/delete-operation"),
                 "gcp_cluster_destroy_provider_observes_delete_operation");
    client.complete(MultiCurlClient::Status::success, 200,
                    R"json({"status":"DONE","statusMessage":"completed normally"})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() && brain.hasActiveControlOperations() &&
                     client.requests.size() == 5 &&
                     stringContains(client.requests[4].url, "/instances/machine?fields=id,labels"),
                 "gcp_cluster_destroy_provider_treats_done_status_message_as_informational");
    client.complete(MultiCurlClient::Status::success, 404, {});
    suite.expect(stack.hasSuspendedCoroutines() == false &&
                     brain.hasActiveControlOperations() == false && failure.empty() &&
                     destroyed == 1 && client.requests.size() == 5,
                 "gcp_cluster_destroy_provider_confirms_absence_count_and_releases_guard");
  }

  {
    ScriptedGcpMetadataClient client = {};
    TestableGcpBrainIaaS brain = {};
    brain.useClient(client);
    ProdigyProviderServices services = {};
    services.operationDeadline = MultiCurlClient::Clock::now() + std::chrono::minutes(1);
    brain.configureProviderServices(services);
    ProdigyRuntimeEnvironmentConfig runtime = {};
    runtime.kind = ProdigyEnvironmentKind::gcp;
    runtime.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
    runtime.providerCredentialMaterial = "labels-token"_ctv;
    brain.configureRuntimeEnvironment(runtime);
    CoroutineStack stack;
    String clusterUUID = "cluster-a"_ctv;
    String cloudID = "123456789"_ctv;
    String failure;

    brain.ensureProdigyMachineTags(&stack, clusterUUID, cloudID, failure);
    clusterUUID.reset();
    cloudID.reset();
    suite.expect(stack.hasSuspendedCoroutines() && brain.hasActiveControlOperations() &&
                     client.requests.size() == 1 &&
                     stringContains(client.requests[0].url,
                                    "/instances?maxResults=2&filter=id%3D123456789&fields=items(id,name),nextPageToken"),
                 "gcp_labels_provider_suspends_with_owned_identity_and_active_lifetime_guard");
    client.complete(MultiCurlClient::Status::success, 200,
                    R"json({"items":[{"id":"123456789","name":"machine"}]})json"_ctv);
    client.complete(MultiCurlClient::Status::success, 200,
                    R"json({"id":"123456789","labelFingerprint":"fp-1","labels":{"owner":"platform","app":"legacy","prodigy_cluster_uuid":"old-cluster"}})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() && brain.hasActiveControlOperations() &&
                     client.requests.size() == 3 &&
                     client.requests[2].method == MultiCurlClient::Method::post &&
                     stringContains(client.requests[2].url, "/instances/machine/setLabels") &&
                     client.requests[2].body ==
                         R"json({"labelFingerprint":"fp-1","labels":{"owner":"platform","app":"prodigy","prodigy_cluster_uuid":"cluster-a"}})json"_ctv,
                 "gcp_labels_provider_preserves_unrelated_labels_and_combines_required_labels_atomically");
    client.complete(MultiCurlClient::Status::success, 200,
                    R"json({"name":"labels-operation"})json"_ctv);
    client.complete(MultiCurlClient::Status::success, 200,
                    R"json({"status":"DONE"})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() == false &&
                     brain.hasActiveControlOperations() == false && failure.empty() &&
                     client.requests.size() == 4 &&
                     stringContains(client.requests[3].url, "/operations/labels-operation"),
                 "gcp_labels_provider_completes_operation_and_releases_guard");
  }

  GcpNeuronIaaS gcpNeuron = {};
  NeuronIaaS& neuron = gcpNeuron;
  neuron.configureRuntimeEnvironment(runtimeEnvironment);

  basics_log("SUMMARY: failed=%d\n", suite.failed);
  return suite.failed == 0 ? 0 : 1;
}
