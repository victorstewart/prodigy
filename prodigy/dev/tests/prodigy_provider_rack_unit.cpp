#include <networking/includes.h>
#include <services/debug.h>
#include <services/base64.h>
#include <prodigy/iaas/aws/aws.h>
#include <prodigy/iaas/gcp/gcp.h>
#include <prodigy/iaas/azure/azure.h>
#include <prodigy/iaas/vultr/vultr.h>

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <simdjson.h>
#include <sys/socket.h>
#include <thread>

class TestSuite {
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    if (condition)
    {
      basics_log("PASS: %s\n", name);
    }
    else
    {
      std::fprintf(stderr, "FAIL: %s\n", name);
      failed += 1;
    }
  }
};

static bool parseJSON(const String& json, simdjson::dom::parser& parser, simdjson::dom::element& doc)
{
  String padded = {};
  padded.assign(json);
  padded.need(simdjson::SIMDJSON_PADDING);
  return parser.parse(padded.c_str(), padded.size()).get(doc) == simdjson::SUCCESS;
}

class ScriptedVultrHttp
{
public:

  MultiCurlClient::Callback callback = {};
  MultiCurlClient::Ticket ticket = {};
  Vector<MultiCurlClient::Request> requests = {};

  static MultiCurlClient::Ticket submit(void *context,
                                        MultiCurlClient::Request&& request,
                                        MultiCurlClient::Callback callback)
  {
    ScriptedVultrHttp& client = *static_cast<ScriptedVultrHttp *>(context);
    client.ticket = {client.ticket.identifier + 1, 1};
    client.callback = callback;
    client.requests.push_back(std::move(request));
    return client.ticket;
  }

  static bool cancel(void *, MultiCurlClient::Ticket)
  {
    return true;
  }

  ProdigyHostHttpSubmission submission(void)
  {
    return {this, submit, cancel};
  }

  void complete(MultiCurlClient::Status status, long statusCode, const String& body = {})
  {
    MultiCurlClient::Result result = {};
    result.status = status;
    result.statusCode = statusCode;
    result.body = body;
    MultiCurlClient::Callback completion = callback;
    completion.function(completion.context, ticket, std::move(result));
  }
};

class ScriptedVultrDelay
{
public:

  TimeoutPacket *pending = nullptr;
  Vector<uint64_t> delays;

  static void queue(void *context, TimeoutPacket *packet)
  {
    auto& owner = *static_cast<ScriptedVultrDelay *>(context);
    owner.pending = packet;
    owner.delays.push_back(uint64_t(packet->timeout.tv_sec) * 1'000'000u +
                           uint64_t(packet->timeout.tv_nsec) / 1'000u);
  }

  static void cancel(void *context, TimeoutPacket *packet)
  {
    auto& owner = *static_cast<ScriptedVultrDelay *>(context);
    if (owner.pending == packet) owner.pending = nullptr;
  }

  ProdigyHostDelayOperation::Submission submission(void)
  {
    return {this, queue, cancel};
  }

  bool complete(void)
  {
    if (pending == nullptr) return false;
    TimeoutPacket *packet = pending;
    pending = nullptr;
    packet->dispatcher->dispatchTimeout(packet);
    return true;
  }
};

static void configureVultrProviderForTest(VultrBrainIaaS& provider, ScriptedVultrHttp& http,
                                          const String& scope = {},
                                          ScriptedVultrDelay *delay = nullptr)
{
  ProdigyProviderServices services = {};
  services.http = http.submission();
  if (delay != nullptr) services.delay = delay->submission();
  services.operationDeadline = MultiCurlClient::Clock::now() + std::chrono::minutes(1);
  provider.configureProviderServices(services);
  ProdigyRuntimeEnvironmentConfig runtime = {};
  runtime.kind = ProdigyEnvironmentKind::vultr;
  runtime.providerCredentialMaterial.assign("unit-test-vultr-credential"_ctv);
  runtime.providerScope = scope;
  provider.configureRuntimeEnvironment(runtime);
}

class BlockingProvisioningProgressSink final : public BrainIaaSMachineProvisioningProgressSink {
public:

  std::mutex mutex;
  std::condition_variable changed;
  bool entered = false;
  bool release = false;
  uint32_t acceptedCalls = 0;

  void reportMachineProvisioningAccepted(const String&) override
  {
    std::unique_lock<std::mutex> lock(mutex);
    ++acceptedCalls;
    entered = true;
    changed.notify_all();
    changed.wait(lock, [&] { return release; });
  }

  void reportMachineProvisioningProgress(const Vector<MachineProvisioningProgress>&) override
  {}
};

int main(void)
{
  TestSuite suite = {};
  auto stringContains = [](const String& haystack, const char *needle) -> bool {
    if (needle == nullptr)
    {
      return false;
    }

    std::string_view haystackView(reinterpret_cast<const char *>(haystack.data()), size_t(haystack.size()));
    return haystackView.find(needle) != std::string_view::npos;
  };
  auto openLoopbackListener = [](uint16_t& portOut) -> int {
    portOut = 0;

    int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0)
    {
      return -1;
    }

    int reuse = 1;
    (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(0);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(listener, reinterpret_cast<const struct sockaddr *>(&address), sizeof(address)) != 0)
    {
      ::close(listener);
      return -1;
    }

    if (::listen(listener, 4) != 0)
    {
      ::close(listener);
      return -1;
    }

    socklen_t addressLen = sizeof(address);
    if (::getsockname(listener, reinterpret_cast<struct sockaddr *>(&address), &addressLen) != 0)
    {
      ::close(listener);
      return -1;
    }

    portOut = ntohs(address.sin_port);
    return listener;
  };

  {
    BrainIaaSMachineProvisioningProgressReporter reporter = {};
    BlockingProvisioningProgressSink sink = {};
    reporter.configureSink(&sink);
    std::thread callback([&] {
      reporter.notifyMachineProvisioningAccepted("machine-1"_ctv);
    });
    {
      std::unique_lock<std::mutex> lock(sink.mutex);
      sink.changed.wait(lock, [&] { return sink.entered; });
    }

    std::atomic<bool> unregisterStarted = false;
    std::atomic<bool> unregisterCompleted = false;
    std::thread unregister([&] {
      unregisterStarted.store(true, std::memory_order_release);
      reporter.configureSink(nullptr);
      unregisterCompleted.store(true, std::memory_order_release);
    });
    while (!unregisterStarted.load(std::memory_order_acquire)) std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    suite.expect(!unregisterCompleted.load(std::memory_order_acquire),
                 "provisioning_progress_sink_unregister_waits_for_inflight_callback");

    {
      std::lock_guard<std::mutex> lock(sink.mutex);
      sink.release = true;
    }
    sink.changed.notify_all();
    callback.join();
    unregister.join();
    reporter.notifyMachineProvisioningAccepted("machine-2"_ctv);
    suite.expect(unregisterCompleted.load(std::memory_order_acquire) && sink.acceptedCalls == 1,
                 "provisioning_progress_sink_unregister_is_quiescent");
  }

  {
    String padded = {};
    Base64::encodePadded(reinterpret_cast<const uint8_t *>("A"), 1, padded);
    suite.expect(padded == "QQ=="_ctv, "base64_encode_padded_tail_one");

    Base64::encodePadded(reinterpret_cast<const uint8_t *>("AB"), 2, padded);
    suite.expect(padded == "QUI="_ctv, "base64_encode_padded_tail_two");

    Base64::encodePadded(reinterpret_cast<const uint8_t *>("ABC"), 3, padded);
    suite.expect(padded == "QUJD"_ctv, "base64_encode_padded_full_triplet");
  }

  {
    String az = "us-east-1a"_ctv;
    suite.expect(awsRackUUIDFromAvailabilityZone(az) != 0, "aws_rack_uuid_from_availability_zone_nonzero");
    suite.expect(
        awsRackUUIDFromAvailabilityZone("us-east-1a"_ctv) != awsRackUUIDFromAvailabilityZone("us-east-1b"_ctv),
        "aws_rack_uuid_changes_with_availability_zone");
  }

  {
    AwsBrainIaaS aws = {};
    AzureBrainIaaS azure = {};
    GcpBrainIaaS gcp = {};
    VultrBrainIaaS vultr = {};

    suite.expect(aws.supportsIncrementalProvisioningCallbacks(), "aws_supports_incremental_provisioning_callbacks");
    suite.expect(azure.supportsIncrementalProvisioningCallbacks(), "azure_supports_incremental_provisioning_callbacks");
    suite.expect(gcp.supportsIncrementalProvisioningCallbacks(), "gcp_supports_incremental_provisioning_callbacks");
    suite.expect(vultr.supportsIncrementalProvisioningCallbacks(), "vultr_supports_incremental_provisioning_callbacks");
    suite.expect(aws.supportsDurableProvisioningRetryIdentity(),
                 "aws_supports_durable_provisioning_retry_identity");
    suite.expect(vultr.supportsDurableProvisioningRetryIdentity(),
                 "vultr_supports_durable_provisioning_retry_identity");
    suite.expect(!gcp.supportsDurableProvisioningRetryIdentity(),
                 "gcp_fails_closed_without_durable_provisioning_retry_identity");
    suite.expect(!azure.supportsDurableProvisioningRetryIdentity(),
                 "azure_fails_closed_without_durable_provisioning_retry_identity");
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String json = "{\"id\":\"1234567890\",\"zone\":\"https://www.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a\"}"_ctv;
    bool parsed = parseJSON(json, parser, doc);
    suite.expect(parsed, "gcp_zone_fallback_json_parses");

    String zoneText = {};
    if (parsed)
    {
      std::string_view zoneURL = {};
      (void)doc["zone"].get(zoneURL);
      suite.expect(gcpExtractZoneName(zoneURL, zoneText), "gcp_extract_zone_name_from_url");
      suite.expect(zoneText == "us-central1-a"_ctv, "gcp_extract_zone_name_value");
      suite.expect(gcpExtractRackUUID(doc, zoneText) == gcpHashRackIdentity(std::string_view(zoneText.c_str(), zoneText.size())), "gcp_rack_uuid_falls_back_to_zone");
    }
  }

  {
    ScriptedVultrHttp http = {};
    VultrBrainIaaS provider = {};
    configureVultrProviderForTest(provider, http, "ewr"_ctv);
    CoroutineStack stack = {};
    String failure = {};
    bytell_hash_set<Machine *> machines = {};
    provider.getMachines(&stack, "ewr"_ctv, machines, failure);
    http.complete(MultiCurlClient::Status::success, 200, R"json({"bare_metals":[]})json"_ctv);
    http.complete(MultiCurlClient::Status::success, 200,
                  R"json({"instances":[{"id":"instance-with-vpc","main_ip":"45.76.166.5","v6_main_ip":"2001:19f0:6001:48e4:5400:06ff:fe05:9ea6","internal_ip":"10.1.96.3","region":"ewr","tags":["prodigy"]}]})json"_ctv);
    http.complete(MultiCurlClient::Status::success, 500);
    bool privateFirst = false;
    bool ondemandLifetime = false;
    for (Machine *machine : machines)
    {
      privateFirst = machine->peerAddresses.size() == 2 &&
          machine->peerAddresses[0].address == "10.1.96.3"_ctv &&
          machine->peerAddresses[1].address == "2001:19f0:6001:48e4:5400:6ff:fe05:9ea6"_ctv;
      ondemandLifetime = machine->lifetime == MachineLifetime::ondemand;
      delete machine;
    }
    suite.expect(!stack.hasSuspendedCoroutines() && failure.empty() &&
                     machines.size() == 1 && privateFirst,
                 "vultr_machine_inventory_prefers_internal_ipv4_when_vpc_lookup_fails");
    suite.expect(!stack.hasSuspendedCoroutines() && failure.empty() &&
                     machines.size() == 1 && ondemandLifetime,
                 "vultr_machine_inventory_sets_ondemand_lifetime");
  }

  {
    ScriptedVultrHttp http = {};
    VultrBrainIaaS provider = {};
    configureVultrProviderForTest(provider, http, "ewr"_ctv);
    CoroutineStack stack = {};
    String failure = {};
    bytell_hash_set<Machine *> machines = {};
    provider.getMachines(&stack, "ewr"_ctv, machines, failure);
    http.complete(MultiCurlClient::Status::success, 200, R"json({"bare_metals":[]})json"_ctv);
    http.complete(MultiCurlClient::Status::success, 200,
                  R"json({"instances":[{"id":"instance-with-late-vpc","main_ip":"45.76.166.6","v6_main_ip":"2001:19f0:6001:48e4:5400:06ff:fe05:9ea7","region":"ewr","tags":["prodigy"]}]})json"_ctv);
    http.complete(MultiCurlClient::Status::success, 200,
                  R"json({"vpcs":[{"ip_address":"10.1.96.4"}]})json"_ctv);
    bool privateFirst = false;
    for (Machine *machine : machines)
    {
      privateFirst = machine->peerAddresses.size() == 3 &&
          machine->peerAddresses[0].address == "10.1.96.4"_ctv &&
          machine->peerAddresses[1].address == "2001:19f0:6001:48e4:5400:6ff:fe05:9ea7"_ctv &&
          machine->peerAddresses[2].address == "45.76.166.6"_ctv;
      delete machine;
    }
    suite.expect(!stack.hasSuspendedCoroutines() && failure.empty() &&
                     machines.size() == 1 && privateFirst,
                 "vultr_machine_inventory_promotes_late_vpc_ipv4_before_public_ipv6");
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String json = "{\"id\":\"1234567890\",\"zone\":\"projects/test-project/zones/us-central1-a\",\"resourceStatus\":{\"physicalHost\":\"host-42\"}}"_ctv;
    bool parsed = parseJSON(json, parser, doc);
    suite.expect(parsed, "gcp_physical_host_json_parses");

    String zoneText = "us-central1-a"_ctv;
    if (parsed)
    {
      suite.expect(gcpExtractRackUUID(doc, zoneText) == gcpHashRackIdentity("host-42"), "gcp_rack_uuid_prefers_physical_host");
    }
  }

  {
    String url = {};
    azureBuildResourceSkusURL("sub-123"_ctv, "eastus"_ctv, url);
    suite.expect(
        url == "https://management.azure.com/subscriptions/sub-123/providers/Microsoft.Compute/skus?api-version=2021-07-01&%24filter=location%20eq%20%27eastus%27"_ctv,
        "azure_resource_skus_url_location_filter");
  }

  {
    String url = {};
    azureBuildResourceSkusURL("sub-123"_ctv, String(), url);
    suite.expect(
        url == "https://management.azure.com/subscriptions/sub-123/providers/Microsoft.Compute/skus?api-version=2021-07-01"_ctv,
        "azure_resource_skus_url_unfiltered_base");
  }

  {
    String fragment = {};
    azureBuildSafeVMNameFragment("Standard_D2als_v6"_ctv, 47, fragment);
    suite.expect(fragment == "standard-d2als-v6"_ctv, "azure_vm_name_fragment_sanitizes_machine_type");
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element sku = {};
    String json = "{\"capabilities\":[{\"name\":\"vCPUs\",\"value\":\"2\"},{\"name\":\"MemoryGB\",\"value\":\"8\"}]}"_ctv;
    bool parsed = parseJSON(json, parser, sku);
    suite.expect(parsed, "azure_machine_type_resources_json_parses");

    if (parsed)
    {
      AzureMachineTypeResources resources = {};
      suite.expect(azureExtractMachineTypeResources(sku, resources), "azure_machine_type_resources_extracts_from_sku");
      suite.expect(resources.logicalCores == 2, "azure_machine_type_resources_cores_match");
      suite.expect(resources.memoryMB == 8 * 1024u, "azure_machine_type_resources_memory_match");
    }
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element vm = {};
    String json = "{\"properties\":{\"storageProfile\":{\"osDisk\":{\"diskSizeGB\":32},\"dataDisks\":[{\"diskSizeGB\":64}]}}}"_ctv;
    bool parsed = parseJSON(json, parser, vm);
    suite.expect(parsed, "azure_vm_storage_json_parses");

    if (parsed)
    {
      Machine machine = {};
      machine.ownershipMode = uint8_t(ClusterMachineOwnershipMode::wholeMachine);
      AzureMachineTypeResources resources = {};
      resources.logicalCores = 2;
      resources.memoryMB = 8 * 1024u;
      String failure = {};
      suite.expect(azureApplyMachineTypeResourcesToMachine(machine, resources, vm, &failure), "azure_machine_resources_apply_to_machine");
      suite.expect(failure.size() == 0, "azure_machine_resources_apply_clears_failure");
      suite.expect(machine.totalLogicalCores == 2, "azure_machine_resources_apply_sets_total_cores");
      suite.expect(machine.totalMemoryMB == 8 * 1024u, "azure_machine_resources_apply_sets_total_memory");
      suite.expect(machine.totalStorageMB == 96 * 1024u, "azure_machine_resources_apply_sets_total_storage");
      suite.expect(machine.ownedMemoryMB > 0, "azure_machine_resources_apply_sets_owned_memory");
      suite.expect(machine.ownedStorageMB > 0, "azure_machine_resources_apply_sets_owned_storage");
      suite.expect(machine.nLogicalCores_available == int32_t(machine.ownedLogicalCores), "azure_machine_resources_apply_sets_available_cores");
      suite.expect(machine.memoryMB_available == int32_t(machine.ownedMemoryMB), "azure_machine_resources_apply_sets_available_memory");
      suite.expect(machine.storageMB_available == int32_t(machine.ownedStorageMB), "azure_machine_resources_apply_sets_available_storage");
      suite.expect(prodigyMachineReadyResourcesAvailable(machine), "azure_machine_resources_apply_marks_machine_ready_resources_available");
    }
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String failure = {};
    String json = "{\"value\":[{\"tags\":{\"app\":\"prodigy\"},\"location\":\"northcentralus\"}]}"_ctv;
    bool parsed = azureParseVMListDocument(json, parser, doc, &failure);
    suite.expect(parsed, "azure_vm_list_json_parses");
    suite.expect(failure.size() == 0, "azure_vm_list_json_parse_failure_cleared");
    suite.expect(doc["value"].is_array(), "azure_vm_list_json_has_value_array");
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String failure = {};
    String json = "{\"value\":["_ctv;
    bool parsed = azureParseVMListDocument(json, parser, doc, &failure);
    suite.expect(!parsed, "azure_vm_list_json_invalid_rejected");
    suite.expect(failure.size() > 0, "azure_vm_list_json_invalid_failure_reported");
    suite.expect(stringContains(failure, "azure vm list json parse failed: "), "azure_vm_list_json_invalid_failure_keeps_prefix");
    suite.expect(stringContains(failure, "responseSnippet=\"{\\\"value\\\":[\""), "azure_vm_list_json_invalid_failure_includes_snippet");
  }

  {
    String name = {};
    azureRenderRandomRoleAssignmentName(name);
    bool valid = name.size() == 36;
    for (uint32_t index = 0; index < uint32_t(name.size()) && valid; ++index)
    {
      char ch = name[index];
      bool hyphen = index == 8 || index == 13 || index == 18 || index == 23;
      if (hyphen)
      {
        valid = ch == '-';
      }
      else
      {
        valid = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
      }
    }
    suite.expect(valid, "azure_role_assignment_name_is_guid_hex");
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String json = "{\"id\":\"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-a\",\"location\":\"eastus\",\"zones\":[\"2\"],\"properties\":{\"instanceView\":{\"platformFaultDomain\":3}}}"_ctv;
    bool parsed = parseJSON(json, parser, doc);
    suite.expect(parsed, "azure_zone_fault_domain_json_parses");

    if (parsed)
    {
      String zoneText = {};
      suite.expect(azureExtractPrimaryZone(doc, zoneText), "azure_extract_primary_zone");
      suite.expect(zoneText == "2"_ctv, "azure_extract_primary_zone_value");
      suite.expect(azureExtractRackUUID(doc, "eastus"_ctv, zoneText) == azureHashRackIdentity("eastus/zone/2/fd/3"_ctv), "azure_rack_uuid_prefers_fault_domain_with_zone");
    }
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String json = "{\"id\":\"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-b\",\"location\":\"eastus2\",\"zones\":[\"1\"]}"_ctv;
    bool parsed = parseJSON(json, parser, doc);
    suite.expect(parsed, "azure_zone_fallback_json_parses");

    if (parsed)
    {
      String zoneText = {};
      suite.expect(azureExtractPrimaryZone(doc, zoneText), "azure_extract_primary_zone_zone_only");
      suite.expect(azureExtractRackUUID(doc, "eastus2"_ctv, zoneText) == azureHashRackIdentity("eastus2/zone/1"_ctv), "azure_rack_uuid_falls_back_to_zone");
    }
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String failure = {};
    String json = "{\"access_token\":\"token\",\"client_id\":\"client\",\"expires_in\":\"86400\",\"expires_on\":\"1774239280\",\"resource\":\"https://management.azure.com/\",\"token_type\":\"Bearer\"}"_ctv;
    bool parsed = azureParseJSONDocument(json, parser, doc, &failure, "azure managed identity token json parse failed"_ctv);
    suite.expect(parsed, "azure_managed_identity_token_json_parses");
    suite.expect(failure.size() == 0, "azure_managed_identity_token_json_parse_failure_cleared");

    if (parsed)
    {
      std::string_view accessToken = {};
      suite.expect(doc["access_token"].get(accessToken) == simdjson::SUCCESS && accessToken == "token", "azure_managed_identity_token_access_token_present");
    }
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String json = "{\"id\":\"abc123\",\"region\":\"ewr\",\"plan\":\"vc2-2c-4gb\",\"host_id\":\"node-77\"}"_ctv;
    bool parsed = parseJSON(json, parser, doc);
    suite.expect(parsed, "vultr_explicit_rack_json_parses");

    if (parsed)
    {
      suite.expect(vultrExtractRackUUID(doc) == vultrHashRackIdentity("node-77"), "vultr_rack_uuid_prefers_explicit_host_id");
    }
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String json = "{\"region\":\"ewr\",\"plan\":\"vc2-2c-4gb\"}"_ctv;
    bool parsed = parseJSON(json, parser, doc);
    suite.expect(parsed, "vultr_region_plan_fallback_json_parses");

    if (parsed)
    {
      String combo = {};
      combo.snprintf<"{}/{}"_ctv>("ewr"_ctv, "vc2-2c-4gb"_ctv);
      suite.expect(vultrExtractRackUUID(doc) == vultrHashRackIdentity(std::string_view(combo.c_str(), combo.size())), "vultr_rack_uuid_falls_back_to_region_plan");
    }
  }

  {
    simdjson::dom::parser firstParser;
    simdjson::dom::element first = {};
    simdjson::dom::parser secondParser;
    simdjson::dom::element second = {};
    String firstJSON = "{\"id\":\"instance-a\",\"region\":\"ewr\",\"plan\":\"vc2-2c-4gb\"}"_ctv;
    String secondJSON = "{\"id\":\"instance-b\",\"region\":\"ewr\",\"plan\":\"vc2-2c-4gb\"}"_ctv;
    bool firstParsed = parseJSON(firstJSON, firstParser, first);
    bool secondParsed = parseJSON(secondJSON, secondParser, second);
    suite.expect(firstParsed && secondParsed, "vultr_instance_rack_fallback_json_parses");

    if (firstParsed && secondParsed)
    {
      suite.expect(vultrExtractRackUUID(first) == vultrHashRackIdentity("instance-a"), "vultr_rack_uuid_falls_back_to_instance_id");
      suite.expect(vultrExtractRackUUID(first) != vultrExtractRackUUID(second), "vultr_instance_rack_fallback_distinguishes_same_plan_instances");
    }
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String json = "{\"id\":\"vx1-g-2c-8g\",\"type\":\"vx1\",\"cpu_vendor\":\"AMD\"}"_ctv;
    bool parsed = parseJSON(json, parser, doc);
    suite.expect(parsed, "vultr_plan_cpu_capability_json_parses");

    if (parsed)
    {
      MachineSchemaCpuCapability capability = {};
      String failure = {};
      suite.expect(vultrInferPlanCpuCapability(doc, capability, &failure), "vultr_plan_cpu_capability_infers_architecture");
      suite.expect(failure.size() == 0, "vultr_plan_cpu_capability_clears_failure");
      suite.expect(capability.architecture == MachineCpuArchitecture::x86_64, "vultr_plan_cpu_capability_architecture_x86_64");
      suite.expect(capability.provenance == MachineSchemaCpuCapabilityProvenance::unavailable, "vultr_plan_cpu_capability_provenance_unavailable");
    }
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String json = "{\"id\":\"mystery-plan\",\"type\":\"mystery\",\"cpu_vendor\":\"MysteryCPU\"}"_ctv;
    bool parsed = parseJSON(json, parser, doc);
    suite.expect(parsed, "vultr_plan_cpu_capability_unknown_vendor_json_parses");

    if (parsed)
    {
      MachineSchemaCpuCapability capability = {};
      String failure = {};
      suite.expect(vultrInferPlanCpuCapability(doc, capability, &failure) == false, "vultr_plan_cpu_capability_unknown_vendor_rejected");
      suite.expect(stringContains(failure, "unsupported"), "vultr_plan_cpu_capability_unknown_vendor_failure_mentions_unsupported");
    }
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String json = "{\"plans\":[{\"id\":\"vc2-1c-1gb\",\"type\":\"vc2\",\"cpu_vendor\":\"AMD\"}],\"meta\":{\"total\":159,\"links\":{\"next\":\"bmV4dF9fdmNnLWExMDAtM2MtMzBnLTIwdnJhbQ==\",\"prev\":\"\"}}}"_ctv;
    bool parsed = parseJSON(json, parser, doc);
    suite.expect(parsed, "vultr_plan_page_cursor_json_parses");

    if (parsed)
    {
      String storageType = {};
      String planType = {};
      String cpuVendor = {};
      bool found = false;
      String nextCursor = {};
      String failure = {};
      suite.expect(vultrExtractPlanMetadata(doc, "vx1-g-2c-8g"_ctv, storageType, planType, cpuVendor, found, nextCursor, &failure), "vultr_plan_page_extract_metadata");
      suite.expect(failure.size() == 0, "vultr_plan_page_extract_metadata_clears_failure");
      suite.expect(found == false, "vultr_plan_page_first_page_does_not_match_vx1");
      suite.expect(nextCursor == "bmV4dF9fdmNnLWExMDAtM2MtMzBnLTIwdnJhbQ=="_ctv, "vultr_plan_page_extracts_next_cursor");
    }
  }

  {
    String url = {};
    String failure = {};
    suite.expect(vultrBuildPlansLookupURL("bmV4dF9fdmNnLWExMDAtM2MtMzBnLTIwdnJhbQ=="_ctv, url, &failure), "vultr_plan_lookup_url_builds_with_cursor");
    suite.expect(failure.size() == 0, "vultr_plan_lookup_url_clears_failure");
    suite.expect(stringContains(url, "https://api.vultr.com/v2/plans?per_page=100&cursor="), "vultr_plan_lookup_url_has_base");
    suite.expect(stringContains(url, "bmV4dF9fdmNnLWExMDAtM2MtMzBnLTIwdnJhbQ%3D%3D"), "vultr_plan_lookup_url_urlencodes_cursor_padding");
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String json = "{\"plans\":[{\"id\":\"vx1-g-2c-8g\",\"type\":\"vx1\",\"cpu_vendor\":\"AMD\",\"storage_type\":\"block_storage\"}],\"meta\":{\"total\":159,\"links\":{\"next\":\"\",\"prev\":\"cHJldl9fdmNnLWExNi0xMmMtMTI4Zy0zMnZyYW0=\"}}}"_ctv;
    bool parsed = parseJSON(json, parser, doc);
    suite.expect(parsed, "vultr_plan_page_match_json_parses");

    if (parsed)
    {
      String storageType = {};
      String planType = {};
      String cpuVendor = {};
      bool found = false;
      String nextCursor = {};
      String failure = {};
      suite.expect(vultrExtractPlanMetadata(doc, "vx1-g-2c-8g"_ctv, storageType, planType, cpuVendor, found, nextCursor, &failure), "vultr_plan_page_match_extract_metadata");
      suite.expect(found, "vultr_plan_page_second_page_finds_vx1");
      suite.expect(storageType == "block_storage"_ctv, "vultr_plan_page_match_storage_type");
      suite.expect(planType == "vx1"_ctv, "vultr_plan_page_match_type");
      suite.expect(cpuVendor == "AMD"_ctv, "vultr_plan_page_match_cpu_vendor");
      suite.expect(nextCursor.size() == 0, "vultr_plan_page_match_has_no_next_cursor");

      MachineSchemaCpuCapability capability = {};
      failure.clear();
      suite.expect(vultrInferPlanCpuCapability("vx1-g-2c-8g"_ctv, planType, cpuVendor, capability, &failure), "vultr_plan_metadata_cpu_capability_infers_architecture");
      suite.expect(failure.size() == 0, "vultr_plan_metadata_cpu_capability_clears_failure");
      suite.expect(capability.architecture == MachineCpuArchitecture::x86_64, "vultr_plan_metadata_cpu_capability_architecture_x86_64");
    }
  }

  {
    uint32_t assignedIPv4 = 0;
    suite.expect(vultrParseAssignedIPv4(std::string_view("45.76.166.5"), assignedIPv4), "vultr_assigned_ipv4_accepts_real_address");
    suite.expect(assignedIPv4 != 0, "vultr_assigned_ipv4_value_nonzero");
    suite.expect(vultrParseAssignedIPv4(std::string_view("0.0.0.0"), assignedIPv4) == false, "vultr_assigned_ipv4_rejects_unspecified_address");
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String json = "{\"v6_main_ip\":\"2001:19f0:6001:48e4:5400:06ff:fe05:9ea6\"}"_ctv;
    bool parsed = parseJSON(json, parser, doc);
    suite.expect(parsed, "vultr_public_ipv6_json_parses");

    if (parsed)
    {
      String publicIPv6 = {};
      suite.expect(vultrExtractPublicIPv6(doc, publicIPv6), "vultr_public_ipv6_extracts_main_ip");
      suite.expect(publicIPv6 == "2001:19f0:6001:48e4:5400:06ff:fe05:9ea6"_ctv, "vultr_public_ipv6_value_matches");
    }
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String json = "{\"id\":\"instance-with-vpc\",\"main_ip\":\"45.76.166.5\",\"v6_main_ip\":\"2001:19f0:6001:48e4:5400:06ff:fe05:9ea6\",\"internal_ip\":\"10.1.96.3\",\"plan\":\"vc2-4c-8gb\",\"region\":\"ewr\",\"tags\":[\"brain\"]}"_ctv;
    bool parsed = parseJSON(json, parser, doc);
    suite.expect(parsed, "vultr_vpc_public_ipv6_machine_json_parses");

    if (parsed)
    {
      String publicIPv6 = {};
      String internalIPv4 = {};
      suite.expect(vultrExtractPublicIPv6(doc, publicIPv6), "vultr_vpc_machine_extracts_public_ipv6");
      suite.expect(vultrExtractInternalIPv4(doc, internalIPv4), "vultr_vpc_machine_extracts_internal_ipv4");
      Vector<ClusterMachinePeerAddress> peerAddresses = {};
      vultrAppendPublicMachinePeerAddresses(publicIPv6, "45.76.166.5"_ctv, true, peerAddresses);
      vultrPreferPrivateMachinePeerAddress(internalIPv4, peerAddresses);
      suite.expect(peerAddresses.size() == 2 &&
          peerAddresses[0].address == "10.1.96.3"_ctv &&
          peerAddresses[1].address == "2001:19f0:6001:48e4:5400:6ff:fe05:9ea6"_ctv,
          "vultr_vpc_machine_prefers_late_private_ipv4_before_public_ipv6");
      ClusterTopology topology = {};
      topology.machines.resize(1);
      topology.machines[0].peerAddresses = std::move(peerAddresses);
      prodigyNormalizeClusterTopologyPeerAddresses(topology);
      const Vector<ClusterMachinePeerAddress>& normalized = topology.machines[0].peerAddresses;
      suite.expect(normalized.size() == 2 &&
          normalized[0].address == "10.1.96.3"_ctv &&
          normalized[1].address == "2001:19f0:6001:48e4:5400:6ff:fe05:9ea6"_ctv,
          "vultr_vpc_machine_preserves_private_ipv4_and_public_ipv6_with_private_first");
    }
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String json = "{\"internal_ip\":\"10.1.96.3\"}"_ctv;
    bool parsed = parseJSON(json, parser, doc);
    suite.expect(parsed, "vultr_internal_ipv4_json_parses");

    if (parsed)
    {
      String internalIPv4 = {};
      suite.expect(vultrExtractInternalIPv4(doc, internalIPv4), "vultr_internal_ipv4_extracts_internal_ip");
      suite.expect(internalIPv4 == "10.1.96.3"_ctv, "vultr_internal_ipv4_value_matches");
    }
  }

  {
    String body = {};
    body.assign("{\"region\":\"ewr\"");
    vultrAppendManagedVPCCreateFields(MachineConfig::MachineKind::vm, "ee803b61-0fbd-4bd2-a312-04d4bfb86618"_ctv, body);
    body.append('}');
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    bool parsed = parseJSON(body, parser, doc);
    suite.expect(parsed, "vultr_vm_create_body_json_parses");
    if (parsed)
    {
      bool enableVPC = false;
      (void)doc["enable_vpc"].get(enableVPC);
      suite.expect(enableVPC, "vultr_vm_create_body_enables_vpc");

      simdjson::dom::array vpcIDs = {};
      bool hasManagedVPC = false;
      if (doc["attach_vpc"].get(vpcIDs) == simdjson::SUCCESS)
      {
        for (auto vpcID : vpcIDs)
        {
          std::string_view value = {};
          if (vpcID.get(value) == simdjson::SUCCESS && value == "ee803b61-0fbd-4bd2-a312-04d4bfb86618")
          {
            hasManagedVPC = true;
            break;
          }
        }
      }
      suite.expect(hasManagedVPC, "vultr_vm_create_body_includes_managed_vpc_id");
      suite.expect(doc["vpc_ids"].is_array() == false, "vultr_vm_create_body_does_not_use_ignored_vpc_ids_field");
    }
  }

  {
    String body = {};
    body.assign("{\"region\":\"ewr\"");
    vultrAppendManagedVPCCreateFields(MachineConfig::MachineKind::bareMetal, "ee803b61-0fbd-4bd2-a312-04d4bfb86618"_ctv, body);
    body.append('}');
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    bool parsed = parseJSON(body, parser, doc);
    suite.expect(parsed, "vultr_bare_metal_create_body_json_parses");
    if (parsed)
    {
      suite.expect(doc["enable_vpc"].is_bool() == false, "vultr_bare_metal_create_body_skips_vm_enable_vpc");
      suite.expect(doc["attach_vpc"].is_array() == false, "vultr_bare_metal_create_body_skips_vm_attach_vpc");
    }
  }

  {
    String description = {};
    vultrManagedVPCDescription("ewr"_ctv, description);
    suite.expect(description == "prodigy-managed-vpc-ewr"_ctv, "vultr_managed_vpc_description_matches_region");

    String scopedDescription = {};
    vultrManagedVPCDescription("ewr"_ctv, "0123456789abcdef0123456789abcdef"_ctv, scopedDescription);
    suite.expect(scopedDescription == "prodigy-managed-vpc-ewr-0123456789abcdef0123456789abcdef"_ctv,
                 "vultr_managed_vpc_description_binds_provisioning_cluster_uuid");
    suite.expect(scopedDescription != description,
                 "vultr_managed_vpc_description_never_reuses_legacy_region_vpc");

    String legacyDescription = {};
    vultrManagedVPCDescription("ewr"_ctv, String(), legacyDescription);
    suite.expect(legacyDescription == description,
                 "vultr_managed_vpc_description_preserves_legacy_without_cluster_uuid");
  }

  {
    suite.expect(vultrManagedVPCPrefixLength() == 20, "vultr_managed_vpc_prefix_length_has_capacity_headroom");
    suite.expect(vultrMachineKindUsesManagedVPC(MachineConfig::MachineKind::vm), "vultr_managed_vpc_used_for_vm");
    suite.expect(vultrMachineKindUsesManagedVPC(MachineConfig::MachineKind::bareMetal), "vultr_managed_vpc_used_for_bare_metal");
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String json = "{\"label\":\"ntg-vultr-vx1-g-2c-8g-1774231035507-boot - Bootable Storage Disk\",\"attached_to_instance\":\"\",\"attached_to_instance_label\":\"\"}"_ctv;
    bool parsed = parseJSON(json, parser, doc);
    suite.expect(parsed, "vultr_boot_block_json_parses");

    if (parsed)
    {
      suite.expect(vultrBlockMatchesMachineLabel(doc, "ntg-vultr-vx1-g-2c-8g-1774231035507"), "vultr_boot_block_matches_machine_label_prefix");
      suite.expect(vultrBlockMatchesMachineLabel(doc, "different-machine") == false, "vultr_boot_block_rejects_other_machine_label");
    }
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String json = "{\"vpcs\":[{\"id\":\"ee803b61-0fbd-4bd2-a312-04d4bfb86618\",\"ip_address\":\"10.1.96.3\"}]}"_ctv;
    bool parsed = parseJSON(json, parser, doc);
    suite.expect(parsed, "vultr_attached_vpc_json_parses");

    if (parsed)
    {
      String privateIPv4 = {};
      suite.expect(vultrExtractAttachedVPCIPv4(doc, privateIPv4), "vultr_attached_vpc_extracts_ip_address");
      suite.expect(privateIPv4 == "10.1.96.3"_ctv, "vultr_attached_vpc_ip_address_matches");
    }
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String json = "{\"instances\":[{\"id\":\"instance-a\",\"label\":\"other\"},{\"id\":\"instance-b\",\"label\":\"ntg-vultr-vx1-g-2c-8g-123\"}]}"_ctv;
    bool parsed = parseJSON(json, parser, doc);
    suite.expect(parsed, "vultr_create_recovery_list_json_parses");
    if (parsed)
    {
      String recoveredID = {};
      suite.expect(vultrFindMachineIDByLabel(doc, MachineConfig::MachineKind::vm, "ntg-vultr-vx1-g-2c-8g-123", recoveredID), "vultr_create_recovery_finds_machine_by_label");
      suite.expect(recoveredID == "instance-b"_ctv, "vultr_create_recovery_returns_matching_id");
      suite.expect(vultrRecoverySeedIdentityMatches("instance-b"_ctv, 1, recoveredID), "vultr_recovery_exact_seed_id_accepts_unique_match");
      suite.expect(!vultrRecoverySeedIdentityMatches("instance-a"_ctv, 1, recoveredID) &&
                   !vultrRecoverySeedIdentityMatches("instance-b"_ctv, 0, recoveredID) &&
                   !vultrRecoverySeedIdentityMatches("instance-b"_ctv, 2, recoveredID), "vultr_recovery_rejects_wrong_missing_or_duplicate_seed");
      suite.expect(vultrRecoverySeedIdentityMatches({ }, 0, recoveredID), "vultr_normal_create_keeps_existing_behavior");
      suite.expect(vultrFindMachineIDByLabel(doc, MachineConfig::MachineKind::vm, "missing", recoveredID) == false, "vultr_create_recovery_rejects_missing_label");
    }
  }

  {
    String clusterUUID = "0d05b0c6179e4d93e8bfbf02c3b4edd1"_ctv;
    String firstLabel = {};
    String firstHostname = {};
    String repeatedLabel = {};
    String repeatedHostname = {};
    String changedOperationLabel = {};
    String changedOperationHostname = {};
    String changedRoleLabel = {};
    String changedRoleHostname = {};
    String changedInstructionLabel = {};
    String changedInstructionHostname = {};
    String changedSlotLabel = {};
    String changedSlotHostname = {};
    suite.expect(
        vultrBuildProvisioningMachineIdentity(
            clusterUUID, 17, 0, "vc2-4c-8gb"_ctv, MachineConfig::MachineKind::vm,
            true, 0, firstLabel, firstHostname),
        "vultr_provisioning_identity_builds");
    suite.expect(
        vultrBuildProvisioningMachineIdentity(
            clusterUUID, 17, 0, "vc2-4c-8gb"_ctv, MachineConfig::MachineKind::vm,
            true, 0, repeatedLabel, repeatedHostname) &&
            repeatedLabel == firstLabel && repeatedHostname == firstHostname,
        "vultr_provisioning_identity_is_stable_for_same_operation_slot");
    suite.expect(
        vultrBuildProvisioningMachineIdentity(
            clusterUUID, 18, 0, "vc2-4c-8gb"_ctv, MachineConfig::MachineKind::vm,
            true, 0, changedOperationLabel, changedOperationHostname) &&
            changedOperationLabel != firstLabel && changedOperationHostname != firstHostname,
        "vultr_provisioning_identity_changes_with_operation");
    suite.expect(
        vultrBuildProvisioningMachineIdentity(
            clusterUUID, 17, 0, "vc2-4c-8gb"_ctv, MachineConfig::MachineKind::vm,
            false, 0, changedRoleLabel, changedRoleHostname) &&
            changedRoleLabel != firstLabel && changedRoleHostname != firstHostname,
        "vultr_provisioning_identity_changes_with_role");
    suite.expect(
        vultrBuildProvisioningMachineIdentity(
            clusterUUID, 17, 1, "vc2-4c-8gb"_ctv, MachineConfig::MachineKind::vm,
            true, 0, changedInstructionLabel, changedInstructionHostname) &&
            changedInstructionLabel != firstLabel && changedInstructionHostname != firstHostname,
        "vultr_provisioning_identity_changes_with_instruction");
    suite.expect(
        vultrBuildProvisioningMachineIdentity(
            clusterUUID, 17, 0, "vc2-4c-8gb"_ctv, MachineConfig::MachineKind::vm,
            true, 1, changedSlotLabel, changedSlotHostname) &&
            changedSlotLabel != firstLabel && changedSlotHostname != firstHostname,
        "vultr_provisioning_identity_changes_with_slot");
    suite.expect(firstHostname.size() <= 63,
                 "vultr_provisioning_hostname_fits_dns_label");
  }

  {
    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    String json = "{\"instances\":[{\"id\":\"instance-a\",\"label\":\"stable-label\"},{\"id\":\"instance-b\",\"label\":\"stable-label\"}]}"_ctv;
    bool parsed = parseJSON(json, parser, doc);
    suite.expect(parsed, "vultr_duplicate_recovery_inventory_json_parses");
    if (parsed)
    {
      String recoveredID = {};
      uint32_t matchCount = 0;
      suite.expect(
          vultrFindMachineIDByLabel(
              doc, MachineConfig::MachineKind::vm, "stable-label", recoveredID,
              &matchCount) == false &&
              recoveredID.empty() && matchCount == 2,
          "vultr_duplicate_recovery_identity_fails_closed");
    }
  }

  {
    VultrBrainIaaS::MachineProvisioningPollObservation initial = {};
    initial.phase = VultrBrainIaaS::MachineProvisioningPollPhase::waitingForPublicSSHAddress;
    initial.providerStatus.assign("active"_ctv);
    suite.expect(
        VultrBrainIaaS::nextMachineProvisioningPollDelayMs(nullptr, initial) == 0,
        "vultr_machine_provisioning_first_observation_polls_immediately");

    VultrBrainIaaS::MachineProvisioningPollObservation unchanged = initial;
    suite.expect(
        VultrBrainIaaS::nextMachineProvisioningPollDelayMs(&initial, unchanged) == vultrMachineProvisioningUnchangedPollSleepMs,
        "vultr_machine_provisioning_unchanged_observation_uses_short_backoff");

    VultrBrainIaaS::MachineProvisioningPollObservation changed = initial;
    changed.phase = VultrBrainIaaS::MachineProvisioningPollPhase::waitingForInstanceAddresses;
    suite.expect(
        VultrBrainIaaS::nextMachineProvisioningPollDelayMs(&initial, changed) == 0,
        "vultr_machine_provisioning_changed_phase_polls_immediately");
  }

  {
    ScriptedVultrHttp http = {};
    VultrBrainIaaS provider = {};
    configureVultrProviderForTest(provider, http);
    CoroutineStack stack = {};
    String failure = {};
    provider.destroyMachine(&stack, "gone-machine"_ctv, failure);
    suite.expect(stack.hasSuspendedCoroutines() && http.requests.size() == 1 &&
                     http.requests[0].method == MultiCurlClient::Method::get,
                 "vultr_delete_missing_machine_checks_bare_metal_before_idempotent_success");
    http.complete(MultiCurlClient::Status::success, 404);
    suite.expect(stack.hasSuspendedCoroutines() && http.requests.size() == 2 &&
                     http.requests[1].method == MultiCurlClient::Method::get,
                 "vultr_delete_missing_machine_checks_vm_before_idempotent_success");
    http.complete(MultiCurlClient::Status::success, 404);
    suite.expect(stack.hasSuspendedCoroutines() == false && failure.empty(),
                 "vultr_delete_verified_missing_machine_is_idempotent");
  }

  {
    ScriptedVultrHttp http = {};
    VultrBrainIaaS provider = {};
    configureVultrProviderForTest(provider, http);
    CoroutineStack stack = {};
    String failure = {};
    provider.hardRebootMachine(&stack, "reboot-machine"_ctv, failure);
    http.complete(MultiCurlClient::Status::success, 404);
    http.complete(MultiCurlClient::Status::success, 200,
                  R"json({"instance":{"id":"reboot-machine"}})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() && http.requests.size() == 3 &&
                     http.requests[2].method == MultiCurlClient::Method::post &&
                     http.requests[2].url ==
                         "https://api.vultr.com/v2/instances/reboot"_ctv &&
                     http.requests[2].body ==
                         R"json({"instance_ids":["reboot-machine"]})json"_ctv,
                 "vultr_hard_reboot_uses_framed_single_machine_batch_request");
    http.complete(MultiCurlClient::Status::success, 204);
    suite.expect(stack.hasSuspendedCoroutines() == false && failure.empty(),
                 "vultr_hard_reboot_accepts_empty_success_receipt");
  }

  {
    ScriptedVultrHttp http = {};
    VultrBrainIaaS provider = {};
    configureVultrProviderForTest(provider, http);
    CoroutineStack stack = {};
    String failure = {};
    provider.destroyMachine(&stack, "ambiguous-machine"_ctv, failure);
    http.complete(MultiCurlClient::Status::success, 404);
    http.complete(MultiCurlClient::Status::transportFailure, 404);
    suite.expect(stack.hasSuspendedCoroutines() == false &&
                     failure == "vultr machine deletion failed"_ctv,
                 "vultr_delete_transport_failure_is_not_idempotent");
  }

  {
    ScriptedVultrHttp http = {};
    VultrBrainIaaS provider = {};
    configureVultrProviderForTest(provider, http);
    CoroutineStack stack = {};
    String failure = {};
    provider.destroyMachine(&stack, "raced-machine"_ctv, failure);
    http.complete(MultiCurlClient::Status::success, 404);
    http.complete(MultiCurlClient::Status::success, 200, R"json({"instance":{"id":"raced-machine"}})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() && http.requests.size() == 3 &&
                     http.requests[2].method == MultiCurlClient::Method::delete_,
                 "vultr_delete_verified_machine_submits_exact_vm_delete");
    http.complete(MultiCurlClient::Status::success, 404);
    suite.expect(stack.hasSuspendedCoroutines() && http.requests.size() == 4 &&
                     http.requests[3].method == MultiCurlClient::Method::get,
                 "vultr_delete_race_requires_verified_absence");
    http.complete(MultiCurlClient::Status::success, 404);
    suite.expect(stack.hasSuspendedCoroutines() == false && failure.empty(),
                 "vultr_delete_raced_verified_not_found_is_idempotent");
  }

  {
    ScriptedVultrHttp http = {};
    ScriptedVultrDelay delay = {};
    VultrBrainIaaS provider = {};
    configureVultrProviderForTest(provider, http, {}, &delay);
    CoroutineStack stack = {};
    String failure = {};
    provider.destroyMachine(&stack, "pending-machine"_ctv, failure);
    http.complete(MultiCurlClient::Status::success, 404);
    http.complete(MultiCurlClient::Status::success, 200, R"json({"instance":{"id":"pending-machine"}})json"_ctv);
    http.complete(MultiCurlClient::Status::success, 204);
    suite.expect(stack.hasSuspendedCoroutines() && http.requests.size() == 4 &&
                     http.requests[3].method == MultiCurlClient::Method::get &&
                     http.requests[3].url == "https://api.vultr.com/v2/instances/pending-machine"_ctv,
                 "vultr_delete_accepted_requires_exact_machine_readback");
    http.complete(MultiCurlClient::Status::success, 200, R"json({"instance":{"id":"pending-machine"}})json"_ctv);
    suite.expect(delay.pending != nullptr && delay.complete(), "vultr_delete_pending_machine_retries");
    http.complete(MultiCurlClient::Status::success, 404);
    suite.expect(!stack.hasSuspendedCoroutines() && failure.empty(), "vultr_delete_succeeds_only_after_absence");
  }

  for (unsigned scenario = 0; scenario < 4; ++scenario)
  {
    ScriptedVultrHttp http = {};
    VultrBrainIaaS provider = {};
    configureVultrProviderForTest(provider, http);
    CoroutineStack stack = {};
    String failure = {};
    provider.destroyMachine(&stack, "verify-machine"_ctv, failure);
    http.complete(MultiCurlClient::Status::success, 404);
    http.complete(MultiCurlClient::Status::success, 200, R"json({"instance":{"id":"verify-machine"}})json"_ctv);
    http.complete(MultiCurlClient::Status::success, 204);
    if (scenario == 0) http.complete(MultiCurlClient::Status::transportFailure, 404);
    else if (scenario == 1) http.complete(MultiCurlClient::Status::success, 403);
    else if (scenario == 2) http.complete(MultiCurlClient::Status::success, 200, "not-json"_ctv);
    else http.complete(MultiCurlClient::Status::success, 200, R"json({"instance":{"id":"other-machine"}})json"_ctv);
    suite.expect(!stack.hasSuspendedCoroutines() && !failure.empty(),
                 "vultr_delete_verification_fails_closed_on_untrusted_response");
  }

  {
    ScriptedVultrHttp http = {};
    ScriptedVultrDelay delay = {};
    VultrBrainIaaS provider = {};
    configureVultrProviderForTest(provider, http, {}, &delay);
    CoroutineStack stack = {};
    String failure = {};
    provider.destroyMachine(&stack, "stuck-machine"_ctv, failure);
    http.complete(MultiCurlClient::Status::success, 404);
    http.complete(MultiCurlClient::Status::success, 200, R"json({"instance":{"id":"stuck-machine"}})json"_ctv);
    http.complete(MultiCurlClient::Status::success, 204);
    for (uint32_t attempt = 0; attempt < vultrMachineDeleteMaxAttempts; ++attempt)
    {
      http.complete(MultiCurlClient::Status::success, 200, R"json({"instance":{"id":"stuck-machine"}})json"_ctv);
      if (attempt + 1 < vultrMachineDeleteMaxAttempts)
        suite.expect(delay.complete(), "vultr_delete_timeout_retry_is_scheduled");
    }
    suite.expect(!stack.hasSuspendedCoroutines() && failure == "timed out waiting for vultr machine deletion"_ctv,
                 "vultr_delete_persistent_machine_times_out");
  }

  {
    ScriptedVultrHttp http = {};
    VultrBrainIaaS provider = {};
    configureVultrProviderForTest(provider, http, "ewr"_ctv);
    CoroutineStack stack = {};
    String failure = {};
    uint32_t destroyed = 99;
    String clusterUUID = "0123456789abcdef0123456789abcdef"_ctv;
    provider.destroyClusterMachines(&stack, clusterUUID, destroyed, failure);
    suite.expect(stack.hasSuspendedCoroutines() && http.requests.size() == 1,
                 "vultr_cluster_cleanup_lists_tagged_vms_before_vpc_cleanup");
    http.complete(MultiCurlClient::Status::success, 200, R"json({"instances":[]})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() && http.requests.size() == 2,
                 "vultr_cluster_cleanup_lists_tagged_bare_metal_before_vpc_cleanup");
    http.complete(MultiCurlClient::Status::success, 200, R"json({"bare_metals":[]})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() && http.requests.size() == 3 &&
                     http.requests[2].method == MultiCurlClient::Method::get,
                 "vultr_cluster_cleanup_lists_scoped_vpc_after_machine_cleanup");
    http.complete(MultiCurlClient::Status::success, 200,
                  R"json({"vpcs":[{"id":"legacy","region":"ewr","description":"prodigy-managed-vpc-ewr"},{"id":"scoped","region":"ewr","description":"prodigy-managed-vpc-ewr-0123456789abcdef0123456789abcdef","v4_subnet":"10.214.32.0","v4_subnet_mask":20}]})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() && http.requests.size() == 4 &&
                     http.requests[3].method == MultiCurlClient::Method::delete_ &&
                     stringContains(http.requests[3].url, "/vpcs/scoped"),
                 "vultr_cluster_cleanup_deletes_only_exact_scoped_vpc");
    http.complete(MultiCurlClient::Status::success, 404);
    suite.expect(stack.hasSuspendedCoroutines() == false && failure.empty() && destroyed == 0,
                 "vultr_cluster_cleanup_scoped_vpc_not_found_delete_is_idempotent");
  }

  {
    ScriptedVultrHttp http = {};
    ScriptedVultrDelay delay = {};
    VultrBrainIaaS provider = {};
    configureVultrProviderForTest(provider, http, "ewr"_ctv, &delay);
    CoroutineStack stack = {};
    String failure = {};
    uint32_t destroyed = 0;
    String clusterUUID = "0123456789abcdef0123456789abcdef"_ctv;
    provider.destroyClusterMachines(&stack, clusterUUID, destroyed, failure);
    http.complete(MultiCurlClient::Status::success, 200, R"json({"instances":[]})json"_ctv);
    http.complete(MultiCurlClient::Status::success, 200, R"json({"bare_metals":[]})json"_ctv);
    http.complete(MultiCurlClient::Status::success, 200,
                  R"json({"vpcs":[{"id":"scoped","region":"ewr","description":"prodigy-managed-vpc-ewr-0123456789abcdef0123456789abcdef","v4_subnet":"10.214.32.0","v4_subnet_mask":20}]})json"_ctv);
    http.complete(MultiCurlClient::Status::success, 400,
                  R"json({"error":"The following servers are attached to this VPC network: 192.0.2.10","status":400})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() && delay.pending != nullptr &&
                     delay.delays.size() == 1 &&
                     delay.delays[0] == uint64_t(vultrManagedVPCDeleteRetryMs) * 1'000u,
                 "vultr_cluster_cleanup_waits_for_lingering_vpc_attachment");
    suite.expect(delay.complete() && http.requests.size() == 5 &&
                     http.requests[4].method == MultiCurlClient::Method::delete_,
                 "vultr_cluster_cleanup_retries_exact_vpc_delete_after_attachment_delay");
    http.complete(MultiCurlClient::Status::success, 204);
    suite.expect(!stack.hasSuspendedCoroutines() && failure.empty() && destroyed == 0,
                 "vultr_cluster_cleanup_lingering_attachment_retry_succeeds");
  }

  {
    ScriptedVultrHttp http = {};
    VultrBrainIaaS provider = {};
    configureVultrProviderForTest(provider, http, "ewr"_ctv);
    CoroutineStack stack = {};
    String failure = {};
    uint32_t destroyed = 0;
    provider.destroyClusterMachines(&stack, "0123456789abcdef0123456789abcdef"_ctv, destroyed, failure);
    http.complete(MultiCurlClient::Status::success, 200, R"json({"instances":[]})json"_ctv);
    http.complete(MultiCurlClient::Status::success, 200, R"json({"bare_metals":[]})json"_ctv);
    http.complete(MultiCurlClient::Status::success, 200,
                  R"json({"vpcs":[{"id":"legacy","region":"ewr","description":"prodigy-managed-vpc-ewr"}]})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() == false && failure.empty() && http.requests.size() == 3,
                 "vultr_cluster_cleanup_never_deletes_legacy_region_vpc");
  }

  {
    ScriptedVultrHttp http = {};
    VultrBrainIaaS provider = {};
    configureVultrProviderForTest(provider, http, "ewr"_ctv);
    CoroutineStack stack = {};
    String failure = {};
    uint32_t destroyed = 0;
    provider.destroyClusterMachines(&stack, "0123456789abcdef0123456789abcdef"_ctv, destroyed, failure);
    http.complete(MultiCurlClient::Status::success, 200, R"json({"instances":[]})json"_ctv);
    http.complete(MultiCurlClient::Status::success, 200, R"json({"bare_metals":[]})json"_ctv);
    http.complete(MultiCurlClient::Status::success, 200,
                  R"json({"vpcs":[{"id":"one","region":"ewr","description":"prodigy-managed-vpc-ewr-0123456789abcdef0123456789abcdef","v4_subnet":"10.214.32.0","v4_subnet_mask":20},{"id":"two","region":"ewr","description":"prodigy-managed-vpc-ewr-0123456789abcdef0123456789abcdef","v4_subnet":"10.214.32.0","v4_subnet_mask":20}]})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() == false &&
                     failure == "vultr managed vpc cleanup 'prodigy-managed-vpc-ewr-0123456789abcdef0123456789abcdef' is ambiguous"_ctv &&
                     http.requests.size() == 3,
                 "vultr_cluster_cleanup_rejects_ambiguous_scoped_vpc");
  }

  {
    ScriptedVultrHttp http = {};
    VultrBrainIaaS provider = {};
    configureVultrProviderForTest(provider, http, "ewr"_ctv);
    CoroutineStack stack = {};
    String failure = {};
    uint32_t destroyed = 0;
    provider.destroyClusterMachines(&stack, "0123456789abcdef0123456789abcdef"_ctv, destroyed, failure);
    http.complete(MultiCurlClient::Status::success, 200, R"json({"instances":[]})json"_ctv);
    http.complete(MultiCurlClient::Status::success, 200, R"json({"bare_metals":[]})json"_ctv);
    http.complete(MultiCurlClient::Status::success, 200,
                  R"json({"vpcs":[{"id":"collision","region":"ewr","description":"prodigy-managed-vpc-ewr-0123456789abcdef0123456789abcdef","v4_subnet":"10.1.0.0","v4_subnet_mask":20}]})json"_ctv);
    suite.expect(stack.hasSuspendedCoroutines() == false &&
                     failure == "vultr managed vpc cleanup 'prodigy-managed-vpc-ewr-0123456789abcdef0123456789abcdef' does not match its subnet identity"_ctv &&
                     http.requests.size() == 3,
                 "vultr_cluster_cleanup_rejects_description_collision_with_other_subnet");
  }

  basics_log("SUMMARY: failed=%d\n", suite.failed);
  return suite.failed == 0 ? 0 : 1;
}
