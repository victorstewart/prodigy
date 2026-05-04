#include <networking/includes.h>
#include <services/debug.h>
#include <services/base64.h>
#include <prodigy/iaas/aws/aws.h>
#include <prodigy/iaas/gcp/gcp.h>
#include <prodigy/iaas/azure/azure.h>
#include <prodigy/iaas/vultr/vultr.h>

#include <arpa/inet.h>
#include <cstdio>
#include <simdjson.h>
#include <sys/socket.h>

class TestSuite
{
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
         basics_log("FAIL: %s\n", name);
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

int main(void)
{
   TestSuite suite = {};
   auto stringContains = [] (const String& haystack, const char *needle) -> bool {
      if (needle == nullptr)
      {
         return false;
      }

      std::string_view haystackView(reinterpret_cast<const char *>(haystack.data()), size_t(haystack.size()));
      return haystackView.find(needle) != std::string_view::npos;
   };
   auto openLoopbackListener = [] (uint16_t& portOut) -> int {
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
      String response = {};
      bool ok = AzureHttp::appendResponseBytes(response, reinterpret_cast<const uint8_t *>("token"), 5);
      suite.expect(ok, "azure_http_append_response_bytes_succeeds");
      suite.expect(response == "token"_ctv, "azure_http_append_response_bytes_writes_all_bytes");
   }

   {
      uint8_t storage[4] = {};
      String constrained(storage, sizeof(storage), Copy::no, 0);
      bool ok = AzureHttp::appendResponseBytes(constrained, reinterpret_cast<const uint8_t *>("token"), 5);
      suite.expect(!ok, "azure_http_append_response_bytes_fails_when_buffer_cannot_grow");
      suite.expect(constrained.size() == 0, "azure_http_append_response_bytes_does_not_silently_truncate");
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
      String json = "{\"id\":\"abc123\",\"region\":\"ewr\",\"plan\":\"vc2-2c-4gb\"}"_ctv;
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
      suite.expect(vultrParseAssignedIPv4("45.76.166.5", assignedIPv4), "vultr_assigned_ipv4_accepts_real_address");
      suite.expect(assignedIPv4 != 0, "vultr_assigned_ipv4_value_nonzero");
      suite.expect(vultrParseAssignedIPv4("0.0.0.0", assignedIPv4) == false, "vultr_assigned_ipv4_rejects_unspecified_address");
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
         suite.expect(vultrFindMachineIDByLabel(doc, MachineConfig::MachineKind::vm, "missing", recoveredID) == false, "vultr_create_recovery_rejects_missing_label");
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

   basics_log("SUMMARY: failed=%d\n", suite.failed);
   return suite.failed == 0 ? 0 : 1;
}
