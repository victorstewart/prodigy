#include <networking/includes.h>
#include <services/debug.h>

#define main nametag_mothership_main_disabled
#include <prodigy/mothership/mothership.cpp>
#undef main

#include <cstdio>
#include <cstdlib>
#include <filesystem>

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

class ScopedEnvVar
{
private:

   String name = {};
   String previousValue = {};
   bool hadPreviousValue = false;

public:

   ScopedEnvVar(const char *envName, const char *value)
   {
      name.assign(envName);
      if (const char *previous = getenv(envName); previous && previous[0] != '\0')
      {
         previousValue.assign(previous);
         hadPreviousValue = true;
      }

      setenv(envName, value, 1);
   }

   ~ScopedEnvVar()
   {
      if (hadPreviousValue)
      {
         setenv(name.c_str(), previousValue.c_str(), 1);
      }
      else
      {
         unsetenv(name.c_str());
      }
   }
};

static ProviderMachineOffer makeProviderOffer(const String& type, MachineConfig::MachineKind kind, double hourlyUSD)
{
   ProviderMachineOffer offer = {};
   offer.provider = ProdigyEnvironmentKind::aws;
   offer.providerScope = "us-east-1"_ctv;
   offer.country = "United States"_ctv;
   offer.region = "us-east-1"_ctv;
   offer.zone = "us-east-1a"_ctv;
   offer.providerMachineType = type;
   offer.lifetime = MachineLifetime::ondemand;
   offer.kind = kind;
   offer.nLogicalCores = 8;
   offer.nMemoryMB = 32768;
   offer.nStorageMB = 262144;
   offer.nicSpeedMbps = 25'000;
   offer.providesHostPublic4 = true;
   offer.hasInternetAccess = true;
   offer.hourlyUSD = hourlyUSD;
   return offer;
}

static MothershipProviderMachineOffer makeSurveyedOffer(const String& type, MachineConfig::MachineKind kind, uint64_t hourlyMicrousd)
{
   MothershipProviderMachineOffer offer = {};
   offer.provider = MothershipClusterProvider::aws;
   offer.providerScope = "us-east-1"_ctv;
   offer.country = "United States"_ctv;
   offer.region = "us-east-1"_ctv;
   offer.zone = "us-east-1a"_ctv;
   offer.providerMachineType = type;
   offer.billingModel = ProviderMachineBillingModel::hourly;
   offer.kind = kind;
   offer.nLogicalCores = 8;
   offer.nMemoryMB = 32u * 1024u;
   offer.nStorageMBDefault = 100u * 1024u;
   offer.nicSpeedMbps = 25'000;
   offer.providesHostPublic4 = true;
   offer.hourlyMicrousd = hourlyMicrousd;
   offer.priceCompleteness = MothershipProviderOfferPriceCompleteness::computeStorageNetwork;
   return offer;
}

static bool selectionVectorContainsType(
   const Vector<MothershipMachineOfferSelection>& selections,
   const String& providerMachineType,
   uint32_t expectedCount = 0)
{
   for (const MothershipMachineOfferSelection& selection : selections)
   {
      if (selection.providerMachineType.equals(providerMachineType))
      {
         return expectedCount == 0 || selection.count == expectedCount;
      }
   }

   return false;
}

static bool offerVectorContainsType(
   const Vector<MothershipProviderMachineOffer>& offers,
   const String& providerMachineType)
{
   for (const MothershipProviderMachineOffer& offer : offers)
   {
      if (offer.providerMachineType.equals(providerMachineType))
      {
         return true;
      }
   }

   return false;
}

static bool providerVectorContains(const Vector<MothershipClusterProvider>& providers, MothershipClusterProvider provider)
{
   for (MothershipClusterProvider candidate : providers)
   {
      if (candidate == provider)
      {
         return true;
      }
   }

   return false;
}

static bool stringVectorContains(const Vector<String>& strings, const String& value)
{
   for (const String& candidate : strings)
   {
      if (candidate.equals(value))
      {
         return true;
      }
   }

   return false;
}

static bool targetVectorContains(
   const Vector<MothershipProviderScopeTarget>& targets,
   MothershipClusterProvider provider,
   const String& providerScope,
   const String& providerCredentialName)
{
   for (const MothershipProviderScopeTarget& target : targets)
   {
      if (target.provider == provider
         && target.providerScope.equals(providerScope)
         && target.providerCredentialName.equals(providerCredentialName))
      {
         return true;
      }
   }

   return false;
}

static bool parseJSON(const char *jsonText, String& storage, simdjson::dom::element& doc, simdjson::dom::parser& parser)
{
   storage.assign(jsonText);
   storage.need(simdjson::SIMDJSON_PADDING);
   return parser.parse(storage.data(), storage.size()).get(doc) == simdjson::SUCCESS;
}

int main(void)
{
   TestSuite suite = {};

   {
      ProviderMachineOfferSurveyRequest request = {};
      request.country = "united states"_ctv;
      request.machineKindsMask = providerMachineKindMaskBit(MachineConfig::MachineKind::bareMetal);
      request.minNICSpeedGbps = 10;

      ProviderMachineOffer bareMetal = makeProviderOffer("bm.large"_ctv, MachineConfig::MachineKind::bareMetal, 1.0);
      ProviderMachineOffer vm = makeProviderOffer("vm.large"_ctv, MachineConfig::MachineKind::vm, 0.5);
      ProviderMachineOffer slowBareMetal = bareMetal;
      slowBareMetal.providerMachineType = "bm.slow"_ctv;
      slowBareMetal.nicSpeedMbps = 1'000;

      suite.expect(providerMachineOfferMatchesSurveyRequest(bareMetal, request), "provider_offer_request_accepts_bare_metal");
      suite.expect(providerMachineOfferMatchesSurveyRequest(vm, request) == false, "provider_offer_request_rejects_vm_when_bare_metal_requested");
      suite.expect(providerMachineOfferMatchesSurveyRequest(slowBareMetal, request) == false, "provider_offer_request_rejects_insufficient_nic_speed_gbps");
   }

   {
      bool providesHostPublic4 = false;
      bool providesHostPublic6 = false;
      String failure = {};

      suite.expect(
         mothershipResolveScopeHostPublicCapabilities(
            MothershipClusterProvider::aws,
            "us-east-1"_ctv,
            providesHostPublic4,
            providesHostPublic6,
            &failure),
         "pricing_host_public_capability_aws_scope");
      suite.expect(providesHostPublic4, "pricing_host_public_capability_aws_public4");
      suite.expect(providesHostPublic6, "pricing_host_public_capability_aws_public6");

      providesHostPublic4 = false;
      providesHostPublic6 = false;
      suite.expect(
         mothershipResolveScopeHostPublicCapabilities(
            MothershipClusterProvider::gcp,
            "projects/my-gcp-project/zones/us-central1-a"_ctv,
            providesHostPublic4,
            providesHostPublic6,
            &failure),
         "pricing_host_public_capability_gcp_scope");
      suite.expect(providesHostPublic4, "pricing_host_public_capability_gcp_public4");
      suite.expect(providesHostPublic6, "pricing_host_public_capability_gcp_public6");

      providesHostPublic4 = false;
      providesHostPublic6 = false;
      suite.expect(
         mothershipResolveScopeHostPublicCapabilities(
            MothershipClusterProvider::azure,
            "sub123/resourcegroup123/eastus"_ctv,
            providesHostPublic4,
            providesHostPublic6,
            &failure),
         "pricing_host_public_capability_azure_scope");
      suite.expect(providesHostPublic4, "pricing_host_public_capability_azure_public4");
      suite.expect(providesHostPublic6, "pricing_host_public_capability_azure_public6");
   }

   {
      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      String json = {};
      suite.expect(parseJSON("{\"architecture\":\"x86_64\",\"nLogicalCores\":2,\"memoryGB\":2,\"filesystemMB\":512,\"storageGB\":10}", json, doc, parser), "pricing_application_config_gb_json");

      ApplicationConfig config = {};
      String failure = {};
      suite.expect(mothershipParsePricingPlanningApplicationConfigJSON(doc, config, &failure), "pricing_application_config_accepts_mb_or_gb");
      suite.expect(failure.size() == 0, "pricing_application_config_accepts_mb_or_gb_no_failure");
      suite.expect(config.cpuMode == ApplicationCPUMode::isolated, "pricing_application_config_defaults_to_isolated_cpu_mode");
      suite.expect(config.nLogicalCores == 2u, "pricing_application_config_integer_cpu_sets_isolated_core_count");
      suite.expect(config.sharedCPUMillis == 0u, "pricing_application_config_integer_cpu_clears_shared_millis");
      suite.expect(config.memoryMB == 2u * 1024u, "pricing_application_config_memory_gb_to_mb");
      suite.expect(config.filesystemMB == 512u, "pricing_application_config_filesystem_mb_preserved");
      suite.expect(config.storageMB == 10u * 1024u, "pricing_application_config_storage_gb_to_mb");
   }

   {
      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      String json = {};
      suite.expect(parseJSON("{\"architecture\":\"x86_64\",\"nLogicalCores\":2,\"memoryMB\":512,\"memoryGB\":1}", json, doc, parser), "pricing_application_config_mixed_units_json");

      ApplicationConfig config = {};
      String failure = {};
      suite.expect(mothershipParsePricingPlanningApplicationConfigJSON(doc, config, &failure) == false, "pricing_application_config_rejects_mb_and_gb_together");
      suite.expect(failure.size() > 0, "pricing_application_config_rejects_mb_and_gb_reason");
   }

   {
      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      String json = {};
      suite.expect(parseJSON("{\"architecture\":\"x86_64\",\"nLogicalCores\":1.5,\"memoryGB\":2}", json, doc, parser), "pricing_application_config_fractional_cpu_json");

      ApplicationConfig config = {};
      String failure = {};
      suite.expect(mothershipParsePricingPlanningApplicationConfigJSON(doc, config, &failure), "pricing_application_config_fractional_cpu_accepts_number");
      suite.expect(failure.size() == 0, "pricing_application_config_fractional_cpu_no_failure");
      suite.expect(config.cpuMode == ApplicationCPUMode::shared, "pricing_application_config_fractional_cpu_shared_mode");
      suite.expect(config.sharedCPUMillis == 1500u, "pricing_application_config_fractional_cpu_millis");
      suite.expect(config.nLogicalCores == 2u, "pricing_application_config_fractional_cpu_core_hint");
   }

   {
      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      String json = {};
      suite.expect(parseJSON("{\"architecture\":\"x86_64\",\"nLogicalCores\":128,\"memoryGB\":2}", json, doc, parser), "pricing_application_config_large_integer_cpu_json");

      ApplicationConfig config = {};
      String failure = {};
      suite.expect(mothershipParsePricingPlanningApplicationConfigJSON(doc, config, &failure), "pricing_application_config_large_integer_cpu_accepts_number");
      suite.expect(failure.size() == 0, "pricing_application_config_large_integer_cpu_no_failure");
      suite.expect(config.cpuMode == ApplicationCPUMode::isolated, "pricing_application_config_large_integer_cpu_isolated_mode");
      suite.expect(config.nLogicalCores == 128u, "pricing_application_config_large_integer_cpu_core_count");
      suite.expect(config.sharedCPUMillis == 0u, "pricing_application_config_large_integer_cpu_clears_shared_millis");
   }

   {
      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      String json = {};
      suite.expect(parseJSON("{\"architecture\":\"x86_64\",\"type\":\"stateless\",\"nLogicalCores\":2,\"memoryGB\":2}", json, doc, parser), "pricing_application_config_rejects_type_json");

      ApplicationConfig config = {};
      String failure = {};
      suite.expect(mothershipParsePricingPlanningApplicationConfigJSON(doc, config, &failure) == false, "pricing_application_config_rejects_type");
      suite.expect(failure.equals("applications[].config.type is not recognized"_ctv), "pricing_application_config_rejects_type_reason");
   }

   {
      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      String json = {};
      suite.expect(parseJSON("{\"architecture\":\"x86_64\",\"nLogicalCores\":2,\"memoryGB\":2,\"minGPUs\":1,\"gpuMemoryGB\":24,\"nicSpeedGbps\":10}", json, doc, parser), "pricing_application_config_flat_machine_fields_json");

      ApplicationConfig config = {};
      String failure = {};
      suite.expect(mothershipParsePricingPlanningApplicationConfigJSON(doc, config, &failure), "pricing_application_config_accepts_flat_machine_fields");
      suite.expect(failure.size() == 0, "pricing_application_config_accepts_flat_machine_fields_no_failure");
      suite.expect(config.minGPUs == 1, "pricing_application_config_sets_min_gpus");
      suite.expect(config.gpuMemoryGB == 24, "pricing_application_config_sets_gpu_memory_gb");
      suite.expect(config.nicSpeedGbps == 10, "pricing_application_config_sets_nic_speed_gbps");
   }

   {
      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      String json = {};
      suite.expect(parseJSON("{\"architecture\":\"x86_64\",\"nLogicalCores\":2,\"memoryGB\":2,\"machineResourceCriteria\":{\"minInternetDownloadMbps\":500}}", json, doc, parser), "pricing_application_config_rejects_internet_criteria_json");

      ApplicationConfig config = {};
      String failure = {};
      suite.expect(mothershipParsePricingPlanningApplicationConfigJSON(doc, config, &failure) == false, "pricing_application_config_rejects_nested_machine_resource_criteria");
      suite.expect(failure.equals("applications[].config.machineResourceCriteria removed; place minGPUs, gpuMemoryGB, and nicSpeedGbps directly on applications[].config"_ctv), "pricing_application_config_rejects_nested_machine_resource_criteria_reason");
   }

   {
      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      String json = {};
      suite.expect(parseJSON("{\"architecture\":\"x86_64\",\"nLogicalCores\":2,\"memoryGB\":2,\"minInternetDownloadMbps\":500}", json, doc, parser), "pricing_application_config_rejects_internet_criteria_json");

      ApplicationConfig config = {};
      String failure = {};
      suite.expect(mothershipParsePricingPlanningApplicationConfigJSON(doc, config, &failure) == false, "pricing_application_config_rejects_internet_criteria");
      suite.expect(failure.equals("applications[].config.minInternetDownloadMbps is not supported for planning"_ctv), "pricing_application_config_rejects_internet_criteria_reason");
   }

   {
      ProviderMachineOffer offer = makeProviderOffer("bm.tight"_ctv, MachineConfig::MachineKind::bareMetal, 1.0);
      offer.nLogicalCores = 4;
      offer.nMemoryMB = 16'384;
      offer.nStorageMB = 102'400;

      uint32_t usableLogicalCores = 0;
      uint32_t usableMemoryMB = 0;
      uint32_t usableStorageMB = 0;
      suite.expect(
         providerMachineOfferResolveUsableResources(offer, usableLogicalCores, usableMemoryMB, usableStorageMB),
         "provider_offer_resolve_usable_resources");
      suite.expect(usableLogicalCores == 2, "provider_offer_resolve_usable_resources_cores");
      suite.expect(usableMemoryMB == 12'288, "provider_offer_resolve_usable_resources_memory");
      suite.expect(usableStorageMB == 98'304, "provider_offer_resolve_usable_resources_storage");

      ProviderMachineOfferSurveyRequest request = {};
      request.country = "United States"_ctv;
      request.minLogicalCores = 3;
      suite.expect(providerMachineOfferMatchesSurveyRequest(offer, request) == false, "provider_offer_request_rejects_raw_core_count_without_usable_headroom");
      request.minLogicalCores = 2;
      request.minMemoryMB = 13'000;
      suite.expect(providerMachineOfferMatchesSurveyRequest(offer, request) == false, "provider_offer_request_rejects_raw_memory_without_usable_headroom");
      request.minMemoryMB = 12'000;
      request.minStorageMB = 99'000;
      suite.expect(providerMachineOfferMatchesSurveyRequest(offer, request) == false, "provider_offer_request_rejects_raw_storage_without_usable_headroom");
      request.minStorageMB = 98'000;
      suite.expect(providerMachineOfferMatchesSurveyRequest(offer, request), "provider_offer_request_accepts_usable_capacity_floor");
   }

   {
      ProviderMachineOffer bareMetal = makeProviderOffer("bm.xlarge"_ctv, MachineConfig::MachineKind::bareMetal, 2.0);
      MachineConfig config = {};
      suite.expect(providerMachineOfferBuildMachineConfig(bareMetal, config), "provider_offer_build_machine_config");
      suite.expect(config.kind == MachineConfig::MachineKind::bareMetal, "provider_offer_build_machine_config_preserves_kind");
      suite.expect(config.slug.equals("bm.xlarge"_ctv), "provider_offer_build_machine_config_preserves_slug");
   }

   {
      Vector<MothershipProviderMachineOffer> offers = {};

      MothershipProviderMachineOffer smallStorage = makeSurveyedOffer("small.storage"_ctv, MachineConfig::MachineKind::vm, 1'000'000);
      smallStorage.nStorageMBDefault = 20u * 1024u;
      smallStorage.extraStorageMicrousdPerGBHour = 50'000;
      offers.push_back(smallStorage);

      MothershipProviderMachineOffer largeStorage = makeSurveyedOffer("large.storage"_ctv, MachineConfig::MachineKind::vm, 1'000'000);
      largeStorage.nStorageMBDefault = 100u * 1024u;
      largeStorage.extraStorageMicrousdPerGBHour = 80'000;
      offers.push_back(largeStorage);

      mothershipPruneDominatedOffers(offers);
      suite.expect(offers.size() == 2, "pricing_dominance_keeps_larger_default_storage_offer");
      suite.expect(offerVectorContainsType(offers, "small.storage"_ctv), "pricing_dominance_keeps_small_storage_offer");
      suite.expect(offerVectorContainsType(offers, "large.storage"_ctv), "pricing_dominance_keeps_large_storage_offer");
   }

   {
      uint32_t usableLogicalCores = 0;
      uint32_t usableMemoryMB = 0;
      uint32_t usableStorageMB = 0;
      suite.expect(
         providerMachineOfferResolveUsableResourcesFromTotals(4, 16'384, 102'400, usableLogicalCores, usableMemoryMB, usableStorageMB),
         "provider_offer_resolve_usable_resources_from_totals");
      suite.expect(usableLogicalCores == 2, "provider_offer_resolve_usable_resources_from_totals_cores");
      suite.expect(usableMemoryMB == 12'288, "provider_offer_resolve_usable_resources_from_totals_memory");
      suite.expect(usableStorageMB == 98'304, "provider_offer_resolve_usable_resources_from_totals_storage");
   }

   {
      MothershipMachineOfferSelection selection = {};
      selection.providerMachineType = "bm-explicit"_ctv;
      selection.kind = MachineConfig::MachineKind::bareMetal;
      selection.count = 3;
      selection.storageMB = 524288;

      String encoded = {};
      BitseryEngine::serialize(encoded, selection);
      MothershipMachineOfferSelection decoded = {};
      suite.expect(BitseryEngine::deserializeSafe(encoded, decoded), "pricing_selection_roundtrip_deserializes");
      suite.expect(decoded.providerMachineType.equals(selection.providerMachineType), "pricing_selection_roundtrip_type");
      suite.expect(decoded.kind == MachineConfig::MachineKind::bareMetal, "pricing_selection_roundtrip_kind");
      suite.expect(decoded.count == 3, "pricing_selection_roundtrip_count");
      suite.expect(decoded.storageMB == 524288, "pricing_selection_roundtrip_storage");
   }

   {
      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      String json = {};
      suite.expect(parseJSON("[{\"providerMachineType\":\"bm-explicit\",\"kind\":\"bareMetal\",\"count\":3,\"storageGB\":512}]", json, doc, parser), "pricing_machine_selection_storage_gb_json");

      Vector<MothershipMachineOfferSelection> selections = {};
      String failure = {};
      suite.expect(mothershipParsePricingMachineSelectionsJSON(doc, selections, &failure), "pricing_machine_selection_accepts_storage_gb");
      suite.expect(failure.size() == 0, "pricing_machine_selection_accepts_storage_gb_no_failure");
      suite.expect(selections.size() == 1, "pricing_machine_selection_accepts_storage_gb_count");
      suite.expect(selections[0].storageMB == 512u * 1024u, "pricing_machine_selection_storage_gb_to_mb");
   }

   {
      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      String json = {};
      suite.expect(parseJSON("[{\"providerMachineType\":\"bm-explicit\",\"kind\":\"bareMetal\",\"count\":3,\"isBrain\":true,\"storageGB\":512}]", json, doc, parser), "pricing_machine_selection_rejects_is_brain_json");

      Vector<MothershipMachineOfferSelection> selections = {};
      String failure = {};
      suite.expect(mothershipParsePricingMachineSelectionsJSON(doc, selections, &failure) == false, "pricing_machine_selection_rejects_is_brain");
      suite.expect(failure.equals("machines[].isBrain is not recognized"_ctv), "pricing_machine_selection_rejects_is_brain_reason");
   }

   {
      MothershipClusterRecommendationRequest request = {};
      request.country = "United States"_ctv;
      request.minMachines = 3;
      request.machineKindsMask = providerMachineKindMaskBit(MachineConfig::MachineKind::bareMetal);

      String encoded = {};
      BitseryEngine::serialize(encoded, request);
      MothershipClusterRecommendationRequest decoded = {};
      suite.expect(BitseryEngine::deserializeSafe(encoded, decoded), "pricing_recommendation_request_roundtrip_deserializes");
      suite.expect(decoded.machineKindsMask == providerMachineKindMaskBit(MachineConfig::MachineKind::bareMetal), "pricing_recommendation_request_roundtrip_machine_kind_mask");
      suite.expect(decoded.minMachines == 3, "pricing_recommendation_request_roundtrip_min_machines");
   }

   {
      MothershipClusterRecommendation recommendation = {};
      recommendation.found = true;
      recommendation.withinBudget = true;
      recommendation.country = "United States"_ctv;
      recommendation.totalMachines = 3;
      recommendation.hourlyMicrousd = 4'000'000;

      MothershipMachineOfferSelection cpuSelection = {};
      cpuSelection.providerMachineType = "cpu.large"_ctv;
      cpuSelection.kind = MachineConfig::MachineKind::vm;
      cpuSelection.count = 2;
      cpuSelection.storageMB = 102400;
      recommendation.machineSelections.push_back(cpuSelection);

      MothershipMachineOfferSelection gpuSelection = {};
      gpuSelection.providerMachineType = "gpu.large"_ctv;
      gpuSelection.kind = MachineConfig::MachineKind::vm;
      gpuSelection.count = 1;
      gpuSelection.storageMB = 204800;
      recommendation.machineSelections.push_back(gpuSelection);

      String encoded = {};
      BitseryEngine::serialize(encoded, recommendation);
      MothershipClusterRecommendation decoded = {};
      suite.expect(BitseryEngine::deserializeSafe(encoded, decoded), "pricing_recommendation_roundtrip_deserializes");
      suite.expect(decoded.machineSelections.size() == 2, "pricing_recommendation_roundtrip_selection_count");
      suite.expect(decoded.totalMachines == 3, "pricing_recommendation_roundtrip_total_machines");
      suite.expect(decoded.machineSelections[0].providerMachineType.equals("cpu.large"_ctv), "pricing_recommendation_roundtrip_first_selection_type");
      suite.expect(decoded.machineSelections[1].providerMachineType.equals("gpu.large"_ctv), "pricing_recommendation_roundtrip_second_selection_type");
   }

   {
      MothershipClusterCostEstimateRequest request = {};
      request.country = "United States"_ctv;
      request.billingModel = ProviderMachineBillingModel::hourly;
      request.ingressMBPerHour = 1024;
      request.egressMBPerHour = 2048;

      MothershipMachineOfferSelection selection = {};
      selection.providerMachineType = "priced.large"_ctv;
      selection.kind = MachineConfig::MachineKind::vm;
      selection.count = 1;
      selection.storageMB = 30u * 1024u;
      request.machines.push_back(selection);

      Vector<MothershipProviderMachineOffer> offers = {};
      MothershipProviderMachineOffer offer = makeSurveyedOffer("priced.large"_ctv, MachineConfig::MachineKind::vm, 1'000'000);
      offer.nStorageMBDefault = 20u * 1024u;
      offer.extraStorageMicrousdPerGBHour = 100'000;
      offer.ingressMicrousdPerGB = 200'000;
      offer.egressMicrousdPerGB = 300'000;
      offers.push_back(offer);

      MothershipClusterHourlyEstimate estimate = {};
      suite.expect(
         mothershipEstimateClusterHourlyCost(request, offers, estimate),
         "pricing_estimate_includes_storage_and_network_breakdown");
      suite.expect(estimate.fits, "pricing_estimate_includes_storage_and_network_breakdown_fits");
      suite.expect(estimate.computeHourlyMicrousd == 1'000'000, "pricing_estimate_compute_breakdown");
      suite.expect(estimate.storageHourlyMicrousd == 1'000'000, "pricing_estimate_storage_breakdown");
      suite.expect(estimate.ingressHourlyMicrousd == 200'000, "pricing_estimate_ingress_breakdown");
      suite.expect(estimate.egressHourlyMicrousd == 600'000, "pricing_estimate_egress_breakdown");
      suite.expect(estimate.hourlyMicrousd == 2'800'000, "pricing_estimate_total_breakdown");
   }

   {
      MothershipClusterRecommendationRequest request = {};
      request.country = "United States"_ctv;
      request.billingModel = ProviderMachineBillingModel::hourly;
      request.minMachines = 1;
      request.ingressMBPerHour = 1536;
      request.egressMBPerHour = 2560;

      String encoded = {};
      BitseryEngine::serialize(encoded, request);
      MothershipClusterRecommendationRequest decoded = {};
      suite.expect(BitseryEngine::deserializeSafe(encoded, decoded), "pricing_recommendation_request_roundtrip_ingress_egress_deserializes");
      suite.expect(decoded.ingressMBPerHour == 1536, "pricing_recommendation_request_roundtrip_ingress");
      suite.expect(decoded.egressMBPerHour == 2560, "pricing_recommendation_request_roundtrip_egress");
   }

   {
      MothershipClusterRecommendationRequest request = {};
      request.country = "United States"_ctv;
      request.billingModel = ProviderMachineBillingModel::hourly;
      request.minMachines = 2;

      MothershipPlanningApplication frontend = {};
      frontend.name = "frontend"_ctv;
      frontend.instances = 1;
      frontend.config.type = ApplicationType::stateless;
      frontend.config.nLogicalCores = 1;
      frontend.config.memoryMB = 1024;
      frontend.config.filesystemMB = 512;
      frontend.config.storageMB = 1024;
      frontend.config.cpuMode = ApplicationCPUMode::shared;
      frontend.config.sharedCPUMillis = 1000;
      request.applications.push_back(frontend);

      MothershipPlanningApplication inference = {};
      inference.name = "inference"_ctv;
      inference.instances = 1;
      inference.config.type = ApplicationType::stateless;
      inference.config.nLogicalCores = 2;
      inference.config.memoryMB = 4096;
      inference.config.filesystemMB = 1024;
      inference.config.storageMB = 4096;
      inference.config.cpuMode = ApplicationCPUMode::shared;
      inference.config.sharedCPUMillis = 2000;
      inference.config.minGPUs = 1;
      inference.config.gpuMemoryGB = 24;
      request.applications.push_back(inference);

      MothershipProviderScopeTarget target = {};
      target.provider = MothershipClusterProvider::aws;
      target.providerScope = "us-east-1"_ctv;

      Vector<MothershipProviderMachineOffer> offers = {};

      MothershipProviderMachineOffer cpuOffer = {};
      cpuOffer.provider = MothershipClusterProvider::aws;
      cpuOffer.providerScope = "us-east-1"_ctv;
      cpuOffer.country = "United States"_ctv;
      cpuOffer.region = "us-east-1"_ctv;
      cpuOffer.zone = "us-east-1a"_ctv;
      cpuOffer.providerMachineType = "cpu.large"_ctv;
      cpuOffer.billingModel = ProviderMachineBillingModel::hourly;
      cpuOffer.kind = MachineConfig::MachineKind::vm;
      cpuOffer.nLogicalCores = 8;
      cpuOffer.nMemoryMB = 32u * 1024u;
      cpuOffer.nStorageMBDefault = 100u * 1024u;
      cpuOffer.nicSpeedMbps = 25'000;
      cpuOffer.providesHostPublic4 = true;
      cpuOffer.hourlyMicrousd = 1'000'000;
      offers.push_back(cpuOffer);

      MothershipProviderMachineOffer gpuOffer = cpuOffer;
      gpuOffer.providerMachineType = "gpu.large"_ctv;
      gpuOffer.gpuCount = 1;
      gpuOffer.gpuMemoryMBPerDevice = 24u * 1024u;
      gpuOffer.hourlyMicrousd = 3'000'000;
      offers.push_back(gpuOffer);

      MothershipClusterRecommendation recommendation = {};
      suite.expect(
         mothershipRecommendClusterForApplications(request, offers, target, recommendation),
         "pricing_recommendation_accepts_generic_machine_pools");
      suite.expect(recommendation.found, "pricing_recommendation_found");
      suite.expect(recommendation.totalMachines == 2, "pricing_recommendation_total_machines");
      suite.expect(recommendation.machineSelections.size() == 2, "pricing_recommendation_selection_count");
      suite.expect(recommendation.hourlyMicrousd == 4'000'000, "pricing_recommendation_hourly_cost");

      bool sawCPU = false;
      bool sawGPU = false;
      for (const MothershipMachineOfferSelection& selection : recommendation.machineSelections)
      {
         if (selection.providerMachineType.equals("cpu.large"_ctv))
         {
            sawCPU = (selection.count == 1);
         }
         else if (selection.providerMachineType.equals("gpu.large"_ctv))
         {
            sawGPU = (selection.count == 1);
         }
      }

      suite.expect(sawCPU, "pricing_recommendation_contains_cpu_selection");
      suite.expect(sawGPU, "pricing_recommendation_contains_gpu_selection");
   }

   {
      MothershipClusterRecommendationRequest request = {};
      request.country = "United States"_ctv;
      request.billingModel = ProviderMachineBillingModel::hourly;
      request.minMachines = 1;

      MothershipPlanningApplication storageHeavy = {};
      storageHeavy.name = "storage-heavy"_ctv;
      storageHeavy.instances = 1;
      storageHeavy.config.type = ApplicationType::stateless;
      storageHeavy.config.nLogicalCores = 1;
      storageHeavy.config.memoryMB = 1024;
      storageHeavy.config.storageMB = 30u * 1024u;
      storageHeavy.config.cpuMode = ApplicationCPUMode::shared;
      storageHeavy.config.sharedCPUMillis = 1000;
      request.applications.push_back(storageHeavy);

      MothershipProviderScopeTarget target = {};
      target.provider = MothershipClusterProvider::aws;
      target.providerScope = "us-east-1"_ctv;

      Vector<MothershipProviderMachineOffer> offers = {};
      MothershipProviderMachineOffer offer = makeSurveyedOffer("storage.large"_ctv, MachineConfig::MachineKind::vm, 500'000);
      offer.nLogicalCores = 3;
      offer.nMemoryMB = 6u * 1024u;
      offer.nStorageMBDefault = 20u * 1024u;
      offer.extraStorageMicrousdPerGBHour = 100'000;
      offers.push_back(offer);

      MothershipClusterRecommendation recommendation = {};
      suite.expect(
         mothershipRecommendClusterForApplications(request, offers, target, recommendation),
         "pricing_recommendation_realizes_extra_storage_above_default");
      suite.expect(recommendation.found, "pricing_recommendation_realizes_extra_storage_found");
      suite.expect(recommendation.machineSelections.size() == 1, "pricing_recommendation_realizes_extra_storage_selection_count");
      if (recommendation.machineSelections.size() == 1)
      {
         suite.expect(recommendation.machineSelections[0].storageMB == 34u * 1024u, "pricing_recommendation_realizes_extra_storage_selection_storage");
      }
      else
      {
         suite.expect(false, "pricing_recommendation_realizes_extra_storage_selection_storage");
      }
      suite.expect(recommendation.storageHourlyMicrousd == 1'400'000, "pricing_recommendation_realizes_extra_storage_breakdown");
      suite.expect(recommendation.hourlyMicrousd == 1'900'000, "pricing_recommendation_realizes_extra_storage_total");
   }

   {
      MothershipClusterRecommendationRequest request = {};
      request.country = "United States"_ctv;
      request.billingModel = ProviderMachineBillingModel::hourly;
      request.minMachines = 3;

      MothershipPlanningApplication frontend = {};
      frontend.name = "frontend"_ctv;
      frontend.instances = 1;
      frontend.config.type = ApplicationType::stateless;
      frontend.config.nLogicalCores = 1;
      frontend.config.memoryMB = 2u * 1024u;
      frontend.config.filesystemMB = 1024;
      frontend.config.cpuMode = ApplicationCPUMode::shared;
      frontend.config.sharedCPUMillis = 1000;
      frontend.config.nicSpeedGbps = 25;
      request.applications.push_back(frontend);

      MothershipPlanningApplication memoryHeavy = {};
      memoryHeavy.name = "memory-heavy"_ctv;
      memoryHeavy.instances = 1;
      memoryHeavy.config.type = ApplicationType::stateless;
      memoryHeavy.config.nLogicalCores = 2;
      memoryHeavy.config.memoryMB = 24u * 1024u;
      memoryHeavy.config.filesystemMB = 1024;
      memoryHeavy.config.cpuMode = ApplicationCPUMode::shared;
      memoryHeavy.config.sharedCPUMillis = 2000;
      request.applications.push_back(memoryHeavy);

      MothershipPlanningApplication gpuHeavy = {};
      gpuHeavy.name = "gpu-heavy"_ctv;
      gpuHeavy.instances = 1;
      gpuHeavy.config.type = ApplicationType::stateless;
      gpuHeavy.config.nLogicalCores = 2;
      gpuHeavy.config.memoryMB = 8u * 1024u;
      gpuHeavy.config.filesystemMB = 1024;
      gpuHeavy.config.cpuMode = ApplicationCPUMode::shared;
      gpuHeavy.config.sharedCPUMillis = 2000;
      gpuHeavy.config.minGPUs = 1;
      gpuHeavy.config.gpuMemoryGB = 24;
      request.applications.push_back(gpuHeavy);

      MothershipProviderScopeTarget target = {};
      target.provider = MothershipClusterProvider::aws;
      target.providerScope = "us-east-1"_ctv;

      Vector<MothershipProviderMachineOffer> offers = {};

      MothershipProviderMachineOffer cpuOffer = makeSurveyedOffer("cpu.large"_ctv, MachineConfig::MachineKind::vm, 500'000);
      cpuOffer.nLogicalCores = 3;
      cpuOffer.nMemoryMB = 6u * 1024u;
      cpuOffer.nicSpeedMbps = 25'000;
      offers.push_back(cpuOffer);

      MothershipProviderMachineOffer memoryOffer = makeSurveyedOffer("mem.large"_ctv, MachineConfig::MachineKind::vm, 700'000);
      memoryOffer.nLogicalCores = 4;
      memoryOffer.nMemoryMB = 28u * 1024u;
      memoryOffer.nicSpeedMbps = 10'000;
      offers.push_back(memoryOffer);

      MothershipProviderMachineOffer gpuOffer = makeSurveyedOffer("gpu.large"_ctv, MachineConfig::MachineKind::vm, 900'000);
      gpuOffer.nLogicalCores = 4;
      gpuOffer.nMemoryMB = 12u * 1024u;
      gpuOffer.gpuCount = 1;
      gpuOffer.gpuMemoryMBPerDevice = 24u * 1024u;
      gpuOffer.nicSpeedMbps = 10'000;
      offers.push_back(gpuOffer);

      MothershipClusterRecommendation recommendation = {};
      suite.expect(
         mothershipRecommendClusterForApplications(request, offers, target, recommendation),
         "pricing_recommendation_supports_three_machine_types");
      suite.expect(recommendation.found, "pricing_recommendation_supports_three_machine_types_found");
      suite.expect(recommendation.totalMachines == 3, "pricing_recommendation_supports_three_machine_types_total");
      suite.expect(recommendation.machineSelections.size() == 3, "pricing_recommendation_supports_three_machine_types_selection_count");
      suite.expect(selectionVectorContainsType(recommendation.machineSelections, "cpu.large"_ctv, 1), "pricing_recommendation_supports_three_machine_types_contains_cpu");
      suite.expect(selectionVectorContainsType(recommendation.machineSelections, "mem.large"_ctv, 1), "pricing_recommendation_supports_three_machine_types_contains_mem");
      suite.expect(selectionVectorContainsType(recommendation.machineSelections, "gpu.large"_ctv, 1), "pricing_recommendation_supports_three_machine_types_contains_gpu");
   }

   {
      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      String json = {};
      suite.expect(parseJSON("[\"all\"]", json, doc, parser), "pricing_parse_providers_all_json");

      Vector<MothershipClusterProvider> providers = {};
      bool allProviders = false;
      String failure = {};
      suite.expect(mothershipParsePricingProvidersJSON(doc, providers, allProviders, &failure), "pricing_parse_providers_all");
      suite.expect(allProviders, "pricing_parse_providers_all_flag");
      suite.expect(providers.empty(), "pricing_parse_providers_all_vector_empty");
      suite.expect(failure.size() == 0, "pricing_parse_providers_all_no_failure");
   }

   {
      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      String json = {};
      suite.expect(parseJSON("[\"aws\",\"azure\"]", json, doc, parser), "pricing_parse_providers_explicit_json");

      Vector<MothershipClusterProvider> providers = {};
      bool allProviders = false;
      String failure = {};
      suite.expect(mothershipParsePricingProvidersJSON(doc, providers, allProviders, &failure), "pricing_parse_providers_explicit");
      suite.expect(allProviders == false, "pricing_parse_providers_explicit_not_all");
      suite.expect(providers.size() == 2, "pricing_parse_providers_explicit_count");
      suite.expect(providerVectorContains(providers, MothershipClusterProvider::aws), "pricing_parse_providers_explicit_contains_aws");
      suite.expect(providerVectorContains(providers, MothershipClusterProvider::azure), "pricing_parse_providers_explicit_contains_azure");
   }

   {
      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      String json = {};
      suite.expect(parseJSON("[\"all\",\"aws\"]", json, doc, parser), "pricing_parse_providers_mixed_json");

      Vector<MothershipClusterProvider> providers = {};
      bool allProviders = false;
      String failure = {};
      suite.expect(mothershipParsePricingProvidersJSON(doc, providers, allProviders, &failure) == false, "pricing_parse_providers_mixed_rejected");
      suite.expect(failure.equals("providers may specify 'all' or explicit providers, not both"_ctv), "pricing_parse_providers_mixed_reason");
   }

   {
      MothershipProviderMachineOffer offer = {};
      offer.provider = MothershipClusterProvider::azure;
      offer.providerScope = "eastus"_ctv;
      offer.country = "United States"_ctv;
      offer.region = "eastus"_ctv;
      offer.zone = "1"_ctv;
      offer.providerMachineType = "Standard_B1s"_ctv;
      offer.billingModel = ProviderMachineBillingModel::spot;
      offer.kind = MachineConfig::MachineKind::vm;
      offer.nLogicalCores = 1;
      offer.nMemoryMB = 1024;
      offer.nStorageMBDefault = 30720;
      offer.providesHostPublic4 = true;
      offer.freeTierEligible = true;
      offer.hourlyMicrousd = 12345;

      String encoded = {};
      BitseryEngine::serialize(encoded, offer);
      MothershipProviderMachineOffer decoded = {};
      suite.expect(BitseryEngine::deserializeSafe(encoded, decoded), "pricing_offer_roundtrip_deserializes");
      suite.expect(decoded.billingModel == ProviderMachineBillingModel::spot, "pricing_offer_roundtrip_billing_model");
      suite.expect(decoded.freeTierEligible, "pricing_offer_roundtrip_free_tier");
      suite.expect(decoded.hourlyMicrousd == 12345, "pricing_offer_roundtrip_hourly_microusd");
   }

   {
      suite.expect(
         mothershipAwsFreeTierEligible("t2.micro"_ctv, ProviderMachineBillingModel::hourly),
         "pricing_aws_free_tier_accepts_t2_micro");
      suite.expect(
         mothershipAwsFreeTierEligible("t3.micro"_ctv, ProviderMachineBillingModel::hourly),
         "pricing_aws_free_tier_accepts_t3_micro");
      suite.expect(
         mothershipAwsFreeTierEligible("c7i-flex.large"_ctv, ProviderMachineBillingModel::hourly) == false,
         "pricing_aws_free_tier_rejects_c7i_flex_large");
   }

   {
      char scratch[] = "/tmp/nametag-mothership-pricing-unit-XXXXXX";
      char *created = mkdtemp(scratch);
      suite.expect(created != nullptr, "pricing_targets_mkdtemp_created");
      if (created != nullptr)
      {
         ScopedEnvVar dbOverride("PRODIGY_MOTHERSHIP_TIDESDB_PATH", created);
         String failure = {};

         {
            MothershipProviderCredentialRegistry registry = MothershipProviderCredentialRegistry();

            MothershipProviderCredential awsCredential = {};
            awsCredential.name = "aws-priced"_ctv;
            awsCredential.provider = MothershipClusterProvider::aws;
            awsCredential.material = "aws-secret"_ctv;
            awsCredential.scope = "us-east-1"_ctv;
            suite.expect(registry.createCredential(awsCredential, nullptr, &failure), "pricing_targets_create_aws_credential");

            MothershipProviderCredential gcpCredential = {};
            gcpCredential.name = "gcp-priced"_ctv;
            gcpCredential.provider = MothershipClusterProvider::gcp;
            gcpCredential.material = "gcp-secret"_ctv;
            gcpCredential.scope = "us-central1-a"_ctv;
            suite.expect(registry.createCredential(gcpCredential, nullptr, &failure), "pricing_targets_create_gcp_credential");

            MothershipProviderCredential azureNoScope = {};
            azureNoScope.name = "azure-noscope"_ctv;
            azureNoScope.provider = MothershipClusterProvider::azure;
            azureNoScope.material = "azure-secret"_ctv;
            suite.expect(registry.createCredential(azureNoScope, nullptr, &failure), "pricing_targets_create_azure_noscope_credential");
         }

         Vector<MothershipClusterProvider> requestedProviders = {};
         Vector<String> requestedCredentialNames = {};
         MothershipPricingResolvedTargets resolved = {};
         suite.expect(mothershipResolveStoredPricingTargets(requestedProviders, requestedCredentialNames, resolved, &failure), "pricing_targets_resolve_all_supported_providers");
         suite.expect(resolved.targets.size() == 2, "pricing_targets_resolve_target_count");
         suite.expect(targetVectorContains(resolved.targets, MothershipClusterProvider::aws, "us-east-1"_ctv, "aws-priced"_ctv), "pricing_targets_resolve_contains_aws");
         suite.expect(targetVectorContains(resolved.targets, MothershipClusterProvider::gcp, "us-central1-a"_ctv, "gcp-priced"_ctv), "pricing_targets_resolve_contains_gcp");
         suite.expect(providerVectorContains(resolved.missingCredentialProviders, MothershipClusterProvider::azure), "pricing_targets_resolve_reports_missing_azure");
         suite.expect(stringVectorContains(resolved.skippedCredentialNames, "azure-noscope"_ctv), "pricing_targets_resolve_reports_skipped_noscope");
         suite.expect(providerVectorContains(resolved.missingCredentialProviders, MothershipClusterProvider::aws) == false, "pricing_targets_resolve_no_missing_aws");
         suite.expect(providerVectorContains(resolved.missingCredentialProviders, MothershipClusterProvider::gcp) == false, "pricing_targets_resolve_no_missing_gcp");

         Vector<MothershipClusterProvider> explicitUnsupportedProviders = {};
         explicitUnsupportedProviders.push_back(MothershipClusterProvider::vultr);
         resolved = {};
         suite.expect(mothershipResolveStoredPricingTargets(explicitUnsupportedProviders, requestedCredentialNames, resolved, &failure), "pricing_targets_resolve_unsupported_provider");
         suite.expect(providerVectorContains(resolved.unsupportedProviders, MothershipClusterProvider::vultr), "pricing_targets_resolve_reports_unsupported_provider");

         std::filesystem::remove_all(created);
      }
   }

   basics_log("SUMMARY: failed=%d\n", suite.failed);
   return suite.failed == 0 ? 0 : 1;
}
