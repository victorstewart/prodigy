#pragma once

#include <simdjson.h>

#include <prodigy/mothership/mothership.deployment.plan.helpers.h>
#include <prodigy/mothership/mothership.pricing.types.h>
#include <prodigy/mothership/mothership.provider.credentials.h>
#include <prodigy/provider.machine.offer.h>

class MothershipPricingResolvedTargets
{
public:

   Vector<MothershipProviderScopeTarget> targets;
   Vector<MothershipClusterProvider> missingCredentialProviders;
   Vector<MothershipClusterProvider> unsupportedProviders;
   Vector<String> skippedCredentialNames;
};

static inline bool mothershipPricingSupportsProvider(MothershipClusterProvider provider)
{
   return provider == MothershipClusterProvider::aws
      || provider == MothershipClusterProvider::gcp
      || provider == MothershipClusterProvider::azure;
}

static inline void mothershipPricingDefaultProviders(Vector<MothershipClusterProvider>& providers)
{
   providers.clear();
   providers.push_back(MothershipClusterProvider::aws);
   providers.push_back(MothershipClusterProvider::gcp);
   providers.push_back(MothershipClusterProvider::azure);
}

static inline bool mothershipPricingProviderVectorContains(const Vector<MothershipClusterProvider>& providers, MothershipClusterProvider provider)
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

static inline void mothershipPricingAppendUniqueProvider(Vector<MothershipClusterProvider>& providers, MothershipClusterProvider provider)
{
   if (mothershipPricingProviderVectorContains(providers, provider) == false)
   {
      providers.push_back(provider);
   }
}

static inline bool mothershipPricingStringVectorContains(const Vector<String>& values, const String& needle)
{
   for (const String& value : values)
   {
      if (value.equals(needle))
      {
         return true;
      }
   }

   return false;
}

static inline bool mothershipParsePricingProvidersJSON(
   const simdjson::dom::element& value,
   Vector<MothershipClusterProvider>& providers,
   bool& allProviders,
   String *failure = nullptr)
{
   providers.clear();
   allProviders = false;
   if (failure) failure->clear();

   if (value.type() != simdjson::dom::element_type::ARRAY)
   {
      if (failure) failure->assign("providers requires an array"_ctv);
      return false;
   }

   for (auto item : value.get_array())
   {
      if (item.type() != simdjson::dom::element_type::STRING)
      {
         if (failure) failure->assign("providers requires string members"_ctv);
         return false;
      }

      String providerName = {};
      providerName.setInvariant(item.get_c_str());
      if (providerName.equal("all"_ctv))
      {
         allProviders = true;
         continue;
      }

      MothershipClusterProvider provider = MothershipClusterProvider::unknown;
      if (parseMothershipClusterProvider(providerName, provider) == false || provider == MothershipClusterProvider::unknown)
      {
         if (failure) failure->snprintf<"providers '{}' is invalid"_ctv>(providerName);
         return false;
      }

      mothershipPricingAppendUniqueProvider(providers, provider);
   }

   if (allProviders && providers.empty() == false)
   {
      if (failure) failure->assign("providers may specify 'all' or explicit providers, not both"_ctv);
      return false;
   }

   if (allProviders == false && providers.empty())
   {
      if (failure) failure->assign("providers requires at least one provider or 'all'"_ctv);
      return false;
   }

   return true;
}

static inline bool mothershipParsePricingMachineKindsJSON(
   const simdjson::dom::element& value,
   uint32_t& machineKindsMask,
   String *failure = nullptr)
{
   machineKindsMask = 0;
   if (failure) failure->clear();

   if (value.type() != simdjson::dom::element_type::ARRAY)
   {
      if (failure) failure->assign("machineKinds requires an array"_ctv);
      return false;
   }

   for (auto item : value.get_array())
   {
      if (item.type() != simdjson::dom::element_type::STRING)
      {
         if (failure) failure->assign("machineKinds requires string members"_ctv);
         return false;
      }

      String kindText = {};
      kindText.setInvariant(item.get_c_str());
      MachineConfig::MachineKind kind = MachineConfig::MachineKind::vm;
      if (kindText.equal("vm"_ctv))
      {
         kind = MachineConfig::MachineKind::vm;
      }
      else if (kindText.equal("bareMetal"_ctv))
      {
         kind = MachineConfig::MachineKind::bareMetal;
      }
      else
      {
         if (failure) failure->snprintf<"machineKinds '{}' is invalid"_ctv>(kindText);
         return false;
      }

      machineKindsMask |= providerMachineKindMaskBit(kind);
   }

   if (machineKindsMask == 0)
   {
      if (failure) failure->assign("machineKinds requires at least one kind"_ctv);
      return false;
   }

   return true;
}

static inline bool mothershipResolveStoredPricingTargets(
   const Vector<MothershipClusterProvider>& requestedProviders,
   const Vector<String>& requestedCredentialNames,
   MothershipPricingResolvedTargets& resolved,
   String *failure = nullptr)
{
   resolved = MothershipPricingResolvedTargets();
   if (failure) failure->clear();

   Vector<MothershipClusterProvider> providers = {};
   if (requestedProviders.empty())
   {
      mothershipPricingDefaultProviders(providers);
   }
   else
   {
      providers = requestedProviders;
   }

   Vector<MothershipProviderCredential> credentials = {};
   MothershipProviderCredentialRegistry providerCredentialRegistry = MothershipProviderCredentialRegistry();
   if (providerCredentialRegistry.listCredentials(credentials, failure) == false)
   {
      return false;
   }

   for (MothershipClusterProvider provider : providers)
   {
      if (mothershipPricingSupportsProvider(provider) == false)
      {
         mothershipPricingAppendUniqueProvider(resolved.unsupportedProviders, provider);
         continue;
      }

      bool foundAny = false;
      for (const MothershipProviderCredential& credential : credentials)
      {
         if (credential.provider != provider)
         {
            continue;
         }

         if (requestedCredentialNames.empty() == false
            && mothershipPricingStringVectorContains(requestedCredentialNames, credential.name) == false)
         {
            continue;
         }

         if (credential.scope.size() == 0)
         {
            if (mothershipPricingStringVectorContains(resolved.skippedCredentialNames, credential.name) == false)
            {
               resolved.skippedCredentialNames.push_back(credential.name);
            }
            continue;
         }

         MothershipProviderScopeTarget target = {};
         target.provider = provider;
         target.providerScope = credential.scope;
         target.providerCredentialName = credential.name;
         resolved.targets.push_back(target);
         foundAny = true;
      }

      if (foundAny == false)
      {
         mothershipPricingAppendUniqueProvider(resolved.missingCredentialProviders, provider);
      }
   }

   for (const String& credentialName : requestedCredentialNames)
   {
      bool matched = false;
      for (const MothershipProviderScopeTarget& target : resolved.targets)
      {
         if (target.providerCredentialName.equals(credentialName))
         {
            matched = true;
            break;
         }
      }

      if (matched == false && mothershipPricingStringVectorContains(resolved.skippedCredentialNames, credentialName) == false)
      {
         bool exists = false;
         for (const MothershipProviderCredential& credential : credentials)
         {
            if (credential.name.equals(credentialName))
            {
               exists = true;
               break;
            }
         }

         if (exists == false)
         {
            resolved.skippedCredentialNames.push_back(credentialName);
         }
      }
   }

   return true;
}

static inline bool mothershipParsePricingPlanningApplicationConfigJSON(
   const simdjson::dom::element& value,
   ApplicationConfig& config,
   String *failure = nullptr)
{
   config = {};
   config.type = ApplicationType::stateless;
   if (failure) failure->clear();

   if (value.type() != simdjson::dom::element_type::OBJECT)
   {
      if (failure) failure->assign("applications[].config requires an object"_ctv);
      return false;
   }

   uint32_t seenConfigBits = 0;
   for (auto field : value.get_object())
   {
      String key = {};
      key.setInvariant(field.key);

      if (key.equal("nLogicalCores"_ctv))
      {
         if (field.value.type() != simdjson::dom::element_type::DOUBLE
            && field.value.type() != simdjson::dom::element_type::INT64
            && field.value.type() != simdjson::dom::element_type::UINT64)
         {
            if (failure) failure->assign("applications[].config.nLogicalCores requires a number"_ctv);
            return false;
         }

         config.cpuMode = ApplicationCPUMode::isolated;
         if (field.value.type() == simdjson::dom::element_type::DOUBLE)
         {
            double requestedCores = 0.0;
            (void)field.value.get(requestedCores);
            double integralPart = 0.0;
            if (std::isfinite(requestedCores) == false || std::modf(requestedCores, &integralPart) != 0.0)
            {
               config.cpuMode = ApplicationCPUMode::shared;
            }
         }

         if (mothershipParseApplicationCPURequest(field.value, config, failure) == false)
         {
            return false;
         }
      }
      else if (key.equal("architecture"_ctv))
      {
         if (mothershipParseApplicationArchitectureField(field.value, config, "applications[].config"_ctv, failure) == false)
         {
            return false;
         }
      }
      else if (key.equal("requiredIsaFeatures"_ctv))
      {
         if (mothershipParseApplicationRequiredIsaFeaturesField(field.value, config, "applications[].config"_ctv, failure) == false)
         {
            return false;
         }
      }
      else
      {
         String sizeFailure = {};
         if (mothershipParseApplicationConfigSizeField(key, field.value, config, seenConfigBits, "applications[].config"_ctv, &sizeFailure))
         {
         }
         else if (sizeFailure.size() > 0)
         {
            if (failure) *failure = sizeFailure;
            return false;
         }
         else if (key.equal("machineResourceCriteria"_ctv))
         {
            if (failure) failure->assign("applications[].config.machineResourceCriteria removed; place minGPUs, gpuMemoryGB, and nicSpeedGbps directly on applications[].config"_ctv);
            return false;
         }
         else if (key.equal("minGPUs"_ctv))
         {
            if (mothershipParseJSONUInt32(field.value, config.minGPUs) == false)
            {
               if (failure) failure->assign("applications[].config.minGPUs invalid"_ctv);
               return false;
            }
         }
         else if (key.equal("gpuMemoryGB"_ctv))
         {
            if (mothershipParseJSONUInt32(field.value, config.gpuMemoryGB) == false)
            {
               if (failure) failure->assign("applications[].config.gpuMemoryGB invalid"_ctv);
               return false;
            }
         }
         else if (key.equal("nicSpeedGbps"_ctv))
         {
            if (mothershipParseJSONUInt32(field.value, config.nicSpeedGbps) == false)
            {
               if (failure) failure->assign("applications[].config.nicSpeedGbps invalid"_ctv);
               return false;
            }
         }
         else if (key.equal("minInternetDownloadMbps"_ctv) || key.equal("minInternetUploadMbps"_ctv) || key.equal("maxInternetLatencyMs"_ctv))
         {
            if (failure) failure->snprintf<"applications[].config.{} is not supported for planning"_ctv>(key);
            return false;
         }
         else
         {
            if (failure) failure->snprintf<"applications[].config.{} is not recognized"_ctv>(key);
            return false;
         }
      }
   }

   if (config.nLogicalCores == 0)
   {
      if (failure) failure->assign("applications[].config.nLogicalCores required"_ctv);
      return false;
   }

   if (mothershipValidateApplicationRuntimeRequirements(config, "applications[].config"_ctv, failure) == false)
   {
      return false;
   }

   if (config.memoryMB == 0)
   {
      if (failure) failure->assign("applications[].config.memoryMB or memoryGB required"_ctv);
      return false;
   }

   if (config.gpuMemoryGB > 0 && config.minGPUs == 0)
   {
      if (failure) failure->assign("applications[].config.gpuMemoryGB requires minGPUs > 0"_ctv);
      return false;
   }

   if (config.gpuMemoryGB > (UINT32_MAX / 1024u))
   {
      if (failure) failure->assign("applications[].config.gpuMemoryGB exceeds supported range"_ctv);
      return false;
   }

   return true;
}

static inline bool mothershipParsePricingPlanningApplicationsJSON(
   const simdjson::dom::element& value,
   Vector<MothershipPlanningApplication>& applications,
   String *failure = nullptr)
{
   applications.clear();
   if (failure) failure->clear();

   if (value.type() != simdjson::dom::element_type::ARRAY)
   {
      if (failure) failure->assign("applications requires an array"_ctv);
      return false;
   }

   for (auto item : value.get_array())
   {
      if (item.type() != simdjson::dom::element_type::OBJECT)
      {
         if (failure) failure->assign("applications requires object members"_ctv);
         return false;
      }

      MothershipPlanningApplication application = {};
      for (auto field : item.get_object())
      {
         String key = {};
         key.setInvariant(field.key);

         if (key.equal("name"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               if (failure) failure->assign("applications[].name requires a string"_ctv);
               return false;
            }

            application.name.assign(field.value.get_c_str());
         }
         else if (key.equal("instances"_ctv))
         {
            uint64_t valueU64 = 0;
            if ((field.value.type() != simdjson::dom::element_type::INT64 && field.value.type() != simdjson::dom::element_type::UINT64)
               || field.value.get(valueU64) != simdjson::SUCCESS
               || valueU64 == 0
               || valueU64 > UINT32_MAX)
            {
               if (failure) failure->assign("applications[].instances invalid"_ctv);
               return false;
            }

            application.instances = uint32_t(valueU64);
         }
         else if (key.equal("config"_ctv))
         {
            if (mothershipParsePricingPlanningApplicationConfigJSON(field.value, application.config, failure) == false)
            {
               return false;
            }
         }
         else
         {
            if (failure) failure->snprintf<"applications[].{} is not recognized"_ctv>(key);
            return false;
         }
      }

      if (application.instances == 0)
      {
         if (failure) failure->assign("applications[].instances required"_ctv);
         return false;
      }

      if (application.name.size() == 0)
      {
         if (failure) failure->assign("applications[].name required"_ctv);
         return false;
      }

      applications.push_back(application);
   }

   return true;
}

static inline bool mothershipParsePricingMachineSelectionsJSON(
   const simdjson::dom::element& value,
   Vector<MothershipMachineOfferSelection>& selections,
   String *failure = nullptr)
{
   selections.clear();
   if (failure) failure->clear();

   if (value.type() != simdjson::dom::element_type::ARRAY)
   {
      if (failure) failure->assign("machines requires an array"_ctv);
      return false;
   }

   for (auto item : value.get_array())
   {
      if (item.type() != simdjson::dom::element_type::OBJECT)
      {
         if (failure) failure->assign("machines requires object members"_ctv);
         return false;
      }

      MothershipMachineOfferSelection selection = {};
      for (auto field : item.get_object())
      {
         String key = {};
         key.setInvariant(field.key);

         if (key.equal("providerMachineType"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               if (failure) failure->assign("machines[].providerMachineType requires a string"_ctv);
               return false;
            }

            selection.providerMachineType.assign(field.value.get_c_str());
         }
         else if (key.equal("kind"_ctv))
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               if (failure) failure->assign("machines[].kind requires a string"_ctv);
               return false;
            }

            String kindText = {};
            kindText.setInvariant(field.value.get_c_str());
            if (kindText.equal("vm"_ctv)) selection.kind = MachineConfig::MachineKind::vm;
            else if (kindText.equal("bareMetal"_ctv)) selection.kind = MachineConfig::MachineKind::bareMetal;
            else
            {
               if (failure) failure->assign("machines[].kind invalid"_ctv);
               return false;
            }
         }
         else if (key.equal("count"_ctv))
         {
            uint64_t valueU64 = 0;
            if ((field.value.type() != simdjson::dom::element_type::INT64 && field.value.type() != simdjson::dom::element_type::UINT64)
               || field.value.get(valueU64) != simdjson::SUCCESS
               || valueU64 == 0
               || valueU64 > UINT32_MAX)
            {
               if (failure) failure->assign("machines[].count invalid"_ctv);
               return false;
            }

            selection.count = uint32_t(valueU64);
         }
         else if (key.equal("storageGB"_ctv))
         {
            uint32_t storageMB = 0;
            if (mothershipParseJSONSizeGBToMB(field.value, storageMB))
            {
               selection.storageMB = storageMB;
            }
            else
            {
               if (failure) failure->assign("machines[].storageGB invalid"_ctv);
               return false;
            }
         }
         else
         {
            if (failure) failure->snprintf<"machines[].{} is not recognized"_ctv>(key);
            return false;
         }
      }

      if (selection.providerMachineType.size() == 0)
      {
         if (failure) failure->assign("machines[].providerMachineType required"_ctv);
         return false;
      }

      if (selection.count == 0)
      {
         if (failure) failure->assign("machines[].count required"_ctv);
         return false;
      }

      selections.push_back(selection);
   }

   return true;
}
