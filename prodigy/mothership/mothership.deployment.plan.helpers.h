#pragma once

#include <cmath>
#include <simdjson.h>

#include <prodigy/types.h>

static inline bool mothershipParseDeploymentPlanUseHostNetworkNamespace(
   const simdjson::dom::element& value,
   DeploymentPlan& plan,
   String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   if (value.type() != simdjson::dom::element_type::BOOL)
   {
      if (failure)
      {
         failure->assign("useHostNetworkNamespace requires a bool"_ctv);
      }

      return false;
   }

   bool useHostNetworkNamespace = false;
   (void)value.get(useHostNetworkNamespace);
   plan.useHostNetworkNamespace = useHostNetworkNamespace;
   return true;
}

static inline bool mothershipParseApplicationCPUIsolationMode(
   const simdjson::dom::element& value,
   ApplicationConfig& config,
   String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   if (value.type() != simdjson::dom::element_type::BOOL)
   {
      if (failure)
      {
         failure->assign("config.isolateCPUs requires a bool"_ctv);
      }

      return false;
   }

   bool isolateCPUs = true;
   (void)value.get(isolateCPUs);
   config.cpuMode = isolateCPUs ? ApplicationCPUMode::isolated : ApplicationCPUMode::shared;
   return true;
}

static inline bool mothershipParseApplicationArchitectureField(
   const simdjson::dom::element& value,
   ApplicationConfig& config,
   const String& contextPrefix,
   String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   if (value.type() != simdjson::dom::element_type::STRING)
   {
      if (failure)
      {
         failure->snprintf<"{}.architecture requires a string"_ctv>(contextPrefix);
      }

      return false;
   }

   String text = {};
   text.setInvariant(value.get_c_str());
   if (parseMachineCpuArchitecture(text, config.architecture) == false
      || prodigyMachineCpuArchitectureSupportedTarget(config.architecture) == false)
   {
      if (failure)
      {
         failure->snprintf<"{}.architecture must be x86_64 or aarch64"_ctv>(contextPrefix);
      }

      config.architecture = MachineCpuArchitecture::unknown;
      return false;
   }

   return true;
}

static inline bool mothershipParseApplicationRequiredIsaFeaturesField(
   const simdjson::dom::element& value,
   ApplicationConfig& config,
   const String& contextPrefix,
   String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   if (value.type() != simdjson::dom::element_type::ARRAY)
   {
      if (failure)
      {
         failure->snprintf<"{}.requiredIsaFeatures requires an array"_ctv>(contextPrefix);
      }

      return false;
   }

   config.requiredIsaFeatures.clear();
   for (auto item : value.get_array())
   {
      if (item.type() != simdjson::dom::element_type::STRING)
      {
         if (failure)
         {
            failure->snprintf<"{}.requiredIsaFeatures requires string members"_ctv>(contextPrefix);
         }

         config.requiredIsaFeatures.clear();
         return false;
      }

      String text = {};
      text.setInvariant(item.get_c_str());
      prodigyAppendNormalizedIsaFeature(config.requiredIsaFeatures, text);
   }

   return true;
}

static inline bool mothershipValidateApplicationRuntimeRequirements(
   const ApplicationConfig& config,
   const String& contextPrefix,
   String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   if (prodigyMachineCpuArchitectureSupportedTarget(config.architecture) == false)
   {
      if (failure)
      {
         failure->snprintf<"{}.architecture is required and must be x86_64 or aarch64"_ctv>(contextPrefix);
      }

      return false;
   }

   return true;
}

static inline bool mothershipParseJSONUInt64(
   const simdjson::dom::element& value,
   uint64_t& parsed,
   bool allowZero = true)
{
   parsed = 0;

   if (value.type() == simdjson::dom::element_type::INT64)
   {
      int64_t signedValue = 0;
      if (value.get(signedValue) != simdjson::SUCCESS)
      {
         return false;
      }

      if (signedValue < 0 || (allowZero == false && signedValue == 0))
      {
         return false;
      }

      parsed = uint64_t(signedValue);
      return true;
   }

   if (value.type() == simdjson::dom::element_type::UINT64)
   {
      if (value.get(parsed) != simdjson::SUCCESS)
      {
         return false;
      }

      if (allowZero == false && parsed == 0)
      {
         return false;
      }

      return true;
   }

   return false;
}

static inline bool mothershipParseJSONUInt32(
   const simdjson::dom::element& value,
   uint32_t& parsed,
   bool allowZero = true)
{
   uint64_t valueU64 = 0;
   if (mothershipParseJSONUInt64(value, valueU64, allowZero) == false || valueU64 > UINT32_MAX)
   {
      parsed = 0;
      return false;
   }

   parsed = uint32_t(valueU64);
   return true;
}

static inline bool mothershipParseServiceUserCapacity(
   const simdjson::dom::element& value,
   ServiceUserCapacity& capacity,
   const String& contextPrefix,
   String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   if (value.type() != simdjson::dom::element_type::OBJECT)
   {
      if (failure)
      {
         failure->snprintf<"{} requires an object"_ctv>(contextPrefix);
      }

      return false;
   }

   ServiceUserCapacity parsed = {};
   for (auto field : value.get_object())
   {
      String key;
      key.setInvariant(field.key.data(), field.key.size());

      if (key.equal("min"_ctv) || key.equal("minimum"_ctv))
      {
         if (mothershipParseJSONUInt32(field.value, parsed.minimum, true) == false)
         {
            if (failure)
            {
               failure->snprintf<"{}.min requires a non-negative uint32"_ctv>(contextPrefix);
            }

            return false;
         }
      }
      else if (key.equal("max"_ctv) || key.equal("maximum"_ctv))
      {
         if (mothershipParseJSONUInt32(field.value, parsed.maximum, true) == false)
         {
            if (failure)
            {
               failure->snprintf<"{}.max requires a non-negative uint32"_ctv>(contextPrefix);
            }

            return false;
         }
      }
      else
      {
         if (failure)
         {
            failure->snprintf<"{} invalid field"_ctv>(contextPrefix);
         }

         return false;
      }
   }

   if (parsed.maximum > 0 && parsed.minimum > parsed.maximum)
   {
      if (failure)
      {
         failure->snprintf<"{}.min cannot exceed max when max is nonzero"_ctv>(contextPrefix);
      }

      return false;
   }

   capacity = parsed;
   return true;
}

static inline bool mothershipConvertGBToMB(uint32_t gb, uint32_t& mb)
{
   if (gb > (UINT32_MAX / 1024u))
   {
      mb = 0;
      return false;
   }

   mb = gb * 1024u;
   return true;
}

static inline bool mothershipParseJSONSizeGBToMB(
   const simdjson::dom::element& value,
   uint32_t& mb,
   bool allowZero = true)
{
   uint32_t gb = 0;
   if (mothershipParseJSONUInt32(value, gb, allowZero) == false)
   {
      mb = 0;
      return false;
   }

   return mothershipConvertGBToMB(gb, mb);
}

enum class MothershipApplicationConfigSizeField : uint8_t
{
   filesystem = 0,
   storage = 1,
   memory = 2
};

static inline uint32_t mothershipApplicationConfigSizeSeenBit(MothershipApplicationConfigSizeField field, bool gb)
{
   const uint32_t fieldIndex = uint32_t(field);
   return 1u << ((fieldIndex * 2u) + (gb ? 1u : 0u));
}

static inline bool mothershipParseApplicationConfigSizeField(
   const String& key,
   const simdjson::dom::element& value,
   ApplicationConfig& config,
   uint32_t& seenMask,
   const String& contextPrefix,
   String *failure = nullptr)
{
   MothershipApplicationConfigSizeField field = MothershipApplicationConfigSizeField::filesystem;
   uint32_t *target = nullptr;
   uint32_t maxMB = 0;
   bool gb = false;

   if (key.equal("filesystemMB"_ctv))
   {
      field = MothershipApplicationConfigSizeField::filesystem;
      target = &config.filesystemMB;
      maxMB = 1024u;
      gb = false;
   }
   else if (key.equal("filesystemGB"_ctv))
   {
      field = MothershipApplicationConfigSizeField::filesystem;
      target = &config.filesystemMB;
      maxMB = 1024u;
      gb = true;
   }
   else if (key.equal("storageMB"_ctv))
   {
      field = MothershipApplicationConfigSizeField::storage;
      target = &config.storageMB;
      maxMB = 1024u * 1024u;
      gb = false;
   }
   else if (key.equal("storageGB"_ctv))
   {
      field = MothershipApplicationConfigSizeField::storage;
      target = &config.storageMB;
      maxMB = 1024u * 1024u;
      gb = true;
   }
   else if (key.equal("memoryMB"_ctv))
   {
      field = MothershipApplicationConfigSizeField::memory;
      target = &config.memoryMB;
      maxMB = 64u * 1024u;
      gb = false;
   }
   else if (key.equal("memoryGB"_ctv))
   {
      field = MothershipApplicationConfigSizeField::memory;
      target = &config.memoryMB;
      maxMB = 64u * 1024u;
      gb = true;
   }
   else
   {
      return false;
   }

   const uint32_t sameUnitBit = mothershipApplicationConfigSizeSeenBit(field, gb);
   const uint32_t otherUnitBit = mothershipApplicationConfigSizeSeenBit(field, gb == false);
   if ((seenMask & otherUnitBit) != 0)
   {
      if (failure)
      {
         String otherKey = key;
         otherKey[key.size() - 2] = gb ? 'M' : 'G';
         otherKey[key.size() - 1] = 'B';
         failure->snprintf<"{}.{} may specify {} or {}, not both"_ctv>(contextPrefix, gb ? otherKey : key, gb ? otherKey : key, gb ? key : otherKey);
      }

      return false;
   }

   if ((seenMask & sameUnitBit) != 0)
   {
      if (failure)
      {
         failure->snprintf<"{}.{} specified more than once"_ctv>(contextPrefix, key);
      }

      return false;
   }

   uint32_t parsedMB = 0;
   if ((gb ? mothershipParseJSONSizeGBToMB(value, parsedMB, false) : mothershipParseJSONUInt32(value, parsedMB, false)) == false
      || parsedMB > maxMB)
   {
      if (failure)
      {
         failure->snprintf<"{}.{} invalid"_ctv>(contextPrefix, key);
      }

      return false;
   }

   *target = parsedMB;
   seenMask |= sameUnitBit;
   if (failure)
   {
      failure->clear();
   }

   return true;
}

static inline bool mothershipParseApplicationCPURequest(
   const simdjson::dom::element& value,
   ApplicationConfig& config,
   String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   const bool sharedCPUs = applicationUsesSharedCPUs(config);
   if (sharedCPUs == false)
   {
      if (value.type() != simdjson::dom::element_type::INT64
         && value.type() != simdjson::dom::element_type::UINT64)
      {
         if (failure)
         {
            failure->assign("config.nLogicalCores requires an integer when isolateCPUs=true"_ctv);
         }

         return false;
      }

      uint64_t requested = 0;
      if (value.type() == simdjson::dom::element_type::INT64)
      {
         int64_t signedRequested = 0;
         (void)value.get(signedRequested);
         if (signedRequested <= 0)
         {
            if (failure)
            {
               failure->assign("config.nLogicalCores must be > 0"_ctv);
            }

            return false;
         }

         requested = uint64_t(signedRequested);
      }
      else
      {
         (void)value.get(requested);
         if (requested == 0)
         {
            if (failure)
            {
               failure->assign("config.nLogicalCores must be > 0"_ctv);
            }

            return false;
         }
      }

      if (requested > uint64_t(UINT32_MAX))
      {
         if (failure)
         {
            failure->assign("config.nLogicalCores value invalid"_ctv);
         }

         return false;
      }

      config.nLogicalCores = uint32_t(requested);
      config.sharedCPUMillis = 0;
      return true;
   }

   if (value.type() != simdjson::dom::element_type::DOUBLE
      && value.type() != simdjson::dom::element_type::INT64
      && value.type() != simdjson::dom::element_type::UINT64)
   {
      if (failure)
      {
         failure->assign("config.nLogicalCores requires a number when isolateCPUs=false"_ctv);
      }

      return false;
   }

   double requestedCores = 0.0;
   if (value.type() == simdjson::dom::element_type::DOUBLE)
   {
      (void)value.get(requestedCores);
   }
   else if (value.type() == simdjson::dom::element_type::INT64)
   {
      int64_t signedRequested = 0;
      (void)value.get(signedRequested);
      requestedCores = double(signedRequested);
   }
   else
   {
      uint64_t unsignedRequested = 0;
      (void)value.get(unsignedRequested);
      requestedCores = double(unsignedRequested);
   }

   if (std::isfinite(requestedCores) == false || requestedCores <= 0.0)
   {
      if (failure)
      {
         failure->assign("config.nLogicalCores value invalid"_ctv);
      }

      return false;
   }

   uint64_t requestedMillis = uint64_t(std::llround(requestedCores * double(prodigyCPUUnitsPerCore)));
   if (requestedMillis == 0 || requestedMillis > uint64_t(UINT32_MAX))
   {
      if (failure)
      {
         failure->assign("config.nLogicalCores value invalid"_ctv);
      }

      return false;
   }

   config.sharedCPUMillis = uint32_t(requestedMillis);
   config.nLogicalCores = prodigyRoundUpDivideU64(requestedMillis, prodigyCPUUnitsPerCore);
   return true;
}

static inline bool mothershipParseSharedCPUOvercommitValue(
   const simdjson::dom::element& value,
   uint16_t& outPermille,
   String *failure = nullptr,
   const String& fieldName = "sharedCpuOvercommit"_ctv)
{
   if (failure)
   {
      failure->clear();
   }

   if (value.type() != simdjson::dom::element_type::DOUBLE
      && value.type() != simdjson::dom::element_type::INT64
      && value.type() != simdjson::dom::element_type::UINT64)
   {
      if (failure)
      {
         failure->snprintf<"{} requires a number"_ctv>(fieldName);
      }

      return false;
   }

   double ratio = 0.0;
   if (value.type() == simdjson::dom::element_type::DOUBLE)
   {
      (void)value.get(ratio);
   }
   else if (value.type() == simdjson::dom::element_type::INT64)
   {
      int64_t signedRatio = 0;
      (void)value.get(signedRatio);
      ratio = double(signedRatio);
   }
   else
   {
      uint64_t unsignedRatio = 0;
      (void)value.get(unsignedRatio);
      ratio = double(unsignedRatio);
   }

   if (std::isfinite(ratio) == false
      || ratio < 1.0
      || ratio > 2.0)
   {
      if (failure)
      {
         failure->snprintf<"{} must be in 1.0..2.0"_ctv>(fieldName);
      }

      return false;
   }

   uint64_t permille = uint64_t(std::llround(ratio * 1000.0));
   if (permille < prodigySharedCPUOvercommitMinPermille
      || permille > prodigySharedCPUOvercommitMaxPermille)
   {
      if (failure)
      {
         failure->snprintf<"{} must be in 1.0..2.0"_ctv>(fieldName);
      }

      return false;
   }

   outPermille = uint16_t(permille);
   return true;
}

static inline bool mothershipParseWormholeQuicCidKeyRotationHours(
   const simdjson::dom::element& value,
   Wormhole& wormhole,
   String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   if (value.type() != simdjson::dom::element_type::INT64
      && value.type() != simdjson::dom::element_type::UINT64)
   {
      if (failure)
      {
         failure->assign("wormhole.quicCidKeyRotationHours requires an integer"_ctv);
      }

      return false;
   }

   uint64_t rotationHours = 0;
   if (value.type() == simdjson::dom::element_type::INT64)
   {
      int64_t signedHours = 0;
      (void)value.get(signedHours);
      if (signedHours <= 0)
      {
         if (failure)
         {
            failure->assign("wormhole.quicCidKeyRotationHours must be > 0"_ctv);
         }

         return false;
      }

      rotationHours = uint64_t(signedHours);
   }
   else
   {
      (void)value.get(rotationHours);
      if (rotationHours == 0)
      {
         if (failure)
         {
            failure->assign("wormhole.quicCidKeyRotationHours must be > 0"_ctv);
         }

         return false;
      }
   }

   if (rotationHours > UINT32_MAX)
   {
      if (failure)
      {
         failure->assign("wormhole.quicCidKeyRotationHours exceeds uint32 range"_ctv);
      }

      return false;
   }

   wormhole.quicCidKeyState.rotationHours = uint32_t(rotationHours);
   return true;
}

static inline bool mothershipParseApplicationMachineSelectionField(
   const String& key,
   const simdjson::dom::element& value,
   ApplicationConfig& config,
   String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   auto parseUInt32Field = [&] (const simdjson::dom::element& fieldValue, const String& fieldName, uint32_t& out) -> bool {
      if (fieldValue.type() != simdjson::dom::element_type::INT64
         && fieldValue.type() != simdjson::dom::element_type::UINT64)
      {
         if (failure)
         {
            failure->snprintf<"{}.{} requires an integer"_ctv>("config"_ctv, fieldName);
         }

         return false;
      }

      uint64_t parsed = 0;
      if (fieldValue.type() == simdjson::dom::element_type::INT64)
      {
         int64_t signedValue = 0;
         (void)fieldValue.get(signedValue);
         if (signedValue < 0)
         {
            if (failure)
            {
               failure->snprintf<"{}.{} must be >= 0"_ctv>("config"_ctv, fieldName);
            }

            return false;
         }

         parsed = uint64_t(signedValue);
      }
      else
      {
         (void)fieldValue.get(parsed);
      }

      if (parsed > UINT32_MAX)
      {
         if (failure)
         {
            failure->snprintf<"{}.{} exceeds uint32 range"_ctv>("config"_ctv, fieldName);
         }

         return false;
      }

      out = uint32_t(parsed);
      return true;
   };

   if (key.equal("minGPUs"_ctv))
   {
      return parseUInt32Field(value, key, config.minGPUs);
   }
   if (key.equal("gpuMemoryGB"_ctv))
   {
      return parseUInt32Field(value, key, config.gpuMemoryGB);
   }
   if (key.equal("nicSpeedGbps"_ctv))
   {
      return parseUInt32Field(value, key, config.nicSpeedGbps);
   }
   if (key.equal("minInternetDownloadMbps"_ctv))
   {
      return parseUInt32Field(value, key, config.minInternetDownloadMbps);
   }
   if (key.equal("minInternetUploadMbps"_ctv))
   {
      return parseUInt32Field(value, key, config.minInternetUploadMbps);
   }
   if (key.equal("maxInternetLatencyMs"_ctv))
   {
      return parseUInt32Field(value, key, config.maxInternetLatencyMs);
   }

   if (failure)
   {
      failure->clear();
   }

   return false;
}

static inline bool mothershipValidateApplicationMachineSelectionFields(
   const ApplicationConfig& config,
   const String& context,
   String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   if (config.gpuMemoryGB > 0 && config.minGPUs == 0)
   {
      if (failure)
      {
         failure->snprintf<"{}.gpuMemoryGB requires minGPUs > 0"_ctv>(context);
      }

      return false;
   }

   if (config.gpuMemoryGB > (UINT32_MAX / 1024u))
   {
      if (failure)
      {
         failure->snprintf<"{}.gpuMemoryGB exceeds supported range"_ctv>(context);
      }

      return false;
   }

   return true;
}

static inline bool mothershipParseApplicationMachineSelectionObject(
   const simdjson::dom::element& value,
   ApplicationConfig& config,
   const String& context,
   String *failure = nullptr)
{
   if (failure)
   {
      failure->clear();
   }

   if (value.type() != simdjson::dom::element_type::OBJECT)
   {
      if (failure)
      {
         failure->snprintf<"{} requires an object"_ctv>(context);
      }

      return false;
   }

   for (auto field : value.get_object())
   {
      String key = {};
      key.setInvariant(field.key);

      String parseFailure = {};
      if (mothershipParseApplicationMachineSelectionField(key, field.value, config, &parseFailure))
      {
         continue;
      }

      if (parseFailure.size() > 0)
      {
         if (failure)
         {
            *failure = parseFailure;
         }

         return false;
      }

      if (failure)
      {
         failure->snprintf<"{}.{} is not recognized"_ctv>(context, key);
      }

      return false;
   }

   return mothershipValidateApplicationMachineSelectionFields(config, context, failure);
}
