#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <limits>

#include <curl/curl.h>
#include <simdjson.h>

#include <cpp-sort/adapters/verge_adapter.h>
#include <cpp-sort/sorters/ska_sorter.h>
#include <prodigy/brain/mesh.node.h>
#include <prodigy/brain/mesh.h>
#include <prodigy/brain/containerviews.h>

static inline cppsort::verge_adapter<cppsort::ska_sorter> sorter;

#include <prodigy/brain/deployments.h>
#include <prodigy/iaas/aws/aws.h>
#include <prodigy/iaas/azure/azure.h>
#include <prodigy/iaas/gcp/gcp.h>
#include <prodigy/mothership/mothership.deployment.plan.helpers.h>
#include <prodigy/mothership/mothership.pricing.types.h>
#include <prodigy/mothership/mothership.provider.credentials.h>

class MothershipGcpPricingShim : public GcpBrainIaaS
{
public:

   bool request(const char *method, const String& url, const String *body, String& response, long *httpStatus, String& failure)
   {
      return sendElasticComputeRequest(method, url, body, response, httpStatus, failure);
   }
};

class MothershipAzurePricingShim : public AzureBrainIaaS
{
public:

   bool request(const char *method, const String& url, const String *body, String& response, long *httpStatus, String& failure)
   {
      return sendARMRaw(method, url, body, response, httpStatus, failure);
   }
};

struct MothershipCloudCountryMapping
{
   const char *scope;
   const char *countryKey;
};

struct MothershipAwsRegionMapping
{
   const char *region;
   const char *countryKey;
};

static inline void mothershipNormalizeCountryKey(const String& value, String& key)
{
   key.clear();

   for (uint64_t index = 0; index < value.size(); ++index)
   {
      unsigned char byte = unsigned(value[index]);
      if (std::isalnum(byte) == 0)
      {
         continue;
      }

      key.append(char(std::tolower(byte)));
   }

   if (key.equal("us"_ctv) || key.equal("usa"_ctv) || key.equal("unitedstatesofamerica"_ctv))
   {
      key.assign("unitedstates"_ctv);
   }
   else if (key.equal("uk"_ctv) || key.equal("greatbritain"_ctv) || key.equal("britain"_ctv))
   {
      key.assign("unitedkingdom"_ctv);
   }
   else if (key.equal("uae"_ctv))
   {
      key.assign("unitedarabemirates"_ctv);
   }
   else if (key.equal("republicofkorea"_ctv) || key.equal("korea"_ctv))
   {
      key.assign("southkorea"_ctv);
   }
}

static inline void mothershipCountryDisplayFromKey(const String& key, String& display)
{
   display.clear();

   if (key.equal("unitedstates"_ctv)) display.assign("United States"_ctv);
   else if (key.equal("canada"_ctv)) display.assign("Canada"_ctv);
   else if (key.equal("mexico"_ctv)) display.assign("Mexico"_ctv);
   else if (key.equal("brazil"_ctv)) display.assign("Brazil"_ctv);
   else if (key.equal("ireland"_ctv)) display.assign("Ireland"_ctv);
   else if (key.equal("unitedkingdom"_ctv)) display.assign("United Kingdom"_ctv);
   else if (key.equal("france"_ctv)) display.assign("France"_ctv);
   else if (key.equal("germany"_ctv)) display.assign("Germany"_ctv);
   else if (key.equal("switzerland"_ctv)) display.assign("Switzerland"_ctv);
   else if (key.equal("sweden"_ctv)) display.assign("Sweden"_ctv);
   else if (key.equal("italy"_ctv)) display.assign("Italy"_ctv);
   else if (key.equal("spain"_ctv)) display.assign("Spain"_ctv);
   else if (key.equal("poland"_ctv)) display.assign("Poland"_ctv);
   else if (key.equal("finland"_ctv)) display.assign("Finland"_ctv);
   else if (key.equal("netherlands"_ctv)) display.assign("Netherlands"_ctv);
   else if (key.equal("belgium"_ctv)) display.assign("Belgium"_ctv);
   else if (key.equal("southafrica"_ctv)) display.assign("South Africa"_ctv);
   else if (key.equal("israel"_ctv)) display.assign("Israel"_ctv);
   else if (key.equal("unitedarabemirates"_ctv)) display.assign("United Arab Emirates"_ctv);
   else if (key.equal("india"_ctv)) display.assign("India"_ctv);
   else if (key.equal("japan"_ctv)) display.assign("Japan"_ctv);
   else if (key.equal("southkorea"_ctv)) display.assign("South Korea"_ctv);
   else if (key.equal("singapore"_ctv)) display.assign("Singapore"_ctv);
   else if (key.equal("hongkong"_ctv)) display.assign("Hong Kong"_ctv);
   else if (key.equal("taiwan"_ctv)) display.assign("Taiwan"_ctv);
   else if (key.equal("australia"_ctv)) display.assign("Australia"_ctv);
   else if (key.equal("newzealand"_ctv)) display.assign("New Zealand"_ctv);
   else if (key.equal("norway"_ctv)) display.assign("Norway"_ctv);
   else
   {
      display.assign(key);
   }
}

static inline bool mothershipCountryMatchesRequested(const String& requestedCountry, const char *expectedCountryKey, String *failure = nullptr)
{
   String requestedKey = {};
   mothershipNormalizeCountryKey(requestedCountry, requestedKey);
   if (requestedKey.size() == 0 || expectedCountryKey == nullptr)
   {
      if (failure) failure->assign("country required"_ctv);
      return false;
   }

   String expectedKey = {};
   expectedKey.assign(expectedCountryKey);
   return requestedKey.equals(expectedKey);
}

static inline bool mothershipTextContains(const String& haystack, const char *needle)
{
   if (needle == nullptr || needle[0] == '\0')
   {
      return false;
   }

   size_t needleLength = std::strlen(needle);
   if (needleLength == 0 || haystack.size() < needleLength)
   {
      return false;
   }

   for (uint64_t index = 0; index + needleLength <= haystack.size(); ++index)
   {
      if (std::memcmp(haystack.data() + index, needle, needleLength) == 0)
      {
         return true;
      }
   }

   return false;
}

static inline bool mothershipTextEndsWith(const String& text, const char *suffix)
{
   if (suffix == nullptr || suffix[0] == '\0')
   {
      return false;
   }

   size_t suffixLength = std::strlen(suffix);
   if (text.size() < suffixLength)
   {
      return false;
   }

   return std::memcmp(text.data() + (text.size() - suffixLength), suffix, suffixLength) == 0;
}

static inline bool mothershipTextEqualsCString(const String& text, const char *other)
{
   if (other == nullptr)
   {
      return false;
   }

   size_t otherLength = std::strlen(other);
   return text.size() == otherLength && std::memcmp(text.data(), other, otherLength) == 0;
}

static inline bool mothershipStringLess(const String& lhs, const String& rhs)
{
   uint64_t limit = std::min(lhs.size(), rhs.size());
   int comparison = std::memcmp(lhs.data(), rhs.data(), limit);
   if (comparison != 0)
   {
      return comparison < 0;
   }

   return lhs.size() < rhs.size();
}

static inline void mothershipUppercaseInPlace(String& text)
{
   for (uint64_t index = 0; index < text.size(); ++index)
   {
      text[index] = char(std::toupper(unsigned(text[index])));
   }
}

static inline void mothershipAppendPercentEncoded(String& output, const String& value)
{
   static constexpr char hex[] = "0123456789ABCDEF";

   for (uint64_t index = 0; index < value.size(); ++index)
   {
      uint8_t byte = value[index];
      bool unreserved = (byte >= 'A' && byte <= 'Z')
         || (byte >= 'a' && byte <= 'z')
         || (byte >= '0' && byte <= '9')
         || byte == '-'
         || byte == '_'
         || byte == '.'
         || byte == '~';

      if (unreserved)
      {
         output.append(byte);
      }
      else
      {
         output.append('%');
         output.append(uint8_t(hex[(byte >> 4) & 0x0f]));
         output.append(uint8_t(hex[byte & 0x0f]));
      }
   }
}

static inline void mothershipAppendPageTokenQuery(String& url, const String& pageToken)
{
   if (pageToken.size() == 0)
   {
      return;
   }

   bool hasQuery = false;
   for (uint64_t index = 0; index < url.size(); ++index)
   {
      if (url[index] == '?')
      {
         hasQuery = true;
         break;
      }
   }

   url.append(hasQuery ? '&' : '?');
   url.append("pageToken="_ctv);
   mothershipAppendPercentEncoded(url, pageToken);
}

static inline bool mothershipResolveAwsRegionCountry(const String& region, String& countryKey)
{
   static constexpr MothershipAwsRegionMapping mappings[] = {
      { "us-east-1", "unitedstates" },
      { "us-east-2", "unitedstates" },
      { "us-west-1", "unitedstates" },
      { "us-west-2", "unitedstates" },
      { "ca-central-1", "canada" },
      { "ca-west-1", "canada" },
      { "mx-central-1", "mexico" },
      { "sa-east-1", "brazil" },
      { "eu-west-1", "ireland" },
      { "eu-west-2", "unitedkingdom" },
      { "eu-west-3", "france" },
      { "eu-central-1", "germany" },
      { "eu-central-2", "switzerland" },
      { "eu-north-1", "sweden" },
      { "eu-south-1", "italy" },
      { "eu-south-2", "spain" },
      { "af-south-1", "southafrica" },
      { "me-central-1", "unitedarabemirates" },
      { "il-central-1", "israel" },
      { "ap-south-1", "india" },
      { "ap-south-2", "india" },
      { "ap-east-1", "hongkong" },
      { "ap-northeast-1", "japan" },
      { "ap-northeast-2", "southkorea" },
      { "ap-northeast-3", "japan" },
      { "ap-southeast-1", "singapore" },
      { "ap-southeast-2", "australia" },
      { "ap-southeast-4", "australia" }
   };

   countryKey.clear();
   for (const MothershipAwsRegionMapping& mapping : mappings)
   {
      if (mothershipTextEqualsCString(region, mapping.region))
      {
         countryKey.assign(mapping.countryKey);
         return true;
      }
   }

   return false;
}

static inline bool mothershipResolveGcpRegionCountry(const String& region, String& countryKey)
{
   static constexpr MothershipCloudCountryMapping mappings[] = {
      { "us-central1", "unitedstates" },
      { "us-east1", "unitedstates" },
      { "us-east4", "unitedstates" },
      { "us-east5", "unitedstates" },
      { "us-south1", "unitedstates" },
      { "us-west1", "unitedstates" },
      { "us-west2", "unitedstates" },
      { "us-west3", "unitedstates" },
      { "us-west4", "unitedstates" },
      { "northamerica-northeast1", "canada" },
      { "northamerica-northeast2", "canada" },
      { "northamerica-south1", "mexico" },
      { "southamerica-east1", "brazil" },
      { "southamerica-west1", "chile" },
      { "europe-west1", "belgium" },
      { "europe-west2", "unitedkingdom" },
      { "europe-west3", "germany" },
      { "europe-west4", "netherlands" },
      { "europe-west6", "switzerland" },
      { "europe-west8", "italy" },
      { "europe-west9", "france" },
      { "europe-west10", "germany" },
      { "europe-west12", "italy" },
      { "europe-central2", "poland" },
      { "europe-north1", "finland" },
      { "europe-southwest1", "spain" },
      { "me-west1", "israel" },
      { "africa-south1", "southafrica" },
      { "asia-east1", "taiwan" },
      { "asia-east2", "hongkong" },
      { "asia-northeast1", "japan" },
      { "asia-northeast2", "japan" },
      { "asia-northeast3", "southkorea" },
      { "asia-south1", "india" },
      { "asia-south2", "india" },
      { "asia-southeast1", "singapore" },
      { "australia-southeast1", "australia" },
      { "australia-southeast2", "australia" }
   };

   countryKey.clear();
   for (const MothershipCloudCountryMapping& mapping : mappings)
   {
      if (mothershipTextEqualsCString(region, mapping.scope))
      {
         countryKey.assign(mapping.countryKey);
         return true;
      }
   }

   return false;
}

static inline bool mothershipResolveAzureLocationCountry(const String& location, String& countryKey)
{
   static constexpr MothershipCloudCountryMapping mappings[] = {
      { "eastus", "unitedstates" },
      { "eastus2", "unitedstates" },
      { "westus", "unitedstates" },
      { "westus2", "unitedstates" },
      { "westus3", "unitedstates" },
      { "centralus", "unitedstates" },
      { "northcentralus", "unitedstates" },
      { "southcentralus", "unitedstates" },
      { "westcentralus", "unitedstates" },
      { "canadacentral", "canada" },
      { "canadaeast", "canada" },
      { "mexicocentral", "mexico" },
      { "brazilsouth", "brazil" },
      { "northeurope", "ireland" },
      { "westeurope", "netherlands" },
      { "uksouth", "unitedkingdom" },
      { "ukwest", "unitedkingdom" },
      { "francecentral", "france" },
      { "germanywestcentral", "germany" },
      { "swedencentral", "sweden" },
      { "switzerlandnorth", "switzerland" },
      { "italynorth", "italy" },
      { "polandcentral", "poland" },
      { "spaincentral", "spain" },
      { "norwayeast", "norway" },
      { "southafricanorth", "southafrica" },
      { "uaenorth", "unitedarabemirates" },
      { "israelcentral", "israel" },
      { "centralindia", "india" },
      { "southindia", "india" },
      { "westindia", "india" },
      { "jioindiawest", "india" },
      { "japaneast", "japan" },
      { "japanwest", "japan" },
      { "koreacentral", "southkorea" },
      { "southeastasia", "singapore" },
      { "eastasia", "hongkong" },
      { "australiaeast", "australia" },
      { "australiasoutheast", "australia" },
      { "newzealandnorth", "newzealand" }
   };

   countryKey.clear();
   for (const MothershipCloudCountryMapping& mapping : mappings)
   {
      if (mothershipTextEqualsCString(location, mapping.scope))
      {
         countryKey.assign(mapping.countryKey);
         return true;
      }
   }

   return false;
}

static inline bool mothershipParseGcpProviderScope(const String& scope, String& projectId, String& zone, String *failure = nullptr)
{
   projectId.clear();
   zone.clear();
   if (failure) failure->clear();

   if (scope.size() == 0)
   {
      if (failure) failure->assign("gcp providerScope required"_ctv);
      return false;
   }

   String scopeText = {};
   scopeText.assign(scope);

   auto findSubstring = [&] (const String& needle) -> int64_t {
      if (needle.size() == 0 || scopeText.size() < needle.size())
      {
         return -1;
      }

      for (uint64_t index = 0; index + needle.size() <= scopeText.size(); ++index)
      {
         if (memcmp(scopeText.data() + index, needle.data(), needle.size()) == 0)
         {
            return int64_t(index);
         }
      }

      return -1;
   };

   String projectPrefix = "projects/"_ctv;
   if (int64_t projectOffset = findSubstring(projectPrefix); projectOffset >= 0)
   {
      uint64_t start = uint64_t(projectOffset) + projectPrefix.size();
      int64_t slash = scopeText.findChar('/', start);
      uint64_t end = (slash >= 0) ? uint64_t(slash) : scopeText.size();
      if (end > start)
      {
         projectId.assign(scopeText.substr(start, end - start, Copy::yes));
      }
   }

   String zonePrefix = "zones/"_ctv;
   if (int64_t zoneOffset = findSubstring(zonePrefix); zoneOffset >= 0)
   {
      uint64_t start = uint64_t(zoneOffset) + zonePrefix.size();
      int64_t slash = scopeText.findChar('/', start);
      uint64_t end = (slash >= 0) ? uint64_t(slash) : scopeText.size();
      if (end > start)
      {
         zone.assign(scopeText.substr(start, end - start, Copy::yes));
      }
   }

   if (projectId.size() == 0)
   {
      int64_t slash = scopeText.findChar('/');
      if (slash > 0)
      {
         projectId.assign(scopeText.substr(0, uint64_t(slash), Copy::yes));
      }
      else
      {
         projectId.assign(scopeText);
      }
   }

   if (zone.size() == 0)
   {
      int64_t lastSlash = scopeText.rfindChar('/');
      if (lastSlash >= 0 && uint64_t(lastSlash + 1) < scopeText.size())
      {
         zone.assign(scopeText.substr(uint64_t(lastSlash + 1), scopeText.size() - uint64_t(lastSlash + 1), Copy::yes));
      }
   }

   if (projectId.size() == 0 || zone.size() == 0)
   {
      if (failure) failure->assign("gcp providerScope requires project and zone"_ctv);
      return false;
   }

   return true;
}

static inline bool mothershipResolveScopeCountry(
   MothershipClusterProvider provider,
   const String& providerScope,
   String& resolvedScope,
   String& resolvedCountryDisplay,
   String *failure = nullptr)
{
   resolvedScope.clear();
   resolvedCountryDisplay.clear();
   if (failure) failure->clear();

   String countryKey = {};

   if (provider == MothershipClusterProvider::aws)
   {
      if (awsScopeRegion(providerScope, resolvedScope) == false || mothershipResolveAwsRegionCountry(resolvedScope, countryKey) == false)
      {
         if (failure) failure->assign("aws providerScope region is unsupported for country mapping"_ctv);
         return false;
      }
   }
   else if (provider == MothershipClusterProvider::gcp)
   {
      String projectId = {};
      String zone = {};
      if (mothershipParseGcpProviderScope(providerScope, projectId, zone, failure) == false)
      {
         return false;
      }

      int64_t dash = zone.rfindChar('-');
      if (dash <= 0)
      {
         if (failure) failure->assign("gcp providerScope zone invalid"_ctv);
         return false;
      }

      resolvedScope.assign(zone.substr(0, uint64_t(dash), Copy::yes));
      if (mothershipResolveGcpRegionCountry(resolvedScope, countryKey) == false)
      {
         if (failure) failure->assign("gcp providerScope region is unsupported for country mapping"_ctv);
         return false;
      }
   }
   else if (provider == MothershipClusterProvider::azure)
   {
      String subscriptionID = {};
      String resourceGroup = {};
      if (parseAzureProviderScope(providerScope, subscriptionID, resourceGroup, resolvedScope, failure) == false)
      {
         return false;
      }

      if (mothershipResolveAzureLocationCountry(resolvedScope, countryKey) == false)
      {
         if (failure) failure->assign("azure providerScope location is unsupported for country mapping"_ctv);
         return false;
      }
   }
   else
   {
      if (failure) failure->assign("unsupported provider for pricing"_ctv);
      return false;
   }

   mothershipCountryDisplayFromKey(countryKey, resolvedCountryDisplay);
   return true;
}

static inline bool mothershipResolveScopeHostPublicCapabilities(
   MothershipClusterProvider provider,
   const String& providerScope,
   bool& providesHostPublic4,
   bool& providesHostPublic6,
   String *failure = nullptr)
{
   providesHostPublic4 = false;
   providesHostPublic6 = false;
   if (failure) failure->clear();

   String resolvedScope = {};
   String resolvedCountryDisplay = {};
   if (mothershipResolveScopeCountry(provider, providerScope, resolvedScope, resolvedCountryDisplay, failure) == false)
   {
      return false;
   }

   // Pricing treats host-public addressing as a provider target capability,
   // not as a machine-type attribute. Every surveyed offer in the same target
   // scope inherits the same capability surface.
   switch (provider)
   {
      case MothershipClusterProvider::aws:
      case MothershipClusterProvider::gcp:
      case MothershipClusterProvider::azure:
      {
         providesHostPublic4 = true;
         providesHostPublic6 = true;
         return true;
      }
      default:
      {
         if (failure) failure->assign("unsupported provider for pricing"_ctv);
         return false;
      }
   }
}

static inline bool mothershipResolveTargetCredential(
   MothershipProviderScopeTarget& target,
   MothershipProviderCredential& credential,
   String *failure = nullptr)
{
   credential = {};
   if (failure) failure->clear();

   if (target.provider == MothershipClusterProvider::unknown)
   {
      if (failure) failure->assign("provider required"_ctv);
      return false;
   }

   if (target.hasProviderCredentialOverride)
   {
      credential = {};
      credential.provider = target.providerCredentialOverride.provider;
      credential.material = target.providerCredentialOverride.material;
      credential.scope = target.providerCredentialOverride.scope;
      if (credential.provider == MothershipClusterProvider::unknown)
      {
         credential.provider = target.provider;
      }
      else if (credential.provider != target.provider)
      {
         if (failure) failure->assign("providerCredentialOverride provider does not match provider"_ctv);
         return false;
      }

      if (target.providerScope.size() == 0 && credential.scope.size() > 0)
      {
         target.providerScope = credential.scope;
      }
      else if (credential.scope.size() == 0)
      {
         credential.scope = target.providerScope;
      }
      else if (target.providerScope.equals(credential.scope) == false)
      {
         if (failure) failure->assign("providerCredentialOverride scope does not match providerScope"_ctv);
         return false;
      }

      if (credential.material.size() == 0)
      {
         if (failure) failure->assign("providerCredentialOverride material required"_ctv);
         return false;
      }

      return true;
   }

   if (target.providerCredentialName.size() == 0)
   {
      if (failure) failure->assign("providerCredentialName or providerCredentialOverride required"_ctv);
      return false;
   }

   MothershipProviderCredentialRegistry providerCredentialRegistry = MothershipProviderCredentialRegistry();
   if (providerCredentialRegistry.getCredential(target.providerCredentialName, credential, failure) == false)
   {
      return false;
   }

   if (credential.provider != target.provider)
   {
      if (failure) failure->assign("providerCredentialName provider does not match provider"_ctv);
      return false;
   }

   if (target.providerScope.size() == 0)
   {
      target.providerScope = credential.scope;
   }
   else if (credential.scope.size() > 0 && target.providerScope.equals(credential.scope) == false)
   {
      if (failure) failure->assign("providerCredentialName scope does not match providerScope"_ctv);
      return false;
   }

   if (target.providerScope.size() == 0)
   {
      if (failure) failure->assign("providerScope required"_ctv);
      return false;
   }

   return true;
}

static inline bool mothershipParseUnsignedDecimalUSDToMicrousd(const simdjson::dom::element& value, uint64_t& microusd, String *failure = nullptr, const String& fieldName = "budgetHourlyUSD"_ctv)
{
   microusd = 0;
   if (failure) failure->clear();

   double hourly = 0.0;
   if (value.type() == simdjson::dom::element_type::DOUBLE)
   {
      (void)value.get(hourly);
   }
   else if (value.type() == simdjson::dom::element_type::INT64)
   {
      int64_t signedValue = 0;
      (void)value.get(signedValue);
      hourly = double(signedValue);
   }
   else if (value.type() == simdjson::dom::element_type::UINT64)
   {
      uint64_t unsignedValue = 0;
      (void)value.get(unsignedValue);
      hourly = double(unsignedValue);
   }
   else
   {
      if (failure) failure->snprintf<"{} requires a number"_ctv>(fieldName);
      return false;
   }

   if (std::isfinite(hourly) == false || hourly < 0.0)
   {
      if (failure) failure->snprintf<"{} must be >= 0"_ctv>(fieldName);
      return false;
   }

   microusd = uint64_t(std::llround(hourly * 1000000.0));
   return true;
}

static inline bool mothershipParseUnsignedDecimalGBToMB(const simdjson::dom::element& value, uint64_t& mb, String *failure = nullptr, const String& fieldName = "ingressGBPerHour"_ctv)
{
   mb = 0;
   if (failure) failure->clear();

   double gb = 0.0;
   if (value.type() == simdjson::dom::element_type::DOUBLE)
   {
      (void)value.get(gb);
   }
   else if (value.type() == simdjson::dom::element_type::INT64)
   {
      int64_t signedValue = 0;
      (void)value.get(signedValue);
      gb = double(signedValue);
   }
   else if (value.type() == simdjson::dom::element_type::UINT64)
   {
      uint64_t unsignedValue = 0;
      (void)value.get(unsignedValue);
      gb = double(unsignedValue);
   }
   else
   {
      if (failure) failure->snprintf<"{} requires a number"_ctv>(fieldName);
      return false;
   }

   if (std::isfinite(gb) == false || gb < 0.0)
   {
      if (failure) failure->snprintf<"{} must be >= 0"_ctv>(fieldName);
      return false;
   }

   mb = uint64_t(std::llround(gb * 1024.0));
   return true;
}

static inline double mothershipMicrousdToUSD(uint64_t microusd)
{
   return double(microusd) / 1000000.0;
}

static inline bool mothershipParseDecimalPriceMicrousd(const String& price, uint64_t& microusd)
{
   microusd = 0;
   if (price.size() == 0)
   {
      return false;
   }

   String priceText = {};
   priceText.assign(price);
   char *end = nullptr;
   double value = std::strtod(priceText.c_str(), &end);
   if (end == nullptr || end == priceText.c_str() || std::isfinite(value) == false || value < 0.0)
   {
      return false;
   }

   microusd = uint64_t(std::llround(value * 1000000.0));
   return true;
}

static inline bool mothershipParseDoubleMicrousd(double value, uint64_t& microusd)
{
   if (std::isfinite(value) == false || value < 0.0)
   {
      return false;
   }

   microusd = uint64_t(std::llround(value * 1000000.0));
   return true;
}

static inline uint32_t mothershipCeilMBToGB(uint64_t mb)
{
   return uint32_t((mb + 1023ull) / 1024ull);
}

static inline uint64_t mothershipScaleMicrousdPerGBByMB(uint64_t perGBMicrousd, uint64_t mb)
{
   if (perGBMicrousd == 0 || mb == 0)
   {
      return 0;
   }

   return uint64_t(std::llround((double(perGBMicrousd) * double(mb)) / 1024.0));
}

static inline uint64_t mothershipPriceMicrousdPerGBHourFromMonthlyRate(uint64_t monthlyMicrousdPerGB)
{
   if (monthlyMicrousdPerGB == 0)
   {
      return 0;
   }

   return uint64_t(std::llround(double(monthlyMicrousdPerGB) / 730.0));
}

static inline const MothershipStoragePricingTier *mothershipFindStorageTierForGB(const Vector<MothershipStoragePricingTier>& tiers, uint32_t capacityGB)
{
   const MothershipStoragePricingTier *smallest = nullptr;
   const MothershipStoragePricingTier *largest = nullptr;
   for (const MothershipStoragePricingTier& tier : tiers)
   {
      if (tier.capacityGB == 0 || tier.hourlyMicrousd == 0)
      {
         continue;
      }

      if (smallest == nullptr || tier.capacityGB < smallest->capacityGB)
      {
         smallest = &tier;
      }

      if (largest == nullptr || tier.capacityGB > largest->capacityGB)
      {
         largest = &tier;
      }
   }

   const MothershipStoragePricingTier *best = nullptr;
   for (const MothershipStoragePricingTier& tier : tiers)
   {
      if (tier.capacityGB == 0 || tier.hourlyMicrousd == 0 || tier.capacityGB < capacityGB)
      {
         continue;
      }

      if (best == nullptr || tier.capacityGB < best->capacityGB)
      {
         best = &tier;
      }
   }

   if (best)
   {
      return best;
   }

   return largest ? largest : smallest;
}

static inline uint64_t mothershipOfferExtraStorageHourlyMicrousd(const MothershipProviderMachineOffer& offer, uint32_t requestedStorageMB)
{
   const uint32_t effectiveStorageMB = requestedStorageMB > 0 ? requestedStorageMB : offer.nStorageMBDefault;
   if (effectiveStorageMB <= offer.nStorageMBDefault)
   {
      return 0;
   }

   if (offer.storageTiers.empty() == false)
   {
      const uint32_t requestedGB = mothershipCeilMBToGB(effectiveStorageMB);
      const uint32_t defaultGB = mothershipCeilMBToGB(offer.nStorageMBDefault);
      const MothershipStoragePricingTier *requestedTier = mothershipFindStorageTierForGB(offer.storageTiers, requestedGB);
      const MothershipStoragePricingTier *defaultTier = mothershipFindStorageTierForGB(offer.storageTiers, defaultGB);
      if (requestedTier && defaultTier && requestedTier->hourlyMicrousd > defaultTier->hourlyMicrousd)
      {
         return requestedTier->hourlyMicrousd - defaultTier->hourlyMicrousd;
      }

      return 0;
   }

   return mothershipScaleMicrousdPerGBByMB(offer.extraStorageMicrousdPerGBHour, uint64_t(effectiveStorageMB - offer.nStorageMBDefault));
}

class MothershipClusterCostBreakdown
{
public:

   uint64_t computeHourlyMicrousd = 0;
   uint64_t storageHourlyMicrousd = 0;
   uint64_t ingressHourlyMicrousd = 0;
   uint64_t egressHourlyMicrousd = 0;

   uint64_t totalHourlyMicrousd(void) const
   {
      return computeHourlyMicrousd + storageHourlyMicrousd + ingressHourlyMicrousd + egressHourlyMicrousd;
   }
};

class MothershipPlanningMachineMetadata
{
public:

   String providerMachineType;
   MachineConfig::MachineKind kind = MachineConfig::MachineKind::vm;
   uint32_t defaultStorageMB = 0;
};

static inline bool mothershipParseMemoryTextMB(const String& text, uint32_t& memoryMB)
{
   memoryMB = 0;
   if (text.size() == 0)
   {
      return false;
   }

   String ownedText = {};
   ownedText.assign(text);
   char *end = nullptr;
   double value = std::strtod(ownedText.c_str(), &end);
   if (end == nullptr || end == ownedText.c_str() || std::isfinite(value) == false || value <= 0.0)
   {
      return false;
   }

   String unit = {};
   while (end && *end != '\0' && std::isspace(unsigned(*end)))
   {
      ++end;
   }

   if (end != nullptr && *end != '\0')
   {
      unit.assign(end);
   }

   for (uint64_t index = 0; index < unit.size(); ++index)
   {
      unit[index] = char(std::tolower(unsigned(unit[index])));
   }

   double factorMB = 1.0;
   if (unit.size() == 0 || unit.equal("mb"_ctv) || unit.equal("mib"_ctv))
   {
      factorMB = 1.0;
   }
   else if (unit.equal("gb"_ctv) || unit.equal("gib"_ctv))
   {
      factorMB = 1024.0;
   }
   else if (unit.equal("tb"_ctv) || unit.equal("tib"_ctv))
   {
      factorMB = 1024.0 * 1024.0;
   }
   else
   {
      return false;
   }

   double total = value * factorMB;
   if (total <= 0.0 || total > double(UINT32_MAX))
   {
      return false;
   }

   memoryMB = uint32_t(std::llround(total));
   return true;
}

static inline uint32_t mothershipParseNetworkPerformanceMbps(const String& performance)
{
   if (performance.size() == 0)
   {
      return 0;
   }

   String performanceText = {};
   performanceText.assign(performance);
   char *end = nullptr;
   double value = std::strtod(performanceText.c_str(), &end);
   if (end == performanceText.c_str() || std::isfinite(value) == false || value <= 0.0)
   {
      return 0;
   }

   String suffix = {};
   while (end && *end != '\0' && std::isspace(unsigned(*end)))
   {
      ++end;
   }
   if (end != nullptr && *end != '\0')
   {
      suffix.assign(end);
      for (uint64_t index = 0; index < suffix.size(); ++index)
      {
         suffix[index] = char(std::tolower(unsigned(suffix[index])));
      }
   }

   if (mothershipTextContains(suffix, "gigabit") || mothershipTextContains(suffix, "gbps"))
   {
      return uint32_t(std::llround(value * 1000.0));
   }

   if (mothershipTextContains(suffix, "megabit") || mothershipTextContains(suffix, "mbps"))
   {
      return uint32_t(std::llround(value));
   }

   return 0;
}

static inline bool mothershipJsonGetString(simdjson::dom::element object, const char *key, String& value)
{
   value.clear();
   std::string_view text = {};
   if (object[key].get(text) != simdjson::SUCCESS || text.size() == 0)
   {
      return false;
   }

   value.assign(text);
   return true;
}

static inline bool mothershipJsonGetUInt32StringOrNumber(simdjson::dom::element object, const char *key, uint32_t& value)
{
   value = 0;

   uint64_t unsignedValue = 0;
   if (object[key].get(unsignedValue) == simdjson::SUCCESS)
   {
      if (unsignedValue > UINT32_MAX)
      {
         return false;
      }

      value = uint32_t(unsignedValue);
      return true;
   }

   int64_t signedValue = 0;
   if (object[key].get(signedValue) == simdjson::SUCCESS)
   {
      if (signedValue < 0 || signedValue > INT32_MAX)
      {
         return false;
      }

      value = uint32_t(signedValue);
      return true;
   }

   String text = {};
   if (mothershipJsonGetString(object, key, text) == false)
   {
      return false;
   }

   String ownedText = {};
   ownedText.assign(text);
   char *end = nullptr;
   long long parsed = std::strtoll(ownedText.c_str(), &end, 10);
   if (end == ownedText.c_str() || parsed < 0 || parsed > INT32_MAX)
   {
      return false;
   }

   value = uint32_t(parsed);
   return true;
}

static inline bool mothershipJsonMoneyMicrousd(simdjson::dom::element money, uint64_t& microusd)
{
   microusd = 0;

   int64_t nanos = 0;
   (void)money["nanos"].get(nanos);

   int64_t signedUnits = 0;
   if (money["units"].get(signedUnits) == simdjson::SUCCESS)
   {
      if (signedUnits < 0)
      {
         return false;
      }

      microusd = uint64_t(signedUnits) * 1000000ull;
      microusd += uint64_t(std::llround(double(nanos) / 1000.0));
      return true;
   }

   std::string_view unitsText = {};
   if (money["units"].get(unitsText) == simdjson::SUCCESS)
   {
      String unitsOwned = {};
      unitsOwned.assign(unitsText);
      char *end = nullptr;
      long long parsedUnits = std::strtoll(unitsOwned.c_str(), &end, 10);
      if (end == unitsOwned.c_str() || parsedUnits < 0)
      {
         return false;
      }

      microusd = uint64_t(parsedUnits) * 1000000ull;
      microusd += uint64_t(std::llround(double(nanos) / 1000.0));
      return true;
   }

   return false;
}

static inline void mothershipOfferSelectionKey(const String& providerMachineType, MachineConfig::MachineKind kind, String& key)
{
   String kindName = {};
   kindName.assign(machineKindName(kind));
   key.snprintf<"{}#{}"_ctv>(providerMachineType, kindName);
}

static inline ProdigyEnvironmentKind mothershipEnvironmentKindFromProvider(MothershipClusterProvider provider)
{
   switch (provider)
   {
      case MothershipClusterProvider::aws:
      {
         return ProdigyEnvironmentKind::aws;
      }
      case MothershipClusterProvider::gcp:
      {
         return ProdigyEnvironmentKind::gcp;
      }
      case MothershipClusterProvider::azure:
      {
         return ProdigyEnvironmentKind::azure;
      }
      case MothershipClusterProvider::vultr:
      {
         return ProdigyEnvironmentKind::vultr;
      }
      case MothershipClusterProvider::unknown:
      {
         break;
      }
   }

   return ProdigyEnvironmentKind::unknown;
}

static inline void mothershipBridgeOfferForSurveyMatch(const MothershipProviderMachineOffer& offer, ProviderMachineOffer& bridged)
{
   bridged = {};
   bridged.provider = mothershipEnvironmentKindFromProvider(offer.provider);
   bridged.providerScope = offer.providerScope;
   bridged.country = offer.country;
   bridged.region = offer.region;
   bridged.zone = offer.zone;
   bridged.providerMachineType = offer.providerMachineType;
   bridged.lifetime = offer.billingModel == ProviderMachineBillingModel::spot ? MachineLifetime::spot : MachineLifetime::ondemand;
   bridged.kind = offer.kind;
   bridged.nLogicalCores = offer.nLogicalCores;
   bridged.nMemoryMB = offer.nMemoryMB;
   bridged.nStorageMB = offer.nStorageMBDefault;
   bridged.gpuCount = offer.gpuCount;
   bridged.gpuMemoryMBPerDevice = offer.gpuMemoryMBPerDevice;
   bridged.nicSpeedMbps = offer.nicSpeedMbps;
   bridged.providesHostPublic4 = offer.providesHostPublic4;
   bridged.providesHostPublic6 = offer.providesHostPublic6;
   bridged.hasInternetAccess = true;
   bridged.freeTierEligible = offer.freeTierEligible;
   bridged.hourlyUSD = mothershipMicrousdToUSD(offer.hourlyMicrousd);
}

static inline bool mothershipOfferMatchesSurveyRequest(const MothershipProviderMachineOffer& offer, const MothershipProviderOfferSurveyRequest& request)
{
   ProviderMachineOffer bridged = {};
   mothershipBridgeOfferForSurveyMatch(offer, bridged);

   ProviderMachineOfferSurveyRequest bridgedRequest = {};
   bridgedRequest.country = request.country;
   bridgedRequest.billingModel = request.billingModel;
   bridgedRequest.machineKindsMask = request.machineKindsMask;
   bridgedRequest.requireFreeTierEligible = request.requireFreeTierEligible;
   bridgedRequest.minLogicalCores = request.minLogicalCores;
   bridgedRequest.minMemoryMB = request.minMemoryMB;
   bridgedRequest.minStorageMB = request.minStorageMB;
   bridgedRequest.minGPUs = request.minGPUs;
   bridgedRequest.minGPUMemoryGB = request.minGPUMemoryGB;
   bridgedRequest.minNICSpeedGbps = request.minNICSpeedGbps;
   bridgedRequest.requireHostPublic4 = request.requireHostPublic4;
   bridgedRequest.requireHostPublic6 = request.requireHostPublic6;
   return providerMachineOfferMatchesSurveyRequest(bridged, bridgedRequest);
}

static inline bool mothershipLookupOfferByType(
   const Vector<MothershipProviderMachineOffer>& offers,
   const String& providerMachineType,
   MachineConfig::MachineKind kind,
   const MothershipProviderMachineOffer *& offer)
{
   offer = nullptr;
   for (const MothershipProviderMachineOffer& candidate : offers)
   {
      if (candidate.providerMachineType.equals(providerMachineType) && candidate.kind == kind)
      {
         offer = &candidate;
         return true;
      }
   }

   return false;
}

static inline Machine mothershipBuildSyntheticMachineFromOffer(
   const MothershipProviderMachineOffer& offer,
   uint32_t storageMB)
{
   Machine machine = {};
   machine.state = MachineState::healthy;
   machine.slug = offer.providerMachineType;
   machine.type = offer.providerMachineType;
   machine.region = offer.region;
   machine.zone = offer.zone;
   machine.publicAddress.clear();
   machine.privateAddress.clear();
   machine.hasInternetAccess = true;
   machine.totalLogicalCores = offer.nLogicalCores;
   machine.totalMemoryMB = offer.nMemoryMB;
   machine.totalStorageMB = storageMB > 0 ? storageMB : offer.nStorageMBDefault;
   if (providerMachineOfferResolveUsableResourcesFromTotals(
      machine.totalLogicalCores,
      machine.totalMemoryMB,
      machine.totalStorageMB,
      machine.ownedLogicalCores,
      machine.ownedMemoryMB,
      machine.ownedStorageMB) == false)
   {
      machine.ownedLogicalCores = 0;
      machine.ownedMemoryMB = 0;
      machine.ownedStorageMB = 0;
   }
   machine.memoryMB_available = int32_t(machine.ownedMemoryMB);
   machine.storageMB_available = int32_t(machine.ownedStorageMB);
   machine.nLogicalCores_available = int32_t(machine.ownedLogicalCores);

   machine.hardware.network.nics.clear();
   MachineNicHardwareProfile nic = {};
   nic.name = "eth0"_ctv;
   nic.linkSpeedMbps = offer.nicSpeedMbps;
   nic.up = true;
   machine.hardware.network.nics.push_back(nic);

   machine.hardware.gpus.clear();
   for (uint32_t index = 0; index < offer.gpuCount; ++index)
   {
      MachineGpuHardwareProfile gpu = {};
      gpu.vendor = "provider"_ctv;
      gpu.model = offer.providerMachineType;
      gpu.busAddress.snprintf<"virtual-gpu-{itoa}"_ctv>(index);
      gpu.memoryMB = offer.gpuMemoryMBPerDevice;
      machine.hardware.gpus.push_back(gpu);
   }

   machine.resetAvailableGPUMemoryMBsFromHardware();
   prodigyRecomputeMachineCPUAvailability(&machine, prodigySharedCPUOvercommitMinPermille);
   machine.memoryMB_available = int32_t(machine.ownedMemoryMB);
   machine.storageMB_available = int32_t(machine.ownedStorageMB);
   return machine;
}

static inline bool mothershipMachineSelectionLess(
   const MothershipMachineOfferSelection& lhs,
   const MothershipMachineOfferSelection& rhs)
{
   if (lhs.kind != rhs.kind)
   {
      return uint8_t(lhs.kind) < uint8_t(rhs.kind);
   }

   if (lhs.providerMachineType.equals(rhs.providerMachineType) == false)
   {
      return std::lexicographical_compare(lhs.providerMachineType.data(), lhs.providerMachineType.data() + lhs.providerMachineType.size(),
         rhs.providerMachineType.data(), rhs.providerMachineType.data() + rhs.providerMachineType.size());
   }

   if (lhs.storageMB != rhs.storageMB)
   {
      return lhs.storageMB < rhs.storageMB;
   }

   return lhs.count < rhs.count;
}

static inline void mothershipAppendMachineSelection(
   Vector<MothershipMachineOfferSelection>& selections,
   const MothershipProviderMachineOffer& offer,
   uint32_t count)
{
   if (count == 0)
   {
      return;
   }

   MothershipMachineOfferSelection selection = {};
   selection.providerMachineType = offer.providerMachineType;
   selection.kind = offer.kind;
   selection.count = count;
   selection.storageMB = 0;
   selections.push_back(selection);
}

static inline void mothershipNormalizeMachineSelections(Vector<MothershipMachineOfferSelection>& selections)
{
   std::sort(selections.begin(), selections.end(), mothershipMachineSelectionLess);

   Vector<MothershipMachineOfferSelection> normalized = {};
   normalized.reserve(selections.size());
   for (const MothershipMachineOfferSelection& selection : selections)
   {
      if (selection.count == 0)
      {
         continue;
      }

      if (normalized.empty() == false)
      {
         MothershipMachineOfferSelection& tail = normalized.back();
         if (tail.kind == selection.kind
            && tail.providerMachineType == selection.providerMachineType
            && tail.storageMB == selection.storageMB)
         {
            tail.count += selection.count;
            continue;
         }
      }

      normalized.push_back(selection);
   }

   selections = std::move(normalized);
}

static inline uint32_t mothershipCountSelectedMachines(const Vector<MothershipMachineOfferSelection>& selections)
{
   uint32_t total = 0;
   for (const MothershipMachineOfferSelection& selection : selections)
   {
      total += selection.count;
   }
   return total;
}

static inline bool mothershipMachineSelectionsLess(
   const Vector<MothershipMachineOfferSelection>& lhs,
   const Vector<MothershipMachineOfferSelection>& rhs)
{
   if (lhs.size() != rhs.size())
   {
      return lhs.size() < rhs.size();
   }

   for (uint32_t index = 0; index < lhs.size() && index < rhs.size(); ++index)
   {
      if (mothershipMachineSelectionLess(lhs[index], rhs[index]))
      {
         return true;
      }

      if (mothershipMachineSelectionLess(rhs[index], lhs[index]))
      {
         return false;
      }
   }

   return false;
}

static inline void mothershipBuildPlanningMachinesFromSelections(
   const Vector<MothershipMachineOfferSelection>& selections,
   const Vector<MothershipProviderMachineOffer>& offers,
   Vector<Machine>& machines,
   Vector<MothershipPlanningMachineMetadata> *metadata = nullptr,
   uint32_t elasticStorageFloorMB = 0)
{
   machines.clear();
   if (metadata)
   {
      metadata->clear();
   }

   for (const MothershipMachineOfferSelection& selection : selections)
   {
      const MothershipProviderMachineOffer *offer = nullptr;
      if (mothershipLookupOfferByType(offers, selection.providerMachineType, selection.kind, offer) == false || offer == nullptr)
      {
         continue;
      }

      for (uint32_t index = 0; index < selection.count; ++index)
      {
         uint32_t requestedStorageMB = selection.storageMB;
         if (requestedStorageMB == 0 && elasticStorageFloorMB > offer->nStorageMBDefault)
         {
            requestedStorageMB = elasticStorageFloorMB;
         }

         machines.push_back(mothershipBuildSyntheticMachineFromOffer(*offer, requestedStorageMB));

         if (metadata)
         {
            MothershipPlanningMachineMetadata item = {};
            item.providerMachineType = selection.providerMachineType;
            item.kind = selection.kind;
            item.defaultStorageMB = offer->nStorageMBDefault;
            metadata->push_back(std::move(item));
         }
      }
   }
}

static inline uint32_t mothershipPlanningElasticStorageFloorMB(const Vector<MothershipPlanningApplication>& applications)
{
   uint64_t requiredOwnedStorageMB = 0;
   for (const MothershipPlanningApplication& application : applications)
   {
      requiredOwnedStorageMB += uint64_t(application.instances) * uint64_t(application.config.totalStorageMB());
      if (requiredOwnedStorageMB > uint64_t(UINT32_MAX - prodigyMachineReservedResources.storageMB))
      {
         return UINT32_MAX;
      }
   }

   uint64_t totalStorageMB = requiredOwnedStorageMB + prodigyMachineReservedResources.storageMB;
   if (totalStorageMB > UINT32_MAX)
   {
      return UINT32_MAX;
   }

   return uint32_t(totalStorageMB);
}

static inline void mothershipSelectionsFromPlacedMachines(
   const Vector<Machine>& machines,
   const Vector<MothershipPlanningMachineMetadata>& metadata,
   Vector<MothershipMachineOfferSelection>& selections)
{
   selections.clear();
   if (machines.size() != metadata.size())
   {
      return;
   }

   for (uint32_t index = 0; index < machines.size(); ++index)
   {
      const Machine& machine = machines[index];
      const MothershipPlanningMachineMetadata& source = metadata[index];

      uint32_t availableStorageMB = uint32_t(machine.storageMB_available > 0 ? machine.storageMB_available : 0);
      uint32_t usedOwnedStorageMB = machine.ownedStorageMB > availableStorageMB
         ? (machine.ownedStorageMB - availableStorageMB)
         : 0u;
      uint64_t requiredStorageMB = uint64_t(prodigyMachineReservedResources.storageMB) + uint64_t(usedOwnedStorageMB);
      if (requiredStorageMB < source.defaultStorageMB)
      {
         requiredStorageMB = source.defaultStorageMB;
      }
      if (requiredStorageMB > UINT32_MAX)
      {
         requiredStorageMB = UINT32_MAX;
      }

      MothershipMachineOfferSelection selection = {};
      selection.providerMachineType = source.providerMachineType;
      selection.kind = source.kind;
      selection.count = 1;
      selection.storageMB = uint32_t(requiredStorageMB);
      selections.push_back(std::move(selection));
   }

   mothershipNormalizeMachineSelections(selections);
}

static inline bool mothershipComputeClusterCostBreakdown(
   const Vector<MothershipMachineOfferSelection>& selections,
   const Vector<MothershipProviderMachineOffer>& offers,
   uint64_t ingressMBPerHour,
   uint64_t egressMBPerHour,
   MothershipClusterCostBreakdown& breakdown,
   String *failure = nullptr)
{
   breakdown = {};
   if (failure) failure->clear();

   bool haveSelectedOffers = false;
   bool allSelectedOffersComplete = true;
   uint64_t ingressMicrousdPerGB = 0;
   uint64_t egressMicrousdPerGB = 0;

   for (const MothershipMachineOfferSelection& selection : selections)
   {
      const MothershipProviderMachineOffer *offer = nullptr;
      if (mothershipLookupOfferByType(offers, selection.providerMachineType, selection.kind, offer) == false || offer == nullptr)
      {
         if (failure) failure->snprintf<"offer '{}:{}' not found in surveyed provider scope"_ctv>(String(machineKindName(selection.kind)), selection.providerMachineType);
         return false;
      }

      haveSelectedOffers = true;
      breakdown.computeHourlyMicrousd += uint64_t(selection.count) * offer->hourlyMicrousd;

      uint64_t selectionStorageMicrousd = mothershipOfferExtraStorageHourlyMicrousd(*offer, selection.storageMB);
      if (selectionStorageMicrousd == 0
         && selection.storageMB > offer->nStorageMBDefault
         && offer->priceCompleteness != MothershipProviderOfferPriceCompleteness::computeStorageNetwork)
      {
         if (failure) failure->snprintf<"offer '{}:{}' missing extra storage pricing"_ctv>(String(machineKindName(selection.kind)), selection.providerMachineType);
         return false;
      }
      breakdown.storageHourlyMicrousd += uint64_t(selection.count) * selectionStorageMicrousd;

      if (offer->priceCompleteness != MothershipProviderOfferPriceCompleteness::computeStorageNetwork)
      {
         allSelectedOffersComplete = false;
      }

      if (offer->ingressMicrousdPerGB > ingressMicrousdPerGB)
      {
         ingressMicrousdPerGB = offer->ingressMicrousdPerGB;
      }

      if (offer->egressMicrousdPerGB > egressMicrousdPerGB)
      {
         egressMicrousdPerGB = offer->egressMicrousdPerGB;
      }
   }

   if (haveSelectedOffers == false)
   {
      if (failure) failure->assign("no machine selections provided"_ctv);
      return false;
   }

   if (allSelectedOffersComplete == false && (ingressMBPerHour > 0 || egressMBPerHour > 0))
   {
      if (failure) failure->assign("selected offers are missing network pricing"_ctv);
      return false;
   }

   breakdown.ingressHourlyMicrousd = mothershipScaleMicrousdPerGBByMB(ingressMicrousdPerGB, ingressMBPerHour);
   breakdown.egressHourlyMicrousd = mothershipScaleMicrousdPerGBByMB(egressMicrousdPerGB, egressMBPerHour);
   return true;
}

static inline bool mothershipPlaceOnePlanningInstance(Machine& machine, const ApplicationConfig& config)
{
   if (prodigyMachineMeetsApplicationResourceCriteria(&machine, config) == false)
   {
      return false;
   }

   uint64_t availableCores = uint64_t(machine.nLogicalCores_available > 0 ? machine.nLogicalCores_available : 0);
   uint64_t availableSharedCPU = uint64_t(machine.sharedCPUMillis_available > 0 ? machine.sharedCPUMillis_available : 0);
   uint64_t availableMemory = uint64_t(machine.memoryMB_available > 0 ? machine.memoryMB_available : 0);
   uint64_t availableStorage = uint64_t(machine.storageMB_available > 0 ? machine.storageMB_available : 0);

   auto countFitOntoResources = [&] () -> uint32_t {
      uint64_t capacityPerCores = 0;
      if (applicationUsesSharedCPUs(config))
      {
         uint64_t requestedSharedCPU = applicationRequestedCPUMillis(config);
         capacityPerCores = (requestedSharedCPU ? (availableSharedCPU / requestedSharedCPU) : 0);
      }
      else
      {
         capacityPerCores = (config.nLogicalCores ? (availableCores / config.nLogicalCores) : 0);
      }

      uint64_t capacityPerMemory = (config.totalMemoryMB() ? (availableMemory / config.totalMemoryMB()) : 0);
      uint64_t capacityPerStorage = (config.totalStorageMB() ? (availableStorage / config.totalStorageMB()) : 0);
      uint64_t canScheduleN = 1;

      if (capacityPerCores < canScheduleN) canScheduleN = capacityPerCores;
      if (capacityPerMemory < canScheduleN) canScheduleN = capacityPerMemory;
      if (capacityPerStorage < canScheduleN) canScheduleN = capacityPerStorage;

      uint32_t requiredGPUs = applicationRequiredWholeGPUs(config);
      if (requiredGPUs > 0 && canScheduleN > 0)
      {
         Vector<uint32_t> scratchGPUMemoryMBs = machine.availableGPUMemoryMBs;
         Vector<uint32_t> assignedGPUMemoryMBs = {};
         uint64_t capacityPerGPUs = 0;

         while (capacityPerGPUs < canScheduleN
            && prodigyAllocateWholeGPUSlots(
               scratchGPUMemoryMBs,
               nullptr,
               nullptr,
               requiredGPUs,
               applicationRequiredGPUMemoryMB(config),
               assignedGPUMemoryMBs))
         {
            capacityPerGPUs += 1;
         }

         if (capacityPerGPUs < canScheduleN)
         {
            canScheduleN = capacityPerGPUs;
         }
      }

      return uint32_t(canScheduleN);
   };

   if (countFitOntoResources() == 0)
   {
      return false;
   }

   Vector<uint32_t> assignedGPUMemoryMBs = {};
   Vector<AssignedGPUDevice> assignedGPUDevices = {};
   if (prodigyReserveMachineGPUsForInstance(&machine, config, assignedGPUMemoryMBs, &assignedGPUDevices) == false)
   {
      return false;
   }

   prodigyDebitMachineScalarResources(&machine, config, 1);
   return true;
}

static inline bool mothershipMachineHasExistingPlacements(const Machine& machine)
{
   if (machine.ownedLogicalCores != uint32_t(machine.nLogicalCores_available > 0 ? machine.nLogicalCores_available : 0))
   {
      return true;
   }

   if (machine.ownedMemoryMB != uint32_t(machine.memoryMB_available > 0 ? machine.memoryMB_available : 0))
   {
      return true;
   }

   if (machine.ownedStorageMB != uint32_t(machine.storageMB_available > 0 ? machine.storageMB_available : 0))
   {
      return true;
   }

   if (machine.sharedCPUMillisCommitted > 0 || machine.isolatedLogicalCoresCommitted > 0)
   {
      return true;
   }

   return machine.availableGPUCount() != machine.hardware.gpus.size();
}

static inline uint64_t mothershipPlacementSlackScore(const Machine& machine, const ApplicationConfig& config)
{
   uint64_t cpuSlack = applicationUsesSharedCPUs(config)
      ? uint64_t(machine.sharedCPUMillis_available > 0 ? machine.sharedCPUMillis_available : 0)
      : uint64_t(machine.nLogicalCores_available > 0 ? machine.nLogicalCores_available : 0) * prodigyCPUUnitsPerCore;

   uint64_t memorySlack = uint64_t(machine.memoryMB_available > 0 ? machine.memoryMB_available : 0);
   uint64_t storageSlack = uint64_t(machine.storageMB_available > 0 ? machine.storageMB_available : 0);
   uint64_t gpuSlack = uint64_t(machine.availableGPUCount());

   return (gpuSlack << 56)
      | ((cpuSlack > 0xffffffffull ? 0xffffffffull : cpuSlack) << 24)
      | ((memorySlack > 0xfffffull ? 0xfffffull : memorySlack) << 4)
      | (storageSlack > 0x0full ? 0x0full : storageSlack);
}

static inline bool mothershipSimulatePlanningPlacement(
   const Vector<MothershipPlanningApplication>& applications,
   Vector<Machine>& machines,
   String *failure = nullptr)
{
   if (failure) failure->clear();

   Vector<uint32_t> order = {};
   order.reserve(applications.size());
   for (uint32_t index = 0; index < applications.size(); ++index)
   {
      order.push_back(index);
   }

   std::sort(order.begin(), order.end(), [&] (uint32_t lhs, uint32_t rhs) -> bool {
      const ApplicationConfig& a = applications[lhs].config;
      const ApplicationConfig& b = applications[rhs].config;
      if (applicationRequiredWholeGPUs(a) != applicationRequiredWholeGPUs(b))
      {
         return applicationRequiredWholeGPUs(a) > applicationRequiredWholeGPUs(b);
      }

      if (applicationRequiredGPUMemoryMB(a) != applicationRequiredGPUMemoryMB(b))
      {
         return applicationRequiredGPUMemoryMB(a) > applicationRequiredGPUMemoryMB(b);
      }

      if (applicationRequestedCPUMillis(a) != applicationRequestedCPUMillis(b))
      {
         return applicationRequestedCPUMillis(a) > applicationRequestedCPUMillis(b);
      }

      if (a.totalMemoryMB() != b.totalMemoryMB())
      {
         return a.totalMemoryMB() > b.totalMemoryMB();
      }

      return a.totalStorageMB() > b.totalStorageMB();
   });

   for (uint32_t applicationIndex : order)
   {
      const MothershipPlanningApplication& application = applications[applicationIndex];
      for (uint32_t instance = 0; instance < application.instances; ++instance)
      {
         int32_t bestMachineIndex = -1;
         bool bestUsed = false;
         uint64_t bestSlack = std::numeric_limits<uint64_t>::max();

         for (uint32_t machineIndex = 0; machineIndex < machines.size(); ++machineIndex)
         {
            Machine candidate = machines[machineIndex];
            if (mothershipPlaceOnePlanningInstance(candidate, application.config) == false)
            {
               continue;
            }

            bool used = mothershipMachineHasExistingPlacements(machines[machineIndex]);
            uint64_t slack = mothershipPlacementSlackScore(candidate, application.config);
            if (bestMachineIndex < 0
               || (used && !bestUsed)
               || (used == bestUsed && slack < bestSlack))
            {
               bestMachineIndex = int32_t(machineIndex);
               bestUsed = used;
               bestSlack = slack;
            }
         }

         if (bestMachineIndex < 0)
         {
            if (failure)
            {
               failure->snprintf<"unable to place application '{}' instance {itoa}"_ctv>(
                  application.name.size() > 0 ? application.name : "unnamed"_ctv,
                  instance + 1);
            }
            return false;
         }

         (void)mothershipPlaceOnePlanningInstance(machines[uint32_t(bestMachineIndex)], application.config);
      }
   }

   return true;
}

static inline uint64_t mothershipOfferRepresentativeExtraStorageMicrousdPerGBHour(const MothershipProviderMachineOffer& offer)
{
   if (offer.extraStorageMicrousdPerGBHour > 0)
   {
      return offer.extraStorageMicrousdPerGBHour;
   }

   if (offer.storageTiers.empty())
   {
      return 0;
   }

   const uint32_t defaultGB = std::max(1u, mothershipCeilMBToGB(offer.nStorageMBDefault));
   const MothershipStoragePricingTier *defaultTier = mothershipFindStorageTierForGB(offer.storageTiers, defaultGB);
   if (defaultTier == nullptr)
   {
      return 0;
   }

   const MothershipStoragePricingTier *nextTier = nullptr;
   for (const MothershipStoragePricingTier& tier : offer.storageTiers)
   {
      if (tier.capacityGB <= defaultTier->capacityGB || tier.hourlyMicrousd <= defaultTier->hourlyMicrousd)
      {
         continue;
      }

      if (nextTier == nullptr || tier.capacityGB < nextTier->capacityGB)
      {
         nextTier = &tier;
      }
   }

   if (nextTier == nullptr || nextTier->capacityGB <= defaultTier->capacityGB)
   {
      return 0;
   }

   return uint64_t(std::llround(
      double(nextTier->hourlyMicrousd - defaultTier->hourlyMicrousd)
      / double(nextTier->capacityGB - defaultTier->capacityGB)));
}

static inline bool mothershipOfferDominates(const MothershipProviderMachineOffer& lhs, const MothershipProviderMachineOffer& rhs)
{
   if (lhs.provider != rhs.provider || lhs.providerScope.equals(rhs.providerScope) == false)
   {
      return false;
   }

   const uint64_t lhsStorageRate = mothershipOfferRepresentativeExtraStorageMicrousdPerGBHour(lhs);
   const uint64_t rhsStorageRate = mothershipOfferRepresentativeExtraStorageMicrousdPerGBHour(rhs);

   bool noWorse =
      lhs.hourlyMicrousd <= rhs.hourlyMicrousd
      && lhs.nLogicalCores >= rhs.nLogicalCores
      && lhs.nMemoryMB >= rhs.nMemoryMB
      && lhs.nStorageMBDefault >= rhs.nStorageMBDefault
      && lhs.gpuCount >= rhs.gpuCount
      && lhs.gpuMemoryMBPerDevice >= rhs.gpuMemoryMBPerDevice
      && lhs.nicSpeedMbps >= rhs.nicSpeedMbps
      && lhsStorageRate <= rhsStorageRate
      && lhs.ingressMicrousdPerGB <= rhs.ingressMicrousdPerGB
      && lhs.egressMicrousdPerGB <= rhs.egressMicrousdPerGB
      && lhs.providesHostPublic4 >= rhs.providesHostPublic4
      && lhs.providesHostPublic6 >= rhs.providesHostPublic6;

   if (noWorse == false)
   {
      return false;
   }

   return lhs.hourlyMicrousd < rhs.hourlyMicrousd
      || lhs.nLogicalCores > rhs.nLogicalCores
      || lhs.nMemoryMB > rhs.nMemoryMB
      || lhs.nStorageMBDefault > rhs.nStorageMBDefault
      || lhs.gpuCount > rhs.gpuCount
      || lhs.gpuMemoryMBPerDevice > rhs.gpuMemoryMBPerDevice
      || lhs.nicSpeedMbps > rhs.nicSpeedMbps
      || lhsStorageRate < rhsStorageRate
      || lhs.ingressMicrousdPerGB < rhs.ingressMicrousdPerGB
      || lhs.egressMicrousdPerGB < rhs.egressMicrousdPerGB
      || lhs.providesHostPublic4 != rhs.providesHostPublic4
      || lhs.providesHostPublic6 != rhs.providesHostPublic6;
}

static inline void mothershipPruneDominatedOffers(Vector<MothershipProviderMachineOffer>& offers)
{
   Vector<MothershipProviderMachineOffer> pruned = {};
   for (uint32_t index = 0; index < offers.size(); ++index)
   {
      bool dominated = false;
      for (uint32_t other = 0; other < offers.size(); ++other)
      {
         if (index == other)
         {
            continue;
         }

         if (mothershipOfferDominates(offers[other], offers[index]))
         {
            dominated = true;
            break;
         }
      }

      if (dominated == false)
      {
         pruned.push_back(offers[index]);
      }
   }

   std::sort(pruned.begin(), pruned.end(), [] (const MothershipProviderMachineOffer& a, const MothershipProviderMachineOffer& b) -> bool {
      if (a.hourlyMicrousd != b.hourlyMicrousd)
      {
         return a.hourlyMicrousd < b.hourlyMicrousd;
      }

      if (a.nLogicalCores != b.nLogicalCores)
      {
         return a.nLogicalCores < b.nLogicalCores;
      }

      if (a.nMemoryMB != b.nMemoryMB)
      {
         return a.nMemoryMB < b.nMemoryMB;
      }

      return mothershipStringLess(a.providerMachineType, b.providerMachineType);
   });

   offers = std::move(pruned);
}

static inline bool mothershipExtractAwsBestUnitPriceMicrousd(
   simdjson::dom::element entry,
   const char *requiredUnitNeedle,
   uint64_t& priceMicrousd)
{
   priceMicrousd = 0;

   auto terms = entry["terms"]["OnDemand"];
   if (terms.is_object() == false)
   {
      return false;
   }

   for (auto term : terms.get_object())
   {
      auto priceDimensions = term.value["priceDimensions"];
      if (priceDimensions.is_object() == false)
      {
         continue;
      }

      for (auto dimension : priceDimensions.get_object())
      {
         String unit = {};
         if (mothershipJsonGetString(dimension.value, "unit", unit) == false)
         {
            continue;
         }

         mothershipUppercaseInPlace(unit);
         if (requiredUnitNeedle != nullptr && requiredUnitNeedle[0] != '\0' && mothershipTextContains(unit, requiredUnitNeedle) == false)
         {
            continue;
         }

         String usd = {};
         if (mothershipJsonGetString(dimension.value["pricePerUnit"], "USD", usd) == false)
         {
            continue;
         }

         uint64_t candidateMicrousd = 0;
         if (mothershipParseDecimalPriceMicrousd(usd, candidateMicrousd) == false || candidateMicrousd == 0)
         {
            continue;
         }

         if (priceMicrousd == 0 || candidateMicrousd < priceMicrousd)
         {
            priceMicrousd = candidateMicrousd;
         }
      }
   }

   return priceMicrousd > 0;
}

static inline bool mothershipSurveyAwsGp3StorageMicrousdPerGBHour(
   const String& region,
   const AwsCredentialMaterial& credential,
   uint64_t& perGBHourMicrousd,
   String& failure)
{
   perGBHourMicrousd = 0;
   failure.clear();

   String body = {};
   awsBuildPricingGetProductsRequestBody(
      "AmazonEC2"_ctv,
      {
         {"regionCode"_ctv, region},
         {"volumeApiName"_ctv, "gp3"_ctv},
      },
      body);

   String response = {};
   long httpCode = 0;
   bool ok = awsSendPricingGetProductsRequest(credential, body, response, failure, &httpCode);
   if (ok == false || httpCode < 200 || httpCode >= 300)
   {
      failure.assign("aws pricing gp3 storage query failed"_ctv);
      return false;
   }

   simdjson::dom::parser parser;
   simdjson::dom::element doc;
   if (parser.parse(response.c_str(), response.size()).get(doc))
   {
      failure.assign("aws pricing gp3 storage response parse failed"_ctv);
      return false;
   }

   auto priceList = doc["PriceList"];
   if (priceList.is_array() == false)
   {
      failure.assign("aws pricing gp3 storage response missing PriceList"_ctv);
      return false;
   }

   uint64_t monthlyMicrousd = 0;
   for (auto encodedEntry : priceList.get_array())
   {
      std::string_view encoded = {};
      if (encodedEntry.get(encoded) != simdjson::SUCCESS || encoded.size() == 0)
      {
         continue;
      }

      String entryText = {};
      entryText.assign(encoded);
      simdjson::dom::parser entryParser;
      simdjson::dom::element entry;
      if (entryParser.parse(entryText.c_str(), entryText.size()).get(entry))
      {
         continue;
      }

      simdjson::dom::element attributes = entry["product"]["attributes"];
      if (attributes.is_object() == false)
      {
         continue;
      }

      String volumeApiName = {};
      if (mothershipJsonGetString(attributes, "volumeApiName", volumeApiName) == false || volumeApiName.equal("gp3"_ctv) == false)
      {
         continue;
      }

      uint64_t candidateMonthlyMicrousd = 0;
      if (mothershipExtractAwsBestUnitPriceMicrousd(entry, "GB", candidateMonthlyMicrousd) == false)
      {
         continue;
      }

      if (monthlyMicrousd == 0 || candidateMonthlyMicrousd < monthlyMicrousd)
      {
         monthlyMicrousd = candidateMonthlyMicrousd;
      }
   }

   if (monthlyMicrousd == 0)
   {
      failure.assign("aws pricing gp3 storage price missing"_ctv);
      return false;
   }

   perGBHourMicrousd = mothershipPriceMicrousdPerGBHourFromMonthlyRate(monthlyMicrousd);
   return perGBHourMicrousd > 0;
}

static inline bool mothershipSurveyAwsInternetTransferMicrousdPerGB(
   const String& region,
   const AwsCredentialMaterial& credential,
   uint64_t& ingressMicrousdPerGB,
   uint64_t& egressMicrousdPerGB,
   String& failure)
{
   ingressMicrousdPerGB = 0;
   egressMicrousdPerGB = 0;
   failure.clear();

   String body = {};
   awsBuildPricingGetProductsRequestBody(
      "AWSDataTransfer"_ctv,
      {
         {"fromRegionCode"_ctv, region},
         {"fromLocationType"_ctv, "AWS Region"_ctv},
         {"toLocation"_ctv, "External"_ctv},
         {"transferType"_ctv, "AWS Outbound"_ctv},
      },
      body);

   String response = {};
   long httpCode = 0;
   bool ok = awsSendPricingGetProductsRequest(credential, body, response, failure, &httpCode);
   if (ok == false || httpCode < 200 || httpCode >= 300)
   {
      failure.assign("aws pricing transfer query failed"_ctv);
      return false;
   }

   simdjson::dom::parser parser;
   simdjson::dom::element doc;
   if (parser.parse(response.c_str(), response.size()).get(doc))
   {
      failure.assign("aws pricing transfer response parse failed"_ctv);
      return false;
   }

   auto priceList = doc["PriceList"];
   if (priceList.is_array() == false)
   {
      failure.assign("aws pricing transfer response missing PriceList"_ctv);
      return false;
   }

   for (auto encodedEntry : priceList.get_array())
   {
      std::string_view encoded = {};
      if (encodedEntry.get(encoded) != simdjson::SUCCESS || encoded.size() == 0)
      {
         continue;
      }

      String entryText = {};
      entryText.assign(encoded);
      simdjson::dom::parser entryParser;
      simdjson::dom::element entry;
      if (entryParser.parse(entryText.c_str(), entryText.size()).get(entry))
      {
         continue;
      }

      simdjson::dom::element attributes = entry["product"]["attributes"];
      if (attributes.is_object() == false)
      {
         continue;
      }

      String transferType = {};
      if (mothershipJsonGetString(attributes, "transferType", transferType) == false || transferType.equal("AWS Outbound"_ctv) == false)
      {
         continue;
      }

      uint64_t candidateMicrousd = 0;
      if (mothershipExtractAwsBestUnitPriceMicrousd(entry, "GB", candidateMicrousd) == false || candidateMicrousd == 0)
      {
         continue;
      }

      if (candidateMicrousd > egressMicrousdPerGB)
      {
         egressMicrousdPerGB = candidateMicrousd;
      }
   }

   if (egressMicrousdPerGB == 0)
   {
      failure.assign("aws pricing transfer price missing"_ctv);
      return false;
   }

   return true;
}

static inline bool mothershipGcpSkuMaxNonZeroUnitPriceMicrousd(simdjson::dom::element sku, uint64_t& priceMicrousd)
{
   priceMicrousd = 0;
   auto pricingInfo = sku["pricingInfo"];
   if (pricingInfo.is_array() == false)
   {
      return false;
   }

   for (auto info : pricingInfo.get_array())
   {
      auto tieredRates = info["pricingExpression"]["tieredRates"];
      if (tieredRates.is_array() == false)
      {
         continue;
      }

      for (auto rate : tieredRates.get_array())
      {
         uint64_t candidateMicrousd = 0;
         if (mothershipJsonMoneyMicrousd(rate["unitPrice"], candidateMicrousd) == false || candidateMicrousd == 0)
         {
            continue;
         }

         if (candidateMicrousd > priceMicrousd)
         {
            priceMicrousd = candidateMicrousd;
         }
      }
   }

   return priceMicrousd > 0;
}

static inline bool mothershipGcpSkuMaxNonZeroUnitPriceMicrousdPerGBHour(simdjson::dom::element sku, uint64_t& priceMicrousdPerGBHour)
{
   priceMicrousdPerGBHour = 0;

   auto pricingInfo = sku["pricingInfo"];
   if (pricingInfo.is_array() == false)
   {
      return false;
   }

   bool sawMonthlyUnit = false;
   for (auto info : pricingInfo.get_array())
   {
      simdjson::dom::element pricingExpression = {};
      if (info["pricingExpression"].get(pricingExpression) != simdjson::SUCCESS)
      {
         continue;
      }

      String usageUnitDescription = {};
      (void)mothershipJsonGetString(pricingExpression, "usageUnitDescription", usageUnitDescription);
      if (usageUnitDescription.size() == 0)
      {
         (void)mothershipJsonGetString(pricingExpression, "usageUnit", usageUnitDescription);
      }
      mothershipUppercaseInPlace(usageUnitDescription);
      if (mothershipTextContains(usageUnitDescription, "MONTH") || mothershipTextContains(usageUnitDescription, ".MO"))
      {
         sawMonthlyUnit = true;
      }

      auto tieredRates = pricingExpression["tieredRates"];
      if (tieredRates.is_array() == false)
      {
         continue;
      }

      for (auto rate : tieredRates.get_array())
      {
         uint64_t candidateMicrousd = 0;
         if (mothershipJsonMoneyMicrousd(rate["unitPrice"], candidateMicrousd) == false || candidateMicrousd == 0)
         {
            continue;
         }

         if (candidateMicrousd > priceMicrousdPerGBHour)
         {
            priceMicrousdPerGBHour = candidateMicrousd;
         }
      }
   }

   if (priceMicrousdPerGBHour == 0)
   {
      return false;
   }

   if (sawMonthlyUnit)
   {
      priceMicrousdPerGBHour = mothershipPriceMicrousdPerGBHourFromMonthlyRate(priceMicrousdPerGBHour);
   }

   return true;
}

static inline uint64_t mothershipGcpPriceMicrousdPerGBHour(simdjson::dom::element pricingExpression, uint64_t unitMicrousd)
{
   String usageUnitDescription = {};
   (void)mothershipJsonGetString(pricingExpression, "usageUnitDescription", usageUnitDescription);
   if (usageUnitDescription.size() == 0)
   {
      (void)mothershipJsonGetString(pricingExpression, "usageUnit", usageUnitDescription);
   }

   mothershipUppercaseInPlace(usageUnitDescription);
   if (mothershipTextContains(usageUnitDescription, "MONTH") || mothershipTextContains(usageUnitDescription, ".MO"))
   {
      return mothershipPriceMicrousdPerGBHourFromMonthlyRate(unitMicrousd);
   }

   return unitMicrousd;
}

static inline bool mothershipAzureStandardSSDTierCapacityGB(const String& meterName, uint32_t& capacityGB)
{
   capacityGB = 0;

   String upper = {};
   upper.assign(meterName);
   mothershipUppercaseInPlace(upper);

   if (upper.size() < 2 || upper[0] != 'E')
   {
      return false;
   }

   uint32_t tier = 0;
   uint64_t index = 1;
   while (index < upper.size() && std::isdigit(unsigned(upper[index])))
   {
      tier = (tier * 10u) + uint32_t(upper[index] - '0');
      ++index;
   }

   switch (tier)
   {
      case 1: capacityGB = 4; return true;
      case 2: capacityGB = 8; return true;
      case 3: capacityGB = 16; return true;
      case 4: capacityGB = 32; return true;
      case 6: capacityGB = 64; return true;
      case 10: capacityGB = 128; return true;
      case 15: capacityGB = 256; return true;
      case 20: capacityGB = 512; return true;
      case 30: capacityGB = 1024; return true;
      case 40: capacityGB = 2048; return true;
      case 50: capacityGB = 4096; return true;
      case 60: capacityGB = 8192; return true;
      case 70: capacityGB = 16384; return true;
      case 80: capacityGB = 32767; return true;
      default: break;
   }

   return false;
}

static inline bool mothershipSurveyAzureStorageTiers(
   const String& location,
   Vector<MothershipStoragePricingTier>& tiers,
   String& failure)
{
   tiers.clear();
   failure.clear();

   String filter = {};
   filter.assign("$filter=serviceName eq 'Storage' and armRegionName eq '"_ctv);
   filter.append(location);
   filter.append("'"_ctv);
   String retailUrl = {};
   retailUrl.assign("https://prices.azure.com/api/retail/prices?"_ctv);
   azureAppendPercentEncoded(retailUrl, filter);

   Vector<String> responses = {};
   simdjson::dom::parser parser;
   String nextPage = retailUrl;
   while (nextPage.size() > 0)
   {
      String response = {};
      if (AzureHttp::send("GET", nextPage, nullptr, nullptr, response) == false)
      {
         failure.assign("azure storage prices request failed"_ctv);
         return false;
      }

      responses.push_back(response);
      simdjson::dom::element doc;
      if (parser.parse(responses.back().c_str(), responses.back().size()).get(doc))
      {
         failure.assign("azure storage prices response parse failed"_ctv);
         return false;
      }

      if (doc["Items"].is_array())
      {
         for (auto item : doc["Items"].get_array())
         {
            String productName = {};
            if (mothershipJsonGetString(item, "productName", productName) == false || productName.equal("Standard SSD Managed Disks"_ctv) == false)
            {
               continue;
            }

            String meterName = {};
            if (mothershipJsonGetString(item, "meterName", meterName) == false)
            {
               continue;
            }

            String upperMeter = {};
            upperMeter.assign(meterName);
            mothershipUppercaseInPlace(upperMeter);
            if (mothershipTextContains(upperMeter, "LRS DISK MOUNT") == false)
            {
               continue;
            }

            String unitOfMeasure = {};
            if (mothershipJsonGetString(item, "unitOfMeasure", unitOfMeasure) == false || unitOfMeasure.equal("1/Month"_ctv) == false)
            {
               continue;
            }

            double retailPrice = 0.0;
            if (item["retailPrice"].get(retailPrice) != simdjson::SUCCESS)
            {
               continue;
            }

            uint64_t monthlyMicrousd = 0;
            if (mothershipParseDoubleMicrousd(retailPrice, monthlyMicrousd) == false || monthlyMicrousd == 0)
            {
               continue;
            }

            uint32_t capacityGB = 0;
            if (mothershipAzureStandardSSDTierCapacityGB(meterName, capacityGB) == false || capacityGB == 0)
            {
               continue;
            }

            uint64_t hourlyMicrousd = mothershipPriceMicrousdPerGBHourFromMonthlyRate(monthlyMicrousd * uint64_t(capacityGB));

            bool merged = false;
            for (MothershipStoragePricingTier& tier : tiers)
            {
               if (tier.capacityGB != capacityGB)
               {
                  continue;
               }

               if (tier.hourlyMicrousd == 0 || hourlyMicrousd < tier.hourlyMicrousd)
               {
                  tier.hourlyMicrousd = hourlyMicrousd;
               }
               merged = true;
               break;
            }

            if (merged == false)
            {
               MothershipStoragePricingTier tier = {};
               tier.capacityGB = capacityGB;
               tier.hourlyMicrousd = hourlyMicrousd;
               tiers.push_back(tier);
            }
         }
      }

      nextPage.clear();
      (void)mothershipJsonGetString(doc, "NextPageLink", nextPage);
   }

   std::sort(tiers.begin(), tiers.end(), [] (const MothershipStoragePricingTier& lhs, const MothershipStoragePricingTier& rhs) -> bool {
      return lhs.capacityGB < rhs.capacityGB;
   });
   return tiers.empty() == false;
}

static inline bool mothershipSurveyAzureBandwidthPricing(
   const String& location,
   uint64_t& ingressMicrousdPerGB,
   uint64_t& egressMicrousdPerGB,
   String& failure)
{
   ingressMicrousdPerGB = 0;
   egressMicrousdPerGB = 0;
   failure.clear();

   String filter = {};
   filter.assign("$filter=serviceName eq 'Bandwidth' and armRegionName eq '"_ctv);
   filter.append(location);
   filter.append("'"_ctv);
   String retailUrl = {};
   retailUrl.assign("https://prices.azure.com/api/retail/prices?"_ctv);
   azureAppendPercentEncoded(retailUrl, filter);

   Vector<String> responses = {};
   simdjson::dom::parser parser;
   String nextPage = retailUrl;
   while (nextPage.size() > 0)
   {
      String response = {};
      if (AzureHttp::send("GET", nextPage, nullptr, nullptr, response) == false)
      {
         failure.assign("azure bandwidth prices request failed"_ctv);
         return false;
      }

      responses.push_back(response);
      simdjson::dom::element doc;
      if (parser.parse(responses.back().c_str(), responses.back().size()).get(doc))
      {
         failure.assign("azure bandwidth prices response parse failed"_ctv);
         return false;
      }

      if (doc["Items"].is_array())
      {
         for (auto item : doc["Items"].get_array())
         {
            String productName = {};
            if (mothershipJsonGetString(item, "productName", productName) == false || productName.equal("Rtn Preference: MGN"_ctv) == false)
            {
               continue;
            }

            String unitOfMeasure = {};
            if (mothershipJsonGetString(item, "unitOfMeasure", unitOfMeasure) == false || unitOfMeasure.equal("1 GB"_ctv) == false)
            {
               continue;
            }

            String meterName = {};
            if (mothershipJsonGetString(item, "meterName", meterName) == false)
            {
               continue;
            }

            double retailPrice = 0.0;
            if (item["retailPrice"].get(retailPrice) != simdjson::SUCCESS)
            {
               continue;
            }

            uint64_t candidateMicrousd = 0;
            if (mothershipParseDoubleMicrousd(retailPrice, candidateMicrousd) == false)
            {
               continue;
            }

            if (meterName.equal("Standard Data Transfer In"_ctv))
            {
               if (ingressMicrousdPerGB == 0 || candidateMicrousd < ingressMicrousdPerGB)
               {
                  ingressMicrousdPerGB = candidateMicrousd;
               }
            }
            else if (meterName.equal("Standard Data Transfer Out"_ctv) && candidateMicrousd > egressMicrousdPerGB)
            {
               egressMicrousdPerGB = candidateMicrousd;
            }
         }
      }

      nextPage.clear();
      (void)mothershipJsonGetString(doc, "NextPageLink", nextPage);
   }

   if (egressMicrousdPerGB == 0)
   {
      failure.assign("azure bandwidth egress price missing"_ctv);
      return false;
   }

   return true;
}

static inline bool mothershipExtractAwsOfferPrice(simdjson::dom::element entry, uint64_t& hourlyMicrousd)
{
   hourlyMicrousd = 0;
   auto terms = entry["terms"]["OnDemand"];
   if (terms.is_object() == false)
   {
      return false;
   }

   for (auto term : terms.get_object())
   {
      auto priceDimensions = term.value["priceDimensions"];
      if (priceDimensions.is_object() == false)
      {
         continue;
      }

      for (auto dimension : priceDimensions.get_object())
      {
         String unit = {};
         if (mothershipJsonGetString(dimension.value, "unit", unit) == false || unit.equal("Hrs"_ctv) == false)
         {
            continue;
         }

         String usd = {};
         if (mothershipJsonGetString(dimension.value["pricePerUnit"], "USD", usd) == false)
         {
            continue;
         }

         if (mothershipParseDecimalPriceMicrousd(usd, hourlyMicrousd))
         {
            return true;
         }
      }
   }

   return false;
}

static inline bool mothershipSurveyAwsSpotPrices(
   const String& region,
   const AwsCredentialMaterial& credential,
   bytell_hash_map<String, uint64_t>& pricesByType,
   String& failure)
{
   pricesByType.clear();
   failure.clear();

   String nextToken = {};
   while (true)
   {
      bool first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "DescribeSpotPriceHistory"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "ProductDescription.1"_ctv, "Linux/UNIX"_ctv, first);
      awsAppendQueryParam(body, "MaxResults"_ctv, "1000"_ctv, first);
      if (nextToken.size() > 0)
      {
         awsAppendQueryParam(body, "NextToken"_ctv, nextToken, first);
      }

      String response = {};
      struct curl_slist *headers = nullptr;
      headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded; charset=utf-8");
      String url = {};
      url.snprintf<"https://ec2.{}.amazonaws.com/"_ctv>(region);
      long httpCode = 0;
      bool ok = AwsHttp::send(
         "POST",
         url,
         region,
         "ec2"_ctv,
         credential,
         headers,
         &body,
         response,
         &httpCode);
      curl_slist_free_all(headers);
      if (ok == false || httpCode < 200 || httpCode >= 300)
      {
         failure.assign("aws DescribeSpotPriceHistory failed"_ctv);
         return false;
      }

      Vector<String> blocks = {};
      awsCollectSetItemBlocks(response, "spotPriceHistorySet", blocks);
      for (const String& block : blocks)
      {
         String instanceType = {};
         String spotPrice = {};
         if (awsExtractXMLValue(block, "instanceType", instanceType) == false
            || awsExtractXMLValue(block, "spotPrice", spotPrice) == false)
         {
            continue;
         }

         uint64_t spotMicrousd = 0;
         if (mothershipParseDecimalPriceMicrousd(spotPrice, spotMicrousd) == false || spotMicrousd == 0)
         {
            continue;
         }

         auto existing = pricesByType.find(instanceType);
         if (existing == pricesByType.end() || spotMicrousd < existing->second)
         {
            pricesByType.insert_or_assign(instanceType, spotMicrousd);
         }
      }

      nextToken.clear();
      (void)awsExtractXMLValue(response, "nextToken", nextToken);
      if (nextToken.size() == 0)
      {
         break;
      }
   }

   return true;
}

static inline bool mothershipAwsFreeTierEligible(const String& instanceType, ProviderMachineBillingModel billingModel)
{
   if (billingModel != ProviderMachineBillingModel::hourly)
   {
      return false;
   }

   return instanceType.equal("t2.micro"_ctv)
      || instanceType.equal("t3.micro"_ctv)
      || instanceType.equal("t4g.micro"_ctv);
}

static inline bool mothershipSurveyAwsOffers(
   const MothershipProviderScopeTarget& resolvedTarget,
   const MothershipProviderCredential& credential,
   const MothershipProviderOfferSurveyRequest& request,
   Vector<MothershipProviderMachineOffer>& offers,
   String& failure)
{
   offers.clear();
   failure.clear();

   String region = {};
   if (awsScopeRegion(resolvedTarget.providerScope, region) == false)
   {
      failure.assign("aws providerScope region missing"_ctv);
      return false;
   }

   String expectedCountryKey = {};
   if (mothershipResolveAwsRegionCountry(region, expectedCountryKey) == false
      || mothershipCountryMatchesRequested(request.country, expectedCountryKey.c_str(), &failure) == false)
   {
      if (failure.size() == 0)
      {
         failure.assign("aws providerScope country mismatch"_ctv);
      }
      return false;
   }

   AwsCredentialMaterial awsCredential = {};
   if (parseAwsCredentialMaterial(credential.material, awsCredential, &failure) == false)
   {
      return false;
   }

   bytell_hash_map<String, uint64_t> spotPricesByType = {};
   if (request.billingModel == ProviderMachineBillingModel::spot
      && mothershipSurveyAwsSpotPrices(region, awsCredential, spotPricesByType, failure) == false)
   {
      return false;
   }

   uint64_t extraStorageMicrousdPerGBHour = 0;
   uint64_t ingressMicrousdPerGB = 0;
   uint64_t egressMicrousdPerGB = 0;
   if (mothershipSurveyAwsGp3StorageMicrousdPerGBHour(region, awsCredential, extraStorageMicrousdPerGBHour, failure) == false)
   {
      return false;
   }

   if (mothershipSurveyAwsInternetTransferMicrousdPerGB(region, awsCredential, ingressMicrousdPerGB, egressMicrousdPerGB, failure) == false)
   {
      return false;
   }

   bool providesHostPublic4 = false;
   bool providesHostPublic6 = false;
   if (mothershipResolveScopeHostPublicCapabilities(
      MothershipClusterProvider::aws,
      resolvedTarget.providerScope,
      providesHostPublic4,
      providesHostPublic6,
      &failure) == false)
   {
      return false;
   }

   bytell_hash_map<String, MothershipProviderMachineOffer> offersByType = {};
   String nextToken = {};
   while (true)
   {
      String body = {};
      awsBuildPricingGetProductsRequestBody(
         "AmazonEC2"_ctv,
         {
            {"regionCode"_ctv, region},
            {"operatingSystem"_ctv, "Linux"_ctv},
            {"preInstalledSw"_ctv, "NA"_ctv},
            {"tenancy"_ctv, "Shared"_ctv},
            {"capacitystatus"_ctv, "Used"_ctv},
         },
         body,
         &nextToken);

      String response = {};
      long httpCode = 0;
      bool ok = awsSendPricingGetProductsRequest(awsCredential, body, response, failure, &httpCode);
      if (ok == false || httpCode < 200 || httpCode >= 300)
      {
         failure.assign("aws pricing GetProducts failed"_ctv);
         return false;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (parser.parse(response.c_str(), response.size()).get(doc))
      {
         failure.assign("aws pricing response parse failed"_ctv);
         return false;
      }

      auto priceList = doc["PriceList"];
      if (priceList.is_array() == false)
      {
         failure.assign("aws pricing response missing PriceList"_ctv);
         return false;
      }

      for (auto encodedEntry : priceList.get_array())
      {
         std::string_view encoded = {};
         if (encodedEntry.get(encoded) != simdjson::SUCCESS || encoded.size() == 0)
         {
            continue;
         }

         String entryText = {};
         entryText.assign(encoded);
         simdjson::dom::parser entryParser;
         simdjson::dom::element entry;
         if (entryParser.parse(entryText.c_str(), entryText.size()).get(entry))
         {
            continue;
         }

         String productFamily = {};
         if (mothershipJsonGetString(entry["product"], "productFamily", productFamily) == false || productFamily.equal("Compute Instance"_ctv) == false)
         {
            continue;
         }

         simdjson::dom::element attributes = entry["product"]["attributes"];
         if (attributes.is_object() == false)
         {
            continue;
         }

         String instanceType = {};
         String memoryText = {};
         uint32_t vcpu = 0;
         if (mothershipJsonGetString(attributes, "instanceType", instanceType) == false
            || mothershipJsonGetString(attributes, "memory", memoryText) == false
            || mothershipJsonGetUInt32StringOrNumber(attributes, "vcpu", vcpu) == false)
         {
            continue;
         }

         uint32_t memoryMB = 0;
         if (mothershipParseMemoryTextMB(memoryText, memoryMB) == false)
         {
            continue;
         }

         MothershipProviderMachineOffer offer = {};
         offer.provider = MothershipClusterProvider::aws;
         offer.providerScope = resolvedTarget.providerScope;
         mothershipCountryDisplayFromKey(expectedCountryKey, offer.country);
         offer.region = region;
         offer.providerMachineType = instanceType;
         offer.billingModel = request.billingModel;
         offer.kind = mothershipTextEndsWith(instanceType, ".metal") ? MachineConfig::MachineKind::bareMetal : MachineConfig::MachineKind::vm;
         offer.nLogicalCores = vcpu;
         offer.nMemoryMB = memoryMB;
         offer.nStorageMBDefault = 0;
         offer.providesHostPublic4 = providesHostPublic4;
         offer.providesHostPublic6 = providesHostPublic6;
         offer.freeTierEligible = mothershipAwsFreeTierEligible(instanceType, request.billingModel);
         offer.extraStorageMicrousdPerGBHour = extraStorageMicrousdPerGBHour;
         offer.ingressMicrousdPerGB = ingressMicrousdPerGB;
         offer.egressMicrousdPerGB = egressMicrousdPerGB;
         offer.priceCompleteness = MothershipProviderOfferPriceCompleteness::computeStorageNetwork;

         String gpuCountText = {};
         if (mothershipJsonGetString(attributes, "gpu", gpuCountText))
         {
            char *end = nullptr;
            long long parsed = std::strtoll(String(gpuCountText).c_str(), &end, 10);
            if (end != nullptr && end != String(gpuCountText).c_str() && parsed > 0)
            {
               offer.gpuCount = uint32_t(parsed);
            }
         }

         String gpuMemoryText = {};
         if (mothershipJsonGetString(attributes, "gpuMemory", gpuMemoryText))
         {
            uint32_t totalGpuMemoryMB = 0;
            if (mothershipParseMemoryTextMB(gpuMemoryText, totalGpuMemoryMB) && offer.gpuCount > 0)
            {
               offer.gpuMemoryMBPerDevice = totalGpuMemoryMB / offer.gpuCount;
            }
         }

         String networkPerformance = {};
         if (mothershipJsonGetString(attributes, "networkPerformance", networkPerformance))
         {
            offer.nicSpeedMbps = mothershipParseNetworkPerformanceMbps(networkPerformance);
         }

         if (request.billingModel == ProviderMachineBillingModel::hourly)
         {
            if (mothershipExtractAwsOfferPrice(entry, offer.hourlyMicrousd) == false || offer.hourlyMicrousd == 0)
            {
               continue;
            }
         }
         else
         {
            auto spotPrice = spotPricesByType.find(instanceType);
            if (spotPrice == spotPricesByType.end() || spotPrice->second == 0)
            {
               continue;
            }

            offer.hourlyMicrousd = spotPrice->second;
         }

         if (mothershipOfferMatchesSurveyRequest(offer, request) == false)
         {
            continue;
         }

         String offerKey = {};
         mothershipOfferSelectionKey(offer.providerMachineType, offer.kind, offerKey);
         auto existing = offersByType.find(offerKey);
         if (existing == offersByType.end() || offer.hourlyMicrousd < existing->second.hourlyMicrousd)
         {
            offersByType.insert_or_assign(offerKey, offer);
         }
      }

      nextToken.clear();
      (void)mothershipJsonGetString(doc, "NextToken", nextToken);
      if (nextToken.size() == 0)
      {
         break;
      }
   }

   for (auto& [instanceType, offer] : offersByType)
   {
      (void)instanceType;
      offers.push_back(offer);
   }

   mothershipPruneDominatedOffers(offers);
   if (offers.empty())
   {
      failure.assign("aws pricing survey produced no offers"_ctv);
      return false;
   }

   return true;
}

struct MothershipGcpFamilyPrice
{
   uint64_t coreMicrousd = 0;
   uint64_t ramGiBMicrousd = 0;
};

static inline void mothershipGcpMachineFamilyFromType(const String& machineType, String& familyKey)
{
   familyKey.clear();
   uint64_t limit = machineType.size();
   for (uint64_t index = 0; index < machineType.size(); ++index)
   {
      if (machineType[index] == '-')
      {
         limit = index;
         break;
      }
   }

   for (uint64_t index = 0; index < limit; ++index)
   {
      familyKey.append(char(std::toupper(unsigned(machineType[index]))));
   }
}

static inline bool mothershipTextContainsUpper(const String& haystack, const String& needle)
{
   if (needle.size() == 0 || haystack.size() < needle.size())
   {
      return false;
   }

   for (uint64_t index = 0; index + needle.size() <= haystack.size(); ++index)
   {
      if (memcmp(haystack.data() + index, needle.data(), needle.size()) == 0)
      {
         return true;
      }
   }

   return false;
}

static inline bool mothershipSurveyGcpOffers(
   const MothershipProviderScopeTarget& resolvedTarget,
   const MothershipProviderCredential& credential,
   const MothershipProviderOfferSurveyRequest& request,
   Vector<MothershipProviderMachineOffer>& offers,
   String& failure)
{
   offers.clear();
   failure.clear();

   String projectId = {};
   String zone = {};
   if (mothershipParseGcpProviderScope(resolvedTarget.providerScope, projectId, zone, &failure) == false)
   {
      return false;
   }

   int64_t dash = zone.rfindChar('-');
   if (dash <= 0)
   {
      failure.assign("gcp providerScope zone invalid"_ctv);
      return false;
   }

   String region = {};
   region.assign(zone.substr(0, uint64_t(dash), Copy::yes));

   String expectedCountryKey = {};
   if (mothershipResolveGcpRegionCountry(region, expectedCountryKey) == false
      || mothershipCountryMatchesRequested(request.country, expectedCountryKey.c_str(), &failure) == false)
   {
      if (failure.size() == 0)
      {
         failure.assign("gcp providerScope country mismatch"_ctv);
      }
      return false;
   }

   ProdigyRuntimeEnvironmentConfig runtime = {};
   runtime.kind = ProdigyEnvironmentKind::gcp;
   runtime.providerScope = resolvedTarget.providerScope;
   if (MothershipProviderCredentialRegistry::applyCredentialToRuntimeEnvironment(credential, runtime, &failure) == false)
   {
      return false;
   }

   MothershipGcpPricingShim shim = {};
   shim.configureRuntimeEnvironment(runtime);

   bool providesHostPublic4 = false;
   bool providesHostPublic6 = false;
   if (mothershipResolveScopeHostPublicCapabilities(
      MothershipClusterProvider::gcp,
      resolvedTarget.providerScope,
      providesHostPublic4,
      providesHostPublic6,
      &failure) == false)
   {
      return false;
   }

   Vector<simdjson::dom::element> machineTypeDocs = {};
   String pageToken = {};
   simdjson::dom::parser parser;
   Vector<String> machineTypeResponses = {};
   while (true)
   {
      String url = {};
      url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/machineTypes"_ctv>(projectId, zone);
      mothershipAppendPageTokenQuery(url, pageToken);

      String response = {};
      long httpStatus = 0;
      if (shim.request("GET", url, nullptr, response, &httpStatus, failure) == false || httpStatus < 200 || httpStatus >= 300)
      {
         if (failure.size() == 0) failure.assign("gcp machineTypes request failed"_ctv);
         return false;
      }

      machineTypeResponses.push_back(response);
      simdjson::dom::element doc;
      if (parser.parse(machineTypeResponses.back().c_str(), machineTypeResponses.back().size()).get(doc))
      {
         failure.assign("gcp machineTypes response parse failed"_ctv);
         return false;
      }

      if (doc["items"].is_array())
      {
         for (auto item : doc["items"].get_array())
         {
            machineTypeDocs.push_back(item);
         }
      }

      pageToken.clear();
      (void)mothershipJsonGetString(doc, "nextPageToken", pageToken);
      if (pageToken.size() == 0)
      {
         break;
      }
   }

   bytell_hash_map<String, MothershipGcpFamilyPrice> familyPricing = {};
   uint64_t storageMicrousdPerGBHour = 0;
   uint64_t ingressMicrousdPerGB = 0;
   uint64_t egressMicrousdPerGB = 0;
   pageToken.clear();
   Vector<String> billingResponses = {};
   simdjson::dom::parser billingParser;
   while (true)
   {
      String url = {};
      url.assign("https://cloudbilling.googleapis.com/v1/services/6F81-5844-456A/skus?pageSize=5000&currencyCode=USD"_ctv);
      mothershipAppendPageTokenQuery(url, pageToken);

      String response = {};
      long httpStatus = 0;
      if (shim.request("GET", url, nullptr, response, &httpStatus, failure) == false || httpStatus < 200 || httpStatus >= 300)
      {
         if (failure.size() == 0) failure.assign("gcp billing skus request failed"_ctv);
         return false;
      }

      billingResponses.push_back(response);
      simdjson::dom::element doc;
      if (billingParser.parse(billingResponses.back().c_str(), billingResponses.back().size()).get(doc))
      {
         failure.assign("gcp billing skus response parse failed"_ctv);
         return false;
      }

      if (doc["skus"].is_array())
      {
         for (auto sku : doc["skus"].get_array())
         {
            bool regionMatch = false;
            if (sku["serviceRegions"].is_array())
            {
               for (auto serviceRegion : sku["serviceRegions"].get_array())
               {
                  std::string_view regionValue = {};
                  if (serviceRegion.get(regionValue) == simdjson::SUCCESS && String(regionValue).equals(region))
                  {
                     regionMatch = true;
                     break;
                  }
               }
            }

            if (regionMatch == false)
            {
               continue;
            }

            String usageType = {};
            String expectedUsageType = {};
            if (request.billingModel == ProviderMachineBillingModel::spot)
            {
               expectedUsageType.assign("Preemptible"_ctv);
            }
            else
            {
               expectedUsageType.assign("OnDemand"_ctv);
            }
            if (mothershipJsonGetString(sku["category"], "usageType", usageType) == false || usageType.equals(expectedUsageType) == false)
            {
               continue;
            }

            String description = {};
            if (mothershipJsonGetString(sku, "description", description) == false)
            {
               continue;
            }

            mothershipUppercaseInPlace(description);

            uint64_t priceMicrousd = 0;
            auto pricingInfo = sku["pricingInfo"];
            if (pricingInfo.is_array() == false)
            {
               continue;
            }

            bool havePrice = false;
            for (auto info : pricingInfo.get_array())
            {
               auto tieredRates = info["pricingExpression"]["tieredRates"];
               if (tieredRates.is_array() == false)
               {
                  continue;
               }

               for (auto rate : tieredRates.get_array())
               {
                  if (mothershipJsonMoneyMicrousd(rate["unitPrice"], priceMicrousd))
                  {
                     havePrice = true;
                     break;
                  }
               }

               if (havePrice)
               {
                  break;
               }
            }

            if (havePrice == false)
            {
               continue;
            }

            uint64_t variableRateMicrousd = 0;
            (void)mothershipGcpSkuMaxNonZeroUnitPriceMicrousdPerGBHour(sku, variableRateMicrousd);

            if ((mothershipTextContains(description, "BALANCED PD CAPACITY")
                  || mothershipTextContains(description, "BALANCED PERSISTENT DISK CAPACITY")
                  || mothershipTextContains(description, "PD BALANCED CAPACITY"))
               && variableRateMicrousd > 0
               && (storageMicrousdPerGBHour == 0 || variableRateMicrousd < storageMicrousdPerGBHour))
            {
               storageMicrousdPerGBHour = variableRateMicrousd;
            }

            if (mothershipTextContains(description, "NETWORK INTERNET EGRESS")
               && mothershipTextContains(description, "WORLDWIDE")
               && mothershipTextContains(description, "CHINA") == false
               && mothershipTextContains(description, "AUSTRALIA") == false
               && mothershipTextContains(description, "INTERCONNECT") == false
               && mothershipTextContains(description, "VPN") == false
               && variableRateMicrousd > egressMicrousdPerGB)
            {
               egressMicrousdPerGB = variableRateMicrousd;
            }

            static constexpr const char *families[] = {
               "N1", "N2", "N2D", "N4", "E2", "C2", "C2D", "C3", "C3D", "C4", "M1", "M2", "M3", "A2", "A3", "G2", "T2A", "T2D", "H3", "H4D", "Z3"
            };

            for (const char *family : families)
            {
               String familyKey = {};
               familyKey.assign(family);
               if (mothershipTextContainsUpper(description, familyKey) == false)
               {
                  continue;
               }

               MothershipGcpFamilyPrice price = familyPricing[familyKey];
               if (mothershipTextContains(description, "INSTANCE CORE"))
               {
                  if (price.coreMicrousd == 0 || priceMicrousd < price.coreMicrousd)
                  {
                     price.coreMicrousd = priceMicrousd;
                  }
               }
               else if (mothershipTextContains(description, "INSTANCE RAM"))
               {
                  if (price.ramGiBMicrousd == 0 || priceMicrousd < price.ramGiBMicrousd)
                  {
                     price.ramGiBMicrousd = priceMicrousd;
                  }
               }

               familyPricing.insert_or_assign(familyKey, price);
            }
         }
      }

      pageToken.clear();
      (void)mothershipJsonGetString(doc, "nextPageToken", pageToken);
      if (pageToken.size() == 0)
      {
         break;
      }
   }

   for (simdjson::dom::element item : machineTypeDocs)
   {
      String name = {};
      if (mothershipJsonGetString(item, "name", name) == false)
      {
         continue;
      }

      bool isSharedCpu = false;
      (void)item["isSharedCpu"].get(isSharedCpu);
      if (isSharedCpu)
      {
         continue;
      }

      String deprecatedState = {};
      if (mothershipJsonGetString(item["deprecated"], "state", deprecatedState)
         && (deprecatedState.equal("DELETED"_ctv) || deprecatedState.equal("OBSOLETE"_ctv)))
      {
         continue;
      }

      auto accelerators = item["accelerators"];
      if (accelerators.is_array())
      {
         bool hasAccelerators = false;
         for (auto accelerator : accelerators.get_array())
         {
            (void)accelerator;
            hasAccelerators = true;
            break;
         }

         if (hasAccelerators)
         {
            continue;
         }
      }

      uint32_t guestCpus = 0;
      uint32_t memoryMB = 0;
      if (mothershipJsonGetUInt32StringOrNumber(item, "guestCpus", guestCpus) == false
         || mothershipJsonGetUInt32StringOrNumber(item, "memoryMb", memoryMB) == false)
      {
         continue;
      }

      String familyKey = {};
      mothershipGcpMachineFamilyFromType(name, familyKey);
      auto familyPrice = familyPricing.find(familyKey);
      if (familyPrice == familyPricing.end()
         || familyPrice->second.coreMicrousd == 0
         || familyPrice->second.ramGiBMicrousd == 0)
      {
         continue;
      }

      uint64_t hourlyMicrousd = uint64_t(guestCpus) * familyPrice->second.coreMicrousd;
      hourlyMicrousd += (uint64_t(memoryMB) * familyPrice->second.ramGiBMicrousd) / 1024ull;

      MothershipProviderMachineOffer offer = {};
      offer.provider = MothershipClusterProvider::gcp;
      offer.providerScope = resolvedTarget.providerScope;
      mothershipCountryDisplayFromKey(expectedCountryKey, offer.country);
      offer.region = region;
      offer.zone = zone;
      offer.providerMachineType = name;
      offer.billingModel = request.billingModel;
      offer.kind = MachineConfig::MachineKind::vm;
      offer.nLogicalCores = guestCpus;
      offer.nMemoryMB = memoryMB;
      offer.nStorageMBDefault = 20u * 1024u;
      offer.providesHostPublic4 = providesHostPublic4;
      offer.providesHostPublic6 = providesHostPublic6;
      offer.hourlyMicrousd = hourlyMicrousd;
      offer.extraStorageMicrousdPerGBHour = storageMicrousdPerGBHour;
      offer.ingressMicrousdPerGB = ingressMicrousdPerGB;
      offer.egressMicrousdPerGB = egressMicrousdPerGB;
      if (storageMicrousdPerGBHour > 0 && egressMicrousdPerGB > 0)
      {
         offer.priceCompleteness = MothershipProviderOfferPriceCompleteness::computeStorageNetwork;
      }
      offer.freeTierEligible = request.billingModel == ProviderMachineBillingModel::hourly
         && name.equal("e2-micro"_ctv)
         && (region.equal("us-west1"_ctv) || region.equal("us-central1"_ctv) || region.equal("us-east1"_ctv));

      if (mothershipOfferMatchesSurveyRequest(offer, request) == false)
      {
         continue;
      }

      offers.push_back(offer);
   }

   mothershipPruneDominatedOffers(offers);
   if (offers.empty())
   {
      failure.assign("gcp pricing survey produced no offers"_ctv);
      return false;
   }

   return true;
}

static inline bool mothershipAzureCapabilityUInt32(simdjson::dom::element sku, const char *capabilityName, uint32_t& value)
{
   value = 0;
   if (sku["capabilities"].is_array() == false)
   {
      return false;
   }

   for (auto capability : sku["capabilities"].get_array())
   {
      String name = {};
      if (mothershipJsonGetString(capability, "name", name) == false || mothershipTextEqualsCString(name, capabilityName) == false)
      {
         continue;
      }

      String text = {};
      if (mothershipJsonGetString(capability, "value", text) == false)
      {
         return false;
      }

      String ownedText = {};
      ownedText.assign(text);
      char *end = nullptr;
      double parsed = std::strtod(ownedText.c_str(), &end);
      if (end == ownedText.c_str() || std::isfinite(parsed) == false || parsed < 0.0)
      {
         return false;
      }

      value = uint32_t(std::llround(parsed));
      return true;
   }

   return false;
}

static inline bool mothershipSurveyAzureOffers(
   const MothershipProviderScopeTarget& resolvedTarget,
   const MothershipProviderCredential& credential,
   const MothershipProviderOfferSurveyRequest& request,
   Vector<MothershipProviderMachineOffer>& offers,
   String& failure)
{
   offers.clear();
   failure.clear();

   String subscriptionID = {};
   String resourceGroup = {};
   String location = {};
   if (parseAzureProviderScope(resolvedTarget.providerScope, subscriptionID, resourceGroup, location, &failure) == false)
   {
      return false;
   }

   String expectedCountryKey = {};
   if (mothershipResolveAzureLocationCountry(location, expectedCountryKey) == false
      || mothershipCountryMatchesRequested(request.country, expectedCountryKey.c_str(), &failure) == false)
   {
      if (failure.size() == 0)
      {
         failure.assign("azure providerScope country mismatch"_ctv);
      }
      return false;
   }

   ProdigyRuntimeEnvironmentConfig runtime = {};
   runtime.kind = ProdigyEnvironmentKind::azure;
   runtime.providerScope = resolvedTarget.providerScope;
   if (MothershipProviderCredentialRegistry::applyCredentialToRuntimeEnvironment(credential, runtime, &failure) == false)
   {
      return false;
   }

   MothershipAzurePricingShim shim = {};
   shim.configureRuntimeEnvironment(runtime);

   bool providesHostPublic4 = false;
   bool providesHostPublic6 = false;
   if (mothershipResolveScopeHostPublicCapabilities(
      MothershipClusterProvider::azure,
      resolvedTarget.providerScope,
      providesHostPublic4,
      providesHostPublic6,
      &failure) == false)
   {
      return false;
   }

   Vector<MothershipStoragePricingTier> storageTiers = {};
   uint64_t ingressMicrousdPerGB = 0;
   uint64_t egressMicrousdPerGB = 0;
   if (mothershipSurveyAzureStorageTiers(location, storageTiers, failure) == false)
   {
      return false;
   }

   if (mothershipSurveyAzureBandwidthPricing(location, ingressMicrousdPerGB, egressMicrousdPerGB, failure) == false)
   {
      return false;
   }

   String skuUrl = {};
   azureBuildResourceSkusURL(subscriptionID, location, skuUrl);

   bytell_hash_map<String, MothershipProviderMachineOffer> offersByType = {};
   String nextLink = skuUrl;
   Vector<String> skuResponses = {};
   simdjson::dom::parser skuParser;
   while (nextLink.size() > 0)
   {
      String response = {};
      long httpStatus = 0;
      if (shim.request("GET", nextLink, nullptr, response, &httpStatus, failure) == false || httpStatus < 200 || httpStatus >= 300)
      {
         if (failure.size() == 0) failure.assign("azure resource skus request failed"_ctv);
         return false;
      }

      skuResponses.push_back(response);
      simdjson::dom::element doc;
      if (skuParser.parse(skuResponses.back().c_str(), skuResponses.back().size()).get(doc))
      {
         failure.assign("azure resource skus response parse failed"_ctv);
         return false;
      }

      if (doc["value"].is_array())
      {
         for (auto sku : doc["value"].get_array())
         {
            String resourceType = {};
            if (mothershipJsonGetString(sku, "resourceType", resourceType) == false || resourceType.equal("virtualMachines"_ctv) == false)
            {
               continue;
            }

            bool locationMatch = false;
            if (sku["locations"].is_array())
            {
               for (auto locationValue : sku["locations"].get_array())
               {
                  std::string_view text = {};
                  if (locationValue.get(text) == simdjson::SUCCESS && String(text).equals(location))
                  {
                     locationMatch = true;
                     break;
                  }
               }
            }

            if (locationMatch == false)
            {
               continue;
            }

            String name = {};
            if (mothershipJsonGetString(sku, "name", name) == false)
            {
               continue;
            }

            uint32_t vcpus = 0;
            uint32_t memoryGB = 0;
            if (mothershipAzureCapabilityUInt32(sku, "vCPUs", vcpus) == false
               || mothershipAzureCapabilityUInt32(sku, "MemoryGB", memoryGB) == false)
            {
               continue;
            }

            MothershipProviderMachineOffer offer = {};
            offer.provider = MothershipClusterProvider::azure;
            offer.providerScope = resolvedTarget.providerScope;
            mothershipCountryDisplayFromKey(expectedCountryKey, offer.country);
            offer.region = location;
            offer.providerMachineType = name;
            offer.billingModel = request.billingModel;
            offer.kind = MachineConfig::MachineKind::vm;
            offer.nLogicalCores = vcpus;
            offer.nMemoryMB = memoryGB * 1024u;
            offer.nStorageMBDefault = 30u * 1024u;
            offer.providesHostPublic4 = providesHostPublic4;
            offer.providesHostPublic6 = providesHostPublic6;
            offer.freeTierEligible = request.billingModel == ProviderMachineBillingModel::hourly
               && (name.equal("Standard_B1s"_ctv)
                  || name.equal("Standard_B2ts_v2"_ctv)
                  || name.equal("Standard_B2pts_v2"_ctv)
                  || name.equal("Standard_B2ats_v2"_ctv));
            (void)mothershipAzureCapabilityUInt32(sku, "GPUs", offer.gpuCount);

            uint32_t nicSpeedMbps = 0;
            if (mothershipAzureCapabilityUInt32(sku, "MaxNetworkBandwidthMbps", nicSpeedMbps))
            {
               offer.nicSpeedMbps = nicSpeedMbps;
            }
            else if (mothershipAzureCapabilityUInt32(sku, "MaxNetworkBandwidthMBps", nicSpeedMbps))
            {
               offer.nicSpeedMbps = nicSpeedMbps * 8u;
            }

            String offerKey = {};
            mothershipOfferSelectionKey(offer.providerMachineType, offer.kind, offerKey);
            offersByType.insert_or_assign(offerKey, offer);
         }
      }

      nextLink.clear();
      (void)mothershipJsonGetString(doc, "nextLink", nextLink);
   }

   String filter = {};
   filter.assign("$filter=serviceName eq 'Virtual Machines' and priceType eq 'Consumption' and armRegionName eq '"_ctv);
   filter.append(location);
   filter.append("'"_ctv);
   String retailUrl = {};
   retailUrl.assign("https://prices.azure.com/api/retail/prices?"_ctv);
   azureAppendPercentEncoded(retailUrl, filter);

   Vector<String> retailResponses = {};
   simdjson::dom::parser retailParser;
   String nextPage = retailUrl;
   while (nextPage.size() > 0)
   {
      String response = {};
      if (AzureHttp::send("GET", nextPage, nullptr, nullptr, response) == false)
      {
         failure.assign("azure retail prices request failed"_ctv);
         return false;
      }

      retailResponses.push_back(response);
      simdjson::dom::element doc;
      if (retailParser.parse(retailResponses.back().c_str(), retailResponses.back().size()).get(doc))
      {
         failure.assign("azure retail prices response parse failed"_ctv);
         return false;
      }

      if (doc["Items"].is_array())
      {
         for (auto item : doc["Items"].get_array())
         {
            String armSkuName = {};
            if (mothershipJsonGetString(item, "armSkuName", armSkuName) == false)
            {
               continue;
            }

            String offerKey = {};
            mothershipOfferSelectionKey(armSkuName, MachineConfig::MachineKind::vm, offerKey);
            auto offerIt = offersByType.find(offerKey);
            if (offerIt == offersByType.end())
            {
               continue;
            }

            String productName = {};
            (void)mothershipJsonGetString(item, "productName", productName);
            for (uint64_t index = 0; index < productName.size(); ++index)
            {
               productName[index] = char(std::toupper(unsigned(productName[index])));
            }

            String meterName = {};
            (void)mothershipJsonGetString(item, "meterName", meterName);
            for (uint64_t index = 0; index < meterName.size(); ++index)
            {
               meterName[index] = char(std::toupper(unsigned(meterName[index])));
            }

            String skuName = {};
            (void)mothershipJsonGetString(item, "skuName", skuName);
            for (uint64_t index = 0; index < skuName.size(); ++index)
            {
               skuName[index] = char(std::toupper(unsigned(skuName[index])));
            }

            bool isSpotEntry = mothershipTextContains(productName, "SPOT")
               || mothershipTextContains(productName, "LOW PRIORITY")
               || mothershipTextContains(meterName, "SPOT")
               || mothershipTextContains(meterName, "LOW PRIORITY")
               || mothershipTextContains(skuName, "SPOT")
               || mothershipTextContains(skuName, "LOW PRIORITY");
            if (mothershipTextContains(productName, "WINDOWS"))
            {
               continue;
            }

            if (request.billingModel == ProviderMachineBillingModel::spot)
            {
               if (isSpotEntry == false)
               {
                  continue;
               }
            }
            else if (isSpotEntry)
            {
               continue;
            }

            double retailPrice = 0.0;
            if (item["retailPrice"].get(retailPrice) != simdjson::SUCCESS)
            {
               continue;
            }

            uint64_t priceMicrousd = 0;
            if (mothershipParseDoubleMicrousd(retailPrice, priceMicrousd) == false || priceMicrousd == 0)
            {
               continue;
            }

            if (offerIt->second.hourlyMicrousd == 0 || priceMicrousd < offerIt->second.hourlyMicrousd)
            {
               offerIt->second.hourlyMicrousd = priceMicrousd;
            }
         }
      }

      nextPage.clear();
      (void)mothershipJsonGetString(doc, "NextPageLink", nextPage);
   }

   for (auto& [skuName, offer] : offersByType)
   {
      (void)skuName;
      offer.storageTiers = storageTiers;
      offer.ingressMicrousdPerGB = ingressMicrousdPerGB;
      offer.egressMicrousdPerGB = egressMicrousdPerGB;
      offer.priceCompleteness = MothershipProviderOfferPriceCompleteness::computeStorageNetwork;
      if (offer.hourlyMicrousd > 0 && mothershipOfferMatchesSurveyRequest(offer, request))
      {
         offers.push_back(offer);
      }
   }

   mothershipPruneDominatedOffers(offers);
   if (offers.empty())
   {
      failure.assign("azure pricing survey produced no offers"_ctv);
      return false;
   }

   return true;
}

static inline bool mothershipSurveyProviderMachineOffers(
   MothershipProviderOfferSurveyRequest request,
   Vector<MothershipProviderMachineOffer>& offers,
   String& failure)
{
   offers.clear();
   failure.clear();

   MothershipProviderCredential credential = {};
   if (mothershipResolveTargetCredential(request.target, credential, &failure) == false)
   {
      return false;
   }

   if (request.country.size() == 0)
   {
      failure.assign("country required"_ctv);
      return false;
   }

   if (request.target.provider == MothershipClusterProvider::aws)
   {
      return mothershipSurveyAwsOffers(request.target, credential, request, offers, failure);
   }

   if (request.target.provider == MothershipClusterProvider::gcp)
   {
      return mothershipSurveyGcpOffers(request.target, credential, request, offers, failure);
   }

   if (request.target.provider == MothershipClusterProvider::azure)
   {
      return mothershipSurveyAzureOffers(request.target, credential, request, offers, failure);
   }

   failure.assign("unsupported provider for pricing survey"_ctv);
   return false;
}

static inline bool mothershipEstimateClusterHourlyCost(
   const MothershipClusterCostEstimateRequest& request,
   const Vector<MothershipProviderMachineOffer>& offers,
   MothershipClusterHourlyEstimate& estimate)
{
   estimate = {};
   estimate.billingModel = request.billingModel;

   Vector<Machine> machines = {};
   for (const MothershipMachineOfferSelection& selection : request.machines)
   {
      const MothershipProviderMachineOffer *offer = nullptr;
      if (mothershipLookupOfferByType(offers, selection.providerMachineType, selection.kind, offer) == false || offer == nullptr)
      {
         estimate.failure.snprintf<"offer '{}:{}' not found in surveyed provider scope"_ctv>(String(machineKindName(selection.kind)), selection.providerMachineType);
         return false;
      }

      for (uint32_t index = 0; index < selection.count; ++index)
      {
         machines.push_back(mothershipBuildSyntheticMachineFromOffer(*offer, selection.storageMB));
      }
   }

   MothershipClusterCostBreakdown breakdown = {};
   if (mothershipComputeClusterCostBreakdown(request.machines, offers, request.ingressMBPerHour, request.egressMBPerHour, breakdown, &estimate.failure) == false)
   {
      return false;
   }

   estimate.computeHourlyMicrousd = breakdown.computeHourlyMicrousd;
   estimate.storageHourlyMicrousd = breakdown.storageHourlyMicrousd;
   estimate.ingressHourlyMicrousd = breakdown.ingressHourlyMicrousd;
   estimate.egressHourlyMicrousd = breakdown.egressHourlyMicrousd;
   estimate.hourlyMicrousd = breakdown.totalHourlyMicrousd();
   estimate.totalMachines = mothershipCountSelectedMachines(request.machines);

   if (request.applications.empty())
   {
      estimate.fits = true;
      return true;
   }

   if (mothershipSimulatePlanningPlacement(request.applications, machines, &estimate.failure) == false)
   {
      estimate.fits = false;
      return true;
   }

   estimate.fits = true;
   return true;
}

static inline bool mothershipRecommendClusterForApplications(
   const MothershipClusterRecommendationRequest& request,
   const Vector<MothershipProviderMachineOffer>& offers,
   const MothershipProviderScopeTarget& target,
   MothershipClusterRecommendation& recommendation)
{
   recommendation = {};
   recommendation.target = target;
   recommendation.country = request.country;
   recommendation.billingModel = request.billingModel;

   if (offers.empty())
   {
      recommendation.failure.assign("no offers available"_ctv);
      return false;
   }

   uint32_t totalInstances = 0;
   for (const MothershipPlanningApplication& application : request.applications)
   {
      totalInstances += application.instances;
   }

   const uint32_t minimumMachines = request.minMachines > 0 ? request.minMachines : 1;
   const uint32_t maximumMachines = std::max(totalInstances, minimumMachines);
   const uint32_t elasticStorageFloorMB = mothershipPlanningElasticStorageFloorMB(request.applications);
   uint64_t bestHourlyMicrousd = std::numeric_limits<uint64_t>::max();
   bool bestWithinBudget = false;
   Vector<MothershipMachineOfferSelection> bestSelections = {};
   MothershipClusterCostBreakdown bestBreakdown = {};
   uint32_t bestTotalMachines = 0;
   bool foundAny = false;

   auto selectionsFeasible = [&] (Vector<MothershipMachineOfferSelection> selections) -> bool
   {
      mothershipNormalizeMachineSelections(selections);
      Vector<Machine> machines = {};
      mothershipBuildPlanningMachinesFromSelections(selections, offers, machines, nullptr, elasticStorageFloorMB);
      return mothershipSimulatePlanningPlacement(request.applications, machines, nullptr);
   };

   auto considerSelections = [&] (Vector<MothershipMachineOfferSelection> selections) -> void
   {
      mothershipNormalizeMachineSelections(selections);
      if (mothershipCountSelectedMachines(selections) < minimumMachines)
      {
         return;
      }

      Vector<Machine> machines = {};
      Vector<MothershipPlanningMachineMetadata> metadata = {};
      mothershipBuildPlanningMachinesFromSelections(selections, offers, machines, &metadata, elasticStorageFloorMB);
      if (mothershipSimulatePlanningPlacement(request.applications, machines, nullptr) == false)
      {
         return;
      }

      Vector<MothershipMachineOfferSelection> realizedSelections = {};
      mothershipSelectionsFromPlacedMachines(machines, metadata, realizedSelections);
      uint32_t totalMachines = mothershipCountSelectedMachines(realizedSelections);

      MothershipClusterCostBreakdown breakdown = {};
      if (mothershipComputeClusterCostBreakdown(realizedSelections, offers, request.ingressMBPerHour, request.egressMBPerHour, breakdown, nullptr) == false)
      {
         return;
      }
      uint64_t hourlyMicrousd = breakdown.totalHourlyMicrousd();

      bool withinBudget = request.hasBudget == false || hourlyMicrousd <= request.budgetMicrousd;
      bool better = false;
      if (foundAny == false)
      {
         better = true;
      }
      else if (bestWithinBudget != withinBudget)
      {
         better = withinBudget;
      }
      else if (hourlyMicrousd < bestHourlyMicrousd)
      {
         better = true;
      }
      else if (hourlyMicrousd == bestHourlyMicrousd && totalMachines < bestTotalMachines)
      {
         better = true;
      }
      else if (hourlyMicrousd == bestHourlyMicrousd
         && totalMachines == bestTotalMachines
         && mothershipMachineSelectionsLess(realizedSelections, bestSelections))
      {
         better = true;
      }

      if (better)
      {
         foundAny = true;
         bestWithinBudget = withinBudget;
         bestHourlyMicrousd = hourlyMicrousd;
         bestTotalMachines = totalMachines;
         bestSelections = std::move(realizedSelections);
         bestBreakdown = breakdown;
      }
   };

   for (const MothershipProviderMachineOffer& primaryOffer : offers)
   {
      if (providerMachineKindMaskAllows(request.machineKindsMask, primaryOffer.kind) == false)
      {
         continue;
      }

      uint32_t low = minimumMachines;
      uint32_t high = maximumMachines;
      uint32_t bestCount = 0;
      bool feasible = false;
      while (low <= high)
      {
         uint32_t mid = low + ((high - low) / 2u);
         Vector<MothershipMachineOfferSelection> selections = {};
         mothershipAppendMachineSelection(selections, primaryOffer, mid);
         if (selectionsFeasible(selections))
         {
            feasible = true;
            bestCount = mid;
            if (mid == 0)
            {
               break;
            }
            high = mid - 1u;
         }
         else
         {
            low = mid + 1u;
         }
      }

      if (feasible)
      {
         Vector<MothershipMachineOfferSelection> selections = {};
         mothershipAppendMachineSelection(selections, primaryOffer, bestCount);
         considerSelections(std::move(selections));
      }
   }

   for (uint32_t primaryIndex = 0; primaryIndex < offers.size(); ++primaryIndex)
   {
      const MothershipProviderMachineOffer& primaryOffer = offers[primaryIndex];
      if (providerMachineKindMaskAllows(request.machineKindsMask, primaryOffer.kind) == false)
      {
         continue;
      }

      for (uint32_t secondaryIndex = primaryIndex + 1u; secondaryIndex < offers.size(); ++secondaryIndex)
      {
         const MothershipProviderMachineOffer& secondaryOffer = offers[secondaryIndex];
         if (providerMachineKindMaskAllows(request.machineKindsMask, secondaryOffer.kind) == false)
         {
            continue;
         }

         for (uint32_t primaryCount = 1; primaryCount < maximumMachines; ++primaryCount)
         {
            uint32_t low = std::max(uint32_t(1), minimumMachines > primaryCount ? (minimumMachines - primaryCount) : 1u);
            if (primaryCount + low > maximumMachines)
            {
               continue;
            }

            uint32_t high = maximumMachines - primaryCount;
            uint32_t bestSecondaryCount = 0;
            bool feasible = false;
            while (low <= high)
            {
               uint32_t mid = low + ((high - low) / 2u);
               Vector<MothershipMachineOfferSelection> selections = {};
               mothershipAppendMachineSelection(selections, primaryOffer, primaryCount);
               mothershipAppendMachineSelection(selections, secondaryOffer, mid);
               if (selectionsFeasible(selections))
               {
                  feasible = true;
                  bestSecondaryCount = mid;
                  if (mid == 0)
                  {
                     break;
                  }
                  high = mid - 1u;
               }
               else
               {
                  low = mid + 1u;
               }
            }

            if (feasible)
            {
               Vector<MothershipMachineOfferSelection> selections = {};
               mothershipAppendMachineSelection(selections, primaryOffer, primaryCount);
               mothershipAppendMachineSelection(selections, secondaryOffer, bestSecondaryCount);
               considerSelections(std::move(selections));
            }
         }
      }
   }

   for (uint32_t primaryIndex = 0; primaryIndex < offers.size(); ++primaryIndex)
   {
      const MothershipProviderMachineOffer& primaryOffer = offers[primaryIndex];
      if (providerMachineKindMaskAllows(request.machineKindsMask, primaryOffer.kind) == false)
      {
         continue;
      }

      for (uint32_t secondaryIndex = primaryIndex + 1u; secondaryIndex < offers.size(); ++secondaryIndex)
      {
         const MothershipProviderMachineOffer& secondaryOffer = offers[secondaryIndex];
         if (providerMachineKindMaskAllows(request.machineKindsMask, secondaryOffer.kind) == false)
         {
            continue;
         }

         for (uint32_t tertiaryIndex = secondaryIndex + 1u; tertiaryIndex < offers.size(); ++tertiaryIndex)
         {
            const MothershipProviderMachineOffer& tertiaryOffer = offers[tertiaryIndex];
            if (providerMachineKindMaskAllows(request.machineKindsMask, tertiaryOffer.kind) == false)
            {
               continue;
            }

            for (uint32_t primaryCount = 1; primaryCount + 2u <= maximumMachines; ++primaryCount)
            {
               for (uint32_t secondaryCount = 1; primaryCount + secondaryCount + 1u <= maximumMachines; ++secondaryCount)
               {
                  uint32_t low = minimumMachines > (primaryCount + secondaryCount)
                     ? (minimumMachines - primaryCount - secondaryCount)
                     : 1u;
                  if (low == 0)
                  {
                     low = 1;
                  }

                  if (primaryCount + secondaryCount + low > maximumMachines)
                  {
                     continue;
                  }

                  uint32_t high = maximumMachines - primaryCount - secondaryCount;
                  uint32_t bestTertiaryCount = 0;
                  bool feasible = false;
                  while (low <= high)
                  {
                     uint32_t mid = low + ((high - low) / 2u);
                     Vector<MothershipMachineOfferSelection> selections = {};
                     mothershipAppendMachineSelection(selections, primaryOffer, primaryCount);
                     mothershipAppendMachineSelection(selections, secondaryOffer, secondaryCount);
                     mothershipAppendMachineSelection(selections, tertiaryOffer, mid);
                     if (selectionsFeasible(selections))
                     {
                        feasible = true;
                        bestTertiaryCount = mid;
                        if (mid == 0)
                        {
                           break;
                        }
                        high = mid - 1u;
                     }
                     else
                     {
                        low = mid + 1u;
                     }
                  }

                  if (feasible)
                  {
                     Vector<MothershipMachineOfferSelection> selections = {};
                     mothershipAppendMachineSelection(selections, primaryOffer, primaryCount);
                     mothershipAppendMachineSelection(selections, secondaryOffer, secondaryCount);
                     mothershipAppendMachineSelection(selections, tertiaryOffer, bestTertiaryCount);
                     considerSelections(std::move(selections));
                  }
               }
            }
         }
      }
   }

   if (foundAny == false)
   {
      recommendation.failure.assign("no feasible cluster recommendation found"_ctv);
      return false;
   }

   recommendation.found = true;
   recommendation.withinBudget = bestWithinBudget;
   recommendation.hourlyMicrousd = bestHourlyMicrousd;
   recommendation.machineSelections = std::move(bestSelections);
   recommendation.totalMachines = bestTotalMachines;
   recommendation.computeHourlyMicrousd = bestBreakdown.computeHourlyMicrousd;
   recommendation.storageHourlyMicrousd = bestBreakdown.storageHourlyMicrousd;
   recommendation.ingressHourlyMicrousd = bestBreakdown.ingressHourlyMicrousd;
   recommendation.egressHourlyMicrousd = bestBreakdown.egressHourlyMicrousd;
   return true;
}
