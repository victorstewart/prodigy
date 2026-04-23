#pragma once

#include <prodigy/iaas/iaas.h>
#include <prodigy/iaas/bootstrap.ssh.h>
#include <prodigy/brain/base.h>
#include <prodigy/brain/machine.h>
#include <prodigy/cluster.machine.helpers.h>
#include <prodigy/netdev.detect.h>
#include <services/base64.h>

#include <simdjson.h>
#include <curl/curl.h>
#include <limits>
#include <cctype>
#include <cstdio>
#include <sys/wait.h>

class AzureCredentialMaterial
{
public:

   String accessToken;
   String tenantID;
   String clientID;
   String clientSecret;
};

static inline void azureAppendJSONFailureSnippet(const String& json, String& failure)
{
   if (json.size() == 0)
   {
      failure.append(" responseSnippet=\"<empty>\""_ctv);
      return;
   }

   failure.append(" responseSnippet=\""_ctv);
   uint64_t limit = json.size() < 192 ? json.size() : 192;
   for (uint64_t index = 0; index < limit; ++index)
   {
      uint8_t ch = json[index];
      if (ch >= 32 && ch <= 126 && ch != '"' && ch != '\\')
      {
         failure.append(char(ch));
      }
      else if (ch == '"' || ch == '\\')
      {
         failure.append('\\');
         failure.append(char(ch));
      }
      else if (ch == '\n' || ch == '\r' || ch == '\t')
      {
         failure.append(' ');
      }
      else
      {
         failure.append('.');
      }
   }

   if (limit < json.size())
   {
      failure.append("..."_ctv);
   }

   failure.append("\""_ctv);
}

template <StringType FailurePrefix>
static inline bool azureParseJSONDocument(const String& json, simdjson::dom::parser& parser, simdjson::dom::element& doc, String *failure, FailurePrefix&& failurePrefix)
{
   simdjson::error_code error = parser.parse(json.data(), json.size(), true).get(doc);
   if (error == simdjson::SUCCESS)
   {
      if (failure) failure->clear();
      return true;
   }

   if (failure != nullptr)
   {
      failure->clear();
      String prefixText = {};
      prefixText.assign(failurePrefix);
      if (prefixText.size() > 0)
      {
         failure->assign(prefixText);
         failure->append(": "_ctv);
      }
      failure->append(simdjson::error_message(error));
      azureAppendJSONFailureSnippet(json, *failure);
   }

   return false;
}

static inline bool azureParseJSONDocument(const String& json, simdjson::dom::parser& parser, simdjson::dom::element& doc, String *failure = nullptr)
{
   return azureParseJSONDocument(json, parser, doc, failure, ""_ctv);
}

static inline bool azureParseVMListDocument(const String& json, simdjson::dom::parser& parser, simdjson::dom::element& doc, String *failure = nullptr)
{
   return azureParseJSONDocument(json, parser, doc, failure, "azure vm list json parse failed"_ctv);
}

static inline void azureBuildSafeVMNameFragment(const String& source, uint32_t maxLength, String& fragment)
{
   fragment.clear();

   bool previousWasHyphen = false;
   for (uint32_t index = 0; index < source.size() && fragment.size() < maxLength; ++index)
   {
      uint8_t raw = source[index];
      char ch = char(std::tolower(raw));
      bool keep = (ch >= 'a' && ch <= 'z')
         || (ch >= '0' && ch <= '9');
      if (keep)
      {
         fragment.append(ch);
         previousWasHyphen = false;
         continue;
      }

      if (previousWasHyphen || fragment.size() == 0)
      {
         continue;
      }

      fragment.append("-"_ctv);
      previousWasHyphen = true;
   }

   while (fragment.size() > 0 && fragment[fragment.size() - 1] == '-')
   {
      fragment.resize(fragment.size() - 1);
   }

   if (fragment.size() == 0)
   {
      fragment.assign("vm"_ctv);
   }
}

static inline bool parseAzureCredentialMaterial(const String& material, AzureCredentialMaterial& credential, String *failure = nullptr)
{
   credential = {};
   if (failure) failure->clear();

   if (material.size() == 0)
   {
      if (failure) failure->assign("azure credential material required"_ctv);
      return false;
   }

   if (material[0] != '{')
   {
      credential.accessToken = material;
      return true;
   }

   String materialText = {};
   materialText.assign(material);
   simdjson::dom::parser parser;
   simdjson::dom::element doc;
   if (azureParseJSONDocument(materialText, parser, doc, failure, "azure credential material json parse failed"_ctv) == false)
   {
      return false;
   }

   std::string_view accessToken;
   std::string_view tenantID;
   std::string_view clientID;
   std::string_view clientSecret;
   (void)doc["accessToken"].get(accessToken);
   if (accessToken.size() == 0) (void)doc["access_token"].get(accessToken);
   (void)doc["tenantId"].get(tenantID);
   if (tenantID.size() == 0) (void)doc["tenant_id"].get(tenantID);
   (void)doc["clientId"].get(clientID);
   if (clientID.size() == 0) (void)doc["client_id"].get(clientID);
   (void)doc["clientSecret"].get(clientSecret);
   if (clientSecret.size() == 0) (void)doc["client_secret"].get(clientSecret);

   credential.accessToken.assign(accessToken);
   credential.tenantID.assign(tenantID);
   credential.clientID.assign(clientID);
   credential.clientSecret.assign(clientSecret);

   if (credential.accessToken.size() == 0 && (credential.tenantID.size() == 0 || credential.clientID.size() == 0 || credential.clientSecret.size() == 0))
   {
      if (failure) failure->assign("azure credential material requires access token or tenant/client/clientSecret json"_ctv);
      return false;
   }

   return true;
}

static inline bool parseAzureProviderScope(const String& scope, String& subscriptionID, String& resourceGroup, String& location, String *failure = nullptr)
{
   subscriptionID.clear();
   resourceGroup.clear();
   location.clear();
   if (failure) failure->clear();

   if (scope.size() == 0)
   {
      if (failure) failure->assign("azure providerScope required"_ctv);
      return false;
   }

   String scopeText = {};
   scopeText.assign(scope);

   auto assignSegment = [&] (uint64_t start, uint64_t end, String& out) -> void {
      if (end > start)
      {
         out.assign(scopeText.substr(start, end - start, Copy::yes));
      }
   };

   auto findKeySegment = [&] (const char *key, String& out) -> bool {
      String keyText = {};
      keyText.snprintf<"{}/"_ctv>(String(key));
      int64_t offset = -1;
      for (uint64_t index = 0; index + keyText.size() <= scopeText.size(); ++index)
      {
         if (memcmp(scopeText.data() + index, keyText.data(), keyText.size()) == 0)
         {
            offset = int64_t(index + keyText.size());
            break;
         }
      }

      if (offset < 0)
      {
         return false;
      }

      uint64_t end = scopeText.size();
      int64_t slash = scopeText.findChar('/', uint64_t(offset));
      if (slash >= 0)
      {
         end = uint64_t(slash);
      }

      assignSegment(uint64_t(offset), end, out);
      return out.size() > 0;
   };

   bool hasStructured =
      findKeySegment("subscriptions", subscriptionID)
      && findKeySegment("resourceGroups", resourceGroup);

   if (hasStructured)
   {
         if (findKeySegment("locations", location) == false)
         {
         int64_t lastSlash = scopeText.rfindChar('/');
         if (lastSlash >= 0 && uint64_t(lastSlash + 1) < scopeText.size())
         {
            location.assign(scopeText.substr(uint64_t(lastSlash + 1), scopeText.size() - uint64_t(lastSlash + 1), Copy::yes));
         }
      }
   }
   else
   {
      Vector<String> parts;
      uint64_t start = 0;
      for (uint64_t index = 0; index <= scopeText.size(); ++index)
      {
         if (index == scopeText.size() || scopeText[index] == '/')
         {
            if (index > start)
            {
               parts.push_back(scopeText.substr(start, index - start, Copy::yes));
            }
            start = index + 1;
         }
      }

      if (parts.size() >= 3)
      {
         subscriptionID = parts[0];
         resourceGroup = parts[1];
         location = parts[2];
      }
   }

   if (subscriptionID.size() == 0 || resourceGroup.size() == 0 || location.size() == 0)
   {
      if (failure) failure->assign("azure providerScope requires subscription/resourceGroup/location"_ctv);
      return false;
   }

   return true;
}

static inline uint32_t azureHashRackIdentity(const String& value)
{
   uint32_t hash = 0;
   for (uint64_t index = 0; index < value.size(); ++index)
   {
      hash = (hash * 131u) + uint8_t(value[index]);
   }

   return hash;
}

static inline bool azureGetNestedElement(simdjson::dom::element root, std::initializer_list<std::string_view> path, simdjson::dom::element& value)
{
   value = root;
   for (std::string_view key : path)
   {
      simdjson::dom::object object = {};
      if (value.get_object().get(object) != simdjson::SUCCESS)
      {
         return false;
      }

      simdjson::dom::element next = {};
      if (object.at_key(key).get(next) != simdjson::SUCCESS)
      {
         return false;
      }

      value = next;
   }

   return true;
}

static inline bool azureExtractPrimaryZone(simdjson::dom::element vm, String& zoneText)
{
   zoneText.clear();
   simdjson::dom::element zones = {};
   if (azureGetNestedElement(vm, { "zones" }, zones) && zones.is_array())
   {
      for (auto zone : zones.get_array())
      {
         std::string_view zoneValue = {};
         if (!zone.get(zoneValue) && zoneValue.size() > 0)
         {
            zoneText.assign(zoneValue);
            return true;
         }
      }
   }

   return false;
}

static inline bool azureExtractFaultDomain(simdjson::dom::element vm, String& faultDomainText)
{
   faultDomainText.clear();

   auto assignIfPresent = [&] (simdjson::dom::element value) -> bool {
      uint64_t numeric = 0;
      if (!value.get(numeric))
      {
         faultDomainText.snprintf<"{itoa}"_ctv>(numeric);
         return true;
      }

      std::string_view textual = {};
      if (!value.get(textual) && textual.size() > 0)
      {
         faultDomainText.assign(textual);
         return true;
      }

      return false;
   };

   simdjson::dom::element value = {};
   if (azureGetNestedElement(vm, { "properties", "platformFaultDomain" }, value) && assignIfPresent(value))
   {
      return true;
   }

   if (azureGetNestedElement(vm, { "properties", "instanceView", "platformFaultDomain" }, value) && assignIfPresent(value))
   {
      return true;
   }

   if (azureGetNestedElement(vm, { "properties", "extended", "instanceView", "platformFaultDomain" }, value) && assignIfPresent(value))
   {
      return true;
   }

   return false;
}

static inline uint32_t azureExtractRackUUID(simdjson::dom::element vm, const String& location, const String& zoneText)
{
   String faultDomainText = {};
   if (azureExtractFaultDomain(vm, faultDomainText))
   {
      String rackIdentity = {};
      if (zoneText.size() > 0)
      {
         rackIdentity.snprintf<"{}/zone/{}/fd/{}"_ctv>(location, zoneText, faultDomainText);
      }
      else
      {
         rackIdentity.snprintf<"{}/fd/{}"_ctv>(location, faultDomainText);
      }

      return azureHashRackIdentity(rackIdentity);
   }

   if (zoneText.size() > 0)
   {
      String rackIdentity = {};
      rackIdentity.snprintf<"{}/zone/{}"_ctv>(location, zoneText);
      return azureHashRackIdentity(rackIdentity);
   }

   if (location.size() > 0)
   {
      return azureHashRackIdentity(location);
   }

   std::string_view resourceID = {};
   if (!vm["id"].get(resourceID) && resourceID.size() > 0)
   {
      String resourceText = {};
      resourceText.assign(resourceID);
      return azureHashRackIdentity(resourceText);
   }

   return 0;
}

class AzureHttp
{
public:
   static constexpr long connectTimeoutMs = 10000L;
   static constexpr long timeoutMs = 60000L;

   static bool ensureGlobalInit(void)
   {
      static bool initialized = (curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK);
      return initialized;
   }

   static bool appendResponseBytes(String& out, const uint8_t *bytes, uint64_t bytesSize)
   {
      if (bytesSize == 0)
      {
         return true;
      }

      uint64_t before = out.size();
      out.append(bytes, bytesSize);
      return (out.size() - before) == bytesSize;
   }

   static void populateTransportFailure(CURLcode rc, const char *errorBuffer, String *transportFailure)
   {
      if (transportFailure == nullptr)
      {
         return;
      }

      transportFailure->clear();
      if (rc == CURLE_OK)
      {
         return;
      }

      if (errorBuffer && errorBuffer[0] != '\0')
      {
         transportFailure->assign(errorBuffer);
      }
      else if (const char *text = curl_easy_strerror(rc); text && text[0] != '\0')
      {
         transportFailure->assign(text);
      }
      else
      {
         transportFailure->assign("curl request failed"_ctv);
      }

      transportFailure->snprintf_add<" (curl rc={itoa})"_ctv>(uint32_t(rc));
   }

   static bool send(const char *method, const String& url, const struct curl_slist *headers, const String *body, String& out, long *httpCode = nullptr, String *transportFailure = nullptr)
   {
      if (ensureGlobalInit() == false)
      {
         return false;
      }

      CURL *curl = curl_easy_init();
      if (curl == nullptr)
      {
         return false;
      }

      out.clear();
      String urlText = {};
      urlText.assign(url);
      char errorBuffer[CURL_ERROR_SIZE];
      errorBuffer[0] = '\0';
      struct WriteState {
         String *out = nullptr;
         bool appendFailed = false;
      } writeState = { .out = &out, .appendFailed = false };

      curl_easy_setopt(curl, CURLOPT_URL, urlText.c_str());
      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
      curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, connectTimeoutMs);
      curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeoutMs);
      curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[] (char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
         WriteState *state = reinterpret_cast<WriteState *>(userdata);
         size_t bytesSize = size * nmemb;
         if (AzureHttp::appendResponseBytes(*state->out, reinterpret_cast<uint8_t *>(ptr), bytesSize))
         {
            return bytesSize;
         }

         state->appendFailed = true;
         return 0;
      });
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &writeState);

      String bodyText = {};
      if (body != nullptr && body->size() > 0)
      {
         bodyText.assign(*body);
         curl_easy_setopt(curl, CURLOPT_POSTFIELDS, bodyText.c_str());
         curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, long(bodyText.size()));
      }

      CURLcode rc = curl_easy_perform(curl);
      long code = 0;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
      if (httpCode) *httpCode = code;
      if (writeState.appendFailed && transportFailure != nullptr)
      {
         transportFailure->assign("azure response buffer append failed"_ctv);
         transportFailure->snprintf_add<" (curl rc={itoa})"_ctv>(uint32_t(rc));
      }
      else
      {
         populateTransportFailure(rc, errorBuffer, transportFailure);
      }
      curl_easy_cleanup(curl);
      return rc == CURLE_OK;
   }

   class MultiRequest {
   public:

      CURL *easy = nullptr;
      struct curl_slist *headers = nullptr;
      void *context = nullptr;
      String method = {};
      String url = {};
      String body = {};
      String response = {};
      String transportFailure = {};
      long timeoutMs = AzureHttp::timeoutMs;
      long httpCode = 0;
      CURLcode curlCode = CURLE_OK;
      bool completed = false;
      bool added = false;

      void resetResult(void)
      {
         response.clear();
         transportFailure.clear();
         httpCode = 0;
         curlCode = CURLE_OK;
         completed = false;
         added = false;
      }

      void clearTransport(void)
      {
         if (easy != nullptr)
         {
            curl_easy_cleanup(easy);
            easy = nullptr;
         }

         if (headers != nullptr)
         {
            curl_slist_free_all(headers);
            headers = nullptr;
         }
      }

      ~MultiRequest()
      {
         clearTransport();
      }
   };

   class MultiClient {
   private:

      CURLM *multi = nullptr;
      Vector<MultiRequest *> completed = {};
      uint32_t inFlight = 0;

      static size_t writeResponse(char *ptr, size_t size, size_t nmemb, void *userdata)
      {
         MultiRequest *request = reinterpret_cast<MultiRequest *>(userdata);
         size_t bytesSize = size * nmemb;
         if (AzureHttp::appendResponseBytes(request->response, reinterpret_cast<uint8_t *>(ptr), bytesSize))
         {
            return bytesSize;
         }

         request->transportFailure.assign("azure response buffer append failed"_ctv);
         return 0;
      }

      void collectCompleted(void)
      {
         int messagesRemaining = 0;
         while (CURLMsg *message = curl_multi_info_read(multi, &messagesRemaining))
         {
            if (message->msg != CURLMSG_DONE)
            {
               continue;
            }

            MultiRequest *request = nullptr;
            (void)curl_easy_getinfo(message->easy_handle, CURLINFO_PRIVATE, &request);
            if (request == nullptr)
            {
               curl_multi_remove_handle(multi, message->easy_handle);
               curl_easy_cleanup(message->easy_handle);
               continue;
            }

            request->curlCode = message->data.result;
            request->httpCode = 0;
            (void)curl_easy_getinfo(message->easy_handle, CURLINFO_RESPONSE_CODE, &request->httpCode);
            if (request->transportFailure.size() == 0)
            {
               populateTransportFailure(request->curlCode, nullptr, &request->transportFailure);
            }
            request->completed = true;
            request->added = false;

            curl_multi_remove_handle(multi, message->easy_handle);
            request->easy = nullptr;
            curl_easy_cleanup(message->easy_handle);
            completed.push_back(request);
            if (inFlight > 0)
            {
               inFlight -= 1;
            }
         }
      }

   public:

      bool init(void)
      {
         if (multi != nullptr)
         {
            return true;
         }

         if (ensureGlobalInit() == false)
         {
            return false;
         }

         multi = curl_multi_init();
         return (multi != nullptr);
      }

      bool start(MultiRequest& request)
      {
         if (init() == false)
         {
            return false;
         }

         request.easy = curl_easy_init();
         if (request.easy == nullptr)
         {
            return false;
         }

         curl_easy_setopt(request.easy, CURLOPT_URL, request.url.c_str());
         curl_easy_setopt(request.easy, CURLOPT_CUSTOMREQUEST, request.method.c_str());
         curl_easy_setopt(request.easy, CURLOPT_CONNECTTIMEOUT_MS, connectTimeoutMs);
         curl_easy_setopt(request.easy, CURLOPT_TIMEOUT_MS, request.timeoutMs);
         curl_easy_setopt(request.easy, CURLOPT_HTTPHEADER, request.headers);
         curl_easy_setopt(request.easy, CURLOPT_WRITEFUNCTION, &writeResponse);
         curl_easy_setopt(request.easy, CURLOPT_WRITEDATA, &request);
         curl_easy_setopt(request.easy, CURLOPT_PRIVATE, &request);

         if (request.body.size() > 0)
         {
            long bodySize = long(request.body.size());
            request.body.addNullTerminator();
            curl_easy_setopt(request.easy, CURLOPT_POSTFIELDS, request.body.c_str());
            curl_easy_setopt(request.easy, CURLOPT_POSTFIELDSIZE, bodySize);
         }

         CURLMcode addCode = curl_multi_add_handle(multi, request.easy);
         if (addCode != CURLM_OK)
         {
            request.clearTransport();
            return false;
         }

         request.added = true;
         inFlight += 1;
         int runningHandles = 0;
         return curl_multi_perform(multi, &runningHandles) == CURLM_OK;
      }

      bool pump(int timeoutMs)
      {
         if (multi == nullptr)
         {
            return true;
         }

         int runningHandles = 0;
         if (curl_multi_perform(multi, &runningHandles) != CURLM_OK)
         {
            return false;
         }

         collectCompleted();
         if (inFlight == 0)
         {
            return true;
         }

         int activeFDs = 0;
         CURLMcode waitCode = curl_multi_wait(multi, nullptr, 0, timeoutMs, &activeFDs);
         if (waitCode != CURLM_OK)
         {
            return false;
         }

         if (curl_multi_perform(multi, &runningHandles) != CURLM_OK)
         {
            return false;
         }

         collectCompleted();
         return true;
      }

      MultiRequest *popCompleted(void)
      {
         if (completed.empty())
         {
            return nullptr;
         }

         MultiRequest *request = completed.back();
         completed.pop_back();
         return request;
      }

      uint32_t pendingCount(void) const
      {
         return inFlight;
      }

      ~MultiClient()
      {
         if (multi != nullptr)
         {
            curl_multi_cleanup(multi);
            multi = nullptr;
         }
      }
   };
};

static inline void azureAppendPercentEncoded(String& out, const String& value)
{
   static constexpr char hex[] = "0123456789ABCDEF";

   for (uint64_t index = 0; index < value.size(); ++index)
   {
      uint8_t byte = value[index];
      bool unreserved =
         (byte >= 'A' && byte <= 'Z')
         || (byte >= 'a' && byte <= 'z')
         || (byte >= '0' && byte <= '9')
         || byte == '-'
         || byte == '_'
         || byte == '.'
         || byte == '~';

      if (unreserved)
      {
         out.append(byte);
      }
      else
      {
         out.append('%');
         out.append(hex[(byte >> 4) & 0x0f]);
         out.append(hex[byte & 0x0f]);
      }
   }
}

static inline void azureBuildResourceSkusURL(const String& subscriptionID, const String& location, String& url)
{
   url.snprintf<"https://management.azure.com/subscriptions/{}/providers/Microsoft.Compute/skus?api-version=2021-07-01"_ctv>(subscriptionID);
   if (location.size() == 0)
   {
      return;
   }

   // The unfiltered SKU catalog is enormous and regularly exceeds the fixed
   // AzureHttp timeout. Restrict by location so control-plane SKU lookups stay
   // bounded and deterministic.
   url.append("&%24filter=location%20eq%20%27"_ctv);
   azureAppendPercentEncoded(url, location);
   url.append("%27"_ctv);
}

static inline void azureAppendFixedWidthHex(String& out, uint64_t value, uint32_t width)
{
   static constexpr char hexDigits[] = "0123456789abcdef";
   for (uint32_t index = 0; index < width; ++index)
   {
      uint32_t shift = (width - index - 1) * 4;
      out.append(hexDigits[(value >> shift) & 0xf]);
   }
}

static inline void azureRenderRandomRoleAssignmentName(String& name)
{
   name.clear();
   azureAppendFixedWidthHex(name, Random::generateNumberWithNBits<32, uint32_t>(), 8);
   name.append("-"_ctv);
   azureAppendFixedWidthHex(name, Random::generateNumberWithNBits<16, uint16_t>(), 4);
   name.append("-"_ctv);
   azureAppendFixedWidthHex(name, Random::generateNumberWithNBits<16, uint16_t>(), 4);
   name.append("-"_ctv);
   azureAppendFixedWidthHex(name, Random::generateNumberWithNBits<16, uint16_t>(), 4);
   name.append("-"_ctv);
   azureAppendFixedWidthHex(name, Random::generateNumberWithNBits<48, uint64_t>(), 12);
}

static inline int64_t azureParseRFC3339Ms(const String& value)
{
   if (value.size() < 20)
   {
      return Time::now<TimeResolution::ms>();
   }

   struct tm tmv = {};
   tmv.tm_year = (value[0] - '0') * 1000 + (value[1] - '0') * 100 + (value[2] - '0') * 10 + (value[3] - '0') - 1900;
   tmv.tm_mon = (value[5] - '0') * 10 + (value[6] - '0') - 1;
   tmv.tm_mday = (value[8] - '0') * 10 + (value[9] - '0');
   tmv.tm_hour = (value[11] - '0') * 10 + (value[12] - '0');
   tmv.tm_min = (value[14] - '0') * 10 + (value[15] - '0');
   tmv.tm_sec = (value[17] - '0') * 10 + (value[18] - '0');
   tmv.tm_isdst = 0;
#ifdef _GNU_SOURCE
   time_t secs = timegm(&tmv);
#else
   char *oldtz = getenv("TZ");
   setenv("TZ", "UTC", 1);
   tzset();
   time_t secs = mktime(&tmv);
   if (oldtz) setenv("TZ", oldtz, 1); else unsetenv("TZ");
   tzset();
#endif
   return int64_t(secs) * 1000LL;
}

class AzureMachineTypeResources
{
public:

   uint32_t logicalCores = 0;
   uint32_t memoryMB = 0;
};

static inline bool azureCapabilityUInt32(simdjson::dom::element sku, const char *capabilityName, uint32_t& value)
{
   value = 0;
   if (capabilityName == nullptr || sku["capabilities"].is_array() == false)
   {
      return false;
   }

   for (auto capability : sku["capabilities"].get_array())
   {
      std::string_view name = {};
      std::string_view text = {};
      if (capability["name"].get(name) != simdjson::SUCCESS
         || capability["value"].get(text) != simdjson::SUCCESS
         || text.empty())
      {
         continue;
      }

      if (name != std::string_view(capabilityName))
      {
         continue;
      }

      String parsedText = {};
      parsedText.assign(text);
      char *end = nullptr;
      double parsed = std::strtod(parsedText.c_str(), &end);
      if (end == parsedText.c_str() || parsed < 0.0)
      {
         return false;
      }

      value = uint32_t(std::llround(parsed));
      return true;
   }

   return false;
}

static inline bool azureExtractMachineTypeResources(simdjson::dom::element sku, AzureMachineTypeResources& resources)
{
   resources = {};
   uint32_t memoryGB = 0;
   return azureCapabilityUInt32(sku, "vCPUs", resources.logicalCores)
      && azureCapabilityUInt32(sku, "MemoryGB", memoryGB)
      && memoryGB > 0
      && (resources.memoryMB = memoryGB * 1024u, true);
}

static inline uint32_t azureExtractVMTotalStorageMB(simdjson::dom::element vm)
{
   uint64_t totalStorageGB = 0;
   if (auto osDisk = vm["properties"]["storageProfile"]["osDisk"]; osDisk.is_object())
   {
      uint64_t diskSizeGB = 0;
      if (osDisk["diskSizeGB"].get(diskSizeGB) == simdjson::SUCCESS && diskSizeGB > 0)
      {
         totalStorageGB += diskSizeGB;
      }
   }

   if (auto dataDisks = vm["properties"]["storageProfile"]["dataDisks"]; dataDisks.is_array())
   {
      for (auto dataDisk : dataDisks.get_array())
      {
         uint64_t diskSizeGB = 0;
         if (dataDisk["diskSizeGB"].get(diskSizeGB) == simdjson::SUCCESS && diskSizeGB > 0)
         {
            totalStorageGB += diskSizeGB;
         }
      }
   }

   if (totalStorageGB == 0)
   {
      return 0;
   }

   uint64_t totalStorageMB = totalStorageGB * 1024ull;
   if (totalStorageMB > UINT32_MAX)
   {
      totalStorageMB = UINT32_MAX;
   }

   return uint32_t(totalStorageMB);
}

static inline bool azureApplyMachineTypeResourcesToMachine(
   Machine& machine,
   const AzureMachineTypeResources& resources,
   simdjson::dom::element vm,
   String *failure = nullptr)
{
   if (failure) failure->clear();

   if (resources.logicalCores == 0 || resources.memoryMB == 0)
   {
      if (failure) failure->assign("azure machine type resources missing cores or memory"_ctv);
      return false;
   }

   machine.totalLogicalCores = resources.logicalCores;
   machine.totalMemoryMB = resources.memoryMB;
   machine.totalStorageMB = azureExtractVMTotalStorageMB(vm);
   if (machine.totalStorageMB == 0)
   {
      machine.totalStorageMB = 30u * 1024u;
   }

   ClusterMachineOwnership ownership = {};
   ownership.mode = ClusterMachineOwnershipMode(machine.ownershipMode);
   ownership.nLogicalCoresCap = machine.ownershipLogicalCoresCap;
   ownership.nMemoryMBCap = machine.ownershipMemoryMBCap;
   ownership.nStorageMBCap = machine.ownershipStorageMBCap;
   ownership.nLogicalCoresBasisPoints = machine.ownershipLogicalCoresBasisPoints;
   ownership.nMemoryBasisPoints = machine.ownershipMemoryBasisPoints;
   ownership.nStorageBasisPoints = machine.ownershipStorageBasisPoints;

   if (clusterMachineResolveOwnedResources(
      ownership,
      machine.totalLogicalCores,
      machine.totalMemoryMB,
      machine.totalStorageMB,
      machine.ownedLogicalCores,
      machine.ownedMemoryMB,
      machine.ownedStorageMB,
      failure) == false)
   {
      return false;
   }

   machine.nLogicalCores_available = int32_t(machine.ownedLogicalCores);
   machine.memoryMB_available = int32_t(machine.ownedMemoryMB);
   machine.storageMB_available = int32_t(machine.ownedStorageMB);
   return true;
}

class AzureMetadataClient
{
public:

   bool get(const String& pathAndQuery, String& out, long *httpCode = nullptr, String *transportFailure = nullptr)
   {
      struct curl_slist *headers = nullptr;
      headers = curl_slist_append(headers, "Metadata: true");

      String url = {};
      url.snprintf<"http://169.254.169.254{}"_ctv>(pathAndQuery);

      bool ok = AzureHttp::send("GET", url, headers, nullptr, out, httpCode, transportFailure);
      curl_slist_free_all(headers);
      return ok;
   }

   bool get(const char *pathAndQuery, String& out, long *httpCode = nullptr, String *transportFailure = nullptr)
   {
      String ownedPath = {};
      if (pathAndQuery != nullptr)
      {
         ownedPath.assign(pathAndQuery);
      }

      return get(ownedPath, out, httpCode, transportFailure);
   }
};

class AzureNeuronIaaS : public NeuronIaaS
{
public:

   void gatherSelfData(uint128_t& uuid, String& metro, bool& isBrain, EthDevice& eth, IPAddress& private4) override
   {
      AzureMetadataClient metadata;

      String deviceName;
      if (prodigyResolvePrimaryNetworkDevice(deviceName))
      {
         eth.setDevice(deviceName);
      }

      uuid = 0;
      metro.clear();
      isBrain = false;
      private4 = {};

      String instance;
      if (metadata.get("/metadata/instance?api-version=2021-02-01", instance))
      {
         simdjson::dom::parser parser;
         simdjson::dom::element doc;

         if (azureParseJSONDocument(instance, parser, doc))
         {
            std::string_view location;
            if (!doc["compute"]["location"].get(location))
            {
               metro.assign(location);
            }

            if (auto interfaces = doc["network"]["interface"]; interfaces.is_array())
            {
               for (auto interfaceElement : interfaces.get_array())
               {
                  if (auto ipv4 = interfaceElement["ipv4"]; ipv4.is_object())
                  {
                     if (auto ipAddresses = ipv4["ipAddress"]; ipAddresses.is_array())
                     {
                        for (auto ipAddress : ipAddresses.get_array())
                        {
                           std::string_view private4Text;
                           if (!ipAddress["privateIpAddress"].get(private4Text))
                           {
                              private4.is6 = false;
                              String privateText = String(private4Text);
                              (void)inet_pton(AF_INET, privateText.c_str(), &private4.v4);
                              break;
                           }
                        }
                     }
                  }

                  if (private4.isNull() == false)
                  {
                     break;
                  }
               }
            }

            std::string_view tags;
            if (!doc["compute"]["tags"].get(tags))
            {
               isBrain = (tags.find("brain:true") != std::string_view::npos)
                  || (tags.find("brain=1") != std::string_view::npos)
                  || (tags.find("brain=true") != std::string_view::npos);
            }
         }
      }

      if (private4.isNull())
      {
         private4.is6 = false;
         private4.v4 = eth.getPrivate4();
      }
   }

   void gatherBGPConfig(NeuronBGPConfig& config, EthDevice& eth, const IPAddress& private4) override
   {
      (void)eth;
      (void)private4;
      config = {};
   }

   void downloadContainerToPath(CoroutineStack *coro, uint64_t deploymentID, const String& path) override
   {
      (void)coro;
      (void)deploymentID;
      (void)path;
   }
};

class AzureBrainIaaS : public BrainIaaS
{
private:

   ProdigyRuntimeEnvironmentConfig runtimeEnvironment;
   String subscriptionID;
   String resourceGroup;
   String location;
   AzureCredentialMaterial credential;
   bool credentialLoaded = false;
   String bearerToken;
   int64_t bearerTokenExpiryMs = 0;
   String subnetID;
   String networkSecurityGroupID;
   String bootstrapSSHUser;
   String bootstrapSSHPrivateKeyPath;
   String bootstrapSSHPublicKey;
   Vault::SSHKeyPackage bootstrapSSHHostKeyPackage;
   String provisioningClusterUUIDTagValue;
   BrainIaaSMachineProvisioningProgressReporter provisioningProgress;
   bytell_hash_map<String, AzureMachineTypeResources> machineTypeResourcesByType;

   static void lowercaseString(const String& input, String& lower)
   {
      lower.clear();
      lower.reserve(input.size());
      for (uint64_t index = 0; index < input.size(); ++index)
      {
         lower.append(char(std::tolower(unsigned(input[index]))));
      }
   }

   static bool azureCapabilityString(simdjson::dom::element sku, const char *capabilityName, String& value)
   {
      value.clear();
      if (capabilityName == nullptr || sku["capabilities"].is_array() == false)
      {
         return false;
      }

      for (auto capability : sku["capabilities"].get_array())
      {
         std::string_view name = {};
         std::string_view text = {};
         if (capability["name"].get(name) != simdjson::SUCCESS
            || capability["value"].get(text) != simdjson::SUCCESS)
         {
            continue;
         }

         String capabilityNameText = {};
         capabilityNameText.assign(name);
         if (capabilityNameText.equal(capabilityName, strlen(capabilityName)))
         {
            value.assign(text);
            return true;
         }
      }

      return false;
   }

   bool lookupCachedMachineTypeResources(const String& providerMachineType, AzureMachineTypeResources& resources) const
   {
      auto it = machineTypeResourcesByType.find(providerMachineType);
      if (it == machineTypeResourcesByType.end())
      {
         resources = {};
         return false;
      }

      resources = it->second;
      return true;
   }

   bool resolveMachineTypeResources(const String& providerMachineType, AzureMachineTypeResources& resources, String& error)
   {
      error.clear();
      if (providerMachineType.size() == 0)
      {
         error.assign("azure providerMachineType missing"_ctv);
         return false;
      }

      if (lookupCachedMachineTypeResources(providerMachineType, resources))
      {
         return true;
      }

      if (ensureScope(error) == false || ensureBearerToken(error) == false)
      {
         return false;
      }

      String nextLink = {};
      azureBuildResourceSkusURL(subscriptionID, location, nextLink);
      while (nextLink.size() > 0)
      {
         String response = {};
         long httpCode = 0;
         if (sendARM("GET", nextLink, nullptr, response, error, &httpCode) == false)
         {
            if (httpCode < 200 || httpCode >= 300)
            {
               if (parseAzureErrorMessage(response, error) == false && error.size() == 0)
               {
                  error.assign("azure resource skus request failed"_ctv);
               }
            }
            return false;
         }

         simdjson::dom::parser parser;
         simdjson::dom::element doc = {};
         if (azureParseJSONDocument(response, parser, doc, &error, "azure resource skus response parse failed"_ctv) == false)
         {
            return false;
         }

         if (doc["value"].is_array())
         {
            for (auto sku : doc["value"].get_array())
            {
               std::string_view resourceType = {};
               if (sku["resourceType"].get(resourceType) != simdjson::SUCCESS || resourceType != "virtualMachines")
               {
                  continue;
               }

               std::string_view name = {};
               if (sku["name"].get(name) != simdjson::SUCCESS || String(name) != providerMachineType)
               {
                  continue;
               }

               if (azureExtractMachineTypeResources(sku, resources) == false)
               {
                  error.assign("azure resource sku missing vCPUs or MemoryGB capability"_ctv);
                  return false;
               }

               machineTypeResourcesByType.insert_or_assign(providerMachineType, resources);
               return true;
            }
         }

         std::string_view nextLinkView = {};
         if (doc["nextLink"].get(nextLinkView) == simdjson::SUCCESS)
         {
            nextLink.assign(nextLinkView);
         }
         else
         {
            nextLink.clear();
         }
      }

      error.snprintf<"azure resource sku '{}' not found"_ctv>(providerMachineType);
      return false;
   }

   static bool parseAzureErrorMessage(const String& response, String& failure)
   {
      failure.clear();
      if (response.size() == 0)
      {
         return false;
      }

      String responseText = {};
      responseText.assign(response);
      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (azureParseJSONDocument(responseText, parser, doc) == false)
      {
         return false;
      }

      if (auto error = doc["error"]; error.is_object())
      {
         String codeText = {};
         std::string_view code = {};
         if (!error["code"].get(code) && code.size() > 0)
         {
            codeText.assign(code);
         }

         std::string_view message = {};
         if (!error["message"].get(message) && message.size() > 0)
         {
            failure.assign(message);
         }

         String detailMessage = {};
         if (auto details = error["details"]; details.is_array())
         {
            for (auto detail : details.get_array())
            {
               std::string_view candidate = {};
               if (!detail["message"].get(candidate) && candidate.size() > 0)
               {
                  detailMessage.assign(candidate);
                  break;
               }
            }
         }

         if (detailMessage.size() > 0 && detailMessage.equals(failure) == false)
         {
            if (failure.equal("A retryable error occurred."_ctv) || failure.size() == 0)
            {
               failure.assign(detailMessage);
            }
            else
            {
               failure.append("\n"_ctv);
               failure.append(detailMessage);
            }
         }

         if (codeText.size() > 0 && failure.size() > 0)
         {
            String enriched = {};
            enriched.snprintf<"{} [{}]"_ctv>(failure, codeText);
            failure.assign(enriched);
         }

         if (failure.size() > 0)
         {
            return true;
         }
      }

      String codeText = {};
      std::string_view code = {};
      if (!doc["error"].get(code) && code.size() > 0)
      {
         codeText.assign(code);
      }

      std::string_view description = {};
      if (!doc["error_description"].get(description) && description.size() > 0)
      {
         failure.assign(description);
      }

      if (codeText.size() > 0 && failure.size() > 0)
      {
         String enriched = {};
         enriched.snprintf<"{} [{}]"_ctv>(failure, codeText);
         failure.assign(enriched);
      }

      if (failure.size() > 0)
      {
         return true;
      }

      return false;
   }

   static bool azureStringHasContent(const String& value)
   {
      return value.size() > 0 && value[0] != '\0';
   }

   static void trimTrailingAsciiWhitespace(String& value)
   {
      while (value.size() > 0)
      {
         uint8_t ch = value[value.size() - 1];
         if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t')
         {
            break;
         }

         value.resize(value.size() - 1);
      }
   }

   static bool runCommandCaptureOutput(const String& command, String& output, String *failure)
   {
      output.clear();
      if (failure) failure->clear();

      String ownedCommand = {};
      ownedCommand.assign(command);
      ownedCommand.addNullTerminator();

      FILE *pipe = ::popen(ownedCommand.c_str(), "r");
      if (pipe == nullptr)
      {
         if (failure) failure->assign("failed to spawn command"_ctv);
         return false;
      }

      char buffer[4096];
      while (true)
      {
         size_t nRead = fread(buffer, 1, sizeof(buffer), pipe);
         if (nRead > 0)
         {
            output.append(reinterpret_cast<const uint8_t *>(buffer), nRead);
         }

         if (nRead < sizeof(buffer))
         {
            break;
         }
      }

      int status = ::pclose(pipe);
      trimTrailingAsciiWhitespace(output);
      if (status == 0)
      {
         return true;
      }

      if (failure)
      {
         if (output.size() > 0)
         {
            failure->assign(output);
         }
         else if (WIFEXITED(status))
         {
            failure->snprintf<"command exited with status {itoa}"_ctv>(uint32_t(WEXITSTATUS(status)));
         }
         else
         {
            failure->assign("command failed"_ctv);
         }
      }

      return false;
   }

   static bool azureHasPrefix(const String& value, const String& prefix)
   {
      return value.size() >= prefix.size() && memcmp(value.data(), prefix.data(), prefix.size()) == 0;
   }

   static bool azureExtractResourceIDSegment(const String& resourceID, const char *segmentKey, String& segmentValue)
   {
      segmentValue.clear();
      if (segmentKey == nullptr)
      {
         return false;
      }

      String needle = {};
      needle.snprintf<"/{}/"_ctv>(String(segmentKey));
      int64_t offset = -1;
      for (uint64_t index = 0; index + needle.size() <= resourceID.size(); ++index)
      {
         if (memcmp(resourceID.data() + index, needle.data(), needle.size()) == 0)
         {
            offset = int64_t(index + needle.size());
            break;
         }
      }

      if (offset < 0)
      {
         return false;
      }

      uint64_t end = resourceID.size();
      int64_t slash = -1;
      for (uint64_t index = uint64_t(offset); index < resourceID.size(); ++index)
      {
         if (resourceID[index] == '/')
         {
            slash = int64_t(index);
            break;
         }
      }
      if (slash >= 0)
      {
         end = uint64_t(slash);
      }

      if (end <= uint64_t(offset))
      {
         return false;
      }

      segmentValue.assign(resourceID.substr(uint64_t(offset), end - uint64_t(offset), Copy::yes));
      return segmentValue.size() > 0;
   }

   bool ensureScope(String& failure)
   {
      if (subscriptionID.size() > 0 && resourceGroup.size() > 0 && location.size() > 0)
      {
         return true;
      }

      return parseAzureProviderScope(runtimeEnvironment.providerScope, subscriptionID, resourceGroup, location, &failure);
   }

   bool ensureResourceGroup(String& failure)
   {
      failure.clear();
      if (ensureScope(failure) == false)
      {
         return false;
      }

      String url = {};
      url.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}?api-version=2024-03-01"_ctv>(
         subscriptionID,
         resourceGroup);

      String body = {};
      body.snprintf<"{\"location\":\"{}\"}"_ctv>(location);

      String response = {};
      if (sendARM("PUT", url, &body, response, failure) == false)
      {
         return false;
      }

      for (uint32_t attempt = 0; attempt < 120; ++attempt)
      {
         response.clear();
         if (sendARM("GET", url, nullptr, response, failure) == false)
         {
            return false;
         }

         simdjson::dom::parser parser;
         simdjson::dom::element doc = {};
         if (azureParseJSONDocument(response, parser, doc, &failure, "azure resource group json parse failed"_ctv) == false)
         {
            return false;
         }

         std::string_view provisioningState = {};
         (void)doc["properties"]["provisioningState"].get(provisioningState);
         if (provisioningState.size() == 0 || provisioningState == "Succeeded")
         {
            return true;
         }

         if (provisioningState == "Failed")
         {
            failure.assign("azure resource group provisioning failed"_ctv);
            return false;
         }

         usleep(500 * 1000);
      }

      failure.assign("azure resource group provisioning timed out"_ctv);
      return false;
   }

   bool ensureCredential(String& failure)
   {
      if (credentialLoaded)
      {
         return true;
      }

      credential = {};
      if (runtimeEnvironment.providerCredentialMaterial.size() > 0)
      {
         if (parseAzureCredentialMaterial(runtimeEnvironment.providerCredentialMaterial, credential, &failure) == false)
         {
            return false;
         }
      }

      credentialLoaded = true;
      return true;
   }

   bool azureHasBootstrapAccessTokenRefreshCommand(void) const
   {
      return runtimeEnvironment.azure.bootstrapAccessTokenRefreshCommand.size() > 0;
   }

   bool refreshAzureBootstrapAccessToken(String& failure)
   {
      failure.clear();

      String refreshedToken = {};
      String detail = {};
      if (runCommandCaptureOutput(runtimeEnvironment.azure.bootstrapAccessTokenRefreshCommand, refreshedToken, &detail) == false)
      {
         if (runtimeEnvironment.azure.bootstrapAccessTokenRefreshFailureHint.size() > 0)
         {
            failure.assign(detail);
            if (failure.size() > 0)
            {
               failure.append("\n"_ctv);
            }
            failure.append(runtimeEnvironment.azure.bootstrapAccessTokenRefreshFailureHint);
         }
         else
         {
            failure = detail;
         }
         return false;
      }

      if (azureStringHasContent(refreshedToken) == false)
      {
         failure.assign("azure access token refresh returned empty output"_ctv);
         if (runtimeEnvironment.azure.bootstrapAccessTokenRefreshFailureHint.size() > 0)
         {
            failure.append("\n"_ctv);
            failure.append(runtimeEnvironment.azure.bootstrapAccessTokenRefreshFailureHint);
         }
         return false;
      }

      credential.accessToken = refreshedToken;
      bearerToken = refreshedToken;
      bearerTokenExpiryMs = Time::now<TimeResolution::ms>() + Time::minsToMs(50);
      return true;
   }

   bool ensureBearerToken(String& failure)
   {
      if (Time::now<TimeResolution::ms>() + 30 * 1000 < bearerTokenExpiryMs && bearerToken.size() > 0)
      {
         return true;
      }

      if (ensureCredential(failure) == false)
      {
         return false;
      }

      if (azureHasBootstrapAccessTokenRefreshCommand())
      {
         return refreshAzureBootstrapAccessToken(failure);
      }

      if (credential.accessToken.size() > 0)
      {
         bearerToken = credential.accessToken;
         bearerTokenExpiryMs = std::numeric_limits<int64_t>::max();
         return true;
      }

      if (credential.clientID.size() > 0 && credential.clientSecret.size() > 0 && credential.tenantID.size() > 0)
      {
         String form = {};
         form.append("grant_type=client_credentials&scope="_ctv);
         azureAppendPercentEncoded(form, "https://management.azure.com/.default"_ctv);
         form.append("&client_id="_ctv);
         azureAppendPercentEncoded(form, credential.clientID);
         form.append("&client_secret="_ctv);
         azureAppendPercentEncoded(form, credential.clientSecret);

         String url = {};
         url.snprintf<"https://login.microsoftonline.com/{}/oauth2/v2.0/token"_ctv>(credential.tenantID);

         struct curl_slist *headers = nullptr;
         headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
         String response;
         long httpCode = 0;
         bool ok = AzureHttp::send("POST", url, headers, &form, response, &httpCode);
         curl_slist_free_all(headers);
         if (ok == false || httpCode < 200 || httpCode >= 300)
         {
            failure.assign("azure aad token request failed"_ctv);
            return false;
         }

         simdjson::dom::parser parser;
         simdjson::dom::element doc;
         if (azureParseJSONDocument(response, parser, doc, &failure, "azure aad token json parse failed"_ctv) == false)
         {
            return false;
         }

         std::string_view accessToken;
         uint64_t expiresIn = 3600;
         if (doc["access_token"].get(accessToken))
         {
            failure.assign("azure aad token missing access_token"_ctv);
            return false;
         }
         (void)doc["expires_in"].get(expiresIn);
         bearerToken.assign(accessToken);
         bearerTokenExpiryMs = Time::now<TimeResolution::ms>() + int64_t(expiresIn) * 1000LL;
         return true;
      }

      AzureMetadataClient metadata;
      String response;
      String metadataPath = "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F"_ctv;
      if (runtimeEnvironment.azure.managedIdentityResourceID.size() > 0)
      {
         metadataPath.append("&msi_res_id="_ctv);
         azureAppendPercentEncoded(metadataPath, runtimeEnvironment.azure.managedIdentityResourceID);
      }
      // Fresh user-assigned identities can lag briefly before IMDS starts
      // issuing tokens on the newly booted VM.
      int64_t deadlineMs = Time::now<TimeResolution::ms>() + 30 * 1000;
      uint32_t backoffMs = 200;
      String lastIdentityFailure = {};

      for (;;)
      {
         response.clear();
         long httpCode = 0;
         String transportFailure = {};
         if (metadata.get(metadataPath, response, &httpCode, &transportFailure) == false)
         {
            lastIdentityFailure.assign(transportFailure.size() > 0 ? transportFailure : "azure managed identity token request failed"_ctv);
         }
         else
         {
            simdjson::dom::parser parser;
            simdjson::dom::element doc;
            if (azureParseJSONDocument(response, parser, doc, &lastIdentityFailure, "azure managed identity token json parse failed"_ctv) == false)
            {
               return false;
            }

            std::string_view accessToken = {};
            if (httpCode >= 200 && httpCode < 300
               && doc["access_token"].get(accessToken) == simdjson::SUCCESS
               && accessToken.size() > 0)
            {
               bearerToken.assign(accessToken);

               uint64_t expiresInSeconds = 3600;
               std::string_view expiresIn = {};
               if (doc["expires_in"].get(expiresIn) == simdjson::SUCCESS && expiresIn.size() > 0)
               {
                  String expiresInText = {};
                  expiresInText.assign(expiresIn);
                  char *tail = nullptr;
                  unsigned long long parsed = std::strtoull(expiresInText.c_str(), &tail, 10);
                  if (tail != nullptr && *tail == '\0')
                  {
                     expiresInSeconds = uint64_t(parsed);
                  }
               }

               bearerTokenExpiryMs = Time::now<TimeResolution::ms>() + int64_t(expiresInSeconds) * 1000LL;
               return true;
            }

            lastIdentityFailure.clear();
            if (parseAzureErrorMessage(response, lastIdentityFailure) == false)
            {
               lastIdentityFailure.assign("azure managed identity token missing access_token"_ctv);
            }

            if (httpCode > 0)
            {
               lastIdentityFailure.snprintf_add<" [http={itoa}]"_ctv>(uint32_t(httpCode));
            }
         }

         if (Time::now<TimeResolution::ms>() >= deadlineMs)
         {
            failure.assign(lastIdentityFailure);
            return false;
         }

         usleep(backoffMs * 1000);
         if (backoffMs < 2000)
         {
            backoffMs = std::min<uint32_t>(backoffMs * 2, 2000);
         }
      }
   }

   void buildAuthHeaders(struct curl_slist *&headers)
   {
      headers = nullptr;
      headers = curl_slist_append(headers, "Content-Type: application/json");
      String auth = {};
      auth.snprintf<"Authorization: Bearer {}"_ctv>(bearerToken);
      headers = curl_slist_append(headers, auth.c_str());
   }

   class PendingMachineProvisioning
   {
   public:

      String vmName = {};
      String providerMachineType = {};
   };

   class ConcurrentWaitCoordinator;

   class ConcurrentWaitTask : public CoroutineStack
   {
   public:

      ConcurrentWaitCoordinator *coordinator = nullptr;
      PendingMachineProvisioning pending = {};
      String schema = {};
      MachineLifetime lifetime = MachineLifetime::spot;
      bool sleeping = false;
      int64_t wakeAtMs = 0;
      bool done = false;
      bool success = false;
      bool provisioningReported = false;
      String error = {};
      Machine *machine = nullptr;
      AzureHttp::MultiRequest request = {};

      ~ConcurrentWaitTask()
      {
         if (machine != nullptr)
         {
            delete machine;
            machine = nullptr;
         }
      }

      void sleepForMs(uint32_t delayMs)
      {
         sleeping = true;
         wakeAtMs = Time::now<TimeResolution::ms>() + int64_t(delayMs);
      }

      bool startRequest(void)
      {
         request.clearTransport();
         request.resetResult();
         request.context = this;
         request.method.assign("GET"_ctv);
         request.url.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}?api-version=2025-04-01"_ctv>(
            coordinator->owner->subscriptionID,
            coordinator->owner->resourceGroup,
            pending.vmName);
         request.timeoutMs = AzureHttp::timeoutMs;
         if (coordinator->owner->ensureBearerToken(error) == false)
         {
            return false;
         }

         coordinator->owner->buildAuthHeaders(request.headers);
         if (request.headers == nullptr)
         {
            error.assign("azure auth headers missing"_ctv);
            return false;
         }

         if (coordinator->http.start(request) == false)
         {
            error.assign("azure concurrent request start failed"_ctv);
            return false;
         }

         return true;
      }

      void execute(void)
      {
         int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(prodigyMachineProvisioningTimeoutMs);
         while (Time::now<TimeResolution::ms>() < deadlineMs)
         {
            if (startRequest() == false)
            {
               done = true;
               success = false;
               co_return;
            }

            co_await suspend();

            if (request.curlCode != CURLE_OK || request.httpCode < 200 || request.httpCode >= 300)
            {
               sleepForMs(prodigyMachineProvisioningPollSleepMs);
               co_await suspend();
               continue;
            }

            simdjson::dom::parser parser;
            simdjson::dom::element vm = {};
            if (azureParseJSONDocument(request.response, parser, vm, &error, "azure vm json parse failed"_ctv) == false)
            {
               done = true;
               success = false;
               co_return;
            }

            std::string_view provisioningState = {};
            (void)vm["properties"]["provisioningState"].get(provisioningState);
            MachineProvisioningProgress& progress = coordinator->owner->provisioningProgress.upsert(schema, pending.providerMachineType, pending.vmName, String());
            if (provisioningState == "Failed")
            {
               progress.status.assign("Failed"_ctv);
               progress.ready = false;
               coordinator->owner->provisioningProgress.emitNow();
               error.assign("azure vm provisioning failed"_ctv);
               done = true;
               success = false;
               co_return;
            }

            if (machine != nullptr)
            {
               delete machine;
               machine = nullptr;
            }

            machine = coordinator->owner->buildMachineFromVM(vm);
            if (machine != nullptr)
            {
               progress.cloud.cloudID = machine->cloudID;
               prodigyPopulateMachineProvisioningProgressFromMachine(progress, *machine);
            }

            if (machine != nullptr && provisioningState == "Succeeded" && prodigyMachineProvisioningReady(*machine))
            {
               progress.status.assign("Succeeded"_ctv);
               progress.ready = true;
               if (provisioningReported == false)
               {
                  coordinator->owner->provisioningProgress.notifyMachineProvisioned(*machine);
                  provisioningReported = true;
               }
               coordinator->owner->provisioningProgress.emitNow();
               machine->lifetime = lifetime;
               done = true;
               success = true;
               co_return;
            }

            progress.status.assign(provisioningState);
            progress.ready = false;
            if (machine != nullptr)
            {
               delete machine;
               machine = nullptr;
            }
            coordinator->owner->provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
            sleepForMs(prodigyMachineProvisioningPollSleepMs);
            co_await suspend();
         }

         error.assign("azure vm provisioning timed out"_ctv);
         done = true;
         success = false;
      }
   };

   class ConcurrentWaitCoordinator
   {
   public:

      AzureBrainIaaS *owner = nullptr;
      AzureHttp::MultiClient http = {};
      Vector<ConcurrentWaitTask *> tasks = {};

      explicit ConcurrentWaitCoordinator(AzureBrainIaaS *thisOwner) : owner(thisOwner)
      {
      }

      ~ConcurrentWaitCoordinator()
      {
         for (ConcurrentWaitTask *task : tasks)
         {
            delete task;
         }
         tasks.clear();
      }

      bool allDone(void) const
      {
         for (ConcurrentWaitTask *task : tasks)
         {
            if (task != nullptr && task->done == false)
            {
               return false;
            }
         }

         return true;
      }

      int64_t nextWakeAtMs(void) const
      {
         int64_t nextWake = 0;
         for (ConcurrentWaitTask *task : tasks)
         {
            if (task == nullptr || task->done || task->sleeping == false)
            {
               continue;
            }

            if (nextWake == 0 || task->wakeAtMs < nextWake)
            {
               nextWake = task->wakeAtMs;
            }
         }

         return nextWake;
      }

      static void resumeTaskOnce(ConcurrentWaitTask *task)
      {
         if (task == nullptr || task->hasSuspendedCoroutines() == false)
         {
            return;
         }

         task->runNextSuspended();
      }

      void wakeReadySleepers(void)
      {
         int64_t nowMs = Time::now<TimeResolution::ms>();
         for (ConcurrentWaitTask *task : tasks)
         {
            if (task == nullptr || task->done || task->sleeping == false || task->wakeAtMs > nowMs)
            {
               continue;
            }

            task->sleeping = false;
            resumeTaskOnce(task);
         }
      }

      bool nudgeDormantTasks(void)
      {
         bool nudged = false;
         for (ConcurrentWaitTask *task : tasks)
         {
            if (task == nullptr || task->done || task->sleeping)
            {
               continue;
            }

            resumeTaskOnce(task);
            nudged = true;
         }

         return nudged;
      }

      bool run(const String& schema, MachineLifetime lifetime, const Vector<PendingMachineProvisioning>& pendingMachines, Vector<Machine *>& readyMachines, String& error)
      {
         error.clear();
         readyMachines.clear();
         uint32_t dormantNudges = 0;

         for (const PendingMachineProvisioning& pending : pendingMachines)
         {
            ConcurrentWaitTask *task = new ConcurrentWaitTask();
            task->coordinator = this;
            task->pending = pending;
            task->schema = schema;
            task->lifetime = lifetime;
            tasks.push_back(task);
            task->execute();
         }

         while (allDone() == false)
         {
            wakeReadySleepers();

            while (AzureHttp::MultiRequest *completed = http.popCompleted())
            {
               ConcurrentWaitTask *task = reinterpret_cast<ConcurrentWaitTask *>(completed->context);
               if (task != nullptr && task->done == false)
               {
                  resumeTaskOnce(task);
               }
            }

            if (allDone())
            {
               break;
            }

            int64_t nowMs = Time::now<TimeResolution::ms>();
            int64_t nextWakeMs = nextWakeAtMs();
            int timeoutMs = 50;
            if (nextWakeMs > nowMs)
            {
               int64_t delayMs = nextWakeMs - nowMs;
               timeoutMs = int(delayMs > 50 ? 50 : delayMs);
            }
            else if (nextWakeMs == 0 && http.pendingCount() == 0)
            {
               if (nudgeDormantTasks())
               {
                  dormantNudges += 1;
                  if (dormantNudges < 8)
                  {
                     continue;
                  }
               }

               error.assign("azure concurrent wait stalled with no pending work"_ctv);
               return false;
            }
            else
            {
               dormantNudges = 0;
            }

            if (http.pendingCount() > 0)
            {
               if (http.pump(timeoutMs) == false)
               {
                  error.assign("azure concurrent wait pump failed"_ctv);
                  return false;
               }
            }
            else
            {
               usleep(useconds_t(timeoutMs) * 1000u);
            }
         }

         for (ConcurrentWaitTask *task : tasks)
         {
            if (task == nullptr)
            {
               continue;
            }

            if (task->success == false)
            {
               error = task->error;
               return false;
            }

            readyMachines.push_back(task->machine);
            task->machine = nullptr;
         }

         return true;
      }
   };

protected:

   virtual bool sendARMRaw(const char *method, const String& url, const String *body, String& response, long *httpCode, String& failure)
   {
      if (ensureBearerToken(failure) == false)
      {
         if (httpCode) *httpCode = 0;
         return false;
      }

      struct curl_slist *headers = nullptr;
      buildAuthHeaders(headers);
      bool ok = AzureHttp::send(method, url, headers, body, response, httpCode, &failure);
      curl_slist_free_all(headers);
      return ok;
   }

private:

   bool sendARM(const char *method, const String& url, const String *body, String& response, String& failure, long *httpCode = nullptr)
   {
      long localHTTPCode = 0;
      bool ok = sendARMRaw(method, url, body, response, &localHTTPCode, failure);
      if (httpCode) *httpCode = localHTTPCode;
      if (ok == false)
      {
         return false;
      }

      if (localHTTPCode < 200 || localHTTPCode >= 300)
      {
         if (parseAzureErrorMessage(response, failure) == false)
         {
            failure.assign("azure request failed"_ctv);
         }
         failure.snprintf_add<" [http={itoa}]"_ctv>(uint32_t(localHTTPCode));
         return false;
      }

      failure.clear();
      return true;
   }

   bool resolvePublicIPPrefixResourceID(const String& providerPool, String& prefixID, String& failure)
   {
      prefixID.clear();
      failure.clear();
      if (providerPool.size() == 0)
      {
         return true;
      }

      String directPrefix = "/subscriptions/"_ctv;
      if (azureHasPrefix(providerPool, directPrefix))
      {
         prefixID.assign(providerPool);
         return true;
      }

      if (ensureScope(failure) == false)
      {
         return false;
      }

      prefixID.snprintf<"/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/publicIPPrefixes/{}"_ctv>(
         subscriptionID,
         resourceGroup,
         providerPool);
      return true;
   }

   static bool parseAzureIPConfigurationID(const String& ipConfigurationID, String& nicID, String& ipConfigName)
   {
      nicID.clear();
      ipConfigName.clear();

      String marker = "/ipConfigurations/"_ctv;
      int64_t markerOffset = -1;
      for (uint64_t index = 0; index + marker.size() <= ipConfigurationID.size(); ++index)
      {
         if (memcmp(ipConfigurationID.data() + index, marker.data(), marker.size()) == 0)
         {
            markerOffset = int64_t(index);
            break;
         }
      }

      if (markerOffset < 0)
      {
         return false;
      }

      nicID.assign(ipConfigurationID.substr(0, uint64_t(markerOffset), Copy::yes));
      uint64_t nameStart = uint64_t(markerOffset) + marker.size();
      if (nameStart >= ipConfigurationID.size())
      {
         return false;
      }

      ipConfigName.assign(ipConfigurationID.substr(nameStart, ipConfigurationID.size() - nameStart, Copy::yes));
      return nicID.size() > 0 && ipConfigName.size() > 0;
   }

   static void appendAzureJSONStringField(String& body, const char *key, const String& value)
   {
      prodigyAppendEscapedJSONStringLiteral(body, String(key));
      body.append(":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, value);
   }

   bool fetchPublicIPAddressByConcreteAddress(const String& requestedAddress, String& publicIPID, String& ipConfigurationID, String& concreteAddress, String& failure)
   {
      publicIPID.clear();
      ipConfigurationID.clear();
      concreteAddress.clear();
      if (ensureScope(failure) == false)
      {
         return false;
      }

      String url = {};
      url.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/publicIPAddresses?api-version=2024-05-01"_ctv>(
         subscriptionID,
         resourceGroup);

      String response = {};
      if (sendARM("GET", url, nullptr, response, failure) == false)
      {
         return false;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (azureParseJSONDocument(response, parser, doc, &failure, "azure public ip list json parse failed"_ctv) == false)
      {
         return false;
      }

      if (auto values = doc["value"]; values.is_array())
      {
         for (auto publicIP : values.get_array())
         {
            std::string_view address = {};
            if (publicIP["properties"]["ipAddress"].get(address) || address != std::string_view(reinterpret_cast<const char *>(requestedAddress.data()), size_t(requestedAddress.size())))
            {
               continue;
            }

            std::string_view id = {};
            if (publicIP["id"].get(id))
            {
               failure.assign("azure public ip missing id"_ctv);
               return false;
            }

            publicIPID.assign(id);
            concreteAddress.assign(address);
            std::string_view ipConfigIDView = {};
            if (!publicIP["properties"]["ipConfiguration"]["id"].get(ipConfigIDView))
            {
               ipConfigurationID.assign(ipConfigIDView);
            }
            return true;
         }
      }

      failure.snprintf<"azure public ip {} not found"_ctv>(requestedAddress);
      return false;
   }

   bool fetchMachinePrimaryNICAndConfig(const String& machineCloudID, String& nicID, String& ipConfigName, String& failure)
   {
      nicID.clear();
      ipConfigName.clear();
      if (ensureScope(failure) == false)
      {
         return false;
      }

      if (machineCloudID.size() == 0)
      {
         failure.assign("azure machine cloudID required"_ctv);
         return false;
      }

      String vmURL = {};
      vmURL.snprintf<"https://management.azure.com{}?api-version=2025-04-01"_ctv>(machineCloudID);
      String vmResponse = {};
      if (sendARM("GET", vmURL, nullptr, vmResponse, failure) == false)
      {
         return false;
      }

      simdjson::dom::parser vmParser;
      simdjson::dom::element vm;
      if (azureParseJSONDocument(vmResponse, vmParser, vm, &failure, "azure vm json parse failed"_ctv) == false)
      {
         return false;
      }

      bool foundPrimaryNic = false;
      if (auto nics = vm["properties"]["networkProfile"]["networkInterfaces"]; nics.is_array())
      {
         for (auto nic : nics.get_array())
         {
            std::string_view candidateID = {};
            if (nic["id"].get(candidateID))
            {
               continue;
            }

            bool primary = false;
            (void)nic["properties"]["primary"].get(primary);
            if (primary || foundPrimaryNic == false)
            {
               nicID.assign(candidateID);
               foundPrimaryNic = primary;
               if (primary)
               {
                  break;
               }
            }
         }
      }

      if (nicID.size() == 0)
      {
         failure.assign("azure vm missing network interface id"_ctv);
         return false;
      }

      String nicURL = {};
      nicURL.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(nicID);
      String nicResponse = {};
      if (sendARM("GET", nicURL, nullptr, nicResponse, failure) == false)
      {
         return false;
      }

      simdjson::dom::parser nicParser;
      simdjson::dom::element nic;
      if (azureParseJSONDocument(nicResponse, nicParser, nic, &failure, "azure nic json parse failed"_ctv) == false)
      {
         return false;
      }

      if (auto ipConfigs = nic["properties"]["ipConfigurations"]; ipConfigs.is_array())
      {
         for (auto ipConfig : ipConfigs.get_array())
         {
            std::string_view name = {};
            if (ipConfig["name"].get(name))
            {
               continue;
            }

            bool primary = false;
            (void)ipConfig["properties"]["primary"].get(primary);
            if (primary || ipConfigName.size() == 0)
            {
               ipConfigName.assign(name);
               if (primary)
               {
                  break;
               }
            }
         }
      }

      if (ipConfigName.size() == 0)
      {
         failure.assign("azure nic missing ipConfiguration name"_ctv);
         return false;
      }

      return true;
   }

   bool patchNICPublicIPAddress(const String& nicID, const String& targetIPConfigName, const String *newPublicIPID, String& failure)
   {
      failure.clear();
      if (nicID.size() == 0 || targetIPConfigName.size() == 0)
      {
         failure.assign("azure nic patch requires nicID and ipConfiguration name"_ctv);
         return false;
      }

      String nicURL = {};
      nicURL.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(nicID);
      String nicResponse = {};
      if (sendARM("GET", nicURL, nullptr, nicResponse, failure) == false)
      {
         return false;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element nic;
      if (azureParseJSONDocument(nicResponse, parser, nic, &failure, "azure nic json parse failed"_ctv) == false)
      {
         return false;
      }

      String body = {};
      body.append("{\"properties\":{\"ipConfigurations\":["_ctv);

      bool firstConfig = true;
      bool matchedTarget = false;
      if (auto ipConfigs = nic["properties"]["ipConfigurations"]; ipConfigs.is_array())
      {
         for (auto ipConfig : ipConfigs.get_array())
         {
            std::string_view name = {};
            if (ipConfig["name"].get(name))
            {
               continue;
            }

            String nameText = {};
            nameText.assign(name);
            String currentPublicIPID = {};
            std::string_view currentPublicIDView = {};
            if (!ipConfig["properties"]["publicIPAddress"]["id"].get(currentPublicIDView))
            {
               currentPublicIPID.assign(currentPublicIDView);
            }

            String effectivePublicIPID = currentPublicIPID;
            if (nameText == targetIPConfigName)
            {
               matchedTarget = true;
               effectivePublicIPID.clear();
               if (newPublicIPID != nullptr)
               {
                  effectivePublicIPID.assign(*newPublicIPID);
               }
            }

            if (firstConfig == false)
            {
               body.append(","_ctv);
            }
            firstConfig = false;

            body.append("{\"name\":"_ctv);
            prodigyAppendEscapedJSONStringLiteral(body, nameText);
            body.append(",\"properties\":{"_ctv);

            bool firstProp = true;
            auto appendComma = [&] () {
               if (firstProp == false)
               {
                  body.append(","_ctv);
               }
               firstProp = false;
            };

            std::string_view subnetIDView = {};
            if (ipConfig["properties"]["subnet"]["id"].get(subnetIDView) == false)
            {
               appendComma();
               body.append("\"subnet\":{\"id\":"_ctv);
               String subnetIDText = {};
               subnetIDText.assign(subnetIDView);
               prodigyAppendEscapedJSONStringLiteral(body, subnetIDText);
               body.append("}"_ctv);
            }

            std::string_view privateIPAddress = {};
            if (!ipConfig["properties"]["privateIPAddress"].get(privateIPAddress))
            {
               appendComma();
               body.append("\"privateIPAddress\":"_ctv);
               String privateIPAddressText = {};
               privateIPAddressText.assign(privateIPAddress);
               prodigyAppendEscapedJSONStringLiteral(body, privateIPAddressText);
            }

            std::string_view allocationMethod = {};
            if (!ipConfig["properties"]["privateIPAllocationMethod"].get(allocationMethod))
            {
               appendComma();
               body.append("\"privateIPAllocationMethod\":"_ctv);
               String allocationMethodText = {};
               allocationMethodText.assign(allocationMethod);
               prodigyAppendEscapedJSONStringLiteral(body, allocationMethodText);
            }

            std::string_view ipVersion = {};
            if (!ipConfig["properties"]["privateIPAddressVersion"].get(ipVersion))
            {
               appendComma();
               body.append("\"privateIPAddressVersion\":"_ctv);
               String ipVersionText = {};
               ipVersionText.assign(ipVersion);
               prodigyAppendEscapedJSONStringLiteral(body, ipVersionText);
            }

            bool primary = false;
            if (!ipConfig["properties"]["primary"].get(primary))
            {
               appendComma();
               body.append("\"primary\":"_ctv);
               if (primary)
               {
                  body.append("true"_ctv);
               }
               else
               {
                  body.append("false"_ctv);
               }
            }

            if (effectivePublicIPID.size() > 0)
            {
               appendComma();
               body.append("\"publicIPAddress\":{\"id\":"_ctv);
               prodigyAppendEscapedJSONStringLiteral(body, effectivePublicIPID);
               body.append("}"_ctv);
            }

            body.append("}}"_ctv);
         }
      }

      if (matchedTarget == false)
      {
         failure.assign("azure target ipConfiguration missing"_ctv);
         return false;
      }

      body.append("]"_ctv);

      bool enableAcceleratedNetworking = false;
      if (!nic["properties"]["enableAcceleratedNetworking"].get(enableAcceleratedNetworking))
      {
         body.append(",\"enableAcceleratedNetworking\":"_ctv);
         if (enableAcceleratedNetworking)
         {
            body.append("true"_ctv);
         }
         else
         {
            body.append("false"_ctv);
         }
      }

      bool enableIPForwarding = false;
      if (!nic["properties"]["enableIPForwarding"].get(enableIPForwarding))
      {
         body.append(",\"enableIPForwarding\":"_ctv);
         if (enableIPForwarding)
         {
            body.append("true"_ctv);
         }
         else
         {
            body.append("false"_ctv);
         }
      }

      std::string_view networkSecurityGroupID = {};
      if (!nic["properties"]["networkSecurityGroup"]["id"].get(networkSecurityGroupID))
      {
         body.append(",\"networkSecurityGroup\":{\"id\":"_ctv);
         String networkSecurityGroupText = {};
         networkSecurityGroupText.assign(networkSecurityGroupID);
         prodigyAppendEscapedJSONStringLiteral(body, networkSecurityGroupText);
         body.append("}"_ctv);
      }

      body.append("}}"_ctv);

      String patchResponse = {};
      return sendARM("PATCH", nicURL, &body, patchResponse, failure);
   }

   bool waitForPublicIPAddressState(const String& publicIPID, const String& expectedIPConfigurationID, bool expectAttached, String *resolvedAddress, String& failure)
   {
      failure.clear();
      if (resolvedAddress)
      {
         resolvedAddress->clear();
      }

      if (publicIPID.size() == 0)
      {
         failure.assign("azure public ip id required"_ctv);
         return false;
      }

      for (uint32_t attempt = 0; attempt < 60; ++attempt)
      {
         String url = {};
         url.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(publicIPID);

         String response = {};
         if (sendARM("GET", url, nullptr, response, failure) == false)
         {
            return false;
         }

         simdjson::dom::parser parser;
         simdjson::dom::element doc;
         if (azureParseJSONDocument(response, parser, doc, &failure, "azure public ip json parse failed"_ctv) == false)
         {
            return false;
         }

         std::string_view address = {};
         if (!doc["properties"]["ipAddress"].get(address) && resolvedAddress != nullptr)
         {
            resolvedAddress->assign(address);
         }

         std::string_view provisioningState = {};
         (void)doc["properties"]["provisioningState"].get(provisioningState);

         String currentIPConfigurationID = {};
         std::string_view ipConfigurationIDView = {};
         if (!doc["properties"]["ipConfiguration"]["id"].get(ipConfigurationIDView))
         {
            currentIPConfigurationID.assign(ipConfigurationIDView);
         }

         bool attached = currentIPConfigurationID.size() > 0;
         bool matches = (currentIPConfigurationID == expectedIPConfigurationID);
         bool ready = (provisioningState.size() == 0 || provisioningState == "Succeeded");
         if (expectAttached)
         {
            if (ready && attached && matches && resolvedAddress != nullptr && resolvedAddress->size() > 0)
            {
               return true;
            }
            if (ready && attached && matches && resolvedAddress == nullptr)
            {
               return true;
            }
         }
         else if (ready && attached == false)
         {
            return true;
         }

         usleep(500 * 1000);
      }

      if (expectAttached)
      {
         failure.assign("timed out waiting for azure public ip attachment"_ctv);
      }
      else
      {
         failure.assign("timed out waiting for azure public ip detachment"_ctv);
      }
      return false;
   }

   bool createPublicIPAddress(const String& providerPool, String& publicIPID, String& concreteAddress, String& failure)
   {
      publicIPID.clear();
      concreteAddress.clear();
      if (ensureScope(failure) == false)
      {
         return false;
      }

      String prefixID = {};
      if (resolvePublicIPPrefixResourceID(providerPool, prefixID, failure) == false)
      {
         return false;
      }

      String publicIPName = {};
      publicIPName.snprintf<"ntg-pip-{itoa}"_ctv>(uint64_t(Random::generateNumberWithNBits<24, uint32_t>()));
      publicIPID.snprintf<"/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/publicIPAddresses/{}"_ctv>(
         subscriptionID,
         resourceGroup,
         publicIPName);

      String url = {};
      url.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(publicIPID);

      String body = {};
      body.append("{\"location\":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, location);
      body.append(",\"sku\":{\"name\":\"Standard\"},\"properties\":{\"publicIPAddressVersion\":\"IPv4\",\"publicIPAllocationMethod\":\"Static\""_ctv);
      if (prefixID.size() > 0)
      {
         body.append(",\"publicIPPrefix\":{\"id\":"_ctv);
         prodigyAppendEscapedJSONStringLiteral(body, prefixID);
         body.append("}"_ctv);
      }
      body.append("}}"_ctv);

      String response = {};
      if (sendARM("PUT", url, &body, response, failure) == false)
      {
         return false;
      }

      return waitForPublicIPAddressState(publicIPID, String(), false, &concreteAddress, failure);
   }

   bool waitForNetworkSecurityGroupState(const String& id, String& failure)
   {
      failure.clear();
      if (id.size() == 0)
      {
         failure.assign("azure network security group id required"_ctv);
         return false;
      }

      for (uint32_t attempt = 0; attempt < 60; ++attempt)
      {
         String url = {};
         url.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(id);

         String response = {};
         if (sendARM("GET", url, nullptr, response, failure) == false)
         {
            return false;
         }

         simdjson::dom::parser parser;
         simdjson::dom::element doc = {};
         if (azureParseJSONDocument(response, parser, doc, &failure, "azure network security group json parse failed"_ctv) == false)
         {
            return false;
         }

         std::string_view provisioningState = {};
         (void)doc["properties"]["provisioningState"].get(provisioningState);
         if (provisioningState.size() == 0 || provisioningState == "Succeeded")
         {
            return true;
         }

         if (provisioningState == "Failed")
         {
            failure.assign("azure network security group provisioning failed"_ctv);
            return false;
         }

         usleep(500 * 1000);
      }

      failure.assign("azure network security group provisioning timed out"_ctv);
      return false;
   }

   bool ensureNetworkSecurityGroup(String& failure)
   {
      if (networkSecurityGroupID.size() > 0)
      {
         return true;
      }

      if (ensureScope(failure) == false)
      {
         return false;
      }

      networkSecurityGroupID.snprintf<"/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/networkSecurityGroups/prodigy-nsg"_ctv>(
         subscriptionID,
         resourceGroup);

      String url = {};
      url.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(networkSecurityGroupID);

      String body = {};
      body.snprintf<
         "{\"location\":\"{}\",\"properties\":{\"securityRules\":[{\"name\":\"allow-ssh-inbound\",\"properties\":{\"protocol\":\"Tcp\",\"sourcePortRange\":\"*\",\"destinationPortRange\":\"22\",\"sourceAddressPrefix\":\"*\",\"destinationAddressPrefix\":\"*\",\"access\":\"Allow\",\"priority\":1000,\"direction\":\"Inbound\"}}]}}"_ctv>
         (location);

      String response = {};
      if (sendARM("PUT", url, &body, response, failure) == false)
      {
         return false;
      }

      return waitForNetworkSecurityGroupState(networkSecurityGroupID, failure);
   }

   bool detachPublicIPAddressAssociation(const String& ipConfigurationID, String& failure)
   {
      failure.clear();
      if (ipConfigurationID.size() == 0)
      {
         return true;
      }

      String nicID = {};
      String ipConfigName = {};
      if (parseAzureIPConfigurationID(ipConfigurationID, nicID, ipConfigName) == false)
      {
         failure.assign("azure ipConfiguration id parse failed"_ctv);
         return false;
      }

      return patchNICPublicIPAddress(nicID, ipConfigName, nullptr, failure);
   }

   bool deletePublicIPAddressResource(const String& publicIPID, String& failure)
   {
      failure.clear();
      if (publicIPID.size() == 0)
      {
         return true;
      }

      String url = {};
      url.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(publicIPID);
      String response = {};
      long httpCode = 0;
      if (sendARMRaw("DELETE", url, nullptr, response, &httpCode, failure) == false)
      {
         return false;
      }

      if (httpCode == 404)
      {
         failure.clear();
         return true;
      }

      if (httpCode < 200 || httpCode >= 300)
      {
         if (parseAzureErrorMessage(response, failure) == false)
         {
            failure.assign("azure public ip delete failed"_ctv);
         }
         return false;
      }

      for (uint32_t attempt = 0; attempt < 60; ++attempt)
      {
         String getResponse = {};
         long getCode = 0;
         String transportFailure = {};
         if (sendARMRaw("GET", url, nullptr, getResponse, &getCode, transportFailure) == false)
         {
            return false;
         }

         if (getCode == 404)
         {
            failure.clear();
            return true;
         }

         usleep(500 * 1000);
      }

      failure.assign("timed out waiting for azure public ip delete"_ctv);
      return false;
   }

   bool ensureSubnet(String& failure)
   {
      if (subnetID.size() > 0)
      {
         return true;
      }

      if (ensureScope(failure) == false)
      {
         return false;
      }

      String vnetName = "prodigy-vnet"_ctv;
      String subnetName = "prodigy-subnet"_ctv;
      subnetID.snprintf<"/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/virtualNetworks/{}/subnets/{}"_ctv>(subscriptionID, resourceGroup, vnetName, subnetName);

      String url = {};
      url.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/virtualNetworks/{}?api-version=2024-05-01"_ctv>(subscriptionID, resourceGroup, vnetName);

      String body = {};
      body.snprintf<
         "{\"location\":\"{}\",\"properties\":{\"addressSpace\":{\"addressPrefixes\":[\"10.250.0.0/16\"]},\"subnets\":[{\"name\":\"{}\",\"properties\":{\"addressPrefix\":\"10.250.0.0/20\"}}]}}"_ctv>
         (location, subnetName);

      String response = {};
      if (sendARM("PUT", url, &body, response, failure) == false)
      {
         return false;
      }

      for (uint32_t attempt = 0; attempt < 120; ++attempt)
      {
         response.clear();
         if (sendARM("GET", url, nullptr, response, failure) == false)
         {
            return false;
         }

         simdjson::dom::parser parser;
         simdjson::dom::element vnet = {};
         if (azureParseJSONDocument(response, parser, vnet, &failure, "azure virtual network json parse failed"_ctv) == false)
         {
            return false;
         }

         std::string_view provisioningState = {};
         (void)vnet["properties"]["provisioningState"].get(provisioningState);
         if (provisioningState == "Succeeded")
         {
            return true;
         }

         if (provisioningState == "Failed")
         {
            failure.assign("azure virtual network provisioning failed"_ctv);
            return false;
         }

         usleep(500 * 1000);
      }

      failure.assign("azure virtual network provisioning timed out"_ctv);
      return false;
   }

   bool buildAzureImageReference(const MachineConfig& config, String& imageReferenceJSON, String& failure)
   {
      imageReferenceJSON.clear();
      if (config.vmImageURI.size() == 0)
      {
         failure.assign("azure vmImageURI missing"_ctv);
         return false;
      }

      uint32_t colonCount = 0;
      for (uint64_t index = 0; index < config.vmImageURI.size(); ++index)
      {
         if (config.vmImageURI[index] == ':')
         {
            colonCount += 1;
         }
      }

      if (colonCount == 3)
      {
         Vector<String> parts;
         uint64_t start = 0;
         for (uint64_t index = 0; index <= config.vmImageURI.size(); ++index)
         {
            if (index == config.vmImageURI.size() || config.vmImageURI[index] == ':')
            {
               parts.push_back(config.vmImageURI.substr(start, index - start, Copy::yes));
               start = index + 1;
            }
         }

         if (parts.size() != 4)
         {
            failure.assign("azure vmImageURI urn parse failed"_ctv);
            return false;
         }

         imageReferenceJSON.snprintf<"{\"publisher\":\"{}\",\"offer\":\"{}\",\"sku\":\"{}\",\"version\":\"{}\"}"_ctv>(parts[0], parts[1], parts[2], parts[3]);
         return true;
      }

      imageReferenceJSON.append("{\"id\":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(imageReferenceJSON, config.vmImageURI);
      imageReferenceJSON.append("}"_ctv);
      return true;
   }

   bool resolveNetworkAddresses(const String& nicID, String& privateAddress, String& publicAddress, String& failure)
   {
      privateAddress.clear();
      publicAddress.clear();

      String nicURL = {};
      nicURL.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(nicID);
      String nicResponse;
      if (sendARM("GET", nicURL, nullptr, nicResponse, failure) == false)
      {
         return false;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element nicDoc;
      if (azureParseJSONDocument(nicResponse, parser, nicDoc, &failure, "azure nic json parse failed"_ctv) == false)
      {
         return false;
      }

      String publicIPID = {};
      if (auto ipConfigs = nicDoc["properties"]["ipConfigurations"]; ipConfigs.is_array())
      {
         for (auto ipConfig : ipConfigs.get_array())
         {
            std::string_view privateIP;
            if (!ipConfig["properties"]["privateIPAddress"].get(privateIP))
            {
               privateAddress.assign(privateIP);
            }

            std::string_view publicID;
            if (!ipConfig["properties"]["publicIPAddress"]["id"].get(publicID))
            {
               publicIPID.assign(publicID);
            }

            if (privateAddress.size() > 0)
            {
               break;
            }
         }
      }

      if (publicIPID.size() > 0)
      {
         String publicURL = {};
         publicURL.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(publicIPID);
         String publicResponse;
         if (sendARM("GET", publicURL, nullptr, publicResponse, failure))
         {
            simdjson::dom::element publicDoc;
            if (azureParseJSONDocument(publicResponse, parser, publicDoc))
            {
               std::string_view publicIP;
               if (!publicDoc["properties"]["ipAddress"].get(publicIP))
               {
                  publicAddress.assign(publicIP);
               }
            }
         }
      }

      return privateAddress.size() > 0;
   }

   Machine *buildMachineFromVM(simdjson::dom::element vm)
   {
      Machine *machine = new Machine();
      std::string_view resourceID;
      (void)vm["id"].get(resourceID);
      machine->cloudID.assign(resourceID);
      for (char c : resourceID)
      {
         machine->uuid = (machine->uuid * 131) + uint8_t(c);
      }

      std::string_view vmSize;
      if (!vm["properties"]["hardwareProfile"]["vmSize"].get(vmSize))
      {
         machine->type.assign(vmSize);
         machine->slug.assign(vmSize);
         AzureMachineTypeResources resources = {};
         String resourceLookupFailure = {};
         if (resolveMachineTypeResources(machine->type, resources, resourceLookupFailure))
         {
            String resourceFailure = {};
            if (azureApplyMachineTypeResourcesToMachine(*machine, resources, vm, &resourceFailure) == false)
            {
               std::fprintf(stderr, "prodigy azure buildMachineFromVM resource-apply-failure type=%.*s errorBytes=%zu error=%.*s\n",
                  int(machine->type.size()),
                  reinterpret_cast<const char *>(machine->type.data()),
                  size_t(resourceFailure.size()),
                  int(resourceFailure.size()),
                  resourceFailure.c_str());
               std::fflush(stderr);
            }
         }
      }

      std::string_view created;
      if (!vm["properties"]["timeCreated"].get(created))
      {
         machine->creationTimeMs = azureParseRFC3339Ms(String(created));
      }

      std::string_view loc;
      if (!vm["location"].get(loc))
      {
         machine->region.assign(loc);
      }

      String zoneText = {};
      if (azureExtractPrimaryZone(vm, zoneText))
      {
         machine->zone = zoneText;
      }
      machine->rackUUID = azureExtractRackUUID(vm, machine->region, machine->zone);

      if (auto tags = vm["tags"]; tags.is_object())
      {
         std::string_view brain;
         if (!tags["brain"].get(brain))
         {
            machine->isBrain = (brain == "1" || brain == "true");
         }
      }

      std::string_view imageID;
      if (!vm["properties"]["storageProfile"]["imageReference"]["id"].get(imageID))
      {
         machine->currentImageURI.assign(imageID);
      }

      std::string_view nicID;
      if (!vm["properties"]["networkProfile"]["networkInterfaces"].at(0)["id"].get(nicID))
      {
         String privateAddress;
         String publicAddress;
         String failure;
         if (resolveNetworkAddresses(String(nicID), privateAddress, publicAddress, failure))
         {
            machine->privateAddress = privateAddress;
            machine->publicAddress = publicAddress;
            machine->sshAddress = publicAddress.size() > 0 ? publicAddress : privateAddress;
            String privateText = {};
            privateText.assign(privateAddress);
            (void)inet_pton(AF_INET, privateText.c_str(), &machine->private4);
         }
      }

      if (bootstrapSSHPrivateKeyPath.size() > 0)
      {
         machine->sshUser = bootstrapSSHUser;
         machine->sshPrivateKeyPath = bootstrapSSHPrivateKeyPath;
         machine->sshHostPublicKeyOpenSSH = bootstrapSSHHostKeyPackage.publicKeyOpenSSH;
      }

      prodigyConfigureMachineNeuronEndpoint(*machine, thisNeuron);

      return machine;
   }

   bool waitForVM(const String& vmName, const String& schema, const String& providerMachineType, Machine *&machine, String& failure)
   {
      machine = nullptr;
      int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(prodigyMachineProvisioningTimeoutMs);
      while (Time::now<TimeResolution::ms>() < deadlineMs)
      {
         String url = {};
         url.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}?api-version=2025-04-01"_ctv>(subscriptionID, resourceGroup, vmName);
         String response;
         long httpCode = 0;
         if (sendARM("GET", url, nullptr, response, failure, &httpCode) == false)
         {
            usleep(useconds_t(prodigyMachineProvisioningPollSleepMs) * 1000u);
            continue;
         }

         simdjson::dom::parser parser;
         simdjson::dom::element vm;
         if (azureParseJSONDocument(response, parser, vm, &failure, "azure vm json parse failed"_ctv) == false)
         {
            return false;
         }

         std::string_view provisioningState;
         (void)vm["properties"]["provisioningState"].get(provisioningState);
         MachineProvisioningProgress& progress = provisioningProgress.upsert(schema, providerMachineType, vmName, String());
         if (provisioningState == "Failed")
         {
            progress.status.assign("Failed"_ctv);
            progress.ready = false;
            provisioningProgress.emitNow();
            failure.assign("azure vm provisioning failed"_ctv);
            return false;
         }

         machine = buildMachineFromVM(vm);
         if (machine != nullptr)
         {
            progress.cloud.cloudID = machine->cloudID;
            prodigyPopulateMachineProvisioningProgressFromMachine(progress, *machine);
         }
         if (provisioningState == "Succeeded" && prodigyMachineProvisioningReady(*machine))
         {
            progress.status.assign("Succeeded"_ctv);
            progress.ready = true;
            provisioningProgress.emitNow();
            return true;
         }

         progress.status.assign(provisioningState);
         progress.ready = false;
         delete machine;
         machine = nullptr;
         provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
         usleep(useconds_t(prodigyMachineProvisioningPollSleepMs) * 1000u);
      }

      failure.assign("azure vm provisioning timed out"_ctv);
      return false;
   }

   bool ensureVMTags(const String& cloudID, const String& clusterUUID, String& failure)
   {
      failure.clear();

      if (cloudID.size() == 0)
      {
         failure.assign("azure machine cloudID required"_ctv);
         return false;
      }

      if (clusterUUID.size() == 0)
      {
         failure.assign("azure clusterUUID tag value required"_ctv);
         return false;
      }

      String url = {};
      url.snprintf<"https://management.azure.com{}?api-version=2025-04-01"_ctv>(cloudID);

      String response = {};
      if (sendARM("GET", url, nullptr, response, failure) == false)
      {
         return false;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element vm;
      if (azureParseJSONDocument(response, parser, vm, &failure, "azure vm json parse failed"_ctv) == false)
      {
         return false;
      }

      bool hasProdigyTag = false;
      bool hasClusterTag = false;
      std::string_view clusterUUIDView(reinterpret_cast<const char *>(clusterUUID.data()), size_t(clusterUUID.size()));
      if (auto tags = vm["tags"]; tags.is_object())
      {
         std::string_view appValue;
         if (!tags["app"].get(appValue) && appValue == "prodigy")
         {
            hasProdigyTag = true;
         }

         std::string_view clusterValue;
         if (!tags["prodigy_cluster_uuid"].get(clusterValue) && clusterValue == clusterUUIDView)
         {
            hasClusterTag = true;
         }
      }

      if (hasProdigyTag && hasClusterTag)
      {
         return true;
      }

      String body = {};
      body.append("{\"tags\":{"_ctv);

      bool first = true;
      if (auto tags = vm["tags"]; tags.is_object())
      {
         for (auto field : tags.get_object())
         {
            std::string_view key = field.key;
            if (key == "app" || key == "prodigy_cluster_uuid")
            {
               continue;
            }

            std::string_view value;
            if (field.value.get(value))
            {
               continue;
            }

            if (first == false)
            {
               body.append(","_ctv);
            }

            String keyText = {};
            keyText.assign(key.data(), key.size());
            prodigyAppendEscapedJSONStringLiteral(body, keyText);
            body.append(":"_ctv);
            String valueText = {};
            valueText.assign(value.data(), value.size());
            prodigyAppendEscapedJSONStringLiteral(body, valueText);
            first = false;
         }
      }

      if (first == false)
      {
         body.append(","_ctv);
      }
      prodigyAppendEscapedJSONStringLiteral(body, "app"_ctv);
      body.append(":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, "prodigy"_ctv);
      body.append(","_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, "prodigy_cluster_uuid"_ctv);
      body.append(":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, clusterUUID);
      body.append("}}"_ctv);

      String patchResponse = {};
      return sendARM("PATCH", url, &body, patchResponse, failure);
   }

   void buildRoleDefinitionID(const char *roleUUID, String& roleDefinitionID)
   {
      roleDefinitionID.snprintf<
         "/subscriptions/{}/providers/Microsoft.Authorization/roleDefinitions/{}"_ctv>(
            subscriptionID,
            String(roleUUID));
   }

   bool azureRoleAssignmentExists(const String& scope, const String& principalID, const String& roleDefinitionID, bool& exists, String& failure)
   {
      exists = false;
      failure.clear();

      String nextURL = {};
      nextURL.snprintf<
         "https://management.azure.com{}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"_ctv>(
            scope);

      while (nextURL.size() > 0)
      {
         String response = {};
         if (sendARM("GET", nextURL, nullptr, response, failure) == false)
         {
            return false;
         }

         simdjson::dom::parser parser;
         simdjson::dom::element doc = {};
         if (azureParseJSONDocument(response, parser, doc, &failure, "azure role assignments response parse failed"_ctv) == false)
         {
            return false;
         }

         if (doc["value"].is_array())
         {
            for (auto assignment : doc["value"].get_array())
            {
               std::string_view assignmentPrincipalID = {};
               std::string_view assignmentRoleDefinitionID = {};
               if (assignment["properties"]["principalId"].get(assignmentPrincipalID) == simdjson::SUCCESS
                  && assignment["properties"]["roleDefinitionId"].get(assignmentRoleDefinitionID) == simdjson::SUCCESS
                  && String(assignmentPrincipalID) == principalID
                  && String(assignmentRoleDefinitionID) == roleDefinitionID)
               {
                  exists = true;
                  return true;
               }
            }
         }

         std::string_view nextLink = {};
         if (doc["nextLink"].get(nextLink) == simdjson::SUCCESS)
         {
            nextURL.assign(nextLink);
         }
         else
         {
            nextURL.clear();
         }
      }

      return true;
   }

   bool ensureAzureRoleAssignment(const String& scope, const String& principalID, const char *roleUUID, String& failure)
   {
      failure.clear();

      String roleDefinitionID = {};
      buildRoleDefinitionID(roleUUID, roleDefinitionID);

      bool exists = false;
      if (azureRoleAssignmentExists(scope, principalID, roleDefinitionID, exists, failure) == false)
      {
         return false;
      }

      if (exists)
      {
         return true;
      }

      String body = {};
      body.snprintf<
         "{\"properties\":{\"roleDefinitionId\":\"{}\",\"principalId\":\"{}\",\"principalType\":\"ServicePrincipal\"}}"_ctv>(
            roleDefinitionID,
            principalID);

      String lastFailure = {};
      for (uint32_t attempt = 0; attempt < 20; ++attempt)
      {
         String assignmentName = {};
         azureRenderRandomRoleAssignmentName(assignmentName);

         String url = {};
         url.snprintf<
            "https://management.azure.com{}/providers/Microsoft.Authorization/roleAssignments/{}?api-version=2022-04-01"_ctv>(
               scope,
               assignmentName);

         String response = {};
         String createFailure = {};
         if (sendARM("PUT", url, &body, response, createFailure))
         {
            failure.clear();
            return true;
         }

         bool nowExists = false;
         String verifyFailure = {};
         if (azureRoleAssignmentExists(scope, principalID, roleDefinitionID, nowExists, verifyFailure) && nowExists)
         {
            failure.clear();
            return true;
         }

         lastFailure = createFailure.size() > 0 ? createFailure : verifyFailure;
         if (attempt + 1 < 20)
         {
            // Fresh managed identities can lag before RBAC sees their principal.
            usleep(2 * 1000 * 1000);
         }
      }

      if (lastFailure.size() == 0)
      {
         lastFailure.assign("azure role assignment create failed"_ctv);
      }

      failure.assign(lastFailure);
      return false;
   }

public:

   bool ensureManagedClusterIdentity(String& failure)
   {
      failure.clear();

      if (runtimeEnvironment.azure.managedIdentityResourceID.size() == 0)
      {
         return true;
      }

      if (ensureScope(failure) == false)
      {
         return false;
      }

      if (ensureResourceGroup(failure) == false)
      {
         return false;
      }

      String identityName = {};
      if (azureExtractResourceIDSegment(runtimeEnvironment.azure.managedIdentityResourceID, "userAssignedIdentities", identityName) == false)
      {
         failure.assign("azure managed identity resource id is invalid"_ctv);
         return false;
      }

      String url = {};
      url.snprintf<"https://management.azure.com{}?api-version=2023-01-31"_ctv>(runtimeEnvironment.azure.managedIdentityResourceID);

      String body = {};
      body.snprintf<"{\"location\":\"{}\"}"_ctv>(location);

      String response = {};
      if (sendARM("PUT", url, &body, response, failure) == false)
      {
         return false;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element doc = {};
      if (azureParseJSONDocument(response, parser, doc, &failure, "azure managed identity response parse failed"_ctv) == false)
      {
         return false;
      }

      std::string_view principalIDView = {};
      if (doc["properties"]["principalId"].get(principalIDView) != simdjson::SUCCESS || principalIDView.empty())
      {
         failure.assign("azure managed identity response missing principalId"_ctv);
         return false;
      }

      String principalID = {};
      principalID.assign(principalIDView);

      String resourceGroupScope = {};
      resourceGroupScope.snprintf<"/subscriptions/{}/resourceGroups/{}"_ctv>(subscriptionID, resourceGroup);

      if (ensureAzureRoleAssignment(resourceGroupScope, principalID, "b24988ac-6180-42a0-ab88-20f7382dd24c", failure) == false)
      {
         return false;
      }

      if (ensureAzureRoleAssignment(runtimeEnvironment.azure.managedIdentityResourceID, principalID, "f1a07417-d97a-45cb-824c-7a7467783830", failure) == false)
      {
         return false;
      }

      return true;
   }

   void boot(void) override
   {
   }

   bool supportsAuthoritativeMachineSchemaCpuCapabilityInference(void) const override
   {
      return false;
   }

   void configureRuntimeEnvironment(const ProdigyRuntimeEnvironmentConfig& config) override
   {
      prodigyOwnRuntimeEnvironmentConfig(config, runtimeEnvironment);
      subscriptionID.clear();
      resourceGroup.clear();
      location.clear();
      credential = {};
      credentialLoaded = false;
      bearerToken.clear();
      bearerTokenExpiryMs = 0;
      subnetID.clear();
      networkSecurityGroupID.clear();
   }

   bool inferMachineSchemaCpuCapability(const MachineConfig& config, MachineSchemaCpuCapability& capability, String& error) override
   {
      capability = {};
      error.clear();

      if (config.providerMachineType.size() == 0)
      {
         error.assign("azure schema cpu inference requires providerMachineType"_ctv);
         return false;
      }

      if (ensureScope(error) == false)
      {
         return false;
      }

      String nextLink = {};
      azureBuildResourceSkusURL(subscriptionID, location, nextLink);
      while (nextLink.size() > 0)
      {
         String response = {};
         long httpCode = 0;
         if (sendARM("GET", nextLink, nullptr, response, error, &httpCode) == false)
         {
            if (httpCode < 200 || httpCode >= 300)
            {
               if (parseAzureErrorMessage(response, error) == false && error.size() == 0)
               {
                  error.assign("azure resource skus request failed"_ctv);
               }
            }
            return false;
         }

         simdjson::dom::parser parser;
         simdjson::dom::element doc = {};
         if (azureParseJSONDocument(response, parser, doc, &error, "azure resource skus response parse failed"_ctv) == false)
         {
            return false;
         }

         if (doc["value"].is_array())
         {
            for (auto sku : doc["value"].get_array())
            {
               String resourceType = {};
               std::string_view resourceTypeView = {};
               if (sku["resourceType"].get(resourceTypeView) != simdjson::SUCCESS)
               {
                  continue;
               }
               resourceType.assign(resourceTypeView);
               if (resourceType != "virtualMachines"_ctv)
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
               std::string_view nameView = {};
               if (sku["name"].get(nameView) != simdjson::SUCCESS)
               {
                  continue;
               }
               name.assign(nameView);
               if (name != config.providerMachineType)
               {
                  continue;
               }

               String architectureText = {};
               if (azureCapabilityString(sku, "CpuArchitectureType", architectureText) == false)
               {
                  (void)azureCapabilityString(sku, "Architecture", architectureText);
               }

               if (architectureText.size() == 0)
               {
                  error.assign("azure resource sku missing CpuArchitectureType capability"_ctv);
                  return false;
               }

               String lowerArchitecture = {};
               lowercaseString(architectureText, lowerArchitecture);
               if (lowerArchitecture == "arm64"_ctv)
               {
                  capability.architecture = MachineCpuArchitecture::aarch64;
               }
               else if (lowerArchitecture == "x64"_ctv || lowerArchitecture == "x86_64"_ctv || lowerArchitecture == "amd64"_ctv)
               {
                  capability.architecture = MachineCpuArchitecture::x86_64;
               }
               else
               {
                  error.snprintf<"azure CpuArchitectureType '{}' unsupported"_ctv>(architectureText);
                  return false;
               }

               capability.provenance = MachineSchemaCpuCapabilityProvenance::unavailable;
               return true;
            }
         }

         std::string_view nextLinkView = {};
         if (doc["nextLink"].get(nextLinkView) == simdjson::SUCCESS)
         {
            nextLink.assign(nextLinkView);
         }
         else
         {
            nextLink.clear();
         }
      }

      error.assign("azure resource sku not found"_ctv);
      return false;
   }

   void configureBootstrapSSHAccess(const String& user, const Vault::SSHKeyPackage& keyPackage, const Vault::SSHKeyPackage& hostKeyPackage, const String& privateKeyPath) override
   {
      prodigyResolveBootstrapSSHUser(user, bootstrapSSHUser);
      bootstrapSSHPrivateKeyPath = privateKeyPath;
      bootstrapSSHPublicKey.clear();
      bootstrapSSHHostKeyPackage.clear();
      if (prodigyBootstrapSSHKeyPackageConfigured(keyPackage))
      {
         bootstrapSSHPublicKey.assign(keyPackage.publicKeyOpenSSH);
      }
      if (prodigyBootstrapSSHKeyPackageConfigured(hostKeyPackage))
      {
         bootstrapSSHHostKeyPackage = hostKeyPackage;
      }
   }

   void configureProvisioningProgressSink(BrainIaaSMachineProvisioningProgressSink *sink) override
   {
      provisioningProgress.configureSink(sink);
   }

   void configureProvisioningClusterUUID(uint128_t clusterUUID) override
   {
      provisioningClusterUUIDTagValue.clear();
      if (clusterUUID != 0)
      {
         provisioningClusterUUIDTagValue.assignItoh(clusterUUID);
      }
   }

   bool supportsIncrementalProvisioningCallbacks() const override
   {
      return true;
   }

   void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bytell_hash_set<Machine *>& newMachines, String& error) override
   {
      (void)coro;
      provisioningProgress.reset();
      if (lifetime == MachineLifetime::owned)
      {
         error.assign("azure auto provisioning does not support MachineLifetime::owned"_ctv);
         return;
      }

      if (ensureScope(error) == false)
      {
         std::fprintf(stderr, "prodigy azure spinMachines-failure step=ensureScope schema=%.*s count=%u errorBytes=%zu error=%.*s\n",
            int(config.slug.size()),
            reinterpret_cast<const char *>(config.slug.data()),
            unsigned(count),
            size_t(error.size()),
            int(error.size()),
            error.c_str());
         std::fflush(stderr);
         return;
      }

      if (ensureSubnet(error) == false)
      {
         std::fprintf(stderr, "prodigy azure spinMachines-failure step=ensureSubnet schema=%.*s count=%u errorBytes=%zu error=%.*s\n",
            int(config.slug.size()),
            reinterpret_cast<const char *>(config.slug.data()),
            unsigned(count),
            size_t(error.size()),
            int(error.size()),
            error.c_str());
         std::fflush(stderr);
         return;
      }

      if (ensureNetworkSecurityGroup(error) == false)
      {
         std::fprintf(stderr, "prodigy azure spinMachines-failure step=ensureNetworkSecurityGroup schema=%.*s count=%u errorBytes=%zu error=%.*s\n",
            int(config.slug.size()),
            reinterpret_cast<const char *>(config.slug.data()),
            unsigned(count),
            size_t(error.size()),
            int(error.size()),
            error.c_str());
         std::fflush(stderr);
         return;
      }

      String imageReferenceJSON = {};
      if (buildAzureImageReference(config, imageReferenceJSON, error) == false)
      {
         std::fprintf(stderr, "prodigy azure spinMachines-failure step=buildAzureImageReference schema=%.*s count=%u errorBytes=%zu error=%.*s\n",
            int(config.slug.size()),
            reinterpret_cast<const char *>(config.slug.data()),
            unsigned(count),
            size_t(error.size()),
            int(error.size()),
            error.c_str());
         std::fflush(stderr);
         return;
      }

      String userData = {};
      if (bootstrapSSHPublicKey.size() > 0)
      {
         String cloudConfig = {};
         prodigyBuildBootstrapSSHCloudConfig(bootstrapSSHUser, bootstrapSSHPublicKey, bootstrapSSHHostKeyPackage, cloudConfig);
         Base64::encodePadded(cloudConfig.data(), cloudConfig.size(), userData);
      }

      class PendingCreateSubmission
      {
      public:

         String vmName = {};
         String providerMachineType = {};
         AzureHttp::MultiRequest request = {};
         bool processed = false;
      };

      Vector<PendingMachineProvisioning> pendingMachines = {};
      Vector<Machine *> readyMachines = {};
      Vector<PendingCreateSubmission> createRequests = {};
      createRequests.reserve(count);
      auto destroyPendingMachineByName = [&] (const String& vmName) -> void {

         if (vmName.size() == 0)
         {
            return;
         }

         String url = {};
         url.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}?api-version=2025-04-01"_ctv>(subscriptionID, resourceGroup, vmName);
         String response = {};
         String destroyFailure = {};
         (void)sendARM("DELETE", url, nullptr, response, destroyFailure);
      };
      auto cleanupProvisioningFailure = [&] () -> void {

         for (Machine *machine : readyMachines)
         {
            destroyMachine(machine);
            delete machine;
         }

         readyMachines.clear();
         for (const PendingCreateSubmission& submission : createRequests)
         {
            destroyPendingMachineByName(submission.vmName);
         }
         createRequests.clear();
         pendingMachines.clear();
      };

      if (config.slug.size() == 0)
      {
         error.assign("azure machine schema slug missing"_ctv);
         cleanupProvisioningFailure();
         return;
      }

      if (config.providerMachineType.size() == 0)
      {
         error.assign("azure providerMachineType missing"_ctv);
         cleanupProvisioningFailure();
         return;
      }

      AzureMachineTypeResources requestedMachineTypeResources = {};
      if (resolveMachineTypeResources(config.providerMachineType, requestedMachineTypeResources, error) == false)
      {
         cleanupProvisioningFailure();
         return;
      }

      if (ensureBearerToken(error) == false)
      {
         cleanupProvisioningFailure();
         return;
      }

      auto processCreateCompletion = [&] (PendingCreateSubmission& submission) -> void {

         if (submission.processed)
         {
            return;
         }
         submission.processed = true;

         if (submission.request.curlCode != CURLE_OK || submission.request.httpCode < 200 || submission.request.httpCode >= 300)
         {
            if (error.size() == 0)
            {
               if (parseAzureErrorMessage(submission.request.response, error) == false)
               {
                  error.assign(submission.request.transportFailure.size() > 0 ? submission.request.transportFailure : "azure vm create failed"_ctv);
               }
               if (submission.request.httpCode > 0)
               {
                  error.snprintf_add<" [http={itoa}]"_ctv>(uint32_t(submission.request.httpCode));
               }
            }
            return;
         }

         PendingMachineProvisioning& pending = pendingMachines.emplace_back();
         pending.vmName = submission.vmName;
         pending.providerMachineType = submission.providerMachineType;
         String cloudID = {};
         cloudID.snprintf<"/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}"_ctv>(
            subscriptionID,
            resourceGroup,
            submission.vmName);
         provisioningProgress.notifyMachineProvisioningAccepted(cloudID);
      };

      auto drainCreateCompletions = [&] (AzureHttp::MultiClient& createClient) -> void {

         while (AzureHttp::MultiRequest *completed = createClient.popCompleted())
         {
            PendingCreateSubmission *submission = reinterpret_cast<PendingCreateSubmission *>(completed->context);
            if (submission != nullptr)
            {
               processCreateCompletion(*submission);
            }
         }
      };

      AzureHttp::MultiClient createClient = {};
      for (uint32_t index = 0; index < count; ++index)
      {
         String providerMachineType = config.providerMachineType;
         String vmNameFragment = {};
         azureBuildSafeVMNameFragment(config.slug, 47, vmNameFragment);

         String vmName = {};
         vmName.snprintf<"ntg-az-{}-{itoa}"_ctv>(
            vmNameFragment,
            uint64_t(Random::generateNumberWithNBits<24, uint32_t>()));
         MachineProvisioningProgress& progress = provisioningProgress.upsert(config.slug, providerMachineType, vmName, String());
         progress.status.assign("launch-submitted"_ctv);
         progress.ready = false;
         provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());

         String url = {};
         url.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}?api-version=2025-04-01"_ctv>(subscriptionID, resourceGroup, vmName);

         uint32_t diskGB = (config.nStorageMB + 1023) / 1024;
         if (diskGB == 0) diskGB = 30;

         String body = {};
         body.append("{\"location\":"_ctv);
         prodigyAppendEscapedJSONStringLiteral(body, location);
         body.append(",\"tags\":{\"app\":\"prodigy\""_ctv);
         if (provisioningClusterUUIDTagValue.size() > 0)
         {
            body.append(",\"prodigy_cluster_uuid\":"_ctv);
            prodigyAppendEscapedJSONStringLiteral(body, provisioningClusterUUIDTagValue);
         }
         body.append("}"_ctv);
         if (runtimeEnvironment.azure.managedIdentityResourceID.size() > 0)
         {
            body.append(",\"identity\":{\"type\":\"UserAssigned\",\"userAssignedIdentities\":{"_ctv);
            prodigyAppendEscapedJSONStringLiteral(body, runtimeEnvironment.azure.managedIdentityResourceID);
            body.append(":{}}}"_ctv);
         }
         body.append(",\"properties\":{\"hardwareProfile\":{\"vmSize\":"_ctv);
         prodigyAppendEscapedJSONStringLiteral(body, providerMachineType);
         body.append("},\"storageProfile\":{\"imageReference\":"_ctv);
         body.append(imageReferenceJSON);
         body.append(",\"osDisk\":{\"createOption\":\"FromImage\",\"deleteOption\":\"Delete\",\"diskSizeGB\":"_ctv);
         String diskSize = {};
         diskSize.assignItoa(diskGB);
         body.append(diskSize);
         body.append("}},\"osProfile\":{\"computerName\":"_ctv);
         prodigyAppendEscapedJSONStringLiteral(body, vmName);
         body.append(",\"adminUsername\":\"prodigyadmin\",\"linuxConfiguration\":{\"disablePasswordAuthentication\":true,\"ssh\":{\"publicKeys\":[{\"path\":\"/home/prodigyadmin/.ssh/authorized_keys\",\"keyData\":"_ctv);
         prodigyAppendEscapedJSONStringLiteral(body, bootstrapSSHPublicKey);
         body.append("}]}}}"_ctv);
         if (userData.size() > 0)
         {
            body.append(",\"userData\":"_ctv);
            prodigyAppendEscapedJSONStringLiteral(body, userData);
         }
         body.append(",\"networkProfile\":{\"networkApiVersion\":\"2024-05-01\",\"networkInterfaceConfigurations\":[{\"name\":\"prodigy-nic\",\"properties\":{\"deleteOption\":\"Delete\",\"primary\":true,\"ipConfigurations\":[{\"name\":\"prodigy-ipconfig\",\"properties\":{\"subnet\":{\"id\":"_ctv);
         prodigyAppendEscapedJSONStringLiteral(body, subnetID);
         body.append("},\"publicIPAddressConfiguration\":{\"name\":\"prodigy-pip\",\"properties\":{\"deleteOption\":\"Delete\",\"publicIPAllocationMethod\":\"Static\"}}}}],\"networkSecurityGroup\":{\"id\":"_ctv);
         prodigyAppendEscapedJSONStringLiteral(body, networkSecurityGroupID);
         body.append("}}}]}"_ctv);
         if (lifetime == MachineLifetime::spot)
         {
            body.append(",\"priority\":\"Spot\",\"evictionPolicy\":\"Delete\""_ctv);
         }
         body.append("}}"_ctv);

         PendingCreateSubmission& submission = createRequests.emplace_back();
         submission.vmName = vmName;
         submission.providerMachineType = providerMachineType;
         submission.request.resetResult();
         submission.request.context = &submission;
         submission.request.method.assign("PUT"_ctv);
         submission.request.url = url;
         submission.request.body = body;
         submission.request.timeoutMs = AzureHttp::timeoutMs;
         buildAuthHeaders(submission.request.headers);
         if (submission.request.headers == nullptr)
         {
            error.assign("azure auth headers missing"_ctv);
            break;
         }

         if (createClient.start(submission.request) == false)
         {
            error.assign("azure create request start failed"_ctv);
            break;
         }
      }

      while (error.size() == 0 && createClient.pendingCount() > 0)
      {
         if (createClient.pump(50) == false)
         {
            error.assign("azure create request pump failed"_ctv);
            break;
         }

         drainCreateCompletions(createClient);
      }

      if (error.size() == 0)
      {
         drainCreateCompletions(createClient);
      }

      if (error.size() != 0)
      {
         std::fprintf(stderr, "prodigy azure spinMachines-failure step=createVM providerMachineType=%.*s errorBytes=%zu error=%.*s\n",
            int(config.providerMachineType.size()),
            reinterpret_cast<const char *>(config.providerMachineType.data()),
            size_t(error.size()),
            int(error.size()),
            error.c_str());
         std::fflush(stderr);
         cleanupProvisioningFailure();
         return;
      }

      if (pendingMachines.size() != count)
      {
         error.snprintf<"azure create returned {itoa} accepted machines but {itoa} were requested"_ctv>(
            uint32_t(pendingMachines.size()),
            count);
         cleanupProvisioningFailure();
         return;
      }

      if (error.size() == 0 && pendingMachines.size() > 0)
      {
         ConcurrentWaitCoordinator coordinator(this);
         (void)coordinator.run(config.slug, lifetime, pendingMachines, readyMachines, error);
      }

      if (error.size() != 0)
      {
         cleanupProvisioningFailure();
         return;
      }

      for (Machine *machine : readyMachines)
      {
         newMachines.insert(machine);
      }
   }

   void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines) override
   {
      (void)coro;
      String failure;
      if (ensureScope(failure) == false)
      {
         return;
      }

      String url = {};
      url.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines?api-version=2025-04-01"_ctv>(subscriptionID, resourceGroup);
      String response;
      if (sendARM("GET", url, nullptr, response, failure) == false)
      {
         return;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (azureParseVMListDocument(response, parser, doc, &failure) == false)
      {
         return;
      }

      if (auto values = doc["value"]; values.is_array())
      {
         for (auto vm : values.get_array())
         {
            std::string_view appTag;
            if (vm["tags"]["app"].get(appTag) || appTag != "prodigy")
            {
               continue;
            }

            std::string_view vmLocation;
            if (!vm["location"].get(vmLocation) && metro.size() > 0 && metro != String(vmLocation))
            {
               continue;
            }

            machines.insert(buildMachineFromVM(vm));
         }
      }
   }

   void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains) override
   {
      (void)coro;
      selfIsBrain = false;

      bytell_hash_set<Machine *> machines;
      getMachines(nullptr, location, machines);
      for (Machine *machine : machines)
      {
         if (machine->isBrain == false)
         {
            delete machine;
            continue;
         }

         if (machine->uuid == selfUUID)
         {
            selfIsBrain = true;
            delete machine;
            continue;
         }

         BrainView *brain = new BrainView();
         brain->uuid = machine->uuid;
         brain->private4 = machine->private4;
         (void)prodigyResolveMachinePeerAddress(*machine, brain->peerAddress, &brain->peerAddressText);
         brain->connectTimeoutMs = BrainBase::controlPlaneConnectTimeoutMs();
         brain->nDefaultAttemptsBudget = BrainBase::controlPlaneConnectAttemptsBudget();
         brains.insert(brain);
         delete machine;
      }
   }

   void hardRebootMachine(uint128_t uuid) override
   {
      bytell_hash_set<Machine *> machines;
      getMachines(nullptr, location, machines);
      String cloudID = {};
      for (Machine *machine : machines)
      {
         if (machine->uuid == uuid)
         {
            cloudID = machine->cloudID;
         }

         delete machine;
      }

      if (cloudID.size() == 0)
      {
         return;
      }

      String url = {};
      url.snprintf<"https://management.azure.com{}/restart?api-version=2025-04-01"_ctv>(cloudID);
      String response;
      String failure;
      String body = "{}"_ctv;
      (void)sendARM("POST", url, &body, response, failure);
   }

   void reportHardwareFailure(uint128_t uuid, const String& report) override
   {
      (void)uuid;
      (void)report;
   }

   void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) override
   {
      (void)coro;
      (void)decommissionedIDs;
   }

   void destroyMachine(Machine *machine) override
   {
      if (machine == nullptr || machine->cloudID.size() == 0)
      {
         return;
      }

      String url = {};
      url.snprintf<"https://management.azure.com{}?api-version=2025-04-01"_ctv>(machine->cloudID);
      String response;
      String failure;
      (void)sendARM("DELETE", url, nullptr, response, failure);
   }

   bool destroyClusterMachines(const String& clusterUUID, uint32_t& destroyed, String& error) override
   {
      destroyed = 0;

      if (ensureScope(error) == false)
      {
         return false;
      }

      if (clusterUUID.size() == 0)
      {
         error.assign("azure clusterUUID tag value required"_ctv);
         return false;
      }

      String listURL = {};
      listURL.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines?api-version=2025-04-01"_ctv>(subscriptionID, resourceGroup);

      Vector<String> cloudIDs = {};
      auto collectCloudIDs = [&] (String& failure) -> bool {
         cloudIDs.clear();

         String response = {};
         if (sendARM("GET", listURL, nullptr, response, failure) == false)
         {
            return false;
         }

         simdjson::dom::parser parser;
         simdjson::dom::element doc;
         if (azureParseJSONDocument(response, parser, doc, &failure, "azure vm list json parse failed"_ctv) == false)
         {
            return false;
         }

         if (auto values = doc["value"]; values.is_array())
         {
            for (auto vm : values.get_array())
            {
               std::string_view appValue = {};
               if (vm["tags"]["app"].get(appValue) || appValue != "prodigy")
               {
                  continue;
               }

               std::string_view clusterValue = {};
               if (vm["tags"]["prodigy_cluster_uuid"].get(clusterValue) || clusterValue != std::string_view(reinterpret_cast<const char *>(clusterUUID.data()), size_t(clusterUUID.size())))
               {
                  continue;
               }

               std::string_view cloudIDView = {};
               if (!vm["id"].get(cloudIDView) && cloudIDView.size() > 0)
               {
                  cloudIDs.push_back(String(cloudIDView));
               }
            }
         }

         return true;
      };

      if (collectCloudIDs(error) == false)
      {
         return false;
      }

      if (cloudIDs.size() == 0)
      {
         return true;
      }

      destroyed = uint32_t(cloudIDs.size());

      for (const String& cloudID : cloudIDs)
      {
         String url = {};
         url.snprintf<"https://management.azure.com{}?api-version=2025-04-01"_ctv>(cloudID);
         String response = {};
         if (sendARM("DELETE", url, nullptr, response, error) == false)
         {
            return false;
         }
      }

      for (uint32_t attempt = 0; attempt < 60; ++attempt)
      {
         if (collectCloudIDs(error) == false)
         {
            return false;
         }

         if (cloudIDs.size() == 0)
         {
            return true;
         }

         usleep(2 * 1000 * 1000);
      }

      error.assign("timed out waiting for azure cluster machines to terminate"_ctv);
      return false;
   }

   bool ensureProdigyMachineTags(const String& clusterUUID, Machine *machine, String& error) override
   {
      if (ensureScope(error) == false)
      {
         return false;
      }

      if (machine == nullptr || machine->cloudID.size() == 0)
      {
         error.assign("azure machine cloudID required"_ctv);
         return false;
      }

      return ensureVMTags(machine->cloudID, clusterUUID, error);
   }

   bool assignProviderElasticAddress(Machine *machine,
      ExternalAddressFamily family,
      const String& requestedAddress,
      const String& providerPool,
      IPAddress& assignedAddress,
      String& allocationID,
      String& associationID,
      bool& releaseOnRemove,
      String& error) override
   {
      assignedAddress = {};
      allocationID.clear();
      associationID.clear();
      releaseOnRemove = false;
      error.clear();

      if (ensureScope(error) == false)
      {
         return false;
      }

      if (machine == nullptr || machine->cloudID.size() == 0)
      {
         error.assign("azure elastic address requires a cloud-backed target machine"_ctv);
         return false;
      }

      if (family != ExternalAddressFamily::ipv4)
      {
         error.assign("azure elastic addresses currently support only ipv4"_ctv);
         return false;
      }

      if (requestedAddress.size() > 0 && providerPool.size() > 0)
      {
         error.assign("azure elastic address cannot combine requestedAddress with providerPool"_ctv);
         return false;
      }

      String nicID = {};
      String ipConfigName = {};
      if (fetchMachinePrimaryNICAndConfig(machine->cloudID, nicID, ipConfigName, error) == false)
      {
         return false;
      }

      associationID.snprintf<"{}/ipConfigurations/{}"_ctv>(nicID, ipConfigName);

      String publicAddress = {};
      String existingIPConfigurationID = {};
      if (requestedAddress.size() > 0)
      {
         if (fetchPublicIPAddressByConcreteAddress(requestedAddress, allocationID, existingIPConfigurationID, publicAddress, error) == false)
         {
            return false;
         }

         releaseOnRemove = false;
      }
      else
      {
         if (createPublicIPAddress(providerPool, allocationID, publicAddress, error) == false)
         {
            return false;
         }

         releaseOnRemove = true;
      }

      auto cleanupOnFailure = [&] () -> void {
         if (associationID.size() > 0)
         {
            String detachFailure = {};
            (void)detachPublicIPAddressAssociation(associationID, detachFailure);
         }

         if (releaseOnRemove && allocationID.size() > 0)
         {
            String deleteFailure = {};
            (void)deletePublicIPAddressResource(allocationID, deleteFailure);
         }
      };

      if (existingIPConfigurationID.size() > 0 && existingIPConfigurationID.equals(associationID) == false)
      {
         if (detachPublicIPAddressAssociation(existingIPConfigurationID, error) == false)
         {
            cleanupOnFailure();
            return false;
         }
      }

      if (existingIPConfigurationID.equals(associationID) == false)
      {
         if (patchNICPublicIPAddress(nicID, ipConfigName, &allocationID, error) == false)
         {
            cleanupOnFailure();
            return false;
         }
      }

      if (waitForPublicIPAddressState(allocationID, associationID, true, &publicAddress, error) == false)
      {
         cleanupOnFailure();
         return false;
      }

      if (ClusterMachine::parseIPAddressLiteral(publicAddress, assignedAddress) == false)
      {
         error.assign("azure elastic address parse failed"_ctv);
         cleanupOnFailure();
         return false;
      }

      return true;
   }

   bool releaseProviderElasticAddress(const RegisteredRoutableAddress& address, String& error) override
   {
      error.clear();
      if (address.kind != RoutableAddressKind::providerElasticAddress)
      {
         return true;
      }

      if (address.providerAssociationID.size() > 0)
      {
         if (detachPublicIPAddressAssociation(address.providerAssociationID, error) == false)
         {
            return false;
         }
      }

      if (address.providerAllocationID.size() > 0)
      {
         (void)waitForPublicIPAddressState(address.providerAllocationID, String(), false, nullptr, error);
         if (error.size() > 0)
         {
            return false;
         }
      }

      if (address.releaseOnRemove)
      {
         if (deletePublicIPAddressResource(address.providerAllocationID, error) == false)
         {
            return false;
         }
      }

      return true;
   }

   uint32_t supportedMachineKindsMask() const override
   {
      return 3u;
   }

   bool supportsAutoProvision() const override
   {
      return true;
   }
};
