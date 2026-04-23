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
#include <cstdio>
#include <sys/wait.h>
#include <unistd.h>

static inline int64_t awsParseRFC3339Ms(const String& value);

class AwsCredentialMaterial
{
public:

   String accessKeyID;
   String secretAccessKey;
   String sessionToken;
   int64_t expirationMs = 0;

   bool valid(void) const
   {
      return accessKeyID.size() > 0 && secretAccessKey.size() > 0;
   }
};

static inline bool parseAwsCredentialMaterial(const String& material, AwsCredentialMaterial& credential, String *failure = nullptr)
{
   credential = {};
   if (failure) failure->clear();

   if (material.size() == 0)
   {
      if (failure) failure->assign("aws credential material required"_ctv);
      return false;
   }

   if (material[0] == '{')
   {
      String materialText = {};
      materialText.assign(material);
      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (parser.parse(materialText.c_str(), materialText.size()).get(doc))
      {
         if (failure) failure->assign("aws credential material json parse failed"_ctv);
         return false;
      }

      std::string_view accessKeyID;
      std::string_view secretAccessKey;
      std::string_view sessionToken;
      std::string_view expiration;
      if (doc["accessKeyId"].get(accessKeyID)
         && doc["accessKeyID"].get(accessKeyID)
         && doc["AccessKeyId"].get(accessKeyID)
         && doc["awsAccessKeyId"].get(accessKeyID))
      {
         accessKeyID = {};
      }

      if (doc["secretAccessKey"].get(secretAccessKey)
         && doc["SecretAccessKey"].get(secretAccessKey)
         && doc["awsSecretAccessKey"].get(secretAccessKey))
      {
         secretAccessKey = {};
      }

      if (doc["sessionToken"].get(sessionToken)
         && doc["SessionToken"].get(sessionToken)
         && doc["Token"].get(sessionToken)
         && doc["token"].get(sessionToken))
      {
         sessionToken = {};
      }

      if (doc["expiration"].get(expiration)
         && doc["Expiration"].get(expiration))
      {
         expiration = {};
      }

      credential.accessKeyID.assign(accessKeyID);
      credential.secretAccessKey.assign(secretAccessKey);
      credential.sessionToken.assign(sessionToken);
      if (expiration.size() > 0)
      {
         credential.expirationMs = awsParseRFC3339Ms(String(expiration));
      }
   }
   else
   {
      String materialText = {};
      materialText.assign(material);
      int64_t firstColon = materialText.findChar(':');
      if (firstColon < 0)
      {
         if (failure) failure->assign("aws credential material requires accessKeyId:secretAccessKey or json"_ctv);
         return false;
      }

      int64_t secondColon = materialText.findChar(':', uint64_t(firstColon + 1));
      credential.accessKeyID.assign(material.substr(0, uint64_t(firstColon), Copy::yes));
      if (secondColon < 0)
      {
         credential.secretAccessKey.assign(material.substr(uint64_t(firstColon + 1), material.size() - uint64_t(firstColon + 1), Copy::yes));
      }
      else
      {
         credential.secretAccessKey.assign(material.substr(uint64_t(firstColon + 1), uint64_t(secondColon - firstColon - 1), Copy::yes));
         credential.sessionToken.assign(material.substr(uint64_t(secondColon + 1), material.size() - uint64_t(secondColon + 1), Copy::yes));
      }
   }

   if (credential.valid() == false)
   {
      if (failure) failure->assign("aws credential material missing access key or secret key"_ctv);
      return false;
   }

   return true;
}

static inline uint32_t awsHashRackIdentity(const String& value)
{
   uint32_t hash = 0;
   for (uint64_t index = 0; index < value.size(); ++index)
   {
      hash = (hash * 131u) + uint8_t(value[index]);
   }

   return hash;
}

static inline uint32_t awsRackUUIDFromAvailabilityZone(const String& availabilityZone)
{
   return awsHashRackIdentity(availabilityZone);
}

class AwsHttp
{
public:

   static bool send(const char *method, const String& url, const String& region, const String& service, const AwsCredentialMaterial& credential, const struct curl_slist *headers, const String *body, String& out, long *httpCode = nullptr)
   {
      CURL *curl = curl_easy_init();
      if (curl == nullptr)
      {
         return false;
      }

      out.clear();

      struct curl_slist *localHeaders = nullptr;
      for (const struct curl_slist *header = headers; header != nullptr; header = header->next)
      {
         localHeaders = curl_slist_append(localHeaders, header->data);
      }

      if (credential.sessionToken.size() > 0)
      {
         String sessionHeader = {};
         sessionHeader.snprintf<"X-Amz-Security-Token: {}"_ctv>(credential.sessionToken);
         localHeaders = curl_slist_append(localHeaders, sessionHeader.c_str());
      }

      String urlText = {};
      urlText.assign(url);
      String regionText = {};
      regionText.assign(region);
      String serviceText = {};
      serviceText.assign(service);
      String accessKeyIDText = {};
      accessKeyIDText.assign(credential.accessKeyID);
      String secretAccessKeyText = {};
      secretAccessKeyText.assign(credential.secretAccessKey);
      String sigv4 = {};
      sigv4.snprintf<"aws:amz:{}:{}"_ctv>(region, service);

      curl_easy_setopt(curl, CURLOPT_URL, urlText.c_str());
      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
      curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 8000L);
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, localHeaders);
      curl_easy_setopt(curl, CURLOPT_AWS_SIGV4, sigv4.c_str());
      curl_easy_setopt(curl, CURLOPT_USERNAME, accessKeyIDText.c_str());
      curl_easy_setopt(curl, CURLOPT_PASSWORD, secretAccessKeyText.c_str());
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[] (char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
         String *s = reinterpret_cast<String *>(userdata);
         s->append(reinterpret_cast<uint8_t *>(ptr), size * nmemb);
         return size * nmemb;
      });
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);

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

      curl_slist_free_all(localHeaders);
      curl_easy_cleanup(curl);
      return (rc == CURLE_OK);
   }
};

class AwsMetadataClient
{
private:

   String token;

public:

   bool ensureToken(void)
   {
      if (token.size() > 0)
      {
         return true;
      }

      struct curl_slist *headers = nullptr;
      headers = curl_slist_append(headers, "X-aws-ec2-metadata-token-ttl-seconds: 21600");

      CURL *curl = curl_easy_init();
      if (curl == nullptr)
      {
         curl_slist_free_all(headers);
         return false;
      }

      String response;
      curl_easy_setopt(curl, CURLOPT_URL, "http://169.254.169.254/latest/api/token");
      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
      curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000L);
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[] (char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
         String *s = reinterpret_cast<String *>(userdata);
         s->append(reinterpret_cast<uint8_t *>(ptr), size * nmemb);
         return size * nmemb;
      });
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

      CURLcode rc = curl_easy_perform(curl);
      long httpCode = 0;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
      curl_slist_free_all(headers);
      curl_easy_cleanup(curl);
      if (rc != CURLE_OK || httpCode < 200 || httpCode >= 300 || response.size() == 0)
      {
         return false;
      }

      token = response;
      return true;
   }

   bool get(const char *path, String& out)
   {
      for (uint32_t attempt = 0; attempt < 2; ++attempt)
      {
         if (ensureToken() == false)
         {
            return false;
         }

         String header = {};
         header.snprintf<"X-aws-ec2-metadata-token: {}"_ctv>(token);

         struct curl_slist *headers = nullptr;
         headers = curl_slist_append(headers, header.c_str());

         String url = {};
         url.assign("http://169.254.169.254"_ctv);
         url.append(path);

         CURL *curl = curl_easy_init();
         if (curl == nullptr)
         {
            curl_slist_free_all(headers);
            return false;
         }

         out.clear();
         String urlText = {};
         urlText.assign(url);
         curl_easy_setopt(curl, CURLOPT_URL, urlText.c_str());
         curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000L);
         curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
         curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[] (char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
            String *s = reinterpret_cast<String *>(userdata);
            s->append(reinterpret_cast<uint8_t *>(ptr), size * nmemb);
            return size * nmemb;
         });
         curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);

         CURLcode rc = curl_easy_perform(curl);
         long httpCode = 0;
         curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
         curl_slist_free_all(headers);
         curl_easy_cleanup(curl);
         if (rc == CURLE_OK && httpCode >= 200 && httpCode < 300)
         {
            return true;
         }

         if (httpCode == 401 || httpCode == 403)
         {
            token.clear();
            continue;
         }

         break;
      }

      out.clear();
      return false;
   }
};

static inline bool awsScopeRegion(const String& scope, String& region)
{
   region.clear();
   if (scope.size() == 0)
   {
      return false;
   }

   int64_t slash = scope.rfindChar('/');
   if (slash >= 0 && uint64_t(slash + 1) < scope.size())
   {
      region.assign(scope.substr(uint64_t(slash + 1), scope.size() - uint64_t(slash + 1), Copy::yes));
      return region.size() > 0;
   }

   region.assign(scope);
   return region.size() > 0;
}

static inline void awsAppendPercentEncoded(String& out, const String& value)
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

static inline void awsAppendQueryParam(String& body, const String& key, const String& value, bool& first)
{
   if (first == false)
   {
      body.append('&');
   }

   first = false;
   awsAppendPercentEncoded(body, key);
   body.append('=');
   awsAppendPercentEncoded(body, value);
}

class AwsPricingFilter
{
public:

   String field;
   String value;
};

static inline void awsAppendJSONString(String& out, const String& value)
{
   static constexpr char hex[] = "0123456789ABCDEF";

   out.append('"');
   for (uint64_t index = 0; index < value.size(); ++index)
   {
      uint8_t byte = uint8_t(value[index]);
      switch (byte)
      {
         case '\\':
            out.append("\\\\"_ctv);
            break;
         case '"':
            out.append("\\\""_ctv);
            break;
         case '\b':
            out.append("\\b"_ctv);
            break;
         case '\f':
            out.append("\\f"_ctv);
            break;
         case '\n':
            out.append("\\n"_ctv);
            break;
         case '\r':
            out.append("\\r"_ctv);
            break;
         case '\t':
            out.append("\\t"_ctv);
            break;
         default:
            if (byte < 0x20)
            {
               out.append("\\u00"_ctv);
               out.append(hex[(byte >> 4) & 0x0f]);
               out.append(hex[byte & 0x0f]);
            }
            else
            {
               out.append(char(byte));
            }
            break;
      }
   }
   out.append('"');
}

static inline void awsBuildPricingGetProductsRequestBody(
   const String& serviceCode,
   std::initializer_list<AwsPricingFilter> filters,
   String& body,
   const String *nextToken = nullptr)
{
   body.clear();
   body.append("{\"ServiceCode\":"_ctv);
   awsAppendJSONString(body, serviceCode);
   body.append(",\"FormatVersion\":\"aws_v1\",\"MaxResults\":100,\"Filters\":["_ctv);

   bool first = true;
   for (const AwsPricingFilter& filter : filters)
   {
      if (first == false)
      {
         body.append(',');
      }
      first = false;
      body.append("{\"Type\":\"TERM_MATCH\",\"Field\":"_ctv);
      awsAppendJSONString(body, filter.field);
      body.append(",\"Value\":"_ctv);
      awsAppendJSONString(body, filter.value);
      body.append('}');
   }

   body.append(']');
   if (nextToken != nullptr && nextToken->size() > 0)
   {
      body.append(",\"NextToken\":"_ctv);
      awsAppendJSONString(body, *nextToken);
   }

   body.append('}');
}

static inline bool awsSendPricingGetProductsRequest(
   const AwsCredentialMaterial& credential,
   const String& requestBody,
   String& response,
   String& failure,
   long *httpCode = nullptr)
{
   response.clear();
   failure.clear();

   struct curl_slist *headers = nullptr;
   headers = curl_slist_append(headers, "Content-Type: application/x-amz-json-1.1");
   headers = curl_slist_append(headers, "X-Amz-Target: AWSPriceListService.GetProducts");

   long localHTTPCode = 0;
   bool ok = AwsHttp::send(
      "POST",
      "https://api.pricing.us-east-1.amazonaws.com/"_ctv,
      "us-east-1"_ctv,
      "pricing"_ctv,
      credential,
      headers,
      &requestBody,
      response,
      &localHTTPCode);
   curl_slist_free_all(headers);

   if (httpCode != nullptr)
   {
      *httpCode = localHTTPCode;
   }

   if (ok == false)
   {
      failure.assign("aws pricing request transport failed"_ctv);
      return false;
   }

   if (localHTTPCode < 200 || localHTTPCode >= 300)
   {
      failure.assign("aws pricing request failed"_ctv);
      if (response.size() > 0)
      {
         failure.append(": "_ctv);
         failure.append(response);
      }
      return false;
   }

   return true;
}

static inline uint64_t awsFindToken(const String& text, const char *token, uint64_t start = 0, uint64_t limit = UINT64_MAX)
{
   uint64_t tokenLength = uint64_t(strlen(token));
   if (limit > text.size())
   {
      limit = text.size();
   }

   if (tokenLength == 0 || limit < tokenLength || start > limit - tokenLength)
   {
      return uint64_t(-1);
   }

   for (uint64_t index = start; index + tokenLength <= limit; ++index)
   {
      if (memcmp(text.data() + index, token, tokenLength) == 0)
      {
         return index;
      }
   }

   return uint64_t(-1);
}

static inline bool awsExtractTagValue(const String& block, const String& key, String& value)
{
   uint64_t tagSetStart = awsFindToken(block, "<tagSet>");
   uint64_t tagSetEnd = awsFindToken(block, "</tagSet>", tagSetStart == uint64_t(-1) ? 0 : tagSetStart);
   if (tagSetStart == uint64_t(-1) || tagSetEnd == uint64_t(-1))
   {
      return false;
   }

   uint64_t search = tagSetStart;
   while (search < tagSetEnd)
   {
      uint64_t itemStart = awsFindToken(block, "<item>", search, tagSetEnd);
      if (itemStart == uint64_t(-1))
      {
         break;
      }

      uint64_t itemEnd = awsFindToken(block, "</item>", itemStart, tagSetEnd);
      if (itemEnd == uint64_t(-1))
      {
         break;
      }

      uint64_t keyStart = awsFindToken(block, "<key>", itemStart, itemEnd);
      uint64_t keyEnd = awsFindToken(block, "</key>", keyStart, itemEnd);
      uint64_t valueStart = awsFindToken(block, "<value>", itemStart, itemEnd);
      uint64_t valueEnd = awsFindToken(block, "</value>", valueStart, itemEnd);
      if (keyStart != uint64_t(-1) && keyEnd != uint64_t(-1) && valueStart != uint64_t(-1) && valueEnd != uint64_t(-1))
      {
         String candidateKey = block.substr(keyStart + 5, keyEnd - (keyStart + 5), Copy::yes);
         if (candidateKey == key)
         {
            value.assign(block.substr(valueStart + 7, valueEnd - (valueStart + 7), Copy::yes));
            return true;
         }
      }

      search = itemEnd + 7;
   }

   return false;
}

static inline bool awsExtractXMLValue(const String& text, const char *tag, String& value, uint64_t start, uint64_t limit);

static inline bool awsExtractInstanceStateName(const String& block, String& stateName)
{
   uint64_t stateStart = awsFindToken(block, "<instanceState>");
   uint64_t stateEnd = awsFindToken(block, "</instanceState>", stateStart == uint64_t(-1) ? 0 : stateStart);
   if (stateStart == uint64_t(-1) || stateEnd == uint64_t(-1))
   {
      return false;
   }

   return awsExtractXMLValue(block, "name", stateName, stateStart, stateEnd);
}

static inline bool awsExtractXMLValue(const String& text, const char *tag, String& value, uint64_t start = 0, uint64_t limit = UINT64_MAX)
{
   String openTag = {};
   openTag.snprintf<"<{}>"_ctv>(String(tag));
   String closeTag = {};
   closeTag.snprintf<"</{}>"_ctv>(String(tag));

   uint64_t open = awsFindToken(text, openTag.c_str(), start, limit);
   if (open == uint64_t(-1))
   {
      return false;
   }

   uint64_t contentStart = open + openTag.size();
   uint64_t close = awsFindToken(text, closeTag.c_str(), contentStart, limit);
   if (close == uint64_t(-1))
   {
      return false;
   }

   value.assign(text.substr(contentStart, close - contentStart, Copy::yes));
   return true;
}

static inline void awsCollectSetItemBlocks(const String& xml, const char *setTag, Vector<String>& blocks)
{
   blocks.clear();

   String openSet = {};
   openSet.snprintf<"<{}>"_ctv>(String(setTag));
   String closeSet = {};
   closeSet.snprintf<"</{}>"_ctv>(String(setTag));

   uint64_t search = 0;
   while (true)
   {
      uint64_t setStart = awsFindToken(xml, openSet.c_str(), search);
      if (setStart == uint64_t(-1))
      {
         break;
      }

      uint64_t setEnd = awsFindToken(xml, closeSet.c_str(), setStart);
      if (setEnd == uint64_t(-1))
      {
         break;
      }

      uint64_t cursor = setStart + openSet.size();
      uint32_t depth = 0;
      uint64_t itemContentStart = 0;

      while (cursor < setEnd)
      {
         uint64_t nextOpen = awsFindToken(xml, "<item>", cursor, setEnd);
         uint64_t nextClose = awsFindToken(xml, "</item>", cursor, setEnd);
         if (nextOpen == uint64_t(-1) && nextClose == uint64_t(-1))
         {
            break;
         }

         if (nextOpen != uint64_t(-1) && (nextClose == uint64_t(-1) || nextOpen < nextClose))
         {
            depth += 1;
            if (depth == 1)
            {
               itemContentStart = nextOpen + strlen("<item>");
            }

            cursor = nextOpen + strlen("<item>");
            continue;
         }

         if (nextClose != uint64_t(-1))
         {
            if (depth == 1 && nextClose >= itemContentStart)
            {
               blocks.push_back(xml.substr(itemContentStart, nextClose - itemContentStart, Copy::yes));
            }

            if (depth > 0)
            {
               depth -= 1;
            }

            cursor = nextClose + strlen("</item>");
            continue;
         }
      }

      search = setEnd + closeSet.size();
   }
}

static inline void awsCollectInstanceBlocks(const String& xml, Vector<String>& blocks)
{
   awsCollectSetItemBlocks(xml, "instancesSet", blocks);
}

static inline int64_t awsParseRFC3339Ms(const String& value)
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

static inline bool awsStringHasContent(const String& value)
{
   return value.size() > 0 && value[0] != '\0';
}

static inline void awsTrimTrailingAsciiWhitespace(String& value)
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

static inline bool awsRunCommandCaptureOutput(const String& command, String& output, String *failure = nullptr)
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
   awsTrimTrailingAsciiWhitespace(output);
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

static inline bool awsHasPrefix(const String& text, const char *prefix)
{
   uint64_t prefixLength = uint64_t(strlen(prefix));
   if (text.size() < prefixLength)
   {
      return false;
   }

   return memcmp(text.data(), prefix, prefixLength) == 0;
}

static inline bool awsContainsCString(const String& text, const char *needle)
{
   return awsFindToken(text, needle) != uint64_t(-1);
}

static inline bool awsIsLaunchTemplateMissingFailure(const String& failure)
{
   return awsContainsCString(failure, "InvalidLaunchTemplateName")
      || awsContainsCString(failure, "does not exist");
}

class AwsNeuronIaaS : public NeuronIaaS
{
public:

   void gatherSelfData(uint128_t& uuid, String& metro, bool& isBrain, EthDevice& eth, IPAddress& private4) override
   {
      AwsMetadataClient metadata;

      String deviceName;
      if (prodigyResolvePrimaryNetworkDevice(deviceName))
      {
         eth.setDevice(deviceName);
      }

      uuid = 0;
      metro.clear();
      isBrain = false;
      private4 = {};

      String document;
      if (metadata.get("/latest/dynamic/instance-identity/document", document))
      {
         simdjson::dom::parser parser;
         simdjson::dom::element doc;

         if (!parser.parse(document.c_str(), document.size()).get(doc))
         {
            std::string_view region;
            if (!doc["region"].get(region))
            {
               metro.assign(region);
            }

            std::string_view private4Text;
            if (!doc["privateIp"].get(private4Text))
            {
               private4.is6 = false;
               String privateText = String(private4Text);
               (void)inet_pton(AF_INET, privateText.c_str(), &private4.v4);
            }
         }
      }

      if (metro.size() == 0)
      {
         String region;
         if (metadata.get("/latest/meta-data/placement/region", region))
         {
            metro = region;
         }
      }

      if (private4.isNull())
      {
         private4.is6 = false;
         private4.v4 = eth.getPrivate4();
      }

      String brainTag;
      if (metadata.get("/latest/meta-data/tags/instance/brain", brainTag))
      {
         isBrain = (brainTag == "1"_ctv || brainTag == "true"_ctv);
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

class AwsBrainIaaS : public BrainIaaS
{
private:

   ProdigyRuntimeEnvironmentConfig runtimeEnvironment;
   String region;
   AwsCredentialMaterial credential;
   bool credentialLoaded = false;
   String bootstrapSSHUser;
   String bootstrapSSHPrivateKeyPath;
   String bootstrapSSHPublicKey;
   Vault::SSHKeyPackage bootstrapSSHHostKeyPackage;
   String provisioningClusterUUIDTagValue;
   BrainIaaSMachineProvisioningProgressReporter provisioningProgress;
   static constexpr const char *canonicalUbuntuSSMPrefix = "resolve:ssm:/aws/service/canonical/ubuntu/server/";

   static void lowercaseString(const String& input, String& lower)
   {
      lower.clear();
      lower.reserve(input.size());
      for (uint64_t index = 0; index < input.size(); ++index)
      {
         lower.append(char(std::tolower(unsigned(input[index]))));
      }
   }

   static bool stringContainsInsensitive(const String& input, const char *needle)
   {
      if (needle == nullptr || needle[0] == '\0')
      {
         return false;
      }

      String lowerInput = {};
      lowercaseString(input, lowerInput);

      String lowerNeedle = {};
      lowerNeedle.assign(needle);
      for (uint64_t index = 0; index < lowerNeedle.size(); ++index)
      {
         lowerNeedle[index] = char(std::tolower(unsigned(lowerNeedle[index])));
      }

      if (lowerNeedle.size() > lowerInput.size())
      {
         return false;
      }

      for (uint64_t offset = 0; offset + lowerNeedle.size() <= lowerInput.size(); ++offset)
      {
         if (lowerInput.substr(offset, lowerNeedle.size()).equal(lowerNeedle))
         {
            return true;
         }
      }

      return false;
   }

   static void appendAwsProcessorFeatures(const String& processorFeatures, Vector<String>& isaFeatures)
   {
      if (stringContainsInsensitive(processorFeatures, "avx512"))
      {
         prodigyAppendNormalizedIsaFeature(isaFeatures, "avx512f"_ctv);
      }

      if (stringContainsInsensitive(processorFeatures, "avx2"))
      {
         prodigyAppendNormalizedIsaFeature(isaFeatures, "avx2"_ctv);
      }

      if (stringContainsInsensitive(processorFeatures, "avx"))
      {
         prodigyAppendNormalizedIsaFeature(isaFeatures, "avx"_ctv);
      }
   }

   bool ensureRegion(void)
   {
      if (region.size() > 0)
      {
         return true;
      }

      if (awsScopeRegion(runtimeEnvironment.providerScope, region))
      {
         return true;
      }

      AwsMetadataClient metadata;
      String discoveredRegion;
      if (metadata.get("/latest/meta-data/placement/region", discoveredRegion))
      {
         region = discoveredRegion;
      }

      return region.size() > 0;
   }

   bool awsHasBootstrapCredentialRefreshCommand(void) const
   {
      return runtimeEnvironment.aws.bootstrapCredentialRefreshCommand.size() > 0;
   }

   bool awsCredentialNeedsRefresh(void) const
   {
      if (credentialLoaded == false || credential.valid() == false)
      {
         return true;
      }

      if (credential.expirationMs <= 0)
      {
         return false;
      }

      return Time::now<TimeResolution::ms>() + 30 * 1000 >= credential.expirationMs;
   }

   bool refreshAwsBootstrapCredential(String& failure)
   {
      failure.clear();

      String material = {};
      String detail = {};
      if (awsRunCommandCaptureOutput(runtimeEnvironment.aws.bootstrapCredentialRefreshCommand, material, &detail) == false)
      {
         if (runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint.size() > 0)
         {
            failure.assign(detail);
            if (failure.size() > 0)
            {
               failure.append("\n"_ctv);
            }
            failure.append(runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint);
         }
         else
         {
            failure = detail;
         }
         return false;
      }

      if (awsStringHasContent(material) == false)
      {
         failure.assign("aws credential refresh returned empty output"_ctv);
         if (runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint.size() > 0)
         {
            failure.append("\n"_ctv);
            failure.append(runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint);
         }
         return false;
      }

      AwsCredentialMaterial refreshed = {};
      if (parseAwsCredentialMaterial(material, refreshed, &failure) == false)
      {
         if (runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint.size() > 0)
         {
            failure.append("\n"_ctv);
            failure.append(runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint);
         }
         return false;
      }

      credential = std::move(refreshed);
      credentialLoaded = credential.valid();
      if (credentialLoaded == false)
      {
         failure.assign("aws credential refresh returned invalid material"_ctv);
         return false;
      }

      if (credential.expirationMs > 0
         && Time::now<TimeResolution::ms>() + 30 * 1000 >= credential.expirationMs)
      {
         failure.assign("aws credential refresh returned expired material"_ctv);
         credentialLoaded = false;
      }

      return credentialLoaded;
   }

   bool loadAwsMetadataCredential(String& failure)
   {
      failure.clear();

      AwsMetadataClient metadata;
      for (uint32_t attempt = 0; attempt < 120; ++attempt)
      {
         String roleName;
         if (metadata.get("/latest/meta-data/iam/security-credentials/", roleName))
         {
            awsTrimTrailingAsciiWhitespace(roleName);
            if (roleName.size() > 0)
            {
               String credentialPath = {};
               credentialPath.snprintf<"/latest/meta-data/iam/security-credentials/{}"_ctv>(roleName);
               String credentialJSON;
               if (metadata.get(credentialPath.c_str(), credentialJSON))
               {
                  AwsCredentialMaterial discovered = {};
                  String parseFailure = {};
                  if (parseAwsCredentialMaterial(credentialJSON, discovered, &parseFailure))
                  {
                     credential = std::move(discovered);
                     credentialLoaded = credential.valid();
                     if (credentialLoaded == false)
                     {
                        failure.assign("aws credential material invalid"_ctv);
                        return false;
                     }

                     return true;
                  }

                  failure = parseFailure;
               }
               else
               {
                  failure.assign("aws metadata credential fetch failed"_ctv);
               }
            }
            else
            {
               failure.assign("aws metadata credentials unavailable"_ctv);
            }
         }
         else
         {
            failure.assign("aws metadata credentials unavailable"_ctv);
         }

         if (attempt + 1 < 120)
         {
            usleep(500000);
         }
      }

      return false;
   }

   bool ensureCredential(String& failure)
   {
      if (awsCredentialNeedsRefresh() == false)
      {
         return true;
      }

      if (awsHasBootstrapCredentialRefreshCommand())
      {
         return refreshAwsBootstrapCredential(failure);
      }

      credential = {};
      if (runtimeEnvironment.providerCredentialMaterial.size() > 0)
      {
         if (parseAwsCredentialMaterial(runtimeEnvironment.providerCredentialMaterial, credential, &failure) == false)
         {
            return false;
         }
         credentialLoaded = credential.valid();
         if (credentialLoaded
            && credential.expirationMs > 0
            && Time::now<TimeResolution::ms>() + 30 * 1000 >= credential.expirationMs)
         {
            failure.assign("aws credential material expired"_ctv);
            credentialLoaded = false;
         }

         if (credentialLoaded)
         {
            // Explicit bootstrap material should win when it is present and
            // valid. This keeps non-EC2 controllers from stalling on IMDS just
            // because the runtime also knows about an eventual instance
            // profile contract for the launched machines.
            return true;
         }
      }

      if (runtimeEnvironment.aws.instanceProfileName.size() > 0
         || runtimeEnvironment.aws.instanceProfileArn.size() > 0)
      {
         return loadAwsMetadataCredential(failure);
      }

      if (runtimeEnvironment.providerCredentialMaterial.size() == 0)
      {
         return loadAwsMetadataCredential(failure);
      }

      if (credentialLoaded == false)
      {
         failure.assign("aws credential material invalid"_ctv);
      }

      return credentialLoaded;
   }

   bool sendPricingRequest(const String& requestBody, String& response, String& failure, long *httpCode = nullptr)
   {
      if (ensureCredential(failure) == false)
      {
         return false;
      }

      return awsSendPricingGetProductsRequest(credential, requestBody, response, failure, httpCode);
   }

protected:

   virtual bool sendElasticEC2Request(const String& actionBody, String& response, String& failure, long *httpCode = nullptr)
   {
      if (ensureRegion() == false)
      {
         failure.assign("aws region missing"_ctv);
         return false;
      }

      if (ensureCredential(failure) == false)
      {
         return false;
      }

      String url = {};
      url.snprintf<"https://ec2.{}.amazonaws.com/"_ctv>(region);

      struct curl_slist *headers = nullptr;
      headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded; charset=utf-8");

      long localHTTPCode = 0;
      bool ok = AwsHttp::send("POST", url, region, "ec2"_ctv, credential, headers, &actionBody, response, &localHTTPCode);
      curl_slist_free_all(headers);
      if (httpCode) *httpCode = localHTTPCode;

      if (ok == false)
      {
         failure.assign("aws request transport failed"_ctv);
         return false;
      }

      if (localHTTPCode < 200 || localHTTPCode >= 300)
      {
         String message;
         if (awsExtractXMLValue(response, "Message", message) == false)
         {
            message.assign("aws request failed"_ctv);
         }
         failure = message;
         return false;
      }

      failure.clear();
      return true;
   }

private:

   bool request(const String& actionBody, String& response, String& failure, long *httpCode = nullptr)
   {
      return sendElasticEC2Request(actionBody, response, failure, httpCode);
   }

   bool describeElasticAddressByPublicIP(const String& requestedAddress, String& publicAddress, String& allocationID, String& associationID, String& failure)
   {
      publicAddress.clear();
      allocationID.clear();
      associationID.clear();

      if (requestedAddress.size() == 0)
      {
         failure.assign("aws elastic address requires a public ip"_ctv);
         return false;
      }

      bool first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "DescribeAddresses"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "Filter.1.Name"_ctv, "public-ip"_ctv, first);
      awsAppendQueryParam(body, "Filter.1.Value.1"_ctv, requestedAddress, first);

      String response = {};
      if (request(body, response, failure) == false)
      {
         return false;
      }

      Vector<String> blocks = {};
      awsCollectSetItemBlocks(response, "addressesSet", blocks);
      if (blocks.empty())
      {
         failure.snprintf<"aws elastic address {} not found"_ctv>(requestedAddress);
         return false;
      }

      awsExtractXMLValue(blocks[0], "publicIp", publicAddress);
      awsExtractXMLValue(blocks[0], "allocationId", allocationID);
      awsExtractXMLValue(blocks[0], "associationId", associationID);
      if (allocationID.size() == 0)
      {
         failure.assign("aws elastic address missing allocationId"_ctv);
         return false;
      }

      failure.clear();
      return true;
   }

   bool allocateElasticAddress(const String& providerPool, String& publicAddress, String& allocationID, String& failure)
   {
      publicAddress.clear();
      allocationID.clear();

      bool first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "AllocateAddress"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "Domain"_ctv, "vpc"_ctv, first);
      if (providerPool.size() > 0)
      {
         awsAppendQueryParam(body, "PublicIpv4Pool"_ctv, providerPool, first);
      }

      String response = {};
      if (request(body, response, failure) == false)
      {
         return false;
      }

      if (awsExtractXMLValue(response, "publicIp", publicAddress) == false
         || awsExtractXMLValue(response, "allocationId", allocationID) == false)
      {
         failure.assign("aws AllocateAddress response missing required fields"_ctv);
         return false;
      }

      failure.clear();
      return true;
   }

   bool associateElasticAddress(const String& allocationID, const String& instanceID, String& associationID, String& failure)
   {
      associationID.clear();

      if (allocationID.size() == 0 || instanceID.size() == 0)
      {
         failure.assign("aws elastic associate requires allocationId and instanceId"_ctv);
         return false;
      }

      bool first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "AssociateAddress"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "AllocationId"_ctv, allocationID, first);
      awsAppendQueryParam(body, "InstanceId"_ctv, instanceID, first);
      awsAppendQueryParam(body, "AllowReassociation"_ctv, "true"_ctv, first);

      String response = {};
      if (request(body, response, failure) == false)
      {
         return false;
      }

      awsExtractXMLValue(response, "associationId", associationID);
      failure.clear();
      return true;
   }

   bool disassociateElasticAddress(const String& associationID, String& failure)
   {
      if (associationID.size() == 0)
      {
         failure.clear();
         return true;
      }

      bool first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "DisassociateAddress"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "AssociationId"_ctv, associationID, first);

      String response = {};
      return request(body, response, failure);
   }

   bool releaseElasticAddressAllocation(const String& allocationID, String& failure)
   {
      if (allocationID.size() == 0)
      {
         failure.clear();
         return true;
      }

      bool first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "ReleaseAddress"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "AllocationId"_ctv, allocationID, first);

      String response = {};
      return request(body, response, failure);
   }

   static bool awsConsumePathSegment(const String& text, uint64_t& offset, String& segment)
   {
      if (offset > text.size())
      {
         return false;
      }

      uint64_t slash = uint64_t(-1);
      for (uint64_t index = offset; index < text.size(); ++index)
      {
         if (text[index] == '/')
         {
            slash = index;
            break;
         }
      }

      if (slash == uint64_t(-1))
      {
         segment.assign(text.substr(offset, text.size() - offset, Copy::yes));
         offset = text.size();
         return true;
      }

      segment.assign(text.substr(offset, slash - offset, Copy::yes));
      offset = slash + 1;
      return true;
   }

   static bool awsResolveCanonicalUbuntuRelease(const String& token, String& version, String& codename)
   {
      if (token.equal("24.04"_ctv) || token.equal("noble"_ctv))
      {
         version = "24.04"_ctv;
         codename = "noble"_ctv;
         return true;
      }

      if (token.equal("22.04"_ctv) || token.equal("jammy"_ctv))
      {
         version = "22.04"_ctv;
         codename = "jammy"_ctv;
         return true;
      }

      if (token.equal("20.04"_ctv) || token.equal("focal"_ctv))
      {
         version = "20.04"_ctv;
         codename = "focal"_ctv;
         return true;
      }

      return false;
   }

   bool resolveCanonicalUbuntuImageID(const String& imageReference, String& imageID, String& failure)
   {
      imageID.clear();

      if (awsHasPrefix(imageReference, canonicalUbuntuSSMPrefix) == false)
      {
         imageID = imageReference;
         failure.clear();
         return true;
      }

      uint64_t offset = uint64_t(strlen(canonicalUbuntuSSMPrefix));
      String releaseToken = {};
      String trackToken = {};
      String currentToken = {};
      String architectureToken = {};
      String virtualizationToken = {};
      String volumeToken = {};
      String leafToken = {};
      if (awsConsumePathSegment(imageReference, offset, releaseToken) == false
         || awsConsumePathSegment(imageReference, offset, trackToken) == false
         || awsConsumePathSegment(imageReference, offset, currentToken) == false
         || awsConsumePathSegment(imageReference, offset, architectureToken) == false
         || awsConsumePathSegment(imageReference, offset, virtualizationToken) == false
         || awsConsumePathSegment(imageReference, offset, volumeToken) == false
         || awsConsumePathSegment(imageReference, offset, leafToken) == false)
      {
         failure.assign("aws canonical ubuntu image reference parse failed"_ctv);
         return false;
      }

      if (leafToken != "ami-id"_ctv || trackToken != "stable"_ctv || currentToken != "current"_ctv)
      {
         failure.assign("aws canonical ubuntu image reference unsupported"_ctv);
         return false;
      }

      String versionToken = {};
      String codenameToken = {};
      if (awsResolveCanonicalUbuntuRelease(releaseToken, versionToken, codenameToken) == false)
      {
         failure.assign("aws canonical ubuntu release unsupported"_ctv);
         return false;
      }

      String architecture = {};
      if (architectureToken == "amd64"_ctv)
      {
         architecture = "x86_64"_ctv;
      }
      else if (architectureToken == "arm64"_ctv)
      {
         architecture = "arm64"_ctv;
      }
      else
      {
         failure.assign("aws canonical ubuntu architecture unsupported"_ctv);
         return false;
      }

      if (virtualizationToken != "hvm"_ctv)
      {
         failure.assign("aws canonical ubuntu virtualization unsupported"_ctv);
         return false;
      }

      String storagePrefix = "hvm-ssd"_ctv;
      if (volumeToken == "ebs-gp3"_ctv)
      {
         storagePrefix = "hvm-ssd-gp3"_ctv;
      }
      else if (volumeToken != "ebs-gp2"_ctv)
      {
         failure.assign("aws canonical ubuntu volume type unsupported"_ctv);
         return false;
      }

      String namePattern = {};
      namePattern.snprintf<"ubuntu/images/{}/ubuntu-{}-{}-{}-server-*"_ctv>(
         storagePrefix,
         codenameToken,
         versionToken,
         architectureToken);

      String bestImageID = {};
      String bestCreationDate = {};
      String nextToken = {};

      while (true)
      {
         bool first = true;
         String body = {};
         awsAppendQueryParam(body, "Action"_ctv, "DescribeImages"_ctv, first);
         awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
         awsAppendQueryParam(body, "Owner.1"_ctv, "099720109477"_ctv, first);
         awsAppendQueryParam(body, "Filter.1.Name"_ctv, "name"_ctv, first);
         awsAppendQueryParam(body, "Filter.1.Value.1"_ctv, namePattern, first);
         awsAppendQueryParam(body, "Filter.2.Name"_ctv, "architecture"_ctv, first);
         awsAppendQueryParam(body, "Filter.2.Value.1"_ctv, architecture, first);
         awsAppendQueryParam(body, "Filter.3.Name"_ctv, "root-device-type"_ctv, first);
         awsAppendQueryParam(body, "Filter.3.Value.1"_ctv, "ebs"_ctv, first);
         awsAppendQueryParam(body, "Filter.4.Name"_ctv, "state"_ctv, first);
         awsAppendQueryParam(body, "Filter.4.Value.1"_ctv, "available"_ctv, first);
         awsAppendQueryParam(body, "Filter.5.Name"_ctv, "virtualization-type"_ctv, first);
         awsAppendQueryParam(body, "Filter.5.Value.1"_ctv, virtualizationToken, first);
         if (nextToken.size() > 0)
         {
            awsAppendQueryParam(body, "NextToken"_ctv, nextToken, first);
         }

         String response = {};
         if (request(body, response, failure) == false)
         {
            return false;
         }

         Vector<String> imageBlocks;
         awsCollectSetItemBlocks(response, "imagesSet", imageBlocks);
         for (const String& block : imageBlocks)
         {
            String candidateID = {};
            String candidateCreationDate = {};
            if (awsExtractXMLValue(block, "imageId", candidateID) == false
               || awsExtractXMLValue(block, "creationDate", candidateCreationDate) == false)
            {
               continue;
            }

            bool newer = (bestCreationDate.size() == 0);
            if (newer == false)
            {
               uint64_t compareBytes = candidateCreationDate.size();
               if (bestCreationDate.size() < compareBytes)
               {
                  compareBytes = bestCreationDate.size();
               }

               int cmp = 0;
               if (compareBytes > 0)
               {
                  cmp = memcmp(candidateCreationDate.data(), bestCreationDate.data(), compareBytes);
               }

               if (cmp > 0 || (cmp == 0 && candidateCreationDate.size() > bestCreationDate.size()))
               {
                  newer = true;
               }
            }

            if (newer)
            {
               bestCreationDate = candidateCreationDate;
               bestImageID = candidateID;
            }
         }

         nextToken.clear();
         awsExtractXMLValue(response, "nextToken", nextToken);
         if (nextToken.size() == 0)
         {
            break;
         }
      }

      if (bestImageID.size() == 0)
      {
         failure.assign("aws canonical ubuntu image not found"_ctv);
         return false;
      }

      imageID = bestImageID;
      failure.clear();
      return true;
   }

   Machine *buildMachineFromInstanceBlock(const String& block)
   {
      Machine *machine = new Machine();

      String instanceID;
      if (awsExtractXMLValue(block, "instanceId", instanceID))
      {
         machine->cloudID = instanceID;
         for (uint64_t index = 0; index < instanceID.size(); ++index)
         {
            machine->uuid = (machine->uuid * 131) + instanceID[index];
         }
      }

      String launchTime;
      if (awsExtractXMLValue(block, "launchTime", launchTime))
      {
         machine->creationTimeMs = awsParseRFC3339Ms(launchTime);
      }

      String imageID;
      if (awsExtractXMLValue(block, "imageId", imageID))
      {
         machine->currentImageURI = imageID;
      }

      String instanceType;
      if (awsExtractXMLValue(block, "instanceType", instanceType))
      {
         machine->type = instanceType;
         machine->slug = instanceType;
      }

      String availabilityZone;
      if (awsExtractXMLValue(block, "availabilityZone", availabilityZone))
      {
         machine->region = region;
         machine->zone = availabilityZone;
         machine->rackUUID = awsRackUUIDFromAvailabilityZone(availabilityZone);
      }

      String privateIP;
      if (awsExtractXMLValue(block, "privateIpAddress", privateIP))
      {
         machine->privateAddress = privateIP;
         String privateText = {};
         privateText.assign(privateIP);
         (void)inet_pton(AF_INET, privateText.c_str(), &machine->private4);
      }

      String ipv6Address;
      if (awsExtractXMLValue(block, "ipv6Address", ipv6Address))
      {
         if (machine->privateAddress.size() == 0)
         {
            machine->privateAddress = ipv6Address;
         }

         if (machine->publicAddress.size() == 0)
         {
            machine->publicAddress = ipv6Address;
         }

         if (machine->sshAddress.size() == 0)
         {
            machine->sshAddress = ipv6Address;
         }
      }

      String publicIP;
      if (awsExtractXMLValue(block, "ipAddress", publicIP))
      {
         machine->publicAddress = publicIP;
         machine->sshAddress = publicIP;
      }
      else
      {
         machine->sshAddress = machine->privateAddress;
      }

      String lifecycle;
      if (awsExtractXMLValue(block, "instanceLifecycle", lifecycle) && lifecycle == "spot"_ctv)
      {
         machine->lifetime = MachineLifetime::spot;
      }

      String brainTag;
      if (awsExtractTagValue(block, "brain"_ctv, brainTag))
      {
         machine->isBrain = (brainTag == "1"_ctv || brainTag == "true"_ctv);
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

   void describeInstances(const String& filterBody, Vector<String>& instanceBlocks, String& failure)
   {
      instanceBlocks.clear();
      String body = {};
      body.append("Action=DescribeInstances&Version=2016-11-15"_ctv);
      if (filterBody.size() > 0)
      {
         body.append('&');
         body.append(filterBody);
      }

      String response;
      if (request(body, response, failure) == false)
      {
         return;
      }

      awsCollectInstanceBlocks(response, instanceBlocks);
   }

   void describeVpcs(Vector<String>& vpcBlocks, String& failure)
   {
      vpcBlocks.clear();

      String response;
      if (request("Action=DescribeVpcs&Version=2016-11-15"_ctv, response, failure) == false)
      {
         return;
      }

      awsCollectSetItemBlocks(response, "vpcSet", vpcBlocks);
   }

   void describeSubnets(const String& filterBody, Vector<String>& subnetBlocks, String& failure)
   {
      subnetBlocks.clear();

      String body = {};
      body.append("Action=DescribeSubnets&Version=2016-11-15"_ctv);
      if (filterBody.size() > 0)
      {
         body.append('&');
         body.append(filterBody);
      }

      String response;
      if (request(body, response, failure) == false)
      {
         return;
      }

      awsCollectSetItemBlocks(response, "subnetSet", subnetBlocks);
   }

   void describeSecurityGroups(const String& filterBody, Vector<String>& groupBlocks, String& failure)
   {
      groupBlocks.clear();

      String body = {};
      body.append("Action=DescribeSecurityGroups&Version=2016-11-15"_ctv);
      if (filterBody.size() > 0)
      {
         body.append('&');
         body.append(filterBody);
      }

      String response;
      if (request(body, response, failure) == false)
      {
         return;
      }

      awsCollectSetItemBlocks(response, "securityGroupInfo", groupBlocks);
   }

   void describeLaunchTemplates(const String& filterBody, Vector<String>& templateBlocks, String& failure)
   {
      templateBlocks.clear();

      String body = {};
      body.append("Action=DescribeLaunchTemplates&Version=2016-11-15"_ctv);
      if (filterBody.size() > 0)
      {
         body.append('&');
         body.append(filterBody);
      }

      String response;
      if (request(body, response, failure) == false)
      {
         return;
      }

      awsCollectSetItemBlocks(response, "launchTemplates", templateBlocks);
      if (templateBlocks.size() == 0)
      {
         awsCollectSetItemBlocks(response, "launchTemplateSet", templateBlocks);
      }
   }

   bool findDefaultVPC(String& vpcID, String& failure)
   {
      vpcID.clear();

      Vector<String> vpcBlocks;
      describeVpcs(vpcBlocks, failure);
      if (failure.size() > 0)
      {
         return false;
      }

      for (const String& block : vpcBlocks)
      {
         String isDefault;
         if (awsExtractXMLValue(block, "isDefault", isDefault) && isDefault == "true"_ctv)
         {
            if (awsExtractXMLValue(block, "vpcId", vpcID))
            {
               failure.clear();
               return true;
            }
         }
      }

      failure.assign("aws default vpc missing"_ctv);
      return false;
   }

   bool findBootstrapSubnet(const String& vpcID, String& subnetID, String& failure)
   {
      subnetID.clear();

      bool first = true;
      String filters = {};
      awsAppendQueryParam(filters, "Filter.1.Name"_ctv, "vpc-id"_ctv, first);
      awsAppendQueryParam(filters, "Filter.1.Value.1"_ctv, vpcID, first);

      Vector<String> subnetBlocks;
      describeSubnets(filters, subnetBlocks, failure);
      if (failure.size() > 0)
      {
         return false;
      }

      String fallbackSubnetID = {};
      for (const String& block : subnetBlocks)
      {
         String currentSubnetID;
         if (awsExtractXMLValue(block, "subnetId", currentSubnetID) == false)
         {
            continue;
         }

         if (fallbackSubnetID.size() == 0)
         {
            fallbackSubnetID = currentSubnetID;
         }

         String defaultForAz;
         if (awsExtractXMLValue(block, "defaultForAz", defaultForAz) && defaultForAz == "true"_ctv)
         {
            subnetID = currentSubnetID;
            failure.clear();
            return true;
         }
      }

      if (fallbackSubnetID.size() > 0)
      {
         subnetID = fallbackSubnetID;
         failure.clear();
         return true;
      }

      failure.assign("aws bootstrap subnet missing"_ctv);
      return false;
   }

   bool findBootstrapSecurityGroup(const String& vpcID, String& groupID, String& failure)
   {
      groupID.clear();

      bool first = true;
      String filters = {};
      awsAppendQueryParam(filters, "Filter.1.Name"_ctv, "vpc-id"_ctv, first);
      awsAppendQueryParam(filters, "Filter.1.Value.1"_ctv, vpcID, first);
      awsAppendQueryParam(filters, "Filter.2.Name"_ctv, "group-name"_ctv, first);
      awsAppendQueryParam(filters, "Filter.2.Value.1"_ctv, "prodigy-bootstrap-ssh"_ctv, first);

      Vector<String> groupBlocks;
      describeSecurityGroups(filters, groupBlocks, failure);
      if (failure.size() > 0)
      {
         return false;
      }

      for (const String& block : groupBlocks)
      {
         if (awsExtractXMLValue(block, "groupId", groupID))
         {
            failure.clear();
            return true;
         }
      }

      failure.clear();
      return true;
   }

   bool createBootstrapSecurityGroup(const String& vpcID, String& groupID, String& failure)
   {
      groupID.clear();

      bool first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "CreateSecurityGroup"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "GroupName"_ctv, "prodigy-bootstrap-ssh"_ctv, first);
      awsAppendQueryParam(body, "GroupDescription"_ctv, "Prodigy bootstrap SSH access"_ctv, first);
      awsAppendQueryParam(body, "VpcId"_ctv, vpcID, first);

      String response;
      if (request(body, response, failure) == false)
      {
         return false;
      }

      if (awsExtractXMLValue(response, "groupId", groupID) == false)
      {
         failure.assign("aws CreateSecurityGroup response missing groupId"_ctv);
         return false;
      }

      failure.clear();
      return true;
   }

   bool authorizeBootstrapSSHIngress(const String& groupID, String& failure)
   {
      bool first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "AuthorizeSecurityGroupIngress"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "GroupId"_ctv, groupID, first);
      awsAppendQueryParam(body, "IpProtocol"_ctv, "tcp"_ctv, first);
      awsAppendQueryParam(body, "FromPort"_ctv, "22"_ctv, first);
      awsAppendQueryParam(body, "ToPort"_ctv, "22"_ctv, first);
      awsAppendQueryParam(body, "CidrIp"_ctv, "0.0.0.0/0"_ctv, first);

      String response;
      if (request(body, response, failure) == false)
      {
         String failureText = {};
         failureText.assign(failure);
         if (strstr(failureText.c_str(), "already exists") != nullptr || strstr(failureText.c_str(), "InvalidPermission.Duplicate") != nullptr)
         {
            failure.clear();
            return true;
         }

         return false;
      }

      failure.clear();
      return true;
   }

   bool authorizeBootstrapMeshIngress(const String& groupID, String& failure)
   {
      bool first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "AuthorizeSecurityGroupIngress"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "GroupId"_ctv, groupID, first);
      awsAppendQueryParam(body, "IpPermissions.1.IpProtocol"_ctv, "-1"_ctv, first);
      awsAppendQueryParam(body, "IpPermissions.1.Groups.1.GroupId"_ctv, groupID, first);

      String response;
      if (request(body, response, failure) == false)
      {
         String failureText = {};
         failureText.assign(failure);
         if (strstr(failureText.c_str(), "already exists") != nullptr || strstr(failureText.c_str(), "InvalidPermission.Duplicate") != nullptr)
         {
            failure.clear();
            return true;
         }

         return false;
      }

      failure.clear();
      return true;
   }

   bool ensureBootstrapPlacement(String& subnetID, String& securityGroupID, String& failure)
   {
      subnetID.clear();
      securityGroupID.clear();

      String vpcID;
      if (findDefaultVPC(vpcID, failure) == false)
      {
         return false;
      }

      if (findBootstrapSubnet(vpcID, subnetID, failure) == false)
      {
         return false;
      }

      if (findBootstrapSecurityGroup(vpcID, securityGroupID, failure) == false)
      {
         return false;
      }

      if (securityGroupID.size() == 0)
      {
         if (createBootstrapSecurityGroup(vpcID, securityGroupID, failure) == false)
         {
            return false;
         }
      }

      if (authorizeBootstrapSSHIngress(securityGroupID, failure) == false)
      {
         return false;
      }

      return authorizeBootstrapMeshIngress(securityGroupID, failure);
   }

   static void awsAppendBootstrapLaunchTemplateData(
      String& body,
      const String& prefix,
      const String& subnetID,
      const String& securityGroupID,
      const String& instanceProfileName,
      const String& instanceProfileArn,
      bool& first)
   {
      String key = {};

      key.snprintf<"{}.MetadataOptions.HttpTokens"_ctv>(prefix);
      awsAppendQueryParam(body, key, "required"_ctv, first);

      key.snprintf<"{}.NetworkInterface.1.DeviceIndex"_ctv>(prefix);
      awsAppendQueryParam(body, key, "0"_ctv, first);

      key.snprintf<"{}.NetworkInterface.1.AssociatePublicIpAddress"_ctv>(prefix);
      awsAppendQueryParam(body, key, "true"_ctv, first);

      key.snprintf<"{}.NetworkInterface.1.SubnetId"_ctv>(prefix);
      awsAppendQueryParam(body, key, subnetID, first);

      key.snprintf<"{}.NetworkInterface.1.SecurityGroupId.1"_ctv>(prefix);
      awsAppendQueryParam(body, key, securityGroupID, first);

      if (instanceProfileArn.size() > 0)
      {
         key.snprintf<"{}.IamInstanceProfile.Arn"_ctv>(prefix);
         awsAppendQueryParam(body, key, instanceProfileArn, first);
      }
      else if (instanceProfileName.size() > 0)
      {
         key.snprintf<"{}.IamInstanceProfile.Name"_ctv>(prefix);
         awsAppendQueryParam(body, key, instanceProfileName, first);
      }
   }

   bool describeBootstrapLaunchTemplate(const String& launchTemplateName, String& launchTemplateID, String& defaultVersionNumber, String& latestVersionNumber, String& failure)
   {
      launchTemplateID.clear();
      defaultVersionNumber.clear();
      latestVersionNumber.clear();

      bool first = true;
      String filters = {};
      awsAppendQueryParam(filters, "LaunchTemplateName.1"_ctv, launchTemplateName, first);

      Vector<String> templateBlocks;
      describeLaunchTemplates(filters, templateBlocks, failure);
      if (failure.size() > 0)
      {
         if (awsIsLaunchTemplateMissingFailure(failure))
         {
            failure.clear();
            return true;
         }

         return false;
      }

      if (templateBlocks.size() == 0)
      {
         return true;
      }

      awsExtractXMLValue(templateBlocks[0], "launchTemplateId", launchTemplateID);
      awsExtractXMLValue(templateBlocks[0], "defaultVersionNumber", defaultVersionNumber);
      awsExtractXMLValue(templateBlocks[0], "latestVersionNumber", latestVersionNumber);
      return true;
   }

   bool createBootstrapLaunchTemplate(
      const String& launchTemplateName,
      const String& subnetID,
      const String& securityGroupID,
      const String& instanceProfileName,
      const String& instanceProfileArn,
      String& failure)
   {
      bool first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "CreateLaunchTemplate"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "LaunchTemplateName"_ctv, launchTemplateName, first);
      awsAppendQueryParam(body, "VersionDescription"_ctv, "prodigy-bootstrap"_ctv, first);
      awsAppendBootstrapLaunchTemplateData(body, "LaunchTemplateData"_ctv, subnetID, securityGroupID, instanceProfileName, instanceProfileArn, first);

      String response;
      return request(body, response, failure);
   }

   bool waitForBootstrapLaunchTemplateState(
      const String& launchTemplateName,
      const String& expectedDefaultVersion,
      String& launchTemplateID,
      String& defaultVersionNumber,
      String& latestVersionNumber,
      String& failure
   )
   {
      launchTemplateID.clear();
      defaultVersionNumber.clear();
      latestVersionNumber.clear();

      for (uint32_t attempt = 0; attempt < 40; ++attempt)
      {
         if (describeBootstrapLaunchTemplate(launchTemplateName, launchTemplateID, defaultVersionNumber, latestVersionNumber, failure) == false)
         {
            if (awsIsLaunchTemplateMissingFailure(failure))
            {
               failure.clear();
               usleep(500'000);
               continue;
            }

            return false;
         }

         bool visible = launchTemplateID.size() > 0;
         bool versionsVisible = defaultVersionNumber.size() > 0 && latestVersionNumber.size() > 0;
         bool expectedDefaultReady = (expectedDefaultVersion.size() == 0) || (defaultVersionNumber == expectedDefaultVersion);
         if (visible && versionsVisible && expectedDefaultReady)
         {
            failure.clear();
            return true;
         }

         usleep(500'000);
      }

      if (expectedDefaultVersion.size() > 0)
      {
         failure.snprintf<"aws bootstrap launch template {} default version {} not visible yet"_ctv>(launchTemplateName, expectedDefaultVersion);
      }
      else
      {
         failure.snprintf<"aws bootstrap launch template {} not visible yet"_ctv>(launchTemplateName);
      }

      return false;
   }

   bool createBootstrapLaunchTemplateVersion(
      const String& launchTemplateName,
      const String& subnetID,
      const String& securityGroupID,
      const String& instanceProfileName,
      const String& instanceProfileArn,
      String& versionNumber,
      String& failure)
   {
      versionNumber.clear();

      bool first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "CreateLaunchTemplateVersion"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "LaunchTemplateName"_ctv, launchTemplateName, first);
      awsAppendQueryParam(body, "VersionDescription"_ctv, "prodigy-bootstrap"_ctv, first);
      awsAppendBootstrapLaunchTemplateData(body, "LaunchTemplateData"_ctv, subnetID, securityGroupID, instanceProfileName, instanceProfileArn, first);

      String response;
      if (request(body, response, failure) == false)
      {
         return false;
      }

      if (awsExtractXMLValue(response, "versionNumber", versionNumber) == false)
      {
         failure.assign("aws CreateLaunchTemplateVersion response missing versionNumber"_ctv);
         return false;
      }

      return true;
   }

   bool setBootstrapLaunchTemplateDefaultVersion(const String& launchTemplateName, const String& versionNumber, String& failure)
   {
      bool first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "ModifyLaunchTemplate"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "LaunchTemplateName"_ctv, launchTemplateName, first);
      awsAppendQueryParam(body, "SetDefaultVersion"_ctv, versionNumber, first);

      String response;
      return request(body, response, failure);
   }

   bool ensureBootstrapLaunchTemplate(String& launchTemplateName, String& launchTemplateVersion, String& failure)
   {
      launchTemplateName = runtimeEnvironment.aws.bootstrapLaunchTemplateName;
      launchTemplateVersion = runtimeEnvironment.aws.bootstrapLaunchTemplateVersion;

      if (launchTemplateName.size() == 0)
      {
         failure.assign("aws bootstrap launch template name missing"_ctv);
         return false;
      }

      if (launchTemplateVersion.size() == 0)
      {
         launchTemplateVersion.assign("$Default"_ctv);
      }

      String subnetID = {};
      String securityGroupID = {};
      const String& instanceProfileName = runtimeEnvironment.aws.instanceProfileName;
      const String& instanceProfileArn = runtimeEnvironment.aws.instanceProfileArn;
      if (ensureBootstrapPlacement(subnetID, securityGroupID, failure) == false)
      {
         return false;
      }

      String launchTemplateID = {};
      String defaultVersionNumber = {};
      String latestVersionNumber = {};
      if (describeBootstrapLaunchTemplate(launchTemplateName, launchTemplateID, defaultVersionNumber, latestVersionNumber, failure) == false)
      {
         return false;
      }

      if (launchTemplateID.size() == 0)
      {
         if (createBootstrapLaunchTemplate(launchTemplateName, subnetID, securityGroupID, instanceProfileName, instanceProfileArn, failure) == false)
         {
            return false;
         }

         if (waitForBootstrapLaunchTemplateState(launchTemplateName, ""_ctv, launchTemplateID, defaultVersionNumber, latestVersionNumber, failure) == false)
         {
            return false;
         }
      }
      else if (launchTemplateVersion == "$Default"_ctv)
      {
         String createdVersionNumber = {};
         if (createBootstrapLaunchTemplateVersion(launchTemplateName, subnetID, securityGroupID, instanceProfileName, instanceProfileArn, createdVersionNumber, failure) == false)
         {
            return false;
         }

         if (setBootstrapLaunchTemplateDefaultVersion(launchTemplateName, createdVersionNumber, failure) == false)
         {
            return false;
         }

         if (waitForBootstrapLaunchTemplateState(launchTemplateName, createdVersionNumber, launchTemplateID, defaultVersionNumber, latestVersionNumber, failure) == false)
         {
            return false;
         }
      }

      if (launchTemplateVersion == "$Default"_ctv)
      {
         if (defaultVersionNumber.size() == 0)
         {
            failure.assign("aws bootstrap launch template default version missing"_ctv);
            return false;
         }

         launchTemplateVersion = defaultVersionNumber;
      }
      else if (launchTemplateVersion == "$Latest"_ctv)
      {
         if (latestVersionNumber.size() == 0)
         {
            failure.assign("aws bootstrap launch template latest version missing"_ctv);
            return false;
         }

         launchTemplateVersion = latestVersionNumber;
      }

      failure.clear();
      return true;
   }

   void terminateCreatedInstances(const Vector<String>& instanceIDs)
   {
      if (instanceIDs.size() == 0)
      {
         return;
      }

      bool first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "TerminateInstances"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      for (uint32_t index = 0; index < instanceIDs.size(); ++index)
      {
         String key = {};
         key.snprintf<"InstanceId.{itoa}"_ctv>(index + 1);
         awsAppendQueryParam(body, key, instanceIDs[index], first);
      }

      String response;
      String failure;
      (void)request(body, response, failure);
   }

public:

   void boot(void) override
   {
   }

   bool supportsAuthoritativeMachineSchemaCpuCapabilityInference(void) const override
   {
      return true;
   }

   void configureRuntimeEnvironment(const ProdigyRuntimeEnvironmentConfig& config) override
   {
      prodigyOwnRuntimeEnvironmentConfig(config, runtimeEnvironment);
      prodigyApplyInternalRuntimeEnvironmentDefaults(runtimeEnvironment);
      region.clear();
      credential = {};
      credentialLoaded = false;
   }

   bool inferMachineSchemaCpuCapability(const MachineConfig& config, MachineSchemaCpuCapability& capability, String& error) override
   {
      capability = {};
      error.clear();

      if (config.providerMachineType.size() == 0)
      {
         error.assign("aws schema cpu inference requires providerMachineType"_ctv);
         return false;
      }

      if (ensureRegion() == false)
      {
         error.assign("aws region missing"_ctv);
         return false;
      }

      bool first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "DescribeInstanceTypes"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "InstanceType.1"_ctv, config.providerMachineType, first);

      String response = {};
      if (request(body, response, error) == false)
      {
         return false;
      }

      Vector<String> instanceTypeBlocks = {};
      awsCollectSetItemBlocks(response, "instanceTypeSet", instanceTypeBlocks);
      if (instanceTypeBlocks.empty())
      {
         awsCollectSetItemBlocks(response, "instanceTypeInfoSet", instanceTypeBlocks);
      }

      if (instanceTypeBlocks.empty())
      {
         error.assign("aws DescribeInstanceTypes response missing instanceType block"_ctv);
         return false;
      }

      Vector<String> architectureBlocks = {};
      awsCollectSetItemBlocks(instanceTypeBlocks[0], "supportedArchitectures", architectureBlocks);
      for (const String& architectureText : architectureBlocks)
      {
         MachineCpuArchitecture parsedArchitecture = MachineCpuArchitecture::unknown;
         String lowerArchitecture = {};
         lowercaseString(architectureText, lowerArchitecture);
         if (parseMachineCpuArchitecture(lowerArchitecture, parsedArchitecture))
         {
            capability.architecture = parsedArchitecture;
            break;
         }
      }

      if (capability.architecture == MachineCpuArchitecture::unknown)
      {
         error.assign("aws instance architecture missing or unsupported"_ctv);
         return false;
      }

      body.clear();
      awsBuildPricingGetProductsRequestBody(
         "AmazonEC2"_ctv,
         {
            {"regionCode"_ctv, region},
            {"instanceType"_ctv, config.providerMachineType},
            {"operatingSystem"_ctv, "Linux"_ctv},
            {"preInstalledSw"_ctv, "NA"_ctv},
            {"tenancy"_ctv, "Shared"_ctv},
            {"capacitystatus"_ctv, "Used"_ctv},
         },
         body);

      response.clear();
      long httpCode = 0;
      if (sendPricingRequest(body, response, error, &httpCode) == false)
      {
         return false;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element doc = {};
      if (parser.parse(response.c_str(), response.size()).get(doc))
      {
         error.assign("aws pricing response parse failed"_ctv);
         return false;
      }

      if (doc["PriceList"].is_array() == false)
      {
         error.assign("aws pricing response missing PriceList"_ctv);
         return false;
      }

      for (auto encodedEntry : doc["PriceList"].get_array())
      {
         std::string_view encoded = {};
         if (encodedEntry.get(encoded) != simdjson::SUCCESS || encoded.size() == 0)
         {
            continue;
         }

         String entryText = {};
         entryText.assign(encoded);
         simdjson::dom::parser entryParser;
         simdjson::dom::element entry = {};
         if (entryParser.parse(entryText.c_str(), entryText.size()).get(entry))
         {
            continue;
         }

         std::string_view instanceType = {};
         if (entry["product"]["attributes"]["instanceType"].get(instanceType) != simdjson::SUCCESS
            || String(instanceType) != config.providerMachineType)
         {
            continue;
         }

         std::string_view processorFeatures = {};
         if (entry["product"]["attributes"]["processorFeatures"].get(processorFeatures) == simdjson::SUCCESS)
         {
            String features = {};
            features.assign(processorFeatures);
            appendAwsProcessorFeatures(features, capability.isaFeatures);
            capability.provenance = MachineSchemaCpuCapabilityProvenance::providerAuthoritative;
         }
         else
         {
            capability.provenance = MachineSchemaCpuCapabilityProvenance::unavailable;
         }

         return true;
      }

      capability.provenance = MachineSchemaCpuCapabilityProvenance::unavailable;
      return true;
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
         error.assign("aws auto provisioning does not support MachineLifetime::owned"_ctv);
         return;
      }

      if (config.vmImageURI.size() == 0)
      {
         error.assign("aws vmImageURI missing"_ctv);
         return;
      }

      if (config.slug.size() == 0)
      {
         error.assign("aws machine schema slug missing"_ctv);
         return;
      }

      if (config.providerMachineType.size() == 0)
      {
         error.assign("aws providerMachineType missing"_ctv);
         return;
      }

      String imageID = {};
      if (resolveCanonicalUbuntuImageID(config.vmImageURI, imageID, error) == false)
      {
         return;
      }

      String launchTemplateName = {};
      String launchTemplateVersion = {};
      if (ensureBootstrapLaunchTemplate(launchTemplateName, launchTemplateVersion, error) == false)
      {
         return;
      }

      String userData = {};
      if (bootstrapSSHPublicKey.size() > 0)
      {
         String script = {};
         prodigyBuildBootstrapSSHCloudConfig(bootstrapSSHUser, bootstrapSSHPublicKey, bootstrapSSHHostKeyPackage, script);
         Base64::encodePadded(script.data(), script.size(), userData);
      }

      Vector<String> createdInstanceIDs = {};
      Vector<String> provisionedInstanceIDs = {};
      auto provisioningAlreadyReported = [&] (const String& instanceID) -> bool {

         for (const String& candidate : provisionedInstanceIDs)
         {
            if (candidate.equals(instanceID))
            {
               return true;
            }
         }

         return false;
      };
      {
         bool first = true;
         String body = {};
         awsAppendQueryParam(body, "Action"_ctv, "RunInstances"_ctv, first);
         awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
         awsAppendQueryParam(body, "ImageId"_ctv, imageID, first);
         awsAppendQueryParam(body, "InstanceType"_ctv, config.providerMachineType, first);
         String requestedCount = {};
         requestedCount.assignItoa(count);
         awsAppendQueryParam(body, "MinCount"_ctv, requestedCount, first);
         awsAppendQueryParam(body, "MaxCount"_ctv, requestedCount, first);
         awsAppendQueryParam(body, "LaunchTemplate.LaunchTemplateName"_ctv, launchTemplateName, first);
         awsAppendQueryParam(body, "LaunchTemplate.Version"_ctv, launchTemplateVersion, first);
         awsAppendQueryParam(body, "TagSpecification.1.ResourceType"_ctv, "instance"_ctv, first);
         awsAppendQueryParam(body, "TagSpecification.1.Tag.1.Key"_ctv, "app"_ctv, first);
         awsAppendQueryParam(body, "TagSpecification.1.Tag.1.Value"_ctv, "prodigy"_ctv, first);
         if (provisioningClusterUUIDTagValue.size() > 0)
         {
            awsAppendQueryParam(body, "TagSpecification.1.Tag.2.Key"_ctv, "prodigy_cluster_uuid"_ctv, first);
            awsAppendQueryParam(body, "TagSpecification.1.Tag.2.Value"_ctv, provisioningClusterUUIDTagValue, first);
         }
         if (userData.size() > 0)
         {
            awsAppendQueryParam(body, "UserData"_ctv, userData, first);
         }

         if (lifetime == MachineLifetime::spot)
         {
            awsAppendQueryParam(body, "InstanceMarketOptions.MarketType"_ctv, "spot"_ctv, first);
            awsAppendQueryParam(body, "InstanceMarketOptions.SpotOptions.InstanceInterruptionBehavior"_ctv, "terminate"_ctv, first);
         }

         if (config.nStorageMB > 0)
         {
            uint32_t diskGB = (config.nStorageMB + 1023) / 1024;
            if (diskGB == 0) diskGB = 20;
            String diskSize = {};
            diskSize.assignItoa(diskGB);
            awsAppendQueryParam(body, "BlockDeviceMapping.1.DeviceName"_ctv, "/dev/xvda"_ctv, first);
            awsAppendQueryParam(body, "BlockDeviceMapping.1.Ebs.VolumeSize"_ctv, diskSize, first);
            awsAppendQueryParam(body, "BlockDeviceMapping.1.Ebs.DeleteOnTermination"_ctv, "true"_ctv, first);
         }

         String response = {};
         if (request(body, response, error) == false)
         {
            terminateCreatedInstances(createdInstanceIDs);
            return;
         }

         Vector<String> launchedInstanceBlocks = {};
         awsCollectInstanceBlocks(response, launchedInstanceBlocks);
         if (launchedInstanceBlocks.size() != count)
         {
            error.snprintf<"aws RunInstances returned {itoa} instances but {itoa} were requested"_ctv>(
               uint32_t(launchedInstanceBlocks.size()),
               count);
            terminateCreatedInstances(createdInstanceIDs);
            return;
         }

         for (const String& launchedInstanceBlock : launchedInstanceBlocks)
         {
            String instanceID = {};
            if (awsExtractXMLValue(launchedInstanceBlock, "instanceId", instanceID) == false)
            {
               error.assign("aws RunInstances response missing instanceId"_ctv);
               terminateCreatedInstances(createdInstanceIDs);
               return;
            }

            createdInstanceIDs.push_back(instanceID);
            MachineProvisioningProgress& progress = provisioningProgress.upsert(config.slug, config.providerMachineType, instanceID, instanceID);
            progress.status.assign("launch-submitted"_ctv);
            progress.ready = false;
            provisioningProgress.notifyMachineProvisioningAccepted(instanceID);
            provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
         }
      }

      if (createdInstanceIDs.size() == 0)
      {
         return;
      }

      bool first = true;
      String describeFilters = {};
      for (uint32_t index = 0; index < createdInstanceIDs.size(); ++index)
      {
         String key = {};
         key.snprintf<"InstanceId.{itoa}"_ctv>(index + 1);
         awsAppendQueryParam(describeFilters, key, createdInstanceIDs[index], first);
      }

      Vector<String> instanceBlocks;
      int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(prodigyMachineProvisioningTimeoutMs);
      while (Time::now<TimeResolution::ms>() < deadlineMs)
      {
         describeInstances(describeFilters, instanceBlocks, error);
         if (error.size() > 0)
         {
            if (awsContainsCString(error, "InvalidInstanceID.NotFound")
               || awsContainsCString(error, "does not exist")
               || awsContainsCString(error, "do not exist"))
            {
               error.clear();
               usleep(useconds_t(prodigyMachineProvisioningPollSleepMs) * 1000u);
               continue;
            }

            return;
         }

         for (const String& instanceID : createdInstanceIDs)
         {
            MachineProvisioningProgress& progress = provisioningProgress.upsert(config.slug, config.providerMachineType, instanceID, instanceID);
            progress.status.assign("waiting-for-running"_ctv);
            progress.ready = false;
         }

         bool ready = (instanceBlocks.size() == createdInstanceIDs.size());
         if (ready)
         {
            for (const String& block : instanceBlocks)
            {
               String stateName;
               Machine *machine = buildMachineFromInstanceBlock(block);
               MachineProvisioningProgress& progress = provisioningProgress.upsert(config.slug, config.providerMachineType, machine->cloudID, machine->cloudID);
               prodigyPopulateMachineProvisioningProgressFromMachine(progress, *machine);
               if (awsExtractInstanceStateName(block, stateName) == false
                  || stateName != "running"_ctv
                  || prodigyMachineProvisioningReady(*machine) == false)
               {
                  progress.status = stateName.size() > 0 ? stateName : "waiting-for-running"_ctv;
                  progress.ready = false;
                  ready = false;
               }
               else
               {
                  progress.status.assign("running"_ctv);
                  progress.ready = true;
                  if (provisioningAlreadyReported(machine->cloudID) == false)
                  {
                     provisioningProgress.notifyMachineProvisioned(*machine);
                     provisionedInstanceIDs.push_back(machine->cloudID);
                  }
               }
               delete machine;
               if (ready == false)
               {
                  break;
               }
            }
         }

         provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());

         if (ready)
         {
            provisioningProgress.emitNow();
            break;
         }

         instanceBlocks.clear();
         usleep(useconds_t(prodigyMachineProvisioningPollSleepMs) * 1000u);
      }

      if (instanceBlocks.size() != createdInstanceIDs.size())
      {
         error.assign("aws instance provisioning timed out"_ctv);
         terminateCreatedInstances(createdInstanceIDs);
         return;
      }

      for (const String& block : instanceBlocks)
      {
         Machine *machine = buildMachineFromInstanceBlock(block);
         machine->lifetime = lifetime;
         newMachines.insert(machine);
      }
   }

   void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines) override
   {
      (void)coro;
      if (metro.size() > 0 && ensureRegion() && metro != region)
      {
         return;
      }

      bool first = true;
      String filters = {};
      awsAppendQueryParam(filters, "Filter.1.Name"_ctv, "tag:app"_ctv, first);
      awsAppendQueryParam(filters, "Filter.1.Value.1"_ctv, "prodigy"_ctv, first);
      awsAppendQueryParam(filters, "Filter.2.Name"_ctv, "instance-state-name"_ctv, first);
      awsAppendQueryParam(filters, "Filter.2.Value.1"_ctv, "pending"_ctv, first);
      awsAppendQueryParam(filters, "Filter.2.Value.2"_ctv, "running"_ctv, first);
      awsAppendQueryParam(filters, "Filter.2.Value.3"_ctv, "stopping"_ctv, first);
      awsAppendQueryParam(filters, "Filter.2.Value.4"_ctv, "stopped"_ctv, first);

      Vector<String> instanceBlocks;
      String failure;
      describeInstances(filters, instanceBlocks, failure);
      if (failure.size() > 0)
      {
         return;
      }

      for (const String& block : instanceBlocks)
      {
         machines.insert(buildMachineFromInstanceBlock(block));
      }
   }

   void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains) override
   {
      (void)coro;
      selfIsBrain = false;

      bool first = true;
      String filters = {};
      awsAppendQueryParam(filters, "Filter.1.Name"_ctv, "tag:brain"_ctv, first);
      awsAppendQueryParam(filters, "Filter.1.Value.1"_ctv, "true"_ctv, first);
      awsAppendQueryParam(filters, "Filter.1.Value.2"_ctv, "1"_ctv, first);

      Vector<String> instanceBlocks;
      String failure;
      describeInstances(filters, instanceBlocks, failure);
      if (failure.size() > 0)
      {
         return;
      }

      for (const String& block : instanceBlocks)
      {
         Machine *machine = buildMachineFromInstanceBlock(block);
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
      bool first = true;
      String filters = {};
      awsAppendQueryParam(filters, "Filter.1.Name"_ctv, "tag:app"_ctv, first);
      awsAppendQueryParam(filters, "Filter.1.Value.1"_ctv, "prodigy"_ctv, first);

      Vector<String> instanceBlocks;
      String failure;
      describeInstances(filters, instanceBlocks, failure);
      if (failure.size() > 0)
      {
         return;
      }

      String instanceID;
      for (const String& block : instanceBlocks)
      {
         Machine *machine = buildMachineFromInstanceBlock(block);
         if (machine->uuid == uuid)
         {
            instanceID = machine->cloudID;
            delete machine;
            break;
         }

         delete machine;
      }

      if (instanceID.size() == 0)
      {
         return;
      }

      first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "RebootInstances"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "InstanceId.1"_ctv, instanceID, first);
      String response;
      (void)request(body, response, failure);
   }

   void reportHardwareFailure(uint128_t uuid, const String& report) override
   {
      (void)uuid;
      (void)report;
   }

   void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) override
   {
      (void)coro;

      bool first = true;
      String filters = {};
      awsAppendQueryParam(filters, "Filter.1.Name"_ctv, "tag:app"_ctv, first);
      awsAppendQueryParam(filters, "Filter.1.Value.1"_ctv, "prodigy"_ctv, first);
      awsAppendQueryParam(filters, "Filter.2.Name"_ctv, "instance-lifecycle"_ctv, first);
      awsAppendQueryParam(filters, "Filter.2.Value.1"_ctv, "spot"_ctv, first);
      awsAppendQueryParam(filters, "Filter.3.Name"_ctv, "instance-state-name"_ctv, first);
      awsAppendQueryParam(filters, "Filter.3.Value.1"_ctv, "shutting-down"_ctv, first);
      awsAppendQueryParam(filters, "Filter.3.Value.2"_ctv, "terminated"_ctv, first);

      Vector<String> instanceBlocks;
      String failure;
      describeInstances(filters, instanceBlocks, failure);
      if (failure.size() > 0)
      {
         return;
      }

      for (const String& block : instanceBlocks)
      {
         String instanceID;
         if (awsExtractXMLValue(block, "instanceId", instanceID))
         {
            decommissionedIDs.push_back(instanceID);
         }
      }
   }

   void destroyMachine(Machine *machine) override
   {
      if (machine == nullptr || machine->cloudID.size() == 0)
      {
         return;
      }

      bool first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "TerminateInstances"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "InstanceId.1"_ctv, machine->cloudID, first);
      String response;
      String failure;
      if (request(body, response, failure) == false)
      {
         return;
      }

      for (uint32_t attempt = 0; attempt < 30; ++attempt)
      {
         String describeFilters = {};
         bool describeFirst = true;
         awsAppendQueryParam(describeFilters, "InstanceId.1"_ctv, machine->cloudID, describeFirst);

         Vector<String> instanceBlocks;
         describeInstances(describeFilters, instanceBlocks, failure);
         if (failure.size() > 0)
         {
            return;
         }

         if (instanceBlocks.size() == 0)
         {
            return;
         }

         String stateName = {};
         if (awsExtractInstanceStateName(instanceBlocks[0], stateName)
            && (stateName == "shutting-down"_ctv || stateName == "terminated"_ctv))
         {
            return;
         }

         usleep(1000 * 1000);
      }
   }

   bool destroyClusterMachines(const String& clusterUUID, uint32_t& destroyed, String& error) override
   {
      destroyed = 0;
      error.clear();

      if (clusterUUID.size() == 0)
      {
         error.assign("aws clusterUUID tag value required"_ctv);
         return false;
      }

      bool first = true;
      String filters = {};
      awsAppendQueryParam(filters, "Filter.1.Name"_ctv, "tag:app"_ctv, first);
      awsAppendQueryParam(filters, "Filter.1.Value.1"_ctv, "prodigy"_ctv, first);
      awsAppendQueryParam(filters, "Filter.2.Name"_ctv, "tag:prodigy_cluster_uuid"_ctv, first);
      awsAppendQueryParam(filters, "Filter.2.Value.1"_ctv, clusterUUID, first);
      awsAppendQueryParam(filters, "Filter.3.Name"_ctv, "instance-state-name"_ctv, first);
      awsAppendQueryParam(filters, "Filter.3.Value.1"_ctv, "pending"_ctv, first);
      awsAppendQueryParam(filters, "Filter.3.Value.2"_ctv, "running"_ctv, first);
      awsAppendQueryParam(filters, "Filter.3.Value.3"_ctv, "stopping"_ctv, first);
      awsAppendQueryParam(filters, "Filter.3.Value.4"_ctv, "stopped"_ctv, first);

      Vector<String> instanceBlocks = {};
      describeInstances(filters, instanceBlocks, error);
      if (error.size() > 0)
      {
         return false;
      }

      Vector<String> cloudIDs = {};
      for (const String& block : instanceBlocks)
      {
         String instanceID = {};
         if (awsExtractXMLValue(block, "instanceId", instanceID))
         {
            cloudIDs.push_back(instanceID);
         }
      }

      if (cloudIDs.size() == 0)
      {
         return true;
      }

      destroyed = uint32_t(cloudIDs.size());

      String body = {};
      first = true;
      awsAppendQueryParam(body, "Action"_ctv, "TerminateInstances"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      for (uint32_t index = 0; index < cloudIDs.size(); ++index)
      {
         String key = {};
         key.snprintf<"InstanceId.{}"_ctv>(index + 1);
         awsAppendQueryParam(body, key, cloudIDs[index], first);
      }

      String response = {};
      if (request(body, response, error) == false)
      {
         return false;
      }

      String pendingFilters = {};
      first = true;
      awsAppendQueryParam(pendingFilters, "Filter.1.Name"_ctv, "tag:app"_ctv, first);
      awsAppendQueryParam(pendingFilters, "Filter.1.Value.1"_ctv, "prodigy"_ctv, first);
      awsAppendQueryParam(pendingFilters, "Filter.2.Name"_ctv, "tag:prodigy_cluster_uuid"_ctv, first);
      awsAppendQueryParam(pendingFilters, "Filter.2.Value.1"_ctv, clusterUUID, first);
      awsAppendQueryParam(pendingFilters, "Filter.3.Name"_ctv, "instance-state-name"_ctv, first);
      awsAppendQueryParam(pendingFilters, "Filter.3.Value.1"_ctv, "pending"_ctv, first);
      awsAppendQueryParam(pendingFilters, "Filter.3.Value.2"_ctv, "running"_ctv, first);
      awsAppendQueryParam(pendingFilters, "Filter.3.Value.3"_ctv, "stopping"_ctv, first);
      awsAppendQueryParam(pendingFilters, "Filter.3.Value.4"_ctv, "stopped"_ctv, first);
      awsAppendQueryParam(pendingFilters, "Filter.3.Value.5"_ctv, "shutting-down"_ctv, first);

      for (uint32_t attempt = 0; attempt < 60; ++attempt)
      {
         instanceBlocks.clear();
         describeInstances(pendingFilters, instanceBlocks, error);
         if (error.size() > 0)
         {
            return false;
         }

         if (instanceBlocks.size() == 0)
         {
            return true;
         }

         usleep(1000 * 1000);
      }

      error.assign("timed out waiting for aws cluster machines to terminate"_ctv);
      return false;
   }

   bool ensureProdigyMachineTags(const String& clusterUUID, Machine *machine, String& error) override
   {
      error.clear();

      if (machine == nullptr || machine->cloudID.size() == 0)
      {
         error.assign("aws machine cloudID required"_ctv);
         return false;
      }

      if (clusterUUID.size() == 0)
      {
         error.assign("aws clusterUUID tag value required"_ctv);
         return false;
      }

      bool first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "CreateTags"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "ResourceId.1"_ctv, machine->cloudID, first);
      awsAppendQueryParam(body, "Tag.1.Key"_ctv, "app"_ctv, first);
      awsAppendQueryParam(body, "Tag.1.Value"_ctv, "prodigy"_ctv, first);
      awsAppendQueryParam(body, "Tag.2.Key"_ctv, "prodigy_cluster_uuid"_ctv, first);
      awsAppendQueryParam(body, "Tag.2.Value"_ctv, clusterUUID, first);

      String response = {};
      return request(body, response, error);
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

      if (machine == nullptr || machine->cloudID.size() == 0)
      {
         error.assign("aws elastic address requires a cloud-backed target machine"_ctv);
         return false;
      }

      if (family != ExternalAddressFamily::ipv4)
      {
         error.assign("aws elastic addresses currently support only ipv4"_ctv);
         return false;
      }

      String publicAddress = {};
      if (requestedAddress.size() > 0)
      {
         if (providerPool.size() > 0)
         {
            error.assign("aws elastic address cannot combine requestedAddress with providerPool"_ctv);
            return false;
         }

         String existingAssociationID = {};
         if (describeElasticAddressByPublicIP(requestedAddress, publicAddress, allocationID, existingAssociationID, error) == false)
         {
            return false;
         }

         releaseOnRemove = false;
      }
      else
      {
         if (allocateElasticAddress(providerPool, publicAddress, allocationID, error) == false)
         {
            return false;
         }

         releaseOnRemove = true;
      }

      if (associateElasticAddress(allocationID, machine->cloudID, associationID, error) == false)
      {
         if (releaseOnRemove)
         {
            String releaseFailure = {};
            (void)releaseElasticAddressAllocation(allocationID, releaseFailure);
         }

         return false;
      }

      if (ClusterMachine::parseIPAddressLiteral(publicAddress, assignedAddress) == false)
      {
         error.assign("aws elastic address parse failed"_ctv);
         if (associationID.size() > 0)
         {
            String disassociateFailure = {};
            (void)disassociateElasticAddress(associationID, disassociateFailure);
         }
         if (releaseOnRemove)
         {
            String releaseFailure = {};
            (void)releaseElasticAddressAllocation(allocationID, releaseFailure);
         }
         return false;
      }

      error.clear();
      return true;
   }

   bool releaseProviderElasticAddress(const RegisteredRoutableAddress& address, String& error) override
   {
      error.clear();

      if (address.kind != RoutableAddressKind::providerElasticAddress)
      {
         return true;
      }

      if (disassociateElasticAddress(address.providerAssociationID, error) == false)
      {
         return false;
      }

      if (address.releaseOnRemove)
      {
         if (releaseElasticAddressAllocation(address.providerAllocationID, error) == false)
         {
            return false;
         }
      }

      error.clear();
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
