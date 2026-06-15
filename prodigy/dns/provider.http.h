#pragma once

#include <cctype>
#include <string_view>

#include <curl/curl.h>
#include <simdjson.h>

#include <prodigy/dns.provider.h>

class ProdigyDNSHTTPRequest {
public:

  String method;
  String url;
  struct curl_slist *headers = nullptr;
  String body;

  ~ProdigyDNSHTTPRequest()
  {
    curl_slist_free_all(headers);
  }

  void header(const char *value)
  {
    headers = curl_slist_append(headers, value);
  }

  void bearer(const String& token)
  {
    String value = {};
    value.snprintf<"Authorization: Bearer {}"_ctv>(token);
    header(value.c_str());
  }
};

enum class ProdigyDNSRecordPresence : uint8_t {
  missing,
  exact,
};

static inline bool prodigyDNSCredentialMetadata(const ApiCredential& credential, const char *name, String& value)
{
  String key = {};
  key.assign(name);
  auto it = credential.metadata.find(key);
  if (it == credential.metadata.end() || it->second.size() == 0)
  {
    value.clear();
    return false;
  }
  value = it->second;
  return true;
}

static inline bool prodigyDNSEncodePathPart(const String& value, String& encoded, String& failure)
{
  encoded.clear();
  CURL *curl = curl_easy_init();
  if (curl == nullptr)
  {
    failure.assign("dns url encoder init failed"_ctv);
    return false;
  }

  String text = {};
  text.assign(value);
  char *escaped = curl_easy_escape(curl, text.c_str(), int(text.size()));
  if (escaped == nullptr)
  {
    curl_easy_cleanup(curl);
    failure.assign("dns url encoder escape failed"_ctv);
    return false;
  }
  encoded.assign(escaped);
  curl_free(escaped);
  curl_easy_cleanup(curl);
  return true;
}

static inline void prodigyDNSLowercase(const String& input, String& lower)
{
  lower.clear();
  lower.reserve(input.size());
  for (uint64_t index = 0; index < input.size(); ++index)
  {
    lower.append(char(std::tolower(static_cast<unsigned char>(input[index]))));
  }
}

static inline String prodigyDNSRelativeName(const String& name, const String& zone)
{
  String lowerName = {};
  String lowerZone = {};
  prodigyDNSLowercase(name, lowerName);
  prodigyDNSLowercase(zone, lowerZone);
  while (lowerName.size() > 0 && lowerName[lowerName.size() - 1] == '.')
  {
    lowerName.resize(lowerName.size() - 1);
  }
  while (lowerZone.size() > 0 && lowerZone[lowerZone.size() - 1] == '.')
  {
    lowerZone.resize(lowerZone.size() - 1);
  }
  if (lowerName.equal(lowerZone))
  {
    return String();
  }

  String suffix = {};
  suffix.snprintf<".{}"_ctv>(lowerZone);
  if (lowerName.size() > suffix.size() && lowerName.substr(lowerName.size() - suffix.size(), suffix.size()).equal(suffix))
  {
    return name.substr(0, lowerName.size() - suffix.size(), Copy::yes);
  }
  return name;
}

static inline void prodigyDNSAppendJSONKV(String& json, const char *key, const String& value, bool comma = true)
{
  if (comma)
  {
    json.append(',');
  }
  json.append('"');
  json.append(key);
  json.append("\":"_ctv);
  appendEscapedJSONString(json, value);
}

static inline bool prodigyDNSAppendRecordJSON(String& body, const ProdigyDNSRecordBinding& record, const char *valueKey, const String *nameOverride, String& failure)
{
  String value = {};
  if (prodigyDNSRecordSingleValue(record, value, failure) == false)
  {
    return false;
  }

  body.assign("{\"type\":"_ctv);
  appendEscapedJSONString(body, record.type);
  prodigyDNSAppendJSONKV(body, "name", nameOverride ? *nameOverride : record.name);
  prodigyDNSAppendJSONKV(body, valueKey, value);
  body.snprintf_add<",\"ttl\":{itoa}}"_ctv>(record.ttl);
  return true;
}

static inline bool prodigyDNSOneValue(simdjson::dom::array values, const String& value)
{
  uint32_t n = 0;
  for (simdjson::dom::element item : values)
  {
    std::string_view text = {};
    if (item.get(text) != simdjson::SUCCESS || String(text).equals(value) == false)
    {
      return false;
    }
    n += 1;
  }
  return n == 1;
}

static inline bool prodigyDNSExistingRecordConflict(String& failure)
{
  failure.assign("DNS record already exists with different value"_ctv);
  return false;
}

static inline bool prodigyDNSFindJSONRecord(const String& response, const char *arrayName, const ProdigyDNSRecordBinding& record, const String& name, const char *valueField, ProdigyDNSRecordPresence& presence, String& id, String& failure)
{
  presence = ProdigyDNSRecordPresence::missing;
  id.clear();
  String recordValue = {};
  if (prodigyDNSRecordSingleValue(record, recordValue, failure) == false)
  {
    return false;
  }

  String text = {};
  text.assign(response);
  text.need(simdjson::SIMDJSON_PADDING);
  simdjson::dom::parser parser;
  simdjson::dom::element doc;
  if (parser.parse(text.data(), text.size()).get(doc))
  {
    failure.assign("dns list response parse failed"_ctv);
    return false;
  }

  simdjson::dom::array rows;
  if (doc[arrayName].get(rows) != simdjson::SUCCESS)
  {
    failure.assign("dns list response missing records"_ctv);
    return false;
  }

  for (simdjson::dom::element row : rows)
  {
    std::string_view rowID = {};
    std::string_view rowType = {};
    std::string_view rowName = {};
    std::string_view rowValue = {};
    if (row["id"].get(rowID) == simdjson::SUCCESS &&
        row["type"].get(rowType) == simdjson::SUCCESS &&
        row["name"].get(rowName) == simdjson::SUCCESS &&
        row[valueField].get(rowValue) == simdjson::SUCCESS &&
        routableResourceDNSPartEquals(String(rowType), record.type, false) &&
        routableResourceDNSPartEquals(String(rowName), name, true))
    {
      if (String(rowValue).equals(recordValue) == false)
      {
        return prodigyDNSExistingRecordConflict(failure);
      }
      presence = ProdigyDNSRecordPresence::exact;
      id.assign(rowID);
      return true;
    }
  }
  failure.clear();
  return true;
}

static inline bool prodigyDNSFindGcpRecord(const String& response, const ProdigyDNSRecordBinding& record, ProdigyDNSRecordPresence& presence, String& failure)
{
  presence = ProdigyDNSRecordPresence::missing;
  String recordValue = {};
  if (prodigyDNSRecordSingleValue(record, recordValue, failure) == false)
  {
    return false;
  }

  String text = {};
  text.assign(response);
  text.need(simdjson::SIMDJSON_PADDING);
  simdjson::dom::parser parser;
  simdjson::dom::element doc;
  if (parser.parse(text.data(), text.size()).get(doc))
  {
    failure.assign("gcp cloud dns rrset parse failed"_ctv);
    return false;
  }

  simdjson::dom::array rows;
  if (doc["rrsets"].get(rows) != simdjson::SUCCESS)
  {
    failure.clear();
    return true;
  }

  for (simdjson::dom::element row : rows)
  {
    std::string_view rowName = {};
    std::string_view rowType = {};
    simdjson::dom::array values;
    if (row["name"].get(rowName) == simdjson::SUCCESS &&
        row["type"].get(rowType) == simdjson::SUCCESS &&
        row["rrdatas"].get(values) == simdjson::SUCCESS &&
        routableResourceDNSPartEquals(String(rowName), record.name, true) &&
        routableResourceDNSPartEquals(String(rowType), record.type, false))
    {
      if (prodigyDNSOneValue(values, recordValue) == false)
      {
        return prodigyDNSExistingRecordConflict(failure);
      }
      presence = ProdigyDNSRecordPresence::exact;
      failure.clear();
      return true;
    }
  }
  failure.clear();
  return true;
}

static inline bool prodigyDNSFindAzureRecord(const String& response, const ProdigyDNSRecordBinding& record, ProdigyDNSRecordPresence& presence, String& failure)
{
  presence = ProdigyDNSRecordPresence::missing;
  String recordValue = {};
  if (prodigyDNSRecordSingleValue(record, recordValue, failure) == false)
  {
    return false;
  }

  String text = {};
  text.assign(response);
  text.need(simdjson::SIMDJSON_PADDING);
  simdjson::dom::parser parser;
  simdjson::dom::element doc;
  if (parser.parse(text.data(), text.size()).get(doc))
  {
    failure.assign("azure dns record set parse failed"_ctv);
    return false;
  }

  simdjson::dom::element properties;
  simdjson::dom::array rows;
  const char *arrayName = record.type.equal("AAAA"_ctv) ? "AAAARecords" : "ARecords";
  const char *valueName = record.type.equal("AAAA"_ctv) ? "ipv6Address" : "ipv4Address";
  if (doc["properties"].get(properties) != simdjson::SUCCESS || properties[arrayName].get(rows) != simdjson::SUCCESS)
  {
    failure.clear();
    return true;
  }

  uint32_t n = 0;
  for (simdjson::dom::element row : rows)
  {
    std::string_view value = {};
    if (row[valueName].get(value) != simdjson::SUCCESS || String(value).equals(recordValue) == false)
    {
      return prodigyDNSExistingRecordConflict(failure);
    }
    n += 1;
  }
  presence = n == 1 ? ProdigyDNSRecordPresence::exact : ProdigyDNSRecordPresence::missing;
  failure.clear();
  return true;
}

class ProdigyHTTPDNSProvider : public ProdigyDNSProvider {
protected:

  virtual bool sendHTTP(ProdigyDNSHTTPRequest& request, String& response, long& httpCode, String& failure)
  {
    response.clear();
    failure.clear();
    httpCode = 0;
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
    {
      failure.assign("dns curl init failed"_ctv);
      return false;
    }

    CURL *curl = curl_easy_init();
    if (curl == nullptr)
    {
      failure.assign("dns curl easy init failed"_ctv);
      return false;
    }

    String method = {};
    String url = {};
    method.assign(request.method);
    url.assign(request.url);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 10'000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 60'000L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, request.headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
      String *out = reinterpret_cast<String *>(userdata);
      out->append(reinterpret_cast<uint8_t *>(ptr), size * nmemb);
      return size * nmemb;
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    String body = {};
    if (request.body.size() > 0)
    {
      body.assign(request.body);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, long(body.size()));
    }

    CURLcode rc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK)
    {
      failure.assign(curl_easy_strerror(rc));
      return false;
    }
    return true;
  }

  bool acceptHTTP(bool ok, long httpCode, const String& response, String& failure, const char *context)
  {
    if (ok == false)
    {
      if (failure.size() == 0)
      {
        failure.assign(context);
      }
      return false;
    }
    if (httpCode >= 200 && httpCode < 300)
    {
      failure.clear();
      return true;
    }

    failure.assign(context);
    failure.snprintf_add<" [http={itoa}]"_ctv>(uint32_t(httpCode));
    if (response.size() > 0)
    {
      failure.append(": "_ctv);
      failure.append(response);
    }
    return false;
  }
};
