#pragma once

#include <algorithm>
#include <cctype>
#include <string_view>

#include <simdjson.h>

#include <prodigy/command.capture.h>
#include <prodigy/dns.provider.h>
#include <prodigy/json.h>

class ProdigyDNSHTTPRequest {
public:

  MultiCurlClient::Method method = MultiCurlClient::Method::get;
  String url;
  Vector<MultiCurlClient::Header> headers;
  String body;

  void bearer(const String& token)
  {
    String value = {};
    value.snprintf<"Bearer {}"_ctv>(token);
    headers.push_back({"Authorization"_ctv, std::move(value)});
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

static inline ProdigyHostTask<bool> prodigyDNSResolveBearerToken(CoroutineStack *coro,
                                                                 const ApiCredential& credential,
                                                                 String& token,
                                                                 String& failure,
                                                                 MultiCurlClient::TimePoint deadline)
{
  String command = {};
  if (prodigyDNSCredentialMetadata(credential, "bearerRefreshCommand", command))
  {
    if (co_await ProdigyCommandCapture::run(coro,
                                            command,
                                            token,
                                            deadline,
                                            &failure) == false)
    {
      co_return false;
    }
    if (token.size() == 0)
    {
      failure.assign("DNS bearer refresh command returned empty output"_ctv);
      co_return false;
    }
    co_return true;
  }
  if (credential.material.size() > 0)
  {
    token = credential.material;
    failure.clear();
    co_return true;
  }
  failure.assign("DNS bearer credential material or metadata.bearerRefreshCommand required"_ctv);
  co_return false;
}

static inline ProdigyHostTask<bool> prodigyDNSApplyBearerAuth(CoroutineStack *coro,
                                                              ProdigyDNSHTTPRequest& request,
                                                              const ApiCredential& credential,
                                                              String& failure,
                                                              MultiCurlClient::TimePoint deadline)
{
  String token = {};
  if (co_await prodigyDNSResolveBearerToken(coro, credential, token, failure, deadline) == false)
  {
    co_return false;
  }
  request.bearer(token);
  co_return true;
}

static inline bool prodigyDNSEncodePathPart(const String& value, String& encoded, String& failure)
{
  encoded.clear();
  constexpr static char hex[] = "0123456789ABCDEF";
  for (uint64_t index = 0; index < value.size(); ++index)
  {
    const uint8_t byte = value[index];
    const bool unreserved = (byte >= 'A' && byte <= 'Z') ||
                            (byte >= 'a' && byte <= 'z') ||
                            (byte >= '0' && byte <= '9') ||
                            byte == '-' || byte == '_' || byte == '.' || byte == '~';
    if (unreserved)
    {
      encoded.append(byte);
    }
    else
    {
      encoded.append('%');
      encoded.append(uint8_t(hex[(byte >> 4) & 0x0f]));
      encoded.append(uint8_t(hex[byte & 0x0f]));
    }
  }
  failure.clear();
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
  prodigyAppendEscapedJSONStringLiteral(json, value);
}

static inline bool prodigyDNSAppendRecordJSON(String& body, const ProdigyDNSRecordBinding& record, const char *valueKey, const String *nameOverride, String& failure)
{
  String value = {};
  if (prodigyDNSRecordSingleValue(record, value, failure) == false)
  {
    return false;
  }

  body.assign("{\"type\":"_ctv);
  prodigyAppendEscapedJSONStringLiteral(body, record.type);
  prodigyDNSAppendJSONKV(body, "name", nameOverride ? *nameOverride : record.name);
  prodigyDNSAppendJSONKV(body, valueKey, value);
  body.snprintf_add<",\"ttl\":{itoa}}"_ctv>(record.ttl);
  return true;
}

static inline void prodigyDNSQuoteTXTValue(const String& value, String& quoted)
{
  quoted.assign("\""_ctv);
  for (uint64_t index = 0; index < value.size(); ++index)
  {
    if (value[index] == '"' || value[index] == '\\')
    {
      quoted.append('\\');
    }
    quoted.append(value[index]);
  }
  quoted.append('"');
}

static inline void prodigyDNSUnquoteTXTValue(const String& value, String& unquoted)
{
  unquoted.clear();
  if (value.size() < 2 || value[0] != '"' || value[value.size() - 1] != '"')
  {
    unquoted = value;
    return;
  }
  for (uint64_t index = 1; index + 1 < value.size(); ++index)
  {
    if (value[index] == '\\' && index + 2 < value.size())
    {
      index += 1;
    }
    unquoted.append(value[index]);
  }
}

static inline bool prodigyDNSProviderValueEquals(const ProdigyDNSRecordBinding& record, const String& providerValue, const String& rawValue)
{
  if (routableResourceDNSPartEquals(record.type, "TXT"_ctv, false) == false)
  {
    return providerValue.equals(rawValue);
  }
  String unquoted = {};
  prodigyDNSUnquoteTXTValue(providerValue, unquoted);
  return unquoted.equals(rawValue);
}

static inline bool prodigyDNSValuesContain(const ProdigyDNSRecordBinding& record, const Vector<String>& values, const String& rawValue)
{
  for (const String& value : values)
  {
    if (prodigyDNSProviderValueEquals(record, value, rawValue))
    {
      return true;
    }
  }
  return false;
}

static inline bool prodigyDNSRemoveProviderValue(const ProdigyDNSRecordBinding& record, Vector<String>& values, const String& rawValue)
{
  for (auto it = values.begin(); it != values.end(); ++it)
  {
    if (prodigyDNSProviderValueEquals(record, *it, rawValue))
    {
      values.erase(it);
      return true;
    }
  }
  return false;
}

static inline void prodigyDNSAppendGcpRRSet(String& body, const ProdigyDNSRecordBinding& record, const Vector<String>& values)
{
  body.append("{\"name\":"_ctv);
  prodigyAppendEscapedJSONStringLiteral(body, record.name);
  prodigyDNSAppendJSONKV(body, "type", record.type);
  body.snprintf_add<",\"ttl\":{itoa},\"rrdatas\":["_ctv>(record.ttl);
  for (uint64_t index = 0; index < values.size(); ++index)
  {
    if (index > 0)
    {
      body.append(',');
    }
    prodigyAppendEscapedJSONStringLiteral(body, values[index]);
  }
  body.append("]}"_ctv);
}

static inline void prodigyDNSAppendAzureRecordSetJSON(String& body, const ProdigyDNSRecordBinding& record, const Vector<String>& values)
{
  body.snprintf<"{\"properties\":{\"TTL\":{itoa},\""_ctv>(record.ttl);
  if (routableResourceDNSPartEquals(record.type, "TXT"_ctv, false))
  {
    body.append("TXTRecords\":["_ctv);
    for (uint64_t index = 0; index < values.size(); ++index)
    {
      if (index > 0)
      {
        body.append(',');
      }
      body.append("{\"value\":["_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, values[index]);
      body.append("]}"_ctv);
    }
    body.append("]}}"_ctv);
    return;
  }
  body.append(record.type.equal("AAAA"_ctv) ? "AAAARecords\":[{\"ipv6Address\":" : "ARecords\":[{\"ipv4Address\":");
  prodigyAppendEscapedJSONStringLiteral(body, values[0]);
  body.append("}]}}"_ctv);
}

static inline bool prodigyDNSExistingRecordConflict(String& failure)
{
  failure.assign("DNS record already exists with different value"_ctv);
  return false;
}

static inline bool prodigyDNSFindJSONRecord(
    const String& response,
    const char *arrayName,
    const ProdigyDNSRecordBinding& record,
    const String& name,
    const char *valueField,
    bool exactOnly,
    ProdigyDNSRecordPresence& presence,
    String& id,
    String& failure)
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
      if (prodigyDNSProviderValueEquals(record, String(rowValue), recordValue) == false)
      {
        if (exactOnly)
        {
          continue;
        }
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

static inline bool prodigyDNSCollectGcpRecordValues(const String& response, const ProdigyDNSRecordBinding& record, Vector<String>& values, bool& found, String& failure)
{
  values.clear();
  found = false;

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
    simdjson::dom::array rrdatas;
    if (row["name"].get(rowName) == simdjson::SUCCESS &&
        row["type"].get(rowType) == simdjson::SUCCESS &&
        row["rrdatas"].get(rrdatas) == simdjson::SUCCESS &&
        routableResourceDNSPartEquals(String(rowName), record.name, true) &&
        routableResourceDNSPartEquals(String(rowType), record.type, false))
    {
      found = true;
      values.clear();
      for (simdjson::dom::element item : rrdatas)
      {
        std::string_view value = {};
        if (item.get(value) != simdjson::SUCCESS)
        {
          failure.assign("gcp cloud dns rrset parse failed"_ctv);
          return false;
        }
        values.push_back(String(value));
      }
      failure.clear();
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

  Vector<String> values = {};
  bool found = false;
  if (prodigyDNSCollectGcpRecordValues(response, record, values, found, failure) == false)
  {
    return false;
  }
  if (found == false)
  {
    failure.clear();
    return true;
  }
  if (values.size() != 1 || prodigyDNSProviderValueEquals(record, values[0], recordValue) == false)
  {
    return prodigyDNSExistingRecordConflict(failure);
  }
  presence = ProdigyDNSRecordPresence::exact;
  failure.clear();
  return true;
}

static inline bool prodigyDNSCollectAzureRecordValues(const String& response, const ProdigyDNSRecordBinding& record, Vector<String>& values, bool& found, String& failure)
{
  values.clear();
  found = false;

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
  const bool isAAAA = routableResourceDNSPartEquals(record.type, "AAAA"_ctv, false);
  const bool isTXT = routableResourceDNSPartEquals(record.type, "TXT"_ctv, false);
  const char *arrayName = isTXT ? "TXTRecords" : (isAAAA ? "AAAARecords" : "ARecords");
  const char *valueName = isTXT ? "value" : (isAAAA ? "ipv6Address" : "ipv4Address");
  if (doc["properties"].get(properties) != simdjson::SUCCESS || properties[arrayName].get(rows) != simdjson::SUCCESS)
  {
    failure.clear();
    return true;
  }

  found = true;
  for (simdjson::dom::element row : rows)
  {
    if (isTXT)
    {
      simdjson::dom::array strings;
      if (row[valueName].get(strings) != simdjson::SUCCESS)
      {
        failure.assign("azure dns record set parse failed"_ctv);
        return false;
      }
      String joined = {};
      for (simdjson::dom::element item : strings)
      {
        std::string_view value = {};
        if (item.get(value) != simdjson::SUCCESS)
        {
          failure.assign("azure dns record set parse failed"_ctv);
          return false;
        }
        joined.append(String(value));
      }
      values.push_back(joined);
      continue;
    }

    std::string_view value = {};
    if (row[valueName].get(value) != simdjson::SUCCESS)
    {
      failure.assign("azure dns record set parse failed"_ctv);
      return false;
    }
    values.push_back(String(value));
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

  Vector<String> values = {};
  bool found = false;
  if (prodigyDNSCollectAzureRecordValues(response, record, values, found, failure) == false)
  {
    return false;
  }
  if (found == false)
  {
    failure.clear();
    return true;
  }
  if (values.size() != 1 || prodigyDNSProviderValueEquals(record, values[0], recordValue) == false)
  {
    return prodigyDNSExistingRecordConflict(failure);
  }
  presence = ProdigyDNSRecordPresence::exact;
  failure.clear();
  return true;
}

class ProdigyHTTPDNSProvider : public ProdigyDNSProvider {
private:

  String requiredHost;

protected:

  explicit ProdigyHTTPDNSProvider(const String& host)
  {
    requiredHost.assign(host);
  }

  virtual ProdigyHostTask<bool> sendHTTP(CoroutineStack *coro,
                                         ProdigyDNSHTTPRequest& request,
                                         String& response,
                                         long& httpCode,
                                         String& failure)
  {
    response.clear();
    failure.clear();
    httpCode = 0;
    if (coro == nullptr || runtime.http.submit == nullptr || runtime.http.cancel == nullptr ||
        requiredHost.empty() || request.body.size() > 1024 * 1024)
    {
      failure.assign("DNS HTTP runtime or request unavailable"_ctv);
      co_return false;
    }

    MultiCurlClient::Request submitted;
    submitted.url.assign(request.url);
    submitted.method = request.method;
    submitted.headers = request.headers;
    submitted.body.assign(request.body);
    submitted.connectTimeout = std::chrono::seconds(10);
    submitted.firstByteTimeout = std::chrono::seconds(30);
    submitted.idleTimeout = std::chrono::seconds(30);
    submitted.responseBytes = 1024 * 1024;
    submitted.originPolicy.requiredScheme.assign("https"_ctv);
    submitted.originPolicy.requiredHost.assign(requiredHost);
    submitted.originPolicy.requiredAuthority.assign(requiredHost);
    submitted.originPolicy.requiredService.assign("443"_ctv);
    const MultiCurlClient::TimePoint localDeadline = MultiCurlClient::Clock::now() + std::chrono::seconds(60);
    submitted.overallDeadline = runtime.operationDeadline < localDeadline ? runtime.operationDeadline : localDeadline;

    ProdigyHostHttpOperation operation(runtime.http, *coro);
    if (operation.submit(std::move(submitted)) == false)
    {
      failure.assign("DNS HTTP request submission failed"_ctv);
      co_return false;
    }
    if (operation.mustSuspend())
    {
      co_await ProdigyHostSuspend(*coro);
    }
    if (operation.hasResult() == false)
    {
      failure.assign("DNS HTTP request canceled"_ctv);
      co_return false;
    }

    MultiCurlClient::Result result = operation.takeResult();
    response = std::move(result.body);
    httpCode = result.statusCode;
    if (result.status != MultiCurlClient::Status::success)
    {
      if (result.status == MultiCurlClient::Status::deadlineExceeded)
      {
        failure.assign("DNS HTTP request deadline exceeded"_ctv);
      }
      else
      {
        failure.assign("DNS HTTP transport failed"_ctv);
      }
      co_return false;
    }
    co_return true;
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
      const uint64_t detailBytes = std::min<uint64_t>(response.size(), 512);
      failure.append(response.data(), detailBytes);
      if (detailBytes < response.size())
      {
        failure.append("..."_ctv);
      }
    }
    return false;
  }
};
