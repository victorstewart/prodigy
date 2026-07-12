#pragma once

#include <prodigy/dns/provider.http.h>

class CloudflareDNSProvider : public ProdigyHTTPDNSProvider {
public:

  CloudflareDNSProvider()
      : ProdigyHTTPDNSProvider("api.cloudflare.com"_ctv)
  {}

  bool supportsProvider(const String& provider) const override
  {
    return routableResourceDNSPartEquals(provider, "cloudflare"_ctv, false);
  }

  ProdigyHostTask<bool> upsert(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    String id = {};
    ProdigyDNSRecordPresence presence = {};
    if (co_await findRecord(coro, record, credential, presence, id, failure) == false)
    {
      co_return false;
    }
    if (presence == ProdigyDNSRecordPresence::exact)
    {
      failure.clear();
      co_return true;
    }
    co_return co_await create(coro, record, credential, failure);
  }

  ProdigyHostTask<bool> remove(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    String id = {};
    ProdigyDNSRecordPresence presence = {};
    if (co_await findRecord(coro, record, credential, presence, id, failure) == false)
    {
      co_return false;
    }
    if (presence == ProdigyDNSRecordPresence::missing)
    {
      failure.clear();
      co_return true;
    }

    co_return co_await removeExact(coro, record, credential, id, failure);
  }

  ProdigyHostTask<bool> presentTXT(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    co_return co_await changeTXT(coro, false, record, credential, failure);
  }

  ProdigyHostTask<bool> cleanupTXT(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    co_return co_await changeTXT(coro, true, record, credential, failure);
  }

private:

  bool cloudflareURL(const ProdigyDNSRecordBinding& record, const String& id, String& url, String& failure)
  {
    String zone = {};
    if (prodigyDNSEncodePathPart(record.zone, zone, failure) == false)
    {
      return false;
    }
    url.snprintf<"https://api.cloudflare.com/client/v4/zones/{}/dns_records"_ctv>(zone);
    if (id.size() > 0)
    {
      String encodedID = {};
      if (prodigyDNSEncodePathPart(id, encodedID, failure) == false)
      {
        return false;
      }
      url.snprintf_add<"/{}"_ctv>(encodedID);
    }
    return true;
  }

  ProdigyHostTask<bool> changeTXT(CoroutineStack *coro, bool removing, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure)
  {
    String ignored = {};
    if (prodigyDNSRecordSingleTXTValue(record, ignored, failure) == false)
    {
      co_return false;
    }
    String id = {};
    ProdigyDNSRecordPresence presence = {};
    if (co_await findRecord(coro, record, credential, presence, id, failure, true) == false)
    {
      co_return false;
    }
    if (presence == ProdigyDNSRecordPresence::exact)
    {
      co_return removing ? co_await removeExact(coro, record, credential, id, failure) : true;
    }
    if (removing)
    {
      failure.clear();
      co_return true;
    }
    co_return co_await create(coro, record, credential, failure);
  }

  ProdigyHostTask<bool> create(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure)
  {
    ProdigyDNSHTTPRequest request = {};
    request.method = MultiCurlClient::Method::post;
    if (cloudflareURL(record, {}, request.url, failure) == false)
    {
      co_return false;
    }
    request.headers.push_back({"Content-Type"_ctv, "application/json"_ctv});
    request.bearer(credential.material);
    String name = cloudflareRecordName(record.name);
    if (prodigyDNSAppendRecordJSON(request.body, record, "content", &name, failure) == false)
    {
      co_return false;
    }
    String response = {};
    long httpCode = 0;
    co_return acceptHTTP(co_await sendHTTP(coro, request, response, httpCode, failure), httpCode, response, failure, "cloudflare dns upsert failed");
  }

  ProdigyHostTask<bool> removeExact(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, const String& id, String& failure)
  {
    ProdigyDNSHTTPRequest request = {};
    request.method = MultiCurlClient::Method::delete_;
    if (cloudflareURL(record, id, request.url, failure) == false)
    {
      co_return false;
    }
    request.bearer(credential.material);
    String response = {};
    long httpCode = 0;
    co_return acceptHTTP(co_await sendHTTP(coro, request, response, httpCode, failure), httpCode, response, failure, "cloudflare dns delete failed");
  }

  ProdigyHostTask<bool> findRecord(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, ProdigyDNSRecordPresence& presence, String& id, String& failure, bool exactOnly = false)
  {
    ProdigyDNSHTTPRequest request = {};
    request.method = MultiCurlClient::Method::get;
    if (cloudflareURL(record, {}, request.url, failure) == false)
    {
      co_return false;
    }
    String type = {};
    String name = {};
    String normalizedName = cloudflareRecordName(record.name);
    if (prodigyDNSEncodePathPart(record.type, type, failure) == false || prodigyDNSEncodePathPart(normalizedName, name, failure) == false)
    {
      co_return false;
    }
    request.url.snprintf_add<"?type={}&name={}"_ctv>(type, name);
    request.bearer(credential.material);
    String response = {};
    long httpCode = 0;
    if (acceptHTTP(co_await sendHTTP(coro, request, response, httpCode, failure), httpCode, response, failure, "cloudflare dns list failed") == false)
    {
      co_return false;
    }
    co_return prodigyDNSFindJSONRecord(response, "result", record, normalizedName, "content", exactOnly, presence, id, failure);
  }

  static String cloudflareRecordName(const String& name)
  {
    String value = name;
    while (value.size() > 0 && value[value.size() - 1] == '.')
    {
      value.resize(value.size() - 1);
    }
    return value;
  }
};
