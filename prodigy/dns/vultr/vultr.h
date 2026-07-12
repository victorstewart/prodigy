#pragma once

#include <prodigy/dns/provider.http.h>

class VultrDNSProvider : public ProdigyHTTPDNSProvider {
public:

  VultrDNSProvider()
      : ProdigyHTTPDNSProvider("api.vultr.com"_ctv)
  {}

  bool supportsProvider(const String& provider) const override
  {
    return routableResourceDNSPartEquals(provider, "vultr"_ctv, false) || routableResourceDNSPartEquals(provider, "vultr-dns"_ctv, false);
  }

  ProdigyHostTask<bool> upsert(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    String id = {};
    String relativeName = prodigyDNSRelativeName(record.name, record.zone);
    ProdigyDNSRecordPresence presence = {};
    if (co_await findRecord(coro, record, relativeName, credential, presence, id, failure) == false)
    {
      co_return false;
    }
    if (presence == ProdigyDNSRecordPresence::exact)
    {
      failure.clear();
      co_return true;
    }
    co_return co_await create(coro, record, relativeName, credential, failure);
  }

  ProdigyHostTask<bool> remove(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    String id = {};
    String relativeName = prodigyDNSRelativeName(record.name, record.zone);
    ProdigyDNSRecordPresence presence = {};
    if (co_await findRecord(coro, record, relativeName, credential, presence, id, failure) == false)
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

  bool vultrURL(const String& zone, const String& id, String& url, String& failure)
  {
    String zonePath = {};
    if (prodigyDNSEncodePathPart(zone, zonePath, failure) == false)
    {
      return false;
    }
    url.snprintf<"https://api.vultr.com/v2/domains/{}/records"_ctv>(zonePath);
    if (id.size() > 0)
    {
      String idPath = {};
      if (prodigyDNSEncodePathPart(id, idPath, failure) == false)
      {
        return false;
      }
      url.snprintf_add<"/{}"_ctv>(idPath);
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
    String relativeName = prodigyDNSRelativeName(record.name, record.zone);
    ProdigyDNSRecordPresence presence = {};
    if (co_await findRecord(coro, record, relativeName, credential, presence, id, failure, true) == false)
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
    co_return co_await create(coro, record, relativeName, credential, failure);
  }

  ProdigyHostTask<bool> create(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const String& relativeName, const ApiCredential& credential, String& failure)
  {
    ProdigyDNSHTTPRequest request = {};
    request.method = MultiCurlClient::Method::post;
    if (vultrURL(record.zone, {}, request.url, failure) == false)
    {
      co_return false;
    }
    request.headers.push_back({"Content-Type"_ctv, "application/json"_ctv});
    request.bearer(credential.material);
    if (prodigyDNSAppendRecordJSON(request.body, record, "data", &relativeName, failure) == false)
    {
      co_return false;
    }
    String response = {};
    long httpCode = 0;
    co_return acceptHTTP(co_await sendHTTP(coro, request, response, httpCode, failure), httpCode, response, failure, "vultr dns upsert failed");
  }

  ProdigyHostTask<bool> removeExact(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, const String& id, String& failure)
  {
    ProdigyDNSHTTPRequest request = {};
    request.method = MultiCurlClient::Method::delete_;
    if (vultrURL(record.zone, id, request.url, failure) == false)
    {
      co_return false;
    }
    request.bearer(credential.material);
    String response = {};
    long httpCode = 0;
    co_return acceptHTTP(co_await sendHTTP(coro, request, response, httpCode, failure), httpCode, response, failure, "vultr dns delete failed");
  }

  ProdigyHostTask<bool> findRecord(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const String& relativeName, const ApiCredential& credential, ProdigyDNSRecordPresence& presence, String& id, String& failure, bool exactOnly = false)
  {
    ProdigyDNSHTTPRequest request = {};
    request.method = MultiCurlClient::Method::get;
    if (vultrURL(record.zone, {}, request.url, failure) == false)
    {
      co_return false;
    }
    request.bearer(credential.material);
    String response = {};
    long httpCode = 0;
    if (acceptHTTP(co_await sendHTTP(coro, request, response, httpCode, failure), httpCode, response, failure, "vultr dns list failed") == false)
    {
      co_return false;
    }
    co_return prodigyDNSFindJSONRecord(response, "records", record, relativeName, "data", exactOnly, presence, id, failure);
  }
};
