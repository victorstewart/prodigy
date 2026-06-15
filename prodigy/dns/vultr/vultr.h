#pragma once

#include <prodigy/dns/provider.http.h>

class VultrDNSProvider : public ProdigyHTTPDNSProvider {
public:

  bool supportsProvider(const String& provider) const override
  {
    return routableResourceDNSPartEquals(provider, "vultr"_ctv, false) || routableResourceDNSPartEquals(provider, "vultr-dns"_ctv, false);
  }

  bool upsert(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    String id = {};
    String relativeName = prodigyDNSRelativeName(record.name, record.zone);
    ProdigyDNSRecordPresence presence = {};
    if (findRecord(record, relativeName, credential, presence, id, failure) == false)
    {
      return false;
    }
    if (presence == ProdigyDNSRecordPresence::exact)
    {
      failure.clear();
      return true;
    }

    ProdigyDNSHTTPRequest request = {};
    request.method.assign("POST"_ctv);
    if (vultrURL(record.zone, {}, request.url, failure) == false)
    {
      return false;
    }
    request.header("Content-Type: application/json");
    request.bearer(credential.material);
    if (prodigyDNSAppendRecordJSON(request.body, record, "data", &relativeName, failure) == false)
    {
      return false;
    }
    String response = {};
    long httpCode = 0;
    return acceptHTTP(sendHTTP(request, response, httpCode, failure), httpCode, response, failure, "vultr dns upsert failed");
  }

  bool remove(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    String id = {};
    String relativeName = prodigyDNSRelativeName(record.name, record.zone);
    ProdigyDNSRecordPresence presence = {};
    if (findRecord(record, relativeName, credential, presence, id, failure) == false)
    {
      return false;
    }
    if (presence == ProdigyDNSRecordPresence::missing)
    {
      failure.clear();
      return true;
    }

    ProdigyDNSHTTPRequest request = {};
    request.method.assign("DELETE"_ctv);
    if (vultrURL(record.zone, id, request.url, failure) == false)
    {
      return false;
    }
    request.bearer(credential.material);
    String response = {};
    long httpCode = 0;
    return acceptHTTP(sendHTTP(request, response, httpCode, failure), httpCode, response, failure, "vultr dns delete failed");
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

  bool findRecord(const ProdigyDNSRecordBinding& record, const String& relativeName, const ApiCredential& credential, ProdigyDNSRecordPresence& presence, String& id, String& failure)
  {
    ProdigyDNSHTTPRequest request = {};
    request.method.assign("GET"_ctv);
    if (vultrURL(record.zone, {}, request.url, failure) == false)
    {
      return false;
    }
    request.bearer(credential.material);
    String response = {};
    long httpCode = 0;
    if (acceptHTTP(sendHTTP(request, response, httpCode, failure), httpCode, response, failure, "vultr dns list failed") == false)
    {
      return false;
    }
    return prodigyDNSFindJSONRecord(response, "records", record, relativeName, "data", presence, id, failure);
  }
};
