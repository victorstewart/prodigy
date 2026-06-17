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
    return create(record, relativeName, credential, failure);
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

    return removeExact(record, credential, id, failure);
  }

  bool presentTXT(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    return changeTXT(false, record, credential, failure);
  }

  bool cleanupTXT(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    return changeTXT(true, record, credential, failure);
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

  bool changeTXT(bool removing, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure)
  {
    String ignored = {};
    if (prodigyDNSRecordSingleTXTValue(record, ignored, failure) == false)
    {
      return false;
    }
    String id = {};
    String relativeName = prodigyDNSRelativeName(record.name, record.zone);
    ProdigyDNSRecordPresence presence = {};
    if (findRecord(record, relativeName, credential, presence, id, failure, true) == false)
    {
      return false;
    }
    if (presence == ProdigyDNSRecordPresence::exact)
    {
      return removing ? removeExact(record, credential, id, failure) : true;
    }
    if (removing)
    {
      failure.clear();
      return true;
    }
    return create(record, relativeName, credential, failure);
  }

  bool create(const ProdigyDNSRecordBinding& record, const String& relativeName, const ApiCredential& credential, String& failure)
  {
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

  bool removeExact(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, const String& id, String& failure)
  {
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

  bool findRecord(const ProdigyDNSRecordBinding& record, const String& relativeName, const ApiCredential& credential, ProdigyDNSRecordPresence& presence, String& id, String& failure, bool exactOnly = false)
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
    return prodigyDNSFindJSONRecord(response, "records", record, relativeName, "data", exactOnly, presence, id, failure);
  }
};
