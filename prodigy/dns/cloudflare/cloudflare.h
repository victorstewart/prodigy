#pragma once

#include <prodigy/dns/provider.http.h>

class CloudflareDNSProvider : public ProdigyHTTPDNSProvider {
public:

  bool supportsProvider(const String& provider) const override
  {
    return routableResourceDNSPartEquals(provider, "cloudflare"_ctv, false);
  }

  bool upsert(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    String id = {};
    ProdigyDNSRecordPresence presence = {};
    if (findRecord(record, credential, presence, id, failure) == false)
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
    if (cloudflareURL(record, {}, request.url, failure) == false)
    {
      return false;
    }
    request.header("Content-Type: application/json");
    request.bearer(credential.material);
    if (prodigyDNSAppendRecordJSON(request.body, record, "content", nullptr, failure) == false)
    {
      return false;
    }
    String response = {};
    long httpCode = 0;
    return acceptHTTP(sendHTTP(request, response, httpCode, failure), httpCode, response, failure, "cloudflare dns upsert failed");
  }

  bool remove(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    String id = {};
    ProdigyDNSRecordPresence presence = {};
    if (findRecord(record, credential, presence, id, failure) == false)
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
    if (cloudflareURL(record, id, request.url, failure) == false)
    {
      return false;
    }
    request.bearer(credential.material);
    String response = {};
    long httpCode = 0;
    return acceptHTTP(sendHTTP(request, response, httpCode, failure), httpCode, response, failure, "cloudflare dns delete failed");
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

  bool findRecord(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, ProdigyDNSRecordPresence& presence, String& id, String& failure)
  {
    ProdigyDNSHTTPRequest request = {};
    request.method.assign("GET"_ctv);
    if (cloudflareURL(record, {}, request.url, failure) == false)
    {
      return false;
    }
    String type = {};
    String name = {};
    if (prodigyDNSEncodePathPart(record.type, type, failure) == false || prodigyDNSEncodePathPart(record.name, name, failure) == false)
    {
      return false;
    }
    request.url.snprintf_add<"?type={}&name={}"_ctv>(type, name);
    request.bearer(credential.material);
    String response = {};
    long httpCode = 0;
    if (acceptHTTP(sendHTTP(request, response, httpCode, failure), httpCode, response, failure, "cloudflare dns list failed") == false)
    {
      return false;
    }
    return prodigyDNSFindJSONRecord(response, "result", record, record.name, "content", presence, id, failure);
  }
};
