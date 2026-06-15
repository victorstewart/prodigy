#pragma once

#include <prodigy/dns/provider.http.h>

class AzureDNSProvider : public ProdigyHTTPDNSProvider {
public:

  bool supportsProvider(const String& provider) const override
  {
    return routableResourceDNSPartEquals(provider, "azure-dns"_ctv, false);
  }

  bool upsert(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    String url = {};
    if (recordSetURL(record, credential, url, failure) == false)
    {
      return false;
    }
    ProdigyDNSRecordPresence presence = {};
    if (findRecord(record, credential, url, presence, failure) == false)
    {
      return false;
    }
    if (presence == ProdigyDNSRecordPresence::exact)
    {
      failure.clear();
      return true;
    }
    String value = {};
    if (prodigyDNSRecordSingleValue(record, value, failure) == false)
    {
      return false;
    }

    ProdigyDNSHTTPRequest request = {};
    request.method.assign("PUT"_ctv);
    request.url = url;
    request.header("Content-Type: application/json");
    request.bearer(credential.material);
    request.body.snprintf<"{\"properties\":{\"TTL\":{itoa},\""_ctv>(record.ttl);
    request.body.append(record.type.equal("AAAA"_ctv) ? "AAAARecords\":[{\"ipv6Address\":" : "ARecords\":[{\"ipv4Address\":");
    appendEscapedJSONString(request.body, value);
    request.body.append("}]}}"_ctv);
    String response = {};
    long httpCode = 0;
    return acceptHTTP(sendHTTP(request, response, httpCode, failure), httpCode, response, failure, "azure dns upsert failed");
  }

  bool remove(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    String url = {};
    if (recordSetURL(record, credential, url, failure) == false)
    {
      return false;
    }
    ProdigyDNSRecordPresence presence = {};
    if (findRecord(record, credential, url, presence, failure) == false)
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
    request.url = url;
    request.bearer(credential.material);
    String response = {};
    long httpCode = 0;
    return acceptHTTP(sendHTTP(request, response, httpCode, failure), httpCode, response, failure, "azure dns delete failed");
  }

private:

  bool recordSetURL(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& url, String& failure)
  {
    String subscription = {};
    String resourceGroup = {};
    if (prodigyDNSCredentialMetadata(credential, "subscriptionID", subscription) == false || prodigyDNSCredentialMetadata(credential, "resourceGroup", resourceGroup) == false)
    {
      failure.assign("azure dns credential metadata.subscriptionID and metadata.resourceGroup required"_ctv);
      return false;
    }

    String subPath = {};
    String rgPath = {};
    String zonePath = {};
    String namePath = {};
    String relativeName = prodigyDNSRelativeName(record.name, record.zone);
    if (relativeName.size() == 0)
    {
      relativeName.assign("@"_ctv);
    }
    if (prodigyDNSEncodePathPart(subscription, subPath, failure) == false ||
        prodigyDNSEncodePathPart(resourceGroup, rgPath, failure) == false ||
        prodigyDNSEncodePathPart(record.zone, zonePath, failure) == false ||
        prodigyDNSEncodePathPart(relativeName, namePath, failure) == false)
    {
      return false;
    }
    url.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/{}/{}?api-version=2018-05-01"_ctv>(
        subPath,
        rgPath,
        zonePath,
        record.type,
        namePath);
    return true;
  }

  bool findRecord(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, const String& url, ProdigyDNSRecordPresence& presence, String& failure)
  {
    ProdigyDNSHTTPRequest request = {};
    request.method.assign("GET"_ctv);
    request.url = url;
    request.bearer(credential.material);
    String response = {};
    long httpCode = 0;
    if (sendHTTP(request, response, httpCode, failure) == false)
    {
      return false;
    }
    if (httpCode == 404)
    {
      presence = ProdigyDNSRecordPresence::missing;
      failure.clear();
      return true;
    }
    if (acceptHTTP(true, httpCode, response, failure, "azure dns get failed") == false)
    {
      return false;
    }
    return prodigyDNSFindAzureRecord(response, record, presence, failure);
  }
};
