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
    Vector<String> values = {};
    values.push_back(value);

    return putRecord(record, credential, url, values, failure);
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

    return deleteRecord(record, credential, url, failure);
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

  bool changeTXT(bool removing, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure)
  {
    String value = {};
    if (prodigyDNSRecordSingleTXTValue(record, value, failure) == false)
    {
      return false;
    }
    String url = {};
    if (recordSetURL(record, credential, url, failure) == false)
    {
      return false;
    }
    Vector<String> values = {};
    bool found = false;
    if (loadRecord(record, credential, url, values, found, failure) == false)
    {
      return false;
    }
    if (removing)
    {
      if (found == false || prodigyDNSRemoveProviderValue(record, values, value) == false)
      {
        failure.clear();
        return true;
      }
      if (values.size() == 0)
      {
        return deleteRecord(record, credential, url, failure);
      }
    }
    else
    {
      if (prodigyDNSValuesContain(record, values, value))
      {
        failure.clear();
        return true;
      }
      values.push_back(value);
    }
    return putRecord(record, credential, url, values, failure);
  }

  bool putRecord(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, const String& url, const Vector<String>& values, String& failure)
  {
    ProdigyDNSHTTPRequest request = {};
    request.method.assign("PUT"_ctv);
    request.url = url;
    request.header("Content-Type: application/json");
    if (prodigyDNSApplyBearerAuth(request, credential, failure) == false)
    {
      return false;
    }
    prodigyDNSAppendAzureRecordSetJSON(request.body, record, values);
    String response = {};
    long httpCode = 0;
    return acceptHTTP(sendHTTP(request, response, httpCode, failure), httpCode, response, failure, "azure dns upsert failed");
  }

  bool deleteRecord(const ProdigyDNSRecordBinding&, const ApiCredential& credential, const String& url, String& failure)
  {
    ProdigyDNSHTTPRequest request = {};
    request.method.assign("DELETE"_ctv);
    request.url = url;
    if (prodigyDNSApplyBearerAuth(request, credential, failure) == false)
    {
      return false;
    }
    String response = {};
    long httpCode = 0;
    return acceptHTTP(sendHTTP(request, response, httpCode, failure), httpCode, response, failure, "azure dns delete failed");
  }

  bool findRecord(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, const String& url, ProdigyDNSRecordPresence& presence, String& failure)
  {
    presence = ProdigyDNSRecordPresence::missing;
    String recordValue = {};
    if (prodigyDNSRecordSingleValue(record, recordValue, failure) == false)
    {
      return false;
    }
    Vector<String> values = {};
    bool found = false;
    if (loadRecord(record, credential, url, values, found, failure) == false)
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

  bool loadRecord(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, const String& url, Vector<String>& values, bool& found, String& failure)
  {
    ProdigyDNSHTTPRequest request = {};
    request.method.assign("GET"_ctv);
    request.url = url;
    if (prodigyDNSApplyBearerAuth(request, credential, failure) == false)
    {
      return false;
    }
    String response = {};
    long httpCode = 0;
    if (sendHTTP(request, response, httpCode, failure) == false)
    {
      return false;
    }
    if (httpCode == 404)
    {
      values.clear();
      found = false;
      failure.clear();
      return true;
    }
    if (acceptHTTP(true, httpCode, response, failure, "azure dns get failed") == false)
    {
      return false;
    }
    return prodigyDNSCollectAzureRecordValues(response, record, values, found, failure);
  }
};
