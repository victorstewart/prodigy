#pragma once

#include <prodigy/dns/provider.http.h>

class AzureDNSProvider : public ProdigyHTTPDNSProvider {
public:

  AzureDNSProvider()
      : ProdigyHTTPDNSProvider("management.azure.com"_ctv)
  {}

  bool supportsProvider(const String& provider) const override
  {
    return routableResourceDNSPartEquals(provider, "azure-dns"_ctv, false);
  }

  ProdigyHostTask<bool> upsert(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    String url = {};
    if (recordSetURL(record, credential, url, failure) == false)
    {
      co_return false;
    }
    ProdigyDNSRecordPresence presence = {};
    if (co_await findRecord(coro, record, credential, url, presence, failure) == false)
    {
      co_return false;
    }
    if (presence == ProdigyDNSRecordPresence::exact)
    {
      failure.clear();
      co_return true;
    }
    String value = {};
    if (prodigyDNSRecordSingleValue(record, value, failure) == false)
    {
      co_return false;
    }
    Vector<String> values = {};
    values.push_back(value);

    co_return co_await putRecord(coro, record, credential, url, values, failure);
  }

  ProdigyHostTask<bool> remove(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    String url = {};
    if (recordSetURL(record, credential, url, failure) == false)
    {
      co_return false;
    }
    ProdigyDNSRecordPresence presence = {};
    if (co_await findRecord(coro, record, credential, url, presence, failure) == false)
    {
      co_return false;
    }
    if (presence == ProdigyDNSRecordPresence::missing)
    {
      failure.clear();
      co_return true;
    }

    co_return co_await deleteRecord(coro, record, credential, url, failure);
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

  ProdigyHostTask<bool> changeTXT(CoroutineStack *coro, bool removing, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure)
  {
    String value = {};
    if (prodigyDNSRecordSingleTXTValue(record, value, failure) == false)
    {
      co_return false;
    }
    String url = {};
    if (recordSetURL(record, credential, url, failure) == false)
    {
      co_return false;
    }
    Vector<String> values = {};
    bool found = false;
    if (co_await loadRecord(coro, record, credential, url, values, found, failure) == false)
    {
      co_return false;
    }
    if (removing)
    {
      if (found == false || prodigyDNSRemoveProviderValue(record, values, value) == false)
      {
        failure.clear();
        co_return true;
      }
      if (values.size() == 0)
      {
        co_return co_await deleteRecord(coro, record, credential, url, failure);
      }
    }
    else
    {
      if (prodigyDNSValuesContain(record, values, value))
      {
        failure.clear();
        co_return true;
      }
      values.push_back(value);
    }
    co_return co_await putRecord(coro, record, credential, url, values, failure);
  }

  ProdigyHostTask<bool> putRecord(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, const String& url, const Vector<String>& values, String& failure)
  {
    ProdigyDNSHTTPRequest request = {};
    request.method = MultiCurlClient::Method::put;
    request.url = url;
    request.headers.push_back({"Content-Type"_ctv, "application/json"_ctv});
    if (co_await prodigyDNSApplyBearerAuth(coro, request, credential, failure, runtime.operationDeadline) == false)
    {
      co_return false;
    }
    prodigyDNSAppendAzureRecordSetJSON(request.body, record, values);
    String response = {};
    long httpCode = 0;
    co_return acceptHTTP(co_await sendHTTP(coro, request, response, httpCode, failure), httpCode, response, failure, "azure dns upsert failed");
  }

  ProdigyHostTask<bool> deleteRecord(CoroutineStack *coro, const ProdigyDNSRecordBinding&, const ApiCredential& credential, const String& url, String& failure)
  {
    ProdigyDNSHTTPRequest request = {};
    request.method = MultiCurlClient::Method::delete_;
    request.url = url;
    if (co_await prodigyDNSApplyBearerAuth(coro, request, credential, failure, runtime.operationDeadline) == false)
    {
      co_return false;
    }
    String response = {};
    long httpCode = 0;
    co_return acceptHTTP(co_await sendHTTP(coro, request, response, httpCode, failure), httpCode, response, failure, "azure dns delete failed");
  }

  ProdigyHostTask<bool> findRecord(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, const String& url, ProdigyDNSRecordPresence& presence, String& failure)
  {
    presence = ProdigyDNSRecordPresence::missing;
    String recordValue = {};
    if (prodigyDNSRecordSingleValue(record, recordValue, failure) == false)
    {
      co_return false;
    }
    Vector<String> values = {};
    bool found = false;
    if (co_await loadRecord(coro, record, credential, url, values, found, failure) == false)
    {
      co_return false;
    }
    if (found == false)
    {
      failure.clear();
      co_return true;
    }
    if (values.size() != 1 || prodigyDNSProviderValueEquals(record, values[0], recordValue) == false)
    {
      co_return prodigyDNSExistingRecordConflict(failure);
    }
    presence = ProdigyDNSRecordPresence::exact;
    failure.clear();
    co_return true;
  }

  ProdigyHostTask<bool> loadRecord(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, const String& url, Vector<String>& values, bool& found, String& failure)
  {
    ProdigyDNSHTTPRequest request = {};
    request.method = MultiCurlClient::Method::get;
    request.url = url;
    if (co_await prodigyDNSApplyBearerAuth(coro, request, credential, failure, runtime.operationDeadline) == false)
    {
      co_return false;
    }
    String response = {};
    long httpCode = 0;
    if (co_await sendHTTP(coro, request, response, httpCode, failure) == false)
    {
      co_return false;
    }
    if (httpCode == 404)
    {
      values.clear();
      found = false;
      failure.clear();
      co_return true;
    }
    if (acceptHTTP(true, httpCode, response, failure, "azure dns get failed") == false)
    {
      co_return false;
    }
    co_return prodigyDNSCollectAzureRecordValues(response, record, values, found, failure);
  }
};
