#pragma once

#include <prodigy/dns/provider.http.h>

class GcpCloudDNSProvider : public ProdigyHTTPDNSProvider {
public:

  GcpCloudDNSProvider()
      : ProdigyHTTPDNSProvider("dns.googleapis.com"_ctv)
  {}

  bool supportsProvider(const String& provider) const override
  {
    return routableResourceDNSPartEquals(provider, "gcp-cloud-dns"_ctv, false) || routableResourceDNSPartEquals(provider, "google-cloud-dns"_ctv, false);
  }

  ProdigyHostTask<bool> upsert(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    co_return co_await change(coro, false, record, credential, failure);
  }

  ProdigyHostTask<bool> remove(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    co_return co_await change(coro, true, record, credential, failure);
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

  bool credentialPaths(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& projectPath, String& zonePath, String& failure)
  {
    String project = {};
    if (prodigyDNSCredentialMetadata(credential, "project", project) == false)
    {
      failure.assign("gcp cloud dns credential metadata.project required"_ctv);
      return false;
    }

    if (prodigyDNSEncodePathPart(project, projectPath, failure) == false || prodigyDNSEncodePathPart(record.zone, zonePath, failure) == false)
    {
      return false;
    }
    return true;
  }

  ProdigyHostTask<bool> change(CoroutineStack *coro, bool removing, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure)
  {
    String projectPath = {};
    String zonePath = {};
    if (credentialPaths(record, credential, projectPath, zonePath, failure) == false)
    {
      co_return false;
    }
    ProdigyDNSRecordPresence presence = {};
    if (co_await findRecord(coro, record, credential, projectPath, zonePath, presence, failure) == false)
    {
      co_return false;
    }
    if (presence == ProdigyDNSRecordPresence::missing)
    {
      if (removing)
      {
        failure.clear();
        co_return true;
      }
    }
    else if (removing == false)
    {
      failure.clear();
      co_return true;
    }
    String value = {};
    if (prodigyDNSRecordSingleValue(record, value, failure) == false)
    {
      co_return false;
    }

    ProdigyDNSHTTPRequest request = {};
    request.method = MultiCurlClient::Method::post;
    request.url.snprintf<"https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/changes"_ctv>(projectPath, zonePath);
    request.headers.push_back({"Content-Type"_ctv, "application/json"_ctv});
    if (co_await prodigyDNSApplyBearerAuth(coro, request, credential, failure, runtime.operationDeadline) == false)
    {
      co_return false;
    }
    request.body.assign("{\""_ctv);
    request.body.append(removing ? "deletions" : "additions");
    request.body.append("\":[{\"name\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(request.body, record.name);
    prodigyDNSAppendJSONKV(request.body, "type", record.type);
    request.body.snprintf_add<",\"ttl\":{itoa},\"rrdatas\":["_ctv>(record.ttl);
    prodigyAppendEscapedJSONStringLiteral(request.body, value);
    request.body.append("]}]}"_ctv);
    String response = {};
    long httpCode = 0;
    co_return acceptHTTP(co_await sendHTTP(coro, request, response, httpCode, failure), httpCode, response, failure, "gcp cloud dns change failed");
  }

  ProdigyHostTask<bool> changeTXT(CoroutineStack *coro, bool removing, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure)
  {
    String value = {};
    if (prodigyDNSRecordSingleTXTValue(record, value, failure) == false)
    {
      co_return false;
    }
    String projectPath = {};
    String zonePath = {};
    if (credentialPaths(record, credential, projectPath, zonePath, failure) == false)
    {
      co_return false;
    }

    String response = {};
    if (co_await listRecordSets(coro, record, credential, projectPath, zonePath, response, failure) == false)
    {
      co_return false;
    }
    Vector<String> oldValues = {};
    bool found = false;
    if (prodigyDNSCollectGcpRecordValues(response, record, oldValues, found, failure) == false)
    {
      co_return false;
    }
    Vector<String> newValues = oldValues;
    if (removing)
    {
      if (found == false || prodigyDNSRemoveProviderValue(record, newValues, value) == false)
      {
        failure.clear();
        co_return true;
      }
    }
    else
    {
      if (prodigyDNSValuesContain(record, newValues, value))
      {
        failure.clear();
        co_return true;
      }
      String quoted = {};
      prodigyDNSQuoteTXTValue(value, quoted);
      newValues.push_back(quoted);
    }
    co_return co_await changeRRSet(coro, record, credential, projectPath, zonePath, found ? &oldValues : nullptr, newValues.size() == 0 ? nullptr : &newValues, failure);
  }

  ProdigyHostTask<bool> changeRRSet(
      CoroutineStack *coro,
      const ProdigyDNSRecordBinding& record,
      const ApiCredential& credential,
      const String& projectPath,
      const String& zonePath,
      const Vector<String> *deletions,
      const Vector<String> *additions,
      String& failure)
  {
    ProdigyDNSHTTPRequest request = {};
    request.method = MultiCurlClient::Method::post;
    request.url.snprintf<"https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/changes"_ctv>(projectPath, zonePath);
    request.headers.push_back({"Content-Type"_ctv, "application/json"_ctv});
    if (co_await prodigyDNSApplyBearerAuth(coro, request, credential, failure, runtime.operationDeadline) == false)
    {
      co_return false;
    }
    request.body.assign("{"_ctv);
    if (deletions)
    {
      request.body.append("\"deletions\":["_ctv);
      prodigyDNSAppendGcpRRSet(request.body, record, *deletions);
      request.body.append(']');
    }
    if (additions)
    {
      if (deletions)
      {
        request.body.append(',');
      }
      request.body.append("\"additions\":["_ctv);
      prodigyDNSAppendGcpRRSet(request.body, record, *additions);
      request.body.append(']');
    }
    request.body.append('}');
    String response = {};
    long httpCode = 0;
    co_return acceptHTTP(co_await sendHTTP(coro, request, response, httpCode, failure), httpCode, response, failure, "gcp cloud dns change failed");
  }

  ProdigyHostTask<bool> findRecord(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, const String& projectPath, const String& zonePath, ProdigyDNSRecordPresence& presence, String& failure)
  {
    String response = {};
    if (co_await listRecordSets(coro, record, credential, projectPath, zonePath, response, failure) == false)
    {
      co_return false;
    }
    co_return prodigyDNSFindGcpRecord(response, record, presence, failure);
  }

  ProdigyHostTask<bool> listRecordSets(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, const String& projectPath, const String& zonePath, String& response, String& failure)
  {
    String name = {};
    String type = {};
    if (prodigyDNSEncodePathPart(record.name, name, failure) == false || prodigyDNSEncodePathPart(record.type, type, failure) == false)
    {
      co_return false;
    }
    ProdigyDNSHTTPRequest request = {};
    request.method = MultiCurlClient::Method::get;
    request.url.snprintf<"https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/rrsets?name={}&type={}"_ctv>(projectPath, zonePath, name, type);
    if (co_await prodigyDNSApplyBearerAuth(coro, request, credential, failure, runtime.operationDeadline) == false)
    {
      co_return false;
    }
    long httpCode = 0;
    if (acceptHTTP(co_await sendHTTP(coro, request, response, httpCode, failure), httpCode, response, failure, "gcp cloud dns rrset list failed") == false)
    {
      co_return false;
    }
    co_return true;
  }
};
