#pragma once

#include <prodigy/dns/provider.http.h>

class GcpCloudDNSProvider : public ProdigyHTTPDNSProvider {
public:

  bool supportsProvider(const String& provider) const override
  {
    return routableResourceDNSPartEquals(provider, "gcp-cloud-dns"_ctv, false) || routableResourceDNSPartEquals(provider, "google-cloud-dns"_ctv, false);
  }

  bool upsert(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    return change(false, record, credential, failure);
  }

  bool remove(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    return change(true, record, credential, failure);
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

  bool change(bool removing, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure)
  {
    String projectPath = {};
    String zonePath = {};
    if (credentialPaths(record, credential, projectPath, zonePath, failure) == false)
    {
      return false;
    }
    ProdigyDNSRecordPresence presence = {};
    if (findRecord(record, credential, projectPath, zonePath, presence, failure) == false)
    {
      return false;
    }
    if (presence == ProdigyDNSRecordPresence::missing)
    {
      if (removing)
      {
        failure.clear();
        return true;
      }
    }
    else if (removing == false)
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
    request.method.assign("POST"_ctv);
    request.url.snprintf<"https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/changes"_ctv>(projectPath, zonePath);
    request.header("Content-Type: application/json");
    if (prodigyDNSApplyBearerAuth(request, credential, failure) == false)
    {
      return false;
    }
    request.body.assign("{\""_ctv);
    request.body.append(removing ? "deletions" : "additions");
    request.body.append("\":[{\"name\":"_ctv);
    appendEscapedJSONString(request.body, record.name);
    prodigyDNSAppendJSONKV(request.body, "type", record.type);
    request.body.snprintf_add<",\"ttl\":{itoa},\"rrdatas\":["_ctv>(record.ttl);
    appendEscapedJSONString(request.body, value);
    request.body.append("]}]}"_ctv);
    String response = {};
    long httpCode = 0;
    return acceptHTTP(sendHTTP(request, response, httpCode, failure), httpCode, response, failure, "gcp cloud dns change failed");
  }

  bool changeTXT(bool removing, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure)
  {
    String value = {};
    if (prodigyDNSRecordSingleTXTValue(record, value, failure) == false)
    {
      return false;
    }
    String projectPath = {};
    String zonePath = {};
    if (credentialPaths(record, credential, projectPath, zonePath, failure) == false)
    {
      return false;
    }

    String response = {};
    if (listRecordSets(record, credential, projectPath, zonePath, response, failure) == false)
    {
      return false;
    }
    Vector<String> oldValues = {};
    bool found = false;
    if (prodigyDNSCollectGcpRecordValues(response, record, oldValues, found, failure) == false)
    {
      return false;
    }
    Vector<String> newValues = oldValues;
    if (removing)
    {
      if (found == false || prodigyDNSRemoveProviderValue(record, newValues, value) == false)
      {
        failure.clear();
        return true;
      }
    }
    else
    {
      if (prodigyDNSValuesContain(record, newValues, value))
      {
        failure.clear();
        return true;
      }
      String quoted = {};
      prodigyDNSQuoteTXTValue(value, quoted);
      newValues.push_back(quoted);
    }
    return changeRRSet(record, credential, projectPath, zonePath, found ? &oldValues : nullptr, newValues.size() == 0 ? nullptr : &newValues, failure);
  }

  bool changeRRSet(
      const ProdigyDNSRecordBinding& record,
      const ApiCredential& credential,
      const String& projectPath,
      const String& zonePath,
      const Vector<String> *deletions,
      const Vector<String> *additions,
      String& failure)
  {
    ProdigyDNSHTTPRequest request = {};
    request.method.assign("POST"_ctv);
    request.url.snprintf<"https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/changes"_ctv>(projectPath, zonePath);
    request.header("Content-Type: application/json");
    if (prodigyDNSApplyBearerAuth(request, credential, failure) == false)
    {
      return false;
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
    return acceptHTTP(sendHTTP(request, response, httpCode, failure), httpCode, response, failure, "gcp cloud dns change failed");
  }

  bool findRecord(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, const String& projectPath, const String& zonePath, ProdigyDNSRecordPresence& presence, String& failure)
  {
    String response = {};
    if (listRecordSets(record, credential, projectPath, zonePath, response, failure) == false)
    {
      return false;
    }
    return prodigyDNSFindGcpRecord(response, record, presence, failure);
  }

  bool listRecordSets(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, const String& projectPath, const String& zonePath, String& response, String& failure)
  {
    String name = {};
    String type = {};
    if (prodigyDNSEncodePathPart(record.name, name, failure) == false || prodigyDNSEncodePathPart(record.type, type, failure) == false)
    {
      return false;
    }
    ProdigyDNSHTTPRequest request = {};
    request.method.assign("GET"_ctv);
    request.url.snprintf<"https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/rrsets?name={}&type={}"_ctv>(projectPath, zonePath, name, type);
    if (prodigyDNSApplyBearerAuth(request, credential, failure) == false)
    {
      return false;
    }
    long httpCode = 0;
    if (acceptHTTP(sendHTTP(request, response, httpCode, failure), httpCode, response, failure, "gcp cloud dns rrset list failed") == false)
    {
      return false;
    }
    return true;
  }
};
