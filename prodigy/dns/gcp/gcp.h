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

private:

  bool change(bool removing, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure)
  {
    String project = {};
    if (prodigyDNSCredentialMetadata(credential, "project", project) == false)
    {
      failure.assign("gcp cloud dns credential metadata.project required"_ctv);
      return false;
    }

    String projectPath = {};
    String zonePath = {};
    if (prodigyDNSEncodePathPart(project, projectPath, failure) == false || prodigyDNSEncodePathPart(record.zone, zonePath, failure) == false)
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
    request.bearer(credential.material);
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

  bool findRecord(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, const String& projectPath, const String& zonePath, ProdigyDNSRecordPresence& presence, String& failure)
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
    request.bearer(credential.material);
    String response = {};
    long httpCode = 0;
    if (acceptHTTP(sendHTTP(request, response, httpCode, failure), httpCode, response, failure, "gcp cloud dns rrset list failed") == false)
    {
      return false;
    }
    return prodigyDNSFindGcpRecord(response, record, presence, failure);
  }
};
