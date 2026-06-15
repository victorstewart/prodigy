#pragma once

#include <prodigy/dns/provider.http.h>
#include <prodigy/iaas/aws/aws.h>

static inline bool prodigyDNSFindRoute53Record(const String& response, const ProdigyDNSRecordBinding& record, ProdigyDNSRecordPresence& presence, String& failure)
{
  presence = ProdigyDNSRecordPresence::missing;
  String recordValue = {};
  if (prodigyDNSRecordSingleValue(record, recordValue, failure) == false)
  {
    return false;
  }

  uint64_t open = awsFindToken(response, "<ResourceRecordSet>", 0);
  uint64_t close = open == uint64_t(-1) ? uint64_t(-1) : awsFindToken(response, "</ResourceRecordSet>", open);
  if (open == uint64_t(-1) || close == uint64_t(-1))
  {
    failure.clear();
    return true;
  }

  String row = response.substr(open, close - open, Copy::yes);
  String name = {};
  String type = {};
  if (awsExtractXMLValue(row, "Name", name) == false || awsExtractXMLValue(row, "Type", type) == false)
  {
    failure.assign("route53 dns list response parse failed"_ctv);
    return false;
  }
  if (routableResourceDNSPartEquals(name, record.name, true) == false || routableResourceDNSPartEquals(type, record.type, false) == false)
  {
    failure.clear();
    return true;
  }

  Vector<String> values = {};
  awsCollectSetItemBlocks(row, "ResourceRecords", values);
  if (values.size() != 1)
  {
    return prodigyDNSExistingRecordConflict(failure);
  }
  String value = {};
  if (awsExtractXMLValue(values[0], "Value", value) == false || value.equals(recordValue) == false)
  {
    return prodigyDNSExistingRecordConflict(failure);
  }
  presence = ProdigyDNSRecordPresence::exact;
  failure.clear();
  return true;
}

class Route53DNSProvider : public ProdigyDNSProvider {
public:

  bool supportsProvider(const String& provider) const override
  {
    return routableResourceDNSPartEquals(provider, "route53"_ctv, false) || routableResourceDNSPartEquals(provider, "aws-route53"_ctv, false);
  }

  bool upsert(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    return change(false, record, credential, failure);
  }

  bool remove(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    return change(true, record, credential, failure);
  }

protected:

  virtual bool sendAWS(const char *method, const String& url, const String& region, const AwsCredentialMaterial& credential, const String *body, String& response, long& httpCode)
  {
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: text/xml");
    bool ok = AwsHttp::send(method, url, region, "route53"_ctv, credential, headers, body, response, &httpCode);
    curl_slist_free_all(headers);
    return ok;
  }

private:

  bool change(bool removing, const ProdigyDNSRecordBinding& record, const ApiCredential& apiCredential, String& failure)
  {
    AwsCredentialMaterial credential = {};
    if (parseAwsCredentialMaterial(apiCredential.material, credential, &failure) == false)
    {
      return false;
    }

    String zone = record.zone;
    if (zone.size() >= 12 && zone.substr(0, 12).equal("/hostedzone/"_ctv))
    {
      zone = zone.substr(12, zone.size() - 12, Copy::yes);
    }
    String region = {};
    if (prodigyDNSCredentialMetadata(apiCredential, "region", region) == false)
    {
      region.assign("us-east-1"_ctv);
    }

    ProdigyDNSRecordPresence presence = {};
    if (findRecord(record, credential, zone, region, presence, failure) == false)
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

    String url = {};
    url.snprintf<"https://route53.amazonaws.com/2013-04-01/hostedzone/{}/rrset"_ctv>(zone);
    String action = {};
    action.assign(removing ? "DELETE" : "CREATE");
    String body = {};
    body.snprintf<"<ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\"><ChangeBatch><Changes><Change><Action>{}</Action><ResourceRecordSet><Name>{}</Name><Type>{}</Type><TTL>{itoa}</TTL><ResourceRecords><ResourceRecord><Value>{}</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>"_ctv>(
        action,
        record.name,
        record.type,
        record.ttl,
        value);
    String response = {};
    long httpCode = 0;
    if (sendAWS("POST", url, region, credential, &body, response, httpCode) == false)
    {
      failure.assign("route53 dns request failed"_ctv);
      return false;
    }
    if (httpCode >= 200 && httpCode < 300)
    {
      failure.clear();
      return true;
    }
    failure.snprintf<"route53 dns change failed [http={itoa}]: {}"_ctv>(uint32_t(httpCode), response);
    return false;
  }

  bool findRecord(const ProdigyDNSRecordBinding& record, const AwsCredentialMaterial& credential, const String& zone, const String& region, ProdigyDNSRecordPresence& presence, String& failure)
  {
    String name = {};
    String type = {};
    if (prodigyDNSEncodePathPart(record.name, name, failure) == false || prodigyDNSEncodePathPart(record.type, type, failure) == false)
    {
      return false;
    }
    String url = {};
    url.snprintf<"https://route53.amazonaws.com/2013-04-01/hostedzone/{}/rrset?name={}&type={}&maxitems=1"_ctv>(zone, name, type);
    String response = {};
    long httpCode = 0;
    if (sendAWS("GET", url, region, credential, nullptr, response, httpCode) == false)
    {
      failure.assign("route53 dns list failed"_ctv);
      return false;
    }
    if (httpCode < 200 || httpCode >= 300)
    {
      failure.snprintf<"route53 dns list failed [http={itoa}]: {}"_ctv>(uint32_t(httpCode), response);
      return false;
    }
    return prodigyDNSFindRoute53Record(response, record, presence, failure);
  }
};
