#pragma once

#include <prodigy/dns/provider.http.h>
#include <prodigy/iaas/aws/aws.h>

static inline void prodigyDNSCollectRoute53ResourceRecords(const String& row, Vector<String>& blocks)
{
  blocks.clear();
  uint64_t search = 0;
  while (true)
  {
    uint64_t open = awsFindToken(row, "<ResourceRecord>", search);
    uint64_t close = open == uint64_t(-1) ? uint64_t(-1) : awsFindToken(row, "</ResourceRecord>", open);
    if (open == uint64_t(-1) || close == uint64_t(-1))
    {
      return;
    }
    open += strlen("<ResourceRecord>");
    blocks.push_back(row.substr(open, close - open, Copy::yes));
    search = close + strlen("</ResourceRecord>");
  }
}

static inline bool prodigyDNSCollectRoute53RecordValues(const String& response, const ProdigyDNSRecordBinding& record, Vector<String>& values, bool& found, String& failure)
{
  values.clear();
  found = false;

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

  Vector<String> blocks = {};
  prodigyDNSCollectRoute53ResourceRecords(row, blocks);
  found = true;
  for (const String& block : blocks)
  {
    String value = {};
    if (awsExtractXMLValue(block, "Value", value) == false)
    {
      failure.assign("route53 dns list response parse failed"_ctv);
      return false;
    }
    values.push_back(value);
  }
  failure.clear();
  return true;
}

static inline bool prodigyDNSFindRoute53Record(const String& response, const ProdigyDNSRecordBinding& record, ProdigyDNSRecordPresence& presence, String& failure)
{
  presence = ProdigyDNSRecordPresence::missing;
  String recordValue = {};
  if (prodigyDNSRecordSingleValue(record, recordValue, failure) == false)
  {
    return false;
  }

  Vector<String> values = {};
  bool found = false;
  if (prodigyDNSCollectRoute53RecordValues(response, record, values, found, failure) == false)
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

static inline void prodigyDNSAppendRoute53XMLText(String& body, const String& value)
{
  for (uint64_t index = 0; index < value.size(); index += 1)
  {
    switch (value[index])
    {
      case '&':
        body.append("&amp;"_ctv);
        break;
      case '<':
        body.append("&lt;"_ctv);
        break;
      case '>':
        body.append("&gt;"_ctv);
        break;
      case '"':
        body.append("&quot;"_ctv);
        break;
      case '\'':
        body.append("&apos;"_ctv);
        break;
      default:
        body.append(value[index]);
        break;
    }
  }
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

  bool presentTXT(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    return changeTXT(false, record, credential, failure);
  }

  bool cleanupTXT(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    return changeTXT(true, record, credential, failure);
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

  bool prepare(
      const ProdigyDNSRecordBinding& record,
      const ApiCredential& apiCredential,
      AwsCredentialMaterial& credential,
      String& zone,
      String& region,
      String& failure)
  {
    if (parseAwsCredentialMaterial(apiCredential.material, credential, &failure) == false)
    {
      return false;
    }

    zone = record.zone;
    if (zone.size() >= 12 && zone.substr(0, 12).equal("/hostedzone/"_ctv))
    {
      zone = zone.substr(12, zone.size() - 12, Copy::yes);
    }
    if (prodigyDNSCredentialMetadata(apiCredential, "region", region) == false)
    {
      region.assign("us-east-1"_ctv);
    }
    return true;
  }

  bool change(bool removing, const ProdigyDNSRecordBinding& record, const ApiCredential& apiCredential, String& failure)
  {
    AwsCredentialMaterial credential = {};
    String zone = {};
    String region = {};
    if (prepare(record, apiCredential, credential, zone, region, failure) == false)
    {
      return false;
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
    Vector<String> values = {};
    values.push_back(value);
    return changeRecordSet(removing ? "DELETE" : "CREATE", record, credential, zone, region, values, failure);
  }

  bool changeTXT(bool removing, const ProdigyDNSRecordBinding& record, const ApiCredential& apiCredential, String& failure)
  {
    String value = {};
    if (prodigyDNSRecordSingleTXTValue(record, value, failure) == false)
    {
      return false;
    }
    AwsCredentialMaterial credential = {};
    String zone = {};
    String region = {};
    if (prepare(record, apiCredential, credential, zone, region, failure) == false)
    {
      return false;
    }
    String response = {};
    if (listRecordSets(record, credential, zone, region, response, failure) == false)
    {
      return false;
    }
    Vector<String> oldValues = {};
    bool found = false;
    if (prodigyDNSCollectRoute53RecordValues(response, record, oldValues, found, failure) == false)
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
      if (newValues.size() == 0)
      {
        return changeRecordSet("DELETE", record, credential, zone, region, oldValues, failure);
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
    return changeRecordSet("UPSERT", record, credential, zone, region, newValues, failure);
  }

  bool changeRecordSet(
      const char *action,
      const ProdigyDNSRecordBinding& record,
      const AwsCredentialMaterial& credential,
      const String& zone,
      const String& region,
      const Vector<String>& values,
      String& failure)
  {
    String url = {};
    url.snprintf<"https://route53.amazonaws.com/2013-04-01/hostedzone/{}/rrset"_ctv>(zone);
    String actionText = {};
    actionText.assign(action);
    String body = {};
    body.snprintf<"<ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\"><ChangeBatch><Changes><Change><Action>{}</Action><ResourceRecordSet><Name>"_ctv>(actionText);
    prodigyDNSAppendRoute53XMLText(body, record.name);
    body.append("</Name><Type>"_ctv);
    prodigyDNSAppendRoute53XMLText(body, record.type);
    body.snprintf_add<"</Type><TTL>{itoa}</TTL><ResourceRecords>"_ctv>(record.ttl);
    for (const String& value : values)
    {
      body.append("<ResourceRecord><Value>"_ctv);
      prodigyDNSAppendRoute53XMLText(body, value);
      body.append("</Value></ResourceRecord>"_ctv);
    }
    body.append("</ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>"_ctv);
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
    String response = {};
    if (listRecordSets(record, credential, zone, region, response, failure) == false)
    {
      return false;
    }
    return prodigyDNSFindRoute53Record(response, record, presence, failure);
  }

  bool listRecordSets(const ProdigyDNSRecordBinding& record, const AwsCredentialMaterial& credential, const String& zone, const String& region, String& response, String& failure)
  {
    String name = {};
    String type = {};
    if (prodigyDNSEncodePathPart(record.name, name, failure) == false || prodigyDNSEncodePathPart(record.type, type, failure) == false)
    {
      return false;
    }
    String url = {};
    url.snprintf<"https://route53.amazonaws.com/2013-04-01/hostedzone/{}/rrset?name={}&type={}&maxitems=1"_ctv>(zone, name, type);
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
    return true;
  }
};
