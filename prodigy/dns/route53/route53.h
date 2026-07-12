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

static inline bool prodigyDNSCollectRoute53RecordValues(const String& response,
                                                        const ProdigyDNSRecordBinding& record,
                                                        Vector<String>& values,
                                                        bool& found,
                                                        String& failure,
                                                        uint32_t *ttl = nullptr)
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
  if (ttl)
  {
    String ttlText;
    if (awsExtractXMLValue(row, "TTL", ttlText) == false || ttlText.empty())
    {
      failure.assign("route53 dns list response TTL missing"_ctv);
      return false;
    }
    for (uint8_t byte : ttlText)
    {
      if (byte < '0' || byte > '9')
      {
        failure.assign("route53 dns list response TTL invalid"_ctv);
        return false;
      }
    }
    *ttl = ttlText.toNumber<uint32_t>();
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
  uint32_t ttl = 0;
  if (prodigyDNSCollectRoute53RecordValues(response, record, values, found, failure, &ttl) == false)
  {
    return false;
  }
  if (found == false)
  {
    failure.clear();
    return true;
  }
  if (ttl != record.ttl || values.size() != 1 ||
      prodigyDNSProviderValueEquals(record, values[0], recordValue) == false)
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

  ProdigyHostTask<bool> upsert(CoroutineStack *coro,
                               const ProdigyDNSRecordBinding& record,
                               const ApiCredential& credential,
                               String& failure) override
  {
    co_return co_await change(coro, false, record, credential, failure);
  }

  ProdigyHostTask<bool> remove(CoroutineStack *coro,
                               const ProdigyDNSRecordBinding& record,
                               const ApiCredential& credential,
                               String& failure) override
  {
    co_return co_await change(coro, true, record, credential, failure);
  }

  ProdigyHostTask<bool> presentTXT(CoroutineStack *coro,
                                   const ProdigyDNSRecordBinding& record,
                                   const ApiCredential& credential,
                                   String& failure) override
  {
    co_return co_await changeTXT(coro, false, record, credential, failure);
  }

  ProdigyHostTask<bool> cleanupTXT(CoroutineStack *coro,
                                   const ProdigyDNSRecordBinding& record,
                                   const ApiCredential& credential,
                                   String& failure) override
  {
    co_return co_await changeTXT(coro, true, record, credential, failure);
  }

protected:

  virtual ProdigyHostTask<bool> sendAWS(CoroutineStack *coro,
                                        MultiCurlClient::Method method,
                                        const AwsHttpRequest::Target& target,
                                        const AwsCredentialMaterial& credential,
                                        const String *body,
                                        String& response,
                                        long& httpCode,
                                        String& failure)
  {
    Vector<MultiCurlClient::Header> headers;
    headers.push_back({"Content-Type"_ctv, "text/xml"_ctv});
    AwsHttpTransport transport(runtime.http, runtime.delay, runtime.operationDeadline);
    MultiCurlClient::Result result = co_await transport.sendSigned(
        coro, target, method, headers, body, credential, &failure);
    response = std::move(result.body);
    httpCode = result.statusCode;
    if (result.status != MultiCurlClient::Status::success)
    {
      AwsHttpTransport::assignTransportFailure(result, failure);
      co_return false;
    }
    co_return true;
  }

private:

  ProdigyHostTask<bool> prepare(
      CoroutineStack *coro,
      const ProdigyDNSRecordBinding& record,
      const ApiCredential& apiCredential,
      AwsCredentialMaterial& credential,
      String& zone,
      String& region,
      String& failure)
  {
    String refreshedMaterial;
    AwsSecretStringScope refreshedMaterialScope(refreshedMaterial);
    String refreshCommand;
    if (prodigyDNSCredentialMetadata(apiCredential, "awsCredentialRefreshCommand", refreshCommand))
    {
      if (co_await ProdigyCommandCapture::run(coro,
                                              refreshCommand,
                                              refreshedMaterial,
                                              runtime.operationDeadline,
                                              &failure) == false)
      {
        co_return false;
      }
    }
    const String& material = refreshCommand.empty() ? apiCredential.material : refreshedMaterial;
    if (parseAwsCredentialMaterial(material, credential, &failure) == false)
    {
      co_return false;
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
    co_return true;
  }

  ProdigyHostTask<bool> change(CoroutineStack *coro,
                               bool removing,
                               const ProdigyDNSRecordBinding& record,
                               const ApiCredential& apiCredential,
                               String& failure)
  {
    AwsCredentialMaterial credential = {};
    String zone = {};
    String region = {};
    if (co_await prepare(coro, record, apiCredential, credential, zone, region, failure) == false)
    {
      co_return false;
    }
    ProdigyDNSRecordPresence presence = {};
    if (co_await findRecord(coro, record, credential, zone, region, presence, failure) == false)
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
    Vector<String> values = {};
    values.push_back(value);
    co_return co_await changeRecordSet(coro,
                                       removing ? "DELETE" : "CREATE",
                                       record,
                                       credential,
                                       zone,
                                       region,
                                       values,
                                       failure);
  }

  ProdigyHostTask<bool> changeTXT(CoroutineStack *coro,
                                  bool removing,
                                  const ProdigyDNSRecordBinding& record,
                                  const ApiCredential& apiCredential,
                                  String& failure)
  {
    String value = {};
    if (prodigyDNSRecordSingleTXTValue(record, value, failure) == false)
    {
      co_return false;
    }
    AwsCredentialMaterial credential = {};
    String zone = {};
    String region = {};
    if (co_await prepare(coro, record, apiCredential, credential, zone, region, failure) == false)
    {
      co_return false;
    }
    String response = {};
    if (co_await listRecordSets(coro, record, credential, zone, region, response, failure) == false)
    {
      co_return false;
    }
    Vector<String> oldValues = {};
    bool found = false;
    if (prodigyDNSCollectRoute53RecordValues(response, record, oldValues, found, failure) == false)
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
      if (newValues.size() == 0)
      {
        co_return co_await changeRecordSet(
            coro, "DELETE", record, credential, zone, region, oldValues, failure);
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
    co_return co_await changeRecordSet(
        coro, "UPSERT", record, credential, zone, region, newValues, failure);
  }

  ProdigyHostTask<bool> changeRecordSet(
      CoroutineStack *coro,
      const char *action,
      const ProdigyDNSRecordBinding& record,
      const AwsCredentialMaterial& credential,
      const String& zone,
      const String& region,
      const Vector<String>& values,
      String& failure)
  {
    AwsHttpRequest::Target target;
    target.authority.assign("route53.amazonaws.com"_ctv);
    target.path.snprintf<"/2013-04-01/hostedzone/{}/rrset"_ctv>(zone);
    target.region.assign(region);
    target.service.assign("route53"_ctv);
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
    if (co_await sendAWS(coro,
                         MultiCurlClient::Method::post,
                         target,
                         credential,
                         &body,
                         response,
                         httpCode,
                         failure) == false)
    {
      if (failure.empty())
      {
        failure.assign("route53 dns request failed"_ctv);
      }
      co_return false;
    }
    if (httpCode >= 200 && httpCode < 300)
    {
      failure.clear();
      co_return true;
    }
    AwsHttpTransport::assignHttpFailure(
        "route53 dns change failed"_ctv, httpCode, response, failure);
    co_return false;
  }

  ProdigyHostTask<bool> findRecord(CoroutineStack *coro,
                                   const ProdigyDNSRecordBinding& record,
                                   const AwsCredentialMaterial& credential,
                                   const String& zone,
                                   const String& region,
                                   ProdigyDNSRecordPresence& presence,
                                   String& failure)
  {
    String response = {};
    if (co_await listRecordSets(coro, record, credential, zone, region, response, failure) == false)
    {
      co_return false;
    }
    co_return prodigyDNSFindRoute53Record(response, record, presence, failure);
  }

  ProdigyHostTask<bool> listRecordSets(CoroutineStack *coro,
                                       const ProdigyDNSRecordBinding& record,
                                       const AwsCredentialMaterial& credential,
                                       const String& zone,
                                       const String& region,
                                       String& response,
                                       String& failure)
  {
    AwsHttpRequest::Target target;
    target.authority.assign("route53.amazonaws.com"_ctv);
    target.path.snprintf<"/2013-04-01/hostedzone/{}/rrset"_ctv>(zone);
    target.query.push_back({"name"_ctv, record.name});
    target.query.push_back({"type"_ctv, record.type});
    target.query.push_back({"maxitems"_ctv, "1"_ctv});
    target.region.assign(region);
    target.service.assign("route53"_ctv);
    long httpCode = 0;
    if (co_await sendAWS(coro,
                         MultiCurlClient::Method::get,
                         target,
                         credential,
                         nullptr,
                         response,
                         httpCode,
                         failure) == false)
    {
      if (failure.empty())
      {
        failure.assign("route53 dns list failed"_ctv);
      }
      co_return false;
    }
    if (httpCode < 200 || httpCode >= 300)
    {
      AwsHttpTransport::assignHttpFailure(
          "route53 dns list failed"_ctv, httpCode, response, failure);
      co_return false;
    }
    co_return true;
  }
};
