#pragma once

#include <prodigy/iaas/aws/aws.http.h>
#include <prodigy/iaas/iaas.h>
#include <prodigy/iaas/bootstrap.ssh.h>
#include <prodigy/brain/base.h>
#include <prodigy/brain/machine.h>
#include <prodigy/cluster.machine.helpers.h>
#include <prodigy/command.capture.h>
#include <prodigy/netdev.detect.h>
#include <services/base64.h>

#include <simdjson.h>
#include <cstdio>

bool awsParseRFC3339Ms(const String& value, int64_t& timestampMs);
int64_t awsParseRFC3339Ms(const String& value);
bool awsFormatRFC3339Seconds(int64_t unixSeconds, String& value);

bool parseAwsCredentialMaterial(const String& material, AwsCredentialMaterial& credential, String *failure = nullptr);
uint32_t awsHashRackIdentity(const String& value);
uint32_t awsRackUUIDFromAvailabilityZone(const String& availabilityZone);

static inline bool awsScopeRegion(const String& scope, String& region)
{
  region.clear();
  if (scope.size() == 0)
  {
    return false;
  }

  int64_t slash = scope.rfindChar('/');
  if (slash >= 0 && uint64_t(slash + 1) < scope.size())
  {
    region.assign(scope.substr(uint64_t(slash + 1), scope.size() - uint64_t(slash + 1), Copy::yes));
    return region.size() > 0;
  }

  region.assign(scope);
  return region.size() > 0;
}

static inline void awsAppendPercentEncoded(String& out, const String& value)
{
  constexpr static char hex[] = "0123456789ABCDEF";

  for (uint64_t index = 0; index < value.size(); ++index)
  {
    uint8_t byte = value[index];
    bool unreserved =
        (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == '.' || byte == '~';

    if (unreserved)
    {
      out.append(byte);
    }
    else
    {
      out.append('%');
      out.append(hex[(byte >> 4) & 0x0f]);
      out.append(hex[byte & 0x0f]);
    }
  }
}

static inline void awsAppendQueryParam(String& body, const String& key, const String& value, bool& first)
{
  if (first == false)
  {
    body.append('&');
  }

  first = false;
  awsAppendPercentEncoded(body, key);
  body.append('=');
  awsAppendPercentEncoded(body, value);
}

static inline void awsAppendInstanceProfile(String& body,
                                            const String& prefix,
                                            const String& instanceProfileName,
                                            const String& instanceProfileArn,
                                            bool& first)
{
  String key;
  if (instanceProfileArn.size() > 0)
  {
    key.snprintf<"{}.Arn"_ctv>(prefix);
    awsAppendQueryParam(body, key, instanceProfileArn, first);
  }
  else if (instanceProfileName.size() > 0)
  {
    key.snprintf<"{}.Name"_ctv>(prefix);
    awsAppendQueryParam(body, key, instanceProfileName, first);
  }
}

static inline void awsAppendBootstrapLaunchTemplateData(
    String& body,
    const String& prefix,
    const String& subnetID,
    const String& securityGroupID,
    const String& instanceProfileName,
    const String& instanceProfileArn,
    bool& first)
{
  String key;
  key.snprintf<"{}.MetadataOptions.HttpTokens"_ctv>(prefix);
  awsAppendQueryParam(body, key, "required"_ctv, first);
  key.snprintf<"{}.NetworkInterface.1.DeviceIndex"_ctv>(prefix);
  awsAppendQueryParam(body, key, "0"_ctv, first);
  key.snprintf<"{}.NetworkInterface.1.AssociatePublicIpAddress"_ctv>(prefix);
  awsAppendQueryParam(body, key, "true"_ctv, first);
  key.snprintf<"{}.NetworkInterface.1.SubnetId"_ctv>(prefix);
  awsAppendQueryParam(body, key, subnetID, first);
  key.snprintf<"{}.NetworkInterface.1.SecurityGroupId.1"_ctv>(prefix);
  awsAppendQueryParam(body, key, securityGroupID, first);
  key.snprintf<"{}.IamInstanceProfile"_ctv>(prefix);
  awsAppendInstanceProfile(body, key, instanceProfileName, instanceProfileArn, first);
}

static inline bool awsBootstrapLaunchTemplateDescription(
    const String& subnetID,
    const String& securityGroupID,
    const String& instanceProfileName,
    const String& instanceProfileArn,
    String& description)
{
  String desiredData;
  bool first = true;
  awsAppendBootstrapLaunchTemplateData(desiredData, "LaunchTemplateData"_ctv,
                                       subnetID, securityGroupID,
                                       instanceProfileName, instanceProfileArn,
                                       first);
  Vector<String> components;
  components.push_back(desiredData);
  String token;
  if (!AwsHttpRequest::idempotencyToken(components, token))
  {
    description.clear();
    return false;
  }
  description.assign("prodigy-bootstrap-"_ctv);
  description.append(token.substr(0, 32, Copy::yes));
  return true;
}

class AwsPricingFilter {
public:

  String field;
  String value;
};

static inline void awsAppendJSONString(String& out, const String& value)
{
  constexpr static char hex[] = "0123456789ABCDEF";

  out.append('"');
  for (uint64_t index = 0; index < value.size(); ++index)
  {
    uint8_t byte = uint8_t(value[index]);
    switch (byte)
    {
      case '\\':
        out.append("\\\\"_ctv);
        break;
      case '"':
        out.append("\\\""_ctv);
        break;
      case '\b':
        out.append("\\b"_ctv);
        break;
      case '\f':
        out.append("\\f"_ctv);
        break;
      case '\n':
        out.append("\\n"_ctv);
        break;
      case '\r':
        out.append("\\r"_ctv);
        break;
      case '\t':
        out.append("\\t"_ctv);
        break;
      default:
        if (byte < 0x20)
        {
          out.append("\\u00"_ctv);
          out.append(hex[(byte >> 4) & 0x0f]);
          out.append(hex[byte & 0x0f]);
        }
        else
        {
          out.append(char(byte));
        }
        break;
    }
  }
  out.append('"');
}

static inline void awsBuildPricingGetProductsRequestBody(
    const String& serviceCode,
    std::initializer_list<AwsPricingFilter> filters,
    String& body,
    const String *nextToken = nullptr)
{
  body.clear();
  body.append("{\"ServiceCode\":"_ctv);
  awsAppendJSONString(body, serviceCode);
  body.append(",\"FormatVersion\":\"aws_v1\",\"MaxResults\":100,\"Filters\":["_ctv);

  bool first = true;
  for (const AwsPricingFilter& filter : filters)
  {
    if (first == false)
    {
      body.append(',');
    }
    first = false;
    body.append("{\"Type\":\"TERM_MATCH\",\"Field\":"_ctv);
    awsAppendJSONString(body, filter.field);
    body.append(",\"Value\":"_ctv);
    awsAppendJSONString(body, filter.value);
    body.append('}');
  }

  body.append(']');
  if (nextToken != nullptr && nextToken->size() > 0)
  {
    body.append(",\"NextToken\":"_ctv);
    awsAppendJSONString(body, *nextToken);
  }

  body.append('}');
}

static inline uint64_t awsFindToken(const String& text, const char *token, uint64_t start = 0, uint64_t limit = UINT64_MAX)
{
  uint64_t tokenLength = uint64_t(strlen(token));
  if (limit > text.size())
  {
    limit = text.size();
  }

  if (tokenLength == 0 || limit < tokenLength || start > limit - tokenLength)
  {
    return uint64_t(-1);
  }

  for (uint64_t index = start; index + tokenLength <= limit; ++index)
  {
    if (memcmp(text.data() + index, token, tokenLength) == 0)
    {
      return index;
    }
  }

  return uint64_t(-1);
}

static inline bool awsExtractTagValue(const String& block, const String& key, String& value)
{
  uint64_t tagSetStart = awsFindToken(block, "<tagSet>");
  uint64_t tagSetEnd = awsFindToken(block, "</tagSet>", tagSetStart == uint64_t(-1) ? 0 : tagSetStart);
  if (tagSetStart == uint64_t(-1) || tagSetEnd == uint64_t(-1))
  {
    return false;
  }

  uint64_t search = tagSetStart;
  while (search < tagSetEnd)
  {
    uint64_t itemStart = awsFindToken(block, "<item>", search, tagSetEnd);
    if (itemStart == uint64_t(-1))
    {
      break;
    }

    uint64_t itemEnd = awsFindToken(block, "</item>", itemStart, tagSetEnd);
    if (itemEnd == uint64_t(-1))
    {
      break;
    }

    uint64_t keyStart = awsFindToken(block, "<key>", itemStart, itemEnd);
    uint64_t keyEnd = awsFindToken(block, "</key>", keyStart, itemEnd);
    uint64_t valueStart = awsFindToken(block, "<value>", itemStart, itemEnd);
    uint64_t valueEnd = awsFindToken(block, "</value>", valueStart, itemEnd);
    if (keyStart != uint64_t(-1) && keyEnd != uint64_t(-1) && valueStart != uint64_t(-1) && valueEnd != uint64_t(-1))
    {
      String candidateKey = block.substr(keyStart + 5, keyEnd - (keyStart + 5), Copy::yes);
      if (candidateKey == key)
      {
        value.assign(block.substr(valueStart + 7, valueEnd - (valueStart + 7), Copy::yes));
        return true;
      }
    }

    search = itemEnd + 7;
  }

  return false;
}

static inline bool awsExtractXMLValue(const String& text, const char *tag, String& value, uint64_t start, uint64_t limit);

static inline bool awsExtractInstanceStateName(const String& block, String& stateName)
{
  uint64_t stateStart = awsFindToken(block, "<instanceState>");
  uint64_t stateEnd = awsFindToken(block, "</instanceState>", stateStart == uint64_t(-1) ? 0 : stateStart);
  if (stateStart == uint64_t(-1) || stateEnd == uint64_t(-1))
  {
    return false;
  }

  return awsExtractXMLValue(block, "name", stateName, stateStart, stateEnd);
}

static inline bool awsExtractXMLValue(const String& text, const char *tag, String& value, uint64_t start = 0, uint64_t limit = UINT64_MAX)
{
  String openTag = {};
  openTag.snprintf<"<{}>"_ctv>(String(tag));
  String closeTag = {};
  closeTag.snprintf<"</{}>"_ctv>(String(tag));

  uint64_t open = awsFindToken(text, openTag.c_str(), start, limit);
  if (open == uint64_t(-1))
  {
    return false;
  }

  uint64_t contentStart = open + openTag.size();
  uint64_t close = awsFindToken(text, closeTag.c_str(), contentStart, limit);
  if (close == uint64_t(-1))
  {
    return false;
  }

  value.assign(text.substr(contentStart, close - contentStart, Copy::yes));
  return true;
}

static inline void awsCollectSetItemBlocks(const String& xml, const char *setTag, Vector<String>& blocks)
{
  blocks.clear();

  String openSet = {};
  openSet.snprintf<"<{}>"_ctv>(String(setTag));
  String closeSet = {};
  closeSet.snprintf<"</{}>"_ctv>(String(setTag));

  uint64_t search = 0;
  while (true)
  {
    uint64_t setStart = awsFindToken(xml, openSet.c_str(), search);
    if (setStart == uint64_t(-1))
    {
      break;
    }

    uint64_t setEnd = awsFindToken(xml, closeSet.c_str(), setStart);
    if (setEnd == uint64_t(-1))
    {
      break;
    }

    uint64_t cursor = setStart + openSet.size();
    uint32_t depth = 0;
    uint64_t itemContentStart = 0;

    while (cursor < setEnd)
    {
      uint64_t nextOpen = awsFindToken(xml, "<item>", cursor, setEnd);
      uint64_t nextClose = awsFindToken(xml, "</item>", cursor, setEnd);
      if (nextOpen == uint64_t(-1) && nextClose == uint64_t(-1))
      {
        break;
      }

      if (nextOpen != uint64_t(-1) && (nextClose == uint64_t(-1) || nextOpen < nextClose))
      {
        depth += 1;
        if (depth == 1)
        {
          itemContentStart = nextOpen + strlen("<item>");
        }

        cursor = nextOpen + strlen("<item>");
        continue;
      }

      if (nextClose != uint64_t(-1))
      {
        if (depth == 1 && nextClose >= itemContentStart)
        {
          blocks.push_back(xml.substr(itemContentStart, nextClose - itemContentStart, Copy::yes));
        }

        if (depth > 0)
        {
          depth -= 1;
        }

        cursor = nextClose + strlen("</item>");
        continue;
      }
    }

    search = setEnd + closeSet.size();
  }
}

static inline void awsCollectInstanceBlocks(const String& xml, Vector<String>& blocks)
{
  awsCollectSetItemBlocks(xml, "instancesSet", blocks);
}

static inline bool awsStringLess(const String& lhs, const String& rhs)
{
  const uint64_t shared = std::min(lhs.size(), rhs.size());
  const int comparison = shared == 0 ? 0 : memcmp(lhs.data(), rhs.data(), shared);
  return comparison < 0 || (comparison == 0 && lhs.size() < rhs.size());
}

static inline bool awsSelectBootstrapSubnet(const Vector<String>& subnetBlocks,
                                            String& subnetID,
                                            String& availabilityZone)
{
  subnetID.clear();
  availabilityZone.clear();
  bool selectedDefault = false;
  for (const String& block : subnetBlocks)
  {
    String candidateID;
    String candidateZone;
    String defaultForZone;
    if (!awsExtractXMLValue(block, "subnetId", candidateID) ||
        !awsExtractXMLValue(block, "availabilityZone", candidateZone))
    {
      continue;
    }
    const bool candidateDefault =
        awsExtractXMLValue(block, "defaultForAz", defaultForZone) &&
        defaultForZone == "true"_ctv;
    if (subnetID.empty() || (candidateDefault && !selectedDefault) ||
        (candidateDefault == selectedDefault && awsStringLess(candidateID, subnetID)))
    {
      subnetID = candidateID;
      availabilityZone = candidateZone;
      selectedDefault = candidateDefault;
    }
  }
  return !subnetID.empty();
}

static inline bool awsStringHasContent(const String& value)
{
  return value.size() > 0 && value[0] != '\0';
}

static inline void awsTrimTrailingAsciiWhitespace(String& value)
{
  while (value.size() > 0)
  {
    uint8_t ch = value[value.size() - 1];
    if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t')
    {
      break;
    }

    value.resize(value.size() - 1);
  }
}

static inline bool awsHasPrefix(const String& text, const char *prefix)
{
  uint64_t prefixLength = uint64_t(strlen(prefix));
  if (text.size() < prefixLength)
  {
    return false;
  }

  return memcmp(text.data(), prefix, prefixLength) == 0;
}

static inline bool awsContainsCString(const String& text, const char *needle)
{
  return awsFindToken(text, needle) != uint64_t(-1);
}

static inline bool awsIsLaunchTemplateMissingFailure(const String& failure)
{
  return awsContainsCString(failure, "InvalidLaunchTemplateName") || awsContainsCString(failure, "does not exist");
}

static inline bool awsIsDryRunSuccessFailure(const String& failure)
{
  return awsContainsCString(failure, "DryRunOperation") || awsContainsCString(failure, "Request would have succeeded");
}

class AwsNeuronIaaS : public NeuronIaaS {
public:

  void gatherSelfData(CoroutineStack *coro, uint128_t& uuid, String& metro, bool& isBrain, EthDevice& eth, IPAddress& private4) override
  {
    AwsHttpTransport transport(providerServices.http,
                               providerServices.delay,
                               providerServices.operationDeadline);
    AwsMetadataSession metadata;

    String deviceName;
    if (prodigyResolvePrimaryNetworkDevice(deviceName))
    {
      eth.setDevice(deviceName);
    }

    uuid = 0;
    metro.clear();
    isBrain = false;
    private4 = {};

    MultiCurlClient::Result document = co_await metadata.get(
        coro,
        transport,
        "/latest/dynamic/instance-identity/document"_ctv);
    if (AwsHttpTransport::succeeded(document))
    {
      simdjson::dom::parser parser;
      simdjson::dom::element doc;

      if (!parser.parse(document.body.c_str(), document.body.size()).get(doc))
      {
        std::string_view region;
        if (!doc["region"].get(region))
        {
          metro.assign(region);
        }

        std::string_view private4Text;
        if (!doc["privateIp"].get(private4Text))
        {
          private4.is6 = false;
          String privateText = String(private4Text);
          (void)inet_pton(AF_INET, privateText.c_str(), &private4.v4);
        }
      }
    }

    if (metro.size() == 0)
    {
      MultiCurlClient::Result discoveredRegion = co_await metadata.get(
          coro,
          transport,
          "/latest/meta-data/placement/region"_ctv);
      if (AwsHttpTransport::succeeded(discoveredRegion))
      {
        metro = std::move(discoveredRegion.body);
        awsTrimTrailingAsciiWhitespace(metro);
      }
    }

    if (private4.isNull())
    {
      private4.is6 = false;
      private4.v4 = eth.getPrivate4();
    }

    MultiCurlClient::Result brainTag = co_await metadata.get(
        coro,
        transport,
        "/latest/meta-data/tags/instance/brain"_ctv);
    if (AwsHttpTransport::succeeded(brainTag))
    {
      awsTrimTrailingAsciiWhitespace(brainTag.body);
      isBrain = (brainTag.body == "1"_ctv || brainTag.body == "true"_ctv);
    }
  }

  void gatherBGPConfig(NeuronBGPConfig& config, EthDevice& eth, const IPAddress& private4) override
  {
    (void)eth;
    (void)private4;
    config = {};
  }

};

class AwsBrainIaaS : public BrainIaaS {
private:

  ProdigyRuntimeEnvironmentConfig runtimeEnvironment;
  String region;
  AwsCredentialMaterial credential;
  AwsMetadataSession metadata;
  bool credentialLoaded = false;
  String bootstrapSSHUser;
  String bootstrapSSHPrivateKeyPath;
  String bootstrapSSHPublicKey;
  Vault::SSHKeyPackage bootstrapSSHHostKeyPackage;
  String provisioningClusterUUIDTagValue;
  uint64_t provisioningOperationID = 0;
  BrainIaaSMachineProvisioningProgressReporter provisioningProgress;
  constexpr static const char *canonicalUbuntuSSMPrefix = "resolve:ssm:/aws/service/canonical/ubuntu/server/";

  static void lowercaseString(const String& input, String& lower)
  {
    lower.clear();
    lower.reserve(input.size());
    for (uint64_t index = 0; index < input.size(); ++index)
    {
      lower.append(char(std::tolower(unsigned(input[index]))));
    }
  }

  static bool stringContainsInsensitive(const String& input, const char *needle)
  {
    if (needle == nullptr || needle[0] == '\0')
    {
      return false;
    }

    String lowerInput = {};
    lowercaseString(input, lowerInput);

    String lowerNeedle = {};
    lowerNeedle.assign(needle);
    for (uint64_t index = 0; index < lowerNeedle.size(); ++index)
    {
      lowerNeedle[index] = char(std::tolower(unsigned(lowerNeedle[index])));
    }

    if (lowerNeedle.size() > lowerInput.size())
    {
      return false;
    }

    for (uint64_t offset = 0; offset + lowerNeedle.size() <= lowerInput.size(); ++offset)
    {
      if (lowerInput.substr(offset, lowerNeedle.size()).equal(lowerNeedle))
      {
        return true;
      }
    }

    return false;
  }

  static void appendAwsProcessorFeatures(const String& processorFeatures, Vector<String>& isaFeatures)
  {
    if (stringContainsInsensitive(processorFeatures, "avx512"))
    {
      prodigyAppendNormalizedIsaFeature(isaFeatures, "avx512f"_ctv);
    }

    if (stringContainsInsensitive(processorFeatures, "avx2"))
    {
      prodigyAppendNormalizedIsaFeature(isaFeatures, "avx2"_ctv);
    }

    if (stringContainsInsensitive(processorFeatures, "avx"))
    {
      prodigyAppendNormalizedIsaFeature(isaFeatures, "avx"_ctv);
    }
  }

  ProdigyHostTask<bool> ensureRegion(CoroutineStack *coro)
  {
    if (region.size() > 0)
    {
      co_return true;
    }

    if (awsScopeRegion(runtimeEnvironment.providerScope, region))
    {
      co_return true;
    }

    AwsHttpTransport transport(providerServices.http,
                               providerServices.delay,
                               providerServices.operationDeadline);
    MultiCurlClient::Result discoveredRegion = co_await metadata.get(
        coro,
        transport,
        "/latest/meta-data/placement/region"_ctv);
    if (AwsHttpTransport::succeeded(discoveredRegion))
    {
      region = std::move(discoveredRegion.body);
      awsTrimTrailingAsciiWhitespace(region);
    }

    co_return region.size() > 0;
  }

  bool awsHasBootstrapCredentialRefreshCommand(void) const
  {
    return runtimeEnvironment.aws.bootstrapCredentialRefreshCommand.size() > 0;
  }

  bool awsCredentialNeedsRefresh(void) const
  {
    if (credentialLoaded == false || credential.valid() == false)
    {
      return true;
    }

    if (credential.expirationMs() <= 0)
    {
      return false;
    }

    return Time::now<TimeResolution::ms>() + 30 * 1000 >= credential.expirationMs();
  }

  ProdigyHostTask<bool> refreshAwsBootstrapCredential(CoroutineStack *coro, String& failure)
  {
    failure.clear();

    String material = {};
    AwsSecretStringScope materialScope(material);
    String detail = {};
    if (material.reserve(ProdigyCommandCapture::maximumOutputBytes) == false)
    {
      failure.assign("aws credential refresh output allocation failed"_ctv);
      co_return false;
    }
    if (co_await ProdigyCommandCapture::run(coro,
                                            runtimeEnvironment.aws.bootstrapCredentialRefreshCommand,
                                            material,
                                            providerServices.operationDeadline,
                                            &detail) == false)
    {
      if (runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint.size() > 0)
      {
        failure.assign(detail);
        if (failure.size() > 0)
        {
          failure.append("\n"_ctv);
        }
        failure.append(runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint);
      }
      else
      {
        failure = detail;
      }
      co_return false;
    }

    if (awsStringHasContent(material) == false)
    {
      failure.assign("aws credential refresh returned empty output"_ctv);
      if (runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint.size() > 0)
      {
        failure.append("\n"_ctv);
        failure.append(runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint);
      }
      co_return false;
    }

    AwsCredentialMaterial refreshed = {};
    if (parseAwsCredentialMaterial(material, refreshed, &failure) == false)
    {
      if (runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint.size() > 0)
      {
        failure.append("\n"_ctv);
        failure.append(runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint);
      }
      co_return false;
    }

    credential = std::move(refreshed);
    credentialLoaded = credential.valid();
    if (credentialLoaded == false)
    {
      failure.assign("aws credential refresh returned invalid material"_ctv);
      co_return false;
    }

    if (credential.expirationMs() > 0 && Time::now<TimeResolution::ms>() + 30 * 1000 >= credential.expirationMs())
    {
      failure.assign("aws credential refresh returned expired material"_ctv);
      credentialLoaded = false;
    }

    co_return credentialLoaded;
  }

  ProdigyHostTask<bool> loadAwsMetadataCredential(CoroutineStack *coro, String& failure)
  {
    failure.clear();

    AwsHttpTransport transport(providerServices.http,
                               providerServices.delay,
                               providerServices.operationDeadline);
    for (uint32_t attempt = 0; attempt < 120; ++attempt)
    {
      MultiCurlClient::Result roleResult = co_await metadata.get(
          coro,
          transport,
          "/latest/meta-data/iam/security-credentials/"_ctv,
          &failure);
      if (AwsHttpTransport::succeeded(roleResult))
      {
        String roleName = std::move(roleResult.body);
        awsTrimTrailingAsciiWhitespace(roleName);
        if (roleName.size() > 0)
        {
          String credentialPath = {};
          credentialPath.snprintf<"/latest/meta-data/iam/security-credentials/{}"_ctv>(roleName);
          MultiCurlClient::Result credentialResult = co_await metadata.get(
              coro,
              transport,
              credentialPath,
              &failure);
          if (AwsHttpTransport::succeeded(credentialResult))
          {
            AwsSecretStringScope credentialResponseScope(credentialResult.body);
            AwsCredentialMaterial discovered = {};
            String parseFailure = {};
            if (parseAwsCredentialMaterial(credentialResult.body, discovered, &parseFailure))
            {
              credential = std::move(discovered);
              credentialLoaded = credential.valid();
              if (credentialLoaded == false)
              {
                failure.assign("aws credential material invalid"_ctv);
                co_return false;
              }

              co_return true;
            }

            failure = parseFailure;
          }
          else
          {
            failure.assign("aws metadata credential fetch failed"_ctv);
          }
        }
        else
        {
          failure.assign("aws metadata credentials unavailable"_ctv);
        }
      }
      else
      {
        failure.assign("aws metadata credentials unavailable"_ctv);
      }

      if (attempt + 1 < 120)
      {
        if (!co_await transport.wait(coro))
        {
          co_return false;
        }
      }
    }

    co_return false;
  }

  ProdigyHostTask<bool> ensureCredential(CoroutineStack *coro, String& failure)
  {
    if (awsCredentialNeedsRefresh() == false)
    {
      co_return true;
    }

    if (awsHasBootstrapCredentialRefreshCommand())
    {
      co_return co_await refreshAwsBootstrapCredential(coro, failure);
    }

    credential = {};
    if (runtimeEnvironment.providerCredentialMaterial.size() > 0)
    {
      if (parseAwsCredentialMaterial(runtimeEnvironment.providerCredentialMaterial, credential, &failure) == false)
      {
        co_return false;
      }
      credentialLoaded = credential.valid();
      if (credentialLoaded && credential.expirationMs() > 0 && Time::now<TimeResolution::ms>() + 30 * 1000 >= credential.expirationMs())
      {
        failure.assign("aws credential material expired"_ctv);
        credentialLoaded = false;
      }

      if (credentialLoaded)
      {
        // Explicit bootstrap material should win when it is present and
        // valid. This keeps non-EC2 controllers from stalling on IMDS just
        // because the runtime also knows about an eventual instance
        // profile contract for the launched machines.
        co_return true;
      }
    }

    if (runtimeEnvironment.aws.instanceProfileName.size() > 0 || runtimeEnvironment.aws.instanceProfileArn.size() > 0)
    {
      co_return co_await loadAwsMetadataCredential(coro, failure);
    }

    if (runtimeEnvironment.providerCredentialMaterial.size() == 0)
    {
      co_return co_await loadAwsMetadataCredential(coro, failure);
    }

    if (credentialLoaded == false)
    {
      failure.assign("aws credential material invalid"_ctv);
    }

    co_return credentialLoaded;
  }

  static AwsHttpRequest::Target target(const String& authority,
                                       const String& region,
                                       const String& service)
  {
    AwsHttpRequest::Target target;
    target.authority.assign(authority);
    target.region.assign(region);
    target.service.assign(service);
    return target;
  }

  ProdigyHostTask<bool> sendPricingRequest(CoroutineStack *coro,
                                           const String& requestBody,
                                           String& response,
                                           String& failure,
                                           long *httpCode = nullptr)
  {
    if (!co_await ensureCredential(coro, failure))
    {
      co_return false;
    }
    Vector<MultiCurlClient::Header> headers;
    headers.push_back({"Content-Type"_ctv, "application/x-amz-json-1.1"_ctv});
    headers.push_back({"X-Amz-Target"_ctv, "AWSPriceListService.GetProducts"_ctv});
    AwsHttpTransport transport(providerServices.http,
                               providerServices.delay,
                               providerServices.operationDeadline);
    MultiCurlClient::Result result = co_await transport.sendSigned(
        coro,
        target("api.pricing.us-east-1.amazonaws.com"_ctv, "us-east-1"_ctv, "pricing"_ctv),
        MultiCurlClient::Method::post,
        headers,
        &requestBody,
        credential,
        &failure);
    response = std::move(result.body);
    if (httpCode)
    {
      *httpCode = result.statusCode;
    }
    if (result.status != MultiCurlClient::Status::success)
    {
      AwsHttpTransport::assignTransportFailure(result, failure);
      co_return false;
    }
    if (result.statusCode < 200 || result.statusCode >= 300)
    {
      AwsHttpTransport::assignHttpFailure(
          "aws pricing request failed"_ctv, result.statusCode, response, failure);
      co_return false;
    }
    failure.clear();
    co_return true;
  }

protected:

  virtual ProdigyHostTask<bool> sendElasticEC2Request(CoroutineStack *coro,
                                                      const String& actionBody,
                                                      String& response,
                                                      String& failure,
                                                      long *httpCode = nullptr)
  {
    if (!co_await ensureRegion(coro))
    {
      failure.assign("aws region missing"_ctv);
      co_return false;
    }

    if (!co_await ensureCredential(coro, failure))
    {
      co_return false;
    }

    String authority;
    authority.snprintf<"ec2.{}.amazonaws.com"_ctv>(region);
    Vector<MultiCurlClient::Header> headers;
    headers.push_back({"Content-Type"_ctv,
                       "application/x-www-form-urlencoded; charset=utf-8"_ctv});
    AwsHttpTransport transport(providerServices.http,
                               providerServices.delay,
                               providerServices.operationDeadline);
    MultiCurlClient::Result result = co_await transport.sendSigned(
        coro,
        target(authority, region, "ec2"_ctv),
        MultiCurlClient::Method::post,
        headers,
        &actionBody,
        credential,
        &failure);
    response = std::move(result.body);
    if (httpCode)
    {
      *httpCode = result.statusCode;
    }

    if (result.status != MultiCurlClient::Status::success)
    {
      AwsHttpTransport::assignTransportFailure(result, failure);
      co_return false;
    }

    if (result.statusCode < 200 || result.statusCode >= 300)
    {
      String message;
      if (awsExtractXMLValue(response, "Message", message) == false)
      {
        message = response;
      }
      AwsHttpTransport::assignHttpFailure(
          "aws request failed"_ctv, result.statusCode, message, failure);
      co_return false;
    }

    failure.clear();
    co_return true;
  }

  virtual ProdigyHostTask<bool> sendIAMRequest(CoroutineStack *coro,
                                               const String& actionBody,
                                               String& response,
                                               String& failure,
                                               long *httpCode = nullptr)
  {
    if (!co_await ensureCredential(coro, failure))
    {
      co_return false;
    }

    Vector<MultiCurlClient::Header> headers;
    headers.push_back({"Content-Type"_ctv,
                       "application/x-www-form-urlencoded; charset=utf-8"_ctv});
    AwsHttpTransport transport(providerServices.http,
                               providerServices.delay,
                               providerServices.operationDeadline);
    MultiCurlClient::Result result = co_await transport.sendSigned(
        coro,
        target("iam.amazonaws.com"_ctv, "us-east-1"_ctv, "iam"_ctv),
        MultiCurlClient::Method::post,
        headers,
        &actionBody,
        credential,
        &failure);
    response = std::move(result.body);
    if (httpCode)
    {
      *httpCode = result.statusCode;
    }

    if (result.status != MultiCurlClient::Status::success)
    {
      AwsHttpTransport::assignTransportFailure(result, failure);
      co_return false;
    }

    if (result.statusCode < 200 || result.statusCode >= 300)
    {
      String message;
      if (awsExtractXMLValue(response, "Message", message) == false)
      {
        message = response;
      }
      AwsHttpTransport::assignHttpFailure(
          "aws iam request failed"_ctv, result.statusCode, message, failure);
      co_return false;
    }

    failure.clear();
    co_return true;
  }

private:

  ProdigyHostTask<bool> request(CoroutineStack *coro,
                                const String& actionBody,
                                String& response,
                                String& failure,
                                long *httpCode = nullptr)
  {
    co_return co_await sendElasticEC2Request(coro, actionBody, response, failure, httpCode);
  }

  ProdigyHostTask<bool> iamRequest(CoroutineStack *coro,
                                   const String& actionBody,
                                   String& response,
                                   String& failure,
                                   long *httpCode = nullptr)
  {
    co_return co_await sendIAMRequest(coro, actionBody, response, failure, httpCode);
  }

  static bool awsConsumePathSegment(const String& text, uint64_t& offset, String& segment)
  {
    if (offset > text.size())
    {
      return false;
    }

    uint64_t slash = uint64_t(-1);
    for (uint64_t index = offset; index < text.size(); ++index)
    {
      if (text[index] == '/')
      {
        slash = index;
        break;
      }
    }

    if (slash == uint64_t(-1))
    {
      segment.assign(text.substr(offset, text.size() - offset, Copy::yes));
      offset = text.size();
      return true;
    }

    segment.assign(text.substr(offset, slash - offset, Copy::yes));
    offset = slash + 1;
    return true;
  }

  static bool awsResolveCanonicalUbuntuRelease(const String& token, String& version, String& codename)
  {
    if (token.equal("24.04"_ctv) || token.equal("noble"_ctv))
    {
      version = "24.04"_ctv;
      codename = "noble"_ctv;
      return true;
    }

    if (token.equal("22.04"_ctv) || token.equal("jammy"_ctv))
    {
      version = "22.04"_ctv;
      codename = "jammy"_ctv;
      return true;
    }

    if (token.equal("20.04"_ctv) || token.equal("focal"_ctv))
    {
      version = "20.04"_ctv;
      codename = "focal"_ctv;
      return true;
    }

    return false;
  }

  ProdigyHostTask<bool> resolveCanonicalUbuntuImageID(CoroutineStack *coro, const String& imageReference, String& imageID, String& failure)
  {
    imageID.clear();

    if (awsHasPrefix(imageReference, canonicalUbuntuSSMPrefix) == false)
    {
      imageID = imageReference;
      failure.clear();
      co_return true;
    }

    uint64_t offset = uint64_t(strlen(canonicalUbuntuSSMPrefix));
    String releaseToken = {};
    String trackToken = {};
    String currentToken = {};
    String architectureToken = {};
    String virtualizationToken = {};
    String volumeToken = {};
    String leafToken = {};
    if (awsConsumePathSegment(imageReference, offset, releaseToken) == false || awsConsumePathSegment(imageReference, offset, trackToken) == false || awsConsumePathSegment(imageReference, offset, currentToken) == false || awsConsumePathSegment(imageReference, offset, architectureToken) == false || awsConsumePathSegment(imageReference, offset, virtualizationToken) == false || awsConsumePathSegment(imageReference, offset, volumeToken) == false || awsConsumePathSegment(imageReference, offset, leafToken) == false)
    {
      failure.assign("aws canonical ubuntu image reference parse failed"_ctv);
      co_return false;
    }

    if (leafToken != "ami-id"_ctv || trackToken != "stable"_ctv || currentToken != "current"_ctv)
    {
      failure.assign("aws canonical ubuntu image reference unsupported"_ctv);
      co_return false;
    }

    String versionToken = {};
    String codenameToken = {};
    if (awsResolveCanonicalUbuntuRelease(releaseToken, versionToken, codenameToken) == false)
    {
      failure.assign("aws canonical ubuntu release unsupported"_ctv);
      co_return false;
    }

    String architecture = {};
    if (architectureToken == "amd64"_ctv)
    {
      architecture = "x86_64"_ctv;
    }
    else if (architectureToken == "arm64"_ctv)
    {
      architecture = "arm64"_ctv;
    }
    else
    {
      failure.assign("aws canonical ubuntu architecture unsupported"_ctv);
      co_return false;
    }

    if (virtualizationToken != "hvm"_ctv)
    {
      failure.assign("aws canonical ubuntu virtualization unsupported"_ctv);
      co_return false;
    }

    String storagePrefix = "hvm-ssd"_ctv;
    if (volumeToken == "ebs-gp3"_ctv)
    {
      storagePrefix = "hvm-ssd-gp3"_ctv;
    }
    else if (volumeToken != "ebs-gp2"_ctv)
    {
      failure.assign("aws canonical ubuntu volume type unsupported"_ctv);
      co_return false;
    }

    String namePattern = {};
    namePattern.snprintf<"ubuntu/images/{}/ubuntu-{}-{}-{}-server-*"_ctv>(
        storagePrefix,
        codenameToken,
        versionToken,
        architectureToken);

    String bestImageID = {};
    String bestCreationDate = {};
    String nextToken = {};
    bytell_hash_set<String> requestedTokens;
    uint32_t pages = 0;

    while (true)
    {
      if (++pages > AwsHttpTransport::maximumPages ||
          (!nextToken.empty() && !requestedTokens.insert(nextToken).second))
      {
        failure.assign("aws DescribeImages pagination limit exceeded"_ctv);
        co_return false;
      }
      bool first = true;
      String body = {};
      awsAppendQueryParam(body, "Action"_ctv, "DescribeImages"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "Owner.1"_ctv, "099720109477"_ctv, first);
      awsAppendQueryParam(body, "Filter.1.Name"_ctv, "name"_ctv, first);
      awsAppendQueryParam(body, "Filter.1.Value.1"_ctv, namePattern, first);
      awsAppendQueryParam(body, "Filter.2.Name"_ctv, "architecture"_ctv, first);
      awsAppendQueryParam(body, "Filter.2.Value.1"_ctv, architecture, first);
      awsAppendQueryParam(body, "Filter.3.Name"_ctv, "root-device-type"_ctv, first);
      awsAppendQueryParam(body, "Filter.3.Value.1"_ctv, "ebs"_ctv, first);
      awsAppendQueryParam(body, "Filter.4.Name"_ctv, "state"_ctv, first);
      awsAppendQueryParam(body, "Filter.4.Value.1"_ctv, "available"_ctv, first);
      awsAppendQueryParam(body, "Filter.5.Name"_ctv, "virtualization-type"_ctv, first);
      awsAppendQueryParam(body, "Filter.5.Value.1"_ctv, virtualizationToken, first);
      if (nextToken.size() > 0)
      {
        awsAppendQueryParam(body, "NextToken"_ctv, nextToken, first);
      }

      String response = {};
      if (co_await request(coro, body, response, failure) == false)
      {
        co_return false;
      }

      Vector<String> imageBlocks;
      awsCollectSetItemBlocks(response, "imagesSet", imageBlocks);
      for (const String& block : imageBlocks)
      {
        String candidateID = {};
        String candidateCreationDate = {};
        if (awsExtractXMLValue(block, "imageId", candidateID) == false || awsExtractXMLValue(block, "creationDate", candidateCreationDate) == false)
        {
          continue;
        }

        bool newer = (bestCreationDate.size() == 0);
        if (newer == false)
        {
          uint64_t compareBytes = candidateCreationDate.size();
          if (bestCreationDate.size() < compareBytes)
          {
            compareBytes = bestCreationDate.size();
          }

          int cmp = 0;
          if (compareBytes > 0)
          {
            cmp = memcmp(candidateCreationDate.data(), bestCreationDate.data(), compareBytes);
          }

          if (cmp > 0 || (cmp == 0 && candidateCreationDate.size() > bestCreationDate.size()))
          {
            newer = true;
          }
        }

        if (newer)
        {
          bestCreationDate = candidateCreationDate;
          bestImageID = candidateID;
        }
      }

      nextToken.clear();
      awsExtractXMLValue(response, "nextToken", nextToken);
      if (nextToken.size() == 0)
      {
        break;
      }
    }

    if (bestImageID.size() == 0)
    {
      failure.assign("aws canonical ubuntu image not found"_ctv);
      co_return false;
    }

    imageID = bestImageID;
    failure.clear();
    co_return true;
  }

  Machine *buildMachineFromInstanceBlock(const String& block)
  {
    Machine *machine = new Machine();

    String instanceID;
    if (awsExtractXMLValue(block, "instanceId", instanceID))
    {
      machine->cloudID = instanceID;
      for (uint64_t index = 0; index < instanceID.size(); ++index)
      {
        machine->uuid = (machine->uuid * 131) + instanceID[index];
      }
    }

    String launchTime;
    if (awsExtractXMLValue(block, "launchTime", launchTime))
    {
      machine->creationTimeMs = awsParseRFC3339Ms(launchTime);
    }

    String imageID;
    if (awsExtractXMLValue(block, "imageId", imageID))
    {
      machine->currentImageURI = imageID;
    }

    String instanceType;
    if (awsExtractXMLValue(block, "instanceType", instanceType))
    {
      machine->type = instanceType;
      machine->slug = instanceType;
    }

    String availabilityZone;
    if (awsExtractXMLValue(block, "availabilityZone", availabilityZone))
    {
      machine->region = region;
      machine->zone = availabilityZone;
      machine->rackUUID = awsRackUUIDFromAvailabilityZone(availabilityZone);
    }

    String privateIP;
    if (awsExtractXMLValue(block, "privateIpAddress", privateIP))
    {
      machine->privateAddress = privateIP;
      String privateText = {};
      privateText.assign(privateIP);
      (void)inet_pton(AF_INET, privateText.c_str(), &machine->private4);
    }

    String ipv6Address;
    if (awsExtractXMLValue(block, "ipv6Address", ipv6Address))
    {
      if (machine->privateAddress.size() == 0)
      {
        machine->privateAddress = ipv6Address;
      }

      if (machine->publicAddress.size() == 0)
      {
        machine->publicAddress = ipv6Address;
      }

      if (machine->sshAddress.size() == 0)
      {
        machine->sshAddress = ipv6Address;
      }
    }

    String publicIP;
    if (awsExtractXMLValue(block, "ipAddress", publicIP))
    {
      machine->publicAddress = publicIP;
      machine->sshAddress = publicIP;
    }
    else
    {
      machine->sshAddress = machine->privateAddress;
    }

    String lifecycle;
    if (awsExtractXMLValue(block, "instanceLifecycle", lifecycle) && lifecycle == "spot"_ctv)
    {
      machine->lifetime = MachineLifetime::spot;
    }

    String brainTag;
    if (awsExtractTagValue(block, "brain"_ctv, brainTag))
    {
      machine->isBrain = (brainTag == "1"_ctv || brainTag == "true"_ctv);
    }

    if (bootstrapSSHPrivateKeyPath.size() > 0)
    {
      machine->sshUser = bootstrapSSHUser;
      machine->sshPrivateKeyPath = bootstrapSSHPrivateKeyPath;
      machine->sshHostPublicKeyOpenSSH = bootstrapSSHHostKeyPackage.publicKeyOpenSSH;
    }

    prodigyConfigureMachineNeuronEndpoint(*machine, thisNeuron);

    return machine;
  }

  ProdigyHostTask<bool> requestPages(CoroutineStack *coro,
                                     const String& baseBody,
                                     const char *setTag,
                                     const char *fallbackSetTag,
                                     Vector<String>& blocks,
                                     String& failure)
  {
    blocks.clear();
    String nextToken;
    bytell_hash_set<String> requestedTokens;
    for (uint32_t page = 0; page < AwsHttpTransport::maximumPages; ++page)
    {
      if (!nextToken.empty() && !requestedTokens.insert(nextToken).second)
      {
        failure.assign("aws EC2 pagination token repeated"_ctv);
        co_return false;
      }

      String body = baseBody;
      if (!nextToken.empty())
      {
        bool first = body.empty();
        awsAppendQueryParam(body, "NextToken"_ctv, nextToken, first);
      }
      String response;
      if (co_await request(coro, body, response, failure) == false)
      {
        co_return false;
      }

      Vector<String> pageBlocks;
      awsCollectSetItemBlocks(response, setTag, pageBlocks);
      if (pageBlocks.empty() && fallbackSetTag)
      {
        awsCollectSetItemBlocks(response, fallbackSetTag, pageBlocks);
      }
      for (String& block : pageBlocks)
      {
        blocks.push_back(std::move(block));
      }

      nextToken.clear();
      (void)awsExtractXMLValue(response, "nextToken", nextToken);
      if (nextToken.empty())
      {
        co_return true;
      }
    }

    failure.assign("aws EC2 pagination page limit exceeded"_ctv);
    co_return false;
  }

  ProdigyHostTask<bool> describeInstances(CoroutineStack *coro, const String& filterBody, Vector<String>& instanceBlocks, String& failure)
  {
    instanceBlocks.clear();
    String body = {};
    body.append("Action=DescribeInstances&Version=2016-11-15"_ctv);
    if (filterBody.size() > 0)
    {
      body.append('&');
      body.append(filterBody);
    }

    co_return co_await requestPages(
        coro, body, "instancesSet", nullptr, instanceBlocks, failure);
  }

  ProdigyHostTask<bool> describeVpcs(CoroutineStack *coro, Vector<String>& vpcBlocks, String& failure)
  {
    vpcBlocks.clear();

    co_return co_await requestPages(coro,
                                    "Action=DescribeVpcs&Version=2016-11-15"_ctv,
                                    "vpcSet",
                                    nullptr,
                                    vpcBlocks,
                                    failure);
  }

  ProdigyHostTask<bool> describeSubnets(CoroutineStack *coro, const String& filterBody, Vector<String>& subnetBlocks, String& failure)
  {
    subnetBlocks.clear();

    String body = {};
    body.append("Action=DescribeSubnets&Version=2016-11-15"_ctv);
    if (filterBody.size() > 0)
    {
      body.append('&');
      body.append(filterBody);
    }

    co_return co_await requestPages(
        coro, body, "subnetSet", nullptr, subnetBlocks, failure);
  }

  ProdigyHostTask<bool> describeSecurityGroups(CoroutineStack *coro, const String& filterBody, Vector<String>& groupBlocks, String& failure)
  {
    groupBlocks.clear();

    String body = {};
    body.append("Action=DescribeSecurityGroups&Version=2016-11-15"_ctv);
    if (filterBody.size() > 0)
    {
      body.append('&');
      body.append(filterBody);
    }

    co_return co_await requestPages(
        coro, body, "securityGroupInfo", nullptr, groupBlocks, failure);
  }

  ProdigyHostTask<bool> describeLaunchTemplates(CoroutineStack *coro, const String& filterBody, Vector<String>& templateBlocks, String& failure)
  {
    templateBlocks.clear();

    String body = {};
    body.append("Action=DescribeLaunchTemplates&Version=2016-11-15"_ctv);
    if (filterBody.size() > 0)
    {
      body.append('&');
      body.append(filterBody);
    }

    co_return co_await requestPages(coro,
                                    body,
                                    "launchTemplates",
                                    "launchTemplateSet",
                                    templateBlocks,
                                    failure);
  }

  ProdigyHostTask<bool> findDefaultVPC(CoroutineStack *coro, String& vpcID, String& failure)
  {
    vpcID.clear();

    Vector<String> vpcBlocks;
    co_await describeVpcs(coro, vpcBlocks, failure);
    if (failure.size() > 0)
    {
      co_return false;
    }

    for (const String& block : vpcBlocks)
    {
      String isDefault;
      if (awsExtractXMLValue(block, "isDefault", isDefault) && isDefault == "true"_ctv)
      {
        if (awsExtractXMLValue(block, "vpcId", vpcID))
        {
          failure.clear();
          co_return true;
        }
      }
    }

    failure.assign("aws default vpc missing"_ctv);
    co_return false;
  }

  ProdigyHostTask<bool> findBootstrapSubnet(CoroutineStack *coro, const String& vpcID, String& subnetID, String& failure)
  {
    subnetID.clear();

    bool first = true;
    String filters = {};
    awsAppendQueryParam(filters, "Filter.1.Name"_ctv, "vpc-id"_ctv, first);
    awsAppendQueryParam(filters, "Filter.1.Value.1"_ctv, vpcID, first);

    Vector<String> subnetBlocks;
    co_await describeSubnets(coro, filters, subnetBlocks, failure);
    if (failure.size() > 0)
    {
      co_return false;
    }

    String availabilityZone;
    if (awsSelectBootstrapSubnet(subnetBlocks, subnetID, availabilityZone))
    {
      failure.clear();
      co_return true;
    }

    failure.assign("aws bootstrap subnet missing"_ctv);
    co_return false;
  }

  ProdigyHostTask<bool> findBootstrapSecurityGroup(CoroutineStack *coro, const String& vpcID, String& groupID, String& failure)
  {
    groupID.clear();

    bool first = true;
    String filters = {};
    awsAppendQueryParam(filters, "Filter.1.Name"_ctv, "vpc-id"_ctv, first);
    awsAppendQueryParam(filters, "Filter.1.Value.1"_ctv, vpcID, first);
    awsAppendQueryParam(filters, "Filter.2.Name"_ctv, "group-name"_ctv, first);
    awsAppendQueryParam(filters, "Filter.2.Value.1"_ctv, "prodigy-bootstrap-ssh"_ctv, first);

    Vector<String> groupBlocks;
    co_await describeSecurityGroups(coro, filters, groupBlocks, failure);
    if (failure.size() > 0)
    {
      co_return false;
    }

    for (const String& block : groupBlocks)
    {
      if (awsExtractXMLValue(block, "groupId", groupID))
      {
        failure.clear();
        co_return true;
      }
    }

    failure.clear();
    co_return true;
  }

  ProdigyHostTask<bool> findDefaultSecurityGroup(CoroutineStack *coro, const String& vpcID, String& groupID, String& failure)
  {
    groupID.clear();

    bool first = true;
    String filters = {};
    awsAppendQueryParam(filters, "Filter.1.Name"_ctv, "vpc-id"_ctv, first);
    awsAppendQueryParam(filters, "Filter.1.Value.1"_ctv, vpcID, first);
    awsAppendQueryParam(filters, "Filter.2.Name"_ctv, "group-name"_ctv, first);
    awsAppendQueryParam(filters, "Filter.2.Value.1"_ctv, "default"_ctv, first);

    Vector<String> groupBlocks;
    co_await describeSecurityGroups(coro, filters, groupBlocks, failure);
    if (failure.size() > 0)
    {
      co_return false;
    }

    for (const String& block : groupBlocks)
    {
      if (awsExtractXMLValue(block, "groupId", groupID))
      {
        failure.clear();
        co_return true;
      }
    }

    failure.assign("aws default security group missing"_ctv);
    co_return false;
  }

  ProdigyHostTask<bool> createBootstrapSecurityGroup(CoroutineStack *coro, const String& vpcID, String& groupID, String& failure)
  {
    groupID.clear();

    bool first = true;
    String body = {};
    awsAppendQueryParam(body, "Action"_ctv, "CreateSecurityGroup"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "GroupName"_ctv, "prodigy-bootstrap-ssh"_ctv, first);
    awsAppendQueryParam(body, "GroupDescription"_ctv, "Prodigy bootstrap SSH access"_ctv, first);
    awsAppendQueryParam(body, "VpcId"_ctv, vpcID, first);

    String response;
    if (co_await request(coro, body, response, failure) == false)
    {
      co_return false;
    }

    if (awsExtractXMLValue(response, "groupId", groupID) == false)
    {
      failure.assign("aws CreateSecurityGroup response missing groupId"_ctv);
      co_return false;
    }

    failure.clear();
    co_return true;
  }

  ProdigyHostTask<bool> authorizeBootstrapSSHIngress(CoroutineStack *coro, const String& groupID, String& failure)
  {
    bool first = true;
    String body = {};
    awsAppendQueryParam(body, "Action"_ctv, "AuthorizeSecurityGroupIngress"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "GroupId"_ctv, groupID, first);
    awsAppendQueryParam(body, "IpProtocol"_ctv, "tcp"_ctv, first);
    awsAppendQueryParam(body, "FromPort"_ctv, "22"_ctv, first);
    awsAppendQueryParam(body, "ToPort"_ctv, "22"_ctv, first);
    awsAppendQueryParam(body, "CidrIp"_ctv, "0.0.0.0/0"_ctv, first);

    String response;
    if (co_await request(coro, body, response, failure) == false)
    {
      String failureText = {};
      failureText.assign(failure);
      if (strstr(failureText.c_str(), "already exists") != nullptr || strstr(failureText.c_str(), "InvalidPermission.Duplicate") != nullptr)
      {
        failure.clear();
        co_return true;
      }

      co_return false;
    }

    failure.clear();
    co_return true;
  }

  ProdigyHostTask<bool> authorizeBootstrapMeshIngress(CoroutineStack *coro, const String& groupID, String& failure)
  {
    bool first = true;
    String body = {};
    awsAppendQueryParam(body, "Action"_ctv, "AuthorizeSecurityGroupIngress"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "GroupId"_ctv, groupID, first);
    awsAppendQueryParam(body, "IpPermissions.1.IpProtocol"_ctv, "-1"_ctv, first);
    awsAppendQueryParam(body, "IpPermissions.1.Groups.1.GroupId"_ctv, groupID, first);

    String response;
    if (co_await request(coro, body, response, failure) == false)
    {
      String failureText = {};
      failureText.assign(failure);
      if (strstr(failureText.c_str(), "already exists") != nullptr || strstr(failureText.c_str(), "InvalidPermission.Duplicate") != nullptr)
      {
        failure.clear();
        co_return true;
      }

      co_return false;
    }

    failure.clear();
    co_return true;
  }

  ProdigyHostTask<bool> ensureBootstrapPlacement(CoroutineStack *coro, String& subnetID, String& securityGroupID, String& failure)
  {
    subnetID.clear();
    securityGroupID.clear();

    String vpcID;
    if (co_await findDefaultVPC(coro, vpcID, failure) == false)
    {
      co_return false;
    }

    if (co_await findBootstrapSubnet(coro, vpcID, subnetID, failure) == false)
    {
      co_return false;
    }

    if (co_await findBootstrapSecurityGroup(coro, vpcID, securityGroupID, failure) == false)
    {
      co_return false;
    }

    if (securityGroupID.size() == 0)
    {
      if (co_await createBootstrapSecurityGroup(coro, vpcID, securityGroupID, failure) == false)
      {
        co_return false;
      }
    }

    if (co_await authorizeBootstrapSSHIngress(coro, securityGroupID, failure) == false)
    {
      co_return false;
    }

    co_return co_await authorizeBootstrapMeshIngress(coro, securityGroupID, failure);
  }

  ProdigyHostTask<bool> describeBootstrapLaunchTemplate(CoroutineStack *coro, const String& launchTemplateName, String& launchTemplateID, String& defaultVersionNumber, String& latestVersionNumber, String& failure)
  {
    launchTemplateID.clear();
    defaultVersionNumber.clear();
    latestVersionNumber.clear();

    bool first = true;
    String filters = {};
    awsAppendQueryParam(filters, "LaunchTemplateName.1"_ctv, launchTemplateName, first);

    Vector<String> templateBlocks;
    co_await describeLaunchTemplates(coro, filters, templateBlocks, failure);
    if (failure.size() > 0)
    {
      if (awsIsLaunchTemplateMissingFailure(failure))
      {
        failure.clear();
        co_return true;
      }

      co_return false;
    }

    if (templateBlocks.size() == 0)
    {
      co_return true;
    }

    awsExtractXMLValue(templateBlocks[0], "launchTemplateId", launchTemplateID);
    awsExtractXMLValue(templateBlocks[0], "defaultVersionNumber", defaultVersionNumber);
    awsExtractXMLValue(templateBlocks[0], "latestVersionNumber", latestVersionNumber);
    co_return true;
  }

  ProdigyHostTask<bool> createBootstrapLaunchTemplate(
      CoroutineStack *coro,
      const String& launchTemplateName,
      const String& subnetID,
      const String& securityGroupID,
      const String& instanceProfileName,
      const String& instanceProfileArn,
      String& failure)
  {
    String description;
    if (!awsBootstrapLaunchTemplateDescription(subnetID,
                                            securityGroupID,
                                            instanceProfileName,
                                            instanceProfileArn,
                                            description))
    {
      failure.assign("aws bootstrap launch template fingerprint failed"_ctv);
      co_return false;
    }
    bool first = true;
    String body = {};
    String clientToken;
    Vector<String> tokenComponents;
    tokenComponents.push_back(launchTemplateName);
    tokenComponents.push_back(description);
    if (!AwsHttpRequest::idempotencyToken(tokenComponents, clientToken))
    {
      failure.assign("aws bootstrap launch template ClientToken failed"_ctv);
      co_return false;
    }
    awsAppendQueryParam(body, "Action"_ctv, "CreateLaunchTemplate"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "ClientToken"_ctv, clientToken, first);
    awsAppendQueryParam(body, "LaunchTemplateName"_ctv, launchTemplateName, first);
    awsAppendQueryParam(body, "VersionDescription"_ctv, description, first);
    awsAppendBootstrapLaunchTemplateData(body, "LaunchTemplateData"_ctv, subnetID, securityGroupID, instanceProfileName, instanceProfileArn, first);

    String response;
    co_return co_await request(coro, body, response, failure);
  }

  ProdigyHostTask<bool> describeBootstrapLaunchTemplateDefaultDescription(
      CoroutineStack *coro,
      const String& launchTemplateName,
      String& description,
      String& failure)
  {
    bool first = true;
    String body;
    awsAppendQueryParam(body, "Action"_ctv, "DescribeLaunchTemplateVersions"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "LaunchTemplateName"_ctv, launchTemplateName, first);
    awsAppendQueryParam(body, "LaunchTemplateVersion.1"_ctv, "$Default"_ctv, first);
    String response;
    if (!co_await request(coro, body, response, failure))
    {
      co_return false;
    }
    if (!awsExtractXMLValue(response, "versionDescription", description))
    {
      description.clear();
    }
    co_return true;
  }

  ProdigyHostTask<bool> waitForBootstrapLaunchTemplateState(
      CoroutineStack *coro,
      const String& launchTemplateName,
      const String& expectedDefaultVersion,
      String& launchTemplateID,
      String& defaultVersionNumber,
      String& latestVersionNumber,
      String& failure)
  {
    launchTemplateID.clear();
    defaultVersionNumber.clear();
    latestVersionNumber.clear();
    AwsHttpTransport transport(providerServices.http,
                               providerServices.delay,
                               providerServices.operationDeadline);

    for (uint32_t attempt = 0; attempt < 40; ++attempt)
    {
      if (co_await describeBootstrapLaunchTemplate(coro, launchTemplateName, launchTemplateID, defaultVersionNumber, latestVersionNumber, failure) == false)
      {
        if (awsIsLaunchTemplateMissingFailure(failure))
        {
          failure.clear();
          if (!co_await transport.wait(coro))
          {
            failure.assign("aws bootstrap launch template wait canceled"_ctv);
            co_return false;
          }
          continue;
        }

        co_return false;
      }

      bool visible = launchTemplateID.size() > 0;
      bool versionsVisible = defaultVersionNumber.size() > 0 && latestVersionNumber.size() > 0;
      bool expectedDefaultReady = (expectedDefaultVersion.size() == 0) || (defaultVersionNumber == expectedDefaultVersion);
      if (visible && versionsVisible && expectedDefaultReady)
      {
        failure.clear();
        co_return true;
      }

      if (!co_await transport.wait(coro))
      {
        failure.assign("aws bootstrap launch template wait canceled"_ctv);
        co_return false;
      }
    }

    if (expectedDefaultVersion.size() > 0)
    {
      failure.snprintf<"aws bootstrap launch template {} default version {} not visible yet"_ctv>(launchTemplateName, expectedDefaultVersion);
    }
    else
    {
      failure.snprintf<"aws bootstrap launch template {} not visible yet"_ctv>(launchTemplateName);
    }

    co_return false;
  }

  ProdigyHostTask<bool> createBootstrapLaunchTemplateVersion(
      CoroutineStack *coro,
      const String& launchTemplateName,
      const String& subnetID,
      const String& securityGroupID,
      const String& instanceProfileName,
      const String& instanceProfileArn,
      String& versionNumber,
      String& failure)
  {
    versionNumber.clear();
    String description;
    if (!awsBootstrapLaunchTemplateDescription(subnetID,
                                            securityGroupID,
                                            instanceProfileName,
                                            instanceProfileArn,
                                            description))
    {
      failure.assign("aws bootstrap launch template fingerprint failed"_ctv);
      co_return false;
    }

    bool first = true;
    String body = {};
    String clientToken;
    Vector<String> tokenComponents;
    tokenComponents.push_back(launchTemplateName);
    tokenComponents.push_back(description);
    if (!AwsHttpRequest::idempotencyToken(tokenComponents, clientToken))
    {
      failure.assign("aws bootstrap launch template version ClientToken failed"_ctv);
      co_return false;
    }
    awsAppendQueryParam(body, "Action"_ctv, "CreateLaunchTemplateVersion"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "ClientToken"_ctv, clientToken, first);
    awsAppendQueryParam(body, "LaunchTemplateName"_ctv, launchTemplateName, first);
    awsAppendQueryParam(body, "VersionDescription"_ctv, description, first);
    awsAppendBootstrapLaunchTemplateData(body, "LaunchTemplateData"_ctv, subnetID, securityGroupID, instanceProfileName, instanceProfileArn, first);

    String response;
    if (co_await request(coro, body, response, failure) == false)
    {
      co_return false;
    }

    if (awsExtractXMLValue(response, "versionNumber", versionNumber) == false)
    {
      failure.assign("aws CreateLaunchTemplateVersion response missing versionNumber"_ctv);
      co_return false;
    }

    co_return true;
  }

  ProdigyHostTask<bool> setBootstrapLaunchTemplateDefaultVersion(CoroutineStack *coro, const String& launchTemplateName, const String& versionNumber, String& failure)
  {
    bool first = true;
    String body = {};
    awsAppendQueryParam(body, "Action"_ctv, "ModifyLaunchTemplate"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "LaunchTemplateName"_ctv, launchTemplateName, first);
    awsAppendQueryParam(body, "SetDefaultVersion"_ctv, versionNumber, first);

    String response;
    co_return co_await request(coro, body, response, failure);
  }

  ProdigyHostTask<bool> ensureBootstrapLaunchTemplate(CoroutineStack *coro, String& launchTemplateName, String& launchTemplateVersion, String& failure)
  {
    launchTemplateName = runtimeEnvironment.aws.bootstrapLaunchTemplateName;
    launchTemplateVersion = runtimeEnvironment.aws.bootstrapLaunchTemplateVersion;

    if (launchTemplateName.size() == 0)
    {
      failure.assign("aws bootstrap launch template name missing"_ctv);
      co_return false;
    }

    if (launchTemplateVersion.size() == 0)
    {
      launchTemplateVersion.assign("$Default"_ctv);
    }

    String subnetID = {};
    String securityGroupID = {};
    const String& instanceProfileName = runtimeEnvironment.aws.instanceProfileName;
    const String& instanceProfileArn = runtimeEnvironment.aws.instanceProfileArn;
    if (co_await ensureBootstrapPlacement(coro, subnetID, securityGroupID, failure) == false)
    {
      co_return false;
    }

    String launchTemplateID = {};
    String defaultVersionNumber = {};
    String latestVersionNumber = {};
    if (co_await describeBootstrapLaunchTemplate(coro, launchTemplateName, launchTemplateID, defaultVersionNumber, latestVersionNumber, failure) == false)
    {
      co_return false;
    }

    if (launchTemplateID.size() == 0)
    {
      if (co_await createBootstrapLaunchTemplate(coro, launchTemplateName, subnetID, securityGroupID, instanceProfileName, instanceProfileArn, failure) == false)
      {
        co_return false;
      }

      if (co_await waitForBootstrapLaunchTemplateState(coro, launchTemplateName, ""_ctv, launchTemplateID, defaultVersionNumber, latestVersionNumber, failure) == false)
      {
        co_return false;
      }
    }
    else if (launchTemplateVersion == "$Default"_ctv)
    {
      String desiredDescription;
      String currentDescription;
      if (!awsBootstrapLaunchTemplateDescription(subnetID,
                                              securityGroupID,
                                              instanceProfileName,
                                              instanceProfileArn,
                                              desiredDescription) ||
          !co_await describeBootstrapLaunchTemplateDefaultDescription(
              coro, launchTemplateName, currentDescription, failure))
      {
        co_return false;
      }
      if (currentDescription != desiredDescription)
      {
        String createdVersionNumber = {};
        if (co_await createBootstrapLaunchTemplateVersion(coro, launchTemplateName, subnetID, securityGroupID, instanceProfileName, instanceProfileArn, createdVersionNumber, failure) == false)
        {
          co_return false;
        }

        if (co_await setBootstrapLaunchTemplateDefaultVersion(coro, launchTemplateName, createdVersionNumber, failure) == false)
        {
          co_return false;
        }

        if (co_await waitForBootstrapLaunchTemplateState(coro, launchTemplateName, createdVersionNumber, launchTemplateID, defaultVersionNumber, latestVersionNumber, failure) == false)
        {
          co_return false;
        }
      }
    }

    if (launchTemplateVersion == "$Default"_ctv)
    {
      if (defaultVersionNumber.size() == 0)
      {
        failure.assign("aws bootstrap launch template default version missing"_ctv);
        co_return false;
      }

      launchTemplateVersion = defaultVersionNumber;
    }
    else if (launchTemplateVersion == "$Latest"_ctv)
    {
      if (latestVersionNumber.size() == 0)
      {
        failure.assign("aws bootstrap launch template latest version missing"_ctv);
        co_return false;
      }

      launchTemplateVersion = latestVersionNumber;
    }

    failure.clear();
    co_return true;
  }

  bool configuredInstanceProfileName(String& name, String& failure) const
  {
    name = runtimeEnvironment.aws.instanceProfileName;
    if (name.size() > 0)
    {
      failure.clear();
      return true;
    }

    const String& arn = runtimeEnvironment.aws.instanceProfileArn;
    int64_t slash = arn.rfindChar('/');
    if (slash >= 0 && uint64_t(slash + 1) < arn.size())
    {
      name.assign(arn.substr(uint64_t(slash + 1), arn.size() - uint64_t(slash + 1), Copy::yes));
      failure.clear();
      return true;
    }

    failure.assign("aws preflight requires aws.instanceProfileName or aws.instanceProfileArn so created brains can use IMDS"_ctv);
    return false;
  }

  ProdigyHostTask<bool> requireInstanceProfile(CoroutineStack *coro, String& failure)
  {
    String name = {};
    if (configuredInstanceProfileName(name, failure) == false)
    {
      co_return false;
    }

    bool first = true;
    String body = {};
    awsAppendQueryParam(body, "Action"_ctv, "GetInstanceProfile"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2010-05-08"_ctv, first);
    awsAppendQueryParam(body, "InstanceProfileName"_ctv, name, first);

    String response = {};
    if (co_await iamRequest(coro, body, response, failure) == false)
    {
      String detail = failure;
      failure.assign("aws instance profile preflight failed: "_ctv);
      failure.append(detail);
      co_return false;
    }

    failure.clear();
    co_return true;
  }

  ProdigyHostTask<bool> dryRunEC2(CoroutineStack *coro, String body, const char *label, String& failure)
  {
    bool first = body.size() == 0;
    awsAppendQueryParam(body, "DryRun"_ctv, "true"_ctv, first);

    String response = {};
    String detail = {};
    if (co_await request(coro, body, response, detail) == false)
    {
      if (awsIsDryRunSuccessFailure(detail))
      {
        failure.clear();
        co_return true;
      }

      failure.assign("aws "_ctv);
      failure.append(label);
      failure.append(" preflight failed: "_ctv);
      failure.append(detail.size() ? detail : String("unknown failure"_ctv));
      co_return false;
    }

    failure.assign("aws "_ctv);
    failure.append(label);
    failure.append(" preflight unexpectedly succeeded with DryRun=true"_ctv);
    co_return false;
  }

  void appendLaunchTemplatePreflightData(String& body, const String& imageID, const String& instanceType, bool& first)
  {
    awsAppendQueryParam(body, "LaunchTemplateData.ImageId"_ctv, imageID, first);
    awsAppendQueryParam(body, "LaunchTemplateData.InstanceType"_ctv, instanceType, first);
    awsAppendInstanceProfile(
        body,
        "LaunchTemplateData.IamInstanceProfile"_ctv,
        runtimeEnvironment.aws.instanceProfileName,
        runtimeEnvironment.aws.instanceProfileArn,
        first);
  }

  ProdigyHostTask<bool> dryRunLaunchTemplateCreate(CoroutineStack *coro, const MachineConfig& config, const String& imageID, String& failure)
  {
    bool first = true;
    String body = {};
    awsAppendQueryParam(body, "Action"_ctv, "CreateLaunchTemplate"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "LaunchTemplateName"_ctv, "prodigy-preflight"_ctv, first);
    awsAppendQueryParam(body, "VersionDescription"_ctv, "prodigy-preflight"_ctv, first);
    appendLaunchTemplatePreflightData(body, imageID, config.providerMachineType, first);
    co_return co_await dryRunEC2(coro, body, "CreateLaunchTemplate", failure);
  }

  ProdigyHostTask<bool> dryRunLaunchTemplateUpdate(CoroutineStack *coro, const MachineConfig& config, const String& imageID, const String& launchTemplateName, String& failure)
  {
    bool first = true;
    String body = {};
    awsAppendQueryParam(body, "Action"_ctv, "CreateLaunchTemplateVersion"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "LaunchTemplateName"_ctv, launchTemplateName, first);
    awsAppendQueryParam(body, "VersionDescription"_ctv, "prodigy-preflight"_ctv, first);
    appendLaunchTemplatePreflightData(body, imageID, config.providerMachineType, first);
    if (co_await dryRunEC2(coro, body, "CreateLaunchTemplateVersion", failure) == false)
    {
      co_return false;
    }

    first = true;
    body.clear();
    awsAppendQueryParam(body, "Action"_ctv, "ModifyLaunchTemplate"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "LaunchTemplateName"_ctv, launchTemplateName, first);
    awsAppendQueryParam(body, "SetDefaultVersion"_ctv, "1"_ctv, first);
    co_return co_await dryRunEC2(coro, body, "ModifyLaunchTemplate", failure);
  }

  ProdigyHostTask<bool> dryRunRunInstances(CoroutineStack *coro, const MachineConfig& config, const String& imageID, String& failure)
  {
    bool first = true;
    String body = {};
    awsAppendQueryParam(body, "Action"_ctv, "RunInstances"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "ImageId"_ctv, imageID, first);
    awsAppendQueryParam(body, "InstanceType"_ctv, config.providerMachineType, first);
    awsAppendQueryParam(body, "MinCount"_ctv, "1"_ctv, first);
    awsAppendQueryParam(body, "MaxCount"_ctv, "1"_ctv, first);
    awsAppendQueryParam(body, "TagSpecification.1.ResourceType"_ctv, "instance"_ctv, first);
    awsAppendQueryParam(body, "TagSpecification.1.Tag.1.Key"_ctv, "app"_ctv, first);
    awsAppendQueryParam(body, "TagSpecification.1.Tag.1.Value"_ctv, "prodigy"_ctv, first);
    awsAppendInstanceProfile(body, "IamInstanceProfile"_ctv, runtimeEnvironment.aws.instanceProfileName, runtimeEnvironment.aws.instanceProfileArn, first);
    co_return co_await dryRunEC2(coro, body, "RunInstances", failure);
  }

  ProdigyHostTask<bool> dryRunTerminateInstances(CoroutineStack *coro, const String& instanceID, String& failure)
  {
    bool first = true;
    String body = {};
    awsAppendQueryParam(body, "Action"_ctv, "TerminateInstances"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "InstanceId.1"_ctv, instanceID, first);
    co_return co_await dryRunEC2(coro, body, "TerminateInstances", failure);
  }

  ProdigyHostTask<bool> dryRunDeleteLaunchTemplate(CoroutineStack *coro, const String& launchTemplateName, String& failure)
  {
    bool first = true;
    String body = {};
    awsAppendQueryParam(body, "Action"_ctv, "DeleteLaunchTemplate"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "LaunchTemplateName"_ctv, launchTemplateName, first);
    co_return co_await dryRunEC2(coro, body, "DeleteLaunchTemplate", failure);
  }

  ProdigyHostTask<bool> dryRunCreateSecurityGroup(CoroutineStack *coro, const String& vpcID, String& failure)
  {
    bool first = true;
    String body = {};
    awsAppendQueryParam(body, "Action"_ctv, "CreateSecurityGroup"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "GroupName"_ctv, "prodigy-bootstrap-ssh-preflight"_ctv, first);
    awsAppendQueryParam(body, "GroupDescription"_ctv, "Prodigy bootstrap preflight"_ctv, first);
    awsAppendQueryParam(body, "VpcId"_ctv, vpcID, first);
    co_return co_await dryRunEC2(coro, body, "CreateSecurityGroup", failure);
  }

  ProdigyHostTask<bool> dryRunAuthorizeBootstrapIngress(CoroutineStack *coro, const String& groupID, bool mesh, String& failure)
  {
    bool first = true;
    String body = {};
    awsAppendQueryParam(body, "Action"_ctv, "AuthorizeSecurityGroupIngress"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "GroupId"_ctv, groupID.size() ? groupID : String("sg-00000000000000000"_ctv), first);
    if (mesh)
    {
      awsAppendQueryParam(body, "IpPermissions.1.IpProtocol"_ctv, "-1"_ctv, first);
      awsAppendQueryParam(body, "IpPermissions.1.Groups.1.GroupId"_ctv, groupID.size() ? groupID : String("sg-00000000000000000"_ctv), first);
      co_return co_await dryRunEC2(coro, body, "AuthorizeSecurityGroupIngress(mesh)", failure);
    }

    awsAppendQueryParam(body, "IpProtocol"_ctv, "tcp"_ctv, first);
    awsAppendQueryParam(body, "FromPort"_ctv, "22"_ctv, first);
    awsAppendQueryParam(body, "ToPort"_ctv, "22"_ctv, first);
    awsAppendQueryParam(body, "CidrIp"_ctv, "0.0.0.0/0"_ctv, first);
    co_return co_await dryRunEC2(coro, body, "AuthorizeSecurityGroupIngress(ssh)", failure);
  }

  static void appendPreflightFailure(String& failures, const String& failure)
  {
    if (failure.size() == 0)
    {
      return;
    }
    if (failures.size() > 0)
    {
      failures.append("; "_ctv);
    }
    failures.append(failure);
  }

  ProdigyHostTask<bool> preflightBootstrapPlacement(CoroutineStack *coro, String& failure)
  {
    String vpcID = {};
    String subnetID = {};
    String groupID = {};
    if (co_await findDefaultVPC(coro, vpcID, failure) == false || co_await findBootstrapSubnet(coro, vpcID, subnetID, failure) == false || co_await findBootstrapSecurityGroup(coro, vpcID, groupID, failure) == false)
    {
      co_return false;
    }

    String failures = {};
    String stepFailure = {};
    if (groupID.size() == 0 && co_await dryRunCreateSecurityGroup(coro, vpcID, stepFailure) == false)
    {
      appendPreflightFailure(failures, stepFailure);
    }

    String ingressGroupID = groupID;
    if (ingressGroupID.size() == 0 && co_await findDefaultSecurityGroup(coro, vpcID, ingressGroupID, stepFailure) == false)
    {
      appendPreflightFailure(failures, stepFailure);
    }

    if (ingressGroupID.size() > 0 && co_await dryRunAuthorizeBootstrapIngress(coro, ingressGroupID, false, stepFailure) == false)
    {
      appendPreflightFailure(failures, stepFailure);
    }
    if (ingressGroupID.size() > 0 && co_await dryRunAuthorizeBootstrapIngress(coro, ingressGroupID, true, stepFailure) == false)
    {
      appendPreflightFailure(failures, stepFailure);
    }

    if (failures.size() > 0)
    {
      failure = failures;
      co_return false;
    }

    failure.clear();
    co_return true;
  }

  ProdigyHostTask<bool> terminateCreatedInstances(CoroutineStack *coro, const Vector<String>& instanceIDs)
  {
    if (instanceIDs.size() == 0)
    {
      co_return true;
    }

    bool first = true;
    String body = {};
    awsAppendQueryParam(body, "Action"_ctv, "TerminateInstances"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    for (uint32_t index = 0; index < instanceIDs.size(); ++index)
    {
      String key = {};
      key.snprintf<"InstanceId.{itoa}"_ctv>(index + 1);
      awsAppendQueryParam(body, key, instanceIDs[index], first);
    }

    String response;
    String failure;
    co_return co_await request(coro, body, response, failure);
  }

  ProdigyHostTask<bool> compensateRunInstances(CoroutineStack *coro,
                                               const String& requestBody,
                                               const String& launchToken,
                                               String& failure)
  {
    Vector<String> instanceIDs;
    auto appendID = [&](const String& instanceID) -> void {
      for (const String& existing : instanceIDs)
      {
        if (existing == instanceID)
        {
          return;
        }
      }
      instanceIDs.push_back(instanceID);
    };

    String retryResponse;
    String retryFailure;
    const bool retryAccepted = co_await request(coro, requestBody, retryResponse, retryFailure);
    if (retryAccepted)
    {
      Vector<String> retryBlocks;
      awsCollectInstanceBlocks(retryResponse, retryBlocks);
      for (const String& block : retryBlocks)
      {
        String instanceID;
        if (awsExtractXMLValue(block, "instanceId", instanceID))
        {
          appendID(instanceID);
        }
      }
    }

    bool first = true;
    String filters;
    awsAppendQueryParam(filters, "Filter.1.Name"_ctv, "tag:prodigy_launch_token"_ctv, first);
    awsAppendQueryParam(filters, "Filter.1.Value.1"_ctv, launchToken, first);
    awsAppendQueryParam(filters, "Filter.2.Name"_ctv, "instance-state-name"_ctv, first);
    awsAppendQueryParam(filters, "Filter.2.Value.1"_ctv, "pending"_ctv, first);
    awsAppendQueryParam(filters, "Filter.2.Value.2"_ctv, "running"_ctv, first);
    awsAppendQueryParam(filters, "Filter.2.Value.3"_ctv, "stopping"_ctv, first);
    awsAppendQueryParam(filters, "Filter.2.Value.4"_ctv, "stopped"_ctv, first);
    awsAppendQueryParam(filters, "Filter.2.Value.5"_ctv, "shutting-down"_ctv, first);

    AwsHttpTransport transport(providerServices.http,
                               providerServices.delay,
                               providerServices.operationDeadline);
    String inventoryFailure;
    for (uint32_t attempt = 0; attempt < 60; ++attempt)
    {
      Vector<String> blocks;
      inventoryFailure.clear();
      if (co_await describeInstances(coro, filters, blocks, inventoryFailure))
      {
        for (const String& block : blocks)
        {
          String instanceID;
          if (awsExtractXMLValue(block, "instanceId", instanceID))
          {
            appendID(instanceID);
          }
        }
        if (!instanceIDs.empty())
        {
          break;
        }
      }
      if (!co_await transport.wait(coro))
      {
        break;
      }
    }

    if (instanceIDs.empty())
    {
      if (retryAccepted)
      {
        failure.assign("aws RunInstances reconciliation returned no instances"_ctv);
      }
      else
      {
        failure.assign("aws RunInstances reconciliation inconclusive"_ctv);
      }
      if (!retryFailure.empty())
      {
        failure.append(": "_ctv);
        failure.append(retryFailure);
      }
      co_return false;
    }
    if (!co_await terminateCreatedInstances(coro, instanceIDs))
    {
      failure.assign("aws RunInstances compensation termination failed"_ctv);
      co_return false;
    }

    first = true;
    String verificationFilters;
    for (uint32_t index = 0; index < instanceIDs.size(); ++index)
    {
      String key;
      key.snprintf<"InstanceId.{itoa}"_ctv>(index + 1);
      awsAppendQueryParam(verificationFilters, key, instanceIDs[index], first);
    }
    for (uint32_t attempt = 0; attempt < 60; ++attempt)
    {
      Vector<String> remaining;
      inventoryFailure.clear();
      if (co_await describeInstances(coro,
                                     verificationFilters,
                                     remaining,
                                     inventoryFailure) &&
          remaining.size() == instanceIDs.size())
      {
        bool terminated = true;
        for (const String& block : remaining)
        {
          String state;
          if (!awsExtractInstanceStateName(block, state) || state != "terminated"_ctv)
          {
            terminated = false;
            break;
          }
        }
        if (terminated)
        {
          failure.clear();
          co_return true;
        }
      }
      if (!co_await transport.wait(coro))
      {
        break;
      }
    }
    failure.assign("aws RunInstances compensation could not prove termination"_ctv);
    if (!inventoryFailure.empty())
    {
      failure.append(": "_ctv);
      failure.append(inventoryFailure);
    }
    co_return false;
  }

  static void appendCompensationFailure(String& operationFailure,
                                        const String& compensationFailure)
  {
    if (compensationFailure.empty())
    {
      return;
    }
    if (!operationFailure.empty())
    {
      operationFailure.append("; "_ctv);
    }
    operationFailure.append(compensationFailure);
  }

  ProdigyHostTask<bool> compensateFailedLaunch(CoroutineStack *coro,
                                               const String& requestBody,
                                               const String& launchToken,
                                               String& operationFailure)
  {
    String compensationFailure;
    if (!co_await compensateRunInstances(coro,
                                         requestBody,
                                         launchToken,
                                         compensationFailure))
    {
      appendCompensationFailure(operationFailure, compensationFailure);
      co_return false;
    }
    provisioningOperationID = 0;
    co_return true;
  }

public:

  void boot(void) override
  {
  }

  bool supportsAuthoritativeMachineSchemaCpuCapabilityInference(void) const override
  {
    return true;
  }

  void configureRuntimeEnvironment(const ProdigyRuntimeEnvironmentConfig& config) override
  {
    prodigyOwnRuntimeEnvironmentConfig(config, runtimeEnvironment);
    prodigyApplyInternalRuntimeEnvironmentDefaults(runtimeEnvironment);
    region.clear();
    credential = {};
    credentialLoaded = false;
    metadata.reset();
    provisioningOperationID = 0;
  }

  void preflightClusterCreate(CoroutineStack *coro, const BrainIaaSClusterCreatePreflight& preflight, String& error) override
  {
    (void)coro;
    error.clear();

    const MachineConfig *config = nullptr;
    for (const MachineConfig& candidate : preflight.configs)
    {
      if (candidate.kind == MachineConfig::MachineKind::vm && candidate.vmImageURI.size() > 0 && candidate.providerMachineType.size() > 0)
      {
        config = &candidate;
        break;
      }
    }

    if (config == nullptr)
    {
      error.assign("aws preflight requires a vm machine schema with vmImageURI and providerMachineType"_ctv);
      co_return;
    }

    if (co_await requireInstanceProfile(coro, error) == false)
    {
      co_return;
    }

    Vector<String> instances = {};
    co_await describeInstances(coro, ""_ctv, instances, error);
    if (error.size() > 0)
    {
      String detail = error;
      error.assign("aws DescribeInstances preflight failed: "_ctv);
      error.append(detail);
      co_return;
    }

    String failures = {};
    String stepFailure = {};
    if (co_await preflightBootstrapPlacement(coro, stepFailure) == false)
    {
      appendPreflightFailure(failures, stepFailure);
    }

    String imageID = {};
    if (co_await resolveCanonicalUbuntuImageID(coro, config->vmImageURI, imageID, error) == false)
    {
      co_return;
    }

    if (co_await dryRunLaunchTemplateCreate(coro, *config, imageID, stepFailure) == false)
    {
      appendPreflightFailure(failures, stepFailure);
    }

    String launchTemplateID = {};
    String defaultVersionNumber = {};
    String latestVersionNumber = {};
    const String& launchTemplateName = runtimeEnvironment.aws.bootstrapLaunchTemplateName;
    if (co_await describeBootstrapLaunchTemplate(coro, launchTemplateName, launchTemplateID, defaultVersionNumber, latestVersionNumber, error) == false)
    {
      co_return;
    }

    if (launchTemplateID.size() > 0 && runtimeEnvironment.aws.bootstrapLaunchTemplateVersion == "$Default"_ctv)
    {
      if (co_await dryRunLaunchTemplateUpdate(coro, *config, imageID, launchTemplateName, stepFailure) == false)
      {
        appendPreflightFailure(failures, stepFailure);
      }
    }

    if (co_await dryRunRunInstances(coro, *config, imageID, stepFailure) == false)
    {
      appendPreflightFailure(failures, stepFailure);
    }
    String existingInstanceID = {};
    for (const String& block : instances)
    {
      if (awsExtractXMLValue(block, "instanceId", existingInstanceID))
      {
        break;
      }
    }
    if (existingInstanceID.size() > 0 && co_await dryRunTerminateInstances(coro, existingInstanceID, stepFailure) == false)
    {
      appendPreflightFailure(failures, stepFailure);
    }
    if (launchTemplateID.size() > 0 && co_await dryRunDeleteLaunchTemplate(coro, launchTemplateName, stepFailure) == false)
    {
      appendPreflightFailure(failures, stepFailure);
    }

    if (failures.size() > 0)
    {
      error = failures;
      co_return;
    }

    error.clear();
  }

  void inferMachineSchemaCpuCapability(CoroutineStack *coro, const MachineConfig& config, MachineSchemaCpuCapability& capability, String& error) override
  {
    (void)coro;
    capability = {};
    error.clear();

    if (config.providerMachineType.size() == 0)
    {
      error.assign("aws schema cpu inference requires providerMachineType"_ctv);
      co_return;
    }

    if (co_await ensureRegion(coro) == false)
    {
      error.assign("aws region missing"_ctv);
      co_return;
    }

    bool first = true;
    String body = {};
    awsAppendQueryParam(body, "Action"_ctv, "DescribeInstanceTypes"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "InstanceType.1"_ctv, config.providerMachineType, first);

    Vector<String> instanceTypeBlocks = {};
    if (!co_await requestPages(coro,
                               body,
                               "instanceTypeSet",
                               "instanceTypeInfoSet",
                               instanceTypeBlocks,
                               error))
    {
      co_return;
    }

    if (instanceTypeBlocks.empty())
    {
      error.assign("aws DescribeInstanceTypes response missing instanceType block"_ctv);
      co_return;
    }

    Vector<String> architectureBlocks = {};
    awsCollectSetItemBlocks(instanceTypeBlocks[0], "supportedArchitectures", architectureBlocks);
    for (const String& architectureText : architectureBlocks)
    {
      MachineCpuArchitecture parsedArchitecture = MachineCpuArchitecture::unknown;
      String lowerArchitecture = {};
      lowercaseString(architectureText, lowerArchitecture);
      if (parseMachineCpuArchitecture(lowerArchitecture, parsedArchitecture))
      {
        capability.architecture = parsedArchitecture;
        break;
      }
    }

    if (capability.architecture == MachineCpuArchitecture::unknown)
    {
      error.assign("aws instance architecture missing or unsupported"_ctv);
      co_return;
    }

    body.clear();
    awsBuildPricingGetProductsRequestBody(
        "AmazonEC2"_ctv,
        {
            {"regionCode"_ctv,      region                    },
            {"instanceType"_ctv,    config.providerMachineType},
            {"operatingSystem"_ctv, "Linux"_ctv               },
            {"preInstalledSw"_ctv,  "NA"_ctv                  },
            {"tenancy"_ctv,         "Shared"_ctv              },
            {"capacitystatus"_ctv,  "Used"_ctv                },
    },
        body);

    String response;
    long httpCode = 0;
    if (co_await sendPricingRequest(coro, body, response, error, &httpCode) == false)
    {
      co_return;
    }

    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    if (parser.parse(response.c_str(), response.size()).get(doc))
    {
      error.assign("aws pricing response parse failed"_ctv);
      co_return;
    }

    if (doc["PriceList"].is_array() == false)
    {
      error.assign("aws pricing response missing PriceList"_ctv);
      co_return;
    }

    for (auto encodedEntry : doc["PriceList"].get_array())
    {
      std::string_view encoded = {};
      if (encodedEntry.get(encoded) != simdjson::SUCCESS || encoded.size() == 0)
      {
        continue;
      }

      String entryText = {};
      entryText.assign(encoded);
      simdjson::dom::parser entryParser;
      simdjson::dom::element entry = {};
      if (entryParser.parse(entryText.c_str(), entryText.size()).get(entry))
      {
        continue;
      }

      std::string_view instanceType = {};
      if (entry["product"]["attributes"]["instanceType"].get(instanceType) != simdjson::SUCCESS || String(instanceType) != config.providerMachineType)
      {
        continue;
      }

      std::string_view processorFeatures = {};
      if (entry["product"]["attributes"]["processorFeatures"].get(processorFeatures) == simdjson::SUCCESS)
      {
        String features = {};
        features.assign(processorFeatures);
        appendAwsProcessorFeatures(features, capability.isaFeatures);
        capability.provenance = MachineSchemaCpuCapabilityProvenance::providerAuthoritative;
      }
      else
      {
        capability.provenance = MachineSchemaCpuCapabilityProvenance::unavailable;
      }

      co_return;
    }

    capability.provenance = MachineSchemaCpuCapabilityProvenance::unavailable;
  }

  void configureBootstrapSSHAccess(const String& user, const Vault::SSHKeyPackage& keyPackage, const Vault::SSHKeyPackage& hostKeyPackage, const String& privateKeyPath) override
  {
    prodigyResolveBootstrapSSHUser(user, bootstrapSSHUser);
    bootstrapSSHPrivateKeyPath = privateKeyPath;
    bootstrapSSHPublicKey.clear();
    bootstrapSSHHostKeyPackage.clear();
    if (prodigyBootstrapSSHKeyPackageConfigured(keyPackage))
    {
      bootstrapSSHPublicKey.assign(keyPackage.publicKeyOpenSSH);
    }
    if (prodigyBootstrapSSHKeyPackageConfigured(hostKeyPackage))
    {
      bootstrapSSHHostKeyPackage = hostKeyPackage;
    }
  }

  void configureProvisioningProgressSink(BrainIaaSMachineProvisioningProgressSink *sink) override
  {
    provisioningProgress.configureSink(sink);
  }

  void configureProvisioningClusterUUID(uint128_t clusterUUID) override
  {
    provisioningClusterUUIDTagValue.clear();
    if (clusterUUID != 0)
    {
      provisioningClusterUUIDTagValue.assignItoh(clusterUUID);
    }
  }

  void configureProvisioningOperationID(uint64_t operationID) override
  {
    provisioningOperationID = operationID;
  }

  bool provisioningOperationSettled(void) override
  {
    return provisioningOperationID == 0;
  }

  bool supportsIncrementalProvisioningCallbacks() const override
  {
    return true;
  }

  void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bytell_hash_set<Machine *>& newMachines, String& error) override
  {
    (void)coro;
    provisioningProgress.reset();
    if (lifetime == MachineLifetime::owned)
    {
      error.assign("aws auto provisioning does not support MachineLifetime::owned"_ctv);
      co_return;
    }

    if (config.vmImageURI.size() == 0)
    {
      error.assign("aws vmImageURI missing"_ctv);
      co_return;
    }

    if (config.slug.size() == 0)
    {
      error.assign("aws machine schema slug missing"_ctv);
      co_return;
    }

    if (config.providerMachineType.size() == 0)
    {
      error.assign("aws providerMachineType missing"_ctv);
      co_return;
    }

    if (count == 0)
    {
      error.assign("aws RunInstances count must be positive"_ctv);
      co_return;
    }

    if (provisioningClusterUUIDTagValue.empty())
    {
      error.assign("aws provisioning cluster UUID required for launch reconciliation"_ctv);
      co_return;
    }

    if (provisioningOperationID == 0)
    {
      error.assign("aws durable provisioning operation ID required"_ctv);
      co_return;
    }

    String imageID = {};
    if (co_await resolveCanonicalUbuntuImageID(coro, config.vmImageURI, imageID, error) == false)
    {
      co_return;
    }

    String launchTemplateName = {};
    String launchTemplateVersion = {};
    if (co_await ensureBootstrapLaunchTemplate(coro, launchTemplateName, launchTemplateVersion, error) == false)
    {
      co_return;
    }

    String userData = {};
    if (bootstrapSSHPublicKey.size() > 0)
    {
      String script = {};
      prodigyBuildBootstrapSSHCloudConfig(bootstrapSSHUser, bootstrapSSHPublicKey, bootstrapSSHHostKeyPackage, script);
      Base64::encodePadded(script.data(), script.size(), userData);
    }

    Vector<String> createdInstanceIDs = {};
    Vector<String> provisionedInstanceIDs = {};
    auto provisioningAlreadyReported = [&](const String& instanceID) -> bool {
      for (const String& candidate : provisionedInstanceIDs)
      {
        if (candidate.equals(instanceID))
        {
          return true;
        }
      }

      return false;
    };
    String runInstancesBody;
    String launchToken;
    {
      bool first = true;
      String& body = runInstancesBody;
      String requestedCount = {};
      requestedCount.assignItoa(count);
      String lifetimeText;
      lifetimeText.assignItoa(uint8_t(lifetime));
      String storageText;
      storageText.assignItoa(config.nStorageMB);
      String operationIDText;
      operationIDText.assignItoa(provisioningOperationID);
      Vector<String> tokenComponents;
      tokenComponents.push_back(provisioningClusterUUIDTagValue);
      tokenComponents.push_back(config.slug);
      tokenComponents.push_back(config.providerMachineType);
      tokenComponents.push_back(imageID);
      tokenComponents.push_back(launchTemplateName);
      tokenComponents.push_back(launchTemplateVersion);
      tokenComponents.push_back(requestedCount);
      tokenComponents.push_back(lifetimeText);
      tokenComponents.push_back(storageText);
      tokenComponents.push_back(operationIDText);
      if (!AwsHttpRequest::idempotencyToken(tokenComponents, launchToken))
      {
        error.assign("aws RunInstances ClientToken generation failed"_ctv);
        co_return;
      }
      awsAppendQueryParam(body, "Action"_ctv, "RunInstances"_ctv, first);
      awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
      awsAppendQueryParam(body, "ClientToken"_ctv, launchToken, first);
      awsAppendQueryParam(body, "ImageId"_ctv, imageID, first);
      awsAppendQueryParam(body, "InstanceType"_ctv, config.providerMachineType, first);
      awsAppendQueryParam(body, "MinCount"_ctv, requestedCount, first);
      awsAppendQueryParam(body, "MaxCount"_ctv, requestedCount, first);
      awsAppendQueryParam(body, "LaunchTemplate.LaunchTemplateName"_ctv, launchTemplateName, first);
      awsAppendQueryParam(body, "LaunchTemplate.Version"_ctv, launchTemplateVersion, first);
      awsAppendQueryParam(body, "TagSpecification.1.ResourceType"_ctv, "instance"_ctv, first);
      awsAppendQueryParam(body, "TagSpecification.1.Tag.1.Key"_ctv, "app"_ctv, first);
      awsAppendQueryParam(body, "TagSpecification.1.Tag.1.Value"_ctv, "prodigy"_ctv, first);
      awsAppendQueryParam(body, "TagSpecification.1.Tag.2.Key"_ctv, "prodigy_cluster_uuid"_ctv, first);
      awsAppendQueryParam(body, "TagSpecification.1.Tag.2.Value"_ctv, provisioningClusterUUIDTagValue, first);
      awsAppendQueryParam(body, "TagSpecification.1.Tag.3.Key"_ctv, "prodigy_launch_token"_ctv, first);
      awsAppendQueryParam(body, "TagSpecification.1.Tag.3.Value"_ctv, launchToken, first);
      if (userData.size() > 0)
      {
        awsAppendQueryParam(body, "UserData"_ctv, userData, first);
      }

      if (lifetime == MachineLifetime::spot)
      {
        awsAppendQueryParam(body, "InstanceMarketOptions.MarketType"_ctv, "spot"_ctv, first);
        awsAppendQueryParam(body, "InstanceMarketOptions.SpotOptions.InstanceInterruptionBehavior"_ctv, "terminate"_ctv, first);
      }

      if (config.nStorageMB > 0)
      {
        uint32_t diskGB = (config.nStorageMB + 1023) / 1024;
        if (diskGB == 0)
        {
          diskGB = 20;
        }
        String diskSize = {};
        diskSize.assignItoa(diskGB);
        awsAppendQueryParam(body, "BlockDeviceMapping.1.DeviceName"_ctv, "/dev/xvda"_ctv, first);
        awsAppendQueryParam(body, "BlockDeviceMapping.1.Ebs.VolumeSize"_ctv, diskSize, first);
        awsAppendQueryParam(body, "BlockDeviceMapping.1.Ebs.DeleteOnTermination"_ctv, "true"_ctv, first);
      }

      String response = {};
      if (co_await request(coro, body, response, error) == false)
      {
        String operationFailure = error;
        (void)co_await compensateFailedLaunch(coro, body, launchToken, operationFailure);
        error = operationFailure;
        co_return;
      }

      Vector<String> launchedInstanceBlocks = {};
      awsCollectInstanceBlocks(response, launchedInstanceBlocks);
      if (launchedInstanceBlocks.size() != count)
      {
        error.snprintf<"aws RunInstances returned {itoa} instances but {itoa} were requested"_ctv>(
            uint32_t(launchedInstanceBlocks.size()),
            count);
        String operationFailure = error;
        (void)co_await compensateFailedLaunch(coro, body, launchToken, operationFailure);
        error = operationFailure;
        co_return;
      }

      for (const String& launchedInstanceBlock : launchedInstanceBlocks)
      {
        String instanceID = {};
        if (awsExtractXMLValue(launchedInstanceBlock, "instanceId", instanceID) == false)
        {
          error.assign("aws RunInstances response missing instanceId"_ctv);
          String operationFailure = error;
          (void)co_await compensateFailedLaunch(coro, body, launchToken, operationFailure);
          error = operationFailure;
          co_return;
        }

        createdInstanceIDs.push_back(instanceID);
        MachineProvisioningProgress& progress = provisioningProgress.upsert(config.slug, config.providerMachineType, instanceID, instanceID);
        progress.status.assign("launch-submitted"_ctv);
        progress.ready = false;
        provisioningProgress.notifyMachineProvisioningAccepted(instanceID);
        provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
      }
    }

    if (createdInstanceIDs.size() == 0)
    {
      co_return;
    }

    bool first = true;
    String describeFilters = {};
    for (uint32_t index = 0; index < createdInstanceIDs.size(); ++index)
    {
      String key = {};
      key.snprintf<"InstanceId.{itoa}"_ctv>(index + 1);
      awsAppendQueryParam(describeFilters, key, createdInstanceIDs[index], first);
    }

    Vector<String> instanceBlocks;
    const MultiCurlClient::TimePoint localDeadline = MultiCurlClient::Clock::now() +
                                                     std::chrono::milliseconds(prodigyMachineProvisioningTimeoutMs);
    const MultiCurlClient::TimePoint deadline = providerServices.operationDeadline < localDeadline ?
                                                    providerServices.operationDeadline : localDeadline;
    AwsHttpTransport transport(providerServices.http, providerServices.delay, deadline);
    while (MultiCurlClient::Clock::now() < deadline)
    {
      co_await describeInstances(coro, describeFilters, instanceBlocks, error);
      if (error.size() > 0)
      {
        if (awsContainsCString(error, "InvalidInstanceID.NotFound") || awsContainsCString(error, "does not exist") || awsContainsCString(error, "do not exist"))
        {
          error.clear();
          if (!co_await transport.wait(coro,
                                       uint64_t(prodigyMachineProvisioningPollSleepMs) * 1000))
          {
            error.assign("aws instance provisioning wait canceled"_ctv);
            (void)co_await compensateFailedLaunch(
                coro, runInstancesBody, launchToken, error);
            co_return;
          }
          continue;
        }

        (void)co_await compensateFailedLaunch(
            coro, runInstancesBody, launchToken, error);
        co_return;
      }

      for (const String& instanceID : createdInstanceIDs)
      {
        MachineProvisioningProgress& progress = provisioningProgress.upsert(config.slug, config.providerMachineType, instanceID, instanceID);
        progress.status.assign("waiting-for-running"_ctv);
        progress.ready = false;
      }

      bool ready = (instanceBlocks.size() == createdInstanceIDs.size());
      if (ready)
      {
        for (const String& block : instanceBlocks)
        {
          String stateName;
          Machine *machine = buildMachineFromInstanceBlock(block);
          MachineProvisioningProgress& progress = provisioningProgress.upsert(config.slug, config.providerMachineType, machine->cloudID, machine->cloudID);
          prodigyPopulateMachineProvisioningProgressFromMachine(progress, *machine);
          bool addressesReady = prodigyMachineProvisioningReady(*machine);
          bool sshReady = addressesReady && prodigyMachineSSHSocketAcceptingConnections(*machine, 2000);
          if (awsExtractInstanceStateName(block, stateName) == false || stateName != "running"_ctv || sshReady == false)
          {
            if (stateName != "running"_ctv)
            {
              progress.status = stateName.size() > 0 ? stateName : "waiting-for-running"_ctv;
            }
            else
            {
              if (addressesReady)
              {
                progress.status.assign("waiting-for-ssh-accept"_ctv);
              }
              else
              {
                progress.status.assign("waiting-for-addresses"_ctv);
              }
            }
            progress.ready = false;
            ready = false;
          }
          else
          {
            progress.status.assign("running"_ctv);
            progress.ready = true;
            if (provisioningAlreadyReported(machine->cloudID) == false)
            {
              provisioningProgress.notifyMachineProvisioned(*machine);
              provisionedInstanceIDs.push_back(machine->cloudID);
            }
          }
          delete machine;
          if (ready == false)
          {
            break;
          }
        }
      }

      provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());

      if (ready)
      {
        provisioningProgress.emitNow();
        break;
      }

      instanceBlocks.clear();
      if (!co_await transport.wait(coro,
                                   uint64_t(prodigyMachineProvisioningPollSleepMs) * 1000))
      {
        error.assign("aws instance provisioning wait canceled"_ctv);
        (void)co_await compensateFailedLaunch(
            coro, runInstancesBody, launchToken, error);
        co_return;
      }
    }

    if (instanceBlocks.size() != createdInstanceIDs.size())
    {
      error.assign("aws instance provisioning timed out"_ctv);
      (void)co_await compensateFailedLaunch(
          coro, runInstancesBody, launchToken, error);
      co_return;
    }

    for (const String& block : instanceBlocks)
    {
      Machine *machine = buildMachineFromInstanceBlock(block);
      machine->lifetime = lifetime;
      newMachines.insert(machine);
    }
    provisioningOperationID = 0;
  }

  void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines, String& failure) override
  {
    (void)coro;
    failure.clear();
    if (metro.size() > 0 && co_await ensureRegion(coro) && metro != region)
    {
      co_return;
    }

    bool first = true;
    String filters = {};
    awsAppendQueryParam(filters, "Filter.1.Name"_ctv, "tag:app"_ctv, first);
    awsAppendQueryParam(filters, "Filter.1.Value.1"_ctv, "prodigy"_ctv, first);
    awsAppendQueryParam(filters, "Filter.2.Name"_ctv, "instance-state-name"_ctv, first);
    awsAppendQueryParam(filters, "Filter.2.Value.1"_ctv, "pending"_ctv, first);
    awsAppendQueryParam(filters, "Filter.2.Value.2"_ctv, "running"_ctv, first);
    awsAppendQueryParam(filters, "Filter.2.Value.3"_ctv, "stopping"_ctv, first);
    awsAppendQueryParam(filters, "Filter.2.Value.4"_ctv, "stopped"_ctv, first);

    Vector<String> instanceBlocks;
    co_await describeInstances(coro, filters, instanceBlocks, failure);
    if (failure.size() > 0)
    {
      co_return;
    }

    for (const String& block : instanceBlocks)
    {
      machines.insert(buildMachineFromInstanceBlock(block));
    }
  }

  void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains, String& failure) override
  {
    (void)coro;
    selfIsBrain = false;
    failure.clear();

    bool first = true;
    String filters = {};
    awsAppendQueryParam(filters, "Filter.1.Name"_ctv, "tag:brain"_ctv, first);
    awsAppendQueryParam(filters, "Filter.1.Value.1"_ctv, "true"_ctv, first);
    awsAppendQueryParam(filters, "Filter.1.Value.2"_ctv, "1"_ctv, first);

    Vector<String> instanceBlocks;
    co_await describeInstances(coro, filters, instanceBlocks, failure);
    if (failure.size() > 0)
    {
      co_return;
    }

    for (const String& block : instanceBlocks)
    {
      Machine *machine = buildMachineFromInstanceBlock(block);
      if (machine->uuid == selfUUID)
      {
        selfIsBrain = true;
        delete machine;
        continue;
      }

      BrainView *brain = new BrainView();
      brain->uuid = machine->uuid;
      brain->private4 = machine->private4;
      (void)prodigyResolveMachinePeerAddress(*machine, brain->peerAddress, &brain->peerAddressText);
      brain->connectTimeoutMs = BrainBase::controlPlaneConnectTimeoutMs();
      brain->nDefaultAttemptsBudget = BrainBase::controlPlaneConnectAttemptsBudget();
      brains.insert(brain);
      delete machine;
    }
  }

  void hardRebootMachine(CoroutineStack *coro, const String& cloudID, String& failure) override
  {
    (void)coro;
    failure.clear();
    if (cloudID.size() == 0)
    {
      failure.assign("aws machine cloudID required"_ctv);
      co_return;
    }

    bool first = true;
    String body = {};
    awsAppendQueryParam(body, "Action"_ctv, "RebootInstances"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "InstanceId.1"_ctv, cloudID, first);
    String response;
    (void)co_await request(coro, body, response, failure);
  }

  void reportHardwareFailure(uint128_t uuid, const String& report) override
  {
    (void)uuid;
    (void)report;
  }

  void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) override
  {
    (void)coro;

    bool first = true;
    String filters = {};
    awsAppendQueryParam(filters, "Filter.1.Name"_ctv, "tag:app"_ctv, first);
    awsAppendQueryParam(filters, "Filter.1.Value.1"_ctv, "prodigy"_ctv, first);
    awsAppendQueryParam(filters, "Filter.2.Name"_ctv, "instance-lifecycle"_ctv, first);
    awsAppendQueryParam(filters, "Filter.2.Value.1"_ctv, "spot"_ctv, first);
    awsAppendQueryParam(filters, "Filter.3.Name"_ctv, "instance-state-name"_ctv, first);
    awsAppendQueryParam(filters, "Filter.3.Value.1"_ctv, "shutting-down"_ctv, first);
    awsAppendQueryParam(filters, "Filter.3.Value.2"_ctv, "terminated"_ctv, first);

    Vector<String> instanceBlocks;
    String failure;
    co_await describeInstances(coro, filters, instanceBlocks, failure);
    if (failure.size() > 0)
    {
      co_return;
    }

    for (const String& block : instanceBlocks)
    {
      String instanceID;
      if (awsExtractXMLValue(block, "instanceId", instanceID))
      {
        decommissionedIDs.push_back(instanceID);
      }
    }
  }

  void destroyMachine(CoroutineStack *coro, const String& cloudID, String& failure) override
  {
    (void)coro;
    failure.clear();
    if (cloudID.size() == 0)
    {
      failure.assign("aws machine cloudID required"_ctv);
      co_return;
    }

    bool first = true;
    String body = {};
    awsAppendQueryParam(body, "Action"_ctv, "TerminateInstances"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "InstanceId.1"_ctv, cloudID, first);
    String response;
    if (co_await request(coro, body, response, failure) == false)
    {
      co_return;
    }

    AwsHttpTransport transport(providerServices.http,
                               providerServices.delay,
                               providerServices.operationDeadline);
    for (uint32_t attempt = 0; attempt < 30; ++attempt)
    {
      String describeFilters = {};
      bool describeFirst = true;
      awsAppendQueryParam(describeFilters, "InstanceId.1"_ctv, cloudID, describeFirst);

      Vector<String> instanceBlocks;
      co_await describeInstances(coro, describeFilters, instanceBlocks, failure);
      if (failure.size() > 0)
      {
        co_return;
      }

      if (instanceBlocks.size() == 0)
      {
        co_return;
      }

      String stateName = {};
      if (awsExtractInstanceStateName(instanceBlocks[0], stateName) && (stateName == "shutting-down"_ctv || stateName == "terminated"_ctv))
      {
        co_return;
      }

      if (!co_await transport.wait(coro, 1000 * 1000))
      {
        failure.assign("aws machine termination wait canceled"_ctv);
        co_return;
      }
    }

    failure.assign("timed out waiting for aws machine termination"_ctv);
  }

private:

  ProdigyHostTask<bool> destroyClusterMachinesInline(CoroutineStack *coro, const String& clusterUUID, uint32_t& destroyed, String& error)
  {
    destroyed = 0;
    error.clear();

    if (clusterUUID.size() == 0)
    {
      error.assign("aws clusterUUID tag value required"_ctv);
      co_return false;
    }

    bool first = true;
    String filters = {};
    awsAppendQueryParam(filters, "Filter.1.Name"_ctv, "tag:app"_ctv, first);
    awsAppendQueryParam(filters, "Filter.1.Value.1"_ctv, "prodigy"_ctv, first);
    awsAppendQueryParam(filters, "Filter.2.Name"_ctv, "tag:prodigy_cluster_uuid"_ctv, first);
    awsAppendQueryParam(filters, "Filter.2.Value.1"_ctv, clusterUUID, first);
    awsAppendQueryParam(filters, "Filter.3.Name"_ctv, "instance-state-name"_ctv, first);
    awsAppendQueryParam(filters, "Filter.3.Value.1"_ctv, "pending"_ctv, first);
    awsAppendQueryParam(filters, "Filter.3.Value.2"_ctv, "running"_ctv, first);
    awsAppendQueryParam(filters, "Filter.3.Value.3"_ctv, "stopping"_ctv, first);
    awsAppendQueryParam(filters, "Filter.3.Value.4"_ctv, "stopped"_ctv, first);

    Vector<String> instanceBlocks = {};
    co_await describeInstances(coro, filters, instanceBlocks, error);
    if (error.size() > 0)
    {
      co_return false;
    }

    Vector<String> cloudIDs = {};
    for (const String& block : instanceBlocks)
    {
      String instanceID = {};
      if (awsExtractXMLValue(block, "instanceId", instanceID))
      {
        cloudIDs.push_back(instanceID);
      }
    }

    if (cloudIDs.size() == 0)
    {
      co_return true;
    }

    String body = {};
    first = true;
    awsAppendQueryParam(body, "Action"_ctv, "TerminateInstances"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    for (uint32_t index = 0; index < cloudIDs.size(); ++index)
    {
      String key = {};
      key.snprintf<"InstanceId.{}"_ctv>(index + 1);
      awsAppendQueryParam(body, key, cloudIDs[index], first);
    }

    String response = {};
    if (co_await request(coro, body, response, error) == false)
    {
      co_return false;
    }
    destroyed = uint32_t(cloudIDs.size());

    String pendingFilters = {};
    first = true;
    awsAppendQueryParam(pendingFilters, "Filter.1.Name"_ctv, "tag:app"_ctv, first);
    awsAppendQueryParam(pendingFilters, "Filter.1.Value.1"_ctv, "prodigy"_ctv, first);
    awsAppendQueryParam(pendingFilters, "Filter.2.Name"_ctv, "tag:prodigy_cluster_uuid"_ctv, first);
    awsAppendQueryParam(pendingFilters, "Filter.2.Value.1"_ctv, clusterUUID, first);
    awsAppendQueryParam(pendingFilters, "Filter.3.Name"_ctv, "instance-state-name"_ctv, first);
    awsAppendQueryParam(pendingFilters, "Filter.3.Value.1"_ctv, "pending"_ctv, first);
    awsAppendQueryParam(pendingFilters, "Filter.3.Value.2"_ctv, "running"_ctv, first);
    awsAppendQueryParam(pendingFilters, "Filter.3.Value.3"_ctv, "stopping"_ctv, first);
    awsAppendQueryParam(pendingFilters, "Filter.3.Value.4"_ctv, "stopped"_ctv, first);
    awsAppendQueryParam(pendingFilters, "Filter.3.Value.5"_ctv, "shutting-down"_ctv, first);

    AwsHttpTransport transport(providerServices.http,
                               providerServices.delay,
                               providerServices.operationDeadline);
    for (uint32_t attempt = 0; attempt < 60; ++attempt)
    {
      instanceBlocks.clear();
      co_await describeInstances(coro, pendingFilters, instanceBlocks, error);
      if (error.size() > 0)
      {
        co_return false;
      }

      if (instanceBlocks.size() == 0)
      {
        co_return true;
      }

      if (!co_await transport.wait(coro, 1000 * 1000))
      {
        error.assign("aws cluster termination wait canceled"_ctv);
        co_return false;
      }
    }

    error.assign("timed out waiting for aws cluster machines to terminate"_ctv);
    co_return false;
  }

public:

  void destroyClusterMachines(CoroutineStack *coro, const String& clusterUUID, uint32_t& destroyed, String& error) override
  {
    (void)coro;
    (void)co_await destroyClusterMachinesInline(coro, clusterUUID, destroyed, error);
    co_return;
  }

  void ensureProdigyMachineTags(CoroutineStack *coro,
                                const String& clusterUUID,
                                const String& cloudID,
                                String& error) override
  {
    (void)coro;
    error.clear();

    if (cloudID.size() == 0)
    {
      error.assign("aws machine cloudID required"_ctv);
      co_return;
    }

    if (clusterUUID.size() == 0)
    {
      error.assign("aws clusterUUID tag value required"_ctv);
      co_return;
    }

    bool first = true;
    String body = {};
    awsAppendQueryParam(body, "Action"_ctv, "CreateTags"_ctv, first);
    awsAppendQueryParam(body, "Version"_ctv, "2016-11-15"_ctv, first);
    awsAppendQueryParam(body, "ResourceId.1"_ctv, cloudID, first);
    awsAppendQueryParam(body, "Tag.1.Key"_ctv, "app"_ctv, first);
    awsAppendQueryParam(body, "Tag.1.Value"_ctv, "prodigy"_ctv, first);
    awsAppendQueryParam(body, "Tag.2.Key"_ctv, "prodigy_cluster_uuid"_ctv, first);
    awsAppendQueryParam(body, "Tag.2.Value"_ctv, clusterUUID, first);

    String response = {};
    (void)co_await request(coro, body, response, error);
  }

private:

public:

  uint32_t supportedMachineKindsMask() const override
  {
    return 3u;
  }

  bool supportsAutoProvision() const override
  {
    return true;
  }
};
