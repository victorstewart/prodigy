#pragma once

#include <prodigy/iaas/iaas.h>
#include <prodigy/iaas/bootstrap.ssh.h>
#include <prodigy/brain/base.h>
#include <prodigy/brain/machine.h>
#include <prodigy/cluster.machine.helpers.h>
#include <prodigy/command.capture.h>
#include <prodigy/iaas/azure/azure.http.h>
#include <prodigy/netdev.detect.h>
#include <services/base64.h>

#include <simdjson.h>
#include <limits>
#include <cctype>
#include <cstdio>

class AzureCredentialMaterial {
public:

  String accessToken;
  String tenantID;
  String clientID;
  String clientSecret;
};

static inline void azureAppendJSONFailureSnippet(const String& json, String& failure)
{
  if (json.size() == 0)
  {
    failure.append(" responseSnippet=\"<empty>\""_ctv);
    return;
  }

  failure.append(" responseSnippet=\""_ctv);
  uint64_t limit = json.size() < 192 ? json.size() : 192;
  for (uint64_t index = 0; index < limit; ++index)
  {
    uint8_t ch = json[index];
    if (ch >= 32 && ch <= 126 && ch != '"' && ch != '\\')
    {
      failure.append(char(ch));
    }
    else if (ch == '"' || ch == '\\')
    {
      failure.append('\\');
      failure.append(char(ch));
    }
    else if (ch == '\n' || ch == '\r' || ch == '\t')
    {
      failure.append(' ');
    }
    else
    {
      failure.append('.');
    }
  }

  if (limit < json.size())
  {
    failure.append("..."_ctv);
  }

  failure.append("\""_ctv);
}

template <StringType FailurePrefix>
static inline bool azureParseJSONDocument(const String& json, simdjson::dom::parser& parser, simdjson::dom::element& doc, String *failure, FailurePrefix&& failurePrefix)
{
  simdjson::error_code error = parser.parse(json.data(), json.size(), true).get(doc);
  if (error == simdjson::SUCCESS)
  {
    if (failure)
    {
      failure->clear();
    }
    return true;
  }

  if (failure != nullptr)
  {
    failure->clear();
    String prefixText = {};
    prefixText.assign(failurePrefix);
    if (prefixText.size() > 0)
    {
      failure->assign(prefixText);
      failure->append(": "_ctv);
    }
    failure->append(simdjson::error_message(error));
    azureAppendJSONFailureSnippet(json, *failure);
  }

  return false;
}

static inline bool azureParseJSONDocument(const String& json, simdjson::dom::parser& parser, simdjson::dom::element& doc, String *failure = nullptr)
{
  return azureParseJSONDocument(json, parser, doc, failure, ""_ctv);
}

static inline bool azureParseVMListDocument(const String& json, simdjson::dom::parser& parser, simdjson::dom::element& doc, String *failure = nullptr)
{
  return azureParseJSONDocument(json, parser, doc, failure, "azure vm list json parse failed"_ctv);
}

static inline void azureBuildSafeVMNameFragment(const String& source, uint32_t maxLength, String& fragment)
{
  fragment.clear();

  bool previousWasHyphen = false;
  for (uint32_t index = 0; index < source.size() && fragment.size() < maxLength; ++index)
  {
    uint8_t raw = source[index];
    char ch = char(std::tolower(raw));
    bool keep = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9');
    if (keep)
    {
      fragment.append(ch);
      previousWasHyphen = false;
      continue;
    }

    if (previousWasHyphen || fragment.size() == 0)
    {
      continue;
    }

    fragment.append("-"_ctv);
    previousWasHyphen = true;
  }

  while (fragment.size() > 0 && fragment[fragment.size() - 1] == '-')
  {
    fragment.resize(fragment.size() - 1);
  }

  if (fragment.size() == 0)
  {
    fragment.assign("vm"_ctv);
  }
}

static inline bool parseAzureCredentialMaterial(const String& material, AzureCredentialMaterial& credential, String *failure = nullptr)
{
  credential = {};
  if (failure)
  {
    failure->clear();
  }

  if (material.size() == 0)
  {
    if (failure)
    {
      failure->assign("azure credential material required"_ctv);
    }
    return false;
  }

  if (material[0] != '{')
  {
    credential.accessToken = material;
    return true;
  }

  String materialText = {};
  materialText.assign(material);
  simdjson::dom::parser parser;
  simdjson::dom::element doc;
  if (azureParseJSONDocument(materialText, parser, doc, failure, "azure credential material json parse failed"_ctv) == false)
  {
    return false;
  }

  std::string_view accessToken;
  std::string_view tenantID;
  std::string_view clientID;
  std::string_view clientSecret;
  (void)doc["accessToken"].get(accessToken);
  if (accessToken.size() == 0)
  {
    (void)doc["access_token"].get(accessToken);
  }
  (void)doc["tenantId"].get(tenantID);
  if (tenantID.size() == 0)
  {
    (void)doc["tenant_id"].get(tenantID);
  }
  (void)doc["clientId"].get(clientID);
  if (clientID.size() == 0)
  {
    (void)doc["client_id"].get(clientID);
  }
  (void)doc["clientSecret"].get(clientSecret);
  if (clientSecret.size() == 0)
  {
    (void)doc["client_secret"].get(clientSecret);
  }

  credential.accessToken.assign(accessToken);
  credential.tenantID.assign(tenantID);
  credential.clientID.assign(clientID);
  credential.clientSecret.assign(clientSecret);

  if (credential.accessToken.size() == 0 && (credential.tenantID.size() == 0 || credential.clientID.size() == 0 || credential.clientSecret.size() == 0))
  {
    if (failure)
    {
      failure->assign("azure credential material requires access token or tenant/client/clientSecret json"_ctv);
    }
    return false;
  }

  return true;
}

static inline bool parseAzureProviderScope(const String& scope, String& subscriptionID, String& resourceGroup, String& location, String *failure = nullptr)
{
  subscriptionID.clear();
  resourceGroup.clear();
  location.clear();
  if (failure)
  {
    failure->clear();
  }

  if (scope.size() == 0)
  {
    if (failure)
    {
      failure->assign("azure providerScope required"_ctv);
    }
    return false;
  }

  String scopeText = {};
  scopeText.assign(scope);

  auto assignSegment = [&](uint64_t start, uint64_t end, String& out) -> void {
    if (end > start)
    {
      out.assign(scopeText.substr(start, end - start, Copy::yes));
    }
  };

  auto findKeySegment = [&](const char *key, String& out) -> bool {
    String keyText = {};
    keyText.snprintf<"{}/"_ctv>(String(key));
    int64_t offset = -1;
    for (uint64_t index = 0; index + keyText.size() <= scopeText.size(); ++index)
    {
      if (memcmp(scopeText.data() + index, keyText.data(), keyText.size()) == 0)
      {
        offset = int64_t(index + keyText.size());
        break;
      }
    }

    if (offset < 0)
    {
      return false;
    }

    uint64_t end = scopeText.size();
    int64_t slash = scopeText.findChar('/', uint64_t(offset));
    if (slash >= 0)
    {
      end = uint64_t(slash);
    }

    assignSegment(uint64_t(offset), end, out);
    return out.size() > 0;
  };

  bool hasStructured =
      findKeySegment("subscriptions", subscriptionID) && findKeySegment("resourceGroups", resourceGroup);

  if (hasStructured)
  {
    if (findKeySegment("locations", location) == false)
    {
      int64_t lastSlash = scopeText.rfindChar('/');
      if (lastSlash >= 0 && uint64_t(lastSlash + 1) < scopeText.size())
      {
        location.assign(scopeText.substr(uint64_t(lastSlash + 1), scopeText.size() - uint64_t(lastSlash + 1), Copy::yes));
      }
    }
  }
  else
  {
    Vector<String> parts;
    uint64_t start = 0;
    for (uint64_t index = 0; index <= scopeText.size(); ++index)
    {
      if (index == scopeText.size() || scopeText[index] == '/')
      {
        if (index > start)
        {
          parts.push_back(scopeText.substr(start, index - start, Copy::yes));
        }
        start = index + 1;
      }
    }

    if (parts.size() >= 3)
    {
      subscriptionID = parts[0];
      resourceGroup = parts[1];
      location = parts[2];
    }
  }

  if (subscriptionID.size() == 0 || resourceGroup.size() == 0 || location.size() == 0)
  {
    if (failure)
    {
      failure->assign("azure providerScope requires subscription/resourceGroup/location"_ctv);
    }
    return false;
  }

  return true;
}

static inline uint32_t azureHashRackIdentity(const String& value)
{
  uint32_t hash = 0;
  for (uint64_t index = 0; index < value.size(); ++index)
  {
    hash = (hash * 131u) + uint8_t(value[index]);
  }

  return hash;
}

static inline bool azureGetNestedElement(simdjson::dom::element root, std::initializer_list<std::string_view> path, simdjson::dom::element& value)
{
  value = root;
  for (std::string_view key : path)
  {
    simdjson::dom::object object = {};
    if (value.get_object().get(object) != simdjson::SUCCESS)
    {
      return false;
    }

    simdjson::dom::element next = {};
    if (object.at_key(key).get(next) != simdjson::SUCCESS)
    {
      return false;
    }

    value = next;
  }

  return true;
}

static inline bool azureExtractPrimaryZone(simdjson::dom::element vm, String& zoneText)
{
  zoneText.clear();
  simdjson::dom::element zones = {};
  if (azureGetNestedElement(vm, {"zones"}, zones) && zones.is_array())
  {
    for (auto zone : zones.get_array())
    {
      std::string_view zoneValue = {};
      if (!zone.get(zoneValue) && zoneValue.size() > 0)
      {
        zoneText.assign(zoneValue);
        return true;
      }
    }
  }

  return false;
}

static inline bool azureExtractFaultDomain(simdjson::dom::element vm, String& faultDomainText)
{
  faultDomainText.clear();

  auto assignIfPresent = [&](simdjson::dom::element value) -> bool {
    uint64_t numeric = 0;
    if (!value.get(numeric))
    {
      faultDomainText.snprintf<"{itoa}"_ctv>(numeric);
      return true;
    }

    std::string_view textual = {};
    if (!value.get(textual) && textual.size() > 0)
    {
      faultDomainText.assign(textual);
      return true;
    }

    return false;
  };

  simdjson::dom::element value = {};
  if (azureGetNestedElement(vm, {"properties", "platformFaultDomain"}, value) && assignIfPresent(value))
  {
    return true;
  }

  if (azureGetNestedElement(vm, {"properties", "instanceView", "platformFaultDomain"}, value) && assignIfPresent(value))
  {
    return true;
  }

  if (azureGetNestedElement(vm, {"properties", "extended", "instanceView", "platformFaultDomain"}, value) && assignIfPresent(value))
  {
    return true;
  }

  return false;
}

static inline uint32_t azureExtractRackUUID(simdjson::dom::element vm, const String& location, const String& zoneText)
{
  String faultDomainText = {};
  if (azureExtractFaultDomain(vm, faultDomainText))
  {
    String rackIdentity = {};
    if (zoneText.size() > 0)
    {
      rackIdentity.snprintf<"{}/zone/{}/fd/{}"_ctv>(location, zoneText, faultDomainText);
    }
    else
    {
      rackIdentity.snprintf<"{}/fd/{}"_ctv>(location, faultDomainText);
    }

    return azureHashRackIdentity(rackIdentity);
  }

  if (zoneText.size() > 0)
  {
    String rackIdentity = {};
    rackIdentity.snprintf<"{}/zone/{}"_ctv>(location, zoneText);
    return azureHashRackIdentity(rackIdentity);
  }

  if (location.size() > 0)
  {
    return azureHashRackIdentity(location);
  }

  std::string_view resourceID = {};
  if (!vm["id"].get(resourceID) && resourceID.size() > 0)
  {
    String resourceText = {};
    resourceText.assign(resourceID);
    return azureHashRackIdentity(resourceText);
  }

  return 0;
}

static inline void azureAppendPercentEncoded(String& out, const String& value)
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

static inline void azureBuildResourceSkusURL(const String& subscriptionID, const String& location, String& url)
{
  url.snprintf<"https://management.azure.com/subscriptions/{}/providers/Microsoft.Compute/skus?api-version=2021-07-01"_ctv>(subscriptionID);
  if (location.size() == 0)
  {
    return;
  }

  // The unfiltered SKU catalog is enormous. Restrict by location so
  // control-plane SKU lookups stay bounded and deterministic.
  url.append("&%24filter=location%20eq%20%27"_ctv);
  azureAppendPercentEncoded(url, location);
  url.append("%27"_ctv);
}

static inline void azureAppendFixedWidthHex(String& out, uint64_t value, uint32_t width)
{
  constexpr static char hexDigits[] = "0123456789abcdef";
  for (uint32_t index = 0; index < width; ++index)
  {
    uint32_t shift = (width - index - 1) * 4;
    out.append(hexDigits[(value >> shift) & 0xf]);
  }
}

static inline void azureRenderRandomRoleAssignmentName(String& name)
{
  name.clear();
  azureAppendFixedWidthHex(name, Random::generateNumberWithNBits<32, uint32_t>(), 8);
  name.append("-"_ctv);
  azureAppendFixedWidthHex(name, Random::generateNumberWithNBits<16, uint16_t>(), 4);
  name.append("-"_ctv);
  azureAppendFixedWidthHex(name, Random::generateNumberWithNBits<16, uint16_t>(), 4);
  name.append("-"_ctv);
  azureAppendFixedWidthHex(name, Random::generateNumberWithNBits<16, uint16_t>(), 4);
  name.append("-"_ctv);
  azureAppendFixedWidthHex(name, Random::generateNumberWithNBits<48, uint64_t>(), 12);
}

static inline int64_t azureParseRFC3339Ms(const String& value)
{
  if (value.size() < 20)
  {
    return Time::now<TimeResolution::ms>();
  }

  struct tm tmv = {};
  tmv.tm_year = (value[0] - '0') * 1000 + (value[1] - '0') * 100 + (value[2] - '0') * 10 + (value[3] - '0') - 1900;
  tmv.tm_mon = (value[5] - '0') * 10 + (value[6] - '0') - 1;
  tmv.tm_mday = (value[8] - '0') * 10 + (value[9] - '0');
  tmv.tm_hour = (value[11] - '0') * 10 + (value[12] - '0');
  tmv.tm_min = (value[14] - '0') * 10 + (value[15] - '0');
  tmv.tm_sec = (value[17] - '0') * 10 + (value[18] - '0');
  tmv.tm_isdst = 0;
#ifdef _GNU_SOURCE
  time_t secs = timegm(&tmv);
#else
  char *oldtz = getenv("TZ");
  setenv("TZ", "UTC", 1);
  tzset();
  time_t secs = mktime(&tmv);
  if (oldtz)
  {
    setenv("TZ", oldtz, 1);
  }
  else
  {
    unsetenv("TZ");
  }
  tzset();
#endif
  return int64_t(secs) * 1000LL;
}

class AzureMachineTypeResources {
public:

  uint32_t logicalCores = 0;
  uint32_t memoryMB = 0;
};

static inline bool azureCapabilityUInt32(simdjson::dom::element sku, const char *capabilityName, uint32_t& value)
{
  value = 0;
  if (capabilityName == nullptr || sku["capabilities"].is_array() == false)
  {
    return false;
  }

  for (auto capability : sku["capabilities"].get_array())
  {
    std::string_view name = {};
    std::string_view text = {};
    if (capability["name"].get(name) != simdjson::SUCCESS || capability["value"].get(text) != simdjson::SUCCESS || text.empty())
    {
      continue;
    }

    if (name != std::string_view(capabilityName))
    {
      continue;
    }

    String parsedText = {};
    parsedText.assign(text);
    char *end = nullptr;
    double parsed = std::strtod(parsedText.c_str(), &end);
    if (end == parsedText.c_str() || parsed < 0.0)
    {
      return false;
    }

    value = uint32_t(std::llround(parsed));
    return true;
  }

  return false;
}

static inline bool azureExtractMachineTypeResources(simdjson::dom::element sku, AzureMachineTypeResources& resources)
{
  resources = {};
  uint32_t memoryGB = 0;
  return azureCapabilityUInt32(sku, "vCPUs", resources.logicalCores) && azureCapabilityUInt32(sku, "MemoryGB", memoryGB) && memoryGB > 0 && (resources.memoryMB = memoryGB * 1024u, true);
}

static inline uint32_t azureExtractVMTotalStorageMB(simdjson::dom::element vm)
{
  uint64_t totalStorageGB = 0;
  if (auto osDisk = vm["properties"]["storageProfile"]["osDisk"]; osDisk.is_object())
  {
    uint64_t diskSizeGB = 0;
    if (osDisk["diskSizeGB"].get(diskSizeGB) == simdjson::SUCCESS && diskSizeGB > 0)
    {
      totalStorageGB += diskSizeGB;
    }
  }

  if (auto dataDisks = vm["properties"]["storageProfile"]["dataDisks"]; dataDisks.is_array())
  {
    for (auto dataDisk : dataDisks.get_array())
    {
      uint64_t diskSizeGB = 0;
      if (dataDisk["diskSizeGB"].get(diskSizeGB) == simdjson::SUCCESS && diskSizeGB > 0)
      {
        totalStorageGB += diskSizeGB;
      }
    }
  }

  if (totalStorageGB == 0)
  {
    return 0;
  }

  uint64_t totalStorageMB = totalStorageGB * 1024ull;
  if (totalStorageMB > UINT32_MAX)
  {
    totalStorageMB = UINT32_MAX;
  }

  return uint32_t(totalStorageMB);
}

static inline bool azureApplyMachineTypeResourcesToMachine(
    Machine& machine,
    const AzureMachineTypeResources& resources,
    simdjson::dom::element vm,
    String *failure = nullptr)
{
  if (failure)
  {
    failure->clear();
  }

  if (resources.logicalCores == 0 || resources.memoryMB == 0)
  {
    if (failure)
    {
      failure->assign("azure machine type resources missing cores or memory"_ctv);
    }
    return false;
  }

  machine.totalLogicalCores = resources.logicalCores;
  machine.totalMemoryMB = resources.memoryMB;
  machine.totalStorageMB = azureExtractVMTotalStorageMB(vm);
  if (machine.totalStorageMB == 0)
  {
    machine.totalStorageMB = 30u * 1024u;
  }

  ClusterMachineOwnership ownership = {};
  ownership.mode = ClusterMachineOwnershipMode(machine.ownershipMode);
  ownership.nLogicalCoresCap = machine.ownershipLogicalCoresCap;
  ownership.nMemoryMBCap = machine.ownershipMemoryMBCap;
  ownership.nStorageMBCap = machine.ownershipStorageMBCap;
  ownership.nLogicalCoresBasisPoints = machine.ownershipLogicalCoresBasisPoints;
  ownership.nMemoryBasisPoints = machine.ownershipMemoryBasisPoints;
  ownership.nStorageBasisPoints = machine.ownershipStorageBasisPoints;

  if (clusterMachineResolveOwnedResources(
          ownership,
          machine.totalLogicalCores,
          machine.totalMemoryMB,
          machine.totalStorageMB,
          machine.ownedLogicalCores,
          machine.ownedMemoryMB,
          machine.ownedStorageMB,
          failure) == false)
  {
    return false;
  }

  machine.nLogicalCores_available = int32_t(machine.ownedLogicalCores);
  machine.memoryMB_available = int32_t(machine.ownedMemoryMB);
  machine.storageMB_available = int32_t(machine.ownedStorageMB);
  return true;
}

class AzureNeuronIaaS : public NeuronIaaS {
public:

  void gatherSelfData(CoroutineStack *coro, uint128_t& uuid, String& metro, bool& isBrain, EthDevice& eth, IPAddress& private4) override
  {
    String deviceName;
    if (prodigyResolvePrimaryNetworkDevice(deviceName))
    {
      eth.setDevice(deviceName);
    }

    uuid = 0;
    metro.clear();
    isBrain = false;
    private4 = {};

    String metadataPath = "/metadata/instance?api-version=2021-02-01"_ctv;
    AzureHttpTransport transport(providerServices.http, providerServices.delay, providerServices.operationDeadline);
    MultiCurlClient::Result metadata = co_await transport.send(
        coro,
        AzureHttpTransport::metadataRequest(metadataPath, providerServices.operationDeadline));
    if (AzureHttpTransport::succeeded(metadata))
    {
      simdjson::dom::parser parser;
      simdjson::dom::element doc;

      if (azureParseJSONDocument(metadata.body, parser, doc))
      {
        std::string_view location;
        if (!doc["compute"]["location"].get(location))
        {
          metro.assign(location);
        }

        if (auto interfaces = doc["network"]["interface"]; interfaces.is_array())
        {
          for (auto interfaceElement : interfaces.get_array())
          {
            if (auto ipv4 = interfaceElement["ipv4"]; ipv4.is_object())
            {
              if (auto ipAddresses = ipv4["ipAddress"]; ipAddresses.is_array())
              {
                for (auto ipAddress : ipAddresses.get_array())
                {
                  std::string_view private4Text;
                  if (!ipAddress["privateIpAddress"].get(private4Text))
                  {
                    private4.is6 = false;
                    String privateText = String(private4Text);
                    (void)inet_pton(AF_INET, privateText.c_str(), &private4.v4);
                    break;
                  }
                }
              }
            }

            if (private4.isNull() == false)
            {
              break;
            }
          }
        }

        std::string_view tags;
        if (!doc["compute"]["tags"].get(tags))
        {
          isBrain = (tags.find("brain:true") != std::string_view::npos) || (tags.find("brain=1") != std::string_view::npos) || (tags.find("brain=true") != std::string_view::npos);
        }
      }
    }

    if (private4.isNull())
    {
      private4.is6 = false;
      private4.v4 = eth.getPrivate4();
    }
  }

  void gatherBGPConfig(NeuronBGPConfig& config, EthDevice& eth, const IPAddress& private4) override
  {
    (void)eth;
    (void)private4;
    config = {};
  }

};

class AzureBrainIaaS : public BrainIaaS {
private:

  ProdigyRuntimeEnvironmentConfig runtimeEnvironment;
  String subscriptionID;
  String resourceGroup;
  String location;
  AzureCredentialMaterial credential;
  bool credentialLoaded = false;
  String bearerToken;
  int64_t bearerTokenExpiryMs = 0;
  String subnetID;
  String networkSecurityGroupID;
  String bootstrapSSHUser;
  String bootstrapSSHPrivateKeyPath;
  String bootstrapSSHPublicKey;
  Vault::SSHKeyPackage bootstrapSSHHostKeyPackage;
  String provisioningClusterUUIDTagValue;
  BrainIaaSMachineProvisioningProgressReporter provisioningProgress;
  bytell_hash_map<String, AzureMachineTypeResources> machineTypeResourcesByType;

  static void lowercaseString(const String& input, String& lower)
  {
    lower.clear();
    lower.reserve(input.size());
    for (uint64_t index = 0; index < input.size(); ++index)
    {
      lower.append(char(std::tolower(unsigned(input[index]))));
    }
  }

  static bool azureCapabilityString(simdjson::dom::element sku, const char *capabilityName, String& value)
  {
    value.clear();
    if (capabilityName == nullptr || sku["capabilities"].is_array() == false)
    {
      return false;
    }

    for (auto capability : sku["capabilities"].get_array())
    {
      std::string_view name = {};
      std::string_view text = {};
      if (capability["name"].get(name) != simdjson::SUCCESS || capability["value"].get(text) != simdjson::SUCCESS)
      {
        continue;
      }

      String capabilityNameText = {};
      capabilityNameText.assign(name);
      if (capabilityNameText.equal(capabilityName, strlen(capabilityName)))
      {
        value.assign(text);
        return true;
      }
    }

    return false;
  }

  bool lookupCachedMachineTypeResources(const String& providerMachineType, AzureMachineTypeResources& resources) const
  {
    auto it = machineTypeResourcesByType.find(providerMachineType);
    if (it == machineTypeResourcesByType.end())
    {
      resources = {};
      return false;
    }

    resources = it->second;
    return true;
  }

  ProdigyHostTask<bool> resolveMachineTypeResources(CoroutineStack *coro,
                                                    const String& providerMachineType,
                                                    AzureMachineTypeResources& resources,
                                                    String& error)
  {
    error.clear();
    if (providerMachineType.size() == 0)
    {
      error.assign("azure providerMachineType missing"_ctv);
      co_return false;
    }

    if (lookupCachedMachineTypeResources(providerMachineType, resources))
    {
      co_return true;
    }

    if (ensureScope(error) == false || co_await ensureBearerToken(coro, error) == false)
    {
      co_return false;
    }

    String nextLink = {};
    azureBuildResourceSkusURL(subscriptionID, location, nextLink);
    while (nextLink.size() > 0)
    {
      String response = {};
      long httpCode = 0;
      if (co_await sendARM(coro, MultiCurlClient::Method::get, nextLink, nullptr, response, error, &httpCode) == false)
      {
        if (httpCode < 200 || httpCode >= 300)
        {
          if (parseAzureErrorMessage(response, error) == false && error.size() == 0)
          {
            error.assign("azure resource skus request failed"_ctv);
          }
        }
        co_return false;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element doc = {};
      if (azureParseJSONDocument(response, parser, doc, &error, "azure resource skus response parse failed"_ctv) == false)
      {
        co_return false;
      }

      if (doc["value"].is_array())
      {
        for (auto sku : doc["value"].get_array())
        {
          std::string_view resourceType = {};
          if (sku["resourceType"].get(resourceType) != simdjson::SUCCESS || resourceType != "virtualMachines")
          {
            continue;
          }

          std::string_view name = {};
          if (sku["name"].get(name) != simdjson::SUCCESS || String(name) != providerMachineType)
          {
            continue;
          }

          if (azureExtractMachineTypeResources(sku, resources) == false)
          {
            error.assign("azure resource sku missing vCPUs or MemoryGB capability"_ctv);
            co_return false;
          }

          machineTypeResourcesByType.insert_or_assign(providerMachineType, resources);
          co_return true;
        }
      }

      std::string_view nextLinkView = {};
      if (doc["nextLink"].get(nextLinkView) == simdjson::SUCCESS)
      {
        nextLink.assign(nextLinkView);
      }
      else
      {
        nextLink.clear();
      }
    }

    error.snprintf<"azure resource sku '{}' not found"_ctv>(providerMachineType);
    co_return false;
  }

  static bool parseAzureErrorMessage(const String& response, String& failure)
  {
    failure.clear();
    if (response.size() == 0)
    {
      return false;
    }

    String responseText = {};
    responseText.assign(response);
    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    if (azureParseJSONDocument(responseText, parser, doc) == false)
    {
      return false;
    }

    if (auto error = doc["error"]; error.is_object())
    {
      String codeText = {};
      std::string_view code = {};
      if (!error["code"].get(code) && code.size() > 0)
      {
        codeText.assign(code);
      }

      std::string_view message = {};
      if (!error["message"].get(message) && message.size() > 0)
      {
        failure.assign(message);
      }

      String detailMessage = {};
      if (auto details = error["details"]; details.is_array())
      {
        for (auto detail : details.get_array())
        {
          std::string_view candidate = {};
          if (!detail["message"].get(candidate) && candidate.size() > 0)
          {
            detailMessage.assign(candidate);
            break;
          }
        }
      }

      if (detailMessage.size() > 0 && detailMessage.equals(failure) == false)
      {
        if (failure.equal("A retryable error occurred."_ctv) || failure.size() == 0)
        {
          failure.assign(detailMessage);
        }
        else
        {
          failure.append("\n"_ctv);
          failure.append(detailMessage);
        }
      }

      if (codeText.size() > 0 && failure.size() > 0)
      {
        String enriched = {};
        enriched.snprintf<"{} [{}]"_ctv>(failure, codeText);
        failure.assign(enriched);
      }

      if (failure.size() > 0)
      {
        return true;
      }
    }

    String codeText = {};
    std::string_view code = {};
    if (!doc["error"].get(code) && code.size() > 0)
    {
      codeText.assign(code);
    }

    std::string_view description = {};
    if (!doc["error_description"].get(description) && description.size() > 0)
    {
      failure.assign(description);
    }

    if (codeText.size() > 0 && failure.size() > 0)
    {
      String enriched = {};
      enriched.snprintf<"{} [{}]"_ctv>(failure, codeText);
      failure.assign(enriched);
    }

    if (failure.size() > 0)
    {
      return true;
    }

    return false;
  }

  static bool azureStringHasContent(const String& value)
  {
    return value.size() > 0 && value[0] != '\0';
  }

  static bool azureHasPrefix(const String& value, const String& prefix)
  {
    return value.size() >= prefix.size() && memcmp(value.data(), prefix.data(), prefix.size()) == 0;
  }

  static bool azureActionPatternMatches(std::string_view patternView, const char *action)
  {
    String pattern = {};
    String lowerPattern = {};
    String actionText = {};
    String lowerAction = {};
    pattern.assign(patternView);
    actionText.assign(action);
    lowercaseString(pattern, lowerPattern);
    lowercaseString(actionText, lowerAction);

    if (lowerPattern == "*"_ctv)
    {
      return true;
    }

    int64_t star = lowerPattern.findChar('*');
    if (star >= 0)
    {
      String prefix = lowerPattern.substr(0, uint64_t(star), Copy::yes);
      String suffix = lowerPattern.substr(uint64_t(star + 1), lowerPattern.size() - uint64_t(star + 1), Copy::yes);
      return azureHasPrefix(lowerAction, prefix) && lowerAction.size() >= suffix.size() && memcmp(lowerAction.data() + lowerAction.size() - suffix.size(), suffix.data(), suffix.size()) == 0;
    }

    return lowerPattern == lowerAction;
  }

  static bool azureActionArrayMatches(simdjson::dom::element array, const char *action)
  {
    if (array.is_array() == false)
    {
      return false;
    }

    for (auto entry : array.get_array())
    {
      std::string_view pattern = {};
      if (entry.get(pattern) == simdjson::SUCCESS && azureActionPatternMatches(pattern, action))
      {
        return true;
      }
    }

    return false;
  }

  static bool azurePermissionsAllowAction(simdjson::dom::element doc, const char *action, String& failure)
  {
    if (auto values = doc["value"]; values.is_array())
    {
      for (auto permission : values.get_array())
      {
        if (azureActionArrayMatches(permission["actions"], action) && azureActionArrayMatches(permission["notActions"], action) == false)
        {
          failure.clear();
          return true;
        }
      }
    }

    failure.snprintf<"azure missing permission {}"_ctv>(String(action));
    return false;
  }

  static bool azureExtractResourceIDSegment(const String& resourceID, const char *segmentKey, String& segmentValue)
  {
    segmentValue.clear();
    if (segmentKey == nullptr)
    {
      return false;
    }

    String needle = {};
    needle.snprintf<"/{}/"_ctv>(String(segmentKey));
    int64_t offset = -1;
    for (uint64_t index = 0; index + needle.size() <= resourceID.size(); ++index)
    {
      if (memcmp(resourceID.data() + index, needle.data(), needle.size()) == 0)
      {
        offset = int64_t(index + needle.size());
        break;
      }
    }

    if (offset < 0)
    {
      return false;
    }

    uint64_t end = resourceID.size();
    int64_t slash = -1;
    for (uint64_t index = uint64_t(offset); index < resourceID.size(); ++index)
    {
      if (resourceID[index] == '/')
      {
        slash = int64_t(index);
        break;
      }
    }
    if (slash >= 0)
    {
      end = uint64_t(slash);
    }

    if (end <= uint64_t(offset))
    {
      return false;
    }

    segmentValue.assign(resourceID.substr(uint64_t(offset), end - uint64_t(offset), Copy::yes));
    return segmentValue.size() > 0;
  }

  bool ensureScope(String& failure)
  {
    if (subscriptionID.size() > 0 && resourceGroup.size() > 0 && location.size() > 0)
    {
      return true;
    }

    return parseAzureProviderScope(runtimeEnvironment.providerScope, subscriptionID, resourceGroup, location, &failure);
  }

  ProdigyHostTask<bool> ensureResourceGroup(CoroutineStack *coro, String& failure)
  {
    failure.clear();
    if (ensureScope(failure) == false)
    {
      co_return false;
    }

    String url = {};
    url.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}?api-version=2024-03-01"_ctv>(
        subscriptionID,
        resourceGroup);

    String body = {};
    body.snprintf<"{\"location\":\"{}\"}"_ctv>(location);

    String response = {};
    if (co_await sendARM(coro, MultiCurlClient::Method::put, url, &body, response, failure) == false)
    {
      co_return false;
    }

    for (uint32_t attempt = 0; attempt < 120; ++attempt)
    {
      response.clear();
      if (co_await sendARM(coro, MultiCurlClient::Method::get, url, nullptr, response, failure) == false)
      {
        co_return false;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element doc = {};
      if (azureParseJSONDocument(response, parser, doc, &failure, "azure resource group json parse failed"_ctv) == false)
      {
        co_return false;
      }

      std::string_view provisioningState = {};
      (void)doc["properties"]["provisioningState"].get(provisioningState);
      if (provisioningState.size() == 0 || provisioningState == "Succeeded")
      {
        co_return true;
      }

      if (provisioningState == "Failed")
      {
        failure.assign("azure resource group provisioning failed"_ctv);
        co_return false;
      }

      AzureHttpTransport transport(providerServices.http, providerServices.delay, providerServices.operationDeadline);
      if (co_await transport.wait(coro) == false)
      {
        failure.assign("azure resource group wait canceled"_ctv);
        co_return false;
      }
    }

    failure.assign("azure resource group provisioning timed out"_ctv);
    co_return false;
  }

  bool ensureCredential(String& failure)
  {
    if (credentialLoaded)
    {
      return true;
    }

    credential = {};
    if (runtimeEnvironment.providerCredentialMaterial.size() > 0)
    {
      if (parseAzureCredentialMaterial(runtimeEnvironment.providerCredentialMaterial, credential, &failure) == false)
      {
        return false;
      }
    }

    credentialLoaded = true;
    return true;
  }

  bool azureHasBootstrapAccessTokenRefreshCommand(void) const
  {
    return runtimeEnvironment.azure.bootstrapAccessTokenRefreshCommand.size() > 0;
  }

  ProdigyHostTask<bool> refreshAzureBootstrapAccessToken(CoroutineStack *coro, String& failure)
  {
    failure.clear();

    String refreshedToken = {};
    String detail = {};
    if (co_await ProdigyCommandCapture::run(coro,
                                            runtimeEnvironment.azure.bootstrapAccessTokenRefreshCommand,
                                            refreshedToken,
                                            providerServices.operationDeadline,
                                            &detail) == false)
    {
      if (runtimeEnvironment.azure.bootstrapAccessTokenRefreshFailureHint.size() > 0)
      {
        failure.assign(detail);
        if (failure.size() > 0)
        {
          failure.append("\n"_ctv);
        }
        failure.append(runtimeEnvironment.azure.bootstrapAccessTokenRefreshFailureHint);
      }
      else
      {
        failure = detail;
      }
      co_return false;
    }

    if (azureStringHasContent(refreshedToken) == false)
    {
      failure.assign("azure access token refresh returned empty output"_ctv);
      if (runtimeEnvironment.azure.bootstrapAccessTokenRefreshFailureHint.size() > 0)
      {
        failure.append("\n"_ctv);
        failure.append(runtimeEnvironment.azure.bootstrapAccessTokenRefreshFailureHint);
      }
      co_return false;
    }

    credential.accessToken = refreshedToken;
    bearerToken = refreshedToken;
    bearerTokenExpiryMs = Time::now<TimeResolution::ms>() + Time::minsToMs(50);
    co_return true;
  }

  ProdigyHostTask<bool> ensureBearerToken(CoroutineStack *coro, String& failure)
  {
    if (Time::now<TimeResolution::ms>() + 30 * 1000 < bearerTokenExpiryMs && bearerToken.size() > 0)
    {
      co_return true;
    }

    if (ensureCredential(failure) == false)
    {
      co_return false;
    }

    if (runtimeEnvironment.azure.managedIdentityResourceID.size() == 0 && azureHasBootstrapAccessTokenRefreshCommand())
    {
      co_return co_await refreshAzureBootstrapAccessToken(coro, failure);
    }

    if (credential.accessToken.size() > 0)
    {
      bearerToken = credential.accessToken;
      bearerTokenExpiryMs = std::numeric_limits<int64_t>::max();
      co_return true;
    }

    if (credential.clientID.size() > 0 && credential.clientSecret.size() > 0 && credential.tenantID.size() > 0)
    {
      String form = {};
      form.append("grant_type=client_credentials&scope="_ctv);
      azureAppendPercentEncoded(form, "https://management.azure.com/.default"_ctv);
      form.append("&client_id="_ctv);
      azureAppendPercentEncoded(form, credential.clientID);
      form.append("&client_secret="_ctv);
      azureAppendPercentEncoded(form, credential.clientSecret);

      String url = {};
      url.snprintf<"https://login.microsoftonline.com/{}/oauth2/v2.0/token"_ctv>(credential.tenantID);

      AzureHttpTransport transport(providerServices.http, providerServices.delay, providerServices.operationDeadline);
      MultiCurlClient::Request request = transport.request(MultiCurlClient::Method::post, url, "login.microsoftonline.com"_ctv, &form);
      request.headers.push_back({"Content-Type"_ctv, "application/x-www-form-urlencoded"_ctv});
      MultiCurlClient::Result result = co_await transport.send(coro, std::move(request));
      if (AzureHttpTransport::succeeded(result) == false)
      {
        failure.assign("azure aad token request failed"_ctv);
        co_return false;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (azureParseJSONDocument(result.body, parser, doc, &failure, "azure aad token json parse failed"_ctv) == false)
      {
        co_return false;
      }

      std::string_view accessToken;
      uint64_t expiresIn = 3600;
      if (doc["access_token"].get(accessToken))
      {
        failure.assign("azure aad token missing access_token"_ctv);
        co_return false;
      }
      (void)doc["expires_in"].get(expiresIn);
      bearerToken.assign(accessToken);
      bearerTokenExpiryMs = Time::now<TimeResolution::ms>() + int64_t(expiresIn) * 1000LL;
      co_return true;
    }

    String metadataPath = {};
    metadataPath.assign("/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F"_ctv);
    if (runtimeEnvironment.azure.managedIdentityResourceID.size() > 0)
    {
      metadataPath.append("&msi_res_id="_ctv);
      azureAppendPercentEncoded(metadataPath, runtimeEnvironment.azure.managedIdentityResourceID);
    }
    // Fresh user-assigned identities can lag briefly before IMDS starts
    // issuing tokens on the newly booted VM.
    int64_t deadlineMs = Time::now<TimeResolution::ms>() + 30 * 1000;
    uint32_t backoffMs = 200;
    String lastIdentityFailure = {};

    for (;;)
    {
      AzureHttpTransport transport(providerServices.http, providerServices.delay, providerServices.operationDeadline);
      MultiCurlClient::Result result = co_await transport.send(
          coro,
          AzureHttpTransport::metadataRequest(metadataPath, providerServices.operationDeadline));
      if (result.status != MultiCurlClient::Status::success)
      {
        AzureHttpTransport::assignTransportFailure(result, lastIdentityFailure);
      }
      else
      {
        simdjson::dom::parser parser;
        simdjson::dom::element doc;
        if (azureParseJSONDocument(result.body, parser, doc, &lastIdentityFailure, "azure managed identity token json parse failed"_ctv) == false)
        {
          co_return false;
        }

        std::string_view accessToken = {};
        if (result.statusCode >= 200 && result.statusCode < 300 && doc["access_token"].get(accessToken) == simdjson::SUCCESS && accessToken.size() > 0)
        {
          bearerToken.assign(accessToken);

          uint64_t expiresInSeconds = 3600;
          std::string_view expiresIn = {};
          if (doc["expires_in"].get(expiresIn) == simdjson::SUCCESS && expiresIn.size() > 0)
          {
            String expiresInText = {};
            expiresInText.assign(expiresIn);
            char *tail = nullptr;
            unsigned long long parsed = std::strtoull(expiresInText.c_str(), &tail, 10);
            if (tail != nullptr && *tail == '\0')
            {
              expiresInSeconds = uint64_t(parsed);
            }
          }

          bearerTokenExpiryMs = Time::now<TimeResolution::ms>() + int64_t(expiresInSeconds) * 1000LL;
          co_return true;
        }

        lastIdentityFailure.clear();
        if (parseAzureErrorMessage(result.body, lastIdentityFailure) == false)
        {
          lastIdentityFailure.assign("azure managed identity token missing access_token"_ctv);
        }

        if (result.statusCode > 0)
        {
          lastIdentityFailure.snprintf_add<" [http={itoa}]"_ctv>(uint32_t(result.statusCode));
        }
      }

      if (Time::now<TimeResolution::ms>() >= deadlineMs)
      {
        failure.assign(lastIdentityFailure);
        co_return false;
      }

      AzureHttpTransport waitTransport(providerServices.http, providerServices.delay, providerServices.operationDeadline);
      if (co_await waitTransport.wait(coro, uint64_t(backoffMs) * 1000) == false)
      {
        failure.assign(lastIdentityFailure);
        co_return false;
      }
      if (backoffMs < 2000)
      {
        backoffMs = std::min<uint32_t>(backoffMs * 2, 2000);
      }
    }
  }

  void buildAuthHeaders(MultiCurlClient::Request& request)
  {
    request.headers.push_back({"Content-Type"_ctv, "application/json"_ctv});
    String auth = {};
    auth.snprintf<"Bearer {}"_ctv>(bearerToken);
    request.headers.push_back({"Authorization"_ctv, std::move(auth)});
  }

  class PendingMachineProvisioning {
  public:

    String vmName = {};
    String providerMachineType = {};
    bool ready = false;
  };

protected:

  virtual ProdigyHostTask<bool> sendARMRaw(CoroutineStack *coro,
                                          MultiCurlClient::Method method,
                                          const String& url,
                                          const String *body,
                                          String& response,
                                          long *httpCode,
                                          String& failure)
  {
    if (co_await ensureBearerToken(coro, failure) == false)
    {
      if (httpCode)
      {
        *httpCode = 0;
      }
      co_return false;
    }

    AzureHttpTransport transport(providerServices.http, providerServices.delay, providerServices.operationDeadline);
    MultiCurlClient::Request request = transport.request(method, url, "management.azure.com"_ctv, body);
    buildAuthHeaders(request);
    MultiCurlClient::Result result = co_await transport.send(coro, std::move(request));
    response = std::move(result.body);
    if (httpCode)
    {
      *httpCode = result.statusCode;
    }
    if (result.status != MultiCurlClient::Status::success)
    {
      AzureHttpTransport::assignTransportFailure(result, failure);
      co_return false;
    }
    failure.clear();
    co_return true;
  }

private:

  ProdigyHostTask<bool> sendARM(CoroutineStack *coro,
                               MultiCurlClient::Method method,
                               const String& url,
                               const String *body,
                               String& response,
                               String& failure,
                               long *httpCode = nullptr)
  {
    long localHTTPCode = 0;
    bool ok = co_await sendARMRaw(coro, method, url, body, response, &localHTTPCode, failure);
    if (httpCode)
    {
      *httpCode = localHTTPCode;
    }
    if (ok == false)
    {
      co_return false;
    }

    if (localHTTPCode < 200 || localHTTPCode >= 300)
    {
      if (parseAzureErrorMessage(response, failure) == false)
      {
        failure.assign("azure request failed"_ctv);
      }
      failure.snprintf_add<" [http={itoa}]"_ctv>(uint32_t(localHTTPCode));
      co_return false;
    }

    failure.clear();
    co_return true;
  }

  bool resolvePublicIPPrefixResourceID(const String& providerPool, String& prefixID, String& failure)
  {
    prefixID.clear();
    failure.clear();
    if (providerPool.size() == 0)
    {
      return true;
    }

    String directPrefix = "/subscriptions/"_ctv;
    if (azureHasPrefix(providerPool, directPrefix))
    {
      prefixID.assign(providerPool);
      return true;
    }

    if (ensureScope(failure) == false)
    {
      return false;
    }

    prefixID.snprintf<"/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/publicIPPrefixes/{}"_ctv>(
        subscriptionID,
        resourceGroup,
        providerPool);
    return true;
  }

  static bool parseAzureIPConfigurationID(const String& ipConfigurationID, String& nicID, String& ipConfigName)
  {
    nicID.clear();
    ipConfigName.clear();

    String marker = "/ipConfigurations/"_ctv;
    int64_t markerOffset = -1;
    for (uint64_t index = 0; index + marker.size() <= ipConfigurationID.size(); ++index)
    {
      if (memcmp(ipConfigurationID.data() + index, marker.data(), marker.size()) == 0)
      {
        markerOffset = int64_t(index);
        break;
      }
    }

    if (markerOffset < 0)
    {
      return false;
    }

    nicID.assign(ipConfigurationID.substr(0, uint64_t(markerOffset), Copy::yes));
    uint64_t nameStart = uint64_t(markerOffset) + marker.size();
    if (nameStart >= ipConfigurationID.size())
    {
      return false;
    }

    ipConfigName.assign(ipConfigurationID.substr(nameStart, ipConfigurationID.size() - nameStart, Copy::yes));
    return nicID.size() > 0 && ipConfigName.size() > 0;
  }

  static void appendAzureJSONStringField(String& body, const char *key, const String& value)
  {
    prodigyAppendEscapedJSONStringLiteral(body, String(key));
    body.append(":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(body, value);
  }

  ProdigyHostTask<bool> fetchPublicIPAddressByConcreteAddress(CoroutineStack *coro,
                                                              const String& requestedAddress,
                                                              String& publicIPID,
                                                              String& ipConfigurationID,
                                                              String& concreteAddress,
                                                              String& failure)
  {
    publicIPID.clear();
    ipConfigurationID.clear();
    concreteAddress.clear();
    if (ensureScope(failure) == false)
    {
      co_return false;
    }

    String url = {};
    url.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/publicIPAddresses?api-version=2024-05-01"_ctv>(
        subscriptionID,
        resourceGroup);

    String response = {};
    if (co_await sendARM(coro, MultiCurlClient::Method::get, url, nullptr, response, failure) == false)
    {
      co_return false;
    }

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    if (azureParseJSONDocument(response, parser, doc, &failure, "azure public ip list json parse failed"_ctv) == false)
    {
      co_return false;
    }

    if (auto values = doc["value"]; values.is_array())
    {
      for (auto publicIP : values.get_array())
      {
        std::string_view address = {};
        if (publicIP["properties"]["ipAddress"].get(address) || address != std::string_view(reinterpret_cast<const char *>(requestedAddress.data()), size_t(requestedAddress.size())))
        {
          continue;
        }

        std::string_view id = {};
        if (publicIP["id"].get(id))
        {
          failure.assign("azure public ip missing id"_ctv);
          co_return false;
        }

        publicIPID.assign(id);
        concreteAddress.assign(address);
        std::string_view ipConfigIDView = {};
        if (!publicIP["properties"]["ipConfiguration"]["id"].get(ipConfigIDView))
        {
          ipConfigurationID.assign(ipConfigIDView);
        }
        co_return true;
      }
    }

    failure.snprintf<"azure public ip {} not found"_ctv>(requestedAddress);
    co_return false;
  }

  ProdigyHostTask<bool> fetchMachinePrimaryNICAndConfig(CoroutineStack *coro,
                                                        const String& machineCloudID,
                                                        String& nicID,
                                                        String& ipConfigName,
                                                        String& failure)
  {
    nicID.clear();
    ipConfigName.clear();
    if (ensureScope(failure) == false)
    {
      co_return false;
    }

    if (machineCloudID.size() == 0)
    {
      failure.assign("azure machine cloudID required"_ctv);
      co_return false;
    }

    String vmURL = {};
    vmURL.snprintf<"https://management.azure.com{}?api-version=2025-04-01"_ctv>(machineCloudID);
    String vmResponse = {};
    if (co_await sendARM(coro, MultiCurlClient::Method::get, vmURL, nullptr, vmResponse, failure) == false)
    {
      co_return false;
    }

    simdjson::dom::parser vmParser;
    simdjson::dom::element vm;
    if (azureParseJSONDocument(vmResponse, vmParser, vm, &failure, "azure vm json parse failed"_ctv) == false)
    {
      co_return false;
    }

    bool foundPrimaryNic = false;
    if (auto nics = vm["properties"]["networkProfile"]["networkInterfaces"]; nics.is_array())
    {
      for (auto nic : nics.get_array())
      {
        std::string_view candidateID = {};
        if (nic["id"].get(candidateID))
        {
          continue;
        }

        bool primary = false;
        (void)nic["properties"]["primary"].get(primary);
        if (primary || foundPrimaryNic == false)
        {
          nicID.assign(candidateID);
          foundPrimaryNic = primary;
          if (primary)
          {
            break;
          }
        }
      }
    }

    if (nicID.size() == 0)
    {
      failure.assign("azure vm missing network interface id"_ctv);
      co_return false;
    }

    String nicURL = {};
    nicURL.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(nicID);
    String nicResponse = {};
    if (co_await sendARM(coro, MultiCurlClient::Method::get, nicURL, nullptr, nicResponse, failure) == false)
    {
      co_return false;
    }

    simdjson::dom::parser nicParser;
    simdjson::dom::element nic;
    if (azureParseJSONDocument(nicResponse, nicParser, nic, &failure, "azure nic json parse failed"_ctv) == false)
    {
      co_return false;
    }

    if (auto ipConfigs = nic["properties"]["ipConfigurations"]; ipConfigs.is_array())
    {
      for (auto ipConfig : ipConfigs.get_array())
      {
        std::string_view name = {};
        if (ipConfig["name"].get(name))
        {
          continue;
        }

        bool primary = false;
        (void)ipConfig["properties"]["primary"].get(primary);
        if (primary || ipConfigName.size() == 0)
        {
          ipConfigName.assign(name);
          if (primary)
          {
            break;
          }
        }
      }
    }

    if (ipConfigName.size() == 0)
    {
      failure.assign("azure nic missing ipConfiguration name"_ctv);
      co_return false;
    }

    co_return true;
  }

  ProdigyHostTask<bool> patchNICPublicIPAddress(CoroutineStack *coro,
                                                const String& nicID,
                                                const String& targetIPConfigName,
                                                const String *newPublicIPID,
                                                String& failure)
  {
    failure.clear();
    if (nicID.size() == 0 || targetIPConfigName.size() == 0)
    {
      failure.assign("azure nic patch requires nicID and ipConfiguration name"_ctv);
      co_return false;
    }

    String nicURL = {};
    nicURL.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(nicID);
    String nicResponse = {};
    if (co_await sendARM(coro, MultiCurlClient::Method::get, nicURL, nullptr, nicResponse, failure) == false)
    {
      co_return false;
    }

    simdjson::dom::parser parser;
    simdjson::dom::element nic;
    if (azureParseJSONDocument(nicResponse, parser, nic, &failure, "azure nic json parse failed"_ctv) == false)
    {
      co_return false;
    }

    String body = {};
    body.append("{\"properties\":{\"ipConfigurations\":["_ctv);

    bool firstConfig = true;
    bool matchedTarget = false;
    if (auto ipConfigs = nic["properties"]["ipConfigurations"]; ipConfigs.is_array())
    {
      for (auto ipConfig : ipConfigs.get_array())
      {
        std::string_view name = {};
        if (ipConfig["name"].get(name))
        {
          continue;
        }

        String nameText = {};
        nameText.assign(name);
        String currentPublicIPID = {};
        std::string_view currentPublicIDView = {};
        if (!ipConfig["properties"]["publicIPAddress"]["id"].get(currentPublicIDView))
        {
          currentPublicIPID.assign(currentPublicIDView);
        }

        String effectivePublicIPID = currentPublicIPID;
        if (nameText == targetIPConfigName)
        {
          matchedTarget = true;
          effectivePublicIPID.clear();
          if (newPublicIPID != nullptr)
          {
            effectivePublicIPID.assign(*newPublicIPID);
          }
        }

        if (firstConfig == false)
        {
          body.append(","_ctv);
        }
        firstConfig = false;

        body.append("{\"name\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, nameText);
        body.append(",\"properties\":{"_ctv);

        bool firstProp = true;
        auto appendComma = [&]() {
          if (firstProp == false)
          {
            body.append(","_ctv);
          }
          firstProp = false;
        };

        std::string_view subnetIDView = {};
        if (ipConfig["properties"]["subnet"]["id"].get(subnetIDView) == false)
        {
          appendComma();
          body.append("\"subnet\":{\"id\":"_ctv);
          String subnetIDText = {};
          subnetIDText.assign(subnetIDView);
          prodigyAppendEscapedJSONStringLiteral(body, subnetIDText);
          body.append("}"_ctv);
        }

        std::string_view privateIPAddress = {};
        if (!ipConfig["properties"]["privateIPAddress"].get(privateIPAddress))
        {
          appendComma();
          body.append("\"privateIPAddress\":"_ctv);
          String privateIPAddressText = {};
          privateIPAddressText.assign(privateIPAddress);
          prodigyAppendEscapedJSONStringLiteral(body, privateIPAddressText);
        }

        std::string_view allocationMethod = {};
        if (!ipConfig["properties"]["privateIPAllocationMethod"].get(allocationMethod))
        {
          appendComma();
          body.append("\"privateIPAllocationMethod\":"_ctv);
          String allocationMethodText = {};
          allocationMethodText.assign(allocationMethod);
          prodigyAppendEscapedJSONStringLiteral(body, allocationMethodText);
        }

        std::string_view ipVersion = {};
        if (!ipConfig["properties"]["privateIPAddressVersion"].get(ipVersion))
        {
          appendComma();
          body.append("\"privateIPAddressVersion\":"_ctv);
          String ipVersionText = {};
          ipVersionText.assign(ipVersion);
          prodigyAppendEscapedJSONStringLiteral(body, ipVersionText);
        }

        bool primary = false;
        if (!ipConfig["properties"]["primary"].get(primary))
        {
          appendComma();
          body.append("\"primary\":"_ctv);
          if (primary)
          {
            body.append("true"_ctv);
          }
          else
          {
            body.append("false"_ctv);
          }
        }

        if (effectivePublicIPID.size() > 0)
        {
          appendComma();
          body.append("\"publicIPAddress\":{\"id\":"_ctv);
          prodigyAppendEscapedJSONStringLiteral(body, effectivePublicIPID);
          body.append("}"_ctv);
        }

        body.append("}}"_ctv);
      }
    }

    if (matchedTarget == false)
    {
      failure.assign("azure target ipConfiguration missing"_ctv);
      co_return false;
    }

    body.append("]"_ctv);

    bool enableAcceleratedNetworking = false;
    if (!nic["properties"]["enableAcceleratedNetworking"].get(enableAcceleratedNetworking))
    {
      body.append(",\"enableAcceleratedNetworking\":"_ctv);
      if (enableAcceleratedNetworking)
      {
        body.append("true"_ctv);
      }
      else
      {
        body.append("false"_ctv);
      }
    }

    bool enableIPForwarding = false;
    if (!nic["properties"]["enableIPForwarding"].get(enableIPForwarding))
    {
      body.append(",\"enableIPForwarding\":"_ctv);
      if (enableIPForwarding)
      {
        body.append("true"_ctv);
      }
      else
      {
        body.append("false"_ctv);
      }
    }

    std::string_view networkSecurityGroupID = {};
    if (!nic["properties"]["networkSecurityGroup"]["id"].get(networkSecurityGroupID))
    {
      body.append(",\"networkSecurityGroup\":{\"id\":"_ctv);
      String networkSecurityGroupText = {};
      networkSecurityGroupText.assign(networkSecurityGroupID);
      prodigyAppendEscapedJSONStringLiteral(body, networkSecurityGroupText);
      body.append("}"_ctv);
    }

    body.append("}}"_ctv);

    String patchResponse = {};
    co_return co_await sendARM(coro, MultiCurlClient::Method::patch, nicURL, &body, patchResponse, failure);
  }

  ProdigyHostTask<bool> waitForPublicIPAddressState(CoroutineStack *coro,
                                                    const String& publicIPID,
                                                    const String& expectedIPConfigurationID,
                                                    bool expectAttached,
                                                    String *resolvedAddress,
                                                    String& failure)
  {
    failure.clear();
    if (resolvedAddress)
    {
      resolvedAddress->clear();
    }

    if (publicIPID.size() == 0)
    {
      failure.assign("azure public ip id required"_ctv);
      co_return false;
    }

    for (uint32_t attempt = 0; attempt < 60; ++attempt)
    {
      String url = {};
      url.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(publicIPID);

      String response = {};
      if (co_await sendARM(coro, MultiCurlClient::Method::get, url, nullptr, response, failure) == false)
      {
        co_return false;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (azureParseJSONDocument(response, parser, doc, &failure, "azure public ip json parse failed"_ctv) == false)
      {
        co_return false;
      }

      std::string_view address = {};
      if (!doc["properties"]["ipAddress"].get(address) && resolvedAddress != nullptr)
      {
        resolvedAddress->assign(address);
      }

      std::string_view provisioningState = {};
      (void)doc["properties"]["provisioningState"].get(provisioningState);

      String currentIPConfigurationID = {};
      std::string_view ipConfigurationIDView = {};
      if (!doc["properties"]["ipConfiguration"]["id"].get(ipConfigurationIDView))
      {
        currentIPConfigurationID.assign(ipConfigurationIDView);
      }

      bool attached = currentIPConfigurationID.size() > 0;
      bool matches = (currentIPConfigurationID == expectedIPConfigurationID);
      bool ready = (provisioningState.size() == 0 || provisioningState == "Succeeded");
      if (expectAttached)
      {
        if (ready && attached && matches && resolvedAddress != nullptr && resolvedAddress->size() > 0)
        {
          co_return true;
        }
        if (ready && attached && matches && resolvedAddress == nullptr)
        {
          co_return true;
        }
      }
      else if (ready && attached == false)
      {
        co_return true;
      }

      AzureHttpTransport transport(providerServices.http, providerServices.delay, providerServices.operationDeadline);
      if (co_await transport.wait(coro) == false)
      {
        failure.assign("azure public ip wait canceled"_ctv);
        co_return false;
      }
    }

    if (expectAttached)
    {
      failure.assign("timed out waiting for azure public ip attachment"_ctv);
    }
    else
    {
      failure.assign("timed out waiting for azure public ip detachment"_ctv);
    }
    co_return false;
  }

  ProdigyHostTask<bool> createPublicIPAddress(CoroutineStack *coro,
                                              const String& providerPool,
                                              String& publicIPID,
                                              String& concreteAddress,
                                              String& failure)
  {
    publicIPID.clear();
    concreteAddress.clear();
    if (ensureScope(failure) == false)
    {
      co_return false;
    }

    String prefixID = {};
    if (resolvePublicIPPrefixResourceID(providerPool, prefixID, failure) == false)
    {
      co_return false;
    }

    String publicIPName = {};
    publicIPName.snprintf<"ntg-pip-{itoa}"_ctv>(uint64_t(Random::generateNumberWithNBits<24, uint32_t>()));
    publicIPID.snprintf<"/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/publicIPAddresses/{}"_ctv>(
        subscriptionID,
        resourceGroup,
        publicIPName);

    String url = {};
    url.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(publicIPID);

    String body = {};
    body.append("{\"location\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(body, location);
    body.append(",\"sku\":{\"name\":\"Standard\"},\"properties\":{\"publicIPAddressVersion\":\"IPv4\",\"publicIPAllocationMethod\":\"Static\""_ctv);
    if (prefixID.size() > 0)
    {
      body.append(",\"publicIPPrefix\":{\"id\":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, prefixID);
      body.append("}"_ctv);
    }
    body.append("}}"_ctv);

    String response = {};
    if (co_await sendARM(coro, MultiCurlClient::Method::put, url, &body, response, failure) == false)
    {
      co_return false;
    }

    co_return co_await waitForPublicIPAddressState(coro, publicIPID, String(), false, &concreteAddress, failure);
  }

  ProdigyHostTask<bool> waitForNetworkSecurityGroupState(CoroutineStack *coro, const String& id, String& failure)
  {
    failure.clear();
    if (id.size() == 0)
    {
      failure.assign("azure network security group id required"_ctv);
      co_return false;
    }

    for (uint32_t attempt = 0; attempt < 60; ++attempt)
    {
      String url = {};
      url.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(id);

      String response = {};
      if (co_await sendARM(coro, MultiCurlClient::Method::get, url, nullptr, response, failure) == false)
      {
        co_return false;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element doc = {};
      if (azureParseJSONDocument(response, parser, doc, &failure, "azure network security group json parse failed"_ctv) == false)
      {
        co_return false;
      }

      std::string_view provisioningState = {};
      (void)doc["properties"]["provisioningState"].get(provisioningState);
      if (provisioningState.size() == 0 || provisioningState == "Succeeded")
      {
        co_return true;
      }

      if (provisioningState == "Failed")
      {
        failure.assign("azure network security group provisioning failed"_ctv);
        co_return false;
      }

      AzureHttpTransport transport(providerServices.http, providerServices.delay, providerServices.operationDeadline);
      if (co_await transport.wait(coro) == false)
      {
        failure.assign("azure network security group wait canceled"_ctv);
        co_return false;
      }
    }

    failure.assign("azure network security group provisioning timed out"_ctv);
    co_return false;
  }

  ProdigyHostTask<bool> ensureNetworkSecurityGroup(CoroutineStack *coro, String& failure)
  {
    if (networkSecurityGroupID.size() > 0)
    {
      co_return true;
    }

    if (ensureScope(failure) == false)
    {
      co_return false;
    }

    networkSecurityGroupID.snprintf<"/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/networkSecurityGroups/prodigy-nsg"_ctv>(
        subscriptionID,
        resourceGroup);

    String url = {};
    url.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(networkSecurityGroupID);

    String body = {};
    body.snprintf<
        "{\"location\":\"{}\",\"properties\":{\"securityRules\":[{\"name\":\"allow-ssh-inbound\",\"properties\":{\"protocol\":\"Tcp\",\"sourcePortRange\":\"*\",\"destinationPortRange\":\"22\",\"sourceAddressPrefix\":\"*\",\"destinationAddressPrefix\":\"*\",\"access\":\"Allow\",\"priority\":1000,\"direction\":\"Inbound\"}}]}}"_ctv>(location);

    String response = {};
    if (co_await sendARM(coro, MultiCurlClient::Method::put, url, &body, response, failure) == false)
    {
      co_return false;
    }

    co_return co_await waitForNetworkSecurityGroupState(coro, networkSecurityGroupID, failure);
  }

  ProdigyHostTask<bool> detachPublicIPAddressAssociation(CoroutineStack *coro,
                                                         const String& ipConfigurationID,
                                                         String& failure)
  {
    failure.clear();
    if (ipConfigurationID.size() == 0)
    {
      co_return true;
    }

    String nicID = {};
    String ipConfigName = {};
    if (parseAzureIPConfigurationID(ipConfigurationID, nicID, ipConfigName) == false)
    {
      failure.assign("azure ipConfiguration id parse failed"_ctv);
      co_return false;
    }

    co_return co_await patchNICPublicIPAddress(coro, nicID, ipConfigName, nullptr, failure);
  }

  ProdigyHostTask<bool> deletePublicIPAddressResource(CoroutineStack *coro,
                                                      const String& publicIPID,
                                                      String& failure)
  {
    failure.clear();
    if (publicIPID.size() == 0)
    {
      co_return true;
    }

    String url = {};
    url.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(publicIPID);
    String response = {};
    long httpCode = 0;
    if (co_await sendARMRaw(coro, MultiCurlClient::Method::delete_, url, nullptr, response, &httpCode, failure) == false)
    {
      co_return false;
    }

    if (httpCode == 404)
    {
      failure.clear();
      co_return true;
    }

    if (httpCode < 200 || httpCode >= 300)
    {
      if (parseAzureErrorMessage(response, failure) == false)
      {
        failure.assign("azure public ip delete failed"_ctv);
      }
      co_return false;
    }

    for (uint32_t attempt = 0; attempt < 60; ++attempt)
    {
      String getResponse = {};
      long getCode = 0;
      String transportFailure = {};
      if (co_await sendARMRaw(coro, MultiCurlClient::Method::get, url, nullptr, getResponse, &getCode, transportFailure) == false)
      {
        co_return false;
      }

      if (getCode == 404)
      {
        failure.clear();
        co_return true;
      }

      AzureHttpTransport transport(providerServices.http, providerServices.delay, providerServices.operationDeadline);
      if (co_await transport.wait(coro) == false)
      {
        failure.assign("azure public ip delete wait canceled"_ctv);
        co_return false;
      }
    }

    failure.assign("timed out waiting for azure public ip delete"_ctv);
    co_return false;
  }

  ProdigyHostTask<bool> ensureSubnet(CoroutineStack *coro, String& failure)
  {
    if (subnetID.size() > 0)
    {
      co_return true;
    }

    if (ensureScope(failure) == false)
    {
      co_return false;
    }

    String vnetName = "prodigy-vnet"_ctv;
    String subnetName = "prodigy-subnet"_ctv;
    subnetID.snprintf<"/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/virtualNetworks/{}/subnets/{}"_ctv>(subscriptionID, resourceGroup, vnetName, subnetName);

    String url = {};
    url.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/virtualNetworks/{}?api-version=2024-05-01"_ctv>(subscriptionID, resourceGroup, vnetName);

    String body = {};
    body.snprintf<
        "{\"location\":\"{}\",\"properties\":{\"addressSpace\":{\"addressPrefixes\":[\"10.250.0.0/16\"]},\"subnets\":[{\"name\":\"{}\",\"properties\":{\"addressPrefix\":\"10.250.0.0/20\"}}]}}"_ctv>(location, subnetName);

    String response = {};
    if (co_await sendARM(coro, MultiCurlClient::Method::put, url, &body, response, failure) == false)
    {
      co_return false;
    }

    for (uint32_t attempt = 0; attempt < 120; ++attempt)
    {
      response.clear();
      if (co_await sendARM(coro, MultiCurlClient::Method::get, url, nullptr, response, failure) == false)
      {
        co_return false;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element vnet = {};
      if (azureParseJSONDocument(response, parser, vnet, &failure, "azure virtual network json parse failed"_ctv) == false)
      {
        co_return false;
      }

      std::string_view provisioningState = {};
      (void)vnet["properties"]["provisioningState"].get(provisioningState);
      if (provisioningState == "Succeeded")
      {
        co_return true;
      }

      if (provisioningState == "Failed")
      {
        failure.assign("azure virtual network provisioning failed"_ctv);
        co_return false;
      }

      AzureHttpTransport transport(providerServices.http, providerServices.delay, providerServices.operationDeadline);
      if (co_await transport.wait(coro) == false)
      {
        failure.assign("azure virtual network wait canceled"_ctv);
        co_return false;
      }
    }

    failure.assign("azure virtual network provisioning timed out"_ctv);
    co_return false;
  }

  bool buildAzureImageReference(const MachineConfig& config, String& imageReferenceJSON, String& failure)
  {
    imageReferenceJSON.clear();
    if (config.vmImageURI.size() == 0)
    {
      failure.assign("azure vmImageURI missing"_ctv);
      return false;
    }

    uint32_t colonCount = 0;
    for (uint64_t index = 0; index < config.vmImageURI.size(); ++index)
    {
      if (config.vmImageURI[index] == ':')
      {
        colonCount += 1;
      }
    }

    if (colonCount == 3)
    {
      Vector<String> parts;
      uint64_t start = 0;
      for (uint64_t index = 0; index <= config.vmImageURI.size(); ++index)
      {
        if (index == config.vmImageURI.size() || config.vmImageURI[index] == ':')
        {
          parts.push_back(config.vmImageURI.substr(start, index - start, Copy::yes));
          start = index + 1;
        }
      }

      if (parts.size() != 4)
      {
        failure.assign("azure vmImageURI urn parse failed"_ctv);
        return false;
      }

      imageReferenceJSON.snprintf<"{\"publisher\":\"{}\",\"offer\":\"{}\",\"sku\":\"{}\",\"version\":\"{}\"}"_ctv>(parts[0], parts[1], parts[2], parts[3]);
      return true;
    }

    imageReferenceJSON.append("{\"id\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(imageReferenceJSON, config.vmImageURI);
    imageReferenceJSON.append("}"_ctv);
    return true;
  }

  ProdigyHostTask<bool> resolveNetworkAddresses(CoroutineStack *coro,
                                                const String& nicID,
                                                String& privateAddress,
                                                String& publicAddress,
                                                String& failure)
  {
    privateAddress.clear();
    publicAddress.clear();

    String nicURL = {};
    nicURL.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(nicID);
    String nicResponse;
    if (co_await sendARM(coro, MultiCurlClient::Method::get, nicURL, nullptr, nicResponse, failure) == false)
    {
      co_return false;
    }

    simdjson::dom::parser parser;
    simdjson::dom::element nicDoc;
    if (azureParseJSONDocument(nicResponse, parser, nicDoc, &failure, "azure nic json parse failed"_ctv) == false)
    {
      co_return false;
    }

    String publicIPID = {};
    if (auto ipConfigs = nicDoc["properties"]["ipConfigurations"]; ipConfigs.is_array())
    {
      for (auto ipConfig : ipConfigs.get_array())
      {
        std::string_view privateIP;
        if (!ipConfig["properties"]["privateIPAddress"].get(privateIP))
        {
          privateAddress.assign(privateIP);
        }

        std::string_view publicID;
        if (!ipConfig["properties"]["publicIPAddress"]["id"].get(publicID))
        {
          publicIPID.assign(publicID);
        }

        if (privateAddress.size() > 0)
        {
          break;
        }
      }
    }

    if (publicIPID.size() > 0)
    {
      String publicURL = {};
      publicURL.snprintf<"https://management.azure.com{}?api-version=2024-05-01"_ctv>(publicIPID);
      String publicResponse;
      if (co_await sendARM(coro, MultiCurlClient::Method::get, publicURL, nullptr, publicResponse, failure))
      {
        simdjson::dom::element publicDoc;
        if (azureParseJSONDocument(publicResponse, parser, publicDoc))
        {
          std::string_view publicIP;
          if (!publicDoc["properties"]["ipAddress"].get(publicIP))
          {
            publicAddress.assign(publicIP);
          }
        }
      }
    }

    co_return privateAddress.size() > 0;
  }

  ProdigyHostTask<Machine *> buildMachineFromVM(CoroutineStack *coro, simdjson::dom::element vm)
  {
    Machine *machine = new Machine();
    std::string_view resourceID;
    (void)vm["id"].get(resourceID);
    machine->cloudID.assign(resourceID);
    for (char c : resourceID)
    {
      machine->uuid = (machine->uuid * 131) + uint8_t(c);
    }

    std::string_view vmSize;
    if (!vm["properties"]["hardwareProfile"]["vmSize"].get(vmSize))
    {
      machine->type.assign(vmSize);
      machine->slug.assign(vmSize);
      AzureMachineTypeResources resources = {};
      String resourceLookupFailure = {};
      if (co_await resolveMachineTypeResources(coro, machine->type, resources, resourceLookupFailure))
      {
        String resourceFailure = {};
        if (azureApplyMachineTypeResourcesToMachine(*machine, resources, vm, &resourceFailure) == false)
        {
          std::fprintf(stderr, "prodigy azure buildMachineFromVM resource-apply-failure type=%.*s errorBytes=%zu error=%.*s\n",
                       int(machine->type.size()),
                       reinterpret_cast<const char *>(machine->type.data()),
                       size_t(resourceFailure.size()),
                       int(resourceFailure.size()),
                       resourceFailure.c_str());
          std::fflush(stderr);
        }
      }
    }

    std::string_view created;
    if (!vm["properties"]["timeCreated"].get(created))
    {
      machine->creationTimeMs = azureParseRFC3339Ms(String(created));
    }

    std::string_view loc;
    if (!vm["location"].get(loc))
    {
      machine->region.assign(loc);
    }

    String zoneText = {};
    if (azureExtractPrimaryZone(vm, zoneText))
    {
      machine->zone = zoneText;
    }
    machine->rackUUID = azureExtractRackUUID(vm, machine->region, machine->zone);

    if (auto tags = vm["tags"]; tags.is_object())
    {
      std::string_view brain;
      if (!tags["brain"].get(brain))
      {
        machine->isBrain = (brain == "1" || brain == "true");
      }
    }

    std::string_view imageID;
    if (!vm["properties"]["storageProfile"]["imageReference"]["id"].get(imageID))
    {
      machine->currentImageURI.assign(imageID);
    }

    std::string_view nicID;
    if (!vm["properties"]["networkProfile"]["networkInterfaces"].at(0)["id"].get(nicID))
    {
      String privateAddress;
      String publicAddress;
      String failure;
      if (co_await resolveNetworkAddresses(coro, String(nicID), privateAddress, publicAddress, failure))
      {
        machine->privateAddress = privateAddress;
        machine->publicAddress = publicAddress;
        machine->sshAddress = publicAddress.size() > 0 ? publicAddress : privateAddress;
        String privateText = {};
        privateText.assign(privateAddress);
        (void)inet_pton(AF_INET, privateText.c_str(), &machine->private4);
      }
    }

    if (bootstrapSSHPrivateKeyPath.size() > 0)
    {
      machine->sshUser = bootstrapSSHUser;
      machine->sshPrivateKeyPath = bootstrapSSHPrivateKeyPath;
      machine->sshHostPublicKeyOpenSSH = bootstrapSSHHostKeyPackage.publicKeyOpenSSH;
    }

    prodigyConfigureMachineNeuronEndpoint(*machine, thisNeuron);

    co_return machine;
  }

  ProdigyHostTask<bool> waitForMachines(CoroutineStack *coro,
                                        const String& schema,
                                        MachineLifetime lifetime,
                                        Vector<PendingMachineProvisioning>& pendingMachines,
                                        Vector<Machine *>& readyMachines,
                                        String& failure)
  {
    readyMachines.clear();
    uint32_t remaining = uint32_t(pendingMachines.size());
    const MultiCurlClient::TimePoint localDeadline = MultiCurlClient::Clock::now() +
                                                     std::chrono::milliseconds(prodigyMachineProvisioningTimeoutMs);
    const MultiCurlClient::TimePoint deadline = providerServices.operationDeadline < localDeadline ?
                                                    providerServices.operationDeadline : localDeadline;
    AzureHttpTransport transport(providerServices.http, providerServices.delay, deadline);
    while (remaining > 0 && MultiCurlClient::Clock::now() < deadline)
    {
      for (uint32_t waveStart = 0; waveStart < pendingMachines.size();)
      {
        Vector<MultiCurlClient::Request> requests;
        Vector<uint32_t> indices;
        for (uint32_t index = waveStart;
             index < pendingMachines.size() && requests.size() < AzureHttpTransport::maximumRequestsPerWave;
             ++index)
        {
          waveStart = index + 1;
          PendingMachineProvisioning& pending = pendingMachines[index];
          if (pending.ready)
          {
            continue;
          }
          String url = {};
          url.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}?api-version=2025-04-01"_ctv>(
              subscriptionID,
              resourceGroup,
              pending.vmName);
          MultiCurlClient::Request request = transport.request(MultiCurlClient::Method::get, url, "management.azure.com"_ctv);
          buildAuthHeaders(request);
          requests.push_back(std::move(request));
          indices.push_back(index);
        }
        if (requests.empty())
        {
          continue;
        }

        ProdigyHostHttpBatchOperation operation(providerServices.http, *coro);
        if (operation.submit(std::move(requests)) == false)
        {
          failure.assign("azure vm poll submission failed"_ctv);
          co_return false;
        }
        if (operation.mustSuspend())
        {
          co_await ProdigyHostSuspend(*coro);
        }
        Vector<MultiCurlClient::Result> results;
        if (operation.takeResults(results) == false || results.size() != indices.size())
        {
          failure.assign("azure vm poll completion mismatch"_ctv);
          co_return false;
        }

        for (uint32_t resultIndex = 0; resultIndex < results.size(); ++resultIndex)
        {
          MultiCurlClient::Result& result = results[resultIndex];
          PendingMachineProvisioning& pending = pendingMachines[indices[resultIndex]];
          if (AzureHttpTransport::succeeded(result) == false)
          {
            continue;
          }
          simdjson::dom::parser parser;
          simdjson::dom::element vm;
          if (azureParseJSONDocument(result.body, parser, vm, &failure, "azure vm json parse failed"_ctv) == false)
          {
            co_return false;
          }

          String provisioningState;
          auto parsedProvisioningState = vm["properties"]["provisioningState"].get_string();
          if (parsedProvisioningState.error() == simdjson::SUCCESS)
          {
            provisioningState.assign(parsedProvisioningState.value_unsafe());
          }
          MachineProvisioningProgress& progress = provisioningProgress.upsert(
              schema,
              pending.providerMachineType,
              pending.vmName,
              String());
          if (provisioningState == "Failed"_ctv)
          {
            progress.status.assign("Failed"_ctv);
            progress.ready = false;
            provisioningProgress.emitNow();
            failure.assign("azure vm provisioning failed"_ctv);
            co_return false;
          }

          Machine *machine = co_await buildMachineFromVM(coro, vm);
          if (machine)
          {
            progress.cloud.cloudID = machine->cloudID;
            prodigyPopulateMachineProvisioningProgressFromMachine(progress, *machine);
          }
          if (machine && provisioningState == "Succeeded"_ctv && prodigyMachineProvisioningReady(*machine))
          {
            machine->lifetime = lifetime;
            pending.ready = true;
            --remaining;
            progress.status.assign("Succeeded"_ctv);
            progress.ready = true;
            provisioningProgress.notifyMachineProvisioned(*machine);
            provisioningProgress.emitNow();
            readyMachines.push_back(machine);
          }
          else
          {
            delete machine;
            progress.status.assign(provisioningState);
            progress.ready = false;
            provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
          }
        }
      }

      if (remaining > 0 && co_await transport.wait(coro, uint64_t(prodigyMachineProvisioningPollSleepMs) * 1000) == false)
      {
        failure.assign("azure vm provisioning wait canceled"_ctv);
        co_return false;
      }
    }

    if (remaining > 0)
    {
      failure.assign("azure vm provisioning timed out"_ctv);
      co_return false;
    }
    failure.clear();
    co_return true;
  }

  ProdigyHostTask<bool> ensureVMTags(CoroutineStack *coro,
                                     const String& cloudID,
                                     const String& clusterUUID,
                                     String& failure)
  {
    failure.clear();

    if (cloudID.size() == 0)
    {
      failure.assign("azure machine cloudID required"_ctv);
      co_return false;
    }

    if (clusterUUID.size() == 0)
    {
      failure.assign("azure clusterUUID tag value required"_ctv);
      co_return false;
    }

    String url = {};
    url.snprintf<"https://management.azure.com{}?api-version=2025-04-01"_ctv>(cloudID);

    String response = {};
    if (co_await sendARM(coro, MultiCurlClient::Method::get, url, nullptr, response, failure) == false)
    {
      co_return false;
    }

    simdjson::dom::parser parser;
    simdjson::dom::element vm;
    if (azureParseJSONDocument(response, parser, vm, &failure, "azure vm json parse failed"_ctv) == false)
    {
      co_return false;
    }

    bool hasProdigyTag = false;
    bool hasClusterTag = false;
    std::string_view clusterUUIDView(reinterpret_cast<const char *>(clusterUUID.data()), size_t(clusterUUID.size()));
    if (auto tags = vm["tags"]; tags.is_object())
    {
      std::string_view appValue;
      if (!tags["app"].get(appValue) && appValue == "prodigy")
      {
        hasProdigyTag = true;
      }

      std::string_view clusterValue;
      if (!tags["prodigy_cluster_uuid"].get(clusterValue) && clusterValue == clusterUUIDView)
      {
        hasClusterTag = true;
      }
    }

    if (hasProdigyTag && hasClusterTag)
    {
      co_return true;
    }

    String body = {};
    body.append("{\"tags\":{"_ctv);

    bool first = true;
    if (auto tags = vm["tags"]; tags.is_object())
    {
      for (auto field : tags.get_object())
      {
        std::string_view key = field.key;
        if (key == "app" || key == "prodigy_cluster_uuid")
        {
          continue;
        }

        std::string_view value;
        if (field.value.get(value))
        {
          continue;
        }

        if (first == false)
        {
          body.append(","_ctv);
        }

        String keyText = {};
        keyText.assign(key.data(), key.size());
        prodigyAppendEscapedJSONStringLiteral(body, keyText);
        body.append(":"_ctv);
        String valueText = {};
        valueText.assign(value.data(), value.size());
        prodigyAppendEscapedJSONStringLiteral(body, valueText);
        first = false;
      }
    }

    if (first == false)
    {
      body.append(","_ctv);
    }
    prodigyAppendEscapedJSONStringLiteral(body, "app"_ctv);
    body.append(":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(body, "prodigy"_ctv);
    body.append(","_ctv);
    prodigyAppendEscapedJSONStringLiteral(body, "prodigy_cluster_uuid"_ctv);
    body.append(":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(body, clusterUUID);
    body.append("}}"_ctv);

    String patchResponse = {};
    co_return co_await sendARM(coro, MultiCurlClient::Method::patch, url, &body, patchResponse, failure);
  }

  void buildRoleDefinitionID(const char *roleUUID, String& roleDefinitionID)
  {
    roleDefinitionID.snprintf<
        "/subscriptions/{}/providers/Microsoft.Authorization/roleDefinitions/{}"_ctv>(
        subscriptionID,
        String(roleUUID));
  }

  ProdigyHostTask<bool> azureRoleAssignmentExists(CoroutineStack *coro,
                                                  const String& scope,
                                                  const String& principalID,
                                                  const String& roleDefinitionID,
                                                  bool& exists,
                                                  String& failure)
  {
    exists = false;
    failure.clear();

    String nextURL = {};
    nextURL.snprintf<
        "https://management.azure.com{}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"_ctv>(
        scope);

    while (nextURL.size() > 0)
    {
      String response = {};
      if (co_await sendARM(coro, MultiCurlClient::Method::get, nextURL, nullptr, response, failure) == false)
      {
        co_return false;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element doc = {};
      if (azureParseJSONDocument(response, parser, doc, &failure, "azure role assignments response parse failed"_ctv) == false)
      {
        co_return false;
      }

      if (doc["value"].is_array())
      {
        for (auto assignment : doc["value"].get_array())
        {
          std::string_view assignmentPrincipalID = {};
          std::string_view assignmentRoleDefinitionID = {};
          if (assignment["properties"]["principalId"].get(assignmentPrincipalID) == simdjson::SUCCESS && assignment["properties"]["roleDefinitionId"].get(assignmentRoleDefinitionID) == simdjson::SUCCESS && String(assignmentPrincipalID) == principalID && String(assignmentRoleDefinitionID) == roleDefinitionID)
          {
            exists = true;
            co_return true;
          }
        }
      }

      std::string_view nextLink = {};
      if (doc["nextLink"].get(nextLink) == simdjson::SUCCESS)
      {
        nextURL.assign(nextLink);
      }
      else
      {
        nextURL.clear();
      }
    }

    co_return true;
  }

  ProdigyHostTask<bool> ensureAzureRoleAssignment(CoroutineStack *coro,
                                                  const String& scope,
                                                  const String& principalID,
                                                  const char *roleUUID,
                                                  String& failure)
  {
    failure.clear();

    String roleDefinitionID = {};
    buildRoleDefinitionID(roleUUID, roleDefinitionID);

    bool exists = false;
    if (co_await azureRoleAssignmentExists(coro, scope, principalID, roleDefinitionID, exists, failure) == false)
    {
      co_return false;
    }

    if (exists)
    {
      co_return true;
    }

    String body = {};
    body.snprintf<
        "{\"properties\":{\"roleDefinitionId\":\"{}\",\"principalId\":\"{}\",\"principalType\":\"ServicePrincipal\"}}"_ctv>(
        roleDefinitionID,
        principalID);

    String lastFailure = {};
    for (uint32_t attempt = 0; attempt < 20; ++attempt)
    {
      String assignmentName = {};
      azureRenderRandomRoleAssignmentName(assignmentName);

      String url = {};
      url.snprintf<
          "https://management.azure.com{}/providers/Microsoft.Authorization/roleAssignments/{}?api-version=2022-04-01"_ctv>(
          scope,
          assignmentName);

      String response = {};
      String createFailure = {};
      if (co_await sendARM(coro, MultiCurlClient::Method::put, url, &body, response, createFailure))
      {
        failure.clear();
        co_return true;
      }

      bool nowExists = false;
      String verifyFailure = {};
      if (co_await azureRoleAssignmentExists(coro, scope, principalID, roleDefinitionID, nowExists, verifyFailure) && nowExists)
      {
        failure.clear();
        co_return true;
      }

      lastFailure = createFailure.size() > 0 ? createFailure : verifyFailure;
      if (attempt + 1 < 20)
      {
        // Fresh managed identities can lag before RBAC sees their principal.
        AzureHttpTransport transport(providerServices.http, providerServices.delay, providerServices.operationDeadline);
        if (co_await transport.wait(coro, 2 * 1000 * 1000) == false)
        {
          failure.assign(lastFailure);
          co_return false;
        }
      }
    }

    if (lastFailure.size() == 0)
    {
      lastFailure.assign("azure role assignment create failed"_ctv);
    }

    failure.assign(lastFailure);
    co_return false;
  }

public:

  ProdigyHostTask<bool> ensureManagedClusterIdentity(CoroutineStack *coro, String& failure)
  {
    failure.clear();

    if (runtimeEnvironment.azure.managedIdentityResourceID.size() == 0)
    {
      co_return true;
    }

    if (ensureScope(failure) == false)
    {
      co_return false;
    }

    if (co_await ensureResourceGroup(coro, failure) == false)
    {
      co_return false;
    }

    String identityName = {};
    if (azureExtractResourceIDSegment(runtimeEnvironment.azure.managedIdentityResourceID, "userAssignedIdentities", identityName) == false)
    {
      failure.assign("azure managed identity resource id is invalid"_ctv);
      co_return false;
    }

    String url = {};
    url.snprintf<"https://management.azure.com{}?api-version=2023-01-31"_ctv>(runtimeEnvironment.azure.managedIdentityResourceID);

    String body = {};
    body.snprintf<"{\"location\":\"{}\"}"_ctv>(location);

    String response = {};
    if (co_await sendARM(coro, MultiCurlClient::Method::put, url, &body, response, failure) == false)
    {
      co_return false;
    }

    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    if (azureParseJSONDocument(response, parser, doc, &failure, "azure managed identity response parse failed"_ctv) == false)
    {
      co_return false;
    }

    std::string_view principalIDView = {};
    if (doc["properties"]["principalId"].get(principalIDView) != simdjson::SUCCESS || principalIDView.empty())
    {
      failure.assign("azure managed identity response missing principalId"_ctv);
      co_return false;
    }

    String principalID = {};
    principalID.assign(principalIDView);

    String resourceGroupScope = {};
    resourceGroupScope.snprintf<"/subscriptions/{}/resourceGroups/{}"_ctv>(subscriptionID, resourceGroup);

    if (co_await ensureAzureRoleAssignment(coro, resourceGroupScope, principalID, "b24988ac-6180-42a0-ab88-20f7382dd24c", failure) == false)
    {
      co_return false;
    }

    if (co_await ensureAzureRoleAssignment(coro, runtimeEnvironment.azure.managedIdentityResourceID, principalID, "f1a07417-d97a-45cb-824c-7a7467783830", failure) == false)
    {
      co_return false;
    }

    co_return true;
  }

  void boot(void) override
  {
  }

  bool supportsAuthoritativeMachineSchemaCpuCapabilityInference(void) const override
  {
    return false;
  }

  void configureRuntimeEnvironment(const ProdigyRuntimeEnvironmentConfig& config) override
  {
    prodigyOwnRuntimeEnvironmentConfig(config, runtimeEnvironment);
    subscriptionID.clear();
    resourceGroup.clear();
    location.clear();
    credential = {};
    credentialLoaded = false;
    bearerToken.clear();
    bearerTokenExpiryMs = 0;
    subnetID.clear();
    networkSecurityGroupID.clear();
  }

  void preflightClusterCreate(CoroutineStack *coro, const BrainIaaSClusterCreatePreflight& preflight, String& error) override
  {
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
      error.assign("azure preflight requires a vm machine schema with vmImageURI and providerMachineType"_ctv);
      co_return;
    }

    if (preflight.azureManagedIdentityResourceID.size() == 0)
    {
      error.assign("azure preflight requires azure.managedIdentityResourceID or azure.managedIdentityName"_ctv);
      co_return;
    }

    String identityName = {};
    if (azureExtractResourceIDSegment(preflight.azureManagedIdentityResourceID, "userAssignedIdentities", identityName) == false)
    {
      error.assign("azure managed identity resource id is invalid"_ctv);
      co_return;
    }

    if (ensureScope(error) == false)
    {
      co_return;
    }

    String imageReferenceJSON = {};
    if (buildAzureImageReference(*config, imageReferenceJSON, error) == false)
    {
      co_return;
    }

    String url = {};
    url.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"_ctv>(
        subscriptionID,
        resourceGroup);

    String response = {};
    if (co_await sendARM(coro, MultiCurlClient::Method::get, url, nullptr, response, error) == false)
    {
      co_return;
    }

    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    if (azureParseJSONDocument(response, parser, doc, &error, "azure permissions response parse failed"_ctv) == false)
    {
      co_return;
    }

    constexpr static const char *required[] = {
        "Microsoft.Authorization/roleAssignments/read",
        "Microsoft.Authorization/roleAssignments/write",
        "Microsoft.Compute/skus/read",
        "Microsoft.Compute/virtualMachines/delete",
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Compute/virtualMachines/restart/action",
        "Microsoft.Compute/virtualMachines/write",
        "Microsoft.ManagedIdentity/userAssignedIdentities/read",
        "Microsoft.ManagedIdentity/userAssignedIdentities/write",
        "Microsoft.Network/networkInterfaces/delete",
        "Microsoft.Network/networkInterfaces/read",
        "Microsoft.Network/networkInterfaces/write",
        "Microsoft.Network/networkSecurityGroups/read",
        "Microsoft.Network/networkSecurityGroups/write",
        "Microsoft.Network/publicIPAddresses/delete",
        "Microsoft.Network/publicIPAddresses/read",
        "Microsoft.Network/publicIPAddresses/write",
        "Microsoft.Network/virtualNetworks/read",
        "Microsoft.Network/virtualNetworks/write",
        "Microsoft.Resources/subscriptions/resourceGroups/read",
        "Microsoft.Resources/subscriptions/resourceGroups/write",
    };
    String missing = {};
    for (uint32_t index = 0; index < sizeof(required) / sizeof(required[0]); ++index)
    {
      if (azurePermissionsAllowAction(doc, required[index], error) == false)
      {
        if (missing.size() == 0)
        {
          missing.assign("azure missing permissions: "_ctv);
        }
        else
        {
          missing.append(", "_ctv);
        }
        missing.append(String(required[index]));
      }
    }

    if (missing.size() > 0)
    {
      error = missing;
      co_return;
    }

    error.clear();
  }

  void inferMachineSchemaCpuCapability(CoroutineStack *coro, const MachineConfig& config, MachineSchemaCpuCapability& capability, String& error) override
  {
    capability = {};
    error.clear();

    if (config.providerMachineType.size() == 0)
    {
      error.assign("azure schema cpu inference requires providerMachineType"_ctv);
      co_return;
    }

    if (ensureScope(error) == false)
    {
      co_return;
    }

    String nextLink = {};
    azureBuildResourceSkusURL(subscriptionID, location, nextLink);
    while (nextLink.size() > 0)
    {
      String response = {};
      long httpCode = 0;
      if (co_await sendARM(coro, MultiCurlClient::Method::get, nextLink, nullptr, response, error, &httpCode) == false)
      {
        if (httpCode < 200 || httpCode >= 300)
        {
          if (parseAzureErrorMessage(response, error) == false && error.size() == 0)
          {
            error.assign("azure resource skus request failed"_ctv);
          }
        }
        co_return;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element doc = {};
      if (azureParseJSONDocument(response, parser, doc, &error, "azure resource skus response parse failed"_ctv) == false)
      {
        co_return;
      }

      if (doc["value"].is_array())
      {
        for (auto sku : doc["value"].get_array())
        {
          String resourceType = {};
          std::string_view resourceTypeView = {};
          if (sku["resourceType"].get(resourceTypeView) != simdjson::SUCCESS)
          {
            continue;
          }
          resourceType.assign(resourceTypeView);
          if (resourceType != "virtualMachines"_ctv)
          {
            continue;
          }

          bool locationMatch = false;
          if (sku["locations"].is_array())
          {
            for (auto locationValue : sku["locations"].get_array())
            {
              std::string_view text = {};
              if (locationValue.get(text) == simdjson::SUCCESS && String(text).equals(location))
              {
                locationMatch = true;
                break;
              }
            }
          }

          if (locationMatch == false)
          {
            continue;
          }

          String name = {};
          std::string_view nameView = {};
          if (sku["name"].get(nameView) != simdjson::SUCCESS)
          {
            continue;
          }
          name.assign(nameView);
          if (name != config.providerMachineType)
          {
            continue;
          }

          String architectureText = {};
          if (azureCapabilityString(sku, "CpuArchitectureType", architectureText) == false)
          {
            (void)azureCapabilityString(sku, "Architecture", architectureText);
          }

          if (architectureText.size() == 0)
          {
            error.assign("azure resource sku missing CpuArchitectureType capability"_ctv);
            co_return;
          }

          String lowerArchitecture = {};
          lowercaseString(architectureText, lowerArchitecture);
          if (lowerArchitecture == "arm64"_ctv)
          {
            capability.architecture = MachineCpuArchitecture::aarch64;
          }
          else if (lowerArchitecture == "x64"_ctv || lowerArchitecture == "x86_64"_ctv || lowerArchitecture == "amd64"_ctv)
          {
            capability.architecture = MachineCpuArchitecture::x86_64;
          }
          else
          {
            error.snprintf<"azure CpuArchitectureType '{}' unsupported"_ctv>(architectureText);
            co_return;
          }

          capability.provenance = MachineSchemaCpuCapabilityProvenance::unavailable;
          co_return;
        }
      }

      std::string_view nextLinkView = {};
      if (doc["nextLink"].get(nextLinkView) == simdjson::SUCCESS)
      {
        nextLink.assign(nextLinkView);
      }
      else
      {
        nextLink.clear();
      }
    }

    error.assign("azure resource sku not found"_ctv);
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

  bool supportsIncrementalProvisioningCallbacks() const override
  {
    return true;
  }

  void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bytell_hash_set<Machine *>& newMachines, String& error) override
  {
    provisioningProgress.reset();
    if (lifetime == MachineLifetime::owned)
    {
      error.assign("azure auto provisioning does not support MachineLifetime::owned"_ctv);
      co_return;
    }

    if (ensureScope(error) == false)
    {
      std::fprintf(stderr, "prodigy azure spinMachines-failure step=ensureScope schema=%.*s count=%u errorBytes=%zu error=%.*s\n",
                   int(config.slug.size()),
                   reinterpret_cast<const char *>(config.slug.data()),
                   unsigned(count),
                   size_t(error.size()),
                   int(error.size()),
                   error.c_str());
      std::fflush(stderr);
      co_return;
    }

    if (co_await ensureSubnet(coro, error) == false)
    {
      std::fprintf(stderr, "prodigy azure spinMachines-failure step=ensureSubnet schema=%.*s count=%u errorBytes=%zu error=%.*s\n",
                   int(config.slug.size()),
                   reinterpret_cast<const char *>(config.slug.data()),
                   unsigned(count),
                   size_t(error.size()),
                   int(error.size()),
                   error.c_str());
      std::fflush(stderr);
      co_return;
    }

    if (co_await ensureNetworkSecurityGroup(coro, error) == false)
    {
      std::fprintf(stderr, "prodigy azure spinMachines-failure step=ensureNetworkSecurityGroup schema=%.*s count=%u errorBytes=%zu error=%.*s\n",
                   int(config.slug.size()),
                   reinterpret_cast<const char *>(config.slug.data()),
                   unsigned(count),
                   size_t(error.size()),
                   int(error.size()),
                   error.c_str());
      std::fflush(stderr);
      co_return;
    }

    String imageReferenceJSON = {};
    if (buildAzureImageReference(config, imageReferenceJSON, error) == false)
    {
      std::fprintf(stderr, "prodigy azure spinMachines-failure step=buildAzureImageReference schema=%.*s count=%u errorBytes=%zu error=%.*s\n",
                   int(config.slug.size()),
                   reinterpret_cast<const char *>(config.slug.data()),
                   unsigned(count),
                   size_t(error.size()),
                   int(error.size()),
                   error.c_str());
      std::fflush(stderr);
      co_return;
    }

    String userData = {};
    if (bootstrapSSHPublicKey.size() > 0)
    {
      String cloudConfig = {};
      prodigyBuildBootstrapSSHCloudConfig(bootstrapSSHUser, bootstrapSSHPublicKey, bootstrapSSHHostKeyPackage, cloudConfig);
      Base64::encodePadded(cloudConfig.data(), cloudConfig.size(), userData);
    }

    class PendingCreateSubmission {
    public:

      String vmName = {};
      String providerMachineType = {};
    };

    Vector<PendingMachineProvisioning> pendingMachines = {};
    Vector<Machine *> readyMachines = {};
    Vector<PendingCreateSubmission> createRequests = {};
    Vector<MultiCurlClient::Request> requests = {};
    createRequests.reserve(count);
    requests.reserve(count);
    auto cleanupProvisioningFailure = [&]() -> ProdigyHostTask<bool> {
      for (Machine *machine : readyMachines)
      {
        delete machine;
      }

      readyMachines.clear();
      for (const PendingCreateSubmission& submission : createRequests)
      {
        if (submission.vmName.size() > 0)
        {
          String url = {};
          url.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}?api-version=2025-04-01"_ctv>(subscriptionID, resourceGroup, submission.vmName);
          String response = {};
          String destroyFailure = {};
          (void)co_await sendARM(coro, MultiCurlClient::Method::delete_, url, nullptr, response, destroyFailure);
        }
      }
      createRequests.clear();
      pendingMachines.clear();
      co_return true;
    };

    if (config.slug.size() == 0)
    {
      error.assign("azure machine schema slug missing"_ctv);
      (void)co_await cleanupProvisioningFailure();
      co_return;
    }

    if (config.providerMachineType.size() == 0)
    {
      error.assign("azure providerMachineType missing"_ctv);
      (void)co_await cleanupProvisioningFailure();
      co_return;
    }

    AzureMachineTypeResources requestedMachineTypeResources = {};
    if (co_await resolveMachineTypeResources(coro, config.providerMachineType, requestedMachineTypeResources, error) == false)
    {
      (void)co_await cleanupProvisioningFailure();
      co_return;
    }

    if (co_await ensureBearerToken(coro, error) == false)
    {
      (void)co_await cleanupProvisioningFailure();
      co_return;
    }
    for (uint32_t index = 0; index < count; ++index)
    {
      String providerMachineType = config.providerMachineType;
      String vmNameFragment = {};
      azureBuildSafeVMNameFragment(config.slug, 47, vmNameFragment);

      String vmName = {};
      vmName.snprintf<"ntg-az-{}-{itoa}"_ctv>(
          vmNameFragment,
          uint64_t(Random::generateNumberWithNBits<24, uint32_t>()));
      MachineProvisioningProgress& progress = provisioningProgress.upsert(config.slug, providerMachineType, vmName, String());
      progress.status.assign("launch-submitted"_ctv);
      progress.ready = false;
      provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());

      String url = {};
      url.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}?api-version=2025-04-01"_ctv>(subscriptionID, resourceGroup, vmName);

      uint32_t diskGB = (config.nStorageMB + 1023) / 1024;
      if (diskGB == 0)
      {
        diskGB = 30;
      }

      String body = {};
      body.append("{\"location\":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, location);
      body.append(",\"tags\":{\"app\":\"prodigy\""_ctv);
      if (provisioningClusterUUIDTagValue.size() > 0)
      {
        body.append(",\"prodigy_cluster_uuid\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, provisioningClusterUUIDTagValue);
      }
      body.append("}"_ctv);
      if (runtimeEnvironment.azure.managedIdentityResourceID.size() > 0)
      {
        body.append(",\"identity\":{\"type\":\"UserAssigned\",\"userAssignedIdentities\":{"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, runtimeEnvironment.azure.managedIdentityResourceID);
        body.append(":{}}}"_ctv);
      }
      body.append(",\"properties\":{\"hardwareProfile\":{\"vmSize\":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, providerMachineType);
      body.append("},\"storageProfile\":{\"imageReference\":"_ctv);
      body.append(imageReferenceJSON);
      body.append(",\"osDisk\":{\"createOption\":\"FromImage\",\"deleteOption\":\"Delete\",\"diskSizeGB\":"_ctv);
      String diskSize = {};
      diskSize.assignItoa(diskGB);
      body.append(diskSize);
      body.append("}},\"osProfile\":{\"computerName\":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, vmName);
      body.append(",\"adminUsername\":\"prodigyadmin\",\"linuxConfiguration\":{\"disablePasswordAuthentication\":true,\"ssh\":{\"publicKeys\":[{\"path\":\"/home/prodigyadmin/.ssh/authorized_keys\",\"keyData\":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, bootstrapSSHPublicKey);
      body.append("}]}}}"_ctv);
      if (userData.size() > 0)
      {
        body.append(",\"userData\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, userData);
      }
      body.append(",\"networkProfile\":{\"networkApiVersion\":\"2024-05-01\",\"networkInterfaceConfigurations\":[{\"name\":\"prodigy-nic\",\"properties\":{\"deleteOption\":\"Delete\",\"primary\":true,\"ipConfigurations\":[{\"name\":\"prodigy-ipconfig\",\"properties\":{\"subnet\":{\"id\":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, subnetID);
      body.append("},\"publicIPAddressConfiguration\":{\"name\":\"prodigy-pip\",\"properties\":{\"deleteOption\":\"Delete\",\"publicIPAllocationMethod\":\"Static\"}}}}],\"networkSecurityGroup\":{\"id\":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, networkSecurityGroupID);
      body.append("}}}]}"_ctv);
      if (lifetime == MachineLifetime::spot)
      {
        body.append(",\"priority\":\"Spot\",\"evictionPolicy\":\"Delete\""_ctv);
      }
      body.append("}}"_ctv);

      PendingCreateSubmission& submission = createRequests.emplace_back();
      submission.vmName = vmName;
      submission.providerMachineType = providerMachineType;
      AzureHttpTransport transport(providerServices.http, providerServices.delay, providerServices.operationDeadline);
      MultiCurlClient::Request request = transport.request(MultiCurlClient::Method::put, url, "management.azure.com"_ctv, &body);
      buildAuthHeaders(request);
      requests.push_back(std::move(request));
    }

    for (uint32_t waveStart = 0; error.size() == 0 && waveStart < requests.size();)
    {
      Vector<MultiCurlClient::Request> wave;
      Vector<uint32_t> indices;
      while (waveStart < requests.size() && wave.size() < AzureHttpTransport::maximumRequestsPerWave)
      {
        indices.push_back(waveStart);
        wave.push_back(std::move(requests[waveStart++]));
      }

      ProdigyHostHttpBatchOperation operation(providerServices.http, *coro);
      if (operation.submit(std::move(wave)) == false)
      {
        error.assign("azure create request submission failed"_ctv);
        break;
      }
      if (operation.mustSuspend())
      {
        co_await ProdigyHostSuspend(*coro);
      }
      Vector<MultiCurlClient::Result> results;
      if (operation.takeResults(results) == false || results.size() != indices.size())
      {
        error.assign("azure create request completion mismatch"_ctv);
        break;
      }
      for (uint32_t resultIndex = 0; resultIndex < results.size(); ++resultIndex)
      {
        MultiCurlClient::Result& result = results[resultIndex];
        PendingCreateSubmission& submission = createRequests[indices[resultIndex]];
        if (AzureHttpTransport::succeeded(result) == false)
        {
          if (parseAzureErrorMessage(result.body, error) == false)
          {
            AzureHttpTransport::assignTransportFailure(result, error);
          }
          if (result.statusCode > 0)
          {
            error.snprintf_add<" [http={itoa}]"_ctv>(uint32_t(result.statusCode));
          }
          break;
        }

        PendingMachineProvisioning& pending = pendingMachines.emplace_back();
        pending.vmName = submission.vmName;
        pending.providerMachineType = submission.providerMachineType;
        String cloudID = {};
        cloudID.snprintf<"/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}"_ctv>(
            subscriptionID,
            resourceGroup,
            submission.vmName);
        provisioningProgress.notifyMachineProvisioningAccepted(cloudID);
      }
    }

    if (error.size() != 0)
    {
      std::fprintf(stderr, "prodigy azure spinMachines-failure step=createVM providerMachineType=%.*s errorBytes=%zu error=%.*s\n",
                   int(config.providerMachineType.size()),
                   reinterpret_cast<const char *>(config.providerMachineType.data()),
                   size_t(error.size()),
                   int(error.size()),
                   error.c_str());
      std::fflush(stderr);
      (void)co_await cleanupProvisioningFailure();
      co_return;
    }

    if (pendingMachines.size() != count)
    {
      error.snprintf<"azure create returned {itoa} accepted machines but {itoa} were requested"_ctv>(
          uint32_t(pendingMachines.size()),
          count);
      (void)co_await cleanupProvisioningFailure();
      co_return;
    }

    if (error.size() == 0 && pendingMachines.size() > 0)
    {
      (void)co_await waitForMachines(coro, config.slug, lifetime, pendingMachines, readyMachines, error);
    }

    if (error.size() != 0)
    {
      (void)co_await cleanupProvisioningFailure();
      co_return;
    }

    for (Machine *machine : readyMachines)
    {
      newMachines.insert(machine);
    }
  }

  void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines, String& failure) override
  {
    failure.clear();
    if (ensureScope(failure) == false)
    {
      co_return;
    }

    String url = {};
    url.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines?api-version=2025-04-01"_ctv>(subscriptionID, resourceGroup);
    String response;
    if (co_await sendARM(coro, MultiCurlClient::Method::get, url, nullptr, response, failure) == false)
    {
      co_return;
    }

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    if (azureParseVMListDocument(response, parser, doc, &failure) == false)
    {
      co_return;
    }

    if (auto values = doc["value"]; values.is_array())
    {
      for (auto vm : values.get_array())
      {
        std::string_view appTag;
        if (vm["tags"]["app"].get(appTag) || appTag != "prodigy")
        {
          continue;
        }

        std::string_view vmLocation;
        if (!vm["location"].get(vmLocation) && metro.size() > 0 && metro != String(vmLocation))
        {
          continue;
        }

        machines.insert(co_await buildMachineFromVM(coro, vm));
      }
    }
  }

  void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains, String& failure) override
  {
    selfIsBrain = false;
    failure.clear();

    bytell_hash_set<Machine *> machines;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          getMachines(coro, location, machines, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    for (Machine *machine : machines)
    {
      if (machine->isBrain == false)
      {
        delete machine;
        continue;
      }

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
    failure.clear();
    if (cloudID.size() == 0)
    {
      failure.assign("azure machine cloudID required"_ctv);
      co_return;
    }

    String url = {};
    url.snprintf<"https://management.azure.com{}/restart?api-version=2025-04-01"_ctv>(cloudID);
    String response;
    failure.clear();
    String body = "{}"_ctv;
    (void)co_await sendARM(coro, MultiCurlClient::Method::post, url, &body, response, failure);
  }

  void reportHardwareFailure(uint128_t uuid, const String& report) override
  {
    (void)uuid;
    (void)report;
  }

  void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) override
  {
    (void)coro;
    (void)decommissionedIDs;
  }

  void destroyMachine(CoroutineStack *coro, const String& cloudID, String& failure) override
  {
    failure.clear();
    if (cloudID.size() == 0)
    {
      failure.assign("azure machine cloudID required"_ctv);
      co_return;
    }

    String url = {};
    url.snprintf<"https://management.azure.com{}?api-version=2025-04-01"_ctv>(cloudID);
    String response;
    (void)co_await sendARM(coro, MultiCurlClient::Method::delete_, url, nullptr, response, failure);
  }

private:

  ProdigyHostTask<bool> destroyClusterMachinesInline(CoroutineStack *coro,
                                                      const String& clusterUUID,
                                                      uint32_t& destroyed,
                                                      String& error)
  {
    destroyed = 0;

    if (ensureScope(error) == false)
    {
      co_return false;
    }

    if (clusterUUID.size() == 0)
    {
      error.assign("azure clusterUUID tag value required"_ctv);
      co_return false;
    }

    String listURL = {};
    listURL.snprintf<"https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines?api-version=2025-04-01"_ctv>(subscriptionID, resourceGroup);

    Vector<String> cloudIDs = {};
    auto collectCloudIDs = [&](String& failure) -> ProdigyHostTask<bool> {
      cloudIDs.clear();

      String response = {};
      if (co_await sendARM(coro, MultiCurlClient::Method::get, listURL, nullptr, response, failure) == false)
      {
        co_return false;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      if (azureParseJSONDocument(response, parser, doc, &failure, "azure vm list json parse failed"_ctv) == false)
      {
        co_return false;
      }

      if (auto values = doc["value"]; values.is_array())
      {
        for (auto vm : values.get_array())
        {
          std::string_view appValue = {};
          if (vm["tags"]["app"].get(appValue) || appValue != "prodigy")
          {
            continue;
          }

          std::string_view clusterValue = {};
          if (vm["tags"]["prodigy_cluster_uuid"].get(clusterValue) || clusterValue != std::string_view(reinterpret_cast<const char *>(clusterUUID.data()), size_t(clusterUUID.size())))
          {
            continue;
          }

          std::string_view cloudIDView = {};
          if (!vm["id"].get(cloudIDView) && cloudIDView.size() > 0)
          {
            cloudIDs.push_back(String(cloudIDView));
          }
        }
      }

      co_return true;
    };

    if (co_await collectCloudIDs(error) == false)
    {
      co_return false;
    }

    if (cloudIDs.size() == 0)
    {
      co_return true;
    }

    destroyed = uint32_t(cloudIDs.size());

    for (const String& cloudID : cloudIDs)
    {
      String url = {};
      url.snprintf<"https://management.azure.com{}?api-version=2025-04-01"_ctv>(cloudID);
      String response = {};
      if (co_await sendARM(coro, MultiCurlClient::Method::delete_, url, nullptr, response, error) == false)
      {
        co_return false;
      }
    }

    for (uint32_t attempt = 0; attempt < 60; ++attempt)
    {
      if (co_await collectCloudIDs(error) == false)
      {
        co_return false;
      }

      if (cloudIDs.size() == 0)
      {
        co_return true;
      }

      AzureHttpTransport transport(providerServices.http, providerServices.delay, providerServices.operationDeadline);
      if (co_await transport.wait(coro, 2 * 1000 * 1000) == false)
      {
        error.assign("azure cluster destroy wait canceled"_ctv);
        co_return false;
      }
    }

    error.assign("timed out waiting for azure cluster machines to terminate"_ctv);
    co_return false;
  }

public:

  void destroyClusterMachines(CoroutineStack *coro, const String& clusterUUID, uint32_t& destroyed, String& error) override
  {
    (void)co_await destroyClusterMachinesInline(coro, clusterUUID, destroyed, error);
    co_return;
  }

  void ensureProdigyMachineTags(CoroutineStack *coro,
                                const String& clusterUUID,
                                const String& cloudID,
                                String& error) override
  {
    if (ensureScope(error) == false)
    {
      co_return;
    }

    if (cloudID.size() == 0)
    {
      error.assign("azure machine cloudID required"_ctv);
      co_return;
    }

    (void)co_await ensureVMTags(coro, cloudID, clusterUUID, error);
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
