#pragma once

#include <prodigy/iaas/gcp/gcp.compute.transaction.h>
#include <prodigy/iaas/iaas.h>
#include <prodigy/json.h>
#include <services/random.h>

class GcpElasticAddressPlanV1
{
public:

  uint8_t version = 1;
  uint128_t nonce = 0;
  String project;
  String region;
  String targetZone;
  String targetID;
  String targetName;
  String targetNic;
  String targetPriorName;
  String targetPriorAddress;
  String targetPriorTier;
  String targetPriorAllocationName;
  String targetPriorAllocationID;
  String desiredName;
  String desiredAllocationID;
  String desiredAddress;
  String desiredTier;
  String desiredPool;
  String requestedAddress;
  String requestedPool;
  String sourceProject;
  String sourceZone;
  String sourceInstance;
  String sourceID;
  String sourceNic;
  String sourceConfig;
  String ownershipMarker;
  IPPrefix deliveryPrefix;
  ElasticPrefixIntent intent = ElasticPrefixIntent::any;
  bool createAllocation = false;
  bool alreadySatisfied = false;
};

template <typename S>
static void serialize(S&& serializer, GcpElasticAddressPlanV1& plan)
{
  serializer.value1b(plan.version);
  serializer.value16b(plan.nonce);
  serializer.text1b(plan.project, UINT32_MAX);
  serializer.text1b(plan.region, UINT32_MAX);
  serializer.text1b(plan.targetZone, UINT32_MAX);
  serializer.text1b(plan.targetID, UINT32_MAX);
  serializer.text1b(plan.targetName, UINT32_MAX);
  serializer.text1b(plan.targetNic, UINT32_MAX);
  serializer.text1b(plan.targetPriorName, UINT32_MAX);
  serializer.text1b(plan.targetPriorAddress, UINT32_MAX);
  serializer.text1b(plan.targetPriorTier, UINT32_MAX);
  serializer.text1b(plan.targetPriorAllocationName, UINT32_MAX);
  serializer.text1b(plan.targetPriorAllocationID, UINT32_MAX);
  serializer.text1b(plan.desiredName, UINT32_MAX);
  serializer.text1b(plan.desiredAllocationID, UINT32_MAX);
  serializer.text1b(plan.desiredAddress, UINT32_MAX);
  serializer.text1b(plan.desiredTier, UINT32_MAX);
  serializer.text1b(plan.desiredPool, UINT32_MAX);
  serializer.text1b(plan.requestedAddress, UINT32_MAX);
  serializer.text1b(plan.requestedPool, UINT32_MAX);
  serializer.text1b(plan.sourceProject, UINT32_MAX);
  serializer.text1b(plan.sourceZone, UINT32_MAX);
  serializer.text1b(plan.sourceInstance, UINT32_MAX);
  serializer.text1b(plan.sourceID, UINT32_MAX);
  serializer.text1b(plan.sourceNic, UINT32_MAX);
  serializer.text1b(plan.sourceConfig, UINT32_MAX);
  serializer.text1b(plan.ownershipMarker, UINT32_MAX);
  serializer.object(plan.deliveryPrefix);
  serializer.value1b(plan.intent);
  serializer.value1b(plan.createAllocation);
  serializer.value1b(plan.alreadySatisfied);
}

class GcpElasticAddressTransaction final
{
public:

  constexpr static uint32_t maximumInterfaces = 32;
  constexpr static uint32_t maximumAccessConfigs = 32;
  constexpr static uint32_t maximumUsers = 1;
  constexpr static uint32_t maximumProjectBytes = 256;
  constexpr static uint32_t maximumTokenBytes = 64 * 1024;
  constexpr static uint32_t maximumUriBytes = 2048;
  constexpr static uint32_t maximumAssociationBytes = 4096;
  constexpr static uint32_t maximumOperationBytes = 256;
  constexpr static uint32_t maximumFieldBytes = 128;
  constexpr static uint32_t maximumResourceNameBytes = 63;
  constexpr static std::chrono::seconds maximumDuration {110};
  constexpr static std::chrono::seconds recoveryReserve {35};

private:

  class User
  {
  public:

    String project;
    String zone;
    String instance;

    bool present(void) const
    {
      return instance.empty() == false;
    }
  };

  class Address
  {
  public:

    String cloudID;
    String name;
    String address;
    String networkTier;
    String ipCollection;
    String ownershipMarker;
    User user;
  };

  class AccessConfig
  {
  public:

    String nic;
    String name;
    String address;
    String networkTier;

    bool present(void) const
    {
      return name.empty() == false;
    }
  };

  class Association
  {
  public:

    String project;
    String region;
    String zone;
    String cloudID;
    String instance;
    String nic;
    String config;
    String address;
    String networkTier;
    String allocation;
    String allocationCloudID;
  };

  enum class MutationState : uint8_t
  {
    rejected,
    accepted
  };

  enum class MutationStep : uint8_t
  {
    releaseDetachTarget = 1,
    releaseDeleteAllocation,
    applyCreateAllocation,
    applyDetachSource,
    applyDetachTargetPrior,
    applyAttachDesired,
    compensateDetachDesired,
    compensateRestoreTarget,
    compensateRestoreSource,
    compensateDeleteAllocation
  };

  ProdigyHostHttpOperation::Submission http;
  ProdigyHostDelayOperation::Submission delay;
  String project;
  String zone;
  String region;
  String token;
  MultiCurlClient::TimePoint deadline;
  MultiCurlClient::TimePoint forwardDeadline;
  uint128_t requestNonce;
  GcpComputeTransaction forward;
  GcpComputeTransaction recovery;

  static MultiCurlClient::TimePoint boundedDeadline(MultiCurlClient::TimePoint requested)
  {
    const MultiCurlClient::TimePoint limit = MultiCurlClient::Clock::now() + maximumDuration;
    return requested < limit ? requested : limit;
  }

  static MultiCurlClient::TimePoint forwardLimit(MultiCurlClient::TimePoint deadline)
  {
    const MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now();
    return deadline > now + recoveryReserve ? deadline - recoveryReserve : now;
  }

  static bool successful(const MultiCurlClient::Result& result)
  {
    return result.status == MultiCurlClient::Status::success &&
           result.statusCode >= 200 && result.statusCode < 300;
  }

  MultiCurlClient::TimePoint recoveryStepDeadline(std::chrono::seconds allowance) const
  {
    const MultiCurlClient::TimePoint limit = MultiCurlClient::Clock::now() + allowance;
    return limit < deadline ? limit : deadline;
  }

  static bool parseIPv4(const String& text, IPAddress& address)
  {
    return ClusterMachine::parseIPAddressLiteral(text, address) && address.is6 == false;
  }

  static bool validNetworkTier(const String& value)
  {
    return value == "PREMIUM"_ctv || value == "STANDARD"_ctv;
  }

  static bool validResourceName(const String& value)
  {
    if (value.empty() || value.size() > maximumResourceNameBytes ||
        value[0] < 'a' || value[0] > 'z' ||
        value[value.size() - 1] == '-')
    {
      return false;
    }
    for (uint64_t index = 0; index < value.size(); ++index)
    {
      const uint8_t byte = value[index];
      if ((byte < 'a' || byte > 'z') && (byte < '0' || byte > '9') && byte != '-')
      {
        return false;
      }
    }
    return true;
  }

  static bool validProviderPool(const String& value)
  {
    if (value.empty())
    {
      return true;
    }
    const String pool = GcpComputeTransaction::view(value);
    return pool.size() <= maximumUriBytes &&
           (GcpComputeTransaction::startsWith(pool, "https://www.googleapis.com/compute/"_ctv) ||
            GcpComputeTransaction::startsWith(pool, "https://compute.googleapis.com/compute/"_ctv)) &&
           GcpComputeTransaction::find(pool, uint8_t('?')) == GcpComputeTransaction::notFound &&
           GcpComputeTransaction::find(pool, uint8_t('#')) == GcpComputeTransaction::notFound;
  }

  static bool parseUser(String uri, User& user)
  {
    constexpr static auto google = "https://www.googleapis.com/compute/v1/projects/"_ctv;
    constexpr static auto compute = "https://compute.googleapis.com/compute/v1/projects/"_ctv;
    if (uri.size() > maximumUriBytes)
    {
      return false;
    }
    uint64_t prefixSize = 0;
    if (GcpComputeTransaction::startsWith(uri, google))
    {
      prefixSize = google.size();
    }
    else if (GcpComputeTransaction::startsWith(uri, compute))
    {
      prefixSize = compute.size();
    }
    else
    {
      return false;
    }
    uri = GcpComputeTransaction::slice(uri, prefixSize);
    const uint64_t zones = GcpComputeTransaction::find(uri, "/zones/"_ctv);
    if (zones == GcpComputeTransaction::notFound || zones == 0)
    {
      return false;
    }
    const uint64_t instances = GcpComputeTransaction::find(uri, "/instances/"_ctv, zones + 7);
    if (instances == GcpComputeTransaction::notFound || instances == zones + 7)
    {
      return false;
    }
    const String name = GcpComputeTransaction::slice(uri, instances + 11);
    if (name.empty() || GcpComputeTransaction::find(name, uint8_t('/')) != GcpComputeTransaction::notFound ||
        GcpComputeTransaction::find(name, uint8_t('?')) != GcpComputeTransaction::notFound ||
        GcpComputeTransaction::find(name, uint8_t('#')) != GcpComputeTransaction::notFound)
    {
      return false;
    }
    const String parsedProject = GcpComputeTransaction::slice(uri, 0, zones);
    const String parsedZone = GcpComputeTransaction::slice(uri, zones + 7, instances - zones - 7);
    if (parsedProject.size() > maximumProjectBytes || validResourceName(parsedZone) == false ||
        validResourceName(name) == false)
    {
      return false;
    }
    user.project.assign(parsedProject);
    user.zone.assign(parsedZone);
    user.instance.assign(name);
    return true;
  }

  bool parseAddress(simdjson::dom::element document, Address& address, String& failure) const
  {
    String name;
    String cloudID;
    String value;
    String type;
    String version;
    String parsedRegion;
    String tier;
    if (document.is_object() == false ||
        prodigyJSONString(document["id"], cloudID) != simdjson::SUCCESS || cloudID.empty() ||
        prodigyJSONString(document["name"], name) != simdjson::SUCCESS ||
        validResourceName(name) == false ||
        prodigyJSONString(document["address"], value) != simdjson::SUCCESS || value.empty() ||
        prodigyJSONString(document["addressType"], type) != simdjson::SUCCESS || type != "EXTERNAL"_ctv ||
        prodigyJSONString(document["ipVersion"], version) != simdjson::SUCCESS || version != "IPV4"_ctv ||
        prodigyJSONString(document["region"], parsedRegion) != simdjson::SUCCESS || parsedRegion.empty() ||
        prodigyJSONString(document["networkTier"], tier) != simdjson::SUCCESS || validNetworkTier(tier) == false)
    {
      failure.assign("gcp regional external ipv4 address response malformed"_ctv);
      return false;
    }
    String cloudIDText;
    cloudIDText.assign(cloudID);
    if (GcpComputeTransaction::validDecimalID(cloudIDText) == false)
    {
      failure.assign("gcp address immutable id malformed"_ctv);
      return false;
    }

    String expectedRegion;
    expectedRegion.assign("https://www.googleapis.com/compute/v1/projects/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(expectedRegion, project);
    expectedRegion.append("/regions/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(expectedRegion, region);
    String alternateRegion;
    alternateRegion.assign("https://compute.googleapis.com/compute/v1/projects/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(alternateRegion, project);
    alternateRegion.append("/regions/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(alternateRegion, region);
    if (parsedRegion != GcpComputeTransaction::view(expectedRegion) &&
        parsedRegion != GcpComputeTransaction::view(alternateRegion))
    {
      failure.assign("gcp address belongs to another project or region"_ctv);
      return false;
    }
    IPAddress parsed;
    String valueText;
    valueText.assign(value);
    if (parseIPv4(valueText, parsed) == false)
    {
      failure.assign("gcp address resource is not ipv4"_ctv);
      return false;
    }

    address = {};
    address.cloudID.assign(cloudID);
    address.name.assign(name);
    address.address.assign(value);
    address.networkTier.assign(tier);
    String ipCollection;
    const simdjson::error_code collectionError = prodigyJSONString(document["ipCollection"], ipCollection);
    if ((collectionError != simdjson::SUCCESS && collectionError != simdjson::NO_SUCH_FIELD) ||
        (collectionError == simdjson::SUCCESS && ipCollection.size() > maximumUriBytes))
    {
      failure.assign("gcp address ipCollection malformed"_ctv);
      return false;
    }
    if (collectionError == simdjson::SUCCESS)
    {
      address.ipCollection.assign(ipCollection);
    }
    simdjson::dom::element labels;
    const simdjson::error_code labelsError = document["labels"].get(labels);
    if (labelsError != simdjson::SUCCESS && labelsError != simdjson::NO_SUCH_FIELD)
    {
      failure.assign("gcp address labels malformed"_ctv);
      return false;
    }
    if (labelsError == simdjson::SUCCESS)
    {
      if (labels.is_object() == false)
      {
        failure.assign("gcp address labels malformed"_ctv);
        return false;
      }
      String marker;
      const simdjson::error_code markerError = prodigyJSONString(labels["prodigy-elastic-saga"], marker);
      if ((markerError != simdjson::SUCCESS && markerError != simdjson::NO_SUCH_FIELD) ||
          (markerError == simdjson::SUCCESS && marker.size() > maximumFieldBytes))
      {
        failure.assign("gcp address ownership marker malformed"_ctv);
        return false;
      }
      if (markerError == simdjson::SUCCESS)
      {
        address.ownershipMarker.assign(marker);
      }
    }
    simdjson::dom::element users;
    const simdjson::error_code usersError = document["users"].get(users);
    if (usersError != simdjson::SUCCESS && usersError != simdjson::NO_SUCH_FIELD)
    {
      failure.assign("gcp address users malformed"_ctv);
      return false;
    }
    if (usersError == simdjson::SUCCESS)
    {
      if (users.is_array() == false)
      {
        failure.assign("gcp address users malformed"_ctv);
        return false;
      }
      uint32_t count = 0;
      for (simdjson::dom::element entry : users.get_array())
      {
        String uri;
        if (++count > maximumUsers || prodigyJSONString(entry, uri) != simdjson::SUCCESS ||
            parseUser(std::move(uri), address.user) == false)
        {
          if (count > maximumUsers)
          {
            failure.assign("gcp address has multiple users"_ctv);
          }
          else
          {
            failure.assign("gcp address has a non-instance user"_ctv);
          }
          return false;
        }
      }
    }
    return true;
  }

  static bool parseInterface(const String& response,
                             const String& cloudID,
                             const String *preferredNic,
                             const String *expectedAddress,
                             AccessConfig& selected,
                             String& failure)
  {
    simdjson::dom::parser parser;
    simdjson::dom::element instance;
    String text = response;
    String id;
    simdjson::dom::element interfaces;
    if (parser.parse(text.c_str(), text.size()).get(instance) || instance.is_object() == false ||
        prodigyJSONString(instance["id"], id) != simdjson::SUCCESS ||
        id != GcpComputeTransaction::view(cloudID) ||
        instance["networkInterfaces"].get(interfaces) || interfaces.is_array() == false)
    {
      failure.assign("gcp elastic target identity or interfaces malformed"_ctv);
      return false;
    }

    selected = {};
    uint32_t interfaceCount = 0;
    for (simdjson::dom::element interface : interfaces.get_array())
    {
      if (++interfaceCount > maximumInterfaces)
      {
        failure.assign("gcp elastic target exceeds interface limit"_ctv);
        return false;
      }
      String nic;
      if (interface.is_object() == false ||
          prodigyJSONString(interface["name"], nic) != simdjson::SUCCESS || nic.empty() ||
          nic.size() > maximumFieldBytes)
      {
        failure.assign("gcp elastic target interface name malformed"_ctv);
        return false;
      }
      if (preferredNic && nic != GcpComputeTransaction::view(*preferredNic))
      {
        continue;
      }
      if (selected.nic.empty())
      {
        selected.nic.assign(nic);
      }

      simdjson::dom::element configs;
      const simdjson::error_code configError = interface["accessConfigs"].get(configs);
      if (configError != simdjson::SUCCESS && configError != simdjson::NO_SUCH_FIELD)
      {
        failure.assign("gcp elastic access configs malformed"_ctv);
        return false;
      }
      if (configError != simdjson::SUCCESS)
      {
        if (preferredNic)
        {
          return true;
        }
        continue;
      }
      if (configs.is_array() == false)
      {
        failure.assign("gcp elastic access configs malformed"_ctv);
        return false;
      }
      uint32_t configCount = 0;
      for (simdjson::dom::element config : configs.get_array())
      {
        if (++configCount > maximumAccessConfigs)
        {
          failure.assign("gcp elastic target exceeds access config limit"_ctv);
          return false;
        }
        String name;
        String address;
        String tier;
        if (config.is_object() == false ||
            prodigyJSONString(config["name"], name) != simdjson::SUCCESS || name.empty() ||
            name.size() > maximumFieldBytes ||
            prodigyJSONString(config["natIP"], address) != simdjson::SUCCESS || address.empty() ||
            prodigyJSONString(config["networkTier"], tier) != simdjson::SUCCESS ||
            validNetworkTier(tier) == false)
        {
          failure.assign("gcp elastic access config malformed"_ctv);
          return false;
        }
        String addressText;
        addressText.assign(address);
        IPAddress parsedAddress;
        if (parseIPv4(addressText, parsedAddress) == false)
        {
          failure.assign("gcp elastic access config natIP is not ipv4"_ctv);
          return false;
        }
        if (expectedAddress && address != GcpComputeTransaction::view(*expectedAddress))
        {
          continue;
        }
        selected.nic.assign(nic);
        selected.name.assign(name);
        selected.address.assign(address);
        selected.networkTier.assign(tier);
        return true;
      }
      if (preferredNic)
      {
        return true;
      }
    }
    if (selected.nic.empty())
    {
      if (preferredNic)
      {
        failure.assign("gcp elastic association interface no longer exists"_ctv);
      }
      else
      {
        failure.assign("gcp elastic target has no network interface"_ctv);
      }
      return false;
    }
    return true;
  }

  static bool parseAssociation(const String& encoded, Association& association, String& failure)
  {
    simdjson::dom::parser parser;
    simdjson::dom::element document;
    String text = encoded;
    uint64_t version = 0;
    String project;
    String region;
    String zone;
    String cloudID;
    String instance;
    String nic;
    String config;
    String address;
    String networkTier;
    String allocation;
    String allocationCloudID;
    if (encoded.size() > maximumAssociationBytes ||
        parser.parse(text.c_str(), text.size()).get(document) || document.is_object() == false ||
        document["v"].get(version) ||
        version != 1 || prodigyJSONString(document["project"], project) != simdjson::SUCCESS || project.empty() ||
        prodigyJSONString(document["region"], region) != simdjson::SUCCESS || validResourceName(region) == false ||
        prodigyJSONString(document["zone"], zone) != simdjson::SUCCESS || zone.empty() ||
        prodigyJSONString(document["targetId"], cloudID) != simdjson::SUCCESS ||
        GcpComputeTransaction::validDecimalID(cloudID) == false ||
        prodigyJSONString(document["instance"], instance) != simdjson::SUCCESS || validResourceName(instance) == false ||
        prodigyJSONString(document["nic"], nic) != simdjson::SUCCESS || nic.empty() || nic.size() > maximumFieldBytes ||
        prodigyJSONString(document["config"], config) != simdjson::SUCCESS || config.empty() || config.size() > maximumFieldBytes ||
        prodigyJSONString(document["address"], address) != simdjson::SUCCESS || address.empty() ||
        prodigyJSONString(document["networkTier"], networkTier) != simdjson::SUCCESS || validNetworkTier(networkTier) == false ||
        prodigyJSONString(document["allocation"], allocation) != simdjson::SUCCESS || validResourceName(allocation) == false ||
        prodigyJSONString(document["allocationId"], allocationCloudID) != simdjson::SUCCESS || allocationCloudID.empty())
    {
      failure.assign("gcp elastic association token malformed"_ctv);
      return false;
    }
    association.project.assign(project);
    association.region.assign(region);
    association.zone.assign(zone);
    association.cloudID.assign(cloudID);
    association.instance.assign(instance);
    association.nic.assign(nic);
    association.config.assign(config);
    association.address.assign(address);
    association.networkTier.assign(networkTier);
    association.allocation.assign(allocation);
    association.allocationCloudID.assign(allocationCloudID);
    IPAddress parsed;
    if (parseIPv4(association.address, parsed) == false ||
        GcpComputeTransaction::validDecimalID(association.allocationCloudID) == false)
    {
      failure.assign("gcp elastic association token address malformed"_ctv);
      return false;
    }
    return true;
  }

  static void encodeAssociation(const String& project,
                                const String& region,
                                const String& zone,
                                const String& cloudID,
                                const String& instance,
                                const AccessConfig& config,
                                const Address& address,
                                String& encoded)
  {
    encoded.assign("{\"v\":1,\"project\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(encoded, project);
    encoded.append(",\"region\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(encoded, region);
    encoded.append(",\"zone\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(encoded, zone);
    encoded.append(",\"targetId\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(encoded, cloudID);
    encoded.append(",\"instance\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(encoded, instance);
    encoded.append(",\"nic\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(encoded, config.nic);
    encoded.append(",\"config\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(encoded, config.name);
    encoded.append(",\"address\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(encoded, address.address);
    encoded.append(",\"networkTier\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(encoded, address.networkTier);
    encoded.append(",\"allocation\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(encoded, address.name);
    encoded.append(",\"allocationId\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(encoded, address.cloudID);
    encoded.append('}');
  }

  void buildRequestID(MutationStep step, String& outputID) const
  {
    constexpr uint128_t multiplier = (uint128_t(0x9e3779b97f4a7c15ULL) << 64) |
                                     uint128_t(0xf39cc0605cedc835ULL);
    uint128_t value = requestNonce ^ (uint128_t(uint8_t(step)) * multiplier);
    if (value == 0)
    {
      value = 1;
    }
    value = (value & ~(uint128_t(0xf) << 76)) | (uint128_t(4) << 76);
    value = (value & ~(uint128_t(0xc) << 60)) | (uint128_t(8) << 60);
    constexpr static char hex[] = "0123456789abcdef";
    char rendered[36];
    uint32_t output = 0;
    for (int32_t nibble = 31; nibble >= 0; --nibble)
    {
      if (output == 8 || output == 13 || output == 18 || output == 23)
      {
        rendered[output++] = '-';
      }
      rendered[output++] = hex[uint8_t((value >> (nibble * 4)) & 0xf)];
    }
    outputID.assign(rendered, sizeof(rendered));
  }

  String addressBaseUrl(const String *name = nullptr) const
  {
    String url;
    url.assign("https://compute.googleapis.com/compute/v1/projects/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, project);
    url.append("/regions/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, region);
    url.append("/addresses"_ctv);
    if (name)
    {
      url.append('/');
      GcpComputeTransaction::appendPercentEncoded(url, *name);
    }
    return url;
  }

  String operationUrl(const String& operation, const String& operationZone) const
  {
    String url;
    url.assign("https://compute.googleapis.com/compute/v1/projects/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, project);
    if (operationZone.empty())
    {
      url.append("/regions/"_ctv);
      GcpComputeTransaction::appendPercentEncoded(url, region);
    }
    else
    {
      url.append("/zones/"_ctv);
      GcpComputeTransaction::appendPercentEncoded(url, operationZone);
    }
    url.append("/operations/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, operation);
    url.append("?fields=status,error,httpErrorStatusCode,httpErrorMessage,statusMessage"_ctv);
    return url;
  }

  String instanceMutationUrl(const String& operationZone,
                             const String& instance,
                             const char *operation,
                             const AccessConfig& config,
                             const String& requestID) const
  {
    String url;
    url.assign("https://compute.googleapis.com/compute/v1/projects/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, project);
    url.append("/zones/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, operationZone);
    url.append("/instances/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, instance);
    url.append('/');
    url.append(operation);
    url.append("?networkInterface="_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, config.nic);
    if (String(operation) == "deleteAccessConfig"_ctv)
    {
      url.append("&accessConfig="_ctv);
      GcpComputeTransaction::appendPercentEncoded(url, config.name);
    }
    url.append("&requestId="_ctv);
    url.append(requestID);
    return url;
  }

  void mutate(CoroutineStack *coro,
              GcpComputeTransaction& compute,
              MultiCurlClient::Request request,
              String operationZone,
              MutationState& state,
              String& failure)
  {
    String ownedOperationZone;
    ownedOperationZone.assign(operationZone);
    state = MutationState::rejected;
    MultiCurlClient::Result result;
    bool complete = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          compute.submit(coro, std::move(request), result, complete);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (complete == false)
    {
      failure.assign("gcp elastic mutation transport outcome ambiguous"_ctv);
      state = MutationState::accepted;
      co_return;
    }
    if (successful(result) == false)
    {
      if (result.status == MultiCurlClient::Status::success && result.statusCode == 404)
      {
        failure.clear();
        state = MutationState::accepted;
        co_return;
      }
      GcpComputeTransaction::assignRequestFailure(result, "gcp elastic mutation"_ctv, failure);
      state = GcpComputeTransaction::mutationMayBeAccepted(result) ? MutationState::accepted :
                                                                    MutationState::rejected;
      co_return;
    }
    state = MutationState::accepted;
    String operation;
    if (GcpComputeTransaction::parseOperationName(result.body, operation, failure) == false)
    {
      co_return;
    }
    if (operation.size() > maximumOperationBytes || validResourceName(GcpComputeTransaction::view(operation)) == false)
    {
      failure.assign("gcp elastic operation name malformed"_ctv);
      co_return;
    }
    GcpComputeTransaction::OperationState operationState = GcpComputeTransaction::OperationState::invalid;
    bool missing = false;
    String url = operationUrl(operation, ownedOperationZone);
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          compute.pollOperationAtUrl(coro, url, operationState, missing, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (operationState == GcpComputeTransaction::OperationState::done)
    {
      state = MutationState::accepted;
      failure.clear();
    }
    else if (operationState == GcpComputeTransaction::OperationState::failed)
    {
      state = MutationState::accepted;
    }
  }

  void fetchAddress(CoroutineStack *coro,
                    GcpComputeTransaction& compute,
                    const String& name,
                    Address& address,
                    bool& exists,
                    String& failure)
  {
    address = {};
    exists = false;
    String url = addressBaseUrl(&name);
    url.append("?fields=id,name,address,addressType,ipVersion,region,networkTier,ipCollection,labels,users"_ctv);
    MultiCurlClient::Result result;
    bool complete = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          compute.submit(coro, compute.request(MultiCurlClient::Method::get, std::move(url)), result, complete);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (complete == false)
    {
      failure.assign("gcp address observation failed"_ctv);
      co_return;
    }
    if (result.status == MultiCurlClient::Status::success && result.statusCode == 404)
    {
      co_return;
    }
    if (successful(result) == false)
    {
      GcpComputeTransaction::assignRequestFailure(result, "gcp address observation"_ctv, failure);
      co_return;
    }
    simdjson::dom::parser parser;
    simdjson::dom::element document;
    String text = result.body;
    if (parser.parse(text.c_str(), text.size()).get(document) ||
        parseAddress(document, address, failure) == false)
    {
      if (failure.empty())
      {
        failure.assign("gcp address response parse failed"_ctv);
      }
      co_return;
    }
    if (address.name != name)
    {
      failure.assign("gcp address observation identity changed"_ctv);
      address = {};
      co_return;
    }
    exists = true;
  }

  void lookupAddress(CoroutineStack *coro,
                     GcpComputeTransaction& compute,
                     const String& requested,
                     Address& address,
                     bool& found,
                     String& failure)
  {
    address = {};
    found = false;
    String url = addressBaseUrl();
    url.append("?maxResults=2&filter=address%3D"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, requested);
    url.append("&fields=items(id,name,address,addressType,ipVersion,region,networkTier,ipCollection,labels,users),nextPageToken"_ctv);
    MultiCurlClient::Result result;
    bool complete = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          compute.submit(coro, compute.request(MultiCurlClient::Method::get, std::move(url)), result, complete);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (complete == false || successful(result) == false)
    {
      GcpComputeTransaction::assignRequestFailure(result, "gcp address lookup"_ctv, failure);
      co_return;
    }

    simdjson::dom::parser parser;
    simdjson::dom::element document;
    String text = result.body;
    if (parser.parse(text.c_str(), text.size()).get(document) || document.is_object() == false)
    {
      failure.assign("gcp address lookup response parse failed"_ctv);
      co_return;
    }
    String pageToken;
    const simdjson::error_code tokenError = prodigyJSONString(document["nextPageToken"], pageToken);
    if ((tokenError != simdjson::SUCCESS && tokenError != simdjson::NO_SUCH_FIELD) ||
        (tokenError == simdjson::SUCCESS && pageToken.empty() == false))
    {
      failure.assign("gcp address lookup returned an unexpected page token"_ctv);
      co_return;
    }
    simdjson::dom::element items;
    const simdjson::error_code itemsError = document["items"].get(items);
    if (itemsError == simdjson::NO_SUCH_FIELD)
    {
      co_return;
    }
    if (itemsError != simdjson::SUCCESS || items.is_array() == false)
    {
      failure.assign("gcp address lookup items malformed"_ctv);
      co_return;
    }
    uint32_t count = 0;
    for (simdjson::dom::element item : items.get_array())
    {
      if (++count > 1)
      {
        failure.assign("gcp requested address resolves to multiple resources"_ctv);
        co_return;
      }
      if (parseAddress(item, address, failure) == false || address.address != requested)
      {
        if (failure.empty())
        {
          failure.assign("gcp address filter returned an unexpected address"_ctv);
        }
        co_return;
      }
      found = true;
    }
  }

  void fetchAccessConfig(CoroutineStack *coro,
                         GcpComputeTransaction& compute,
                         const String& instance,
                         const String& cloudID,
                         const String *nic,
                         const String *address,
                         AccessConfig& config,
                         bool& exists,
                         String& failure)
  {
    config = {};
    exists = false;
    MultiCurlClient::Result result;
    bool complete = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          compute.fetchInstance(coro,
                                instance,
                                "id,networkInterfaces(name,accessConfigs(name,natIP,networkTier))"_ctv,
                                result,
                                complete,
                                failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (failure.empty() == false || complete == false || result.statusCode == 404)
    {
      co_return;
    }
    if (parseInterface(result.body, cloudID, nic, address, config, failure))
    {
      exists = true;
    }
  }

  void detach(CoroutineStack *coro,
              GcpComputeTransaction& compute,
              const String& operationZone,
              const String& instance,
              const String& cloudID,
              const AccessConfig& config,
              MutationStep requestStep,
              bool& mayHaveMutated,
              bool& absent,
              String& failure)
  {
    mayHaveMutated = false;
    absent = false;
    String requestID;
    buildRequestID(requestStep, requestID);
    String url = instanceMutationUrl(operationZone, instance, "deleteAccessConfig", config, requestID);
    MutationState state = MutationState::rejected;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          mutate(coro,
                 compute,
                 compute.request(MultiCurlClient::Method::post, std::move(url)),
                 operationZone,
                 state,
                 failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    mayHaveMutated = state != MutationState::rejected;
    if (state == MutationState::rejected)
    {
      co_return;
    }
    AccessConfig observed;
    bool instanceExists = false;
    String observationFailure;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          fetchAccessConfig(coro,
                            compute,
                            instance,
                            cloudID,
                            &config.nic,
                            &config.address,
                            observed,
                            instanceExists,
                            observationFailure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (observationFailure.empty() == false)
    {
      failure.assign(observationFailure);
      co_return;
    }
    absent = instanceExists == false || observed.present() == false;
    if (absent)
    {
      failure.clear();
    }
    else if (failure.empty())
    {
      failure.assign("gcp elastic detach postcondition not observed"_ctv);
    }
  }

  void attach(CoroutineStack *coro,
              GcpComputeTransaction& compute,
              const String& operationZone,
              const String& instance,
              const String& cloudID,
              const AccessConfig& desired,
              bool ephemeral,
              MutationStep requestStep,
              bool& mayHaveMutated,
              bool& attached,
              String& failure)
  {
    mayHaveMutated = false;
    attached = false;
    String requestID;
    buildRequestID(requestStep, requestID);
    String url = instanceMutationUrl(operationZone, instance, "addAccessConfig", desired, requestID);
    String body;
    body.assign("{\"name\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(body, desired.name);
    body.append(",\"type\":\"ONE_TO_ONE_NAT\""_ctv);
    if (ephemeral == false)
    {
      body.append(",\"natIP\":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, desired.address);
    }
    body.append(",\"networkTier\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(body, desired.networkTier);
    body.append('}');
    MutationState state = MutationState::rejected;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          mutate(coro,
                 compute,
                 compute.request(MultiCurlClient::Method::post, std::move(url), &body),
                 operationZone,
                 state,
                 failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    mayHaveMutated = state != MutationState::rejected;
    if (state == MutationState::rejected)
    {
      co_return;
    }
    AccessConfig observed;
    bool instanceExists = false;
    String observationFailure;
    const String *expected = ephemeral ? nullptr : &desired.address;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          fetchAccessConfig(coro,
                            compute,
                            instance,
                            cloudID,
                            &desired.nic,
                            expected,
                            observed,
                            instanceExists,
                            observationFailure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (observationFailure.empty() == false)
    {
      failure.assign(observationFailure);
      co_return;
    }
    attached = instanceExists && observed.present() && observed.name == desired.name &&
               observed.networkTier == desired.networkTier &&
               (ephemeral || observed.address == desired.address);
    if (attached)
    {
      failure.clear();
    }
    else if (failure.empty())
    {
      failure.assign("gcp elastic attach postcondition not observed"_ctv);
    }
  }

  void allocate(CoroutineStack *coro,
                const String& providerPool,
                const String& ownershipMarker,
                MutationStep requestStep,
                Address& address,
                bool& mayExist,
                bool& allocated,
                String& failure)
  {
    mayExist = false;
    allocated = false;
    String suffix;
    suffix.assignItoh(requestNonce);
    address.name.assign("prodigy-eip-"_ctv);
    address.name.append(suffix);
    String requestID;
    buildRequestID(requestStep, requestID);
    String url = addressBaseUrl();
    url.append("?requestId="_ctv);
    url.append(requestID);
    String body;
    body.assign("{\"name\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(body, address.name);
    body.append(",\"addressType\":\"EXTERNAL\",\"ipVersion\":\"IPV4\",\"networkTier\":\"PREMIUM\""_ctv);
    if (providerPool.empty() == false)
    {
      body.append(",\"ipCollection\":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, providerPool);
    }
    if (ownershipMarker.empty() == false)
    {
      body.append(",\"labels\":{\"prodigy-elastic-saga\":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, ownershipMarker);
      body.append("}"_ctv);
    }
    body.append('}');
    MutationState state = MutationState::rejected;
    String mutationFailure;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          mutate(coro,
                 forward,
                 forward.request(MultiCurlClient::Method::post, std::move(url), &body),
                 String(),
                 state,
                 mutationFailure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    mayExist = state != MutationState::rejected;
    Address observed;
    bool exists = false;
    if (state != MutationState::rejected)
    {
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            fetchAddress(coro, forward, address.name, observed, exists, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
    }
    if (exists)
    {
      if (observed.networkTier != "PREMIUM"_ctv ||
          (providerPool.empty() == false && observed.ipCollection != providerPool) ||
          (ownershipMarker.empty() == false && observed.ownershipMarker != ownershipMarker))
      {
        failure.assign("gcp allocated address tier or ipCollection differs from request"_ctv);
        address = std::move(observed);
        allocated = false;
        co_return;
      }
      address = std::move(observed);
      allocated = true;
      failure.clear();
    }
    else if (failure.empty())
    {
      if (mutationFailure.empty())
      {
        failure.assign("gcp address allocation postcondition not observed"_ctv);
      }
      else
      {
        failure.assign(mutationFailure);
      }
    }
  }

  void deleteAllocation(CoroutineStack *coro,
                        GcpComputeTransaction& compute,
                        const Address& expected,
                        MutationStep requestStep,
                        bool& mayHaveMutated,
                        bool& removed,
                        String& failure)
  {
    mayHaveMutated = false;
    removed = false;
    Address current;
    bool exists = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          fetchAddress(coro, compute, expected.name, current, exists, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (failure.empty() == false)
    {
      co_return;
    }
    if (exists == false)
    {
      removed = true;
      co_return;
    }
    if ((expected.cloudID.empty() == false && current.cloudID != expected.cloudID) ||
        (expected.address.empty() == false && current.address != expected.address) ||
        (expected.networkTier.empty() == false && current.networkTier != expected.networkTier) ||
        (expected.ownershipMarker.empty() == false && current.ownershipMarker != expected.ownershipMarker) ||
        current.user.present())
    {
      if ((expected.cloudID.empty() == false && current.cloudID != expected.cloudID) ||
          (expected.address.empty() == false && current.address != expected.address) ||
          (expected.networkTier.empty() == false && current.networkTier != expected.networkTier) ||
          (expected.ownershipMarker.empty() == false && current.ownershipMarker != expected.ownershipMarker))
      {
        failure.assign("gcp elastic allocation identity changed"_ctv);
      }
      else
      {
        failure.assign("gcp elastic allocation remains in use"_ctv);
      }
      co_return;
    }
    String requestID;
    buildRequestID(requestStep, requestID);
    String url = addressBaseUrl(&expected.name);
    url.append("?requestId="_ctv);
    url.append(requestID);
    MutationState state = MutationState::rejected;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          mutate(coro,
                 compute,
                 compute.request(MultiCurlClient::Method::delete_, std::move(url)),
                 String(),
                 state,
                 failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    mayHaveMutated = state != MutationState::rejected;
    Address observed;
    bool stillExists = false;
    String observationFailure;
    if (state != MutationState::rejected)
    {
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            fetchAddress(coro, compute, expected.name, observed, stillExists, observationFailure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
    }
    if (observationFailure.empty() == false)
    {
      failure.assign(observationFailure);
    }
    else if (stillExists == false && state != MutationState::rejected)
    {
      removed = true;
      failure.clear();
    }
  }

  static void appendRecoveryFailure(const String& step, const String& detail, String& failure)
  {
    failure.append("; recovery "_ctv);
    failure.append(step);
    failure.append(": "_ctv);
    failure.append(detail.empty() ? "postcondition not observed"_ctv : detail);
  }

public:

  GcpElasticAddressTransaction(ProdigyHostHttpOperation::Submission http,
                               ProdigyHostDelayOperation::Submission delay,
                               String project,
                               String zone,
                               String region,
                               String token,
                               MultiCurlClient::TimePoint deadline,
                               uint128_t requestNonce = 0)
      : http(http),
        delay(delay),
        project(),
        zone(),
        region(),
        token(),
        deadline(boundedDeadline(deadline)),
        forwardDeadline(forwardLimit(this->deadline)),
        requestNonce(requestNonce == 0 ? Random::generateNumberWithNBits<128, uint128_t>() : requestNonce),
        forward(http, delay, project, zone, token, forwardDeadline),
        recovery(http, delay, project, zone, token, this->deadline)
  {
    this->project.assign(project);
    this->zone.assign(zone);
    this->region.assign(region);
    this->token.assign(token);
  }

  static bool decodePlan(const ProviderElasticAddressPlan& encoded,
                         GcpElasticAddressPlanV1& plan,
                         const String *expectedProject = nullptr,
                         const String *expectedRegion = nullptr,
                         const String *expectedZone = nullptr)
  {
    plan = {};
    if (encoded.opaque.empty() || encoded.opaque.size() > ProviderElasticAddressPlan::maximumBytes ||
        BitseryEngine::deserializeSafe(encoded.opaque, plan) == false || plan.version != 1 ||
        plan.nonce == 0 || plan.project.empty() || plan.project.size() > maximumProjectBytes ||
        validResourceName(GcpComputeTransaction::view(plan.region)) == false ||
        validResourceName(GcpComputeTransaction::view(plan.targetZone)) == false ||
        GcpComputeTransaction::validDecimalID(plan.targetID) == false ||
        validResourceName(GcpComputeTransaction::view(plan.targetName)) == false ||
        plan.targetNic.empty() || plan.targetNic.size() > maximumFieldBytes ||
        plan.desiredName.empty() || validResourceName(GcpComputeTransaction::view(plan.desiredName)) == false ||
        (plan.createAllocation == false && plan.desiredAddress.empty()) ||
        plan.desiredTier.empty() || validNetworkTier(GcpComputeTransaction::view(plan.desiredTier)) == false ||
        plan.deliveryPrefix.network.is6 || plan.deliveryPrefix.cidr != 32 ||
        elasticPrefixIntentIsValid(plan.intent) == false ||
        plan.requestedAddress.size() > maximumFieldBytes ||
        validProviderPool(plan.requestedPool) == false ||
        (plan.intent == ElasticPrefixIntent::create && plan.requestedAddress.empty() == false) ||
        (plan.intent == ElasticPrefixIntent::any && plan.requestedAddress.empty()) ||
        (plan.requestedAddress.empty() == false && plan.requestedPool.empty() == false) ||
        plan.createAllocation != plan.requestedAddress.empty() ||
        (plan.createAllocation && plan.desiredPool != plan.requestedPool) ||
        (plan.createAllocation == false && plan.desiredAddress != plan.requestedAddress) ||
        (plan.createAllocation && plan.ownershipMarker.empty()) ||
        (plan.createAllocation == false && (plan.desiredAllocationID.empty() || plan.ownershipMarker.empty() == false)) ||
        (expectedProject && plan.project != *expectedProject) ||
        (expectedRegion && plan.region != *expectedRegion) ||
        (expectedZone && plan.targetZone != *expectedZone))
    {
      return false;
    }
    IPAddress desired;
    if (plan.desiredAddress.empty() == false && parseIPv4(plan.desiredAddress, desired) == false)
    {
      return false;
    }
    if (plan.createAllocation)
    {
      String suffix;
      suffix.assignItoh(plan.nonce);
      String expectedName;
      expectedName.assign("prodigy-eip-"_ctv);
      expectedName.append(suffix);
      if (plan.ownershipMarker != suffix || plan.desiredName != expectedName)
      {
        return false;
      }
    }
    const bool targetPriorPresent = plan.targetPriorName.empty() == false;
    if (targetPriorPresent != (plan.targetPriorAddress.empty() == false) ||
        targetPriorPresent != (plan.targetPriorTier.empty() == false) ||
        (targetPriorPresent && validNetworkTier(GcpComputeTransaction::view(plan.targetPriorTier)) == false) ||
        (targetPriorPresent && plan.targetPriorAddress != plan.desiredAddress &&
         (plan.targetPriorAllocationName.empty() || plan.targetPriorAllocationID.empty())))
    {
      return false;
    }
    const bool sourcePresent = plan.sourceInstance.empty() == false;
    const bool sourceValid = sourcePresent == (plan.sourceID.empty() == false) &&
                             sourcePresent == (plan.sourceNic.empty() == false) &&
                             sourcePresent == (plan.sourceConfig.empty() == false) &&
                             (sourcePresent == false ||
                              (plan.sourceProject == plan.project &&
                               validResourceName(GcpComputeTransaction::view(plan.sourceZone)) &&
                               validResourceName(GcpComputeTransaction::view(plan.sourceInstance)) &&
                               GcpComputeTransaction::validDecimalID(plan.sourceID)));
    const bool alreadySatisfied = plan.createAllocation == false && targetPriorPresent && sourcePresent &&
                                  plan.targetPriorAddress == plan.desiredAddress &&
                                  plan.targetPriorTier == plan.desiredTier &&
                                  plan.sourceProject == plan.project &&
                                  plan.sourceZone == plan.targetZone &&
                                  plan.sourceID == plan.targetID && plan.sourceNic == plan.targetNic &&
                                  plan.sourceConfig == plan.targetPriorName;
    return sourceValid && plan.alreadySatisfied == alreadySatisfied;
  }

  static bool planMatchesRequest(const GcpElasticAddressPlanV1& plan,
                                 const ProviderElasticAddressRequest& request,
                                 uint128_t transactionNonce)
  {
    const bool creates = request.requestedAddress.empty();
    return transactionNonce != 0 && plan.nonce == transactionNonce &&
           request.family == ExternalAddressFamily::ipv4 &&
           elasticPrefixIntentIsValid(request.intent) && plan.intent == request.intent &&
           plan.targetID == request.cloudID && plan.deliveryPrefix.equals(request.deliveryPrefix) &&
           plan.requestedAddress == request.requestedAddress &&
           plan.requestedPool == request.providerPool && validProviderPool(request.providerPool) &&
           (request.intent != ElasticPrefixIntent::create || request.requestedAddress.empty()) &&
           (request.intent != ElasticPrefixIntent::any || request.requestedAddress.empty() == false) &&
           (request.requestedAddress.empty() || request.providerPool.empty()) &&
           plan.createAllocation == creates &&
           (creates ? (plan.desiredAddress.empty() && plan.desiredPool == request.providerPool) :
                      (plan.desiredAddress == request.requestedAddress && request.providerPool.empty()));
  }

  void prepare(CoroutineStack *coro,
               const ProviderElasticAddressRequest& request,
               ProviderElasticAddressPlan& encoded,
               String& failure)
  {
    encoded = {};
    failure.clear();
    if (coro == nullptr || forward.runtimeAvailable() == false || forward.identityAvailable() == false ||
        request.family != ExternalAddressFamily::ipv4 || request.cloudID.empty() ||
        request.deliveryPrefix.network.is6 || request.deliveryPrefix.cidr != 32 ||
        elasticPrefixIntentIsValid(request.intent) == false ||
        (request.intent == ElasticPrefixIntent::create && request.requestedAddress.empty() == false) ||
        (request.intent == ElasticPrefixIntent::any && request.requestedAddress.empty()) ||
        (request.requestedAddress.empty() == false && request.providerPool.empty() == false) ||
        validProviderPool(request.providerPool) == false)
    {
      failure.assign("gcp elastic address prepare request invalid"_ctv);
      co_return;
    }

    GcpElasticAddressPlanV1 plan;
    plan.nonce = requestNonce;
    plan.project.assign(project);
    plan.region.assign(region);
    plan.targetZone.assign(zone);
    plan.targetID.assign(request.cloudID);
    plan.deliveryPrefix = request.deliveryPrefix;
    plan.intent = request.intent;
    plan.requestedAddress.assign(request.requestedAddress);
    plan.requestedPool.assign(request.providerPool);
    bool targetResolved = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          forward.resolveName(coro, plan.targetID, plan.targetName, targetResolved, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (targetResolved == false || failure.empty() == false)
    {
      co_return;
    }

    AccessConfig targetPrior;
    bool targetExists = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          fetchAccessConfig(coro, forward, plan.targetName, plan.targetID, nullptr, nullptr,
                            targetPrior, targetExists, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (targetExists == false || failure.empty() == false)
    {
      co_return;
    }
    plan.targetNic.assign(targetPrior.nic);
    plan.targetPriorName.assign(targetPrior.name);
    plan.targetPriorAddress.assign(targetPrior.address);
    plan.targetPriorTier.assign(targetPrior.networkTier);

    Address desired;
    bool desiredFound = false;
    if (request.requestedAddress.empty() == false)
    {
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            lookupAddress(coro, forward, request.requestedAddress, desired, desiredFound, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (failure.empty() == false || desiredFound == false)
      {
        if (failure.empty())
        {
          failure.assign("gcp requested elastic address not found"_ctv);
        }
        co_return;
      }
    }
    else
    {
      String suffix;
      suffix.assignItoh(requestNonce);
      desired.name.assign("prodigy-eip-"_ctv);
      desired.name.append(suffix);
      desired.networkTier.assign("PREMIUM"_ctv);
      desired.ipCollection.assign(request.providerPool);
      desired.ownershipMarker.assign(suffix);
      bool collision = false;
      Address existing;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            fetchAddress(coro, forward, desired.name, existing, collision, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (failure.empty() == false || collision)
      {
        if (failure.empty())
        {
          failure.assign("gcp elastic saga allocation name already exists"_ctv);
        }
        co_return;
      }
      plan.createAllocation = true;
    }
    plan.desiredName.assign(desired.name);
    plan.desiredAllocationID.assign(desired.cloudID);
    plan.desiredAddress.assign(desired.address);
    plan.desiredTier.assign(desired.networkTier);
    plan.desiredPool.assign(desired.ipCollection);
    plan.ownershipMarker.assign(desired.ownershipMarker);

    if (targetPrior.present() && targetPrior.address != desired.address)
    {
      Address targetPriorAllocation;
      bool priorReserved = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            lookupAddress(coro, forward, targetPrior.address, targetPriorAllocation, priorReserved, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (failure.empty() == false || priorReserved == false)
      {
        if (failure.empty())
        {
          failure.assign("gcp target prior address is not exactly restorable"_ctv);
        }
        co_return;
      }
      plan.targetPriorAllocationName.assign(targetPriorAllocation.name);
      plan.targetPriorAllocationID.assign(targetPriorAllocation.cloudID);
    }

    if (desired.user.present())
    {
      if (desired.user.project != project)
      {
        failure.assign("gcp elastic address source belongs to another project"_ctv);
        co_return;
      }
      GcpComputeTransaction source(http, delay, project, desired.user.zone, token, forwardDeadline);
      MultiCurlClient::Result sourceResult;
      bool sourceComplete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            source.fetchInstance(coro, desired.user.instance,
                                 "id,networkInterfaces(name,accessConfigs(name,natIP,networkTier))"_ctv,
                                 sourceResult, sourceComplete, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      simdjson::dom::parser parser;
      simdjson::dom::element document;
      String sourceID;
      String sourceText = sourceResult.body;
      AccessConfig sourcePrior;
      if (failure.empty() == false || sourceComplete == false ||
          parser.parse(sourceText.c_str(), sourceText.size()).get(document) ||
          prodigyJSONString(document["id"], sourceID) != simdjson::SUCCESS || sourceID.empty())
      {
        if (failure.empty())
        {
          failure.assign("gcp elastic source identity malformed"_ctv);
        }
        co_return;
      }
      String ownedSourceID;
      ownedSourceID.assign(sourceID);
      if (parseInterface(sourceResult.body, ownedSourceID, nullptr, &desired.address,
                         sourcePrior, failure) == false || sourcePrior.present() == false)
      {
        co_return;
      }
      plan.sourceProject.assign(project);
      plan.sourceZone.assign(desired.user.zone);
      plan.sourceInstance.assign(desired.user.instance);
      plan.sourceID.assign(ownedSourceID);
      plan.sourceNic.assign(sourcePrior.nic);
      plan.sourceConfig.assign(sourcePrior.name);
    }

    const bool targetAlreadyDesired = targetPrior.present() &&
                                      targetPrior.address == desired.address &&
                                      targetPrior.networkTier == desired.networkTier;
    plan.alreadySatisfied = targetAlreadyDesired && plan.sourceProject == plan.project &&
                            plan.sourceZone == plan.targetZone && plan.sourceID == plan.targetID &&
                            plan.sourceNic == plan.targetNic && plan.sourceConfig == plan.targetPriorName;
    if (targetAlreadyDesired && plan.alreadySatisfied == false)
    {
      failure.assign("gcp desired allocation user disagrees with preexisting target attachment"_ctv);
      co_return;
    }

    BitseryEngine::serialize(encoded.opaque, plan);
    if (encoded.opaque.size() > ProviderElasticAddressPlan::maximumBytes ||
        decodePlan(encoded, plan, &project, &region, &zone) == false ||
        planMatchesRequest(plan, request, requestNonce) == false)
    {
      encoded = {};
      failure.assign("gcp elastic address plan exceeds contract"_ctv);
    }
  }

  void apply(CoroutineStack *coro,
             const ProviderElasticAddressPlan& encoded,
             ProviderElasticAddressAssignment& assignment,
             String& failure)
  {
    assignment = {};
    failure.clear();
    GcpElasticAddressPlanV1 plan;
    if (coro == nullptr || decodePlan(encoded, plan, &project, &region, &zone) == false)
    {
      failure.assign("gcp elastic address plan invalid"_ctv);
      co_return;
    }

    Address desired;
    bool desiredExists = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          fetchAddress(coro, forward, plan.desiredName, desired, desiredExists, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (failure.empty() == false)
    {
      co_return;
    }
    if (desiredExists == false && plan.createAllocation)
    {
      Address requested;
      requested.name.assign(plan.desiredName);
      requested.networkTier.assign(plan.desiredTier);
      requested.ipCollection.assign(plan.desiredPool);
      requested.ownershipMarker.assign(plan.ownershipMarker);
      bool mayExist = false;
      bool allocated = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            allocate(coro, plan.desiredPool, plan.ownershipMarker, MutationStep::applyCreateAllocation,
                     requested, mayExist, allocated, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      desired = std::move(requested);
      desiredExists = allocated;
    }
    if (desiredExists == false || desired.name != plan.desiredName ||
        (plan.createAllocation && desired.ownershipMarker != plan.ownershipMarker) ||
        (plan.createAllocation == false && desired.cloudID != plan.desiredAllocationID) ||
        (plan.desiredAddress.empty() == false && desired.address != plan.desiredAddress) ||
        desired.networkTier != plan.desiredTier || desired.ipCollection != plan.desiredPool)
    {
      failure.assign("gcp elastic desired allocation identity changed"_ctv);
      co_return;
    }

    const bool sourceIsTarget = plan.sourceID == plan.targetID && plan.sourceZone == plan.targetZone;
    if (plan.sourceID.empty() == false && sourceIsTarget == false)
    {
      GcpComputeTransaction source(http, delay, project, plan.sourceZone, token, forwardDeadline);
      AccessConfig sourceCurrent;
      bool sourceExists = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            fetchAccessConfig(coro, source, plan.sourceInstance, plan.sourceID, &plan.sourceNic,
                              &desired.address, sourceCurrent, sourceExists, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (failure.empty() == false)
      {
        co_return;
      }
      if (sourceExists == false)
      {
        failure.assign("gcp elastic source instance disappeared"_ctv);
        co_return;
      }
      if (sourceExists && sourceCurrent.present())
      {
        if (sourceCurrent.name != plan.sourceConfig || sourceCurrent.networkTier != desired.networkTier)
        {
          failure.assign("gcp elastic source access config changed"_ctv);
          co_return;
        }
        bool attempted = false;
        bool absent = false;
        if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
              detach(coro, source, plan.sourceZone, plan.sourceInstance, plan.sourceID,
                     sourceCurrent, MutationStep::applyDetachSource, attempted, absent, failure);
            }))
        {
          co_await coro->suspendAtIndex(suspendIndex);
        }
        if (absent == false)
        {
          co_return;
        }
      }
      else
      {
        AccessConfig replacement;
        bool stillExists = false;
        if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
              fetchAccessConfig(coro, source, plan.sourceInstance, plan.sourceID, &plan.sourceNic,
                                nullptr, replacement, stillExists, failure);
            }))
        {
          co_await coro->suspendAtIndex(suspendIndex);
        }
        if (failure.empty() == false || stillExists == false || replacement.present())
        {
          if (failure.empty())
          {
            if (stillExists)
            {
              failure.assign("gcp elastic source was replaced after prepare"_ctv);
            }
            else
            {
              failure.assign("gcp elastic source instance disappeared"_ctv);
            }
          }
          co_return;
        }
      }
    }

    AccessConfig targetCurrent;
    bool targetExists = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          fetchAccessConfig(coro, forward, plan.targetName, plan.targetID, &plan.targetNic,
                            nullptr, targetCurrent, targetExists, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (targetExists == false || failure.empty() == false)
    {
      if (failure.empty())
      {
        failure.assign("gcp elastic target instance disappeared"_ctv);
      }
      co_return;
    }
    const bool desiredAttached = targetCurrent.present() && targetCurrent.address == desired.address &&
                                 targetCurrent.networkTier == desired.networkTier;
    if (desiredAttached == false && targetCurrent.present())
    {
      if (targetCurrent.name != plan.targetPriorName || targetCurrent.address != plan.targetPriorAddress ||
          targetCurrent.networkTier != plan.targetPriorTier)
      {
        failure.assign("gcp elastic target prior access config changed"_ctv);
        co_return;
      }
      if (targetCurrent.address != desired.address)
      {
        Address priorAllocation;
        bool priorExists = false;
        if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
              fetchAddress(coro, forward, plan.targetPriorAllocationName,
                           priorAllocation, priorExists, failure);
            }))
        {
          co_await coro->suspendAtIndex(suspendIndex);
        }
        if (failure.empty() == false || priorExists == false ||
            priorAllocation.cloudID != plan.targetPriorAllocationID ||
            priorAllocation.address != plan.targetPriorAddress || priorAllocation.user.present() == false)
        {
          if (failure.empty())
          {
            failure.assign("gcp elastic target prior allocation identity changed"_ctv);
          }
          co_return;
        }
      }
      bool attempted = false;
      bool absent = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            detach(coro, forward, plan.targetZone, plan.targetName, plan.targetID,
                   targetCurrent, MutationStep::applyDetachTargetPrior, attempted, absent, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (absent == false)
      {
        co_return;
      }
    }
    if (desiredAttached == false)
    {
      AccessConfig desiredConfig;
      desiredConfig.nic.assign(plan.targetNic);
      if (plan.targetPriorName.empty())
      {
        desiredConfig.name.assign("External NAT"_ctv);
      }
      else
      {
        desiredConfig.name.assign(plan.targetPriorName);
      }
      desiredConfig.address.assign(desired.address);
      desiredConfig.networkTier.assign(desired.networkTier);
      bool attempted = false;
      bool attached = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            attach(coro, forward, plan.targetZone, plan.targetName, plan.targetID, desiredConfig,
                   false, MutationStep::applyAttachDesired, attempted, attached, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (attached == false)
      {
        co_return;
      }
      targetCurrent = std::move(desiredConfig);
    }

    IPAddress address;
    if (parseIPv4(desired.address, address) == false)
    {
      failure.assign("gcp elastic desired address malformed after apply"_ctv);
      co_return;
    }
    assignment.assignedPrefix.network = address;
    assignment.assignedPrefix.cidr = 32;
    assignment.deliveryPrefix = plan.deliveryPrefix;
    assignment.allocationID.assign(desired.name);
    encodeAssociation(project, region, zone, plan.targetID, plan.targetName, targetCurrent,
                      desired, assignment.associationID);
    assignment.releaseOnRemove = plan.createAllocation;
  }

  void compensate(CoroutineStack *coro,
                  const ProviderElasticAddressPlan& encoded,
                  String& failure)
  {
    failure.clear();
    GcpElasticAddressPlanV1 plan;
    if (coro == nullptr || decodePlan(encoded, plan, &project, &region, &zone) == false)
    {
      failure.assign("gcp elastic compensation plan invalid"_ctv);
      co_return;
    }
    if (plan.alreadySatisfied)
    {
      co_return;
    }
    Address desired;
    bool desiredExists = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          fetchAddress(coro, recovery, plan.desiredName, desired, desiredExists, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (failure.empty() == false ||
        (desiredExists && ((plan.createAllocation && desired.ownershipMarker != plan.ownershipMarker) ||
                           (plan.createAllocation == false && desired.cloudID != plan.desiredAllocationID) ||
                           (plan.desiredAddress.empty() == false && desired.address != plan.desiredAddress) ||
                           desired.networkTier != plan.desiredTier ||
                           desired.ipCollection != plan.desiredPool)))
    {
      if (failure.empty())
      {
        failure.assign("gcp elastic compensation allocation identity changed"_ctv);
      }
      co_return;
    }
    const String& desiredAddress = desiredExists ? desired.address : plan.desiredAddress;

    AccessConfig targetCurrent;
    bool targetExists = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          fetchAccessConfig(coro, recovery, plan.targetName, plan.targetID, &plan.targetNic,
                            nullptr, targetCurrent, targetExists, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (failure.empty() == false)
    {
      co_return;
    }
    if (targetExists && targetCurrent.present() && targetCurrent.address == desiredAddress)
    {
      String expectedName;
      if (plan.targetPriorName.empty())
      {
        expectedName.assign("External NAT"_ctv);
      }
      else
      {
        expectedName.assign(plan.targetPriorName);
      }
      if (targetCurrent.name != expectedName || targetCurrent.address != desiredAddress ||
          targetCurrent.networkTier != plan.desiredTier)
      {
        failure.assign("gcp elastic compensation target changed"_ctv);
        co_return;
      }
      bool attempted = false;
      bool absent = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            detach(coro, recovery, plan.targetZone, plan.targetName, plan.targetID,
                   targetCurrent, MutationStep::compensateDetachDesired, attempted, absent, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (absent == false)
      {
        co_return;
      }
      targetCurrent = {};
    }
    if (targetExists && targetCurrent.present() &&
        (targetCurrent.name != plan.targetPriorName || targetCurrent.address != plan.targetPriorAddress ||
         targetCurrent.networkTier != plan.targetPriorTier))
    {
      failure.assign("gcp elastic compensation target changed"_ctv);
      co_return;
    }
    if (targetExists && targetCurrent.present() == false && plan.targetPriorName.empty() == false)
    {
      Address priorAllocation;
      bool priorExists = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            fetchAddress(coro, recovery, plan.targetPriorAllocationName,
                         priorAllocation, priorExists, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (failure.empty() == false || priorExists == false ||
          priorAllocation.cloudID != plan.targetPriorAllocationID ||
          priorAllocation.address != plan.targetPriorAddress || priorAllocation.user.present())
      {
        if (failure.empty())
        {
          failure.assign("gcp elastic compensation target prior allocation changed"_ctv);
        }
        co_return;
      }
      AccessConfig prior;
      prior.nic.assign(plan.targetNic);
      prior.name.assign(plan.targetPriorName);
      prior.address.assign(plan.targetPriorAddress);
      prior.networkTier.assign(plan.targetPriorTier);
      bool attempted = false;
      bool attached = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            attach(coro, recovery, plan.targetZone, plan.targetName, plan.targetID, prior,
                   false, MutationStep::compensateRestoreTarget, attempted, attached, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (attached == false)
      {
        co_return;
      }
    }

    const bool sourceIsTarget = plan.sourceID == plan.targetID && plan.sourceZone == plan.targetZone;
    if (plan.sourceID.empty() == false && sourceIsTarget == false)
    {
      GcpComputeTransaction source(http, delay, project, plan.sourceZone, token, deadline);
      AccessConfig sourceCurrent;
      bool sourceExists = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            fetchAccessConfig(coro, source, plan.sourceInstance, plan.sourceID, &plan.sourceNic,
                              nullptr, sourceCurrent, sourceExists, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (failure.empty() == false || sourceExists == false)
      {
        if (failure.empty())
        {
          failure.assign("gcp elastic compensation source instance disappeared"_ctv);
        }
        co_return;
      }
      if (sourceCurrent.present() &&
          (sourceCurrent.name != plan.sourceConfig || sourceCurrent.address != desiredAddress ||
           sourceCurrent.networkTier != plan.desiredTier))
      {
        failure.assign("gcp elastic compensation source changed"_ctv);
        co_return;
      }
      if (sourceCurrent.present() == false)
      {
        AccessConfig sourcePrior;
        sourcePrior.nic.assign(plan.sourceNic);
        sourcePrior.name.assign(plan.sourceConfig);
        sourcePrior.address.assign(desiredAddress);
        sourcePrior.networkTier.assign(plan.desiredTier);
        bool attempted = false;
        bool attached = false;
        if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
              attach(coro, source, plan.sourceZone, plan.sourceInstance, plan.sourceID, sourcePrior,
                     false, MutationStep::compensateRestoreSource, attempted, attached, failure);
            }))
        {
          co_await coro->suspendAtIndex(suspendIndex);
        }
        if (attached == false)
        {
          co_return;
        }
      }
    }

    if (plan.createAllocation && desiredExists)
    {
      bool attempted = false;
      bool removed = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            deleteAllocation(coro, recovery, desired, MutationStep::compensateDeleteAllocation,
                             attempted, removed, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (removed == false && failure.empty())
      {
        failure.assign("gcp elastic compensation allocation remains"_ctv);
      }
    }
  }

  void release(CoroutineStack *coro,
               const ProviderElasticAddressRelease& release,
               String& failure)
  {
    ProviderElasticAddressRelease owned;
    owned.transactionNonce = release.transactionNonce;
    owned.kind = release.kind;
    owned.assignedPrefix = release.assignedPrefix;
    owned.allocationID.assign(release.allocationID);
    owned.associationID.assign(release.associationID);
    owned.releaseOnRemove = release.releaseOnRemove;
    failure.clear();
    if (owned.kind != RoutablePrefixKind::elastic)
    {
      co_return;
    }
    if (owned.transactionNonce == 0 || owned.transactionNonce != requestNonce)
    {
      failure.assign("gcp elastic release transaction nonce invalid"_ctv);
      co_return;
    }
    if (coro == nullptr || recovery.runtimeAvailable() == false || recovery.identityAvailable() == false)
    {
      failure.assign("gcp elastic release runtime unavailable"_ctv);
      co_return;
    }
    if (owned.allocationID.size() > maximumResourceNameBytes ||
        (owned.allocationID.empty() == false &&
         validResourceName(GcpComputeTransaction::view(owned.allocationID)) == false))
    {
      failure.assign("gcp elastic release allocation identity malformed"_ctv);
      co_return;
    }
    if (owned.releaseOnRemove && owned.associationID.empty())
    {
      failure.assign("gcp elastic owned allocation release requires immutable association token"_ctv);
      co_return;
    }

    String releasedAddress;
    const bool prefixRequired = owned.associationID.empty() == false || owned.releaseOnRemove;
    if (prefixRequired &&
        (owned.assignedPrefix.network.is6 || owned.assignedPrefix.cidr != 32 ||
         ClusterMachine::renderIPAddressLiteral(owned.assignedPrefix.network, releasedAddress) == false))
    {
      failure.assign("gcp elastic release prefix malformed"_ctv);
      co_return;
    }

    Association association;
    bool associationDetached = false;
    if (owned.associationID.empty() == false)
    {
      if (parseAssociation(owned.associationID, association, failure) == false)
      {
        co_return;
      }
      if (association.project != project || association.region != region || association.zone != zone)
      {
        failure.assign("gcp elastic association token scope mismatch"_ctv);
        co_return;
      }
      if (owned.allocationID.empty() || association.allocation != owned.allocationID ||
          association.address != releasedAddress)
      {
        failure.assign("gcp elastic release tuple does not match association token"_ctv);
        co_return;
      }
      Address allocation;
      bool allocationExists = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            fetchAddress(coro, recovery, owned.allocationID, allocation, allocationExists, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (failure.empty() == false)
      {
        co_return;
      }
      if (allocationExists == false)
      {
        co_return;
      }
      if (allocation.cloudID != association.allocationCloudID ||
          allocation.address != association.address ||
          allocation.networkTier != association.networkTier)
      {
        failure.assign("gcp elastic release allocation identity changed"_ctv);
        co_return;
      }
      if (allocation.user.present() &&
          (allocation.user.project != project || allocation.user.zone != zone ||
           allocation.user.instance != association.instance))
      {
        failure.assign("gcp elastic release allocation user changed"_ctv);
        co_return;
      }
      if (allocation.user.present() == false)
      {
        if (owned.releaseOnRemove == false)
        {
          co_return;
        }
      }

      AccessConfig current;
      bool targetExists = false;
      if (allocation.user.present())
      {
        if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
              fetchAccessConfig(coro,
                                recovery,
                                association.instance,
                                association.cloudID,
                                &association.nic,
                                nullptr,
                                current,
                                targetExists,
                                failure);
            }))
        {
          co_await coro->suspendAtIndex(suspendIndex);
        }
      }
      if (failure.empty() == false)
      {
        co_return;
      }
      if (allocation.user.present() && targetExists && current.present())
      {
        if (current.name != association.config || current.address != association.address ||
            current.networkTier != association.networkTier)
        {
          failure.assign("gcp elastic release refused changed target association"_ctv);
          co_return;
        }
        bool absent = false;
        bool detachAttempted = false;
        if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
              detach(coro,
                     recovery,
                     zone,
                     association.instance,
                     association.cloudID,
                     current,
                     MutationStep::releaseDetachTarget,
                     detachAttempted,
                     absent,
                     failure);
            }))
        {
          co_await coro->suspendAtIndex(suspendIndex);
        }
        if (absent == false)
        {
          if (detachAttempted)
          {
            GcpComputeTransaction::appendPartial(association.instance, failure);
          }
          co_return;
        }
        associationDetached = true;
      }
    }

    if (owned.releaseOnRemove && owned.allocationID.empty() == false)
    {
      Address expected;
      expected.name = owned.allocationID;
      expected.address = releasedAddress;
      if (association.allocation.empty() == false)
      {
        expected.cloudID = association.allocationCloudID;
        expected.networkTier = association.networkTier;
      }
      bool deleteAttempted = false;
      bool removed = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            deleteAllocation(coro, recovery, expected, MutationStep::releaseDeleteAllocation,
                             deleteAttempted, removed, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (removed == false && failure.empty())
      {
        failure.assign("gcp elastic allocation release postcondition not observed"_ctv);
      }
      if (removed == false && (deleteAttempted || associationDetached))
      {
        GcpComputeTransaction::appendPartial(owned.allocationID, failure);
        if (associationDetached)
        {
          GcpComputeTransaction::appendPartial(association.instance, failure);
        }
      }
    }
  }
};
