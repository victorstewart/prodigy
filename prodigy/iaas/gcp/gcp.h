#pragma once

#include <prodigy/iaas/iaas.h>
#include <services/debug.h>
#include <prodigy/iaas/bootstrap.ssh.h>
#include <prodigy/iaas/gcp/gcp.cluster.destroy.h>
#include <prodigy/iaas/gcp/gcp.elastic.address.h>
#include <prodigy/iaas/gcp/gcp.labels.h>
#include <prodigy/iaas/gcp/gcp.lifecycle.h>
#include <prodigy/iaas/gcp/gcp.managed.template.h>
#include <prodigy/iaas/gcp/gcp.provisioning.h>
#include <prodigy/brain/base.h>
#include <prodigy/cluster.machine.helpers.h>
#include <prodigy/command.capture.h>
#include <prodigy/host.http.operation.h>
#include <prodigy/netdev.detect.h>
#include <services/filesystem.h>
#include <simdjson.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <limits>
#include <unistd.h>

constexpr static size_t gcpMetadataResponseBytes = 64 * 1024;

static inline MultiCurlClient::Request gcpMetadataRequest(
    const String& path,
    MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now(),
    MultiCurlClient::TimePoint operationDeadline = MultiCurlClient::TimePoint::max())
{
  MultiCurlClient::Request request = {};
  request.url.assign("http://169.254.169.254"_ctv);
  request.url.append(path);
  request.resolveHost.assign("169.254.169.254"_ctv);
  request.authority.assign("metadata.google.internal"_ctv);
  request.httpPolicy = MultiCurlClient::HttpPolicy::requireHttp1;
  request.family = AsyncDnsResolver::Family::ipv4;
  request.requireTls = false;
  request.connectTimeout = std::chrono::seconds(3);
  const MultiCurlClient::TimePoint requestLimit = now + std::chrono::seconds(3);
  request.overallDeadline = operationDeadline < requestLimit ? operationDeadline : requestLimit;
  request.responseBytes = gcpMetadataResponseBytes;
  request.headers.push_back({"Metadata-Flavor"_ctv, "Google"_ctv});
  request.originPolicy.requiredScheme.assign("http"_ctv);
  request.originPolicy.requiredHost.assign("169.254.169.254"_ctv);
  request.originPolicy.requiredAuthority.assign("metadata.google.internal"_ctv);
  request.originPolicy.requiredService.assign("80"_ctv);
  request.originPolicy.requiredResolveHost.assign("169.254.169.254"_ctv);
  return request;
}

static inline bool gcpSuccessfulResponse(const MultiCurlClient::Result& result)
{
  return result.status == MultiCurlClient::Status::success &&
         result.statusCode >= 200 && result.statusCode < 300;
}

static inline void gcpHostRequest(ProdigyHostHttpOperation::Submission client,
                              CoroutineStack *coro,
                              MultiCurlClient::Request request,
                              MultiCurlClient::Result& result,
                              bool& success)
{
  success = false;
  if (coro == nullptr || client.submit == nullptr || client.cancel == nullptr)
  {
    co_return;
  }

  ProdigyHostHttpOperation operation(client, *coro);
  if (operation.submit(std::move(request)) == false)
  {
    co_return;
  }
  if (operation.mustSuspend())
  {
    co_await coro->suspend();
  }
  if (operation.hasResult() == false)
  {
    co_return;
  }
  result = operation.takeResult();
  success = gcpSuccessfulResponse(result);
}

static inline void gcpReadNeuronStartupMetro(ProdigyHostHttpOperation::Submission client,
                                             CoroutineStack *coro,
                                             String& metro)
{
  metro.clear();
  if (coro == nullptr)
  {
    co_return;
  }

  MultiCurlClient::Result result = {};
  bool success = false;
  if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
        gcpHostRequest(client, coro, gcpMetadataRequest("/computeMetadata/v1/instance/zone"_ctv), result, success);
      }))
  {
    co_await coro->suspendAtIndex(suspendIndex);
  }
  if (success)
  {
    String& zone = result.body;
    // Zone metadata ends in the full metro name, for example us-central1-a.
    int64_t slash = -1;
    for (int64_t index = int64_t(zone.size()) - 1; index >= 0; --index)
    {
      if (zone[uint64_t(index)] == '/')
      {
        slash = index;
        break;
      }
    }
    metro = (slash >= 0)
                ? zone.substr(uint64_t(slash + 1), zone.size() - uint64_t(slash + 1), Copy::yes)
                : std::move(zone);
  }
}

class GcpNeuronIaaS : public NeuronIaaS {
public:

  void gatherSelfData(CoroutineStack *coro, uint128_t& uuid, String& metro, bool& isBrain, EthDevice& eth, IPAddress& private4) override
  {
    // Runtime persistence owns the canonical brain UUID.
    uuid = 0;
    if (providerServices.http)
    {
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            gcpReadNeuronStartupMetro(providerServices.http, coro, metro);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
    }
    else
    {
      metro.clear();
    }
    // Runtime-aware bootstrap state owns the brain role; provider metadata does not.
    isBrain = false;

    // Network: use EthDevice to compute gateway and private IPv4
    String deviceName;
    if (prodigyResolvePrimaryNetworkDevice(deviceName) == false)
    {
      basics_log("gcp primary network device detection failed\n");
      std::abort();
    }
    eth.setDevice(deviceName);
    private4.is6 = false;
    private4.v4 = eth.getPrivate4();
  }

};

uint32_t gcpHashRackIdentity(std::string_view s);
bool gcpGetNestedElement(simdjson::dom::element root, std::initializer_list<std::string_view> path, simdjson::dom::element& value);
bool gcpExtractZoneName(const String& zoneURL, String& zoneText);
uint32_t gcpExtractRackUUID(simdjson::dom::element inst, const String& zoneText);

class GcpBrainIaaS : public BrainIaaS {
private:

  ProdigyRuntimeEnvironmentConfig runtimeEnvironment;
  String bootstrapSSHUser;
  String bootstrapSSHPrivateKeyPath;
  String bootstrapSSHPublicKey;
  Vault::SSHKeyPackage bootstrapSSHHostKeyPackage;
  BrainIaaSMachineProvisioningProgressReporter provisioningProgress;
  String projectId;
  String zone;
  String region;
  String token;
  String provisioningClusterUUIDTagValue;
  int64_t tokenExpiryMs {0};
  int64_t tokenResolvedAtMs {0};
  String lastAuthFailure;
  bytell_hash_map<String, MachineSchemaCpuCapability> validationMachineCapabilities;
  Vector<String> validationZoneCpuPlatforms;
  bool spotTerminationCheckActive = false;
  bool validationAuthReady = false;
  bool validationZoneCpuPlatformsReady = false;
  uint32_t inventoryOperations = 0;
  uint32_t provisioningOperations = 0;
  uint32_t lifecycleOperations = 0;
  uint32_t labelOperations = 0;
  uint32_t clusterDestroyOperations = 0;
  uint32_t elasticOperations = 0;

  static void appendPercentEncoded(String& output, const String& value)
  {
    constexpr static char hex[] = "0123456789ABCDEF";

    for (uint64_t index = 0; index < value.size(); ++index)
    {
      uint8_t byte = value[index];
      bool unreserved = (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == '.' || byte == '~';

      if (unreserved)
      {
        output.append(byte);
      }
      else
      {
        output.append('%');
        output.append(uint8_t(hex[(byte >> 4) & 0x0f]));
        output.append(uint8_t(hex[byte & 0x0f]));
      }
    }
  }

  static void appendPageTokenQuery(String& url, const String& pageToken)
  {
    if (pageToken.size() == 0)
    {
      return;
    }

    bool hasQuery = false;
    for (uint64_t index = 0; index < url.size(); ++index)
    {
      if (url[index] == '?')
      {
        hasQuery = true;
        break;
      }
    }

    url.append(hasQuery ? '&' : '?');
    url.append("pageToken="_ctv);
    appendPercentEncoded(url, pageToken);
  }

  static void appendEscapedJSONStringLiteral(String& output, std::string_view value)
  {
    String stringView = {};
    stringView.setInvariant(value.data(), value.size());
    prodigyAppendEscapedJSONStringLiteral(output, stringView);
  }

  static std::string_view stringViewFor(const String& value)
  {
    return std::string_view(reinterpret_cast<const char *>(value.data()), value.size());
  }

  static bool parseAPIErrorMessage(const String& response, String& message)
  {
    message.clear();

    if (response.size() == 0)
    {
      return false;
    }

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    String responseText = {};
    responseText.assign(response);
    if (parser.parse(responseText.c_str(), responseText.size()).get(doc))
    {
      return false;
    }

    if (auto error = doc["error"]; error.is_object())
    {
      std::string_view text;
      if (!error["message"].get(text))
      {
        message.assign(text);
        return true;
      }

      if (auto errors = error["errors"]; errors.is_array())
      {
        for (auto entry : errors.get_array())
        {
          if (!entry["message"].get(text))
          {
            message.assign(text);
            return true;
          }
        }
      }
    }

    return false;
  }

  static uint64_t findFirstChar(const String& text, uint8_t value, uint64_t start = 0)
  {
    for (uint64_t index = start; index < text.size(); ++index)
    {
      if (text[index] == value)
      {
        return index;
      }
    }

    return uint64_t(-1);
  }

  static uint64_t findSubstring(const String& text, String needle)
  {
    if (needle.size() == 0 || text.size() < needle.size())
    {
      return uint64_t(-1);
    }

    uint64_t limit = text.size() - needle.size();
    for (uint64_t index = 0; index <= limit; ++index)
    {
      if (memcmp(text.data() + index, needle.data(), needle.size()) == 0)
      {
        return index;
      }
    }

    return uint64_t(-1);
  }

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

    return findSubstring(lowerInput, lowerNeedle) != uint64_t(-1);
  }

public:

  constexpr static size_t metadataResponseBytes = gcpMetadataResponseBytes;
  constexpr static size_t spotPageResponseBytes = 4 * 1024 * 1024;
  constexpr static size_t spotCheckMaxPages = 256;
  constexpr static size_t spotCheckMaxResultsPerPage = 500;
  constexpr static size_t spotCheckMaxDecommissionedIDs = spotCheckMaxPages * spotCheckMaxResultsPerPage;
  constexpr static size_t spotPageTokenBytes = 2048;
  constexpr static std::chrono::seconds spotCheckTimeout = std::chrono::seconds(15);
  constexpr static size_t inventoryPageResponseBytes = 8 * 1024 * 1024;
  constexpr static size_t inventoryMaxPages = 256;
  constexpr static size_t inventoryMaxResultsPerPage = 500;
  constexpr static size_t inventoryMaxInstances = inventoryMaxPages * inventoryMaxResultsPerPage;
  constexpr static size_t inventoryPageTokenBytes = 2048;
  constexpr static std::chrono::seconds inventoryTimeout = std::chrono::seconds(15);
  constexpr static size_t validationResponseBytes = 1024 * 1024;

  static MultiCurlClient::TimePoint requestDeadline(MultiCurlClient::TimePoint now,
                                                    MultiCurlClient::TimePoint operationDeadline)
  {
    const MultiCurlClient::TimePoint requestLimit = now + std::chrono::seconds(3);
    return operationDeadline < requestLimit ? operationDeadline : requestLimit;
  }

  static MultiCurlClient::Request validationRequest(const String& url,
                                                    const String& host,
                                                    const String& accessToken,
                                                    MultiCurlClient::Method method,
                                                    const String *body,
                                                    MultiCurlClient::TimePoint now,
                                                    MultiCurlClient::TimePoint operationDeadline)
  {
    MultiCurlClient::Request request = {};
    request.url = url;
    request.resolveHost = host;
    request.authority = host;
    request.method = method;
    request.family = AsyncDnsResolver::Family::ipv4;
    request.caSource = MultiCurlClient::CaSource::system;
    request.connectTimeout = std::chrono::seconds(3);
    MultiCurlClient::TimePoint requestLimit = now + (method == MultiCurlClient::Method::get ? std::chrono::seconds(3) : std::chrono::seconds(8));
    request.overallDeadline = operationDeadline < requestLimit ? operationDeadline : requestLimit;
    request.responseBytes = validationResponseBytes;
    String authorization = {};
    authorization.snprintf<"Bearer {}"_ctv>(accessToken);
    request.headers.push_back({"Authorization"_ctv, std::move(authorization)});
    if (body)
    {
      request.body = *body;
      request.headers.push_back({"Content-Type"_ctv, "application/json"_ctv});
    }
    request.originPolicy.requiredScheme.assign("https"_ctv);
    request.originPolicy.requiredHost = host;
    request.originPolicy.requiredAuthority = host;
    request.originPolicy.requiredService.assign("443"_ctv);
    request.originPolicy.requiredResolveHost = host;
    return request;
  }

  static MultiCurlClient::Request computeValidationRequest(const String& url,
                                                           const String& accessToken,
                                                           MultiCurlClient::TimePoint now,
                                                           MultiCurlClient::TimePoint operationDeadline)
  {
    return validationRequest(url, "compute.googleapis.com"_ctv, accessToken,
                             MultiCurlClient::Method::get, nullptr, now, operationDeadline);
  }

  static MultiCurlClient::Request iamValidationRequest(const String& url,
                                                       const String& host,
                                                       const String& accessToken,
                                                       const String& body,
                                                       MultiCurlClient::TimePoint now,
                                                       MultiCurlClient::TimePoint operationDeadline)
  {
    return validationRequest(url, host, accessToken, MultiCurlClient::Method::post,
                             &body, now, operationDeadline);
  }

  static bool canRequestSpotPage(size_t requestedPages,
                                 size_t decommissionedIDs,
                                 const String& pageToken,
                                 const bytell_hash_set<String>& requestedPageTokens)
  {
    return requestedPages < spotCheckMaxPages &&
           decommissionedIDs < spotCheckMaxDecommissionedIDs &&
           pageToken.size() <= spotPageTokenBytes &&
           requestedPageTokens.contains(pageToken) == false;
  }

  static MultiCurlClient::Request metadataRequest(const String& path,
                                                  MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now(),
                                                  MultiCurlClient::TimePoint operationDeadline = MultiCurlClient::TimePoint::max())
  {
    return gcpMetadataRequest(path, now, operationDeadline);
  }

  static MultiCurlClient::Request spotInstancesRequest(const String& project,
                                                       const String& instanceZone,
                                                       const String& accessToken,
                                                       const String& pageToken,
                                                       MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now(),
                                                       MultiCurlClient::TimePoint operationDeadline = MultiCurlClient::TimePoint::max())
  {
    MultiCurlClient::Request request = {};
    request.url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances?filter=labels.app%3Aprodigy&maxResults=500&fields=items(id,labels,scheduling(preemptible,provisioningModel),status),nextPageToken"_ctv>(project, instanceZone);
    appendPageTokenQuery(request.url, pageToken);
    request.resolveHost.assign("compute.googleapis.com"_ctv);
    request.authority.assign("compute.googleapis.com"_ctv);
    request.family = AsyncDnsResolver::Family::ipv4;
    request.caSource = MultiCurlClient::CaSource::system;
    request.connectTimeout = std::chrono::seconds(3);
    request.overallDeadline = requestDeadline(now, operationDeadline);
    request.responseBytes = spotPageResponseBytes;
    String authorization = {};
    authorization.snprintf<"Bearer {}"_ctv>(accessToken);
    request.headers.push_back({"Authorization"_ctv, std::move(authorization)});
    request.originPolicy.requiredScheme.assign("https"_ctv);
    request.originPolicy.requiredHost.assign("compute.googleapis.com"_ctv);
    request.originPolicy.requiredAuthority.assign("compute.googleapis.com"_ctv);
    request.originPolicy.requiredService.assign("443"_ctv);
    request.originPolicy.requiredResolveHost.assign("compute.googleapis.com"_ctv);
    return request;
  }

  static MultiCurlClient::Request inventoryInstancesRequest(const String& project,
                                                            const String& instanceZone,
                                                            const String& accessToken,
                                                            const String& pageToken,
                                                            MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now(),
                                                            MultiCurlClient::TimePoint operationDeadline = MultiCurlClient::TimePoint::max())
  {
    MultiCurlClient::Request request = {};
    request.url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances?filter=labels.app%3Aprodigy&maxResults=500&fields=items(id,creationTimestamp,labels,networkInterfaces(networkIP,ipv6Address,accessConfigs(natIP,externalIpv6)),zone,scheduling(preemptible,provisioningModel),reservationAffinity(consumeReservationType),resourceStatus(physicalHost,physicalHostTopology(cluster,block,subblock)),disks(boot,initializeParams(sourceImage),source)),nextPageToken"_ctv>(project, instanceZone);
    appendPageTokenQuery(request.url, pageToken);
    request.resolveHost.assign("compute.googleapis.com"_ctv);
    request.authority.assign("compute.googleapis.com"_ctv);
    request.family = AsyncDnsResolver::Family::ipv4;
    request.caSource = MultiCurlClient::CaSource::system;
    request.connectTimeout = std::chrono::seconds(3);
    request.overallDeadline = requestDeadline(now, operationDeadline);
    request.responseBytes = inventoryPageResponseBytes;
    String authorization = {};
    authorization.snprintf<"Bearer {}"_ctv>(accessToken);
    request.headers.push_back({"Authorization"_ctv, std::move(authorization)});
    request.originPolicy.requiredScheme.assign("https"_ctv);
    request.originPolicy.requiredHost.assign("compute.googleapis.com"_ctv);
    request.originPolicy.requiredAuthority.assign("compute.googleapis.com"_ctv);
    request.originPolicy.requiredService.assign("443"_ctv);
    request.originPolicy.requiredResolveHost.assign("compute.googleapis.com"_ctv);
    return request;
  }

  static bool canRequestInventoryPage(size_t requestedPages,
                                      size_t instances,
                                      const String& pageToken,
                                      const bytell_hash_set<String>& requestedPageTokens)
  {
    return requestedPages < inventoryMaxPages &&
           instances < inventoryMaxInstances &&
           pageToken.size() <= inventoryPageTokenBytes &&
           requestedPageTokens.contains(pageToken) == false;
  }

  template <typename Visitor>
  static void readInventoryPages(ProdigyHostHttpOperation::Submission client,
                                 CoroutineStack *coro,
                                 String project,
                                 String instanceZone,
                                 String accessToken,
                                 MultiCurlClient::TimePoint deadline,
                                 Visitor visitor,
                                 String& failure)
  {
    failure.clear();
    if (coro == nullptr || client.submit == nullptr || client.cancel == nullptr)
    {
      failure.assign("gcp inventory HTTP client unavailable"_ctv);
      co_return;
    }

    String nextPageToken = {};
    bytell_hash_set<String> requestedPageTokens = {};
    size_t requestedPages = 0;
    size_t instances = 0;
    for (;;)
    {
      if (MultiCurlClient::Clock::now() >= deadline)
      {
        failure.assign("gcp inventory deadline exceeded"_ctv);
        co_return;
      }
      if (requestedPages >= inventoryMaxPages || instances >= inventoryMaxInstances)
      {
        failure.assign("gcp inventory result limit exceeded"_ctv);
        co_return;
      }
      if (nextPageToken.size() > inventoryPageTokenBytes)
      {
        failure.assign("gcp inventory page token too large"_ctv);
        co_return;
      }
      if (requestedPageTokens.contains(nextPageToken))
      {
        failure.assign("gcp inventory repeated page token"_ctv);
        co_return;
      }
      requestedPageTokens.insert(nextPageToken);
      ++requestedPages;

      MultiCurlClient::Result result = {};
      bool requestSucceeded = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            gcpHostRequest(client,
                       coro,
                       inventoryInstancesRequest(project, instanceZone, accessToken,
                                                 nextPageToken, MultiCurlClient::Clock::now(), deadline),
                       result,
                       requestSucceeded);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (requestSucceeded == false)
      {
        failure.assign("gcp inventory request failed"_ctv);
        co_return;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element document;
      if (parser.parse(result.body.c_str(), result.body.size()).get(document))
      {
        failure.assign("gcp inventory response parse failed"_ctv);
        co_return;
      }

      simdjson::dom::element items = {};
      simdjson::error_code itemsError = document["items"].get(items);
      if (itemsError && itemsError != simdjson::NO_SUCH_FIELD)
      {
        failure.assign("gcp inventory items field invalid"_ctv);
        co_return;
      }
      if (!itemsError)
      {
        if (items.is_array() == false)
        {
          failure.assign("gcp inventory items field invalid"_ctv);
          co_return;
        }
        for (auto instance : items.get_array())
        {
          if (++instances > inventoryMaxInstances ||
              (isProdigyInstance(instance) && visitor(instance) == false))
          {
            failure.assign("gcp inventory result limit exceeded"_ctv);
            co_return;
          }
        }
      }

      String pageToken;
      simdjson::error_code pageTokenError = prodigyJSONString(document["nextPageToken"], pageToken);
      if (pageTokenError == simdjson::NO_SUCH_FIELD)
      {
        co_return;
      }
      if (pageTokenError)
      {
        failure.assign("gcp inventory page token invalid"_ctv);
        co_return;
      }
      nextPageToken.assign(pageToken);
      if (nextPageToken.size() == 0)
      {
        co_return;
      }
    }
  }

  static bool successfulResponse(const MultiCurlClient::Result& result)
  {
    return gcpSuccessfulResponse(result);
  }

  static bool parseMachineArchitectureText(const String& text, MachineCpuArchitecture& architecture)
  {
    String lower = {};
    lowercaseString(text, lower);
    return parseMachineCpuArchitecture(lower, architecture);
  }

  static bool resolveMachineArchitecture(const String& machineTypeName, const String& architectureText, MachineCpuArchitecture& architecture)
  {
    (void)machineTypeName;
    if (architectureText.size() > 0)
    {
      return parseMachineArchitectureText(architectureText, architecture);
    }

    // GCP now omits `architecture` on at least some default x86 machine
    // types such as `e2-medium`. Treat the missing field as x86_64 instead
    // of failing cluster creation before launch.
    architecture = MachineCpuArchitecture::x86_64;
    return true;
  }

private:

  static bool gcpCpuPlatformMatchesArchitecture(const String& cpuPlatform, MachineCpuArchitecture architecture)
  {
    if (architecture == MachineCpuArchitecture::aarch64)
    {
      return stringContainsInsensitive(cpuPlatform, "ampere") || stringContainsInsensitive(cpuPlatform, "arm");
    }

    if (architecture == MachineCpuArchitecture::x86_64)
    {
      return gcpCpuPlatformMatchesArchitecture(cpuPlatform, MachineCpuArchitecture::aarch64) == false;
    }

    return false;
  }

  static void gcpAppendCpuPlatformIsaFeatures(MachineCpuArchitecture architecture, const String& cpuPlatform, Vector<String>& features)
  {
    if (architecture == MachineCpuArchitecture::x86_64)
    {
      prodigyAppendNormalizedIsaFeature(features, "sse"_ctv);
      prodigyAppendNormalizedIsaFeature(features, "sse2"_ctv);
      prodigyAppendNormalizedIsaFeature(features, "ssse3"_ctv);
      prodigyAppendNormalizedIsaFeature(features, "sse4_2"_ctv);
      prodigyAppendNormalizedIsaFeature(features, "avx"_ctv);

      if (stringContainsInsensitive(cpuPlatform, "haswell") || stringContainsInsensitive(cpuPlatform, "broadwell") || stringContainsInsensitive(cpuPlatform, "skylake") || stringContainsInsensitive(cpuPlatform, "cascade") || stringContainsInsensitive(cpuPlatform, "ice") || stringContainsInsensitive(cpuPlatform, "sapphire") || stringContainsInsensitive(cpuPlatform, "genoa") || stringContainsInsensitive(cpuPlatform, "turin") || stringContainsInsensitive(cpuPlatform, "rome") || stringContainsInsensitive(cpuPlatform, "milan") || stringContainsInsensitive(cpuPlatform, "epyc") || stringContainsInsensitive(cpuPlatform, "zen"))
      {
        prodigyAppendNormalizedIsaFeature(features, "avx2"_ctv);
      }

      if (stringContainsInsensitive(cpuPlatform, "skylake") || stringContainsInsensitive(cpuPlatform, "cascade") || stringContainsInsensitive(cpuPlatform, "ice") || stringContainsInsensitive(cpuPlatform, "sapphire") || stringContainsInsensitive(cpuPlatform, "genoa") || stringContainsInsensitive(cpuPlatform, "turin"))
      {
        prodigyAppendNormalizedIsaFeature(features, "avx512f"_ctv);
      }

      return;
    }

    if (architecture == MachineCpuArchitecture::aarch64)
    {
      prodigyAppendNormalizedIsaFeature(features, "asimd"_ctv);
      if (stringContainsInsensitive(cpuPlatform, "sve2"))
      {
        prodigyAppendNormalizedIsaFeature(features, "sve2"_ctv);
      }
      if (stringContainsInsensitive(cpuPlatform, "sve"))
      {
        prodigyAppendNormalizedIsaFeature(features, "sve"_ctv);
      }
    }
  }

  static void intersectIsaFeatures(Vector<String>& base, const Vector<String>& candidate)
  {
    Vector<String> filtered = {};
    filtered.reserve(base.size());
    for (const String& feature : base)
    {
      if (prodigyIsaFeaturesContain(candidate, feature))
      {
        filtered.push_back(feature);
      }
    }
    base = std::move(filtered);
  }

  bool resolveConfiguredProjectZone()
  {
    if (runtimeEnvironment.providerScope.size() > 0)
    {
      String scope = {};
      scope.assign(runtimeEnvironment.providerScope);

      if (projectId.size() == 0)
      {
        String projectPrefix = "projects/"_ctv;
        uint64_t projectPrefixOffset = findSubstring(scope, projectPrefix);
        if (projectPrefixOffset != uint64_t(-1))
        {
          uint64_t projectStart = projectPrefixOffset + projectPrefix.size();
          uint64_t projectEnd = findFirstChar(scope, '/', projectStart);
          if (projectEnd == uint64_t(-1))
          {
            projectId.assign(scope.substr(projectStart, scope.size() - projectStart, Copy::yes));
          }
          else
          {
            projectId.assign(scope.substr(projectStart, projectEnd - projectStart, Copy::yes));
          }
        }
        else
        {
          uint64_t slash = findFirstChar(scope, '/');
          if (slash != uint64_t(-1))
          {
            projectId.assign(scope.substr(0, slash, Copy::yes));
          }
          else
          {
            projectId.assign(scope);
          }
        }
      }

      if (zone.size() == 0)
      {
        String zonePrefix = "zones/"_ctv;
        uint64_t zonePrefixOffset = findSubstring(scope, zonePrefix);
        if (zonePrefixOffset != uint64_t(-1))
        {
          uint64_t zoneStart = zonePrefixOffset + zonePrefix.size();
          uint64_t zoneEnd = findFirstChar(scope, '/', zoneStart);
          if (zoneEnd == uint64_t(-1))
          {
            zone.assign(scope.substr(zoneStart, scope.size() - zoneStart, Copy::yes));
          }
          else
          {
            zone.assign(scope.substr(zoneStart, zoneEnd - zoneStart, Copy::yes));
          }
        }
        else
        {
          int64_t lastSlash = -1;
          for (int64_t index = int64_t(scope.size()) - 1; index >= 0; --index)
          {
            if (scope[uint64_t(index)] == '/')
            {
              lastSlash = index;
              break;
            }
          }

          if (lastSlash >= 0 && uint64_t(lastSlash + 1) < scope.size())
          {
            zone.assign(scope.substr(uint64_t(lastSlash + 1), scope.size() - uint64_t(lastSlash + 1), Copy::yes));
          }
        }
      }
    }

    trimTrailingAsciiWhitespace(projectId);
    trimTrailingAsciiWhitespace(zone);

    if (zone.size() == 0 && thisNeuron && thisNeuron->metro.size() > 0)
    {
      zone = thisNeuron->metro;
      trimTrailingAsciiWhitespace(zone);
    }

    return projectId.size() > 0 && zone.size() > 0;
  }

  static void assignMetadataZone(String metadataZone, String& output)
  {
    trimTrailingAsciiWhitespace(metadataZone);
    int64_t slash = -1;
    for (int64_t index = int64_t(metadataZone.size()) - 1; index >= 0; --index)
    {
      if (metadataZone[uint64_t(index)] == '/')
      {
        slash = index;
        break;
      }
    }
    output = (slash >= 0)
                 ? metadataZone.substr(uint64_t(slash + 1), metadataZone.size() - uint64_t(slash + 1), Copy::yes)
                 : metadataZone;
    trimTrailingAsciiWhitespace(output);
  }

protected:

  virtual ProdigyHostHttpOperation::Submission hostHttpSubmission(void)
  {
    return providerServices.http;
  }

  void hostRequest(CoroutineStack *coro, MultiCurlClient::Request request, MultiCurlClient::Result& result, bool& success)
  {
    ProdigyHostHttpOperation::Submission client = hostHttpSubmission();
    if (client.submit == nullptr || client.cancel == nullptr)
    {
      success = false;
      co_return;
    }
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          gcpHostRequest(client, coro, std::move(request), result, success);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }

  void ensureProjectZoneAsync(CoroutineStack *coro,
                              bool& success,
                              MultiCurlClient::TimePoint operationDeadline = MultiCurlClient::TimePoint::max())
  {
    success = resolveConfiguredProjectZone();
    if (success)
    {
      co_return;
    }

    if (projectId.size() == 0)
    {
      MultiCurlClient::Result result = {};
      bool requestSucceeded = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            hostRequest(coro, metadataRequest("/computeMetadata/v1/project/project-id"_ctv,
                                          MultiCurlClient::Clock::now(),
                                          operationDeadline), result, requestSucceeded);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (requestSucceeded)
      {
        projectId = std::move(result.body);
        trimTrailingAsciiWhitespace(projectId);
      }
    }

    if (zone.size() == 0)
    {
      MultiCurlClient::Result result = {};
      bool requestSucceeded = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            hostRequest(coro, metadataRequest("/computeMetadata/v1/instance/zone"_ctv,
                                          MultiCurlClient::Clock::now(),
                                          operationDeadline), result, requestSucceeded);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (requestSucceeded)
      {
        assignMetadataZone(std::move(result.body), zone);
      }
    }

    success = projectId.size() > 0 && zone.size() > 0;
  }

  static void trimTrailingAsciiWhitespace(String& value)
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

  bool usesRefreshableBootstrapAccessToken() const
  {
    return runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand.size() > 0;
  }

  void clearCachedProviderAccessToken()
  {
    token.clear();
    tokenExpiryMs = 0;
    tokenResolvedAtMs = 0;
    lastAuthFailure.clear();
    validationMachineCapabilities.clear();
    validationZoneCpuPlatforms.clear();
    validationAuthReady = false;
    validationZoneCpuPlatformsReady = false;
  }

  ProdigyHostTask<bool> resolveRefreshableBootstrapAccessToken(CoroutineStack *coro,
                                                                String *failure = nullptr)
  {
    if (failure)
    {
      failure->clear();
    }
    lastAuthFailure.clear();

    String refreshedToken = {};
    String detail = {};
    if (co_await ProdigyCommandCapture::run(coro,
                                            runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand,
                                            refreshedToken,
                                            providerServices.operationDeadline,
                                            &detail) == false)
    {
      clearCachedProviderAccessToken();
      lastAuthFailure.assign("gcp bootstrap access token refresh failed"_ctv);
      if (detail.size() > 0)
      {
        lastAuthFailure.append(": "_ctv);
        lastAuthFailure.append(detail);
      }
      if (runtimeEnvironment.gcp.bootstrapAccessTokenRefreshFailureHint.size() > 0)
      {
        lastAuthFailure.append(" | "_ctv);
        lastAuthFailure.append(runtimeEnvironment.gcp.bootstrapAccessTokenRefreshFailureHint);
      }

      if (failure)
      {
        failure->assign(lastAuthFailure);
      }
      co_return false;
    }

    if (refreshedToken.size() == 0)
    {
      clearCachedProviderAccessToken();
      lastAuthFailure.assign("gcp bootstrap access token refresh failed: command returned empty output"_ctv);
      if (runtimeEnvironment.gcp.bootstrapAccessTokenRefreshFailureHint.size() > 0)
      {
        lastAuthFailure.append(" | "_ctv);
        lastAuthFailure.append(runtimeEnvironment.gcp.bootstrapAccessTokenRefreshFailureHint);
      }

      if (failure)
      {
        failure->assign(lastAuthFailure);
      }
      co_return false;
    }

    int64_t now = Time::now<TimeResolution::ms>();
    token.assign(refreshedToken);
    tokenResolvedAtMs = now;
    tokenExpiryMs = now + 30 * 1000;
    lastAuthFailure.clear();
    if (failure)
    {
      failure->clear();
    }
    co_return true;
  }

protected:

  bool ensureTokenFastPath(bool& resolved, String *failure = nullptr)
  {
    resolved = true;
    if (failure)
    {
      failure->clear();
    }
    lastAuthFailure.clear();

    if (usesRefreshableBootstrapAccessToken())
    {
      int64_t now = Time::now<TimeResolution::ms>();
      if (token.size() > 0 && now < tokenExpiryMs)
      {
        return true;
      }

      if (token.size() == 0 && tokenResolvedAtMs == 0 && runtimeEnvironment.providerCredentialMaterial.size() > 0)
      {
        token.assign(runtimeEnvironment.providerCredentialMaterial);
        tokenResolvedAtMs = now;
        tokenExpiryMs = now + 30 * 1000;
        return true;
      }

      resolved = false;
      return false;
    }

    if (runtimeEnvironment.providerCredentialMaterial.size() > 0)
    {
      token = runtimeEnvironment.providerCredentialMaterial;
      tokenResolvedAtMs = std::numeric_limits<int64_t>::max();
      tokenExpiryMs = std::numeric_limits<int64_t>::max();
      return true;
    }

    if (Time::now<TimeResolution::ms>() + 30 * 1000 < tokenExpiryMs && token.size() > 0)
    {
      return true;
    }

    resolved = false;
    return false;
  }

  bool parseMetadataAccessToken(const String& response, String *failure = nullptr)
  {
    simdjson::dom::parser parser;
    simdjson::dom::element document;
    String responseText = {};
    responseText.assign(response);
    if (parser.parse(responseText.c_str(), responseText.size()).get(document))
    {
      if (failure)
      {
        failure->assign("gcp metadata token parse failed"_ctv);
      }
      return false;
    }

    String accessToken;
    uint64_t expiresInSeconds = 0;
    if (prodigyJSONString(document["access_token"], accessToken) != simdjson::SUCCESS ||
        document["expires_in"].get(expiresInSeconds) || accessToken.empty() || expiresInSeconds <= 30 ||
        expiresInSeconds > uint64_t(std::numeric_limits<int64_t>::max() / 1000))
    {
      if (failure)
      {
        failure->assign("gcp metadata token response missing fields"_ctv);
      }
      return false;
    }

    const int64_t now = Time::now<TimeResolution::ms>();
    const int64_t usableLifetimeMs = int64_t(expiresInSeconds) * 1000 - 30 * 1000;
    if (now > std::numeric_limits<int64_t>::max() - usableLifetimeMs)
    {
      if (failure)
      {
        failure->assign("gcp metadata token expiry out of range"_ctv);
      }
      return false;
    }

    token.assign(accessToken);
    tokenResolvedAtMs = now;
    tokenExpiryMs = now + usableLifetimeMs;
    return true;
  }

  void ensureTokenAsync(CoroutineStack *coro,
                        bool& success,
                        String *failure = nullptr,
                        MultiCurlClient::TimePoint operationDeadline = MultiCurlClient::TimePoint::max())
  {
    bool resolved = false;
    success = ensureTokenFastPath(resolved, failure);
    if (resolved)
    {
      co_return;
    }

    if (usesRefreshableBootstrapAccessToken())
    {
      success = co_await resolveRefreshableBootstrapAccessToken(coro, failure);
      co_return;
    }

    MultiCurlClient::Result result = {};
    bool requestSucceeded = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          hostRequest(coro,
                  metadataRequest("/computeMetadata/v1/instance/service-accounts/default/token"_ctv,
                                  MultiCurlClient::Clock::now(),
                                  operationDeadline),
                  result,
                  requestSucceeded);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (requestSucceeded == false)
    {
      if (failure)
      {
        failure->assign("gcp metadata token fetch failed"_ctv);
      }
      co_return;
    }
    success = parseMetadataAccessToken(result.body, failure);
  }

  template <typename Visitor>
  void walkInventory(CoroutineStack *coro, Visitor visitor, String& failure)
  {
    failure.clear();
    const MultiCurlClient::TimePoint deadline = MultiCurlClient::Clock::now() + inventoryTimeout;
    bool projectZoneReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureProjectZoneAsync(coro, projectZoneReady, deadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (projectZoneReady == false)
    {
      failure.assign("gcp inventory project/zone unavailable"_ctv);
      co_return;
    }

    bool tokenReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureTokenAsync(coro, tokenReady, nullptr, deadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (tokenReady == false)
    {
      failure.assign("gcp inventory token unavailable"_ctv);
      co_return;
    }

    if (!providerServices.http)
    {
      failure.assign("gcp inventory HTTP client unavailable"_ctv);
      co_return;
    }
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          readInventoryPages(providerServices.http,
                             coro, projectId, zone, token, deadline, visitor, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }

public:

  void configureRuntimeEnvironment(const ProdigyRuntimeEnvironmentConfig& config) override
  {
    prodigyOwnRuntimeEnvironmentConfig(config, runtimeEnvironment);
    projectId.clear();
    zone.clear();
    region.clear();
    clearCachedProviderAccessToken();
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

  bool hasActiveControlOperations(void) const override
  {
    return spotTerminationCheckActive || inventoryOperations > 0 ||
           provisioningOperations > 0 || lifecycleOperations > 0 || labelOperations > 0 ||
           clusterDestroyOperations > 0 || elasticOperations > 0;
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

  static uint128_t hash_uuid(const String& text)
  {
    uint128_t u = 0;
    for (uint64_t index = 0; index < text.size(); ++index)
    {
      u = (u * 131) + text[index];
    }
    return u;
  }

  static int64_t parseRFC3339Ms(const String& v)
  {
    if (v.size() < 19)
    {
      return Time::now<TimeResolution::ms>();
    }

    auto parseDecimalRange = [&](size_t offset, size_t count, int& out) -> bool {
      if ((offset + count) > v.size())
      {
        return false;
      }

      out = 0;
      for (size_t index = 0; index < count; ++index)
      {
        char c = v[offset + index];
        if (c < '0' || c > '9')
        {
          return false;
        }

        out = (out * 10) + int(c - '0');
      }

      return true;
    };

    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;
    if (parseDecimalRange(0, 4, year) == false || parseDecimalRange(5, 2, month) == false || parseDecimalRange(8, 2, day) == false || parseDecimalRange(11, 2, hour) == false || parseDecimalRange(14, 2, minute) == false || parseDecimalRange(17, 2, second) == false)
    {
      return Time::now<TimeResolution::ms>();
    }

    struct tm tmv = {};
    tmv.tm_year = year - 1900;
    tmv.tm_mon = month - 1;
    tmv.tm_mday = day;
    tmv.tm_hour = hour;
    tmv.tm_min = minute;
    tmv.tm_sec = second;
    tmv.tm_isdst = 0;

    size_t cursor = 19;
    int64_t millis = 0;
    if (cursor < v.size() && v[cursor] == '.')
    {
      cursor += 1;
      int digits = 0;
      while (cursor < v.size() && v[cursor] >= '0' && v[cursor] <= '9')
      {
        if (digits < 3)
        {
          millis = (millis * 10) + int64_t(v[cursor] - '0');
        }

        digits += 1;
        cursor += 1;
      }

      while (digits > 0 && digits < 3)
      {
        millis *= 10;
        digits += 1;
      }
    }

    int64_t timezoneOffsetSeconds = 0;
    if (cursor < v.size() && (v[cursor] == 'Z' || v[cursor] == 'z'))
    {
      cursor += 1;
    }
    else if (cursor < v.size() && (v[cursor] == '+' || v[cursor] == '-'))
    {
      int tzHours = 0;
      int tzMinutes = 0;
      char sign = v[cursor];
      if (parseDecimalRange(cursor + 1, 2, tzHours) == false)
      {
        return Time::now<TimeResolution::ms>();
      }

      size_t tzMinuteOffset = cursor + 3;
      if (tzMinuteOffset < v.size() && v[tzMinuteOffset] == ':')
      {
        tzMinuteOffset += 1;
      }

      if (parseDecimalRange(tzMinuteOffset, 2, tzMinutes) == false)
      {
        return Time::now<TimeResolution::ms>();
      }

      timezoneOffsetSeconds = int64_t((tzHours * 60) + tzMinutes) * 60;
      if (sign == '-')
      {
        timezoneOffsetSeconds *= -1;
      }
    }

    time_t secs = 0;
#ifdef _GNU_SOURCE
    secs = timegm(&tmv);
#else
    char *oldtz = getenv("TZ");
    setenv("TZ", "UTC", 1);
    tzset();
    secs = mktime(&tmv);
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

    return (int64_t(secs) - timezoneOffsetSeconds) * 1000LL + millis;
  }

  static bool deriveRegionFromZone(const String& zoneText, String& regionText)
  {
    regionText.clear();
    int64_t dash = zoneText.rfindChar('-');
    if (dash <= 0)
    {
      return false;
    }

    regionText.assign(zoneText.substr(0, uint64_t(dash), Copy::yes));
    return regionText.size() > 0;
  }

private:

  static MachineLifetime deriveLifetimeFromInstance(simdjson::dom::element inst)
  {
    if (auto scheduling = inst["scheduling"]; scheduling.is_object())
    {
      std::string_view provisioningModel;
      if (!scheduling["provisioningModel"].get(provisioningModel) && provisioningModel == "SPOT")
      {
        return MachineLifetime::spot;
      }

      bool preemptible = false;
      if (!scheduling["preemptible"].get(preemptible) && preemptible)
      {
        return MachineLifetime::spot;
      }
    }

    if (auto reservationAffinity = inst["reservationAffinity"]; reservationAffinity.is_object())
    {
      std::string_view consumeReservationType;
      if (!reservationAffinity["consumeReservationType"].get(consumeReservationType) && consumeReservationType != "NO_RESERVATION")
      {
        return MachineLifetime::reserved;
      }
    }

    return MachineLifetime::ondemand;
  }

  static bool isProdigyInstance(simdjson::dom::element inst)
  {
    if (auto labels = inst["labels"]; labels.is_object())
    {
      std::string_view app;
      if (!labels["app"].get(app) && app == "prodigy")
      {
        return true;
      }
    }

    return false;
  }

  static bool isBrainInstance(simdjson::dom::element inst)
  {
    if (auto labels = inst["labels"]; labels.is_object())
    {
      std::string_view brain;
      if (!labels["brain"].get(brain) && (brain == "true" || brain == "1"))
      {
        return true;
      }
    }

    return false;
  }

  static bool isSpotInstance(simdjson::dom::element inst)
  {
    return deriveLifetimeFromInstance(inst) == MachineLifetime::spot;
  }

public:

  static bool parseSpotTerminationPage(const String& response,
                                       Vector<String>& decommissionedIDs,
                                       String& nextPageToken,
                                       size_t maximumDecommissionedIDs = spotCheckMaxDecommissionedIDs)
  {
    nextPageToken.clear();
    simdjson::dom::parser parser;
    simdjson::dom::element document;
    String responseText = {};
    responseText.assign(response);
    if (parser.parse(responseText.c_str(), responseText.size()).get(document))
    {
      return false;
    }

    if (auto items = document["items"]; items.is_array())
    {
      for (auto instance : items.get_array())
      {
        if (isProdigyInstance(instance) == false || isSpotInstance(instance) == false)
        {
          continue;
        }

        String status;
        if (prodigyJSONString(instance["status"], status) != simdjson::SUCCESS ||
            status != "TERMINATED"_ctv)
        {
          continue;
        }

        String id;
        if (prodigyJSONString(instance["id"], id) == simdjson::SUCCESS)
        {
          if (decommissionedIDs.size() >= maximumDecommissionedIDs)
          {
            return false;
          }
          decommissionedIDs.emplace_back(String(id));
        }
      }
    }

    String pageToken;
    if (prodigyJSONString(document["nextPageToken"], pageToken) == simdjson::SUCCESS)
    {
      nextPageToken.assign(pageToken);
    }
    return true;
  }

private:

  Machine *buildMachineFromInstance(simdjson::dom::element inst)
  {
    Machine *m = new Machine();
    String id;
    (void)prodigyJSONString(inst["id"], id);
    m->cloudID.assign(id);
    m->uuid = hash_uuid(id);
    m->lifetime = deriveLifetimeFromInstance(inst);
    String creationTimestamp;
    if (prodigyJSONString(inst["creationTimestamp"], creationTimestamp) == simdjson::SUCCESS)
    {
      m->creationTimeMs = parseRFC3339Ms(creationTimestamp);
    }
    else
    {
      m->creationTimeMs = Time::now<TimeResolution::ms>();
    }
    // brain label
    m->isBrain = isBrainInstance(inst);
    // private4
    if (auto nics = inst["networkInterfaces"]; nics.is_array())
    {
      for (auto nic : nics.get_array())
      {
        String nip;
        if (prodigyJSONString(nic["networkIP"], nip) == simdjson::SUCCESS)
        {
          String privateText = nip;
          m->privateAddress.assign(privateText);
          IPAddress p;
          inet_pton(AF_INET, privateText.c_str(), &p.v4);
          m->private4 = p.v4;
        }

        String ipv6Address;
        if (m->privateAddress.size() == 0 &&
            prodigyJSONString(nic["ipv6Address"], ipv6Address) == simdjson::SUCCESS)
        {
          m->privateAddress.assign(ipv6Address);
        }

        if (auto accessConfigs = nic["accessConfigs"]; accessConfigs.is_array())
        {
          for (auto access : accessConfigs.get_array())
          {
            String natIP;
            if (prodigyJSONString(access["natIP"], natIP) == simdjson::SUCCESS)
            {
              m->publicAddress.assign(natIP);
              m->sshAddress.assign(natIP);
              break;
            }

            String externalIpv6;
            if (m->publicAddress.size() == 0 &&
                prodigyJSONString(access["externalIpv6"], externalIpv6) == simdjson::SUCCESS)
            {
              m->publicAddress.assign(externalIpv6);
              if (m->sshAddress.size() == 0)
              {
                m->sshAddress.assign(externalIpv6);
              }
            }
          }
        }

        break;
      }
    }
    String zoneText = {};
    String zoneURL;
    if (prodigyJSONString(inst["zone"], zoneURL) == simdjson::SUCCESS)
    {
      (void)gcpExtractZoneName(zoneURL, zoneText);
    }
    if (zoneText.size() > 0)
    {
      m->zone = zoneText;
      if (region.size() > 0)
      {
        m->region = region;
      }
      else
      {
        (void)deriveRegionFromZone(zoneText, m->region);
      }
    }
    else if (region.size() > 0)
    {
      m->region = region;
    }
    m->rackUUID = gcpExtractRackUUID(inst, zoneText);
    if (m->sshAddress.size() == 0)
    {
      m->sshAddress = m->privateAddress;
    }
    // capture current image URI from boot disk when available
    if (auto disks = inst["disks"]; disks.is_array())
    {
      for (auto d : disks.get_array())
      {
        bool boot = false;
        (void)d["boot"].get(boot);
        if (!boot)
        {
          continue;
        }
        // Prefer initializeParams.sourceImage (template image) but fall back to source
        if (auto ip = d["initializeParams"]; ip.is_object())
        {
          String img;
          if (prodigyJSONString(ip["sourceImage"], img) == simdjson::SUCCESS)
          {
            m->currentImageURI.assign(img);
          }
        }
        if (m->currentImageURI.size() == 0)
        {
          String src;
          if (prodigyJSONString(d["source"], src) == simdjson::SUCCESS)
          {
            m->currentImageURI.assign(src);
          }
        }
        break;
      }
    }

    // Configure the Neuron path from the resolved machine peer address.
    prodigyConfigureMachineNeuronEndpoint(*m, thisNeuron);
    if (bootstrapSSHPrivateKeyPath.size() > 0)
    {
      m->sshUser = bootstrapSSHUser;
      m->sshPrivateKeyPath = bootstrapSSHPrivateKeyPath;
      m->sshHostPublicKeyOpenSSH = bootstrapSSHHostKeyPackage.publicKeyOpenSSH;
    }
    return m;
  }

  static void assignValidationRequestFailure(const MultiCurlClient::Result& result, const char *fallback, String& error)
  {
    if (parseAPIErrorMessage(result.body, error))
    {
      return;
    }
    if (result.status == MultiCurlClient::Status::deadlineExceeded)
    {
      error.assign("gcp validation deadline exceeded"_ctv);
    }
    else if (result.status == MultiCurlClient::Status::success)
    {
      error.snprintf<"{} (HTTP {itoa})"_ctv>(String(fallback), uint32_t(result.statusCode));
    }
    else
    {
      error.assign(fallback);
    }
  }

  void ensureValidationAuth(CoroutineStack *coro, MultiCurlClient::TimePoint deadline, String& error)
  {
    error.clear();
    if (validationAuthReady)
    {
      co_return;
    }
    ProdigyHostHttpOperation::Submission client = hostHttpSubmission();
    if (coro == nullptr || client.submit == nullptr || client.cancel == nullptr)
    {
      error.assign("gcp validation HTTP client unavailable"_ctv);
      co_return;
    }
    if (MultiCurlClient::Clock::now() >= deadline)
    {
      error.assign("gcp validation deadline exceeded"_ctv);
      co_return;
    }
    bool projectZoneReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureProjectZoneAsync(coro, projectZoneReady, deadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (projectZoneReady == false)
    {
      error.assign("gcp validation project/zone unavailable"_ctv);
      co_return;
    }

    bool tokenReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureTokenAsync(coro, tokenReady, &error, deadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (tokenReady == false)
    {
      if (error.size() == 0)
      {
        error.assign("gcp validation token unavailable"_ctv);
      }
      co_return;
    }
    validationAuthReady = true;
  }

  void ensureValidationZoneCpuPlatforms(CoroutineStack *coro, MultiCurlClient::TimePoint deadline, String& error)
  {
    if (validationZoneCpuPlatformsReady)
    {
      co_return;
    }

    String url = {};
    url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}?fields=availableCpuPlatforms"_ctv>(projectId, zone);
    MultiCurlClient::Result result = {};
    bool success = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          hostRequest(coro, computeValidationRequest(url, token, MultiCurlClient::Clock::now(), deadline), result, success);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (success == false)
    {
      assignValidationRequestFailure(result, "gcp zone cpu platform lookup failed", error);
      co_return;
    }

    simdjson::dom::parser parser;
    simdjson::dom::element document = {};
    if (parser.parse(result.body.c_str(), result.body.size()).get(document))
    {
      error.assign("gcp zone cpu platform response parse failed"_ctv);
      co_return;
    }
    validationZoneCpuPlatforms.clear();
    if (document["availableCpuPlatforms"].is_array())
    {
      for (auto item : document["availableCpuPlatforms"].get_array())
      {
        String platform;
        if (prodigyJSONString(item, platform) == simdjson::SUCCESS && platform.size() > 0)
        {
          validationZoneCpuPlatforms.emplace_back(platform);
        }
      }
    }
    validationZoneCpuPlatformsReady = true;
  }

  void testIamPermissions(CoroutineStack *coro,
                          const String& url,
                          const String& host,
                          const char *const *permissions,
                          uint32_t count,
                          const char *label,
                          MultiCurlClient::TimePoint deadline,
                          bool& success,
                          String& error)
  {
    success = false;
    String body = {};
    body.append("{\"permissions\":["_ctv);
    for (uint32_t index = 0; index < count; ++index)
    {
      if (index > 0)
      {
        body.append(',');
      }
      String permission = {};
      permission.assign(permissions[index]);
      prodigyAppendEscapedJSONStringLiteral(body, permission);
    }
    body.append("]}"_ctv);

    MultiCurlClient::Result result = {};
    bool requestSucceeded = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          hostRequest(coro, iamValidationRequest(url, host, token, body, MultiCurlClient::Clock::now(), deadline), result, requestSucceeded);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (requestSucceeded == false)
    {
      assignValidationRequestFailure(result, "gcp iam permissions test failed", error);
      co_return;
    }

    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    if (parser.parse(result.body.c_str(), result.body.size()).get(doc))
    {
      error.assign("gcp iam permissions response parse failed"_ctv);
      co_return;
    }

    String missing = {};
    for (uint32_t index = 0; index < count; ++index)
    {
      bool found = false;
      if (auto returned = doc["permissions"]; returned.is_array())
      {
        for (auto entry : returned.get_array())
        {
          String text;
          if (prodigyJSONString(entry, text) == simdjson::SUCCESS &&
              text.equal(permissions[index], strlen(permissions[index])))
          {
            found = true;
            break;
          }
        }
      }

      if (found == false)
      {
        if (missing.size() == 0)
        {
          missing.snprintf<"gcp {} missing permissions: "_ctv>(String(label));
        }
        else
        {
          missing.append(", "_ctv);
        }
        missing.append(String(permissions[index]));
      }
    }

    if (missing.size() > 0)
    {
      error = missing;
      co_return;
    }

    error.clear();
    success = true;
  }

public:

  void boot(void) override {}

  uint32_t supportedMachineKindsMask() const override
  {
    return 2u;
  }

  bool supportsAutoProvision() const override
  {
    return true;
  }

  bool supportsAuthoritativeMachineSchemaCpuCapabilityInference(void) const override
  {
    return true;
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
      error.assign("gcp preflight requires a vm machine schema with vmImageURI and providerMachineType"_ctv);
      co_return;
    }

    if (preflight.gcpServiceAccountEmail.size() == 0)
    {
      error.assign("gcp preflight requires gcp.serviceAccountEmail"_ctv);
      co_return;
    }
    if (coro == nullptr)
    {
      error.assign("gcp preflight coroutine required"_ctv);
      co_return;
    }

    MultiCurlClient::TimePoint deadline = providerServices.operationDeadline;
    if (deadline == MultiCurlClient::TimePoint::max())
    {
      deadline = MultiCurlClient::Clock::now() + std::chrono::seconds(30);
    }
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureValidationAuth(coro, deadline, error);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (error.size() > 0)
    {
      co_return;
    }

    constexpr static const char *projectPermissions[] = {
        "compute.disks.create",
        "compute.disks.delete",
        "compute.instanceTemplates.create",
        "compute.instanceTemplates.delete",
        "compute.instanceTemplates.get",
        "compute.instanceTemplates.useReadOnly",
        "compute.instances.create",
        "compute.instances.delete",
        "compute.instances.get",
        "compute.instances.list",
        "compute.instances.setLabels",
        "compute.instances.setMetadata",
        "compute.instances.setServiceAccount",
        "compute.machineTypes.get",
        "compute.networks.get",
        "compute.subnetworks.get",
        "compute.subnetworks.use",
        "compute.subnetworks.useExternalIp",
        "compute.zones.get",
    };
    String projectURL = {};
    projectURL.snprintf<"https://cloudresourcemanager.googleapis.com/v1/projects/{}:testIamPermissions"_ctv>(projectId);
    String projectError = {};
    bool projectOK = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          testIamPermissions(coro, projectURL, "cloudresourcemanager.googleapis.com"_ctv,
                             projectPermissions, uint32_t(sizeof(projectPermissions) / sizeof(projectPermissions[0])),
                             "project", deadline, projectOK, projectError);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }

    constexpr static const char *serviceAccountPermissions[] = {"iam.serviceAccounts.actAs"};
    String serviceAccountURL = {};
    serviceAccountURL.snprintf<"https://iam.googleapis.com/v1/projects/{}/serviceAccounts/"_ctv>(projectId);
    appendPercentEncoded(serviceAccountURL, preflight.gcpServiceAccountEmail);
    serviceAccountURL.append(":testIamPermissions"_ctv);
    String serviceAccountError = {};
    bool serviceAccountOK = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          testIamPermissions(coro, serviceAccountURL, "iam.googleapis.com"_ctv,
                             serviceAccountPermissions, uint32_t(sizeof(serviceAccountPermissions) / sizeof(serviceAccountPermissions[0])),
                             "service account", deadline, serviceAccountOK, serviceAccountError);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }

    if (projectOK == false || serviceAccountOK == false)
    {
      error.clear();
      if (projectOK == false)
      {
        error.append(projectError);
      }
      if (serviceAccountOK == false)
      {
        if (error.size() > 0)
        {
          error.append("; "_ctv);
        }
        error.append(serviceAccountError);
      }
      co_return;
    }

    error.clear();
  }

  void inferMachineSchemaCpuCapability(CoroutineStack *coro, const MachineConfig& config, MachineSchemaCpuCapability& capability, String& error) override
  {
    capability = {};
    error.clear();
    if (coro == nullptr)
    {
      error.assign("gcp schema cpu inference coroutine required"_ctv);
      co_return;
    }

    if (config.providerMachineType.size() == 0)
    {
      error.assign("gcp schema cpu inference requires providerMachineType"_ctv);
      co_return;
    }

    auto cached = validationMachineCapabilities.find(config.providerMachineType);
    if (cached != validationMachineCapabilities.end())
    {
      capability = cached->second;
      co_return;
    }

    MultiCurlClient::TimePoint deadline = providerServices.operationDeadline;
    if (deadline == MultiCurlClient::TimePoint::max())
    {
      deadline = MultiCurlClient::Clock::now() + std::chrono::seconds(15);
    }
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureValidationAuth(coro, deadline, error);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (error.size() > 0)
    {
      co_return;
    }

    String machineTypeUrl = {};
    machineTypeUrl.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/machineTypes/{}?fields=name,architecture"_ctv>(
        projectId,
        zone,
        config.providerMachineType);

    MultiCurlClient::Result machineTypeResult = {};
    bool machineTypeSuccess = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          hostRequest(coro, computeValidationRequest(machineTypeUrl, token, MultiCurlClient::Clock::now(), deadline), machineTypeResult, machineTypeSuccess);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (machineTypeSuccess == false)
    {
      assignValidationRequestFailure(machineTypeResult, "gcp machineTypes lookup failed", error);
      co_return;
    }

    simdjson::dom::parser parser;
    simdjson::dom::element doc = {};
    if (parser.parse(machineTypeResult.body.c_str(), machineTypeResult.body.size()).get(doc))
    {
      error.assign("gcp machineTypes response parse failed"_ctv);
      co_return;
    }

    String architectureText = {};
    String architectureView;
    if (prodigyJSONString(doc["architecture"], architectureView) == simdjson::SUCCESS)
    {
      architectureText.assign(architectureView);
    }
    MachineSchemaCpuCapability inferred = {};
    if (resolveMachineArchitecture(config.providerMachineType, architectureText, inferred.architecture) == false)
    {
      error.snprintf<"gcp machineTypes architecture '{}' unsupported for machineType '{}'"_ctv>(architectureText, config.providerMachineType);
      co_return;
    }

    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureValidationZoneCpuPlatforms(coro, deadline, error);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (error.size() > 0)
    {
      co_return;
    }

    Vector<String> compatiblePlatforms = {};
    for (const String& platform : validationZoneCpuPlatforms)
    {
      if (gcpCpuPlatformMatchesArchitecture(platform, inferred.architecture))
      {
        compatiblePlatforms.push_back(platform);
      }
    }

    if (compatiblePlatforms.empty())
    {
      inferred.provenance = MachineSchemaCpuCapabilityProvenance::unavailable;
      validationMachineCapabilities.insert_or_assign(config.providerMachineType, inferred);
      capability = std::move(inferred);
      co_return;
    }

    Vector<String> intersected = {};
    for (uint32_t index = 0; index < compatiblePlatforms.size(); ++index)
    {
      Vector<String> platformFeatures = {};
      gcpAppendCpuPlatformIsaFeatures(inferred.architecture, compatiblePlatforms[index], platformFeatures);
      if (index == 0)
      {
        intersected = platformFeatures;
      }
      else
      {
        intersectIsaFeatures(intersected, platformFeatures);
      }
    }

    if (compatiblePlatforms.size() == 1)
    {
      inferred.cpuPlatform = compatiblePlatforms[0];
    }

    inferred.isaFeatures = std::move(intersected);
    inferred.provenance = MachineSchemaCpuCapabilityProvenance::providerAuthoritative;
    validationMachineCapabilities.insert_or_assign(config.providerMachineType, inferred);
    capability = std::move(inferred);
  }

  void prepareManagedInstanceTemplates(CoroutineStack *coro,
                                       const Vector<GcpManagedTemplateTransaction::Spec>& specs,
                                       String& error)
  {
    error.clear();
    const MultiCurlClient::TimePoint deadline = providerServices.operationDeadline;
    if (coro == nullptr || MultiCurlClient::Clock::now() >= deadline)
    {
      error.assign("gcp managed template deadline exceeded"_ctv);
      co_return;
    }
    bool identityReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureProjectZoneAsync(coro, identityReady, deadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (identityReady == false)
    {
      error.assign("gcp managed template project/zone unavailable"_ctv);
      co_return;
    }
    bool tokenReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureTokenAsync(coro, tokenReady, &error, deadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (tokenReady == false)
    {
      if (error.empty())
      {
        error.assign("gcp managed template token unavailable"_ctv);
      }
      co_return;
    }
    GcpManagedTemplateTransaction transaction(hostHttpSubmission(),
                                              ProdigyHostDelayOperation::submission(),
                                              projectId,
                                              token,
                                              deadline);
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          transaction.run(coro, specs, error);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }

  void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bytell_hash_set<Machine *>& newMachines, String& error) override
  {
    spinMachines(coro, lifetime, config, count, false, newMachines, error);
  }

  void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bool isBrain, bytell_hash_set<Machine *>& newMachines, String& error) override
  {
    provisioningProgress.reset();
    error.clear();
    if (coro == nullptr)
    {
      error.assign("gcp provisioning coroutine required"_ctv);
      co_return;
    }
    if (lifetime == MachineLifetime::owned)
    {
      error.assign("gcp auto provisioning does not support MachineLifetime::owned"_ctv);
      co_return;
    }
    if (config.kind != MachineConfig::MachineKind::vm)
    {
      error.assign("gcp auto provisioning only supports vm machine kinds"_ctv);
      co_return;
    }
    if (count == 0 || count > GcpMachineProvisioningTransaction::maximumMachines)
    {
      error.assign("gcp provisioning requires between 1 and 256 machines"_ctv);
      co_return;
    }
    if (config.vmImageURI.empty())
    {
      error.assign("vmImageURI missing"_ctv);
      co_return;
    }
    if (config.providerMachineType.empty())
    {
      error.assign("providerMachineType missing"_ctv);
      co_return;
    }
    const String& instanceTemplateName =
        lifetime == MachineLifetime::spot ? config.gcpInstanceTemplateSpot :
                                            config.gcpInstanceTemplate;
    if (instanceTemplateName.empty())
    {
      if (lifetime == MachineLifetime::spot)
      {
        error.assign("gcpInstanceTemplateSpot missing"_ctv);
      }
      else
      {
        error.assign("gcpInstanceTemplate missing"_ctv);
      }
      co_return;
    }
    const MultiCurlClient::TimePoint localDeadline =
        MultiCurlClient::Clock::now() +
        std::chrono::milliseconds(prodigyMachineProvisioningTimeoutMs);
    const MultiCurlClient::TimePoint deadline =
        providerServices.operationDeadline < localDeadline ?
            providerServices.operationDeadline : localDeadline;
    if (MultiCurlClient::Clock::now() >= deadline)
    {
      error.assign("gcp provisioning deadline exceeded"_ctv);
      co_return;
    }

    ++provisioningOperations;
    struct ActiveProvisioning final
    {
      uint32_t& operations;
      ~ActiveProvisioning()
      {
        --operations;
      }
    } activeProvisioning {provisioningOperations};

    bool identityReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureProjectZoneAsync(coro, identityReady, deadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (identityReady == false)
    {
      error.assign("gcp provisioning project/zone unavailable"_ctv);
      co_return;
    }

    bool tokenReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureTokenAsync(coro, tokenReady, &error, deadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (tokenReady == false)
    {
      if (error.empty())
      {
        error.assign("gcp provisioning token unavailable"_ctv);
      }
      co_return;
    }

    Vector<GcpMachineProvisioningTransaction::Spec> specs;
    specs.reserve(count);
    bytell_hash_set<String> names;
    names.reserve(count);
    for (uint32_t index = 0; index < count; ++index)
    {
      String name;
      for (uint32_t attempt = 0; attempt < 16; ++attempt)
      {
        String suffix;
        suffix.assignItoh(Random::generateNumberWithNBits<64, uint64_t>());
        name.assign("ntg-"_ctv);
        name.append(suffix);
        if (names.insert(name).second)
        {
          break;
        }
        name.clear();
      }
      if (name.empty())
      {
        error.assign("gcp provisioning could not generate distinct instance names"_ctv);
        co_return;
      }

      GcpMachineProvisioningTransaction::Spec spec;
      if (GcpMachineProvisioningTransaction::buildSpec(
              name,
              zone,
              config.vmImageURI,
              config.providerMachineType,
              config.cpu.cpuPlatform,
              config.nStorageMB,
              isBrain,
              provisioningClusterUUIDTagValue,
              bootstrapSSHUser,
              bootstrapSSHPublicKey,
              bootstrapSSHHostKeyPackage,
              spec,
              error) == false)
      {
        co_return;
      }
      specs.push_back(std::move(spec));
    }

    for (const GcpMachineProvisioningTransaction::Spec& spec : specs)
    {
      MachineProvisioningProgress& progress = provisioningProgress.upsert(
          config.slug, config.providerMachineType, spec.name, String());
      progress.status.assign("launch-submitted"_ctv);
      progress.ready = false;
    }
    provisioningProgress.emitNow();

    Vector<std::unique_ptr<Machine>> staged;
    staged.resize(count);
    auto ready = [&](uint32_t index, const String& response, String& detail) -> bool {
      String responseText = response;
      simdjson::dom::parser parser;
      simdjson::dom::element instance;
      if (parser.parse(responseText.c_str(), responseText.size()).get(instance))
      {
        detail.assign("gcp instance response parse failed"_ctv);
        return false;
      }
      std::unique_ptr<Machine> candidate(buildMachineFromInstance(instance));
      if (candidate == nullptr || candidate->cloudID.empty())
      {
        detail.assign("gcp instance response missing cloud id"_ctv);
        return false;
      }
      candidate->lifetime = lifetime;
      MachineProvisioningProgress& progress = provisioningProgress.upsert(
          config.slug, config.providerMachineType, specs[index].name, candidate->cloudID);
      prodigyPopulateMachineProvisioningProgressFromMachine(progress, *candidate);
      if (prodigyMachineProvisioningReady(*candidate) == false)
      {
        progress.status.assign("waiting-for-instance-addresses"_ctv);
        progress.ready = false;
        provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
        return false;
      }
      progress.status.assign("running"_ctv);
      progress.ready = true;
      staged[index] = std::move(candidate);
      return true;
    };

    GcpMachineProvisioningTransaction transaction(hostHttpSubmission(),
                                                  ProdigyHostDelayOperation::submission(),
                                                  projectId,
                                                  zone,
                                                  token,
                                                  deadline);
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          transaction.run(coro, instanceTemplateName, specs, ready, error);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (error.empty() == false)
    {
      for (const GcpMachineProvisioningTransaction::Spec& spec : specs)
      {
        MachineProvisioningProgress& progress = provisioningProgress.upsert(
            config.slug, config.providerMachineType, spec.name, String());
        if (progress.ready == false)
        {
          progress.status = error;
        }
        progress.ready = false;
      }
      provisioningProgress.emitNow();
      co_return;
    }

    for (std::unique_ptr<Machine>& machine : staged)
    {
      if (machine == nullptr)
      {
        error.assign("gcp provisioning completed without every machine snapshot"_ctv);
        provisioningProgress.emitNow();
        co_return;
      }
    }
    for (std::unique_ptr<Machine>& machine : staged)
    {
      provisioningProgress.notifyMachineProvisioningAccepted(machine->cloudID);
      provisioningProgress.notifyMachineProvisioned(*machine);
      newMachines.insert(machine.release());
    }
    provisioningProgress.emitNow();
  }
  void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines, String& failure) override
  {
    (void)metro;
    failure.clear();
    if (coro == nullptr)
    {
      failure.assign("gcp inventory coroutine required"_ctv);
      co_return;
    }

    ++inventoryOperations;
    struct ActiveInventory final
    {
      uint32_t& operations;
      ~ActiveInventory()
      {
        --operations;
      }
    } activeInventory {inventoryOperations};
    Vector<std::unique_ptr<Machine>> pendingMachines = {};
    auto visit = [&](simdjson::dom::element instance) -> bool {
      pendingMachines.emplace_back(buildMachineFromInstance(instance));
      return true;
    };
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          walkInventory(coro, visit, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (failure.size() == 0)
    {
      for (std::unique_ptr<Machine>& machine : pendingMachines)
      {
        machines.insert(machine.release());
      }
    }
  }

  void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains, String& failure) override
  {
    selfIsBrain = false;
    (void)selfUUID;
    failure.clear();
    if (coro == nullptr)
    {
      failure.assign("gcp inventory coroutine required"_ctv);
      co_return;
    }

    ++inventoryOperations;
    struct ActiveInventory final
    {
      uint32_t& operations;
      ~ActiveInventory()
      {
        --operations;
      }
    } activeInventory {inventoryOperations};
    bool pendingSelfIsBrain = false;
    Vector<std::unique_ptr<BrainView>> pendingBrains = {};
    auto visit = [&](simdjson::dom::element instance) -> bool {
      if (isBrainInstance(instance) == false)
      {
        return true;
      }

      String networkIP;
      auto interfaces = instance["networkInterfaces"].get_array();
      if (interfaces.error())
      {
        return true;
      }
      for (auto interface : interfaces)
      {
        if (prodigyJSONString(interface["networkIP"], networkIP) != simdjson::SUCCESS)
        {
          continue;
        }

        String privateText = networkIP;
        uint32_t ip = 0;
        if (inet_pton(AF_INET, privateText.c_str(), &ip) != 1)
        {
          continue;
        }
        if (thisNeuron != nullptr && ip == thisNeuron->private4.v4)
        {
          pendingSelfIsBrain = true;
          return true;
        }

        std::unique_ptr<BrainView> brain = std::make_unique<BrainView>();
        brain->private4 = ip;
        brain->peerAddress.is6 = false;
        brain->peerAddress.v4 = ip;
        brain->peerAddressText.assign(privateText);
        brain->connectTimeoutMs = BrainBase::controlPlaneConnectTimeoutMs();
        brain->nDefaultAttemptsBudget = BrainBase::controlPlaneConnectAttemptsBudget();
        pendingBrains.push_back(std::move(brain));
        return true;
      }
      return true;
    };
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          walkInventory(coro, visit, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (failure.size() == 0)
    {
      selfIsBrain = pendingSelfIsBrain;
      for (std::unique_ptr<BrainView>& brain : pendingBrains)
      {
        brains.insert(brain.release());
      }
    }
  }

  void machineLifecycle(CoroutineStack *coro,
                        GcpMachineLifecycleTransaction::Action action,
                        const String& cloudID,
                        String& failure)
  {
    failure.clear();
    String targetCloudID;
    targetCloudID.assign(cloudID);
    if (coro == nullptr || targetCloudID.empty())
    {
      failure.assign("gcp machine lifecycle coroutine and cloudID required"_ctv);
      co_return;
    }
    const MultiCurlClient::TimePoint localDeadline =
        MultiCurlClient::Clock::now() + std::chrono::minutes(3);
    const MultiCurlClient::TimePoint deadline =
        providerServices.operationDeadline < localDeadline ?
            providerServices.operationDeadline : localDeadline;
    if (MultiCurlClient::Clock::now() >= deadline)
    {
      failure.assign("gcp machine lifecycle deadline exceeded"_ctv);
      co_return;
    }

    ++lifecycleOperations;
    struct ActiveLifecycle final
    {
      uint32_t& operations;
      ~ActiveLifecycle()
      {
        --operations;
      }
    } activeLifecycle {lifecycleOperations};

    bool identityReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureProjectZoneAsync(coro, identityReady, deadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (identityReady == false)
    {
      failure.assign("gcp machine lifecycle project/zone unavailable"_ctv);
      co_return;
    }

    bool tokenReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureTokenAsync(coro, tokenReady, &failure, deadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (tokenReady == false)
    {
      if (failure.empty())
      {
        failure.assign("gcp machine lifecycle token unavailable"_ctv);
      }
      co_return;
    }

    GcpMachineLifecycleTransaction transaction(hostHttpSubmission(),
                                               ProdigyHostDelayOperation::submission(),
                                               projectId,
                                               zone,
                                               token,
                                               deadline);
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          transaction.run(coro, action, targetCloudID, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }

  void prepareElasticAddressOperation(CoroutineStack *coro,
                                      MultiCurlClient::TimePoint deadline,
                                      bool& ready,
                                      String& failure)
  {
    ready = false;
    bool identityReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureProjectZoneAsync(coro, identityReady, deadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (identityReady == false || (region.empty() && deriveRegionFromZone(zone, region) == false))
    {
      failure.assign("gcp elastic address project, zone, or region unavailable"_ctv);
      co_return;
    }

    bool tokenReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureTokenAsync(coro, tokenReady, &failure, deadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (tokenReady == false)
    {
      if (failure.empty())
      {
        failure.assign("gcp elastic address token unavailable"_ctv);
      }
      co_return;
    }
    ready = true;
  }

  void ensureProdigyMachineTags(CoroutineStack *coro,
                                const String& clusterUUID,
                                const String& cloudID,
                                String& failure) override
  {
    failure.clear();
    String targetClusterUUID;
    String targetCloudID;
    targetClusterUUID.assign(clusterUUID);
    targetCloudID.assign(cloudID);
    if (coro == nullptr || targetClusterUUID.empty() || targetCloudID.empty())
    {
      failure.assign("gcp machine labels coroutine, clusterUUID, and cloudID required"_ctv);
      co_return;
    }
    if (usesRefreshableBootstrapAccessToken())
    {
      failure.assign("gcp machine labels forbid executable credential refresh"_ctv);
      co_return;
    }
    const MultiCurlClient::TimePoint localDeadline =
        MultiCurlClient::Clock::now() + std::chrono::minutes(3);
    const MultiCurlClient::TimePoint deadline =
        providerServices.operationDeadline < localDeadline ?
            providerServices.operationDeadline : localDeadline;
    if (MultiCurlClient::Clock::now() >= deadline)
    {
      failure.assign("gcp machine labels deadline exceeded"_ctv);
      co_return;
    }

    ++labelOperations;
    struct ActiveLabels final
    {
      uint32_t& operations;
      ~ActiveLabels()
      {
        --operations;
      }
    } activeLabels {labelOperations};

    bool identityReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureProjectZoneAsync(coro, identityReady, deadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (identityReady == false)
    {
      failure.assign("gcp machine labels project/zone unavailable"_ctv);
      co_return;
    }

    bool tokenReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureTokenAsync(coro, tokenReady, &failure, deadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (tokenReady == false)
    {
      if (failure.empty())
      {
        failure.assign("gcp machine labels token unavailable"_ctv);
      }
      co_return;
    }

    GcpInstanceLabelsTransaction transaction(hostHttpSubmission(),
                                             ProdigyHostDelayOperation::submission(),
                                             projectId,
                                             zone,
                                             token,
                                             deadline);
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          transaction.run(coro, targetCloudID, targetClusterUUID, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }

  void hardRebootMachine(CoroutineStack *coro,
                         const String& cloudID,
                         String& failure) override
  {
    if (coro == nullptr)
    {
      failure.assign("gcp machine lifecycle coroutine required"_ctv);
      co_return;
    }
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          machineLifecycle(coro,
                           GcpMachineLifecycleTransaction::Action::reset,
                           cloudID,
                           failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }

  void reportHardwareFailure(uint128_t uuid, const String& report) override
  {
    (void)uuid;
    (void)report;
  }

  void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) override
  {
    if (coro == nullptr || spotTerminationCheckActive)
    {
      co_return;
    }

    spotTerminationCheckActive = true;
    struct ActiveCheck final
    {
      bool& active;
      ~ActiveCheck()
      {
        active = false;
      }
    } activeCheck {spotTerminationCheckActive};

    const MultiCurlClient::TimePoint checkDeadline = MultiCurlClient::Clock::now() + spotCheckTimeout;

    bool projectZoneReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureProjectZoneAsync(coro, projectZoneReady, checkDeadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (projectZoneReady == false)
    {
      co_return;
    }

    bool tokenReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureTokenAsync(coro, tokenReady, nullptr, checkDeadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (tokenReady == false)
    {
      co_return;
    }

    String nextPageToken = {};
    bytell_hash_set<String> requestedPageTokens = {};
    size_t requestedPages = 0;
    while (MultiCurlClient::Clock::now() < checkDeadline &&
           canRequestSpotPage(requestedPages,
                              decommissionedIDs.size(),
                              nextPageToken,
                              requestedPageTokens))
    {
      requestedPageTokens.insert(nextPageToken);
      ++requestedPages;

      MultiCurlClient::Result result = {};
      bool requestSucceeded = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            hostRequest(coro,
                    spotInstancesRequest(projectId,
                                         zone,
                                         token,
                                         nextPageToken,
                                         MultiCurlClient::Clock::now(),
                                         checkDeadline),
                    result,
                    requestSucceeded);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (requestSucceeded == false)
      {
        break;
      }

      String followingPageToken = {};
      if (parseSpotTerminationPage(result.body, decommissionedIDs, followingPageToken) == false)
      {
        break;
      }
      nextPageToken = std::move(followingPageToken);
      if (nextPageToken.size() == 0 ||
          nextPageToken.size() > spotPageTokenBytes ||
          requestedPageTokens.contains(nextPageToken))
      {
        break;
      }
    }
  }

  void destroyMachine(CoroutineStack *coro,
                      const String& cloudID,
                      String& failure) override
  {
    if (coro == nullptr)
    {
      failure.assign("gcp machine lifecycle coroutine required"_ctv);
      co_return;
    }
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          machineLifecycle(coro,
                           GcpMachineLifecycleTransaction::Action::destroy,
                           cloudID,
                           failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }

  void destroyClusterMachines(CoroutineStack *coro,
                              const String& clusterUUID,
                              uint32_t& destroyed,
                              String& failure) override
  {
    String targetClusterUUID;
    targetClusterUUID.assign(clusterUUID);
    destroyed = 0;
    failure.clear();
    if (coro == nullptr || targetClusterUUID.empty())
    {
      failure.assign("gcp cluster destroy coroutine and cluster UUID required"_ctv);
      co_return;
    }
    const MultiCurlClient::TimePoint localDeadline =
        MultiCurlClient::Clock::now() + std::chrono::minutes(10);
    const MultiCurlClient::TimePoint deadline =
        providerServices.operationDeadline < localDeadline ?
            providerServices.operationDeadline : localDeadline;
    if (MultiCurlClient::Clock::now() >= deadline)
    {
      failure.assign("gcp cluster destroy deadline exceeded"_ctv);
      co_return;
    }

    ++clusterDestroyOperations;
    struct ActiveClusterDestroy final
    {
      uint32_t& operations;
      ~ActiveClusterDestroy()
      {
        --operations;
      }
    } activeClusterDestroy {clusterDestroyOperations};

    bool identityReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureProjectZoneAsync(coro, identityReady, deadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (identityReady == false)
    {
      failure.assign("gcp cluster destroy project/zone unavailable"_ctv);
      co_return;
    }

    bool tokenReady = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          ensureTokenAsync(coro, tokenReady, &failure, deadline);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (tokenReady == false)
    {
      if (failure.empty())
      {
        failure.assign("gcp cluster destroy token unavailable"_ctv);
      }
      co_return;
    }

    GcpClusterDestroyTransaction transaction(hostHttpSubmission(),
                                             ProdigyHostDelayOperation::submission(),
                                             projectId,
                                             zone,
                                             token,
                                             deadline);
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          transaction.run(coro, targetClusterUUID, destroyed, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }

  void prepareProviderElasticAddress(CoroutineStack *coro,
                                     const ProviderElasticAddressRequest& request,
                                     uint128_t transactionNonce,
                                     ProviderElasticAddressPlan& plan,
                                     String& failure) override
  {
    ProviderElasticAddressRequest owned;
    owned.cloudID.assign(request.cloudID);
    owned.family = request.family;
    owned.intent = request.intent;
    owned.requestedAddress.assign(request.requestedAddress);
    owned.providerPool.assign(request.providerPool);
    owned.deliveryPrefix = request.deliveryPrefix;
    plan = {};
    failure.clear();
    if (coro == nullptr)
    {
      failure.assign("gcp elastic address assignment coroutine required"_ctv);
      co_return;
    }
    const MultiCurlClient::TimePoint localDeadline =
        MultiCurlClient::Clock::now() + GcpElasticAddressTransaction::maximumDuration;
    const MultiCurlClient::TimePoint deadline =
        providerServices.operationDeadline < localDeadline ?
            providerServices.operationDeadline : localDeadline;
    if (MultiCurlClient::Clock::now() >= deadline)
    {
      failure.assign("gcp elastic address assignment deadline exceeded"_ctv);
      co_return;
    }

    ++elasticOperations;
    struct ActiveElastic final
    {
      uint32_t& operations;
      ~ActiveElastic()
      {
        --operations;
      }
    } activeElastic {elasticOperations};

    bool ready = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          prepareElasticAddressOperation(coro, deadline, ready, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (ready == false)
    {
      co_return;
    }

    GcpElasticAddressTransaction transaction(hostHttpSubmission(),
                                             ProdigyHostDelayOperation::submission(),
                                             projectId,
                                             zone,
                                             region,
                                             token,
                                             deadline,
                                             transactionNonce);
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          transaction.prepare(coro, owned, plan, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }

  bool validateProviderElasticAddressPlan(const ProviderElasticAddressPlan& plan,
                                          const ProviderElasticAddressRequest& request,
                                          uint128_t transactionNonce) const override
  {
    GcpElasticAddressPlanV1 decoded;
    return GcpElasticAddressTransaction::decodePlan(plan, decoded, &projectId, &region, &zone) &&
           GcpElasticAddressTransaction::planMatchesRequest(decoded, request, transactionNonce);
  }

  void applyProviderElasticAddress(CoroutineStack *coro,
                                   const ProviderElasticAddressPlan& plan,
                                   ProviderElasticAddressAssignment& assignment,
                                   String& failure) override
  {
    GcpElasticAddressPlanV1 decoded;
    assignment = {};
    failure.clear();
    if (coro == nullptr ||
        GcpElasticAddressTransaction::decodePlan(plan, decoded, &projectId, &region, &zone) == false)
    {
      failure.assign("gcp elastic address apply plan invalid"_ctv);
      co_return;
    }
    const MultiCurlClient::TimePoint localDeadline =
        MultiCurlClient::Clock::now() + GcpElasticAddressTransaction::maximumDuration;
    const MultiCurlClient::TimePoint deadline = providerServices.operationDeadline < localDeadline ?
                                                    providerServices.operationDeadline : localDeadline;
    bool ready = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          prepareElasticAddressOperation(coro, deadline, ready, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (ready == false)
    {
      co_return;
    }
    GcpElasticAddressTransaction transaction(hostHttpSubmission(),
                                             ProdigyHostDelayOperation::submission(),
                                             projectId, zone, region, token, deadline, decoded.nonce);
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          transaction.apply(coro, plan, assignment, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }

  void compensateProviderElasticAddress(CoroutineStack *coro,
                                        const ProviderElasticAddressPlan& plan,
                                        String& failure) override
  {
    GcpElasticAddressPlanV1 decoded;
    failure.clear();
    if (coro == nullptr ||
        GcpElasticAddressTransaction::decodePlan(plan, decoded, &projectId, &region, &zone) == false)
    {
      failure.assign("gcp elastic address compensation plan invalid"_ctv);
      co_return;
    }
    const MultiCurlClient::TimePoint localDeadline =
        MultiCurlClient::Clock::now() + GcpElasticAddressTransaction::maximumDuration;
    const MultiCurlClient::TimePoint deadline = providerServices.operationDeadline < localDeadline ?
                                                    providerServices.operationDeadline : localDeadline;
    bool ready = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          prepareElasticAddressOperation(coro, deadline, ready, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (ready == false)
    {
      co_return;
    }
    GcpElasticAddressTransaction transaction(hostHttpSubmission(),
                                             ProdigyHostDelayOperation::submission(),
                                             projectId, zone, region, token, deadline, decoded.nonce);
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          transaction.compensate(coro, plan, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }

  void releaseProviderElasticAddress(CoroutineStack *coro,
                                     const ProviderElasticAddressRelease& release,
                                     String& failure) override
  {
    ProviderElasticAddressRelease owned;
    owned.transactionNonce = release.transactionNonce;
    owned.kind = release.kind;
    owned.assignedPrefix = release.assignedPrefix;
    owned.allocationID.assign(release.allocationID);
    owned.associationID.assign(release.associationID);
    owned.releaseOnRemove = release.releaseOnRemove;
    failure.clear();
    if (coro == nullptr)
    {
      failure.assign("gcp elastic address release coroutine required"_ctv);
      co_return;
    }
    const MultiCurlClient::TimePoint localDeadline =
        MultiCurlClient::Clock::now() + GcpElasticAddressTransaction::maximumDuration;
    const MultiCurlClient::TimePoint deadline =
        providerServices.operationDeadline < localDeadline ?
            providerServices.operationDeadline : localDeadline;
    if (MultiCurlClient::Clock::now() >= deadline)
    {
      failure.assign("gcp elastic address release deadline exceeded"_ctv);
      co_return;
    }

    ++elasticOperations;
    struct ActiveElastic final
    {
      uint32_t& operations;
      ~ActiveElastic()
      {
        --operations;
      }
    } activeElastic {elasticOperations};

    bool ready = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          prepareElasticAddressOperation(coro, deadline, ready, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (ready == false)
    {
      co_return;
    }

    GcpElasticAddressTransaction transaction(hostHttpSubmission(),
                                             ProdigyHostDelayOperation::submission(),
                                             projectId,
                                             zone,
                                             region,
                                             token,
                                             deadline,
                                             owned.transactionNonce);
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          transaction.release(coro, owned, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }

  bool supportsTransactionalElasticAddresses(void) const override
  {
    return true;
  }

};
