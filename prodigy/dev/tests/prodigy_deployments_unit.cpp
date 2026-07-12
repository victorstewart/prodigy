#include <prodigy/prodigy.h>
#include <limits.h>
#include <services/debug.h>
#include <prodigy/brain/brain.h>
#include <prodigy/containerstore.h>
#include <prodigy/acme.certbot.h>
#include <prodigy/dns.providers.h>
#include <prodigy/mothership/mothership.deployment.plan.helpers.h>
#include <prodigy/neuron/containers.h>

#include <cstdlib>
#include <cstdio>
#include <filesystem>
#include <string_view>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <type_traits>
#include <utility>
#include <unistd.h>
#include <simdjson.h>

class TestBrain final : public BrainBase {
public:

  Mesh meshStorage = {};
  uint32_t progressCount = 0;
  uint32_t failureCount = 0;
  uint32_t finCount = 0;
  uint32_t requestMachinesCount = 0;
  String lastProgressMessage = {};
  String lastFailureMessage = {};

  TestBrain()
  {
    this->mesh = &meshStorage;
  }

  void respinApplication(ApplicationDeployment *deployment) override
  {
    (void)deployment;
  }

  void pushSpinApplicationProgressToMothership(ApplicationDeployment *deployment, const String& message) override
  {
    (void)deployment;
    progressCount += 1;
    lastProgressMessage = message;
  }

  void spinApplicationFailed(ApplicationDeployment *deployment, const String& message) override
  {
    (void)deployment;
    failureCount += 1;
    lastFailureMessage = message;
  }

  void spinApplicationFin(ApplicationDeployment *deployment) override
  {
    (void)deployment;
    finCount += 1;
  }

  void requestMachines(MachineTicket *ticket, ApplicationDeployment *deployment, ApplicationLifetime lifetime, uint32_t nMore) override
  {
    requestMachinesCount += 1;
    (void)ticket;
    (void)deployment;
    (void)lifetime;
    (void)nMore;
  }
};

class TestSuite {
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    if (condition)
    {
      basics_log("PASS: %s\n", name);
    }
    else
    {
      basics_log("FAIL: %s\n", name);
      dprintf(STDERR_FILENO, "FAIL: %s\n", name);
      failed += 1;
    }
  }
};

static bool tunnelProviderHeaderValid(const String& blobPath, String *failureReport)
{
  int fd = -1;
  bool ok = prodigyOpenMothershipTunnelProviderBlobPayloadAfterContractHeader(blobPath, fd, failureReport);
  if (fd >= 0)
  {
    close(fd);
  }
  return ok;
}

class PairingCountingContainerView : public ContainerView {
public:

  uint32_t advertisementActivations = 0;
  uint32_t subscriptionActivations = 0;
  uint32_t subscriptionDeactivations = 0;

  bool readyForSubscriptionPairingNotifications(void) const override
  {
    return runtimeReady || state == ContainerState::healthy;
  }

  void advertisementPairing(uint128_t, uint128_t, uint64_t, uint16_t, bool activate) override
  {
    if (activate)
    {
      advertisementActivations += 1;
    }
  }

  void subscriptionPairing(uint128_t, uint128_t, uint64_t, uint16_t, uint16_t, bool activate) override
  {
    if (activate)
    {
      subscriptionActivations += 1;
    }
    else
    {
      subscriptionDeactivations += 1;
    }
  }
};

class ScopedFreshRing final {
public:

  bool hadRing = false;

  ScopedFreshRing()
  {
    hadRing = (Ring::getRingFD() > 0);
    if (hadRing)
    {
      Ring::shutdownForExec();
    }

    Ring::createRing(8, 8, 32, 32, -1, -1, 0);
  }

  ~ScopedFreshRing()
  {
    Ring::shutdownForExec();
    if (hadRing)
    {
      Ring::createRing(8, 8, 32, 32, -1, -1, 0);
    }
  }
};

class ScopedSocketPair final {
public:

  int left = -1;
  int right = -1;

  ~ScopedSocketPair()
  {
    if (left >= 0)
    {
      close(left);
    }

    if (right >= 0)
    {
      close(right);
    }
  }

  bool create(TestSuite& suite, const char *name)
  {
    int sockets[2] = {-1, -1};
    bool created = (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockets) == 0);
    suite.expect(created, name);
    if (created == false)
    {
      if (sockets[0] >= 0)
      {
        close(sockets[0]);
      }

      if (sockets[1] >= 0)
      {
        close(sockets[1]);
      }

      return false;
    }

    left = sockets[0];
    right = sockets[1];
    return true;
  }

  int adoptLeftIntoFixedFileSlot(void)
  {
    if (left < 0)
    {
      return -1;
    }

    int fslot = Ring::adoptProcessFDIntoFixedFileSlot(left);
    if (fslot >= 0)
    {
      left = -1;
    }

    return fslot;
  }
};

static std::filesystem::path filesystemPathFromString(const String& value)
{
  return std::filesystem::path(std::string(reinterpret_cast<const char *>(value.data()), size_t(value.size())));
}

static String stringFromFilesystemPath(const std::filesystem::path& value)
{
  std::string native = value.string();
  String output = {};
  output.assign(native.data(), native.size());
  return output;
}

static bool stringContains(const String& haystack, const char *needle)
{
  std::string_view haystackView(reinterpret_cast<const char *>(haystack.data()), size_t(haystack.size()));
  return haystackView.find(needle) != std::string_view::npos;
}

template <class Operation>
static bool runDNSProviderOperation(Operation&& operation)
{
  CoroutineStack coroutine;
  bool complete = false;
  bool success = false;
  [&]() -> void {
    success = co_await operation(&coroutine);
    complete = true;
  }();
  return complete && success;
}

template <class Provider>
static bool testDNSUpsert(Provider& provider, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure)
{
  return runDNSProviderOperation([&](CoroutineStack *coro) {
    return provider.upsert(coro, record, credential, failure);
  });
}

template <class Provider>
static bool testDNSRemove(Provider& provider, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure)
{
  return runDNSProviderOperation([&](CoroutineStack *coro) {
    return provider.remove(coro, record, credential, failure);
  });
}

template <class Provider>
static bool testDNSPresentTXT(Provider& provider, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure)
{
  return runDNSProviderOperation([&](CoroutineStack *coro) {
    return provider.presentTXT(coro, record, credential, failure);
  });
}

template <class Provider>
static bool testDNSCleanupTXT(Provider& provider, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure)
{
  return runDNSProviderOperation([&](CoroutineStack *coro) {
    return provider.cleanupTXT(coro, record, credential, failure);
  });
}

static const char *dnsHTTPMethodName(MultiCurlClient::Method method)
{
  switch (method)
  {
    case MultiCurlClient::Method::get:
      return "GET";
    case MultiCurlClient::Method::head:
      return "HEAD";
    case MultiCurlClient::Method::post:
      return "POST";
    case MultiCurlClient::Method::put:
      return "PUT";
    case MultiCurlClient::Method::patch:
      return "PATCH";
    case MultiCurlClient::Method::delete_:
      return "DELETE";
  }
  return "";
}

class CapturedDNSHTTPRequest {
public:

  String method;
  String url;
  Vector<String> headers;
  String body;
};

template <class Provider>
class RecordingHTTPDNSProvider final : public Provider {
public:

  Vector<CapturedDNSHTTPRequest> requests;
  Vector<String> responses;
  Vector<long> httpCodes;

protected:

  ProdigyHostTask<bool> sendHTTP(CoroutineStack *, ProdigyDNSHTTPRequest& request, String& response, long& httpCode, String& failure) override
  {
    CapturedDNSHTTPRequest captured = {};
    captured.method.assign(dnsHTTPMethodName(request.method));
    captured.url = request.url;
    captured.body = request.body;
    for (const MultiCurlClient::Header& header : request.headers)
    {
      String value = {};
      value.snprintf<"{}: {}"_ctv>(header.name, header.value);
      captured.headers.push_back(value);
    }
    uint64_t index = requests.size();
    requests.push_back(captured);
    if (index < responses.size())
    {
      response = responses[index];
    }
    else
    {
      response.assign("{}"_ctv);
    }
    httpCode = index < httpCodes.size() ? httpCodes[index] : 200;
    failure.clear();
    co_return true;
  }
};

using RecordingCloudflareDNSProvider = RecordingHTTPDNSProvider<CloudflareDNSProvider>;
using RecordingGcpCloudDNSProvider = RecordingHTTPDNSProvider<GcpCloudDNSProvider>;
using RecordingAzureDNSProvider = RecordingHTTPDNSProvider<AzureDNSProvider>;
using RecordingVultrDNSProvider = RecordingHTTPDNSProvider<VultrDNSProvider>;

class RecordingRoute53DNSProvider final : public Route53DNSProvider {
public:

  Vector<CapturedDNSHTTPRequest> requests;
  Vector<String> responses;
  Vector<long> httpCodes;
  String url;
  String region;
  String body;

protected:

  ProdigyHostTask<bool> sendAWS(CoroutineStack *,
                                MultiCurlClient::Method requestMethod,
                                const AwsHttpRequest::Target& target,
                                const AwsCredentialMaterial& credential,
                                const String *requestBody,
                                String& response,
                                long& httpCode,
                                String& failure) override
  {
    (void)credential;
    CapturedDNSHTTPRequest captured = {};
    captured.method.assign(dnsHTTPMethodName(requestMethod));
    captured.url = target.path;
    if (requestBody != nullptr)
    {
      captured.body = *requestBody;
    }
    uint64_t index = requests.size();
    requests.push_back(captured);
    url = target.path;
    region = target.region;
    body = requestBody == nullptr ? String() : *requestBody;
    response = index < responses.size() ? responses[index] : String("<ok/>"_ctv);
    httpCode = index < httpCodes.size() ? httpCodes[index] : 200;
    failure.clear();
    co_return true;
  }
};

class AddressOnlyDNSProvider final : public ProdigyDNSProvider {
public:

  bool supportsProvider(const String& provider) const override
  {
    return provider.equal("address-only"_ctv);
  }

  ProdigyHostTask<bool> upsert(CoroutineStack *, const ProdigyDNSRecordBinding&, const ApiCredential&, String& failure) override
  {
    failure.clear();
    co_return true;
  }

  ProdigyHostTask<bool> remove(CoroutineStack *, const ProdigyDNSRecordBinding&, const ApiCredential&, String& failure) override
  {
    failure.clear();
    co_return true;
  }
};

static uid_t fixtureWritableUserID(void)
{
  if (geteuid() == 0)
  {
    return 65'534;
  }

  return geteuid();
}

static gid_t fixtureWritableGroupID(void)
{
  if (geteuid() == 0)
  {
    return 65'534;
  }

  return getegid();
}

class TemporaryDirectory {
public:

  String path = {};

  bool create(void)
  {
    char scratch[] = "/tmp/prodigy-deployments-unit-XXXXXX";
    char *created = ::mkdtemp(scratch);
    if (created == nullptr)
    {
      return false;
    }

    path.assign(created);
    return true;
  }

  ~TemporaryDirectory()
  {
    if (path.size() == 0)
    {
      return;
    }

    std::error_code ignored;
    std::filesystem::remove_all(filesystemPathFromString(path), ignored);
  }
};

static bool writeLaunchMetadataFixture(const String& artifactRoot, const char *metadataJSON)
{
  String metadataDir = {};
  metadataDir.assign(artifactRoot);
  metadataDir.append("/.prodigy-private"_ctv);

  std::error_code createError;
  std::filesystem::create_directories(filesystemPathFromString(metadataDir), createError);
  if (createError)
  {
    return false;
  }

  String metadataPath = {};
  metadataPath.assign(metadataDir);
  metadataPath.append("/launch.metadata"_ctv);

  String payload = {};
  payload.assign(metadataJSON);
  if (Filesystem::openWriteAtClose(-1, metadataPath, payload) < 0)
  {
    return false;
  }

  return true;
}

static bool writeFileFixture(const std::filesystem::path& path, const char *payloadText)
{
  std::error_code createError;
  std::filesystem::create_directories(path.parent_path(), createError);
  if (createError)
  {
    return false;
  }

  String targetPath = stringFromFilesystemPath(path);
  String payload = {};
  payload.assign(payloadText);
  return Filesystem::openWriteAtClose(-1, targetPath, payload) >= 0;
}

static bool writeFileFixture(const std::filesystem::path& path, const String& payload)
{
  std::error_code createError;
  std::filesystem::create_directories(path.parent_path(), createError);
  if (createError)
  {
    return false;
  }

  String targetPath = stringFromFilesystemPath(path);
  return Filesystem::openWriteAtClose(-1, targetPath, payload) >= 0;
}

static bool readFileFixture(const std::filesystem::path& path, String& payload)
{
  payload.clear();
  if (std::filesystem::exists(path) == false)
  {
    return false;
  }
  Filesystem::openReadAtClose(-1, stringFromFilesystemPath(path), payload);
  return true;
}

static String repeatedString(uint64_t bytes, char fill)
{
  std::string text(size_t(bytes), fill);
  String output = {};
  output.assign(text.data(), text.size());
  return output;
}

static bool createDirectoryFixture(const std::filesystem::path& path)
{
  std::error_code error;
  std::filesystem::create_directories(path, error);
  return error.value() == 0;
}

static bool createSymlinkFixture(const std::filesystem::path& target, const std::filesystem::path& linkPath)
{
  std::error_code error;
  std::filesystem::create_symlink(target, linkPath, error);
  return error.value() == 0;
}

static bool makeFileExecutableFixture(const std::filesystem::path& path)
{
  std::error_code error;
  std::filesystem::permissions(
      path,
      std::filesystem::perms::owner_exec | std::filesystem::perms::group_exec | std::filesystem::perms::others_exec,
      std::filesystem::perm_options::add,
      error);
  return error.value() == 0;
}

static MachineCpuArchitecture alternateSupportedArchitecture(MachineCpuArchitecture architecture)
{
  if (architecture == MachineCpuArchitecture::x86_64)
  {
    return MachineCpuArchitecture::aarch64;
  }

  if (architecture == MachineCpuArchitecture::aarch64)
  {
    return MachineCpuArchitecture::x86_64;
  }

  return MachineCpuArchitecture::unknown;
}

static void seedCommonPlan(ApplicationDeployment& deployment, bool isStateful)
{
  deployment.plan.isStateful = isStateful;
  deployment.plan.config.applicationID = 999;
  deployment.plan.config.versionID = 1;
  deployment.plan.config.nLogicalCores = 2;
  deployment.plan.config.memoryMB = 512;
  deployment.plan.config.filesystemMB = 64;
  deployment.plan.config.storageMB = 64;
  deployment.plan.stateless.maxPerRackRatio = 1.0f;
  deployment.plan.stateless.maxPerMachineRatio = 1.0f;
}

static void markNeuronControlActive(Machine& machine, int fslot)
{
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = fslot;
  machine.neuron.connected = true;
  machine.runtimeReady = true;
}

static bool armNeuronControlStream(Machine& machine, ScopedSocketPair& sockets)
{
  machine.neuron.machine = &machine;
  machine.neuron.fd = -1;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = sockets.adoptLeftIntoFixedFileSlot();
  machine.neuron.connected = (machine.neuron.fslot >= 0);
  machine.runtimeReady = machine.neuron.connected;
  return machine.neuron.connected;
}

static bool seedSchedulableMachine(TestBrain& brain, Rack& rack, Machine& machine, uint128_t uuid, uint32_t private4, const String& slug, ScopedSocketPair& sockets)
{
  machine.uuid = uuid;
  machine.private4 = private4;
  machine.slug = slug;
  machine.rack = &rack;
  machine.state = MachineState::healthy;
  machine.lifetime = MachineLifetime::owned;
  machine.isBrain = true;
  machine.hardware.inventoryComplete = true;
  machine.hardware.cpu.architecture = nametagCurrentBuildMachineArchitecture();
  machine.hardware.cpu.logicalCores = machine.ownedLogicalCores = machine.totalLogicalCores = machine.nLogicalCores_available = 8;
  machine.hardware.memory.totalMB = machine.ownedMemoryMB = machine.totalMemoryMB = machine.memoryMB_available = 8192;
  machine.ownedStorageMB = machine.totalStorageMB = machine.storageMB_available = 4096;
  machine.neuron.machine = &machine;
  machine.neuron.fd = -1;
  machine.neuron.isFixedFile = true;
  machine.neuron.fslot = sockets.adoptLeftIntoFixedFileSlot();
  machine.neuron.connected = machine.neuron.fslot >= 0;
  machine.runtimeReady = machine.neuron.connected;
  rack.machines.insert(&machine);
  brain.machines.insert(&machine);
  return machine.neuron.connected;
}

int main(void)
{
  TestSuite suite;

  {
    IPPrefix all4("0.0.0.0", false, 0);
    IPPrefix host4("203.0.113.9", false, 32);
    IPPrefix left4("198.51.100.0", false, 25);
    IPPrefix right4("198.51.100.128", false, 25);
    IPPrefix parent4("198.51.100.99", false, 24);
    IPPrefix child4("198.51.100.200", false, 32);
    IPPrefix all6("::", true, 0);
    IPPrefix host6("2001:db8::1", true, 128);
    IPPrefix parent6("2001:db8:abcd:1200::beef", true, 48);
    IPPrefix child6("2001:db8:abcd:12ff::1", true, 128);
    IPPrefix invalid4("198.51.100.0", false, 33);
    IPPrefix invalid6("2001:db8::", true, 129);

    suite.expect(ipPrefixesOverlap(all4, host4), "ip_prefixes_overlap_ipv4_zero_contains_host");
    suite.expect(ipPrefixesOverlap(all6, host6), "ip_prefixes_overlap_ipv6_zero_contains_host");
    suite.expect(ipPrefixesOverlap(parent4, child4), "ip_prefixes_overlap_ipv4_parent_child_canonicalizes_parent");
    suite.expect(ipPrefixesOverlap(parent6, child6), "ip_prefixes_overlap_ipv6_parent_child_canonicalizes_parent");
    suite.expect(ipPrefixesOverlap(left4, right4) == false, "ip_prefixes_overlap_ipv4_adjacent_disjoint");
    suite.expect(ipPrefixesOverlap(parent4, host6) == false, "ip_prefixes_overlap_family_mismatch");
    suite.expect(ipPrefixesOverlap(host4, host4), "ip_prefixes_overlap_ipv4_host_exact");
    suite.expect(ipPrefixesOverlap(host6, host6), "ip_prefixes_overlap_ipv6_host_exact");
    suite.expect(ipPrefixesOverlap(invalid4, host4) == false, "ip_prefixes_overlap_rejects_invalid_ipv4_cidr");
    suite.expect(ipPrefixesOverlap(invalid6, host6) == false, "ip_prefixes_overlap_rejects_invalid_ipv6_cidr");
  }

  {
    auto owner = [](uint16_t app, uint64_t version, uint64_t lineage, const char *name) {
      RoutableResourceLeaseOwner value = {};
      value.applicationID = app;
      value.deploymentID = (uint64_t(app) << 48) | version;
      value.lineageID = lineage;
      value.name.assign(name);
      return value;
    };
    auto addressLease = [](RoutableResourceLeaseKind kind, const RoutableResourceLeaseOwner& owner, const char *ip, uint16_t port = 0) {
      RoutableResourceLease value = {};
      value.kind = kind;
      value.owner = owner;
      value.address = IPAddress(ip, false);
      value.sourcePort = port;
      return value;
    };

    RoutableResourceLeaseOwner ownerA = owner(42, 1, 7001, "api-v1");
    RoutableResourceLeaseOwner ownerUpgrade = owner(42, 2, 7001, "api-v2");
    RoutableResourceLeaseOwner ownerB = owner(43, 1, 9001, "other");
    RoutableResourceLease wormholeA = addressLease(RoutableResourceLeaseKind::wormholeAddress, ownerA, "198.51.100.10");
    RoutableResourceLease wormholeUpgrade = addressLease(RoutableResourceLeaseKind::wormholeAddress, ownerUpgrade, "198.51.100.10");
    RoutableResourceLease wormholeB = addressLease(RoutableResourceLeaseKind::wormholeAddress, ownerB, "198.51.100.10");
    suite.expect(routableResourceLeasesConflict(wormholeA, wormholeB), "routable_lease_conflicts_on_duplicate_wormhole_address");
    suite.expect(routableResourceLeasesConflict(wormholeA, wormholeUpgrade) == false, "routable_lease_allows_same_lineage_wormhole_transfer");

    RoutableResourceLease whiteholeA = addressLease(RoutableResourceLeaseKind::whiteholeAddressPort, ownerA, "198.51.100.20", 50'000);
    RoutableResourceLease whiteholeB = addressLease(RoutableResourceLeaseKind::whiteholeAddressPort, ownerB, "198.51.100.20", 50'000);
    RoutableResourceLease whiteholeNextPort = addressLease(RoutableResourceLeaseKind::whiteholeAddressPort, ownerB, "198.51.100.20", 50'001);
    suite.expect(routableResourceLeasesConflict(whiteholeA, whiteholeB), "routable_lease_conflicts_on_duplicate_whitehole_ip_port");
    suite.expect(routableResourceLeasesConflict(whiteholeA, whiteholeNextPort) == false, "routable_lease_allows_whitehole_same_ip_different_port");

    RoutableResourceLease dnsA = {};
    dnsA.kind = RoutableResourceLeaseKind::dnsRecord;
    dnsA.owner = ownerA;
    dnsA.dnsProvider = "Cloudflare"_ctv;
    dnsA.dnsCredentialName = "cf-prod"_ctv;
    dnsA.dnsZone = "Example.COM."_ctv;
    dnsA.dnsName = "Api.Example.COM."_ctv;
    dnsA.dnsType = "A"_ctv;
    dnsA.dnsTTL = 300;
    RoutableResourceLease dnsB = dnsA;
    dnsB.owner = ownerB;
    dnsB.dnsProvider = "cloudflare"_ctv;
    dnsB.dnsZone = "example.com"_ctv;
    dnsB.dnsName = "api.example.com"_ctv;
    dnsB.dnsType = "a"_ctv;
    suite.expect(routableResourceLeasesConflict(dnsA, dnsB), "routable_lease_conflicts_on_canonical_dns_identity");
  }

  {
    ProdigyDNSRecordBinding record = {};
    record.provider = "cloudflare"_ctv;
    record.credentialName = "dns"_ctv;
    record.zone = "zone-123"_ctv;
    record.name = "api.example.com."_ctv;
    record.type = "A"_ctv;
    record.values.push_back("203.0.113.10"_ctv);
    record.ttl = 300;

    ApiCredential credential = {};
    credential.material = "token"_ctv;
    String failure = {};

    suite.expect(prodigyDNSRelativeName("api.example.com."_ctv, "example.com"_ctv).equal("api"_ctv), "dns_provider_relative_name_trims_zone_and_trailing_dot");

    ProdigyDefaultDNSProvider defaults = {};
    suite.expect(defaults.supportsProvider("cloudflare"_ctv), "dns_provider_default_supports_cloudflare");
    suite.expect(defaults.supportsProvider("route53"_ctv), "dns_provider_default_supports_route53");
    suite.expect(defaults.supportsProvider("gcp-cloud-dns"_ctv), "dns_provider_default_supports_gcp");
    suite.expect(defaults.supportsProvider("azure-dns"_ctv), "dns_provider_default_supports_azure");
    suite.expect(defaults.supportsProvider("vultr-dns"_ctv), "dns_provider_default_supports_vultr");

    RecordingCloudflareDNSProvider cloudflare = {};
    cloudflare.responses.push_back("{\"result\":[]}"_ctv);
    cloudflare.responses.push_back("{\"success\":true}"_ctv);
    suite.expect(testDNSUpsert(cloudflare, record, credential, failure), "dns_provider_cloudflare_create_succeeds");
    suite.expect(cloudflare.requests.size() == 2, "dns_provider_cloudflare_create_lists_then_writes");
    suite.expect(cloudflare.requests.size() == 2 && cloudflare.requests[0].method.equal("GET"_ctv), "dns_provider_cloudflare_create_lists");
    suite.expect(cloudflare.requests.size() == 2 && stringContains(cloudflare.requests[0].url, "name=api.example.com"), "dns_provider_cloudflare_create_query_omits_trailing_dot");
    suite.expect(cloudflare.requests.size() == 2 && cloudflare.requests[1].method.equal("POST"_ctv), "dns_provider_cloudflare_create_posts");
    suite.expect(cloudflare.requests.size() == 2 && stringContains(cloudflare.requests[1].body, "\"content\":\"203.0.113.10\""), "dns_provider_cloudflare_create_body_targets_address");
    suite.expect(cloudflare.requests.size() == 2 && stringContains(cloudflare.requests[1].body, "\"name\":\"api.example.com\""), "dns_provider_cloudflare_create_body_omits_trailing_dot");

    RecordingCloudflareDNSProvider cloudflareConflict = {};
    cloudflareConflict.responses.push_back("{\"result\":[{\"id\":\"rec-2\",\"type\":\"A\",\"name\":\"api.example.com\",\"content\":\"203.0.113.11\"}]}"_ctv);
    suite.expect(testDNSUpsert(cloudflareConflict, record, credential, failure) == false, "dns_provider_cloudflare_rejects_existing_different_record");
    suite.expect(failure.equal("DNS record already exists with different value"_ctv), "dns_provider_cloudflare_conflict_failure_text");
    suite.expect(cloudflareConflict.requests.size() == 1, "dns_provider_cloudflare_conflict_does_not_write");

    RecordingCloudflareDNSProvider cloudflareDelete = {};
    cloudflareDelete.responses.push_back("{\"result\":[{\"id\":\"rec-1\",\"type\":\"A\",\"name\":\"api.example.com.\",\"content\":\"203.0.113.10\"}]}"_ctv);
    cloudflareDelete.responses.push_back("{}"_ctv);
    suite.expect(testDNSRemove(cloudflareDelete, record, credential, failure), "dns_provider_cloudflare_delete_succeeds");
    suite.expect(cloudflareDelete.requests.size() == 2 && cloudflareDelete.requests[1].method.equal("DELETE"_ctv), "dns_provider_cloudflare_delete_uses_record_id");
    suite.expect(cloudflareDelete.requests.size() == 2 && stringContains(cloudflareDelete.requests[1].url, "/rec-1"), "dns_provider_cloudflare_delete_url_contains_record_id");

    RecordingRoute53DNSProvider route53 = {};
    record.provider = "route53"_ctv;
    record.zone = "/hostedzone/Z123"_ctv;
    credential.material = "AKIA:SECRET"_ctv;
    suite.expect(testDNSUpsert(route53, record, credential, failure), "dns_provider_route53_upsert_succeeds");
    suite.expect(route53.requests.size() == 2, "dns_provider_route53_upsert_lists_then_writes");
    suite.expect(route53.requests.size() == 2 && route53.requests[0].method.equal("GET"_ctv), "dns_provider_route53_upsert_lists_first");
    suite.expect(route53.requests.size() == 2 && route53.requests[1].method.equal("POST"_ctv), "dns_provider_route53_upsert_posts_change");
    suite.expect(stringContains(route53.url, "/hostedzone/Z123/rrset"), "dns_provider_route53_url_uses_hosted_zone");
    suite.expect(route53.region.equal("us-east-1"_ctv), "dns_provider_route53_defaults_region");
    suite.expect(stringContains(route53.body, "<Action>CREATE</Action>"), "dns_provider_route53_body_creates_missing_record");
    suite.expect(stringContains(route53.body, "<Value>203.0.113.10</Value>"), "dns_provider_route53_body_targets_address");

    RecordingRoute53DNSProvider route53Conflict = {};
    route53Conflict.responses.push_back("<ListResourceRecordSetsResponse><ResourceRecordSets><ResourceRecordSet><Name>api.example.com.</Name><Type>A</Type><TTL>300</TTL><ResourceRecords><ResourceRecord><Value>203.0.113.11</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></ResourceRecordSets></ListResourceRecordSetsResponse>"_ctv);
    suite.expect(testDNSUpsert(route53Conflict, record, credential, failure) == false, "dns_provider_route53_rejects_existing_different_record");
    suite.expect(failure.equal("DNS record already exists with different value"_ctv), "dns_provider_route53_conflict_failure_text");
    suite.expect(route53Conflict.requests.size() == 1, "dns_provider_route53_conflict_does_not_write");

    RecordingRoute53DNSProvider route53TTLMismatch = {};
    route53TTLMismatch.responses.push_back("<ListResourceRecordSetsResponse><ResourceRecordSets><ResourceRecordSet><Name>api.example.com.</Name><Type>A</Type><TTL>301</TTL><ResourceRecords><ResourceRecord><Value>203.0.113.10</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></ResourceRecordSets></ListResourceRecordSetsResponse>"_ctv);
    suite.expect(testDNSUpsert(route53TTLMismatch, record, credential, failure) == false,
                 "dns_provider_route53_rejects_existing_different_ttl");
    suite.expect(route53TTLMismatch.requests.size() == 1,
                 "dns_provider_route53_ttl_conflict_does_not_write");

    RecordingGcpCloudDNSProvider gcp = {};
    record.provider = "gcp-cloud-dns"_ctv;
    record.zone = "prod-zone"_ctv;
    credential.material = "stale-gcp-token"_ctv;
    credential.metadata.clear();
    credential.metadata["project"_ctv] = "proj"_ctv;
    credential.metadata["bearerRefreshCommand"_ctv] = "printf refreshed-gcp"_ctv;
    gcp.responses.push_back("{\"rrsets\":[]}"_ctv);
    gcp.responses.push_back("{\"id\":\"change-1\"}"_ctv);
    suite.expect(testDNSUpsert(gcp, record, credential, failure), "dns_provider_gcp_create_succeeds");
    suite.expect(gcp.requests.size() == 2 && gcp.requests[0].method.equal("GET"_ctv) && gcp.requests[1].method.equal("POST"_ctv), "dns_provider_gcp_lists_then_writes");
    suite.expect(gcp.requests.size() == 2 && gcp.requests[0].headers.size() == 1 && gcp.requests[0].headers[0].equal("Authorization: Bearer refreshed-gcp"_ctv), "dns_provider_gcp_refresh_command_supplies_bearer");

    RecordingGcpCloudDNSProvider gcpConflict = {};
    gcpConflict.responses.push_back("{\"rrsets\":[{\"name\":\"api.example.com.\",\"type\":\"A\",\"rrdatas\":[\"203.0.113.11\"]}]}"_ctv);
    suite.expect(testDNSUpsert(gcpConflict, record, credential, failure) == false, "dns_provider_gcp_rejects_existing_different_record");
    suite.expect(gcpConflict.requests.size() == 1, "dns_provider_gcp_conflict_does_not_write");

    RecordingAzureDNSProvider azure = {};
    record.provider = "azure-dns"_ctv;
    record.zone = "example.com"_ctv;
    credential.material = "stale-azure-token"_ctv;
    credential.metadata.clear();
    credential.metadata["subscriptionID"_ctv] = "sub"_ctv;
    credential.metadata["resourceGroup"_ctv] = "rg"_ctv;
    credential.metadata["bearerRefreshCommand"_ctv] = "printf refreshed-azure"_ctv;
    azure.httpCodes.push_back(404);
    azure.httpCodes.push_back(200);
    azure.responses.push_back("{}"_ctv);
    azure.responses.push_back("{}"_ctv);
    suite.expect(testDNSUpsert(azure, record, credential, failure), "dns_provider_azure_create_succeeds");
    suite.expect(azure.requests.size() == 2 && azure.requests[0].method.equal("GET"_ctv) && azure.requests[1].method.equal("PUT"_ctv), "dns_provider_azure_gets_then_writes");
    suite.expect(azure.requests.size() == 2 && azure.requests[0].headers.size() == 1 && azure.requests[0].headers[0].equal("Authorization: Bearer refreshed-azure"_ctv), "dns_provider_azure_refresh_command_supplies_bearer");

    RecordingAzureDNSProvider azureConflict = {};
    azureConflict.responses.push_back("{\"properties\":{\"ARecords\":[{\"ipv4Address\":\"203.0.113.11\"}]}}"_ctv);
    suite.expect(testDNSUpsert(azureConflict, record, credential, failure) == false, "dns_provider_azure_rejects_existing_different_record");
    suite.expect(azureConflict.requests.size() == 1, "dns_provider_azure_conflict_does_not_write");

    RecordingVultrDNSProvider vultrConflict = {};
    record.provider = "vultr-dns"_ctv;
    credential.metadata.clear();
    vultrConflict.responses.push_back("{\"records\":[{\"id\":\"rec-3\",\"type\":\"A\",\"name\":\"api\",\"data\":\"203.0.113.11\"}]}"_ctv);
    suite.expect(testDNSUpsert(vultrConflict, record, credential, failure) == false, "dns_provider_vultr_rejects_existing_different_record");
    suite.expect(vultrConflict.requests.size() == 1, "dns_provider_vultr_conflict_does_not_write");

    ProdigyDNSRecordBinding txt = {};
    txt.zone = "example.com"_ctv;
    txt.name = "_acme-challenge.api.example.com."_ctv;
    txt.type = "TXT"_ctv;
    txt.values.push_back("token-1"_ctv);
    txt.ttl = 60;

    AddressOnlyDNSProvider addressOnly = {};
    suite.expect(testDNSPresentTXT(addressOnly, txt, credential, failure) == false && failure.equal("DNS provider does not implement ACME TXT present"_ctv), "dns_provider_base_present_txt_fails_closed");
    suite.expect(testDNSCleanupTXT(addressOnly, txt, credential, failure) == false && failure.equal("DNS provider does not implement ACME TXT cleanup"_ctv), "dns_provider_base_cleanup_txt_fails_closed");

    RecordingCloudflareDNSProvider cloudflareTXT = {};
    txt.provider = "cloudflare"_ctv;
    credential.material = "token"_ctv;
    credential.metadata.clear();
    cloudflareTXT.responses.push_back("{\"result\":[{\"id\":\"old\",\"type\":\"TXT\",\"name\":\"_acme-challenge.api.example.com.\",\"content\":\"old-token\"}]}"_ctv);
    cloudflareTXT.responses.push_back("{\"success\":true}"_ctv);
    suite.expect(testDNSPresentTXT(cloudflareTXT, txt, credential, failure), "dns_provider_cloudflare_present_txt_ignores_sibling_value");
    suite.expect(cloudflareTXT.requests.size() == 2 && cloudflareTXT.requests[1].method.equal("POST"_ctv), "dns_provider_cloudflare_present_txt_posts_missing_exact_value");

    RecordingCloudflareDNSProvider cloudflareTXTCleanup = {};
    cloudflareTXTCleanup.responses.push_back("{\"result\":[{\"id\":\"old\",\"type\":\"TXT\",\"name\":\"_acme-challenge.api.example.com.\",\"content\":\"old-token\"},{\"id\":\"new\",\"type\":\"TXT\",\"name\":\"_acme-challenge.api.example.com.\",\"content\":\"token-1\"}]}"_ctv);
    cloudflareTXTCleanup.responses.push_back("{}"_ctv);
    suite.expect(testDNSCleanupTXT(cloudflareTXTCleanup, txt, credential, failure), "dns_provider_cloudflare_cleanup_txt_removes_exact_value");
    suite.expect(cloudflareTXTCleanup.requests.size() == 2 && stringContains(cloudflareTXTCleanup.requests[1].url, "/new"), "dns_provider_cloudflare_cleanup_txt_uses_exact_record_id");

    RecordingCloudflareDNSProvider cloudflareTXTMissingCleanup = {};
    cloudflareTXTMissingCleanup.responses.push_back("{\"result\":[{\"id\":\"old\",\"type\":\"TXT\",\"name\":\"_acme-challenge.api.example.com.\",\"content\":\"old-token\"}]}"_ctv);
    suite.expect(testDNSCleanupTXT(cloudflareTXTMissingCleanup, txt, credential, failure), "dns_provider_cloudflare_cleanup_txt_missing_exact_value_succeeds");
    suite.expect(cloudflareTXTMissingCleanup.requests.size() == 1, "dns_provider_cloudflare_cleanup_txt_missing_exact_value_does_not_delete");

    RecordingRoute53DNSProvider route53TXT = {};
    txt.provider = "route53"_ctv;
    txt.zone = "/hostedzone/Z123"_ctv;
    credential.material = "AKIA:SECRET"_ctv;
    route53TXT.responses.push_back("<ListResourceRecordSetsResponse><ResourceRecordSets><ResourceRecordSet><Name>_acme-challenge.api.example.com.</Name><Type>TXT</Type><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>\"old-token\"</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></ResourceRecordSets></ListResourceRecordSetsResponse>"_ctv);
    suite.expect(testDNSPresentTXT(route53TXT, txt, credential, failure), "dns_provider_route53_present_txt_merges_rrset");
    suite.expect(stringContains(route53TXT.body, "<Action>UPSERT</Action>"), "dns_provider_route53_present_txt_upserts");
    suite.expect(stringContains(route53TXT.body, "<Value>&quot;old-token&quot;</Value>") && stringContains(route53TXT.body, "<Value>&quot;token-1&quot;</Value>"), "dns_provider_route53_present_txt_preserves_sibling");

    RecordingRoute53DNSProvider route53TXTXML = {};
    ProdigyDNSRecordBinding xmlTXT = txt;
    xmlTXT.values.clear();
    xmlTXT.values.push_back("token&<\"quote"_ctv);
    suite.expect(testDNSPresentTXT(route53TXTXML, xmlTXT, credential, failure), "dns_provider_route53_present_txt_xml_escapes");
    suite.expect(stringContains(route53TXTXML.body, "<Value>&quot;token&amp;&lt;\\&quot;quote&quot;</Value>"), "dns_provider_route53_present_txt_xml_escaped_value");

    RecordingRoute53DNSProvider route53TXTCleanup = {};
    route53TXTCleanup.responses.push_back("<ListResourceRecordSetsResponse><ResourceRecordSets><ResourceRecordSet><Name>_acme-challenge.api.example.com.</Name><Type>TXT</Type><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>\"old-token\"</Value></ResourceRecord><ResourceRecord><Value>\"token-1\"</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></ResourceRecordSets></ListResourceRecordSetsResponse>"_ctv);
    suite.expect(testDNSCleanupTXT(route53TXTCleanup, txt, credential, failure), "dns_provider_route53_cleanup_txt_preserves_sibling");
    suite.expect(stringContains(route53TXTCleanup.body, "<Action>UPSERT</Action>") && stringContains(route53TXTCleanup.body, "<Value>&quot;old-token&quot;</Value>") && stringContains(route53TXTCleanup.body, "<Value>&quot;token-1&quot;</Value>") == false, "dns_provider_route53_cleanup_txt_removes_exact_value");

    RecordingRoute53DNSProvider route53TXTDelete = {};
    route53TXTDelete.responses.push_back("<ListResourceRecordSetsResponse><ResourceRecordSets><ResourceRecordSet><Name>_acme-challenge.api.example.com.</Name><Type>TXT</Type><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>\"token-1\"</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></ResourceRecordSets></ListResourceRecordSetsResponse>"_ctv);
    suite.expect(testDNSCleanupTXT(route53TXTDelete, txt, credential, failure), "dns_provider_route53_cleanup_txt_deletes_empty_rrset");
    suite.expect(stringContains(route53TXTDelete.body, "<Action>DELETE</Action>") && stringContains(route53TXTDelete.body, "<Value>&quot;token-1&quot;</Value>"), "dns_provider_route53_cleanup_txt_delete_body_targets_old_rrset");

    RecordingGcpCloudDNSProvider gcpTXT = {};
    txt.provider = "gcp-cloud-dns"_ctv;
    txt.zone = "prod-zone"_ctv;
    credential.material = "token"_ctv;
    credential.metadata.clear();
    credential.metadata["project"_ctv] = "proj"_ctv;
    credential.metadata["bearerRefreshCommand"_ctv] = "printf refreshed-gcp-txt"_ctv;
    gcpTXT.responses.push_back("{\"rrsets\":[{\"name\":\"_acme-challenge.api.example.com.\",\"type\":\"TXT\",\"ttl\":60,\"rrdatas\":[\"\\\"old-token\\\"\"]}]}"_ctv);
    gcpTXT.responses.push_back("{\"id\":\"change-1\"}"_ctv);
    suite.expect(testDNSPresentTXT(gcpTXT, txt, credential, failure), "dns_provider_gcp_present_txt_merges_rrset");
    suite.expect(gcpTXT.requests.size() == 2 && stringContains(gcpTXT.requests[1].body, "\"deletions\"") && stringContains(gcpTXT.requests[1].body, "\"additions\""), "dns_provider_gcp_present_txt_replaces_rrset");
    suite.expect(stringContains(gcpTXT.requests[1].body, "\\\"old-token\\\"") && stringContains(gcpTXT.requests[1].body, "\\\"token-1\\\""), "dns_provider_gcp_present_txt_preserves_sibling");
    suite.expect(gcpTXT.requests.size() == 2 && gcpTXT.requests[0].headers.size() == 1 && gcpTXT.requests[1].headers.size() == 2 && gcpTXT.requests[0].headers[0].equal("Authorization: Bearer refreshed-gcp-txt"_ctv) && gcpTXT.requests[1].headers[1].equal("Authorization: Bearer refreshed-gcp-txt"_ctv), "dns_provider_gcp_present_txt_refreshes_bearer");

    RecordingGcpCloudDNSProvider gcpTXTCleanup = {};
    gcpTXTCleanup.responses.push_back("{\"rrsets\":[{\"name\":\"_acme-challenge.api.example.com.\",\"type\":\"TXT\",\"ttl\":60,\"rrdatas\":[\"\\\"old-token\\\"\",\"\\\"token-1\\\"\"]}]}"_ctv);
    gcpTXTCleanup.responses.push_back("{\"id\":\"change-2\"}"_ctv);
    suite.expect(testDNSCleanupTXT(gcpTXTCleanup, txt, credential, failure), "dns_provider_gcp_cleanup_txt_preserves_sibling");
    suite.expect(gcpTXTCleanup.requests.size() == 2 && stringContains(gcpTXTCleanup.requests[1].body, "\"deletions\"") && stringContains(gcpTXTCleanup.requests[1].body, "\"additions\""), "dns_provider_gcp_cleanup_txt_replaces_rrset");
    suite.expect(stringContains(gcpTXTCleanup.requests[1].body, "\\\"old-token\\\"") && stringContains(gcpTXTCleanup.requests[1].body, "\\\"token-1\\\""), "dns_provider_gcp_cleanup_txt_delete_mentions_old_rrset");

    RecordingGcpCloudDNSProvider gcpTXTDelete = {};
    gcpTXTDelete.responses.push_back("{\"rrsets\":[{\"name\":\"_acme-challenge.api.example.com.\",\"type\":\"TXT\",\"ttl\":60,\"rrdatas\":[\"\\\"token-1\\\"\"]}]}"_ctv);
    gcpTXTDelete.responses.push_back("{\"id\":\"change-3\"}"_ctv);
    suite.expect(testDNSCleanupTXT(gcpTXTDelete, txt, credential, failure), "dns_provider_gcp_cleanup_txt_deletes_empty_rrset");
    suite.expect(gcpTXTDelete.requests.size() == 2 && stringContains(gcpTXTDelete.requests[1].body, "\"deletions\"") && stringContains(gcpTXTDelete.requests[1].body, "\"additions\"") == false, "dns_provider_gcp_cleanup_txt_delete_omits_empty_additions");

    RecordingAzureDNSProvider azureTXT = {};
    txt.provider = "azure-dns"_ctv;
    txt.zone = "example.com"_ctv;
    credential.metadata.clear();
    credential.metadata["subscriptionID"_ctv] = "sub"_ctv;
    credential.metadata["resourceGroup"_ctv] = "rg"_ctv;
    credential.metadata["bearerRefreshCommand"_ctv] = "printf refreshed-azure-txt"_ctv;
    azureTXT.responses.push_back("{\"properties\":{\"TXTRecords\":[{\"value\":[\"old-token\"]}]}}"_ctv);
    azureTXT.responses.push_back("{}"_ctv);
    suite.expect(testDNSPresentTXT(azureTXT, txt, credential, failure), "dns_provider_azure_present_txt_merges_rrset");
    suite.expect(azureTXT.requests.size() == 2 && azureTXT.requests[1].method.equal("PUT"_ctv), "dns_provider_azure_present_txt_puts_rrset");
    suite.expect(stringContains(azureTXT.requests[1].body, "\"TXTRecords\"") && stringContains(azureTXT.requests[1].body, "\"old-token\"") && stringContains(azureTXT.requests[1].body, "\"token-1\""), "dns_provider_azure_present_txt_preserves_sibling");
    suite.expect(azureTXT.requests.size() == 2 && azureTXT.requests[0].headers.size() == 1 && azureTXT.requests[1].headers.size() == 2 && azureTXT.requests[0].headers[0].equal("Authorization: Bearer refreshed-azure-txt"_ctv) && azureTXT.requests[1].headers[1].equal("Authorization: Bearer refreshed-azure-txt"_ctv), "dns_provider_azure_present_txt_refreshes_bearer");

    RecordingAzureDNSProvider azureTXTCleanup = {};
    azureTXTCleanup.responses.push_back("{\"properties\":{\"TXTRecords\":[{\"value\":[\"old-token\"]},{\"value\":[\"token-1\"]}]}}"_ctv);
    azureTXTCleanup.responses.push_back("{}"_ctv);
    suite.expect(testDNSCleanupTXT(azureTXTCleanup, txt, credential, failure), "dns_provider_azure_cleanup_txt_preserves_sibling");
    suite.expect(azureTXTCleanup.requests.size() == 2 && azureTXTCleanup.requests[1].method.equal("PUT"_ctv), "dns_provider_azure_cleanup_txt_puts_remaining_rrset");
    suite.expect(stringContains(azureTXTCleanup.requests[1].body, "\"old-token\"") && stringContains(azureTXTCleanup.requests[1].body, "\"token-1\"") == false, "dns_provider_azure_cleanup_txt_removes_exact_value");

    RecordingAzureDNSProvider azureTXTDelete = {};
    azureTXTDelete.responses.push_back("{\"properties\":{\"TXTRecords\":[{\"value\":[\"token-1\"]}]}}"_ctv);
    azureTXTDelete.responses.push_back("{}"_ctv);
    suite.expect(testDNSCleanupTXT(azureTXTDelete, txt, credential, failure), "dns_provider_azure_cleanup_txt_deletes_empty_rrset");
    suite.expect(azureTXTDelete.requests.size() == 2 && azureTXTDelete.requests[1].method.equal("DELETE"_ctv), "dns_provider_azure_cleanup_txt_delete_uses_delete");

    RecordingVultrDNSProvider vultrTXT = {};
    txt.provider = "vultr-dns"_ctv;
    credential.material = "token"_ctv;
    credential.metadata.clear();
    vultrTXT.responses.push_back("{\"records\":[{\"id\":\"old\",\"type\":\"TXT\",\"name\":\"_acme-challenge.api\",\"data\":\"old-token\"}]}"_ctv);
    vultrTXT.responses.push_back("{}"_ctv);
    suite.expect(testDNSPresentTXT(vultrTXT, txt, credential, failure), "dns_provider_vultr_present_txt_ignores_sibling_value");
    suite.expect(vultrTXT.requests.size() == 2 && vultrTXT.requests[1].method.equal("POST"_ctv), "dns_provider_vultr_present_txt_posts_missing_exact_value");

    RecordingVultrDNSProvider vultrTXTMissingCleanup = {};
    vultrTXTMissingCleanup.responses.push_back("{\"records\":[{\"id\":\"old\",\"type\":\"TXT\",\"name\":\"_acme-challenge.api\",\"data\":\"old-token\"}]}"_ctv);
    suite.expect(testDNSCleanupTXT(vultrTXTMissingCleanup, txt, credential, failure), "dns_provider_vultr_cleanup_txt_missing_exact_value_succeeds");
    suite.expect(vultrTXTMissingCleanup.requests.size() == 1, "dns_provider_vultr_cleanup_txt_missing_exact_value_does_not_delete");
  }

  {
    Advertisement scheduledAdvertisement(0x1001, ContainerState::scheduled, ContainerState::destroying, 7001);
    Advertisement healthyAdvertisement(0x1002, ContainerState::healthy, ContainerState::destroying, 7002);
    Subscription scheduledSubscription(0x1003, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::any);
    Subscription healthySubscription(0x1004, ContainerState::healthy, ContainerState::destroying, SubscriptionNature::any);

    suite.expect(
        serviceBlueprintActiveAtContainerState(scheduledAdvertisement, ContainerState::scheduled),
        "service_blueprint_scheduled_advertisement_active_at_scheduled");
    suite.expect(
        serviceBlueprintActiveAtContainerState(healthyAdvertisement, ContainerState::scheduled) == false,
        "service_blueprint_healthy_advertisement_inactive_at_scheduled");
    suite.expect(
        serviceBlueprintActiveAtContainerState(scheduledSubscription, ContainerState::healthy),
        "service_blueprint_scheduled_subscription_still_active_at_healthy");
    suite.expect(
        serviceBlueprintActiveAtContainerState(healthySubscription, ContainerState::healthy),
        "service_blueprint_healthy_subscription_active_at_healthy");
    suite.expect(
        serviceBlueprintActiveAtContainerState(scheduledAdvertisement, ContainerState::crashedRestarting),
        "service_blueprint_scheduled_advertisement_active_at_crashed_restarting");
    suite.expect(
        serviceBlueprintActiveAtContainerState(healthyAdvertisement, ContainerState::crashedRestarting) == false,
        "service_blueprint_healthy_advertisement_inactive_at_crashed_restarting");
    suite.expect(
        serviceBlueprintActiveAtContainerState(scheduledAdvertisement, ContainerState::destroying) == false,
        "service_blueprint_scheduled_advertisement_inactive_at_destroying");
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);
    deployment.state = DeploymentState::running;

    PairingCountingContainerView advertiser;
    PairingCountingContainerView subscriber;
    const uint64_t service = (uint64_t(777) << 48) | uint64_t(1);
    const uint16_t port = 9191;

    advertiser.uuid = uint128_t(0x777001);
    advertiser.deploymentID = deployment.plan.config.deploymentID();
    advertiser.applicationID = deployment.plan.config.applicationID;
    advertiser.lifetime = ApplicationLifetime::base;
    advertiser.state = ContainerState::scheduled;
    advertiser.advertisements.emplace(service, Advertisement(service, ContainerState::scheduled, ContainerState::destroying, port));
    advertiser.advertisingOnPorts.insert(port);

    subscriber.uuid = uint128_t(0x777002);
    subscriber.deploymentID = deployment.plan.config.deploymentID();
    subscriber.applicationID = deployment.plan.config.applicationID;
    subscriber.lifetime = ApplicationLifetime::base;
    subscriber.state = ContainerState::scheduled;
    subscriber.subscriptions.emplace(service, Subscription(service, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all));

    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);
    deployment.containers.insert(&advertiser);
    deployment.containers.insert(&subscriber);

    brain.mesh->advertise(service, &advertiser, port, false);
    brain.mesh->subscribe(service, &subscriber, SubscriptionNature::all, false);

    suite.expect(brain.mesh->pairingSecretFor(&advertiser, &subscriber, service) != 0, "container_healthy_replay_fixture_has_scheduled_pairing");
    suite.expect(advertiser.advertisementActivations == 0, "container_healthy_replay_fixture_defers_advertiser_pairing_until_runtime_ready");
    suite.expect(subscriber.subscriptionActivations == 0, "container_healthy_replay_fixture_does_not_notify_subscriber");
    advertiser.advertisementActivations = 0;
    subscriber.subscriptionActivations = 0;

    deployment.containerIsHealthy(&subscriber);
    suite.expect(advertiser.advertisementActivations == 0, "container_healthy_does_not_replay_scheduled_pairing_to_peer");
    suite.expect(subscriber.subscriptionActivations == 0, "container_healthy_does_not_replay_scheduled_pairing_to_self");

    deployment.containerIsHealthy(&subscriber);
    suite.expect(advertiser.advertisementActivations == 0, "container_duplicate_healthy_does_not_replay_pairing_to_peer");
    suite.expect(subscriber.subscriptionActivations == 0, "container_duplicate_healthy_does_not_replay_pairing_to_self");

    deployment.recoverAfterReboot();
    suite.expect(advertiser.advertisementActivations == 0, "deployment_recover_after_reboot_does_not_replay_pairing_to_peer");
    suite.expect(subscriber.subscriptionActivations == 0, "deployment_recover_after_reboot_does_not_replay_pairing_to_self");

    brain.deployments.erase(deployment.plan.config.deploymentID());
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rackA {};
    rackA.uuid = 1905;
    Rack rackB {};
    rackB.uuid = 1906;
    brain.racks.insert_or_assign(rackA.uuid, &rackA);
    brain.racks.insert_or_assign(rackB.uuid, &rackB);

    Machine closedMachine {};
    closedMachine.uuid = uint128_t(0x190507);
    closedMachine.slug = "closed-neuron-source"_ctv;
    closedMachine.rack = &rackA;
    closedMachine.state = MachineState::healthy;
    closedMachine.lifetime = MachineLifetime::owned;
    closedMachine.nLogicalCores_available = 8;
    closedMachine.memoryMB_available = 8192;
    closedMachine.storageMB_available = 4096;
    closedMachine.neuron.machine = &closedMachine;
    rackA.machines.insert(&closedMachine);
    brain.machines.insert(&closedMachine);

    ScopedSocketPair socket = {};
    bool socketReady = socket.create(suite, "drainMachine_filtered_scheduled_waiter_creates_socketpair");

    Machine targetMachine {};
    targetMachine.uuid = uint128_t(0x190508);
    targetMachine.slug = "scheduled-waiter-target"_ctv;
    targetMachine.rack = &rackB;
    targetMachine.state = MachineState::healthy;
    targetMachine.lifetime = MachineLifetime::owned;
    targetMachine.nLogicalCores_available = 8;
    targetMachine.memoryMB_available = 8192;
    targetMachine.storageMB_available = 4096;
    bool targetReady = socketReady && armNeuronControlStream(targetMachine, socket);
    rackB.machines.insert(&targetMachine);
    brain.machines.insert(&targetMachine);

    suite.expect(targetReady, "drainMachine_filtered_scheduled_waiter_seeds_target_control_stream");

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.stateless.nBase = 2;
    deployment.nTargetBase = 2;
    deployment.nDeployedBase = 2;
    deployment.nHealthyBase = 1;
    deployment.state = DeploymentState::deploying;
    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

    ContainerView *scheduled = new ContainerView();
    scheduled->uuid = uint128_t(0x190501);
    scheduled->deploymentID = deployment.plan.config.deploymentID();
    scheduled->applicationID = deployment.plan.config.applicationID;
    scheduled->machine = &closedMachine;
    scheduled->lifetime = ApplicationLifetime::base;
    scheduled->state = ContainerState::scheduled;

    ContainerView *healthy = new ContainerView();
    healthy->uuid = uint128_t(0x190502);
    healthy->deploymentID = deployment.plan.config.deploymentID();
    healthy->applicationID = deployment.plan.config.applicationID;
    healthy->machine = &closedMachine;
    healthy->lifetime = ApplicationLifetime::base;
    healthy->state = ContainerState::healthy;

    deployment.containers.insert(scheduled);
    deployment.containers.insert(healthy);
    deployment.waitingOnContainers.insert_or_assign(scheduled, ContainerState::healthy);
    closedMachine.upsertContainerIndexEntry(healthy->deploymentID, healthy);
    brain.containers.insert_or_assign(scheduled->uuid, scheduled);
    brain.containers.insert_or_assign(healthy->uuid, healthy);

    uint128_t scheduledUUID = scheduled->uuid;

    deployment.drainMachine(&closedMachine, true, true);

    suite.expect(brain.containers.contains(scheduledUUID) == false, "drainMachine_filtered_scheduled_waiter_destroys_lost_container");
    suite.expect(deployment.containers.contains(healthy), "drainMachine_filtered_scheduled_waiter_preserves_healthy_container");
    suite.expect(closedMachine.containersByDeploymentID.hasEntryFor(healthy->deploymentID, healthy), "drainMachine_filtered_scheduled_waiter_keeps_healthy_machine_index");
    suite.expect(deployment.waitingOnContainers.contains(scheduled) == false, "drainMachine_filtered_scheduled_waiter_clears_old_waiter");

    ContainerView *replacement = nullptr;
    for (ContainerView *container : deployment.containers)
    {
      if (container != healthy && container->machine == &targetMachine)
      {
        replacement = container;
        break;
      }
    }

    suite.expect(replacement != nullptr, "drainMachine_filtered_scheduled_waiter_creates_replacement");
    suite.expect(replacement == nullptr || replacement->state == ContainerState::scheduled, "drainMachine_filtered_scheduled_waiter_schedules_replacement");
    suite.expect(replacement == nullptr || targetMachine.containersByDeploymentID.hasEntryFor(replacement->deploymentID, replacement), "drainMachine_filtered_scheduled_waiter_indexes_replacement_target");
    suite.expect(deployment.waitingOnContainers.size() == 1, "drainMachine_filtered_scheduled_waiter_waits_on_replacement_only");
    suite.expect(deployment.nDeployedBase == 2, "drainMachine_filtered_scheduled_waiter_preserves_deployed_target");
    suite.expect(deployment.nHealthyBase == 1, "drainMachine_filtered_scheduled_waiter_preserves_healthy_count");

    Vector<ContainerView *> cleanup;
    for (ContainerView *container : deployment.containers)
    {
      cleanup.push_back(container);
    }
    for (ContainerView *container : cleanup)
    {
      if (container == nullptr)
      {
        continue;
      }
      if (container->plannedWork)
      {
        deployment.cancelDeploymentWork(container->plannedWork);
      }
      deployment.waitingOnContainers.erase(container);
      deployment.containers.erase(container);
      if (container->machine)
      {
        container->machine->removeContainerIndexEntry(container->deploymentID, container);
      }
      brain.containers.erase(container->uuid);
      delete container;
    }

    brain.deployments.erase(deployment.plan.config.deploymentID());
    brain.machines.erase(&closedMachine);
    brain.machines.erase(&targetMachine);
    rackA.machines.erase(&closedMachine);
    rackB.machines.erase(&targetMachine);
    brain.racks.erase(rackA.uuid);
    brain.racks.erase(rackB.uuid);
    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);
    deployment.state = DeploymentState::running;

    PairingCountingContainerView advertiser;
    PairingCountingContainerView subscriber;
    const uint64_t service = (uint64_t(887) << 48) | uint64_t(2);
    const uint16_t port = 9287;

    advertiser.uuid = uint128_t(0x887001);
    advertiser.deploymentID = deployment.plan.config.deploymentID();
    advertiser.applicationID = deployment.plan.config.applicationID;
    advertiser.lifetime = ApplicationLifetime::base;
    advertiser.state = ContainerState::scheduled;
    advertiser.advertisements.emplace(service, Advertisement(service, ContainerState::scheduled, ContainerState::destroying, port));
    advertiser.advertisingOnPorts.insert(port);

    subscriber.uuid = uint128_t(0x887002);
    subscriber.deploymentID = deployment.plan.config.deploymentID();
    subscriber.applicationID = deployment.plan.config.applicationID;
    subscriber.lifetime = ApplicationLifetime::base;
    subscriber.state = ContainerState::scheduled;
    subscriber.subscriptions.emplace(service, Subscription(service, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all));

    deployment.containers.insert(&advertiser);
    deployment.containers.insert(&subscriber);

    brain.mesh->advertise(service, &advertiser, port, false);
    brain.mesh->subscribe(service, &subscriber, SubscriptionNature::all, false);

    suite.expect(brain.mesh->pairingSecretFor(&advertiser, &subscriber, service) != 0, "container_runtime_ready_advertiser_first_fixture_has_pairing");
    advertiser.advertisementActivations = 0;
    subscriber.subscriptionActivations = 0;

    deployment.containerIsRuntimeReady(&advertiser);
    suite.expect(advertiser.advertisementActivations == 1, "container_runtime_ready_advertiser_first_preinstalls_secret");
    suite.expect(subscriber.subscriptionActivations == 0, "container_runtime_ready_advertiser_first_waits_for_subscriber");

    deployment.containerIsRuntimeReady(&subscriber);
    suite.expect(advertiser.advertisementActivations == 1, "container_runtime_ready_subscriber_second_does_not_reinstall_secret");
    suite.expect(subscriber.subscriptionActivations == 1, "container_runtime_ready_subscriber_second_connects_after_secret_preinstall");

    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);
    deployment.state = DeploymentState::running;

    PairingCountingContainerView advertiser;
    PairingCountingContainerView subscriber;
    const uint64_t service = (uint64_t(888) << 48) | uint64_t(2);
    const uint16_t port = 9292;

    advertiser.uuid = uint128_t(0x888001);
    advertiser.deploymentID = deployment.plan.config.deploymentID();
    advertiser.applicationID = deployment.plan.config.applicationID;
    advertiser.lifetime = ApplicationLifetime::base;
    advertiser.state = ContainerState::scheduled;
    advertiser.advertisements.emplace(service, Advertisement(service, ContainerState::scheduled, ContainerState::destroying, port));
    advertiser.advertisingOnPorts.insert(port);

    subscriber.uuid = uint128_t(0x888002);
    subscriber.deploymentID = deployment.plan.config.deploymentID();
    subscriber.applicationID = deployment.plan.config.applicationID;
    subscriber.lifetime = ApplicationLifetime::base;
    subscriber.state = ContainerState::scheduled;
    subscriber.subscriptions.emplace(service, Subscription(service, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all));

    deployment.containers.insert(&advertiser);
    deployment.containers.insert(&subscriber);

    brain.mesh->advertise(service, &advertiser, port, false);
    brain.mesh->subscribe(service, &subscriber, SubscriptionNature::all, false);

    suite.expect(brain.mesh->pairingSecretFor(&advertiser, &subscriber, service) != 0, "container_runtime_ready_fixture_has_scheduled_pairing");
    advertiser.advertisementActivations = 0;
    subscriber.subscriptionActivations = 0;

    deployment.containerIsRuntimeReady(&subscriber);
    suite.expect(subscriber.runtimeReady, "container_runtime_ready_marks_first_peer_ready");
    suite.expect(advertiser.advertisementActivations == 0, "container_runtime_ready_waits_for_advertiser");
    suite.expect(subscriber.subscriptionActivations == 0, "container_runtime_ready_waits_for_peer_listener");

    deployment.containerIsRuntimeReady(&subscriber);
    suite.expect(advertiser.advertisementActivations == 0, "container_runtime_ready_ignores_duplicate_subscriber");
    suite.expect(subscriber.subscriptionActivations == 0, "container_runtime_ready_duplicate_subscriber_has_no_subscription");

    deployment.containerIsRuntimeReady(&advertiser);
    suite.expect(advertiser.runtimeReady, "container_runtime_ready_marks_second_peer_ready");
    suite.expect(advertiser.advertisementActivations == 1, "container_runtime_ready_replays_advertiser_pairing_after_both_ready");
    suite.expect(subscriber.subscriptionActivations == 1, "container_runtime_ready_replays_subscriber_pairing_after_both_ready");

    deployment.containerIsRuntimeReady(&advertiser);
    suite.expect(advertiser.advertisementActivations == 1, "container_runtime_ready_ignores_duplicate_advertiser");
    suite.expect(subscriber.subscriptionActivations == 1, "container_runtime_ready_duplicate_advertiser_has_no_subscription");

    advertiser.runtimeReady = false;
    deployment.containerIsRuntimeReady(&advertiser);
    suite.expect(advertiser.advertisementActivations == 2, "container_runtime_ready_replays_after_restart_reset");
    suite.expect(subscriber.subscriptionActivations == 2, "container_runtime_ready_replays_subscription_after_restart_reset");

    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);
    deployment.state = DeploymentState::running;

    PairingCountingContainerView advertiser;
    PairingCountingContainerView subscriber;
    const uint64_t service = (uint64_t(891) << 48) | uint64_t(2);
    const uint16_t port = 9595;

    advertiser.uuid = uint128_t(0x891001);
    advertiser.deploymentID = deployment.plan.config.deploymentID();
    advertiser.applicationID = deployment.plan.config.applicationID;
    advertiser.lifetime = ApplicationLifetime::base;
    advertiser.state = ContainerState::healthy;
    advertiser.runtimeReady = true;
    advertiser.advertisements.emplace(service, Advertisement(service, ContainerState::scheduled, ContainerState::destroying, port));
    advertiser.advertisingOnPorts.insert(port);

    subscriber.uuid = uint128_t(0x891002);
    subscriber.deploymentID = deployment.plan.config.deploymentID();
    subscriber.applicationID = deployment.plan.config.applicationID;
    subscriber.lifetime = ApplicationLifetime::base;
    subscriber.state = ContainerState::healthy;
    subscriber.runtimeReady = false;
    subscriber.subscriptions.emplace(service, Subscription(service, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all));

    brain.mesh->advertise(service, &advertiser, port, false);
    brain.mesh->subscribe(service, &subscriber, SubscriptionNature::all, false);

    suite.expect(brain.mesh->pairingSecretFor(&advertiser, &subscriber, service) != 0, "container_restart_peer_refresh_fixture_has_pairing");
    suite.expect(advertiser.advertisingTo.hasEntryFor(service, &subscriber), "container_restart_peer_refresh_fixture_has_advertising_edge");
    suite.expect(subscriber.subscribedTo.hasEntryFor(service, &advertiser), "container_restart_peer_refresh_fixture_has_subscription_edge");

    advertiser.deactivateActivePeerSubscriptionsForRestart();
    suite.expect(subscriber.subscriptionDeactivations == 1, "container_restart_peer_refresh_deactivates_peer_subscription");
    suite.expect(advertiser.advertisingTo.hasEntryFor(service, &subscriber), "container_restart_peer_refresh_keeps_advertising_edge");
    suite.expect(subscriber.subscribedTo.hasEntryFor(service, &advertiser), "container_restart_peer_refresh_keeps_subscription_edge");

    advertiser.runtimeReady = false;
    deployment.containerIsRuntimeReady(&advertiser);
    suite.expect(subscriber.subscriptionActivations == 1, "container_restart_peer_refresh_reactivates_healthy_subscriber_without_runtime_ready");

    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);
    deployment.state = DeploymentState::running;

    PairingCountingContainerView advertiser;
    PairingCountingContainerView subscriber;
    const uint64_t service = (uint64_t(889) << 48) | uint64_t(2);
    const uint16_t port = 9393;

    advertiser.uuid = uint128_t(0x889001);
    advertiser.deploymentID = deployment.plan.config.deploymentID();
    advertiser.applicationID = deployment.plan.config.applicationID;
    advertiser.lifetime = ApplicationLifetime::base;
    advertiser.state = ContainerState::scheduled;
    advertiser.advertisements.emplace(service, Advertisement(service, ContainerState::scheduled, ContainerState::destroying, port));
    advertiser.advertisingOnPorts.insert(port);

    subscriber.uuid = uint128_t(0x889002);
    subscriber.deploymentID = deployment.plan.config.deploymentID();
    subscriber.applicationID = deployment.plan.config.applicationID;
    subscriber.lifetime = ApplicationLifetime::base;
    subscriber.state = ContainerState::scheduled;
    subscriber.subscriptions.emplace(service, Subscription(service, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all));

    brain.mesh->advertise(service, &advertiser, port, false);
    brain.mesh->subscribe(service, &subscriber, SubscriptionNature::all, false);

    suite.expect(brain.mesh->pairingSecretFor(&advertiser, &subscriber, service) != 0, "containerview_generatePlan_runtime_ready_fixture_has_pairing");

    ContainerPlan subscriberUnreadyPlan = subscriber.generatePlan(deployment.plan);
    ContainerPlan advertiserUnreadyPlan = advertiser.generatePlan(deployment.plan);
    suite.expect(subscriberUnreadyPlan.subscriptionPairings.isEmpty(), "containerview_generatePlan_omits_subscription_to_unready_advertiser");
    suite.expect(advertiserUnreadyPlan.advertisementPairings.isEmpty() == false, "containerview_generatePlan_preinstalls_advertisement_for_unready_subscriber");

    advertiser.runtimeReady = true;
    ContainerPlan subscriberAdvertiserReadyPlan = subscriber.generatePlan(deployment.plan);
    ContainerPlan advertiserSubscriberUnreadyPlan = advertiser.generatePlan(deployment.plan);
    suite.expect(subscriberAdvertiserReadyPlan.subscriptionPairings.isEmpty() == false, "containerview_generatePlan_includes_subscription_to_ready_advertiser");
    suite.expect(advertiserSubscriberUnreadyPlan.advertisementPairings.isEmpty() == false, "containerview_generatePlan_keeps_advertisement_for_unready_subscriber");

    subscriber.runtimeReady = true;
    ContainerPlan advertiserBothReadyPlan = advertiser.generatePlan(deployment.plan);
    suite.expect(advertiserBothReadyPlan.advertisementPairings.isEmpty() == false, "containerview_generatePlan_includes_advertisement_for_ready_subscriber");

    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);
    deployment.state = DeploymentState::running;

    PairingCountingContainerView advertiser;
    PairingCountingContainerView subscriber;
    const uint64_t service = (uint64_t(890) << 48) | uint64_t(2);
    const uint16_t port = 9494;

    advertiser.uuid = uint128_t(0x890001);
    advertiser.deploymentID = deployment.plan.config.deploymentID();
    advertiser.applicationID = deployment.plan.config.applicationID;
    advertiser.lifetime = ApplicationLifetime::base;
    advertiser.state = ContainerState::scheduled;
    advertiser.advertisements.emplace(service, Advertisement(service, ContainerState::scheduled, ContainerState::destroying, port));
    advertiser.advertisingOnPorts.insert(port);

    subscriber.uuid = uint128_t(0x890002);
    subscriber.deploymentID = deployment.plan.config.deploymentID();
    subscriber.applicationID = deployment.plan.config.applicationID;
    subscriber.lifetime = ApplicationLifetime::base;
    subscriber.state = ContainerState::scheduled;
    subscriber.subscriptions.emplace(service, Subscription(service, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all));

    deployment.containers.insert(&advertiser);
    deployment.containers.insert(&subscriber);

    brain.mesh->advertise(service, &advertiser, port, true);
    brain.mesh->subscribe(service, &subscriber, SubscriptionNature::all, true);

    suite.expect(brain.mesh->pairingSecretFor(&advertiser, &subscriber, service) != 0, "mesh_notify_true_unready_fixture_has_pairing");
    suite.expect(advertiser.advertisementActivations == 0, "mesh_notify_true_unready_advertiser_not_notified");
    suite.expect(subscriber.subscriptionActivations == 0, "mesh_notify_true_unready_subscriber_not_notified");

    deployment.containerIsRuntimeReady(&subscriber);
    suite.expect(advertiser.advertisementActivations == 0, "mesh_notify_true_subscriber_first_advertiser_not_notified");
    suite.expect(subscriber.subscriptionActivations == 0, "mesh_notify_true_subscriber_first_subscription_not_notified");

    deployment.containerIsRuntimeReady(&advertiser);
    suite.expect(advertiser.advertisementActivations == 1, "mesh_notify_true_advertiser_second_advertisement_notified");
    suite.expect(subscriber.subscriptionActivations == 1, "mesh_notify_true_advertiser_second_subscription_notified");

    thisBrain = savedBrain;
  }

  {
    suite.expect(
        prodigyContainerIngressNetkitAttachType() == BPF_NETKIT_PRIMARY,
        "container_netkit_ingress_attach_type_is_primary");
    suite.expect(
        prodigyContainerEgressNetkitAttachType() == BPF_NETKIT_PEER,
        "container_netkit_egress_attach_type_is_peer");
    suite.expect(
        prodigyContainerIngressNetkitAttachType() != prodigyContainerEgressNetkitAttachType(),
        "container_netkit_attach_types_are_distinct");
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Machine machine = {};
    machine.ownedLogicalCores = 6;
    machine.ownedMemoryMB = 12'288;
    machine.ownedStorageMB = 258'048;

    ApplicationConfig config = {};
    config.architecture = nametagCurrentBuildMachineArchitecture();

    suite.expect(prodigyMachineMeetsApplicationResourceCriteria(&machine, config) == false, "resource_criteria_rejects_unknown_architecture_in_production");

    brain.brainConfig.runtimeEnvironment.test.enabled = true;
    brain.brainConfig.architecture = config.architecture;
    suite.expect(prodigyMachineMeetsApplicationResourceCriteria(&machine, config), "resource_criteria_uses_test_cluster_configured_architecture");

    thisBrain = savedBrain;
  }

  {
    Vector<MachineDiskHardwareProfile> disks;

    auto addDisk = [&](const char *mountPath) -> void {
      MachineDiskHardwareProfile disk = {};
      disk.mountPath.assign(mountPath);
      disks.push_back(std::move(disk));
    };

    addDisk("/");
    addDisk("/boot");
    addDisk("/boot/efi");
    addDisk("/containers");
    addDisk("/containers/data");
    addDisk("/data");
    addDisk("/archive");
    addDisk("/data");

    Vector<String> mountPaths;
    prodigyCollectUniqueContainerStorageMountPaths(disks, mountPaths);

    suite.expect(mountPaths.size() == 2, "storage_mount_inventory_excludes_reserved_paths_and_deduplicates");
    suite.expect(mountPaths.size() == 2 && mountPaths[0] == "/archive"_ctv, "storage_mount_inventory_sorts_mount_paths_0");
    suite.expect(mountPaths.size() == 2 && mountPaths[1] == "/data"_ctv, "storage_mount_inventory_sorts_mount_paths_1");
  }

  {
    Vector<String> mountPaths;
    mountPaths.push_back("/archive"_ctv);
    mountPaths.push_back("/data"_ctv);

    Vector<ProdigyContainerStorageDevicePlan> plans;
    prodigyBuildContainerStorageDevicePlan(mountPaths, "container-uuid"_ctv, 127, plans);
    suite.expect(plans.empty(), "storage_plan_builder_requires_minimum_loop_device_size");

    prodigyBuildContainerStorageDevicePlan(mountPaths, "container-uuid"_ctv, 256, plans);
    suite.expect(plans.size() == 2, "storage_plan_builder_uses_inventory_mount_paths");
    suite.expect(plans.size() == 2 && plans[0].mountPath == "/archive"_ctv, "storage_plan_builder_sets_mount_path_0");
    suite.expect(plans.size() == 2 && plans[1].mountPath == "/data"_ctv, "storage_plan_builder_sets_mount_path_1");
    suite.expect(plans.size() == 2 && plans[0].sizeMB == 128, "storage_plan_builder_splits_target_size_0");
    suite.expect(plans.size() == 2 && plans[1].sizeMB == 128, "storage_plan_builder_splits_target_size_1");
    suite.expect(
        plans.size() == 2 && plans[0].backingFilePath == "/archive/.prodigy/container-storage/container-uuid.btrfs.loop"_ctv,
        "storage_plan_builder_sets_backing_file_path_0");
    suite.expect(
        plans.size() == 2 && plans[1].backingFilePath == "/data/.prodigy/container-storage/container-uuid.btrfs.loop"_ctv,
        "storage_plan_builder_sets_backing_file_path_1");
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "launch_metadata_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      MachineCpuArchitecture currentArchitecture = nametagCurrentBuildMachineArchitecture();
      String currentArchitectureText = {};
      currentArchitectureText.assign(machineCpuArchitectureName(currentArchitecture));
      String metadataJSON = {};
      metadataJSON.assign(
          "{\n"
          "  \"execute_path\": \"/app/hello\",\n"
          "  \"execute_args\": [\"--port\", \"7777\"],\n"
          "  \"execute_env\": [\"FOO=bar\", \"BAZ=qux\"],\n"
          "  \"execute_cwd\": \"/app\",\n"
          "  \"execute_arch\": \"");
      metadataJSON.append(currentArchitectureText);
      metadataJSON.append("\"\n}\n"_ctv);
      suite.expect(
          writeLaunchMetadataFixture(
              artifactRoot.path,
              metadataJSON.c_str()),
          "launch_metadata_fixture_written");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);
      container.plan.config.architecture = currentArchitecture;

      String failure = {};
      bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);

      suite.expect(loaded, "launch_metadata_runtime_loader_accepts_private_blob_metadata");
      suite.expect(failure.size() == 0, "launch_metadata_runtime_loader_success_clears_failure");
      suite.expect(container.executePath == "/app/hello"_ctv, "launch_metadata_runtime_loader_sets_execute_path");
      suite.expect(container.executeArgs.size() == 2, "launch_metadata_runtime_loader_sets_execute_arg_count");
      suite.expect(container.executeArgs.size() == 2 && container.executeArgs[0] == "--port"_ctv, "launch_metadata_runtime_loader_sets_execute_arg_0");
      suite.expect(container.executeArgs.size() == 2 && container.executeArgs[1] == "7777"_ctv, "launch_metadata_runtime_loader_sets_execute_arg_1");
      suite.expect(container.executeEnv.size() == 2, "launch_metadata_runtime_loader_sets_execute_env_count");
      suite.expect(container.executeEnv.size() == 2 && container.executeEnv[0] == "FOO=bar"_ctv, "launch_metadata_runtime_loader_sets_execute_env_0");
      suite.expect(container.executeEnv.size() == 2 && container.executeEnv[1] == "BAZ=qux"_ctv, "launch_metadata_runtime_loader_sets_execute_env_1");
      suite.expect(container.executeCwd == "/app"_ctv, "launch_metadata_runtime_loader_sets_execute_cwd");
      suite.expect(container.executeArchitecture == currentArchitecture, "launch_metadata_runtime_loader_sets_execute_architecture");
      suite.expect(container.executePath.c_str() != nullptr, "launch_metadata_runtime_loader_materializes_execute_path_c_string");
      suite.expect(container.executeCwd.c_str() != nullptr, "launch_metadata_runtime_loader_materializes_execute_cwd_c_string");
      suite.expect(container.executeArgs.size() == 2 && container.executeArgs[0].c_str() != nullptr, "launch_metadata_runtime_loader_materializes_execute_arg_c_string");
      suite.expect(container.executeEnv.size() == 2 && container.executeEnv[0].c_str() != nullptr, "launch_metadata_runtime_loader_materializes_execute_env_c_string");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "launch_metadata_arch_mismatch_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      suite.expect(
          writeLaunchMetadataFixture(
              artifactRoot.path,
              R"({
  "execute_path": "/app/hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/",
  "execute_arch": "x86_64"
})"),
          "launch_metadata_arch_mismatch_fixture_written");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);
      container.plan.config.architecture = MachineCpuArchitecture::aarch64;

      String failure = {};
      bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);

      suite.expect(loaded == false, "launch_metadata_runtime_loader_rejects_execute_arch_plan_mismatch");
      suite.expect(
          stringContains(failure, "mismatches plan architecture"),
          "launch_metadata_runtime_loader_reports_execute_arch_plan_mismatch");
    }
  }

  {
    MachineCpuArchitecture localArchitecture = nametagCurrentBuildMachineArchitecture();
    MachineCpuArchitecture wrongArchitecture = alternateSupportedArchitecture(localArchitecture);
    suite.expect(
        wrongArchitecture != MachineCpuArchitecture::unknown,
        "launch_metadata_local_arch_mismatch_fixture_has_supported_alternate_architecture");

    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "launch_metadata_local_arch_mismatch_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0 && wrongArchitecture != MachineCpuArchitecture::unknown)
    {
      String wrongArchitectureText = {};
      wrongArchitectureText.assign(machineCpuArchitectureName(wrongArchitecture));

      String metadataJSON = {};
      metadataJSON.assign(
          "{\n"
          "  \"execute_path\": \"/app/hello\",\n"
          "  \"execute_args\": [],\n"
          "  \"execute_env\": [],\n"
          "  \"execute_cwd\": \"/\",\n"
          "  \"execute_arch\": \""_ctv);
      metadataJSON.append(wrongArchitectureText);
      metadataJSON.append("\"\n}\n"_ctv);
      suite.expect(
          writeLaunchMetadataFixture(artifactRoot.path, metadataJSON.c_str()),
          "launch_metadata_local_arch_mismatch_fixture_written");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);
      container.plan.config.architecture = MachineCpuArchitecture::unknown;

      String failure = {};
      bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);

      suite.expect(loaded == false, "launch_metadata_runtime_loader_rejects_execute_arch_local_machine_mismatch");
      suite.expect(
          stringContains(failure, "mismatches local machine architecture"),
          "launch_metadata_runtime_loader_reports_execute_arch_local_machine_mismatch");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "launch_metadata_symlink_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "launch_metadata_symlink_fixture_private_dir_created");
      suite.expect(
          writeFileFixture(
              artifactRootPath / "outside-launch.metadata",
              "{\n  \"execute_path\": \"/app/hello\",\n  \"execute_args\": [],\n  \"execute_env\": [],\n  \"execute_cwd\": \"/\",\n  \"execute_arch\": \"x86_64\"\n}\n"),
          "launch_metadata_symlink_fixture_outside_metadata_written");
      suite.expect(
          createSymlinkFixture(artifactRootPath / "outside-launch.metadata", artifactRootPath / ".prodigy-private" / "launch.metadata"),
          "launch_metadata_symlink_fixture_symlink_created");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);
      container.plan.config.architecture = MachineCpuArchitecture::x86_64;

      String failure = {};
      bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);
      suite.expect(loaded == false, "launch_metadata_runtime_loader_rejects_symlinked_launch_metadata");
      suite.expect(
          stringContains(failure, "launch.metadata"),
          "launch_metadata_runtime_loader_reports_symlinked_launch_metadata");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "launch_metadata_non_normalized_execute_path_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      suite.expect(
          writeLaunchMetadataFixture(
              artifactRoot.path,
              R"({
  "execute_path": "/app/../hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/",
  "execute_arch": "x86_64"
})"),
          "launch_metadata_non_normalized_execute_path_fixture_written");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);
      container.plan.config.architecture = MachineCpuArchitecture::x86_64;

      String failure = {};
      bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);
      suite.expect(loaded == false, "launch_metadata_runtime_loader_rejects_non_normalized_execute_path");
      suite.expect(
          stringContains(failure, "must not contain '..' path components"),
          "launch_metadata_runtime_loader_reports_non_normalized_execute_path");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "launch_metadata_non_normalized_execute_cwd_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      suite.expect(
          writeLaunchMetadataFixture(
              artifactRoot.path,
              R"({
  "execute_path": "/app/hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/app//logs",
  "execute_arch": "x86_64"
})"),
          "launch_metadata_non_normalized_execute_cwd_fixture_written");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);
      container.plan.config.architecture = MachineCpuArchitecture::x86_64;

      String failure = {};
      bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);
      suite.expect(loaded == false, "launch_metadata_runtime_loader_rejects_non_normalized_execute_cwd");
      suite.expect(
          stringContains(failure, "must not contain empty path components"),
          "launch_metadata_runtime_loader_reports_non_normalized_execute_cwd");
    }
  }

  {
    TemporaryDirectory workspace;
    suite.expect(workspace.create(), "container_blob_digest_fixture_mkdtemp_created");

    if (workspace.path.size() > 0)
    {
      std::filesystem::path blobPath = filesystemPathFromString(workspace.path) / "container.zst";
      String payload = {};
      payload.assign(prodigyDiscombobulatorBlobHeaderText());
      payload.append("discombobulator-blob-payload"_ctv);
      suite.expect(
          Filesystem::openWriteAtClose(-1, stringFromFilesystemPath(blobPath), payload) >= 0,
          "container_blob_digest_fixture_written");

      uint64_t expectedBytes = payload.size();
      String expectedDigest = {};
      String digestFailure = {};
      suite.expect(
          prodigyComputeSHA256Hex(payload, expectedDigest, &digestFailure),
          "container_blob_digest_fixture_sha256_computed");
      suite.expect(digestFailure.size() == 0, "container_blob_digest_fixture_sha256_failure_cleared");

      String verificationFailure = {};
      bool verified = ContainerManager::debugVerifyCompressedContainerBlob(
          stringFromFilesystemPath(blobPath),
          expectedDigest,
          expectedBytes,
          &verificationFailure);
      suite.expect(verified, "container_blob_digest_verifier_accepts_matching_sha256");
      suite.expect(verificationFailure.size() == 0, "container_blob_digest_verifier_success_clears_failure");

      String wrongDigest = {};
      wrongDigest.assign("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv);
      verified = ContainerManager::debugVerifyCompressedContainerBlob(
          stringFromFilesystemPath(blobPath),
          wrongDigest,
          expectedBytes,
          &verificationFailure);
      suite.expect(verified == false, "container_blob_digest_verifier_rejects_mismatched_sha256");
      suite.expect(
          stringContains(verificationFailure, "sha256 mismatch"),
          "container_blob_digest_verifier_reports_mismatched_sha256");

      verified = ContainerManager::debugVerifyCompressedContainerBlob(
          stringFromFilesystemPath(blobPath),
          expectedDigest,
          expectedBytes + 1,
          &verificationFailure);
      suite.expect(verified == false, "container_blob_digest_verifier_rejects_mismatched_size");
      suite.expect(
          stringContains(verificationFailure, "blob size mismatch"),
          "container_blob_digest_verifier_reports_mismatched_size");

      std::filesystem::path missingHeaderPath = filesystemPathFromString(workspace.path) / "missing-header-container.zst";
      String missingHeaderPayload = {};
      missingHeaderPayload.assign("discombobulator-blob-payload"_ctv);
      suite.expect(
          Filesystem::openWriteAtClose(-1, stringFromFilesystemPath(missingHeaderPath), missingHeaderPayload) >= 0,
          "container_blob_contract_missing_header_fixture_written");
      String missingHeaderDigest = {};
      suite.expect(
          prodigyComputeSHA256Hex(missingHeaderPayload, missingHeaderDigest, &digestFailure),
          "container_blob_contract_missing_header_sha256_computed");
      verified = ContainerManager::debugVerifyCompressedContainerBlob(
          stringFromFilesystemPath(missingHeaderPath),
          missingHeaderDigest,
          missingHeaderPayload.size(),
          &verificationFailure);
      suite.expect(verified == false, "container_blob_digest_verifier_rejects_missing_contract_header");
      suite.expect(
          stringContains(verificationFailure, "Discombobulator app-container contract header"),
          "container_blob_digest_verifier_reports_missing_contract_header");

      std::filesystem::path tunnelBlobPath = filesystemPathFromString(workspace.path) / "mothership-tunnel-provider.blob";
      String tunnelPayload = {};
      tunnelPayload.assign(prodigyDiscombobulatorMothershipTunnelProviderBlobHeaderText());
      tunnelPayload.append("tunnel-provider-payload"_ctv);
      suite.expect(
          Filesystem::openWriteAtClose(-1, stringFromFilesystemPath(tunnelBlobPath), tunnelPayload) >= 0,
          "mothership_tunnel_provider_blob_fixture_written");
      suite.expect(
          tunnelProviderHeaderValid(stringFromFilesystemPath(tunnelBlobPath), &verificationFailure),
          "mothership_tunnel_provider_header_accepts_tunnel_blob");
      suite.expect(
          tunnelProviderHeaderValid(stringFromFilesystemPath(blobPath), &verificationFailure) == false,
          "mothership_tunnel_provider_header_rejects_app_blob");

      std::filesystem::path unknownTunnelBlobPath = filesystemPathFromString(workspace.path) / "mothership-tunnel-provider-v2.blob";
      String unknownTunnelPayload = {};
      unknownTunnelPayload.assign("PRODIGY-DISCOMBOBULATOR-MOTHERSHIP-TUNNEL-PROVIDER\ncontract=prodigy-mothership-tunnel-provider\ncontract_version=2\ncontainer_kind=mothershipTunnelProvider\nrequires_standard_neuron_socket=false\nrequires_mothership_tunnel_gateway=true\nnetwork_policy=tcpEgressOnly\n\npayload"_ctv);
      suite.expect(
          Filesystem::openWriteAtClose(-1, stringFromFilesystemPath(unknownTunnelBlobPath), unknownTunnelPayload) >= 0,
          "mothership_tunnel_provider_unknown_contract_fixture_written");
      suite.expect(
          tunnelProviderHeaderValid(stringFromFilesystemPath(unknownTunnelBlobPath), &verificationFailure) == false,
          "mothership_tunnel_provider_header_rejects_unknown_contract_version");

      String tunnelDigest = {};
      suite.expect(
          prodigyComputeSHA256Hex(tunnelPayload, tunnelDigest, &digestFailure),
          "mothership_tunnel_provider_blob_sha256_computed");
      TemporaryDirectory systemStoreRoot;
      suite.expect(systemStoreRoot.create(), "system_container_store_fixture_mkdtemp_created");
      if (systemStoreRoot.path.size() > 0)
      {
        bool stored = ContainerStore::systemStore(tunnelDigest,
                                                  tunnelPayload.size(),
                                                  tunnelPayload,
                                                  &verificationFailure,
                                                  &systemStoreRoot.path);
        suite.expect(stored, "system_container_store_stores_tunnel_provider_blob");
        suite.expect(
            ContainerStore::systemVerify(tunnelDigest, tunnelPayload.size(), nullptr, nullptr, &verificationFailure, &systemStoreRoot.path),
            "system_container_store_verifies_tunnel_provider_blob");
        String loadedSystemBlob = {};
        suite.expect(
            ContainerStore::systemLoadVerified(tunnelDigest, tunnelPayload.size(), loadedSystemBlob, &verificationFailure, &systemStoreRoot.path),
            "system_container_store_loads_verified_tunnel_provider_blob");
        suite.expect(loadedSystemBlob.equals(tunnelPayload), "system_container_store_loads_original_tunnel_provider_blob");
        String wrongTunnelDigest = {};
        wrongTunnelDigest.assign("0000000000000000000000000000000000000000000000000000000000000000"_ctv);
        suite.expect(
            ContainerStore::systemStore(wrongTunnelDigest, tunnelPayload.size(), tunnelPayload, &verificationFailure, &systemStoreRoot.path) == false,
            "system_container_store_rejects_digest_mismatch");
        suite.expect(
            stringContains(verificationFailure, "sha256 mismatch"),
            "system_container_store_reports_digest_mismatch");
        suite.expect(
            ContainerStore::systemStore(expectedDigest, payload.size(), payload, &verificationFailure, &systemStoreRoot.path) == false,
            "system_container_store_rejects_app_blob_for_tunnel_provider_kind");
        suite.expect(
            stringContains(verificationFailure, "mothership tunnel-provider contract header"),
            "system_container_store_reports_app_blob_contract_mismatch");
      }
    }
  }

  {
    TemporaryDirectory workspace;
    suite.expect(workspace.create(), "container_blob_size_cap_fixture_mkdtemp_created");

    if (workspace.path.size() > 0)
    {
      std::filesystem::path blobPath = filesystemPathFromString(workspace.path) / "container.zst";
      suite.expect(
          writeFileFixture(blobPath, "small-blob"),
          "container_blob_size_cap_fixture_written");

      String verificationFailure = {};
      bool verified = ContainerManager::debugVerifyCompressedContainerBlob(
          stringFromFilesystemPath(blobPath),
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv,
          prodigyContainerRuntimeLimits.maxCompressedBlobBytes + 1,
          &verificationFailure);
      suite.expect(verified == false, "container_blob_digest_verifier_rejects_oversized_trusted_blob");
      suite.expect(
          stringContains(verificationFailure, "size exceeds maximum"),
          "container_blob_digest_verifier_reports_oversized_trusted_blob");
    }
  }

  {
    TemporaryDirectory storeRoot;
    suite.expect(storeRoot.create(), "container_store_fixture_mkdtemp_created");

    if (storeRoot.path.size() > 0)
    {
      const uint64_t deploymentID = 987'654'321ULL;
      String firstPayload = prodigyDiscombobulatorBlobHeaderText();
      firstPayload.append("abcdefghijklmnopqrstuvwxyz0123456789"_ctv);
      String firstDigest = {};
      uint64_t firstBytes = 0;
      String failure = {};

      bool stored = ContainerStore::debugStoreAtRoot(
          storeRoot.path,
          deploymentID,
          firstPayload,
          &firstDigest,
          &firstBytes,
          nullptr,
          nullptr,
          &failure);
      suite.expect(stored, "container_store_debug_store_accepts_initial_blob");
      suite.expect(failure.size() == 0, "container_store_debug_store_initial_success_clears_failure");
      suite.expect(firstBytes == firstPayload.size(), "container_store_debug_store_reports_initial_size");

      String storedPath = ContainerStore::debugPathForContainerImageAtRoot(storeRoot.path, deploymentID);
      suite.expect(Filesystem::fileSize(storedPath) == firstPayload.size(), "container_store_debug_store_writes_initial_exact_size");

      String secondPayload = prodigyDiscombobulatorBlobHeaderText();
      secondPayload.append("tiny"_ctv);
      String secondDigest = {};
      uint64_t secondBytes = 0;
      stored = ContainerStore::debugStoreAtRoot(
          storeRoot.path,
          deploymentID,
          secondPayload,
          &secondDigest,
          &secondBytes,
          nullptr,
          nullptr,
          &failure);
      suite.expect(stored, "container_store_debug_store_overwrites_existing_blob");
      suite.expect(failure.size() == 0, "container_store_debug_store_overwrite_success_clears_failure");
      suite.expect(secondBytes == secondPayload.size(), "container_store_debug_store_reports_overwrite_size");
      suite.expect(Filesystem::fileSize(storedPath) == secondPayload.size(), "container_store_debug_store_overwrite_truncates_to_exact_size");

      String readback = {};
      Filesystem::openReadAtClose(-1, storedPath, readback);
      suite.expect(readback.equals(secondPayload), "container_store_debug_store_overwrite_replaces_payload_without_trailing_bytes");

      String verifyDigest = {};
      uint64_t verifyBytes = 0;
      bool verified = ContainerStore::debugVerifyAtRoot(
          storeRoot.path,
          deploymentID,
          secondDigest,
          secondPayload.size(),
          &verifyDigest,
          &verifyBytes,
          &failure);
      suite.expect(verified, "container_store_debug_verify_accepts_matching_digest_and_size");
      suite.expect(failure.size() == 0, "container_store_debug_verify_success_clears_failure");
      suite.expect(verifyDigest.equals(secondDigest), "container_store_debug_verify_reports_digest");
      suite.expect(verifyBytes == secondPayload.size(), "container_store_debug_verify_reports_size");

      verified = ContainerStore::debugVerifyAtRoot(
          storeRoot.path,
          deploymentID,
          secondDigest,
          secondPayload.size() + 1,
          &verifyDigest,
          &verifyBytes,
          &failure);
      suite.expect(verified == false, "container_store_debug_verify_rejects_mismatched_size");
      suite.expect(stringContains(failure, "blob size mismatch"), "container_store_debug_verify_reports_mismatched_size");

      String tunnelPayload = prodigyDiscombobulatorMothershipTunnelProviderBlobHeaderText();
      tunnelPayload.append("tunnel-provider-payload"_ctv);
      stored = ContainerStore::debugStoreAtRoot(storeRoot.path, deploymentID + 1, tunnelPayload, nullptr, nullptr, nullptr, nullptr, &failure);
      suite.expect(stored == false, "container_store_rejects_tunnel_provider_blob_as_app");
      suite.expect(stringContains(failure, "app-container contract header"), "container_store_reports_tunnel_provider_app_contract_mismatch");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "artifact_shape_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "artifact_shape_fixture_rootfs_created");
      suite.expect(
          writeLaunchMetadataFixture(
              artifactRoot.path,
              R"({
  "execute_path": "/app/hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/",
  "execute_arch": "x86_64"
})"),
          "artifact_shape_fixture_metadata_written");

      String failure = {};
      bool valid = ContainerManager::debugValidateContainerArtifactShape(artifactRoot.path, &failure);
      suite.expect(valid, "artifact_shape_validator_accepts_exact_runtime_shape");
      suite.expect(failure.size() == 0, "artifact_shape_validator_success_clears_failure");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "artifact_shape_missing_rootfs_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      suite.expect(
          writeLaunchMetadataFixture(
              artifactRoot.path,
              R"({
  "execute_path": "/app/hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/",
  "execute_arch": "x86_64"
})"),
          "artifact_shape_missing_rootfs_fixture_metadata_written");

      String failure = {};
      bool valid = ContainerManager::debugValidateContainerArtifactShape(artifactRoot.path, &failure);
      suite.expect(valid == false, "artifact_shape_validator_rejects_missing_rootfs");
      suite.expect(
          stringContains(failure, "missing required top-level rootfs"),
          "artifact_shape_validator_reports_missing_rootfs");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "artifact_shape_extra_entry_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "artifact_shape_extra_entry_fixture_rootfs_created");
      suite.expect(createDirectoryFixture(artifactRootPath / "extra"), "artifact_shape_extra_entry_fixture_extra_created");
      suite.expect(
          writeLaunchMetadataFixture(
              artifactRoot.path,
              R"({
  "execute_path": "/app/hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/",
  "execute_arch": "x86_64"
})"),
          "artifact_shape_extra_entry_fixture_metadata_written");

      String failure = {};
      bool valid = ContainerManager::debugValidateContainerArtifactShape(artifactRoot.path, &failure);
      suite.expect(valid == false, "artifact_shape_validator_rejects_unexpected_top_level_entry");
      suite.expect(
          stringContains(failure, "unexpected top-level artifact entry"),
          "artifact_shape_validator_reports_unexpected_top_level_entry");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "artifact_shape_symlink_metadata_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "artifact_shape_symlink_metadata_fixture_rootfs_created");
      suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "artifact_shape_symlink_metadata_fixture_private_dir_created");
      suite.expect(
          writeFileFixture(artifactRootPath / "outside-launch.metadata", "{}\n"),
          "artifact_shape_symlink_metadata_fixture_outside_metadata_written");
      suite.expect(
          createSymlinkFixture(artifactRootPath / "outside-launch.metadata", artifactRootPath / ".prodigy-private" / "launch.metadata"),
          "artifact_shape_symlink_metadata_fixture_symlink_created");

      String failure = {};
      bool valid = ContainerManager::debugValidateContainerArtifactShape(artifactRoot.path, &failure);
      suite.expect(valid == false, "artifact_shape_validator_rejects_symlinked_launch_metadata");
      suite.expect(
          stringContains(failure, "launch.metadata"),
          "artifact_shape_validator_reports_symlinked_launch_metadata");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "artifact_shape_oversized_metadata_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "artifact_shape_oversized_metadata_fixture_rootfs_created");
      suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "artifact_shape_oversized_metadata_fixture_private_created");

      String oversizedMetadata = repeatedString(prodigyContainerRuntimeLimits.maxLaunchMetadataBytes + 1, 'x');
      suite.expect(
          writeFileFixture(artifactRootPath / ".prodigy-private" / "launch.metadata", oversizedMetadata),
          "artifact_shape_oversized_metadata_fixture_metadata_written");

      String failure = {};
      bool valid = ContainerManager::debugValidateContainerArtifactShape(artifactRoot.path, &failure);
      suite.expect(valid == false, "artifact_shape_validator_rejects_oversized_launch_metadata");
      suite.expect(
          stringContains(failure, "exceeds maximum size"),
          "artifact_shape_validator_reports_oversized_launch_metadata");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);
      container.plan.config.architecture = MachineCpuArchitecture::x86_64;

      failure.clear();
      bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);
      suite.expect(loaded == false, "launch_metadata_runtime_loader_rejects_oversized_launch_metadata");
      suite.expect(
          stringContains(failure, "failed to read launch metadata"),
          "launch_metadata_runtime_loader_reports_oversized_launch_metadata");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "launch_metadata_too_many_args_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::string metadata = "{\n"
                             "  \"execute_path\": \"/app/hello\",\n"
                             "  \"execute_args\": [";
      for (uint32_t i = 0; i < (prodigyContainerRuntimeLimits.maxLaunchMetadataArrayEntries + 1); i += 1)
      {
        if (i > 0)
        {
          metadata += ", ";
        }
        metadata += "\"arg\"";
      }
      metadata += "],\n"
                  "  \"execute_env\": [],\n"
                  "  \"execute_cwd\": \"/\",\n"
                  "  \"execute_arch\": \"x86_64\"\n"
                  "}\n";

      String metadataText = {};
      metadataText.assign(metadata.data(), metadata.size());
      suite.expect(
          writeLaunchMetadataFixture(artifactRoot.path, metadataText.c_str()),
          "launch_metadata_too_many_args_fixture_written");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);
      container.plan.config.architecture = MachineCpuArchitecture::x86_64;

      String failure = {};
      bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);
      suite.expect(loaded == false, "launch_metadata_runtime_loader_rejects_too_many_execute_args");
      suite.expect(
          stringContains(failure, "execute_args must contain at most"),
          "launch_metadata_runtime_loader_reports_too_many_execute_args");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "launch_metadata_oversized_env_entry_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      String oversizedEnv = {};
      oversizedEnv.assign("A="_ctv);
      oversizedEnv.append(repeatedString(prodigyContainerRuntimeLimits.maxLaunchMetadataEntryBytes, 'x'));

      String metadata = {};
      metadata.assign(
          "{\n"
          "  \"execute_path\": \"/app/hello\",\n"
          "  \"execute_args\": [],\n"
          "  \"execute_env\": [\""_ctv);
      metadata.append(oversizedEnv);
      metadata.append("\"],\n"
                      "  \"execute_cwd\": \"/\",\n"
                      "  \"execute_arch\": \"x86_64\"\n"
                      "}\n"_ctv);

      suite.expect(
          writeLaunchMetadataFixture(artifactRoot.path, metadata.c_str()),
          "launch_metadata_oversized_env_entry_fixture_written");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);
      container.plan.config.architecture = MachineCpuArchitecture::x86_64;

      String failure = {};
      bool loaded = ContainerManager::debugLoadContainerLaunchMetadata(&container, &failure);
      suite.expect(loaded == false, "launch_metadata_runtime_loader_rejects_oversized_execute_env_entry");
      suite.expect(
          stringContains(failure, "execute_env entries must be at most"),
          "launch_metadata_runtime_loader_reports_oversized_execute_env_entry");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "artifact_resource_limits_rootfs_bytes_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(
          writeFileFixture(artifactRootPath / "rootfs" / "large.bin", repeatedString(2ULL * 1024ULL * 1024ULL, 'r')),
          "artifact_resource_limits_rootfs_bytes_fixture_large_file_written");
      suite.expect(
          writeLaunchMetadataFixture(
              artifactRoot.path,
              R"({
  "execute_path": "/app/hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/",
  "execute_arch": "x86_64"
})"),
          "artifact_resource_limits_rootfs_bytes_fixture_metadata_written");

      String failure = {};
      bool valid = ContainerManager::debugValidateContainerArtifactResourceLimits(
          artifactRoot.path,
          1ULL * 1024ULL * 1024ULL,
          prodigyContainerRuntimeLimits.maxArtifactEntries,
          prodigyContainerRuntimeLimits.maxArtifactBytes,
          &failure);
      suite.expect(valid == false, "artifact_resource_limits_reject_rootfs_bytes_above_filesystem_limit");
      suite.expect(
          stringContains(failure, "rootfs regular-file bytes exceed filesystemMB"),
          "artifact_resource_limits_report_rootfs_bytes_above_filesystem_limit");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "artifact_resource_limits_total_bytes_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(
          writeFileFixture(artifactRootPath / "rootfs" / "large.bin", repeatedString(2ULL * 1024ULL * 1024ULL, 't')),
          "artifact_resource_limits_total_bytes_fixture_large_file_written");
      suite.expect(
          writeLaunchMetadataFixture(
              artifactRoot.path,
              R"({
  "execute_path": "/app/hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/",
  "execute_arch": "x86_64"
})"),
          "artifact_resource_limits_total_bytes_fixture_metadata_written");

      String failure = {};
      bool valid = ContainerManager::debugValidateContainerArtifactResourceLimits(
          artifactRoot.path,
          4ULL * 1024ULL * 1024ULL,
          prodigyContainerRuntimeLimits.maxArtifactEntries,
          1ULL * 1024ULL * 1024ULL,
          &failure);
      suite.expect(valid == false, "artifact_resource_limits_reject_total_artifact_bytes_above_global_limit");
      suite.expect(
          stringContains(failure, "artifact regular-file bytes exceed maximum"),
          "artifact_resource_limits_report_total_artifact_bytes_above_global_limit");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "artifact_resource_limits_entry_count_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(
          writeFileFixture(artifactRootPath / "rootfs" / "a", "a"),
          "artifact_resource_limits_entry_count_fixture_file_a_written");
      suite.expect(
          writeFileFixture(artifactRootPath / "rootfs" / "b", "b"),
          "artifact_resource_limits_entry_count_fixture_file_b_written");
      suite.expect(
          writeLaunchMetadataFixture(
              artifactRoot.path,
              R"({
  "execute_path": "/app/hello",
  "execute_args": [],
  "execute_env": [],
  "execute_cwd": "/",
  "execute_arch": "x86_64"
})"),
          "artifact_resource_limits_entry_count_fixture_metadata_written");

      String failure = {};
      bool valid = ContainerManager::debugValidateContainerArtifactResourceLimits(
          artifactRoot.path,
          8ULL * 1024ULL * 1024ULL,
          4,
          prodigyContainerRuntimeLimits.maxArtifactBytes,
          &failure);
      suite.expect(valid == false, "artifact_resource_limits_reject_too_many_entries");
      suite.expect(
          stringContains(failure, "artifact contains too many entries"),
          "artifact_resource_limits_report_too_many_entries");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "rootfs_host_mount_targets_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "rootfs_host_mount_targets_fixture_rootfs_created");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);
      container.userID = uint32_t(fixtureWritableUserID());

      String failure = {};
      bool prepared = ContainerManager::debugPrepareContainerRootFSMountTargets(&container, &failure);
      suite.expect(prepared, "rootfs_host_mount_targets_prepare_succeeds");
      suite.expect(failure.size() == 0, "rootfs_host_mount_targets_prepare_clears_failure");
      suite.expect(
          std::filesystem::exists(artifactRootPath / "rootfs" / "etc" / "resolv.conf"),
          "rootfs_host_mount_targets_prepare_creates_resolv_conf_target");
      suite.expect(
          std::filesystem::exists(artifactRootPath / "rootfs" / "proc"),
          "rootfs_host_mount_targets_prepare_creates_proc_directory");
      suite.expect(
          std::filesystem::exists(artifactRootPath / "rootfs" / "dev" / "null"),
          "rootfs_host_mount_targets_prepare_creates_standard_device_nodes");
      struct stat etcStat = {};
      struct stat resolvStat = {};
      int etcStatResult = ::stat((artifactRootPath / "rootfs" / "etc").c_str(), &etcStat);
      int resolvStatResult = ::stat((artifactRootPath / "rootfs" / "etc" / "resolv.conf").c_str(), &resolvStat);
      suite.expect(
          etcStatResult == 0 && etcStat.st_uid == fixtureWritableUserID() && etcStat.st_gid == fixtureWritableGroupID(),
          "rootfs_host_mount_targets_prepare_sets_etc_ownership");
      suite.expect(
          resolvStatResult == 0 && resolvStat.st_uid == fixtureWritableUserID() && resolvStat.st_gid == fixtureWritableGroupID(),
          "rootfs_host_mount_targets_prepare_sets_resolv_conf_ownership");
      suite.expect(
          std::filesystem::exists(artifactRootPath / "rootfs" / "run" / "systemd" / "resolve" / "io.systemd.Resolve") == false,
          "rootfs_host_mount_targets_prepare_does_not_create_systemd_resolve_target");
      suite.expect(
          std::filesystem::exists(artifactRootPath / "rootfs" / "var" / "cache" / "ca-certs") == false,
          "rootfs_host_mount_targets_prepare_does_not_create_host_ca_cache_target");
    }
  }

  {
    suite.expect(
        ContainerManager::debugIsAllowlistedCanonicalGPUDevicePath("/dev/dri/renderD128"_ctv),
        "gpu_device_allowlist_accepts_dri_render_node");
    suite.expect(
        ContainerManager::debugIsAllowlistedCanonicalGPUDevicePath("/dev/dri/card0"_ctv),
        "gpu_device_allowlist_accepts_dri_card_node");
    suite.expect(
        ContainerManager::debugIsAllowlistedCanonicalGPUDevicePath("/dev/nvidia0"_ctv),
        "gpu_device_allowlist_accepts_nvidia_minor_node");
    suite.expect(
        ContainerManager::debugIsAllowlistedCanonicalGPUDevicePath("/dev/nvidiactl"_ctv),
        "gpu_device_allowlist_accepts_nvidiactl");
    suite.expect(
        ContainerManager::debugIsAllowlistedCanonicalGPUDevicePath("/dev/null"_ctv) == false,
        "gpu_device_allowlist_rejects_non_gpu_char_device");
    suite.expect(
        ContainerManager::debugIsAllowlistedCanonicalGPUDevicePath("/dev/sda"_ctv) == false,
        "gpu_device_allowlist_rejects_block_device_path");
    suite.expect(
        ContainerManager::debugIsAllowlistedCanonicalGPUDevicePath("/tmp/fake-gpu"_ctv) == false,
        "gpu_device_allowlist_rejects_non_dev_path");
    suite.expect(
        ContainerManager::debugIsAllowlistedCanonicalGPUDevicePath("/dev/nvidiactl/extra"_ctv) == false,
        "gpu_device_allowlist_rejects_nested_path");
  }

  {
    int pipeFDs[2] = {-1, -1};
    suite.expect(pipe(pipeFDs) == 0, "container_exec_fd_move_fixture_pipe_created");

    if (pipeFDs[0] >= 0 && pipeFDs[1] >= 0)
    {
      int movedFD = pipeFDs[1];
      String failure = {};
      bool moved = ContainerManager::debugMoveContainerExecDescriptorAboveMinimum(movedFD, &failure);
      suite.expect(moved, "container_exec_fd_move_rehomes_low_fd");
      suite.expect(failure.size() == 0, "container_exec_fd_move_success_clears_failure");
      suite.expect(movedFD >= containerExecInheritedFDMinimum, "container_exec_fd_move_places_fd_above_minimum");
      suite.expect(fcntl(movedFD, F_GETFD) >= 0, "container_exec_fd_move_preserves_rehomed_fd");
      suite.expect(fcntl(pipeFDs[1], F_GETFD) < 0 && errno == EBADF, "container_exec_fd_move_closes_original_fd");
      close(pipeFDs[0]);
      close(movedFD);
    }
  }

  {
    int preservedFDs[2] = {-1, -1};
    int extraFDs[2] = {-1, -1};
    suite.expect(pipe(preservedFDs) == 0, "container_exec_fd_sanitizer_fixture_preserved_pipe_created");
    suite.expect(pipe(extraFDs) == 0, "container_exec_fd_sanitizer_fixture_extra_pipe_created");

    if (preservedFDs[0] >= 0 && preservedFDs[1] >= 0 && extraFDs[0] >= 0 && extraFDs[1] >= 0)
    {
      pid_t child = fork();
      suite.expect(child >= 0, "container_exec_fd_sanitizer_fixture_fork_created");

      if (child == 0)
      {
        int preservedFD = preservedFDs[1];
        String failure = {};
        bool sanitized = ContainerManager::debugCloseAllContainerExecDescriptorsExcept(preservedFD, -1, &failure);
        if (sanitized == false)
        {
          _exit(10);
        }

        if (fcntl(preservedFD, F_GETFD) < 0)
        {
          _exit(11);
        }

        if (fcntl(extraFDs[0], F_GETFD) >= 0 || errno != EBADF)
        {
          _exit(12);
        }

        if (fcntl(extraFDs[1], F_GETFD) >= 0 || errno != EBADF)
        {
          _exit(13);
        }

        _exit(0);
      }

      if (child > 0)
      {
        int status = 0;
        waitpid(child, &status, 0);
        suite.expect(WIFEXITED(status) && WEXITSTATUS(status) == 0, "container_exec_fd_sanitizer_closes_unpreserved_fds");
      }

      close(preservedFDs[0]);
      close(preservedFDs[1]);
      close(extraFDs[0]);
      close(extraFDs[1]);
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "launch_target_validation_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(
          writeFileFixture(artifactRootPath / "rootfs" / "app" / "hello", "#!/bin/sh\nexit 0\n"),
          "launch_target_validation_fixture_binary_written");
      suite.expect(
          makeFileExecutableFixture(artifactRootPath / "rootfs" / "app" / "hello"),
          "launch_target_validation_fixture_binary_executable");
      suite.expect(
          createDirectoryFixture(artifactRootPath / "rootfs" / "app"),
          "launch_target_validation_fixture_cwd_created");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);
      container.executePath.assign("/app/hello"_ctv);
      container.executeCwd.assign("/app"_ctv);

      String failure = {};
      bool valid = ContainerManager::debugValidateContainerLaunchTargets(&container, &failure);
      suite.expect(valid, "launch_target_validation_accepts_paths_beneath_rootfs");
      suite.expect(failure.size() == 0, "launch_target_validation_success_clears_failure");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "launch_target_execute_symlink_escape_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "launch_target_execute_symlink_escape_fixture_rootfs_created");
      suite.expect(createDirectoryFixture(artifactRootPath / "outside"), "launch_target_execute_symlink_escape_fixture_outside_created");
      suite.expect(
          writeFileFixture(artifactRootPath / "outside" / "hello", "#!/bin/sh\nexit 0\n"),
          "launch_target_execute_symlink_escape_fixture_outside_binary_written");
      suite.expect(
          makeFileExecutableFixture(artifactRootPath / "outside" / "hello"),
          "launch_target_execute_symlink_escape_fixture_outside_binary_executable");
      suite.expect(
          createSymlinkFixture("../outside", artifactRootPath / "rootfs" / "app"),
          "launch_target_execute_symlink_escape_fixture_symlink_created");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);
      container.executePath.assign("/app/hello"_ctv);
      container.executeCwd.assign("/"_ctv);

      String failure = {};
      bool valid = ContainerManager::debugValidateContainerLaunchTargets(&container, &failure);
      suite.expect(valid == false, "launch_target_validation_rejects_execute_path_symlink_escape");
      suite.expect(
          stringContains(failure, "execute_path does not resolve beneath container rootfs"),
          "launch_target_validation_reports_execute_path_symlink_escape");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "launch_target_cwd_symlink_escape_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(
          writeFileFixture(artifactRootPath / "rootfs" / "bin" / "hello", "#!/bin/sh\nexit 0\n"),
          "launch_target_cwd_symlink_escape_fixture_binary_written");
      suite.expect(
          makeFileExecutableFixture(artifactRootPath / "rootfs" / "bin" / "hello"),
          "launch_target_cwd_symlink_escape_fixture_binary_executable");
      suite.expect(createDirectoryFixture(artifactRootPath / "outside-work"), "launch_target_cwd_symlink_escape_fixture_outside_created");
      suite.expect(
          createSymlinkFixture("../outside-work", artifactRootPath / "rootfs" / "work"),
          "launch_target_cwd_symlink_escape_fixture_symlink_created");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);
      container.executePath.assign("/bin/hello"_ctv);
      container.executeCwd.assign("/work"_ctv);

      String failure = {};
      bool valid = ContainerManager::debugValidateContainerLaunchTargets(&container, &failure);
      suite.expect(valid == false, "launch_target_validation_rejects_execute_cwd_symlink_escape");
      suite.expect(
          stringContains(failure, "execute_cwd does not resolve beneath container rootfs"),
          "launch_target_validation_reports_execute_cwd_symlink_escape");
    }
  }

  {
    TemporaryDirectory receiveScratch;
    suite.expect(receiveScratch.create(), "receive_scratch_single_entry_fixture_mkdtemp_created");

    if (receiveScratch.path.size() > 0)
    {
      std::filesystem::path receiveScratchPath = filesystemPathFromString(receiveScratch.path);
      suite.expect(
          createDirectoryFixture(receiveScratchPath / "artifact"),
          "receive_scratch_single_entry_fixture_artifact_created");

      String artifactName = {};
      String artifactPath = {};
      String failure = {};
      bool selected = ContainerManager::debugSelectReceivedContainerArtifactFromScratch(
          receiveScratch.path,
          artifactName,
          artifactPath,
          &failure);

      String expectedArtifactPath = {};
      expectedArtifactPath.assign(receiveScratch.path);
      expectedArtifactPath.append("/artifact"_ctv);

      suite.expect(selected, "receive_scratch_selector_accepts_exact_single_entry");
      suite.expect(failure.size() == 0, "receive_scratch_selector_success_clears_failure");
      suite.expect(artifactName == "artifact"_ctv, "receive_scratch_selector_returns_entry_name");
      suite.expect(artifactPath.equals(expectedArtifactPath), "receive_scratch_selector_returns_entry_path");
    }
  }

  {
    TemporaryDirectory receiveScratch;
    suite.expect(receiveScratch.create(), "receive_scratch_empty_fixture_mkdtemp_created");

    if (receiveScratch.path.size() > 0)
    {
      String artifactName = {};
      String artifactPath = {};
      String failure = {};
      bool selected = ContainerManager::debugSelectReceivedContainerArtifactFromScratch(
          receiveScratch.path,
          artifactName,
          artifactPath,
          &failure);

      suite.expect(selected == false, "receive_scratch_selector_rejects_empty_directory");
      suite.expect(
          stringContains(failure, "produced no artifact"),
          "receive_scratch_selector_reports_empty_directory");
    }
  }

  {
    TemporaryDirectory receiveScratch;
    suite.expect(receiveScratch.create(), "receive_scratch_hidden_entry_fixture_mkdtemp_created");

    if (receiveScratch.path.size() > 0)
    {
      std::filesystem::path receiveScratchPath = filesystemPathFromString(receiveScratch.path);
      suite.expect(
          createDirectoryFixture(receiveScratchPath / ".artifact"),
          "receive_scratch_hidden_entry_fixture_artifact_created");

      String artifactName = {};
      String artifactPath = {};
      String failure = {};
      bool selected = ContainerManager::debugSelectReceivedContainerArtifactFromScratch(
          receiveScratch.path,
          artifactName,
          artifactPath,
          &failure);

      suite.expect(selected == false, "receive_scratch_selector_rejects_hidden_entry");
      suite.expect(
          stringContains(failure, "hidden top-level artifact entries"),
          "receive_scratch_selector_reports_hidden_entry");
    }
  }

  {
    TemporaryDirectory receiveScratch;
    suite.expect(receiveScratch.create(), "receive_scratch_multiple_entries_fixture_mkdtemp_created");

    if (receiveScratch.path.size() > 0)
    {
      std::filesystem::path receiveScratchPath = filesystemPathFromString(receiveScratch.path);
      suite.expect(
          createDirectoryFixture(receiveScratchPath / "artifact-a"),
          "receive_scratch_multiple_entries_fixture_a_created");
      suite.expect(
          createDirectoryFixture(receiveScratchPath / "artifact-b"),
          "receive_scratch_multiple_entries_fixture_b_created");

      String artifactName = {};
      String artifactPath = {};
      String failure = {};
      bool selected = ContainerManager::debugSelectReceivedContainerArtifactFromScratch(
          receiveScratch.path,
          artifactName,
          artifactPath,
          &failure);

      suite.expect(selected == false, "receive_scratch_selector_rejects_multiple_entries");
      suite.expect(
          stringContains(failure, "exactly one top-level artifact entry"),
          "receive_scratch_selector_reports_multiple_entries");
    }
  }

  {
    TemporaryDirectory containersRoot;
    suite.expect(containersRoot.create(), "failed_create_artifact_cleanup_fixture_mkdtemp_created");

    if (containersRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(containersRoot.path) / "1234";
      suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "failed_create_artifact_cleanup_fixture_rootfs_created");
      suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "failed_create_artifact_cleanup_fixture_private_dir_created");
      suite.expect(
          writeFileFixture(artifactRootPath / ".prodigy-private" / "launch.metadata", "{}\n"),
          "failed_create_artifact_cleanup_fixture_metadata_written");

      Container container {};
      container.artifactRootPath.assign(stringFromFilesystemPath(artifactRootPath));
      container.rootfsPath.assign(stringFromFilesystemPath(artifactRootPath / "rootfs"));

      String failure = {};
      bool cleaned = ContainerManager::debugCleanupFailedCreateArtifactRoot(&container, &failure);

      std::error_code existsError;
      bool artifactExists = std::filesystem::exists(artifactRootPath, existsError);

      suite.expect(cleaned, "failed_create_artifact_cleanup_removes_artifact_root");
      suite.expect(failure.size() == 0, "failed_create_artifact_cleanup_success_clears_failure");
      suite.expect(existsError.value() == 0 && artifactExists == false, "failed_create_artifact_cleanup_erases_artifact_tree");
      suite.expect(container.artifactRootPath.size() == 0, "failed_create_artifact_cleanup_clears_artifact_root_path");
      suite.expect(container.rootfsPath.size() == 0, "failed_create_artifact_cleanup_clears_rootfs_path");
    }
  }

  {
    TemporaryDirectory containersRoot;
    suite.expect(containersRoot.create(), "rejected_artifact_janitor_orphan_fixture_mkdtemp_created");

    if (containersRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(containersRoot.path) / "1001";
      suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "rejected_artifact_janitor_orphan_fixture_rootfs_created");
      suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "rejected_artifact_janitor_orphan_fixture_private_dir_created");
      suite.expect(
          writeFileFixture(artifactRootPath / ".prodigy-private" / "launch.metadata", "{}\n"),
          "rejected_artifact_janitor_orphan_fixture_metadata_written");
      suite.expect(
          writeFileFixture(artifactRootPath / ".prodigy-private" / "create.pending", "99999999\n"),
          "rejected_artifact_janitor_orphan_fixture_marker_written");

      String failure = {};
      bool cleaned = ContainerManager::debugCleanupRejectedOrphanedContainerArtifacts(containersRoot.path, &failure);

      std::error_code existsError;
      bool artifactExists = std::filesystem::exists(artifactRootPath, existsError);

      suite.expect(cleaned, "rejected_artifact_janitor_reaps_orphaned_pending_artifact");
      suite.expect(failure.size() == 0, "rejected_artifact_janitor_orphan_success_clears_failure");
      suite.expect(existsError.value() == 0 && artifactExists == false, "rejected_artifact_janitor_erases_orphaned_artifact_tree");
    }
  }

  {
    TemporaryDirectory containersRoot;
    suite.expect(containersRoot.create(), "rejected_artifact_janitor_live_fixture_mkdtemp_created");

    if (containersRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(containersRoot.path) / "1002";
      suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "rejected_artifact_janitor_live_fixture_rootfs_created");
      suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "rejected_artifact_janitor_live_fixture_private_dir_created");
      suite.expect(
          writeFileFixture(artifactRootPath / ".prodigy-private" / "launch.metadata", "{}\n"),
          "rejected_artifact_janitor_live_fixture_metadata_written");
      char livePidText[64] = {0};
      std::snprintf(livePidText, sizeof(livePidText), "%d\n", int(getpid()));
      suite.expect(
          writeFileFixture(artifactRootPath / ".prodigy-private" / "create.pending", livePidText),
          "rejected_artifact_janitor_live_fixture_marker_written");

      String failure = {};
      bool cleaned = ContainerManager::debugCleanupRejectedOrphanedContainerArtifacts(containersRoot.path, &failure);

      std::error_code existsError;
      bool artifactExists = std::filesystem::exists(artifactRootPath, existsError);

      suite.expect(cleaned, "rejected_artifact_janitor_preserves_live_pending_artifact");
      suite.expect(failure.size() == 0, "rejected_artifact_janitor_live_success_clears_failure");
      suite.expect(existsError.value() == 0 && artifactExists, "rejected_artifact_janitor_keeps_live_pending_artifact_tree");
    }
  }

  {
    TemporaryDirectory containersRoot;
    suite.expect(containersRoot.create(), "rejected_artifact_janitor_unmarked_fixture_mkdtemp_created");

    if (containersRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(containersRoot.path) / "1003";
      suite.expect(createDirectoryFixture(artifactRootPath / "rootfs"), "rejected_artifact_janitor_unmarked_fixture_rootfs_created");
      suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "rejected_artifact_janitor_unmarked_fixture_private_dir_created");
      suite.expect(
          writeFileFixture(artifactRootPath / ".prodigy-private" / "launch.metadata", "{}\n"),
          "rejected_artifact_janitor_unmarked_fixture_metadata_written");

      String failure = {};
      bool cleaned = ContainerManager::debugCleanupRejectedOrphanedContainerArtifacts(containersRoot.path, &failure);

      std::error_code existsError;
      bool artifactExists = std::filesystem::exists(artifactRootPath, existsError);

      suite.expect(cleaned, "rejected_artifact_janitor_preserves_unmarked_artifact");
      suite.expect(failure.size() == 0, "rejected_artifact_janitor_unmarked_success_clears_failure");
      suite.expect(existsError.value() == 0 && artifactExists, "rejected_artifact_janitor_keeps_unmarked_artifact_tree");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    TemporaryDirectory retentionRoot;
    suite.expect(artifactRoot.create(), "failed_container_retention_fixture_artifact_root_created");
    suite.expect(retentionRoot.create(), "failed_container_retention_fixture_retention_root_created");

    if (artifactRoot.path.size() > 0 && retentionRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      std::filesystem::path rootfsPath = artifactRootPath / "rootfs";
      suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "failed_container_retention_fixture_private_dir_created");
      suite.expect(createDirectoryFixture(rootfsPath), "failed_container_retention_fixture_rootfs_dir_created");
      suite.expect(createDirectoryFixture(rootfsPath / "logs"), "failed_container_retention_fixture_logs_dir_created");
      suite.expect(writeFileFixture(rootfsPath / "bootstage.txt", "boot=prepare\n"), "failed_container_retention_fixture_bootstage_written");
      suite.expect(writeFileFixture(rootfsPath / "crashreport.txt", "crash=segv\n"), "failed_container_retention_fixture_crashreport_written");
      suite.expect(writeFileFixture(rootfsPath / "readytrace.log", "ready=0\n"), "failed_container_retention_fixture_readytrace_written");
      suite.expect(writeFileFixture(artifactRootPath / ".prodigy-private" / "launch.metadata", "{\"launch\":1}\n"), "failed_container_retention_fixture_launch_metadata_written");
      suite.expect(writeFileFixture(rootfsPath / "logs" / "stdout.log", "stdout-line\n"), "failed_container_retention_fixture_stdout_written");
      suite.expect(writeFileFixture(rootfsPath / "logs" / "stderr.log", "stderr-line\n"), "failed_container_retention_fixture_stderr_written");

      Container container = {};
      container.plan.uuid = uint128_t(0x7123);
      container.plan.config.applicationID = 77;
      container.plan.state = ContainerState::healthy;
      container.plan.restartOnFailure = true;
      container.name.assign("15947919734958006183"_ctv);
      container.pid = 4242;
      container.artifactRootPath.assign(artifactRoot.path);
      container.rootfsPath.assign(stringFromFilesystemPath(rootfsPath));

      siginfo_t info = {};
      info.si_code = CLD_DUMPED;
      info.si_status = SIGSEGV;
      info.si_pid = container.pid;

      String retainedBundlePath = {};
      String failure = {};
      bool preserved = ContainerManager::debugPreserveFailedContainerArtifactsAtPath(
          retentionRoot.path,
          &container,
          info,
          1'710'000'000'000LL,
          SIGSEGV,
          &retainedBundlePath,
          &failure);
      if (!preserved || failure.size() > 0)
      {
        fprintf(stderr, "detail failed_container_retention preserve=%d failure=%s retainedPath=%s\n",
                int(preserved),
                failure.c_str(),
                retainedBundlePath.c_str());
        fflush(stderr);
      }
      suite.expect(preserved, "failed_container_retention_preserves_bundle");
      suite.expect(failure.size() == 0, "failed_container_retention_success_clears_failure");

      std::filesystem::path retainedPath = filesystemPathFromString(retainedBundlePath);
      suite.expect(std::filesystem::exists(retainedPath / "metadata.txt"), "failed_container_retention_writes_metadata");
      suite.expect(std::filesystem::exists(retainedPath / "bootstage.txt"), "failed_container_retention_copies_bootstage");
      suite.expect(std::filesystem::exists(retainedPath / "crashreport.txt"), "failed_container_retention_copies_crashreport");
      suite.expect(std::filesystem::exists(retainedPath / "readytrace.log"), "failed_container_retention_copies_readytrace");
      suite.expect(std::filesystem::exists(retainedPath / "launch.metadata"), "failed_container_retention_copies_launch_metadata");
      suite.expect(std::filesystem::exists(retainedPath / "logs" / "stdout.log"), "failed_container_retention_copies_stdout");
      suite.expect(std::filesystem::exists(retainedPath / "logs" / "stderr.log"), "failed_container_retention_copies_stderr");
    }
  }

  {
    TemporaryDirectory retentionRoot;
    suite.expect(retentionRoot.create(), "failed_container_retention_gc_fixture_root_created");

    if (retentionRoot.path.size() > 0)
    {
      std::filesystem::path rootPath = filesystemPathFromString(retentionRoot.path);
      std::filesystem::path expiredBundle = rootPath / "77" / "111" / "1000";
      std::filesystem::path freshBundle = rootPath / "77" / "222" / "2000";
      suite.expect(createDirectoryFixture(expiredBundle), "failed_container_retention_gc_fixture_expired_bundle_created");
      suite.expect(createDirectoryFixture(freshBundle), "failed_container_retention_gc_fixture_fresh_bundle_created");
      suite.expect(writeFileFixture(expiredBundle / "metadata.txt", "expired\n"), "failed_container_retention_gc_fixture_expired_metadata_written");
      suite.expect(writeFileFixture(freshBundle / "metadata.txt", "fresh\n"), "failed_container_retention_gc_fixture_fresh_metadata_written");

      std::error_code oldTimeError = {};
      std::filesystem::last_write_time(
          expiredBundle,
          std::filesystem::file_time_type::clock::now() - std::chrono::hours(30),
          oldTimeError);
      suite.expect(oldTimeError.value() == 0, "failed_container_retention_gc_fixture_sets_expired_bundle_time");

      std::error_code freshTimeError = {};
      std::filesystem::last_write_time(
          freshBundle,
          std::filesystem::file_time_type::clock::now() - std::chrono::hours(1),
          freshTimeError);
      suite.expect(freshTimeError.value() == 0, "failed_container_retention_gc_fixture_sets_fresh_bundle_time");

      String failure = {};
      bool cleaned = ContainerManager::debugCleanupExpiredFailedContainerArtifactsAtPath(
          retentionRoot.path,
          Time::now<TimeResolution::ms>(),
          failedContainerArtifactRetentionMs,
          &failure);
      suite.expect(cleaned, "failed_container_retention_gc_succeeds");
      suite.expect(failure.size() == 0, "failed_container_retention_gc_success_clears_failure");
      suite.expect(std::filesystem::exists(expiredBundle) == false, "failed_container_retention_gc_removes_expired_bundle");
      suite.expect(std::filesystem::exists(freshBundle), "failed_container_retention_gc_keeps_fresh_bundle");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    TemporaryDirectory retentionRoot;
    suite.expect(artifactRoot.create(), "failed_container_retention_if_needed_fixture_artifact_root_created");
    suite.expect(retentionRoot.create(), "failed_container_retention_if_needed_fixture_retention_root_created");

    if (artifactRoot.path.size() > 0 && retentionRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      std::filesystem::path rootfsPath = artifactRootPath / "rootfs";
      suite.expect(createDirectoryFixture(artifactRootPath / ".prodigy-private"), "failed_container_retention_if_needed_fixture_private_dir_created");
      suite.expect(createDirectoryFixture(rootfsPath), "failed_container_retention_if_needed_fixture_rootfs_dir_created");
      suite.expect(createDirectoryFixture(rootfsPath / "logs"), "failed_container_retention_if_needed_fixture_logs_dir_created");
      suite.expect(writeFileFixture(rootfsPath / "crashreport.txt", "crash=abort\n"), "failed_container_retention_if_needed_fixture_crashreport_written");
      suite.expect(writeFileFixture(rootfsPath / "logs" / "stderr.log", "stderr-line\n"), "failed_container_retention_if_needed_fixture_stderr_written");

      Container container = {};
      container.plan.uuid = uint128_t(0x8123);
      container.plan.config.applicationID = 88;
      container.plan.state = ContainerState::healthy;
      container.plan.restartOnFailure = false;
      container.name.assign("17170712990884937031"_ctv);
      container.pid = 5151;
      container.artifactRootPath.assign(artifactRoot.path);
      container.rootfsPath.assign(stringFromFilesystemPath(rootfsPath));
      container.infop = {};
      container.infop.si_pid = container.pid;
      container.infop.si_code = CLD_DUMPED;
      container.infop.si_status = SIGABRT;

      String firstRetainedBundlePath = {};
      String secondRetainedBundlePath = {};
      String failure = {};
      bool firstPreserved = ContainerManager::debugPreserveFailedContainerArtifactsIfNeededAtPath(
          retentionRoot.path,
          &container,
          1'710'000'123'000LL,
          &firstRetainedBundlePath,
          &failure);
      suite.expect(firstPreserved, "failed_container_retention_if_needed_first_preserves_bundle");
      suite.expect(failure.size() == 0, "failed_container_retention_if_needed_first_success_clears_failure");
      suite.expect(container.failedArtifactsPreserved, "failed_container_retention_if_needed_first_sets_preserved_flag");

      failure.clear();
      bool secondPreserved = ContainerManager::debugPreserveFailedContainerArtifactsIfNeededAtPath(
          retentionRoot.path,
          &container,
          1'710'000'124'000LL,
          &secondRetainedBundlePath,
          &failure);
      suite.expect(secondPreserved, "failed_container_retention_if_needed_second_succeeds");
      suite.expect(failure.size() == 0, "failed_container_retention_if_needed_second_success_clears_failure");
      suite.expect(secondRetainedBundlePath.size() == 0, "failed_container_retention_if_needed_second_noops_without_new_bundle");

      std::filesystem::path retainedRootPath = filesystemPathFromString(retentionRoot.path);
      uint32_t bundleCount = 0;
      std::error_code iteratorError = {};
      for (std::filesystem::recursive_directory_iterator it(retainedRootPath, iteratorError), end; it != end; it.increment(iteratorError))
      {
        if (iteratorError)
        {
          break;
        }

        std::error_code statusError = {};
        std::filesystem::file_status status = it->symlink_status(statusError);
        if (statusError)
        {
          iteratorError = statusError;
          break;
        }

        if (std::filesystem::is_directory(status) && it->path().filename() == "1710000123000")
        {
          bundleCount += 1;
        }
      }
      suite.expect(iteratorError.value() == 0, "failed_container_retention_if_needed_bundle_count_iteration_succeeds");
      suite.expect(bundleCount == 1, "failed_container_retention_if_needed_only_one_bundle_written");
      suite.expect(std::filesystem::exists(filesystemPathFromString(firstRetainedBundlePath) / "metadata.txt"), "failed_container_retention_if_needed_first_bundle_writes_metadata");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "secure_rootfs_symlink_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(
          createDirectoryFixture(artifactRootPath / "outside-rootfs"),
          "secure_rootfs_symlink_fixture_outside_directory_created");
      suite.expect(
          createSymlinkFixture(artifactRootPath / "outside-rootfs", artifactRootPath / "rootfs"),
          "secure_rootfs_symlink_fixture_rootfs_symlink_created");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);

      String failure = {};
      bool opened = ContainerManager::debugOpenVerifiedContainerRootfs(&container, &failure);
      suite.expect(opened == false, "secure_rootfs_open_rejects_rootfs_symlink");
      suite.expect(
          stringContains(failure, "without following symlinks"),
          "secure_rootfs_open_reports_rootfs_symlink_rejection");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "rootfs_ownership_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(
          createDirectoryFixture(artifactRootPath / "rootfs"),
          "rootfs_ownership_fixture_rootfs_created");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);

      uid_t targetUserID = fixtureWritableUserID();
      gid_t targetGroupID = fixtureWritableGroupID();

      String failure = {};
      bool assigned = ContainerManager::debugAssignContainerRootfsOwnership(
          &container,
          uint32_t(targetUserID),
          uint32_t(targetGroupID),
          &failure);
      suite.expect(assigned, "rootfs_ownership_helper_accepts_o_path_descriptor");
      suite.expect(failure.size() == 0, "rootfs_ownership_helper_success_clears_failure");

      struct stat rootfsStat = {};
      int statResult = ::stat((artifactRootPath / "rootfs").c_str(), &rootfsStat);
      suite.expect(statResult == 0, "rootfs_ownership_fixture_stat_succeeds");
      suite.expect(
          statResult == 0 && rootfsStat.st_uid == targetUserID,
          "rootfs_ownership_helper_sets_rootfs_uid");
      suite.expect(
          statResult == 0 && rootfsStat.st_gid == targetGroupID,
          "rootfs_ownership_helper_sets_rootfs_gid");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "secure_mount_target_etc_symlink_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(
          createDirectoryFixture(artifactRootPath / "rootfs"),
          "secure_mount_target_etc_symlink_fixture_rootfs_created");
      suite.expect(
          createDirectoryFixture(artifactRootPath / "outside-etc"),
          "secure_mount_target_etc_symlink_fixture_outside_created");
      suite.expect(
          createSymlinkFixture(artifactRootPath / "outside-etc", artifactRootPath / "rootfs" / "etc"),
          "secure_mount_target_etc_symlink_fixture_symlink_created");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);
      container.userID = uint32_t(fixtureWritableUserID());

      String failure = {};
      bool prepared = ContainerManager::debugPrepareContainerRootFSMountTargets(&container, &failure);
      suite.expect(prepared == false, "secure_mount_target_prep_rejects_etc_symlink");
      suite.expect(
          stringContains(failure, "without following symlinks"),
          "secure_mount_target_prep_reports_etc_symlink_rejection");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "secure_mount_target_run_symlink_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(
          createDirectoryFixture(artifactRootPath / "rootfs"),
          "secure_mount_target_run_symlink_fixture_rootfs_created");
      suite.expect(
          createDirectoryFixture(artifactRootPath / "outside-run"),
          "secure_mount_target_run_symlink_fixture_outside_created");
      suite.expect(
          createSymlinkFixture(artifactRootPath / "outside-run", artifactRootPath / "rootfs" / "run"),
          "secure_mount_target_run_symlink_fixture_symlink_created");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);
      container.userID = uint32_t(fixtureWritableUserID());

      String failure = {};
      bool prepared = ContainerManager::debugPrepareContainerRootFSMountTargets(&container, &failure);
      suite.expect(prepared, "secure_mount_target_prep_ignores_run_symlink_when_run_mount_removed");
      suite.expect(
          failure.size() == 0,
          "secure_mount_target_prep_run_symlink_removed_surface_clears_failure");
      suite.expect(
          std::filesystem::is_symlink(artifactRootPath / "rootfs" / "run"),
          "secure_mount_target_prep_run_symlink_removed_surface_leaves_run_symlink_untouched");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "secure_mount_target_storage_symlink_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(
          createDirectoryFixture(artifactRootPath / "rootfs"),
          "secure_mount_target_storage_symlink_fixture_rootfs_created");
      suite.expect(
          createDirectoryFixture(artifactRootPath / "outside-storage"),
          "secure_mount_target_storage_symlink_fixture_outside_created");
      suite.expect(
          createSymlinkFixture(artifactRootPath / "outside-storage", artifactRootPath / "rootfs" / "storage"),
          "secure_mount_target_storage_symlink_fixture_symlink_created");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);
      container.plan.config.storageMB = 64;
      container.userID = uint32_t(fixtureWritableUserID());

      String failure = {};
      bool prepared = ContainerManager::debugPrepareContainerRootFSMountTargets(&container, &failure);
      suite.expect(prepared == false, "secure_mount_target_prep_rejects_storage_symlink");
      suite.expect(
          stringContains(failure, "without following symlinks"),
          "secure_mount_target_prep_reports_storage_symlink_rejection");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "secure_mount_target_var_symlink_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(
          createDirectoryFixture(artifactRootPath / "rootfs"),
          "secure_mount_target_var_symlink_fixture_rootfs_created");
      suite.expect(
          createDirectoryFixture(artifactRootPath / "outside-var"),
          "secure_mount_target_var_symlink_fixture_outside_created");
      suite.expect(
          createSymlinkFixture(artifactRootPath / "outside-var", artifactRootPath / "rootfs" / "var"),
          "secure_mount_target_var_symlink_fixture_symlink_created");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);
      container.userID = uint32_t(fixtureWritableUserID());

      String failure = {};
      bool prepared = ContainerManager::debugPrepareContainerRootFSMountTargets(&container, &failure);
      suite.expect(prepared, "secure_mount_target_prep_ignores_var_symlink_when_var_mount_removed");
      suite.expect(
          failure.size() == 0,
          "secure_mount_target_prep_var_symlink_removed_surface_clears_failure");
      suite.expect(
          std::filesystem::is_symlink(artifactRootPath / "rootfs" / "var"),
          "secure_mount_target_prep_var_symlink_removed_surface_leaves_var_symlink_untouched");
    }
  }

  {
    TemporaryDirectory artifactRoot;
    suite.expect(artifactRoot.create(), "secure_bind_target_dev_symlink_fixture_mkdtemp_created");

    if (artifactRoot.path.size() > 0)
    {
      std::filesystem::path artifactRootPath = filesystemPathFromString(artifactRoot.path);
      suite.expect(
          createDirectoryFixture(artifactRootPath / "rootfs"),
          "secure_bind_target_dev_symlink_fixture_rootfs_created");
      suite.expect(
          createDirectoryFixture(artifactRootPath / "outside-dev"),
          "secure_bind_target_dev_symlink_fixture_outside_created");
      suite.expect(
          createSymlinkFixture(artifactRootPath / "outside-dev", artifactRootPath / "rootfs" / "dev"),
          "secure_bind_target_dev_symlink_fixture_symlink_created");

      Container container {};
      container.artifactRootPath.assign(artifactRoot.path);

      String failure = {};
      bool prepared = ContainerManager::debugPrepareBindMountFileTargetInRootFS(&container, "/dev/null"_ctv, &failure);
      suite.expect(prepared == false, "secure_bind_target_prep_rejects_dev_symlink");
      suite.expect(
          stringContains(failure, "without following symlinks"),
          "secure_bind_target_prep_reports_dev_symlink_rejection");
    }
  }

  {
    String hex = {};
    hex.assignItoh(uint16_t(0x1234));
    suite.expect(hex == "0x1234"_ctv, "assignItoh_uint16_formats_canonical_hex");
    suite.expect(String::numberFromHexString<uint16_t>(hex) == uint16_t(0x1234), "numberFromHexString_uint16_roundtrips_canonical_hex");
  }

  {
    const uint128_t uuid = (uint128_t(0x25a812f1daecf688ULL) << 64) | uint128_t(0xfc738a2aa4684e95ULL);
    String hex = {};
    hex.assignItoh(uuid);

    suite.expect(hex == "0x25a812f1daecf688fc738a2aa4684e95"_ctv, "assignItoh_uint128_formats_canonical_hex");
    suite.expect(String::numberFromHexString<uint128_t>(hex) == uuid, "numberFromHexString_uint128_roundtrips_canonical_hex");
    suite.expect(
        String::numberFromHexString<uint128_t>("0X000025A812F1DAECF688FC738A2AA4684E95"_ctv) == uuid,
        "numberFromHexString_uint128_accepts_prefix_case_and_leading_zeroes");
    suite.expect(
        String::numberFromHexString<uint128_t>("0x25a812f1daecf688fc738a2aa4684e95gg"_ctv) == uint128_t(0),
        "numberFromHexString_uint128_rejects_invalid_hex");
  }

  {
    DeploymentPlan plan {};
    plan.config.config_version = 77;
    plan.config.applicationID = 42;
    plan.config.versionID = 9;
    plan.config.type = ApplicationType::stateful;
    plan.config.containerBlobSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv;
    plan.config.containerBlobBytes = 4096;
    plan.minimumSubscriberCapacity = 11;
    plan.isStateful = true;
    plan.config.minGPUs = 2;
    plan.config.gpuMemoryGB = 24;
    plan.config.nicSpeedGbps = 10;
    plan.config.minInternetDownloadMbps = 500;
    plan.config.minInternetUploadMbps = 250;
    plan.config.maxInternetLatencyMs = 20;
    plan.config.maxPids = 5;
    plan.config.isolatedChildMemoryMB = 64;
    plan.stateful.clientPrefix = 101;
    plan.stateful.siblingPrefix = 102;
    plan.stateful.cousinPrefix = 103;
    plan.stateful.seedingPrefix = 104;
    plan.stateful.shardingPrefix = 105;
    plan.stateful.allowUpdateInPlace = true;
    plan.stateful.seedingAlways = false;
    plan.stateful.neverShard = false;
    plan.stateful.allMasters = true;
    plan.useHostNetworkNamespace = true;
    plan.networkAccess = ContainerNetworkAccess::declaredOnly;
    plan.hasTlsIssuancePolicy = true;
    plan.tlsIssuancePolicy.applicationID = 42;
    plan.tlsIssuancePolicy.enablePerContainerLeafs = true;
    plan.tlsIssuancePolicy.leafValidityDays = 15;
    plan.tlsIssuancePolicy.identityNames.push_back("inbound_server_tls"_ctv);
    plan.tlsIssuancePolicy.dnsSans.push_back("nametag.social"_ctv);
    plan.tlsIssuancePolicy.dnsSans.push_back("dev.nametag.social"_ctv);
    plan.tlsIssuancePolicy.ipSans.push_back(IPAddress("10.0.0.18", false));
    plan.tlsIssuancePolicy.ipSans.push_back(IPAddress("fd7a:115c:a1e0::18", true));
    Whitehole whitehole = {};
    whitehole.transport = ExternalAddressTransport::quic;
    whitehole.family = ExternalAddressFamily::ipv6;
    whitehole.source = ExternalAddressSource::hostPublicAddress;
    whitehole.hasAddress = true;
    whitehole.address = IPAddress("2001:db8::55", true);
    whitehole.sourcePort = 5555;
    whitehole.bindingNonce = 77;
    plan.whiteholes.push_back(whitehole);

    String serialized;
    BitseryEngine::serialize(serialized, plan);

    DeploymentPlan roundtrip {};
    bool decoded = BitseryEngine::deserializeSafe(serialized, roundtrip);

    suite.expect(decoded, "deployment_plan_roundtrip_deserializes");
    suite.expect(roundtrip.config.config_version == 77, "deployment_plan_roundtrip_preserves_config_version");
    suite.expect(roundtrip.config.minGPUs == 2, "deployment_plan_roundtrip_preserves_min_gpus");
    suite.expect(roundtrip.config.gpuMemoryGB == 24, "deployment_plan_roundtrip_preserves_gpu_memory_gb");
    suite.expect(roundtrip.config.nicSpeedGbps == 10, "deployment_plan_roundtrip_preserves_nic_speed_gbps");
    suite.expect(roundtrip.config.minInternetDownloadMbps == 500, "deployment_plan_roundtrip_preserves_min_internet_download");
    suite.expect(roundtrip.config.minInternetUploadMbps == 250, "deployment_plan_roundtrip_preserves_min_internet_upload");
    suite.expect(roundtrip.config.maxInternetLatencyMs == 20, "deployment_plan_roundtrip_preserves_max_internet_latency");
    suite.expect(roundtrip.config.maxPids == 5, "deployment_plan_roundtrip_preserves_max_pids");
    suite.expect(roundtrip.config.isolatedChildMemoryMB == 64,
                 "deployment_plan_roundtrip_preserves_isolated_child_memory");
    suite.expect(roundtrip.config.containerBlobSHA256.equals(plan.config.containerBlobSHA256), "deployment_plan_roundtrip_preserves_container_blob_sha256");
    suite.expect(roundtrip.config.containerBlobBytes == plan.config.containerBlobBytes, "deployment_plan_roundtrip_preserves_container_blob_bytes");
    suite.expect(roundtrip.stateful.allMasters == true, "deployment_plan_roundtrip_preserves_all_masters");
    suite.expect(roundtrip.useHostNetworkNamespace == true, "deployment_plan_roundtrip_preserves_host_network_namespace");
    suite.expect(roundtrip.networkAccess == ContainerNetworkAccess::declaredOnly, "deployment_plan_roundtrip_preserves_network_access");
    suite.expect(roundtrip.hasTlsIssuancePolicy, "deployment_plan_roundtrip_preserves_tls_policy_flag");
    suite.expect(roundtrip.tlsIssuancePolicy.identityNames.size() == 1, "deployment_plan_roundtrip_preserves_tls_identity_count");
    suite.expect(roundtrip.tlsIssuancePolicy.dnsSans.size() == 2, "deployment_plan_roundtrip_preserves_tls_dns_san_count");
    suite.expect(roundtrip.tlsIssuancePolicy.dnsSans[0].equal("nametag.social"_ctv), "deployment_plan_roundtrip_preserves_tls_dns_san");
    suite.expect(roundtrip.tlsIssuancePolicy.ipSans.size() == 2, "deployment_plan_roundtrip_preserves_tls_ip_san_count");
    suite.expect(roundtrip.tlsIssuancePolicy.ipSans[0].equals(IPAddress("10.0.0.18", false)), "deployment_plan_roundtrip_preserves_tls_ipv4_san");
    suite.expect(roundtrip.tlsIssuancePolicy.ipSans[1].equals(IPAddress("fd7a:115c:a1e0::18", true)), "deployment_plan_roundtrip_preserves_tls_ipv6_san");
    suite.expect(roundtrip.whiteholes.size() == 1, "deployment_plan_roundtrip_preserves_whiteholes");
    suite.expect(roundtrip.whiteholes[0].sourcePort == 5555, "deployment_plan_roundtrip_preserves_whitehole_source_port");
    suite.expect(roundtrip.whiteholes[0].bindingNonce == 77, "deployment_plan_roundtrip_preserves_whitehole_binding_nonce");
  }

  {
    DeploymentPlan plan {};
    Wormhole wormhole = {};
    wormhole.name.assign("public-api-quic"_ctv);
    wormhole.externalAddress = IPAddress("2001:db8::44", true);
    wormhole.externalPort = 443;
    wormhole.containerPort = 8443;
    wormhole.layer4 = IPPROTO_UDP;
    wormhole.isQuic = true;
    wormhole.hasQuicCidKeyState = true;
    wormhole.source = ExternalAddressSource::registeredRoutablePrefix;
    wormhole.routablePrefixUUID = uint128_t(0xAABBCCDD0011);
    wormhole.quicCidKeyState.rotationHours = 12;
    wormhole.quicCidKeyState.activeKeyIndex = 1;
    wormhole.quicCidKeyState.rotatedAtMs = 123'456'789;
    wormhole.quicCidKeyState.keyMaterialByIndex[0] = uint128_t(0x1111222233334444ULL);
    wormhole.quicCidKeyState.keyMaterialByIndex[1] = uint128_t(0xAAAABBBBCCCCDDDDULL);
    wormhole.hasTlsResumptionConfig = true;
    wormhole.tlsResumption.alpns.push_back("h3"_ctv);
    wormhole.tlsResumption.sniNames.push_back("api.example.com"_ctv);
    wormhole.hasDNSConfig = true;
    wormhole.dns.provider = "cloudflare"_ctv;
    wormhole.dns.credentialName = "cf-prod"_ctv;
    wormhole.dns.zone = "example.com"_ctv;
    wormhole.dns.name = "api.example.com"_ctv;
    wormhole.dns.bindingName = "api-binding"_ctv;
    wormhole.dns.type = "AAAA"_ctv;
    wormhole.dns.ttl = 300;
    plan.wormholes.push_back(wormhole);

    WormholePublicTLSConfig publicTLS = {};
    publicTLS.wormholeName = "public-api-quic"_ctv;
    publicTLS.identityName = "public-api-quic-public"_ctv;
    publicTLS.domains.push_back("api.example.com"_ctv);
    publicTLS.issuer = "letsencrypt"_ctv;
    publicTLS.keyType = "ecdsa"_ctv;
    publicTLS.staging = true;
    publicTLS.renewAfterLifetimePermille = 667;
    plan.publicTLS.push_back(publicTLS);

    String serialized;
    BitseryEngine::serialize(serialized, plan);

    DeploymentPlan roundtrip {};
    bool decoded = BitseryEngine::deserializeSafe(serialized, roundtrip);

    suite.expect(decoded, "deployment_plan_roundtrip_quic_wormhole_deserializes");
    suite.expect(roundtrip.wormholes.size() == 1, "deployment_plan_roundtrip_preserves_wormhole_count");
    suite.expect(roundtrip.wormholes[0].name.equal("public-api-quic"_ctv), "deployment_plan_roundtrip_preserves_wormhole_name");
    suite.expect(roundtrip.wormholes[0].isQuic == true, "deployment_plan_roundtrip_preserves_wormhole_quic_flag");
    suite.expect(roundtrip.wormholes[0].hasQuicCidKeyState == true, "deployment_plan_roundtrip_preserves_wormhole_quic_key_state_flag");
    suite.expect(roundtrip.wormholes[0].quicCidKeyState.rotationHours == 12, "deployment_plan_roundtrip_preserves_wormhole_quic_rotation_hours");
    suite.expect(roundtrip.wormholes[0].quicCidKeyState.activeKeyIndex == 1, "deployment_plan_roundtrip_preserves_wormhole_quic_active_key_index");
    suite.expect(roundtrip.wormholes[0].quicCidKeyState.rotatedAtMs == 123'456'789, "deployment_plan_roundtrip_preserves_wormhole_quic_rotated_at");
    suite.expect(roundtrip.wormholes[0].quicCidKeyState.keyMaterialByIndex[0] == uint128_t(0x1111222233334444ULL), "deployment_plan_roundtrip_preserves_wormhole_quic_key_slot_0");
    suite.expect(roundtrip.wormholes[0].quicCidKeyState.keyMaterialByIndex[1] == uint128_t(0xAAAABBBBCCCCDDDDULL), "deployment_plan_roundtrip_preserves_wormhole_quic_key_slot_1");
    suite.expect(wormholeUsesQuicCidEncryption(roundtrip.wormholes[0]), "deployment_plan_roundtrip_recognizes_quic_wormhole");
    suite.expect(wormholeQuicCidInactiveKeyIndex(roundtrip.wormholes[0].quicCidKeyState) == 0, "deployment_plan_roundtrip_computes_quic_inactive_key_index");
    suite.expect(roundtrip.wormholes[0].hasTlsResumptionConfig, "deployment_plan_roundtrip_preserves_wormhole_tls_resumption_flag");
    suite.expect(roundtrip.wormholes[0].tlsResumption.alpns.size() == 1 && roundtrip.wormholes[0].tlsResumption.alpns[0].equal("h3"_ctv), "deployment_plan_roundtrip_preserves_wormhole_tls_resumption_alpn");
    suite.expect(roundtrip.wormholes[0].tlsResumption.sniNames.size() == 1 && roundtrip.wormholes[0].tlsResumption.sniNames[0].equal("api.example.com"_ctv), "deployment_plan_roundtrip_preserves_wormhole_tls_resumption_sni");
    suite.expect(roundtrip.wormholes[0].hasDNSConfig, "deployment_plan_roundtrip_preserves_wormhole_dns_flag");
    suite.expect(roundtrip.wormholes[0].dns.provider.equal("cloudflare"_ctv), "deployment_plan_roundtrip_preserves_wormhole_dns_provider");
    suite.expect(roundtrip.wormholes[0].dns.credentialName.equal("cf-prod"_ctv), "deployment_plan_roundtrip_preserves_wormhole_dns_credential");
    suite.expect(roundtrip.wormholes[0].dns.zone.equal("example.com"_ctv), "deployment_plan_roundtrip_preserves_wormhole_dns_zone");
    suite.expect(roundtrip.wormholes[0].dns.name.equal("api.example.com"_ctv), "deployment_plan_roundtrip_preserves_wormhole_dns_name");
    suite.expect(roundtrip.wormholes[0].dns.bindingName.equal("api-binding"_ctv), "deployment_plan_roundtrip_preserves_wormhole_dns_binding_name");
    suite.expect(roundtrip.wormholes[0].dns.type.equal("AAAA"_ctv), "deployment_plan_roundtrip_preserves_wormhole_dns_type");
    suite.expect(roundtrip.wormholes[0].dns.ttl == 300, "deployment_plan_roundtrip_preserves_wormhole_dns_ttl");
    suite.expect(roundtrip.publicTLS.size() == 1, "deployment_plan_roundtrip_preserves_public_tls_count");
    suite.expect(roundtrip.publicTLS[0].wormholeName.equal("public-api-quic"_ctv), "deployment_plan_roundtrip_preserves_public_tls_wormhole");
    suite.expect(roundtrip.publicTLS[0].identityName.equal("public-api-quic-public"_ctv), "deployment_plan_roundtrip_preserves_public_tls_identity");
    suite.expect(roundtrip.publicTLS[0].domains.size() == 1 && roundtrip.publicTLS[0].domains[0].equal("api.example.com"_ctv), "deployment_plan_roundtrip_preserves_public_tls_domain");
    suite.expect(roundtrip.publicTLS[0].issuer.equal("letsencrypt"_ctv), "deployment_plan_roundtrip_preserves_public_tls_issuer");
    suite.expect(roundtrip.publicTLS[0].keyType.equal("ecdsa"_ctv), "deployment_plan_roundtrip_preserves_public_tls_key_type");
    suite.expect(roundtrip.publicTLS[0].staging == true, "deployment_plan_roundtrip_preserves_public_tls_staging");
    suite.expect(roundtrip.publicTLS[0].renewAfterLifetimePermille == 667, "deployment_plan_roundtrip_preserves_public_tls_renew_after");
  }

  {
    ContainerPlan plan {};
    plan.uuid = uint128_t(0x77);
    plan.config.applicationID = 88;
    plan.fragment = 9;
    plan.useHostNetworkNamespace = true;
    plan.networkAccess = ContainerNetworkAccess::declaredOnly;
    plan.restartOnFailure = true;
    plan.runtimeReady = true;
    plan.isStateful = true;
    plan.shardGroup = 3;
    plan.nShardGroups = 5;
    plan.statefulMeshRoles.sibling = 0x0100000000000001ULL;
    plan.statefulMeshRoles.topologyBridge = 0x0100000000000002ULL;
    plan.statefulTopology.operationID = 77;
    plan.statefulTopology.shardGroup = 3;
    plan.statefulTopology.topologyEpoch = 400;
    plan.statefulTopology.workerCount = 4;
    plan.statefulTopology.servingMode = StatefulTopologyServingMode::catchupOnly;
    plan.statefulTopology.sourceEpoch = 200;
    plan.statefulTopology.targetEpoch = 400;
    plan.statefulTopology.bridgeMode = StatefulTopologyBridgeMode::sourceToTarget;
    plan.assignedGPUMemoryMBs.push_back(16 * 1024u);
    plan.assignedGPUMemoryMBs.push_back(24 * 1024u);
    AssignedGPUDevice firstGPU = {};
    firstGPU.vendor = "nvidia"_ctv;
    firstGPU.model = "L4"_ctv;
    firstGPU.busAddress = "0000:65:00.0"_ctv;
    firstGPU.memoryMB = 24 * 1024u;
    plan.assignedGPUDevices.push_back(firstGPU);
    AssignedGPUDevice secondGPU = {};
    secondGPU.vendor = "amd"_ctv;
    secondGPU.model = "MI210"_ctv;
    secondGPU.busAddress = "0000:66:00.0"_ctv;
    secondGPU.memoryMB = 16 * 1024u;
    plan.assignedGPUDevices.push_back(secondGPU);
    Whitehole whitehole = {};
    whitehole.transport = ExternalAddressTransport::tcp;
    whitehole.family = ExternalAddressFamily::ipv4;
    whitehole.source = ExternalAddressSource::hostPublicAddress;
    whitehole.hasAddress = true;
    whitehole.address = IPAddress("203.0.113.99", false);
    whitehole.sourcePort = 6000;
    whitehole.bindingNonce = 1234;
    plan.whiteholes.push_back(whitehole);

    String serialized;
    BitseryEngine::serialize(serialized, plan);

    ContainerPlan roundtrip {};
    bool decoded = BitseryEngine::deserializeSafe(serialized, roundtrip);

    suite.expect(decoded, "container_plan_roundtrip_deserializes");
    suite.expect(roundtrip.useHostNetworkNamespace == true, "container_plan_roundtrip_preserves_host_network_namespace");
    suite.expect(roundtrip.networkAccess == ContainerNetworkAccess::declaredOnly, "container_plan_roundtrip_preserves_network_access");
    suite.expect(roundtrip.runtimeReady == true, "container_plan_roundtrip_preserves_runtime_ready");
    suite.expect(roundtrip.fragment == 9, "container_plan_roundtrip_preserves_fragment");
    suite.expect(roundtrip.shardGroup == 3, "container_plan_roundtrip_preserves_shard_group");
    suite.expect(roundtrip.nShardGroups == 5, "container_plan_roundtrip_preserves_shard_group_count");
    suite.expect(roundtrip.statefulMeshRoles.sibling == plan.statefulMeshRoles.sibling, "container_plan_roundtrip_preserves_stateful_sibling_role");
    suite.expect(roundtrip.statefulMeshRoles.topologyBridge == plan.statefulMeshRoles.topologyBridge, "container_plan_roundtrip_preserves_stateful_topology_bridge_role");
    suite.expect(roundtrip.statefulTopology.operationID == 77, "container_plan_roundtrip_preserves_topology_operation_id");
    suite.expect(roundtrip.statefulTopology.topologyEpoch == 400, "container_plan_roundtrip_preserves_topology_epoch");
    suite.expect(roundtrip.statefulTopology.workerCount == 4, "container_plan_roundtrip_preserves_topology_worker_count");
    suite.expect(roundtrip.statefulTopology.servingMode == StatefulTopologyServingMode::catchupOnly, "container_plan_roundtrip_preserves_topology_serving_mode");
    suite.expect(roundtrip.statefulTopology.sourceEpoch == 200, "container_plan_roundtrip_preserves_topology_source_epoch");
    suite.expect(roundtrip.statefulTopology.targetEpoch == 400, "container_plan_roundtrip_preserves_topology_target_epoch");
    suite.expect(roundtrip.statefulTopology.bridgeMode == StatefulTopologyBridgeMode::sourceToTarget, "container_plan_roundtrip_preserves_topology_bridge_mode");
    suite.expect(roundtrip.assignedGPUMemoryMBs.size() == 2, "container_plan_roundtrip_preserves_assigned_gpu_count");
    suite.expect(roundtrip.assignedGPUMemoryMBs[0] == 16 * 1024u && roundtrip.assignedGPUMemoryMBs[1] == 24 * 1024u, "container_plan_roundtrip_preserves_assigned_gpu_memory");
    suite.expect(roundtrip.assignedGPUDevices.size() == 2, "container_plan_roundtrip_preserves_assigned_gpu_devices_count");
    suite.expect(roundtrip.assignedGPUDevices[0].busAddress == "0000:65:00.0"_ctv && roundtrip.assignedGPUDevices[1].busAddress == "0000:66:00.0"_ctv, "container_plan_roundtrip_preserves_assigned_gpu_device_bus_addresses");
    suite.expect(roundtrip.assignedGPUDevices[0].vendor == "nvidia"_ctv && roundtrip.assignedGPUDevices[1].vendor == "amd"_ctv, "container_plan_roundtrip_preserves_assigned_gpu_device_vendors");
    suite.expect(roundtrip.whiteholes.size() == 1, "container_plan_roundtrip_preserves_whiteholes");
    suite.expect(roundtrip.whiteholes[0].sourcePort == 6000, "container_plan_roundtrip_preserves_whitehole_source_port");
    suite.expect(roundtrip.whiteholes[0].bindingNonce == 1234, "container_plan_roundtrip_preserves_whitehole_binding_nonce");
  }

  {
    DeploymentPlan plan {};
    plan.config.applicationID = 77;
    plan.config.versionID = 1;
    plan.config.type = ApplicationType::stateless;
    plan.config.filesystemMB = 64;
    plan.config.storageMB = 64;
    plan.config.memoryMB = 128;
    plan.config.nLogicalCores = 1;
    plan.config.msTilHealthy = 10'000;
    plan.config.sTilHealthcheck = 15;
    plan.config.sTilKillable = 30;
    plan.minimumSubscriberCapacity = 1024;
    plan.isStateful = false;
    plan.stateless.nBase = 1;
    plan.stateless.maxPerRackRatio = 1.0f;
    plan.stateless.maxPerMachineRatio = 1.0f;
    plan.stateless.moveableDuringCompaction = true;
    plan.useHostNetworkNamespace = false;
    plan.moveConstructively = true;
    plan.requiresDatacenterUniqueTag = false;

    Advertisement advertisement {};
    advertisement.service = 0x0100000000000001ULL;
    advertisement.startAt = ContainerState::scheduled;
    advertisement.stopAt = ContainerState::destroying;
    advertisement.port = 19'121;
    plan.advertisements.push_back(advertisement);

    Subscription subscription {};
    subscription.service = 0x0100000000000001ULL;
    subscription.startAt = ContainerState::scheduled;
    subscription.stopAt = ContainerState::destroying;
    subscription.nature = SubscriptionNature::any;
    plan.subscriptions.push_back(subscription);

    String serialized;
    BitseryEngine::serialize(serialized, plan);

    DeploymentPlan roundtrip {};
    const bool decoded = BitseryEngine::deserializeSafe(serialized, roundtrip);

    suite.expect(decoded, "deployment_plan_mesh_roundtrip_deserializes");
    suite.expect(roundtrip.advertisements.size() == 1, "deployment_plan_mesh_roundtrip_preserves_advertisement");
    suite.expect(roundtrip.subscriptions.size() == 1, "deployment_plan_mesh_roundtrip_preserves_subscription");

    String messageBuffer;
    const uint32_t headerOffset = Message::appendHeader(messageBuffer, MothershipTopic::measureApplication);
    Message::serializeAndAppendObject(messageBuffer, plan);
    Message::finish(messageBuffer, headerOffset);
    suite.expect(messageBuffer.size() >= sizeof(Message), "deployment_plan_mesh_message_serializes");

    Message *message = reinterpret_cast<Message *>(messageBuffer.data());
    uint8_t *args = message->args;
    String payload;
    Message::extractToStringView(args, payload);
    DeploymentPlan messageRoundtrip {};
    const bool messageDecoded = BitseryEngine::deserializeSafe(payload, messageRoundtrip);
    suite.expect(messageDecoded, "deployment_plan_mesh_message_deserializes");
    suite.expect(messageRoundtrip.advertisements.size() == 1, "deployment_plan_mesh_message_preserves_advertisement");

    String stagedMessageBuffer;
    const uint32_t stagedHeaderOffset = Message::appendHeader(stagedMessageBuffer, MothershipTopic::measureApplication);
    String stagedSerializedPlan;
    BitseryEngine::serialize(stagedSerializedPlan, plan);
    Message::appendValue(stagedMessageBuffer, stagedSerializedPlan);
    Message::finish(stagedMessageBuffer, stagedHeaderOffset);

    Message *stagedMessage = reinterpret_cast<Message *>(stagedMessageBuffer.data());
    uint8_t *stagedArgs = stagedMessage->args;
    String stagedPayload;
    Message::extractToStringView(stagedArgs, stagedPayload);
    DeploymentPlan stagedRoundtrip {};
    const bool stagedDecoded = BitseryEngine::deserializeSafe(stagedPayload, stagedRoundtrip);
    suite.expect(stagedDecoded, "deployment_plan_mesh_staged_message_deserializes");
    suite.expect(stagedRoundtrip.advertisements.size() == 1, "deployment_plan_mesh_staged_message_preserves_advertisement");
    suite.expect(stagedRoundtrip.subscriptions.size() == 1, "deployment_plan_mesh_staged_message_preserves_subscription");
  }

  {
    DeploymentPlan plan {};

    HorizontalScaler horizontalCpu {};
    horizontalCpu.name.assign(ProdigyMetrics::runtimeContainerCpuUtilPctName);
    plan.horizontalScalers.push_back(horizontalCpu);

    HorizontalScaler horizontalIngress {};
    horizontalIngress.name.assign(ProdigyMetrics::runtimeIngressQueueWaitCompositeName);
    plan.horizontalScalers.push_back(horizontalIngress);

    VerticalScaler verticalMemory {};
    verticalMemory.resource = ScalingDimension::memory;
    plan.verticalScalers.push_back(verticalMemory);

    NeuronContainerMetricPolicy policy = deriveNeuronMetricPolicyForDeployment(plan);
    const uint64_t expectedMask =
        ProdigyMetrics::maskForScalingDimension(ScalingDimension::cpu) |
        ProdigyMetrics::maskForScalingDimension(ScalingDimension::memory);

    suite.expect(policy.scalingDimensionsMask == expectedMask, "deriveNeuronMetricPolicy_uses_collectable_scaler_dimensions");
    suite.expect(policy.metricsCadenceMs == ProdigyMetrics::defaultNeuronCollectionCadenceMs, "deriveNeuronMetricPolicy_sets_default_cadence_when_collectable_present");
  }

  {
    DeploymentPlan plan {};
    HorizontalScaler horizontalIngress {};
    horizontalIngress.name.assign(ProdigyMetrics::runtimeIngressQueueWaitCompositeName);
    plan.horizontalScalers.push_back(horizontalIngress);

    NeuronContainerMetricPolicy policy = deriveNeuronMetricPolicyForDeployment(plan);
    suite.expect(policy.scalingDimensionsMask == 0, "deriveNeuronMetricPolicy_excludes_ingress_composite_from_neuron_sampling");
    suite.expect(policy.metricsCadenceMs == 0, "deriveNeuronMetricPolicy_keeps_zero_cadence_without_collectable_dimensions");
  }

  {
    ContainerPlan plan {};
    constexpr uint64_t dynamicSubscriptionService = 0x700000000001ULL;
    constexpr uint64_t scheduledSubscriptionService = 0x700000000002ULL;
    constexpr uint64_t healthySubscriptionService = 0x700000000003ULL;
    constexpr uint64_t dynamicAdvertisementService = 0x700000000004ULL;
    constexpr uint64_t scheduledAdvertisementService = 0x700000000005ULL;
    constexpr uint64_t healthyAdvertisementService = 0x700000000006ULL;

    plan.state = ContainerState::healthy;
    plan.subscriptions.insert_or_assign(
        scheduledSubscriptionService,
        Subscription(scheduledSubscriptionService, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all));
    plan.subscriptions.insert_or_assign(
        healthySubscriptionService,
        Subscription(healthySubscriptionService, ContainerState::healthy, ContainerState::destroying, SubscriptionNature::all));
    plan.advertisements.insert_or_assign(
        scheduledAdvertisementService,
        Advertisement(scheduledAdvertisementService, ContainerState::scheduled, ContainerState::destroying, 12'001));
    plan.advertisements.insert_or_assign(
        healthyAdvertisementService,
        Advertisement(healthyAdvertisementService, ContainerState::healthy, ContainerState::destroying, 12'002));

    plan.subscriptionPairings.insert(dynamicSubscriptionService, SubscriptionPairing(uint128_t(1), uint128_t(2), dynamicSubscriptionService, 13'001));
    plan.subscriptionPairings.insert(scheduledSubscriptionService, SubscriptionPairing(uint128_t(3), uint128_t(4), scheduledSubscriptionService, 13'002));
    plan.subscriptionPairings.insert(healthySubscriptionService, SubscriptionPairing(uint128_t(5), uint128_t(6), healthySubscriptionService, 13'003));
    plan.advertisementPairings.insert(dynamicAdvertisementService, AdvertisementPairing(uint128_t(7), uint128_t(8), dynamicAdvertisementService));
    plan.advertisementPairings.insert(scheduledAdvertisementService, AdvertisementPairing(uint128_t(9), uint128_t(10), scheduledAdvertisementService));
    plan.advertisementPairings.insert(healthyAdvertisementService, AdvertisementPairing(uint128_t(11), uint128_t(12), healthyAdvertisementService));

    plan.prepareForRestartSchedule();

    suite.expect(plan.state == ContainerState::scheduled, "container_plan_restart_prepare_marks_scheduled");
    suite.expect(plan.subscriptionPairings.find(dynamicSubscriptionService) != plan.subscriptionPairings.end(), "container_plan_restart_prepare_keeps_dynamic_subscription_pairing");
    suite.expect(plan.subscriptionPairings.find(scheduledSubscriptionService) != plan.subscriptionPairings.end(), "container_plan_restart_prepare_keeps_scheduled_subscription_pairing");
    suite.expect(plan.subscriptionPairings.find(healthySubscriptionService) != plan.subscriptionPairings.end(), "container_plan_restart_prepare_keeps_healthy_subscription_pairing");
    suite.expect(plan.advertisementPairings.find(dynamicAdvertisementService) != plan.advertisementPairings.end(), "container_plan_restart_prepare_keeps_dynamic_advertisement_pairing");
    suite.expect(plan.advertisementPairings.find(scheduledAdvertisementService) != plan.advertisementPairings.end(), "container_plan_restart_prepare_keeps_scheduled_advertisement_pairing");
    suite.expect(plan.advertisementPairings.find(healthyAdvertisementService) != plan.advertisementPairings.end(), "container_plan_restart_prepare_keeps_healthy_advertisement_pairing");
  }

  {
    NeuronContainerBootstrap bootstrap {};
    bootstrap.plan.uuid = uint128_t(0x1234);
    bootstrap.plan.config.applicationID = 55;
    bootstrap.plan.config.versionID = 66;
    bootstrap.plan.config.containerBlobSHA256 = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"_ctv;
    bootstrap.plan.config.containerBlobBytes = 8192;
    bootstrap.plan.useHostNetworkNamespace = true;
    Whitehole whitehole = {};
    whitehole.transport = ExternalAddressTransport::tcp;
    whitehole.family = ExternalAddressFamily::ipv4;
    whitehole.source = ExternalAddressSource::hostPublicAddress;
    whitehole.hasAddress = true;
    whitehole.address = IPAddress("198.51.100.77", false);
    whitehole.sourcePort = 4444;
    whitehole.bindingNonce = 222;
    bootstrap.plan.whiteholes.push_back(whitehole);
    bootstrap.metricPolicy.scalingDimensionsMask = ProdigyMetrics::maskForScalingDimension(ScalingDimension::storage);
    bootstrap.metricPolicy.metricsCadenceMs = 9000;

    String serialized;
    BitseryEngine::serialize(serialized, bootstrap);

    NeuronContainerBootstrap roundtrip {};
    const bool decoded = BitseryEngine::deserializeSafe(serialized, roundtrip);

    suite.expect(decoded, "neuron_container_bootstrap_roundtrip_deserializes");
    suite.expect(roundtrip.plan.uuid == uint128_t(0x1234), "neuron_container_bootstrap_roundtrip_preserves_plan_uuid");
    suite.expect(roundtrip.plan.config.applicationID == 55 && roundtrip.plan.config.versionID == 66, "neuron_container_bootstrap_roundtrip_preserves_plan_config_ids");
    suite.expect(roundtrip.plan.config.containerBlobSHA256.equals(bootstrap.plan.config.containerBlobSHA256), "neuron_container_bootstrap_roundtrip_preserves_plan_blob_sha256");
    suite.expect(roundtrip.plan.config.containerBlobBytes == bootstrap.plan.config.containerBlobBytes, "neuron_container_bootstrap_roundtrip_preserves_plan_blob_bytes");
    suite.expect(roundtrip.plan.useHostNetworkNamespace == true, "neuron_container_bootstrap_roundtrip_preserves_host_network_namespace");
    suite.expect(roundtrip.plan.whiteholes.size() == 1, "neuron_container_bootstrap_roundtrip_preserves_whiteholes");
    suite.expect(roundtrip.plan.whiteholes[0].sourcePort == 4444, "neuron_container_bootstrap_roundtrip_preserves_whitehole_source_port");
    suite.expect(roundtrip.metricPolicy.scalingDimensionsMask == bootstrap.metricPolicy.scalingDimensionsMask, "neuron_container_bootstrap_roundtrip_preserves_metric_mask");
    suite.expect(roundtrip.metricPolicy.metricsCadenceMs == 9000, "neuron_container_bootstrap_roundtrip_preserves_metric_cadence");

    String stagedMessageBuffer;
    const uint32_t stagedHeaderOffset = Message::appendHeader(stagedMessageBuffer, NeuronTopic::stateUpload);
    String stagedSerializedBootstrap;
    BitseryEngine::serialize(stagedSerializedBootstrap, bootstrap);
    Message::appendValue(stagedMessageBuffer, stagedSerializedBootstrap);
    Message::finish(stagedMessageBuffer, stagedHeaderOffset);

    Message *stagedMessage = reinterpret_cast<Message *>(stagedMessageBuffer.data());
    uint8_t *stagedArgs = stagedMessage->args;
    String stagedPayload;
    Message::extractToStringView(stagedArgs, stagedPayload);
    NeuronContainerBootstrap stagedRoundtrip {};
    const bool stagedDecoded = BitseryEngine::deserializeSafe(stagedPayload, stagedRoundtrip);
    suite.expect(stagedDecoded, "neuron_container_bootstrap_staged_message_deserializes");
    suite.expect(stagedRoundtrip.plan.uuid == bootstrap.plan.uuid, "neuron_container_bootstrap_staged_message_preserves_plan_uuid");
    suite.expect(stagedRoundtrip.metricPolicy.metricsCadenceMs == bootstrap.metricPolicy.metricsCadenceMs, "neuron_container_bootstrap_staged_message_preserves_metric_cadence");
  }

  {
    DeploymentPlan deploymentPlan {};
    deploymentPlan.config.applicationID = 501;
    deploymentPlan.config.versionID = 3;
    deploymentPlan.useHostNetworkNamespace = true;
    deploymentPlan.requiresDatacenterUniqueTag = true;

    ContainerView container {};
    container.uuid = uint128_t(0x8888);
    container.fragment = 17;
    container.lifetime = ApplicationLifetime::base;
    container.state = ContainerState::scheduled;
    container.createdAtMs = 123'456;
    container.shardGroup = 7;
    container.networkAccess = ContainerNetworkAccess::declaredOnly;
    container.assignedGPUMemoryMBs.push_back(24 * 1024u);
    AssignedGPUDevice assignedGPU = {};
    assignedGPU.vendor = "nvidia"_ctv;
    assignedGPU.model = "A10"_ctv;
    assignedGPU.busAddress = "0000:af:00.0"_ctv;
    assignedGPU.memoryMB = 24 * 1024u;
    container.assignedGPUDevices.push_back(assignedGPU);

    ContainerPlan plan = container.generatePlan(deploymentPlan);
    suite.expect(plan.useHostNetworkNamespace == true, "containerview_generatePlan_preserves_host_network_namespace");
    suite.expect(plan.networkAccess == ContainerNetworkAccess::declaredOnly, "containerview_generatePlan_preserves_network_access");
    suite.expect(plan.requiresDatacenterUniqueTag == true, "containerview_generatePlan_preserves_unique_tag");
    suite.expect(plan.fragment == 17, "containerview_generatePlan_preserves_fragment");
    suite.expect(plan.assignedGPUMemoryMBs.size() == 1 && plan.assignedGPUMemoryMBs[0] == 24 * 1024u, "containerview_generatePlan_preserves_assigned_gpu_memory");
    suite.expect(plan.assignedGPUDevices.size() == 1 && plan.assignedGPUDevices[0].busAddress == "0000:af:00.0"_ctv, "containerview_generatePlan_preserves_assigned_gpu_devices");
  }

  {
    DeploymentPlan deploymentPlan {};
    deploymentPlan.config.applicationID = 502;
    deploymentPlan.config.versionID = 4;
    deploymentPlan.useHostNetworkNamespace = true;
    deploymentPlan.isStateful = true;
    deploymentPlan.stateful.clientPrefix = (uint64_t(502) << 48) | (uint64_t(1) << 40) | 0x3ffULL;
    deploymentPlan.stateful.siblingPrefix = (uint64_t(502) << 48) | (uint64_t(2) << 40) | 0x3ffULL;
    deploymentPlan.stateful.cousinPrefix = (uint64_t(502) << 48) | (uint64_t(3) << 40) | 0x3ffULL;
    deploymentPlan.stateful.seedingPrefix = (uint64_t(502) << 48) | (uint64_t(4) << 40) | 0x3ffULL;
    deploymentPlan.stateful.shardingPrefix = (uint64_t(502) << 48) | (uint64_t(5) << 40) | 0x3ffULL;

    ContainerView container {};
    container.uuid = uint128_t(0x9999);
    container.fragment = 18;
    container.lifetime = ApplicationLifetime::base;
    container.state = ContainerState::scheduled;
    container.createdAtMs = 123'457;
    container.shardGroup = 7;
    container.isStateful = true;

    StatefulMeshRoles roles = StatefulMeshRoles::forShardGroup(deploymentPlan.stateful, deploymentPlan.config.applicationID, container.shardGroup);
    container.advertisements.emplace(roles.sibling, Advertisement(roles.sibling, ContainerState::scheduled, ContainerState::destroying, 19'113));
    container.subscriptions.emplace(roles.sibling, Subscription(roles.sibling, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all));
    container.subscriptions.emplace(roles.seeding, Subscription(roles.seeding, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::all));

    ContainerPlan plan = container.generatePlan(deploymentPlan, 11);
    suite.expect(plan.statefulMeshRoles.client == 0, "containerview_generatePlan_prunes_unassigned_stateful_client_role");
    suite.expect(plan.statefulMeshRoles.sibling == roles.sibling, "containerview_generatePlan_preserves_assigned_stateful_sibling_role");
    suite.expect(plan.statefulMeshRoles.cousin == 0, "containerview_generatePlan_prunes_unassigned_stateful_cousin_role");
    suite.expect(plan.statefulMeshRoles.seeding == roles.seeding, "containerview_generatePlan_preserves_assigned_stateful_seeding_role");
    suite.expect(plan.statefulMeshRoles.sharding == 0, "containerview_generatePlan_prunes_unassigned_stateful_sharding_role");
    suite.expect(plan.statefulMeshRoles.topologyBridge == 0, "containerview_generatePlan_prunes_unassigned_stateful_topology_bridge_role");
    suite.expect(plan.nShardGroups == 11, "containerview_generatePlan_preserves_stateful_shard_group_count");
  }

  {
    ContainerPlan plan {};
    plan.isStateful = true;
    plan.shardGroup = 7;
    plan.nShardGroups = 13;

    Vector<uint64_t> flags = {};
    prodigyBuildContainerStartupFlags(plan, flags);

    suite.expect(flags.size() == 2, "container_startup_flags_stateful_include_two_entries");
    suite.expect(flags[0] == 7, "container_startup_flags_stateful_preserve_shard_group");
    suite.expect(flags[1] == 13, "container_startup_flags_stateful_preserve_shard_group_count");
  }

  {
    ContainerPlan plan {};
    Vector<uint64_t> flags = {};
    prodigyBuildContainerStartupFlags(plan, flags);

    suite.expect(flags.size() == 1, "container_startup_flags_stateless_keep_one_entry_shape");
    suite.expect(flags[0] == 0, "container_startup_flags_stateless_default_zero_group");
  }

  {
    StatefulMeshRoles roles {};
    roles.topologyBridge = 0x0100000000001234ULL;

    suite.expect(
        roles.classify(roles.topologyBridge) == StatefulMeshRole::topologyBridge,
        "stateful_mesh_roles_classify_topology_bridge");
  }

  {
    StatefulDeploymentPlan plan {};
    plan.clientPrefix = MeshServices::generateStatefulService(501, 1);
    plan.siblingPrefix = MeshServices::generateStatefulService(501, 2);
    plan.cousinPrefix = MeshServices::generateStatefulService(501, 3);
    plan.seedingPrefix = MeshServices::generateStatefulService(501, 4);
    plan.shardingPrefix = MeshServices::generateStatefulService(501, 5);

    StatefulMeshRoles roles = StatefulMeshRoles::forShardGroup(plan, 501, 7);
    suite.expect(roles.topologyBridge == MeshServices::constrainPrefixToGroup(prodigyDefaultStatefulTopologyBridgePrefix(501), 7), "stateful_mesh_roles_for_shard_group_derives_topology_bridge");
  }

  {
    ApplicationConfig config {};
    config.nLogicalCores = 6;

    StatefulTopology topology {};
    prodigyPopulateDefaultStatefulTopology(topology, 7, config);

    suite.expect(topology.shardGroup == 7, "stateful_topology_defaults_preserve_shard_group");
    suite.expect(topology.workerCount == 4, "stateful_topology_defaults_derive_worker_count");
    suite.expect(topology.topologyEpoch == 4, "stateful_topology_defaults_epoch_matches_worker_count");
    suite.expect(topology.sourceEpoch == 4, "stateful_topology_defaults_source_epoch_matches_topology_epoch");
    suite.expect(topology.targetEpoch == 4, "stateful_topology_defaults_target_epoch_matches_topology_epoch");
    suite.expect(topology.servingMode == StatefulTopologyServingMode::serve, "stateful_topology_defaults_to_serve");
  }

  {
    suite.expect(prodigyStatefulCoreChangeRequiresTopologyUpgrade(true, 1, 2), "stateful_core_change_upgrade_required_for_one_to_two");
    suite.expect(prodigyStatefulCoreChangeRequiresTopologyUpgrade(true, 3, 2), "stateful_core_change_upgrade_required_for_three_to_two");
    suite.expect(prodigyStatefulCoreChangeRequiresTopologyUpgrade(true, 4, 4) == false, "stateful_core_change_upgrade_not_required_without_core_change");
    suite.expect(prodigyStatefulCoreChangeRequiresTopologyUpgrade(false, 4, 6) == false, "stateful_core_change_upgrade_not_required_for_stateless");
  }

  {
    ContainerView container {};
    container.applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverSourceEpochKey(), 200);
    container.applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverTargetEpochKey(), 400);
    container.applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverReadyKey(), 1);

    suite.expect(container.hasStatefulTopologyCutoverBarrier(200, 400), "containerview_cutover_metric_sets_ready_barrier");

    container.applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverReadyKey(), 0);
    suite.expect(container.hasStatefulTopologyCutoverBarrier(200, 400) == false, "containerview_cutover_metric_zero_clears_barrier");
    suite.expect(container.statefulTopologyCutoverSourceEpoch == 0 && container.statefulTopologyCutoverTargetEpoch == 0, "containerview_cutover_metric_zero_clears_epochs");
  }

  {
    StatefulTopology source {};
    source.topologyEpoch = 200;
    source.sourceEpoch = 200;
    source.targetEpoch = 400;
    source.bridgeMode = StatefulTopologyBridgeMode::sourceToTarget;

    StatefulTopology target = source;
    target.topologyEpoch = 400;

    suite.expect(prodigyStatefulTopologyShouldAdvertiseBridge(source), "stateful_topology_source_to_target_source_advertises_bridge");
    suite.expect(prodigyStatefulTopologyShouldSubscribeBridge(source) == false, "stateful_topology_source_to_target_source_does_not_subscribe_bridge");
    suite.expect(prodigyStatefulTopologyShouldAdvertiseBridge(target) == false, "stateful_topology_source_to_target_target_does_not_advertise_bridge");
    suite.expect(prodigyStatefulTopologyShouldSubscribeBridge(target), "stateful_topology_source_to_target_target_subscribes_bridge");
  }

  {
    ContainerParameters parameters {};
    parameters.nLogicalCores = 6;
    parameters.lowCPU = 2;
    parameters.highCPU = 7;
    parameters.statefulMeshRoles.sibling = 0x0100000000000101ULL;
    parameters.statefulMeshRoles.topologyBridge = 0x0100000000000102ULL;
    parameters.statefulTopology.operationID = 88;
    parameters.statefulTopology.shardGroup = 5;
    parameters.statefulTopology.topologyEpoch = 400;
    parameters.statefulTopology.workerCount = 4;
    parameters.statefulTopology.servingMode = StatefulTopologyServingMode::drainOnly;
    parameters.statefulTopology.sourceEpoch = 200;
    parameters.statefulTopology.targetEpoch = 400;
    parameters.statefulTopology.bridgeMode = StatefulTopologyBridgeMode::targetToSource;
    parameters.subscriptionPairings.insert(
        0x0100000000000101ULL,
        SubscriptionPairing(uint128_t(0x1111222233334444ULL), uint128_t(0x5555666677778888ULL), 0x0100000000000101ULL, 8443));
    parameters.advertisementPairings.insert(
        0x0100000000000102ULL,
        AdvertisementPairing(uint128_t(0x9999aaaabbbbccccULL), uint128_t(0xddddeeeeffff0001ULL), 0x0100000000000102ULL));

    String serialized;
    BitseryEngine::serialize(serialized, parameters);

    ContainerParameters roundtrip {};
    bool decoded = BitseryEngine::deserializeSafe(serialized, roundtrip);

    suite.expect(decoded, "container_parameters_roundtrip_deserializes");
    suite.expect(roundtrip.statefulMeshRoles.sibling == parameters.statefulMeshRoles.sibling, "container_parameters_roundtrip_preserves_stateful_sibling_role");
    suite.expect(roundtrip.statefulMeshRoles.topologyBridge == parameters.statefulMeshRoles.topologyBridge, "container_parameters_roundtrip_preserves_topology_bridge_role");
    suite.expect(roundtrip.statefulTopology.operationID == 88, "container_parameters_roundtrip_preserves_topology_operation_id");
    suite.expect(roundtrip.statefulTopology.shardGroup == 5, "container_parameters_roundtrip_preserves_topology_shard_group");
    suite.expect(roundtrip.statefulTopology.topologyEpoch == 400, "container_parameters_roundtrip_preserves_topology_epoch");
    suite.expect(roundtrip.statefulTopology.workerCount == 4, "container_parameters_roundtrip_preserves_topology_worker_count");
    suite.expect(roundtrip.statefulTopology.servingMode == StatefulTopologyServingMode::drainOnly, "container_parameters_roundtrip_preserves_topology_serving_mode");
    suite.expect(roundtrip.statefulTopology.sourceEpoch == 200, "container_parameters_roundtrip_preserves_topology_source_epoch");
    suite.expect(roundtrip.statefulTopology.targetEpoch == 400, "container_parameters_roundtrip_preserves_topology_target_epoch");
    suite.expect(roundtrip.statefulTopology.bridgeMode == StatefulTopologyBridgeMode::targetToSource, "container_parameters_roundtrip_preserves_topology_bridge_mode");
    auto subscriptionIt = roundtrip.subscriptionPairings.find(0x0100000000000101ULL);
    bool subscriptionPreserved =
        subscriptionIt != roundtrip.subscriptionPairings.end() &&
        subscriptionIt->second.size() == 1 &&
        subscriptionIt->second[0] == SubscriptionPairing(uint128_t(0x1111222233334444ULL), uint128_t(0x5555666677778888ULL), 0x0100000000000101ULL, 8443);
    suite.expect(subscriptionPreserved, "container_parameters_roundtrip_preserves_subscription_pairings");
    if (subscriptionPreserved)
    {
      uint64_t hash = AegisStream::generateSecretServiceHash(subscriptionIt->second[0].secret, subscriptionIt->second[0].service);
      suite.expect(hash != 0, "container_parameters_roundtrip_subscription_pairing_hashes");
    }
    auto advertisementIt = roundtrip.advertisementPairings.find(0x0100000000000102ULL);
    suite.expect(
        advertisementIt != roundtrip.advertisementPairings.end() &&
        advertisementIt->second.size() == 1 &&
        advertisementIt->second[0] == AdvertisementPairing(uint128_t(0x9999aaaabbbbccccULL), uint128_t(0xddddeeeeffff0001ULL), 0x0100000000000102ULL),
        "container_parameters_roundtrip_preserves_advertisement_pairings");
  }

  {
    ProdigyMasterAuthorityRuntimeState runtimeState = {};
    runtimeState.generation = 17;
    runtimeState.nextPendingAddMachinesOperationID = 9;

    ProdigyStatefulWorkerTopologyUpgradeOperation operation = {};
    operation.deploymentID = 9911;
    operation.applicationID = 88;
    operation.operationID = 7711;
    operation.phase = StatefulWorkerTopologyUpgradePhase::greenBootstrap;
    operation.sourceWorkerCount = 2;
    operation.targetWorkerCount = 4;
    operation.sourceEpoch = 200;
    operation.targetEpoch = 400;
    operation.targetLogicalCores = 4;
    operation.targetMemoryMB = 512;
    operation.targetStorageMB = 64;
    operation.lockedShardGroups.push_back(0);
    operation.lockedShardGroups.push_back(2);
    operation.updatedAtMs = 123'456'789;
    runtimeState.statefulWorkerTopologyUpgradeOperations.push_back(operation);

    RoutableResourceLease lease = {};
    lease.kind = RoutableResourceLeaseKind::whiteholeAddressPort;
    lease.owner.applicationID = 88;
    lease.owner.deploymentID = 9911;
    lease.owner.lineageID = 9911;
    lease.owner.name = "egress"_ctv;
    lease.registeredPrefixUUID = 0x991100;
    lease.address = IPAddress("198.51.100.88", false);
    lease.sourcePort = 50'088;
    runtimeState.routableResourceLeases.push_back(lease);

    PublicTlsCertificateState publicCert = {};
    publicCert.spec.applicationID = 88;
    publicCert.spec.deploymentID = 9911;
    publicCert.spec.wormholeName = "api"_ctv;
    publicCert.spec.identityName = "api-public"_ctv;
    publicCert.spec.domains.push_back("api.example.com"_ctv);
    publicCert.spec.issuer = "letsencrypt"_ctv;
    publicCert.spec.keyType = "ecdsa"_ctv;
    publicCert.spec.dnsProvider = "cloudflare"_ctv;
    publicCert.spec.dnsCredentialName = "prod-dns"_ctv;
    publicCert.spec.dnsZone = "example.com"_ctv;
    publicCert.spec.dnsTTL = 60;
    publicCert.identity.name = "api-public"_ctv;
    publicCert.identity.generation = 4;
    publicCert.identity.notBeforeMs = 1'700'000'000'000;
    publicCert.identity.notAfterMs = 1'700'086'400'000;
    publicCert.identity.certPem = "cert"_ctv;
    publicCert.identity.keyPem = "key"_ctv;
    publicCert.identity.chainPem = "chain"_ctv;
    publicCert.identity.dnsSans.push_back("api.example.com"_ctv);
    publicCert.certbotCertName = "app88-api"_ctv;
    publicCert.lineagePath = "/var/lib/prodigy/certbot/cluster/config/live/app88-api"_ctv;
    publicCert.generation = 4;
    publicCert.nextRenewAtMs = prodigyCertificateRenewAtMs(publicCert.identity.notBeforeMs, publicCert.identity.notAfterMs, publicCert.spec.renewAfterLifetimePermille);
    publicCert.lastAttemptMs = 1'700'010'000'000;
    publicCert.lastSuccessMs = 1'700'010'001'000;
    publicCert.failureCount = 2;
    publicCert.lastFailure = "previous public tls failure"_ctv;
    runtimeState.publicTlsCertificates.push_back(publicCert);

    PrivateTlsVaultLifecycleState privateVault = {};
    privateVault.applicationID = 88;
    privateVault.factoryGeneration = 12;
    privateVault.rootNotBeforeMs = 1'700'000'000'000;
    privateVault.rootNotAfterMs = 1'725'920'000'000;
    privateVault.intermediateNotBeforeMs = 1'700'000'000'000;
    privateVault.intermediateNotAfterMs = 1'708'640'000'000;
    privateVault.leafNotBeforeMs = 1'700'000'000'000;
    privateVault.leafNotAfterMs = 1'701'296'000'000;
    privateVault.leafNextRenewAtMs = prodigyCertificateRenewAtMs(privateVault.leafNotBeforeMs, privateVault.leafNotAfterMs, prodigyDefaultCertificateRenewAfterLifetimePermille);
    privateVault.nextRenewAtMs = prodigyEarliestPositiveMs(
        prodigyCertificateRenewAtMs(privateVault.intermediateNotBeforeMs, privateVault.intermediateNotAfterMs, prodigyDefaultCertificateRenewAfterLifetimePermille),
        privateVault.leafNextRenewAtMs);
    privateVault.failureCount = 3;
    privateVault.lastFailure = "previous private tls failure"_ctv;
    runtimeState.privateTlsVaultLifecycles.push_back(privateVault);

    String serialized = {};
    BitseryEngine::serialize(serialized, runtimeState);

    ProdigyMasterAuthorityRuntimeState roundtrip = {};
    bool decoded = BitseryEngine::deserializeSafe(serialized, roundtrip);

    suite.expect(decoded, "runtime_state_roundtrip_deserializes_stateful_worker_topology_upgrade");
    suite.expect(roundtrip.statefulWorkerTopologyUpgradeOperations.size() == 1, "runtime_state_roundtrip_preserves_stateful_worker_topology_upgrade_count");
    suite.expect(roundtrip.statefulWorkerTopologyUpgradeOperations.size() == 1 && roundtrip.statefulWorkerTopologyUpgradeOperations[0].deploymentID == 9911, "runtime_state_roundtrip_preserves_stateful_worker_topology_upgrade_deployment_id");
    suite.expect(roundtrip.statefulWorkerTopologyUpgradeOperations.size() == 1 && roundtrip.statefulWorkerTopologyUpgradeOperations[0].operationID == 7711, "runtime_state_roundtrip_preserves_stateful_worker_topology_upgrade_operation_id");
    suite.expect(roundtrip.statefulWorkerTopologyUpgradeOperations.size() == 1 && roundtrip.statefulWorkerTopologyUpgradeOperations[0].phase == StatefulWorkerTopologyUpgradePhase::greenBootstrap, "runtime_state_roundtrip_preserves_stateful_worker_topology_upgrade_phase");
    suite.expect(roundtrip.statefulWorkerTopologyUpgradeOperations.size() == 1 && roundtrip.statefulWorkerTopologyUpgradeOperations[0].targetLogicalCores == 4, "runtime_state_roundtrip_preserves_stateful_worker_topology_upgrade_target_cores");
    suite.expect(roundtrip.statefulWorkerTopologyUpgradeOperations.size() == 1 && roundtrip.statefulWorkerTopologyUpgradeOperations[0].lockedShardGroups.size() == 2, "runtime_state_roundtrip_preserves_stateful_worker_topology_upgrade_locked_groups");
    suite.expect(roundtrip.routableResourceLeases.size() == 1, "runtime_state_roundtrip_preserves_routable_resource_lease_count");
    suite.expect(roundtrip.routableResourceLeases.size() == 1 && roundtrip.routableResourceLeases[0] == lease, "runtime_state_roundtrip_preserves_routable_resource_lease");
    suite.expect(roundtrip.publicTlsCertificates.size() == 1, "runtime_state_roundtrip_preserves_public_tls_certificate_count");
    suite.expect(roundtrip.publicTlsCertificates.size() == 1 && prodigyPublicTlsCertificateStatesEqual(roundtrip.publicTlsCertificates[0], publicCert), "runtime_state_roundtrip_preserves_public_tls_certificate");
    suite.expect(roundtrip.privateTlsVaultLifecycles.size() == 1, "runtime_state_roundtrip_preserves_private_tls_vault_lifecycle_count");
    suite.expect(roundtrip.privateTlsVaultLifecycles.size() == 1 && prodigyPrivateTlsVaultLifecycleStatesEqual(roundtrip.privateTlsVaultLifecycles[0], privateVault), "runtime_state_roundtrip_preserves_private_tls_vault_lifecycle");
    suite.expect(publicCert.nextRenewAtMs == 1'700'057'628'800, "certificate_renew_at_uses_two_thirds_actual_lifetime");
  }

  {
    BrainConfig config = {};
    config.clusterUUID = 0xA11CE;
    config.controlSocketPath = "/run/prodigy/control.sock"_ctv;
    config.remoteProdigyPath = "/opt/prodigy-root"_ctv;
    config.acme.accountEmail = "ops@example.com"_ctv;
    config.acme.certbotInstall = "bundle"_ctv;
    config.acme.certbotPath = "/opt/prodigy/certbot/bin/certbot"_ctv;
    config.acme.certbotVersion = "5.6.0"_ctv;
    config.acme.termsAgreed = true;

    PublicTlsCertificateState cert = {};
    cert.spec.applicationID = 7;
    cert.spec.deploymentID = 12'345;
    cert.spec.wormholeName = "api"_ctv;
    cert.spec.identityName = "api-public"_ctv;
    cert.spec.keyType = "ecdsa"_ctv;
    cert.spec.staging = true;
    cert.spec.domains.push_back("api.example.com"_ctv);
    cert.spec.domains.push_back("*.example.com"_ctv);
    cert.certbotCertName = "app7-api"_ctv;

    ProdigyCertbotCommand command = {};
    String failure = {};
    suite.expect(prodigyBuildCertbotCertonlyCommand(config, cert, {}, command, &failure), "certbot_certonly_command_builds");
    suite.expect(failure.size() == 0, "certbot_certonly_command_no_failure");
    suite.expect(command.argv.size() >= 30 && command.argv[0].equal("/opt/prodigy/certbot/bin/certbot"_ctv) && command.argv[1].equal("certonly"_ctv), "certbot_certonly_command_starts_managed_certbot");
    BrainConfig noSocketConfig = config;
    noSocketConfig.controlSocketPath.clear();
    ProdigyCertbotCommand badCommand = {};
    suite.expect(prodigyBuildCertbotCertonlyCommand(noSocketConfig, cert, {}, badCommand, &failure) == false, "certbot_certonly_command_requires_control_socket");
    suite.expect(failure.equal("public TLS Certbot requires cluster control socket"_ctv), "certbot_certonly_command_control_socket_failure");
    BrainConfig noClusterConfig = config;
    noClusterConfig.clusterUUID = 0;
    suite.expect(prodigyBuildCertbotCertonlyCommand(noClusterConfig, cert, {}, badCommand, &failure) == false, "certbot_certonly_command_requires_cluster_uuid");
    suite.expect(failure.equal("public TLS Certbot requires cluster UUID"_ctv), "certbot_certonly_command_cluster_uuid_failure");
    BrainConfig systemCertbotConfig = config;
    systemCertbotConfig.acme.certbotInstall = "system"_ctv;
    suite.expect(prodigyBuildCertbotCertonlyCommand(systemCertbotConfig, cert, {}, badCommand, &failure) == false, "certbot_certonly_command_rejects_system_certbot");
    suite.expect(failure.equal("ACME Certbot install must be bundle"_ctv), "certbot_certonly_command_rejects_system_certbot_reason");
    ProdigyCertbotPaths badPaths = {};
    badPaths.certbotPath = "/tmp/ambient-certbot"_ctv;
    suite.expect(prodigyBuildCertbotCertonlyCommand(config, cert, badPaths, badCommand, &failure) == false, "certbot_certonly_command_rejects_path_override");
    suite.expect(failure.equal("ACME Certbot path override does not match managed cluster path"_ctv), "certbot_certonly_command_rejects_path_override_reason");

    auto hasAdjacent = [&](const String& flag, const String& value) -> bool {
      for (uint32_t index = 0; index + 1 < command.argv.size(); index += 1)
      {
        if (command.argv[index].equal(flag) && command.argv[index + 1].equals(value))
        {
          return true;
        }
      }
      return false;
    };
    auto hasArg = [&](const String& arg) -> bool {
      for (const String& value : command.argv)
      {
        if (value.equal(arg))
        {
          return true;
        }
      }
      return false;
    };
    auto hasEnv = [&](const String& expected) -> bool {
      for (const String& entry : command.env)
      {
        if (entry.equals(expected))
        {
          return true;
        }
      }
      return false;
    };

    String clusterText;
    clusterText.assignItoh(config.clusterUUID);
    String expectedConfigDir;
    expectedConfigDir.assign("/var/lib/prodigy/certbot/"_ctv);
    expectedConfigDir.append(clusterText);
    expectedConfigDir.append("/config"_ctv);
    String expectedLogsDir;
    expectedLogsDir.assign("/var/log/prodigy/certbot/"_ctv);
    expectedLogsDir.append(clusterText);
    String expectedClusterEnv;
    expectedClusterEnv.assign("PRODIGY_CLUSTER_UUID="_ctv);
    expectedClusterEnv.append(clusterText);

    suite.expect(hasAdjacent("--cert-name"_ctv, "app7-api"_ctv), "certbot_certonly_command_cert_name");
    suite.expect(hasAdjacent("--email"_ctv, "ops@example.com"_ctv), "certbot_certonly_command_email");
    suite.expect(hasAdjacent("--key-type"_ctv, "ecdsa"_ctv), "certbot_certonly_command_key_type");
    suite.expect(hasAdjacent("-d"_ctv, "api.example.com"_ctv) && hasAdjacent("-d"_ctv, "*.example.com"_ctv), "certbot_certonly_command_domains");
    suite.expect(hasArg("--manual"_ctv) && hasArg("--agree-tos"_ctv) && hasArg("--test-cert"_ctv) && hasArg("--force-renewal"_ctv) && hasArg("--no-directory-hooks"_ctv), "certbot_certonly_command_modes");
    suite.expect(hasAdjacent("--config-dir"_ctv, expectedConfigDir), "certbot_certonly_command_default_config_dir");
    suite.expect(hasAdjacent("--logs-dir"_ctv, expectedLogsDir), "certbot_certonly_command_default_logs_dir");
    suite.expect(hasEnv("PRODIGY_CONTROL_SOCKET=/run/prodigy/control.sock"_ctv), "certbot_certonly_env_control_socket");
    suite.expect(hasEnv("PRODIGY_MOTHERSHIP_SOCKET=/run/prodigy/control.sock"_ctv), "certbot_certonly_env_mothership_socket");
    suite.expect(hasEnv("PRODIGY_MOTHERSHIP=/opt/prodigy-root/tools/mothership"_ctv), "certbot_certonly_env_mothership_path");
    suite.expect(hasEnv(expectedClusterEnv), "certbot_certonly_env_cluster_uuid");
    suite.expect(hasEnv("PRODIGY_ACME_CERT_NAME=app7-api"_ctv), "certbot_certonly_env_cert_name");
    suite.expect(hasEnv("PRODIGY_ACME_APPLICATION_ID=7"_ctv), "certbot_certonly_env_application");
    suite.expect(hasEnv("PRODIGY_ACME_DEPLOYMENT_ID=12345"_ctv), "certbot_certonly_env_deployment");
    suite.expect(hasEnv("PRODIGY_ACME_WORMHOLE_NAME=api"_ctv), "certbot_certonly_env_wormhole");

    setenv("AWS_SECRET_ACCESS_KEY", "must-not-leak", 1);
    Vector<String> childEnv = {};
    Vector<String> overrides = {};
    overrides.push_back("PRODIGY_ONLY=1"_ctv);
    prodigyBuildEnvironmentWithOverrides(overrides, childEnv);
    auto childHasEnv = [&](const String& expected) -> bool {
      for (const String& entry : childEnv)
      {
        if (entry.equals(expected))
        {
          return true;
        }
      }
      return false;
    };
    auto childHasEnvPrefix = [&](const String& prefix) -> bool {
      for (const String& entry : childEnv)
      {
        if (entry.size() >= prefix.size() && entry.substr(0, prefix.size()).equals(prefix))
        {
          return true;
        }
      }
      return false;
    };
    suite.expect(childHasEnv("PATH=/usr/sbin:/usr/bin:/sbin:/bin"_ctv), "certbot_child_env_has_minimal_path");
    suite.expect(childHasEnv("LANG=C.UTF-8"_ctv), "certbot_child_env_has_minimal_lang");
    suite.expect(childHasEnv("PRODIGY_ONLY=1"_ctv), "certbot_child_env_keeps_override");
    suite.expect(childHasEnvPrefix("AWS_SECRET_ACCESS_KEY="_ctv) == false, "certbot_child_env_drops_parent_secret");
    unsetenv("AWS_SECRET_ACCESS_KEY");

    String recordName = {};
    suite.expect(prodigyACMEDNS01RecordName("*.example.com"_ctv, recordName, &failure) && recordName.equal("_acme-challenge.example.com."_ctv), "acme_dns01_record_name_canonicalizes_wildcard");
    suite.expect(prodigyACMEDNS01RecordName("API.Example.COM."_ctv, recordName, &failure) && recordName.equal("_acme-challenge.api.example.com."_ctv), "acme_dns01_record_name_canonicalizes_fqdn");
    suite.expect(prodigyACMEDNS01RecordName("https://api.example.com"_ctv, recordName, &failure) == false && failure.equal("ACME DNS-01 identifier is not a valid DNS name"_ctv), "acme_dns01_record_name_rejects_url");

    setenv("PRODIGY_ACME_APPLICATION_ID", "7", 1);
    setenv("PRODIGY_ACME_DEPLOYMENT_ID", "12345", 1);
    setenv("PRODIGY_ACME_WORMHOLE_NAME", "api", 1);
    setenv("PRODIGY_ACME_CERT_NAME", "app7-api", 1);
    setenv("PRODIGY_CLUSTER_UUID", clusterText.c_str(), 1);
    setenv("CERTBOT_IDENTIFIER", "*.example.com", 1);
    setenv("CERTBOT_VALIDATION", "txt-token", 1);
    AcmeDNS01ChallengeRequest challenge = {};
    suite.expect(prodigyBuildACMEDNS01ChallengeRequestFromEnv(challenge, &failure), "acme_dns01_hook_request_parses_env");
    suite.expect(challenge.clusterUUID == config.clusterUUID && challenge.applicationID == 7 && challenge.deploymentID == 12'345 && challenge.certName.equal("app7-api"_ctv) && challenge.validation.equal("txt-token"_ctv), "acme_dns01_hook_request_values");

    setenv("RENEWED_LINEAGE", "/var/lib/prodigy/certbot/config/live/app7-api", 1);
    setenv("RENEWED_DOMAINS", "api.example.com *.example.com", 1);
    AcmeLineageImportRequest import = {};
    suite.expect(prodigyBuildACMELineageImportRequestFromEnv(import, &failure), "acme_import_hook_request_parses_env");
    suite.expect(import.clusterUUID == config.clusterUUID && import.renewedDomains.size() == 2 && import.renewedDomains[0].equal("api.example.com"_ctv) && import.renewedDomains[1].equal("*.example.com"_ctv), "acme_import_hook_request_splits_domains");
    setenv("PRODIGY_CLUSTER_UUID", "0", 1);
    suite.expect(prodigyBuildACMEDNS01ChallengeRequestFromEnv(challenge, &failure) == false && failure.equal("invalid environment variable PRODIGY_CLUSTER_UUID"_ctv), "acme_dns01_hook_request_rejects_zero_cluster_uuid");
    setenv("PRODIGY_CLUSTER_UUID", clusterText.c_str(), 1);

    TemporaryDirectory hookTemp;
    suite.expect(hookTemp.create(), "acme_hook_wrapper_temp_created");
    std::filesystem::path fakeMothership = filesystemPathFromString(hookTemp.path) / "mothership";
    suite.expect(writeFileFixture(fakeMothership, "#!/bin/sh\nfor arg in \"$@\"; do printf '%s\\n' \"$arg\"; done > \"$PRODIGY_ACME_HOOK_CAPTURE\"\n") && makeFileExecutableFixture(fakeMothership), "acme_hook_wrapper_fake_mothership_ready");
    auto hookDelegates = [&](const char *name, const char *operation, const char *target) -> bool {
      std::filesystem::path hook = std::filesystem::path(PRODIGY_ACME_HOOKS_DIR) / name;
      if (std::filesystem::exists(hook) == false ||
          (std::filesystem::status(hook).permissions() & std::filesystem::perms::owner_exec) == std::filesystem::perms::none)
      {
        return false;
      }
      std::filesystem::path capture = filesystemPathFromString(hookTemp.path) / name;
      Vector<String> argv = {};
      argv.push_back(stringFromFilesystemPath(hook));
      Vector<String> env = {};
      String mothershipEnv = {};
      mothershipEnv.assign("PRODIGY_MOTHERSHIP="_ctv);
      mothershipEnv.append(stringFromFilesystemPath(fakeMothership));
      env.push_back(std::move(mothershipEnv));
      String captureEnv = {};
      captureEnv.assign("PRODIGY_ACME_HOOK_CAPTURE="_ctv);
      captureEnv.append(stringFromFilesystemPath(capture));
      env.push_back(std::move(captureEnv));
      if (target != nullptr)
      {
        String targetEnv = {};
        targetEnv.assign("PRODIGY_ACME_TARGET="_ctv);
        targetEnv.append(target);
        env.push_back(std::move(targetEnv));
      }
      int status = -1;
      String runFailure = {};
      String output = {};
      String expected = {};
      expected.assign(operation);
      expected.append("\n"_ctv);
      if (target != nullptr)
      {
        expected.append(target);
        expected.append("\n"_ctv);
      }
      return prodigyRunBlockingArgv(argv, env, &status, &runFailure) && status == 0 && readFileFixture(capture, output) && output.equals(expected);
    };
    suite.expect(hookDelegates("acme-present-dns-01", "acme-present-dns-01", nullptr), "acme_present_hook_wrapper_delegates");
    suite.expect(hookDelegates("acme-cleanup-dns-01", "acme-cleanup-dns-01", "local"), "acme_cleanup_hook_wrapper_delegates_target");
    suite.expect(hookDelegates("acme-import-lineage", "acme-import-lineage", "local"), "acme_import_hook_wrapper_delegates_target");
    String presentHook = {};
    String cleanupHook = {};
    suite.expect(readFileFixture(std::filesystem::path(PRODIGY_ACME_HOOKS_DIR) / "acme-present-dns-01", presentHook) && stringContains(presentHook, ">&2"), "acme_present_hook_keeps_certbot_auth_output_quiet");
    suite.expect(readFileFixture(std::filesystem::path(PRODIGY_ACME_HOOKS_DIR) / "acme-cleanup-dns-01", cleanupHook) && stringContains(cleanupHook, ">&2"), "acme_cleanup_hook_keeps_stdout_quiet");

    unsetenv("PRODIGY_ACME_APPLICATION_ID");
    unsetenv("PRODIGY_ACME_DEPLOYMENT_ID");
    unsetenv("PRODIGY_ACME_WORMHOLE_NAME");
    unsetenv("PRODIGY_ACME_CERT_NAME");
    unsetenv("PRODIGY_CLUSTER_UUID");
    unsetenv("CERTBOT_IDENTIFIER");
    unsetenv("CERTBOT_VALIDATION");
    unsetenv("RENEWED_LINEAGE");
    unsetenv("RENEWED_DOMAINS");

    cert.certbotCertName = "../bad"_ctv;
    suite.expect(prodigyBuildCertbotCertonlyCommand(config, cert, {}, command, &failure) == false, "certbot_certonly_command_rejects_unsafe_cert_name");
    suite.expect(failure.equal("public TLS cert name must be a safe path segment"_ctv), "certbot_certonly_command_unsafe_cert_name_failure");
    cert.certbotCertName = "app7-api"_ctv;

    config.acme.termsAgreed = false;
    suite.expect(prodigyBuildCertbotCertonlyCommand(config, cert, {}, command, &failure) == false, "certbot_certonly_command_requires_terms");
    suite.expect(failure.equal("ACME accountEmail and termsAgreed are required"_ctv), "certbot_certonly_command_terms_failure");
  }

  {
    ApplicationDeployment deployment {};
    seedCommonPlan(deployment, true);
    deployment.nShardGroups = 3;

    deployment.armStatefulWorkerTopologyUpgrade(2, 4, 4, 512, 64);

    suite.expect(deployment.statefulWorkerTopologyUpgradePendingForAnyShardGroup(), "stateful_worker_topology_upgrade_marks_pending");
    suite.expect(deployment.statefulWorkerTopologyUpgradePhase == ApplicationDeployment::StatefulWorkerTopologyUpgradePhase::greenBootstrap, "stateful_worker_topology_upgrade_enters_green_bootstrap_phase");
    suite.expect(deployment.statefulWorkerTopologyUpgradeOperationID != 0, "stateful_worker_topology_upgrade_assigns_operation_id");
    suite.expect(deployment.statefulWorkerTopologyUpgradeSourceWorkerCount == 2, "stateful_worker_topology_upgrade_preserves_source_worker_count");
    suite.expect(deployment.statefulWorkerTopologyUpgradeTargetWorkerCount == 4, "stateful_worker_topology_upgrade_preserves_target_worker_count");
    suite.expect(deployment.statefulWorkerTopologyUpgradeSourceEpoch == 2, "stateful_worker_topology_upgrade_preserves_source_epoch");
    suite.expect(deployment.statefulWorkerTopologyUpgradeTargetEpoch != 0 && deployment.statefulWorkerTopologyUpgradeTargetEpoch != deployment.statefulWorkerTopologyUpgradeSourceEpoch, "stateful_worker_topology_upgrade_assigns_distinct_target_epoch");
    suite.expect(deployment.statefulWorkerTopologyUpgradeLocksShardGroup(0), "stateful_worker_topology_upgrade_locks_group_0");
    suite.expect(deployment.statefulWorkerTopologyUpgradeLocksShardGroup(1), "stateful_worker_topology_upgrade_locks_group_1");
    suite.expect(deployment.statefulWorkerTopologyUpgradeLocksShardGroup(2), "stateful_worker_topology_upgrade_locks_group_2");
    suite.expect(deployment.statefulWorkerTopologyUpgradeLocksShardGroup(3) == false, "stateful_worker_topology_upgrade_does_not_lock_out_of_range_group");
    suite.expect(deployment.desiredReplicaCountForShardGroup(0) == 6, "stateful_worker_topology_upgrade_doubles_desired_replicas_per_group");
    suite.expect(deployment.maxReplicasPerRackForShardGroup(0) == 2, "stateful_worker_topology_upgrade_allows_second_replica_per_rack");
  }

  {
    ApplicationDeployment deployment {};
    seedCommonPlan(deployment, true);
    deployment.plan.config.nLogicalCores = 3;
    deployment.nShardGroups = 1;

    deployment.armStatefulWorkerTopologyUpgrade(1, 1, 2, 512, 64);

    ContainerView target = {};
    target.isStateful = true;
    target.shardGroup = 0;
    target.explicitStatefulTopology.topologyEpoch = deployment.statefulWorkerTopologyUpgradeTargetEpoch;

    ApplicationConfig targetConfig = deployment.statefulWorkerTopologyUpgradeTargetConfig();

    suite.expect(deployment.statefulWorkerTopologyUpgradeSourceWorkerCount == 1, "stateful_worker_topology_upgrade_same_worker_count_preserves_source_worker_count");
    suite.expect(deployment.statefulWorkerTopologyUpgradeTargetWorkerCount == 1, "stateful_worker_topology_upgrade_same_worker_count_preserves_target_worker_count");
    suite.expect(deployment.statefulWorkerTopologyUpgradeTargetEpoch != deployment.statefulWorkerTopologyUpgradeSourceEpoch, "stateful_worker_topology_upgrade_same_worker_count_assigns_distinct_epoch");
    suite.expect(targetConfig.nLogicalCores == 2, "stateful_worker_topology_upgrade_same_worker_count_uses_target_core_count");
    suite.expect(deployment.resourceConfigForContainer(&target).nLogicalCores == 2, "stateful_worker_topology_upgrade_same_worker_count_applies_target_cores_to_green");
  }

  {
    BrainBase *savedBrain = thisBrain;
    thisBrain = nullptr;

    ApplicationDeployment deployment {};
    seedCommonPlan(deployment, true);
    deployment.plan.config.nLogicalCores = 3;
    deployment.nShardGroups = 1;

    const uint32_t currentServingEpoch = 987'654'321;
    ContainerView servingA = {};
    ContainerView servingB = {};
    ContainerView servingC = {};
    ContainerView *serving[] = {&servingA, &servingB, &servingC};
    for (ContainerView *container : serving)
    {
      container->isStateful = true;
      container->shardGroup = 0;
      container->state = ContainerState::healthy;
      container->explicitStatefulTopology.shardGroup = 0;
      container->explicitStatefulTopology.topologyEpoch = currentServingEpoch;
      container->explicitStatefulTopology.workerCount = 1;
      container->explicitStatefulTopology.servingMode = StatefulTopologyServingMode::serve;
      container->explicitStatefulTopology.sourceEpoch = currentServingEpoch;
      container->explicitStatefulTopology.targetEpoch = currentServingEpoch;
      deployment.containers.insert(container);
      deployment.containersByShardGroup.insert(0, container);
    }

    deployment.armStatefulWorkerTopologyUpgrade(1, 3, 5, 512, 64);

    suite.expect(deployment.statefulWorkerTopologyUpgradeSourceEpoch == currentServingEpoch, "stateful_worker_topology_upgrade_reuses_current_serving_epoch_for_repeated_raise");
    suite.expect(deployment.statefulWorkerTopologyUpgradeTargetEpoch != currentServingEpoch, "stateful_worker_topology_upgrade_repeated_raise_assigns_distinct_target_epoch");
    suite.expect(servingA.explicitStatefulTopology.sourceEpoch == currentServingEpoch, "stateful_worker_topology_upgrade_repeated_raise_preserves_source_epoch_on_blue");
    suite.expect(servingA.explicitStatefulTopology.targetEpoch == deployment.statefulWorkerTopologyUpgradeTargetEpoch, "stateful_worker_topology_upgrade_repeated_raise_sets_next_target_epoch_on_blue");

    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment {};
    seedCommonPlan(deployment, true);
    deployment.nShardGroups = 2;

    deployment.armStatefulWorkerTopologyUpgrade(2, 4, 4, 512, 64);

    suite.expect(brain.statefulWorkerTopologyUpgradeRuntimeState.size() == 1, "stateful_worker_topology_upgrade_persists_runtime_state_record");
    suite.expect(
        brain.statefulWorkerTopologyUpgradeRuntimeState.size() == 1 && brain.statefulWorkerTopologyUpgradeRuntimeState[0].deploymentID == deployment.plan.config.deploymentID(),
        "stateful_worker_topology_upgrade_persists_runtime_state_deployment_id");
    suite.expect(
        brain.statefulWorkerTopologyUpgradeRuntimeState.size() == 1 && brain.statefulWorkerTopologyUpgradeRuntimeState[0].phase == StatefulWorkerTopologyUpgradePhase::greenBootstrap,
        "stateful_worker_topology_upgrade_persists_runtime_state_phase");
    suite.expect(
        brain.statefulWorkerTopologyUpgradeRuntimeState.size() == 1 && brain.statefulWorkerTopologyUpgradeRuntimeState[0].lockedShardGroups.size() == 2,
        "stateful_worker_topology_upgrade_persists_runtime_state_locked_groups");
    suite.expect(
        brain.statefulWorkerTopologyUpgradeRuntimeState.size() == 1 && brain.statefulWorkerTopologyUpgradeRuntimeState[0].targetLogicalCores == 4,
        "stateful_worker_topology_upgrade_persists_runtime_state_target_cores");

    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;
    brain.brainConfig.runtimeEnvironment.test.enabled = true;
    brain.brainConfig.architecture = nametagCurrentBuildMachineArchitecture();

    Rack rack {};
    rack.uuid = 19'603'101;
    brain.racks.insert_or_assign(rack.uuid, &rack);

    Machine pinned {};
    pinned.uuid = uint128_t(0x19603101);
    pinned.slug = "single-prefix-unavailable-host"_ctv;
    pinned.rack = &rack;
    pinned.state = MachineState::neuronRebooting;
    pinned.lifetime = MachineLifetime::owned;
    pinned.hardware.inventoryComplete = true;
    pinned.hardware.cpu.architecture = nametagCurrentBuildMachineArchitecture();
    pinned.hardware.cpu.logicalCores = pinned.ownedLogicalCores = pinned.totalLogicalCores = pinned.nLogicalCores_available = 8;
    pinned.hardware.memory.totalMB = pinned.ownedMemoryMB = pinned.totalMemoryMB = pinned.memoryMB_available = 8192;
    pinned.ownedStorageMB = pinned.totalStorageMB = pinned.storageMB_available = 4096;
    rack.machines.insert(&pinned);
    brain.machines.insert(&pinned);

    DistributableExternalSubnet registered = {};
    registered.uuid = uint128_t(0x19603102);
    registered.name = "single-prefix-unavailable-route"_ctv;
    registered.machineUUID = pinned.uuid;
    registered.ingressScope = RoutableIngressScope::singleMachine;
    registered.usage = ExternalSubnetUsage::wormholes;
    registered.subnet = IPPrefix("2001:db8:196::2", true, 128);
    brain.brainConfig.distributableExternalSubnets.push_back(registered);

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.applicationID = 19'631;
    deployment.plan.config.versionID = 1;
    deployment.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
    deployment.plan.config.nLogicalCores = 1;
    deployment.plan.stateless.nBase = 1;

    Wormhole wormhole = {};
    wormhole.externalPort = 443;
    wormhole.containerPort = 8443;
    wormhole.layer4 = IPPROTO_UDP;
    wormhole.isQuic = true;
    wormhole.source = ExternalAddressSource::registeredRoutablePrefix;
    wormhole.routablePrefixUUID = registered.uuid;
    deployment.plan.wormholes.push_back(wormhole);
    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

    deployment.deploy();

    suite.expect(brain.requestMachinesCount == 0, "deploy_single_machine_prefix_unavailable_host_does_not_request_new_machine");
    suite.expect(deployment.state == DeploymentState::deploying, "deploy_single_machine_prefix_unavailable_host_stays_deploying");
    suite.expect(deployment.nDeployedBase == 0, "deploy_single_machine_prefix_unavailable_host_deploys_zero");
    suite.expect(deployment.toSchedule.empty(), "deploy_single_machine_prefix_unavailable_host_has_no_schedule");
    suite.expect(deployment.waitingOnContainers.empty(), "deploy_single_machine_prefix_unavailable_host_has_no_waiters");
    suite.expect(brain.finCount == 0, "deploy_single_machine_prefix_unavailable_host_does_not_finish_spin");

    brain.deployments.erase(deployment.plan.config.deploymentID());
    rack.machines.erase(&pinned);
    brain.machines.erase(&pinned);
    brain.racks.erase(rack.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;
    brain.brainConfig.runtimeEnvironment.test.enabled = true;
    brain.brainConfig.architecture = nametagCurrentBuildMachineArchitecture();

    Rack rack = {};
    rack.uuid = 0x19602041;
    brain.racks.insert_or_assign(rack.uuid, &rack);

    ScopedSocketPair socket = {};
    bool socketReady = socket.create(suite, "recoverAfterReboot_pending_plan_no_capacity_fixture_socketpair");

    Machine machine = {};
    machine.uuid = uint128_t(0x19602042);
    machine.slug = "recover-pending-plan-no-capacity"_ctv;
    machine.rack = &rack;
    machine.state = MachineState::healthy;
    machine.lifetime = MachineLifetime::owned;
    machine.hardware.cpu.architecture = nametagCurrentBuildMachineArchitecture();
    bool machineReady = socketReady && armNeuronControlStream(machine, socket);
    rack.machines.insert(&machine);
    brain.machines.insert(&machine);

    suite.expect(machineReady, "recoverAfterReboot_pending_plan_no_capacity_fixture_machine_ready");

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.type = ApplicationType::stateless;
    deployment.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
    deployment.plan.stateless.nBase = 1;
    deployment.state = DeploymentState::none;
    deployment.nTargetBase = 1;
    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

    if (machineReady)
    {
      deployment.recoverAfterReboot();

      suite.expect(deployment.nDeployed() == 0, "recoverAfterReboot_pending_plan_no_capacity_does_not_schedule");
      suite.expect(deployment.state == DeploymentState::none, "recoverAfterReboot_pending_plan_no_capacity_restores_pending_state");
      suite.expect(deployment.nSuspended == 0, "recoverAfterReboot_pending_plan_no_capacity_does_not_suspend");
      suite.expect(deployment.schedulingStack.execution == nullptr, "recoverAfterReboot_pending_plan_no_capacity_has_no_scheduler");
      suite.expect(machine.neuron.pendingSend == false, "recoverAfterReboot_pending_plan_no_capacity_queues_no_neuron_work");
    }

    brain.deployments.erase(deployment.plan.config.deploymentID());
    rack.machines.erase(&machine);
    brain.machines.erase(&machine);
    brain.racks.erase(rack.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;
    brain.brainConfig.runtimeEnvironment.test.enabled = true;
    brain.brainConfig.architecture = nametagCurrentBuildMachineArchitecture();

    Rack rack = {};
    rack.uuid = 0x19602031;
    brain.racks.insert_or_assign(rack.uuid, &rack);

    ScopedSocketPair socket = {};
    bool socketReady = socket.create(suite, "recoverAfterReboot_pending_plan_fixture_socketpair");

    Machine machine = {};
    machine.uuid = uint128_t(0x19602032);
    machine.slug = "recover-pending-plan-target"_ctv;
    machine.rack = &rack;
    machine.state = MachineState::healthy;
    machine.lifetime = MachineLifetime::owned;
    machine.hardware.cpu.architecture = nametagCurrentBuildMachineArchitecture();
    machine.nLogicalCores_available = 8;
    machine.memoryMB_available = 8192;
    machine.storageMB_available = 4096;
    bool machineReady = socketReady && armNeuronControlStream(machine, socket);
    rack.machines.insert(&machine);
    brain.machines.insert(&machine);

    suite.expect(machineReady, "recoverAfterReboot_pending_plan_fixture_machine_ready");

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.type = ApplicationType::stateless;
    deployment.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
    deployment.plan.stateless.nBase = 1;
    deployment.plan.canaryCount = 0;
    deployment.plan.canariesMustLiveForMinutes = 0;
    deployment.plan.moveConstructively = true;
    deployment.plan.useHostNetworkNamespace = false;
    deployment.plan.requiresDatacenterUniqueTag = false;
    deployment.state = DeploymentState::none;
    deployment.nTargetBase = 1;
    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

    if (machineReady)
    {
      deployment.recoverAfterReboot();

      suite.expect(deployment.state == DeploymentState::deploying, "recoverAfterReboot_pending_plan_schedules_underprovisioned");
      suite.expect(deployment.nDeployedBase == 1, "recoverAfterReboot_pending_plan_deploys_missing_base");
      suite.expect(deployment.waitingOnContainers.size() == 1, "recoverAfterReboot_pending_plan_waits_for_construct_health");
      suite.expect(deployment.schedulingStack.execution != nullptr, "recoverAfterReboot_pending_plan_starts_scheduler");
      suite.expect(machine.neuron.pendingSend && machine.neuron.wBuffer.size() > 0, "recoverAfterReboot_pending_plan_queues_neuron_spin");

      if (deployment.containers.empty() == false)
      {
        ContainerView *container = *deployment.containers.begin();
        deployment.destructContainer(container);
        deployment.containerDestroyed(container);
      }
    }

    brain.deployments.erase(deployment.plan.config.deploymentID());
    rack.machines.erase(&machine);
    brain.machines.erase(&machine);
    brain.racks.erase(rack.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;
    brain.brainConfig.runtimeEnvironment.test.enabled = true;
    brain.brainConfig.architecture = nametagCurrentBuildMachineArchitecture();

    ApplicationDeployment deployment {};
    seedCommonPlan(deployment, true);
    deployment.nShardGroups = 1;
    deployment.recomputeStatefulBaseTargetFromShardGroups();

    HorizontalScaler scaler = {};
    scaler.name.assign(ProdigyMetrics::runtimeContainerCpuUtilPctName);
    scaler.percentile = 95.0;
    scaler.lookbackSeconds = 60;
    scaler.threshold = 0.50;
    scaler.direction = Scaler::Direction::upscale;
    scaler.lifetime = ApplicationLifetime::base;
    deployment.plan.horizontalScalers.push_back(scaler);

    ProdigyStatefulWorkerTopologyUpgradeOperation operation = {};
    operation.deploymentID = deployment.plan.config.deploymentID();
    operation.applicationID = deployment.plan.config.applicationID;
    operation.operationID = 0x19072012ull;
    operation.phase = StatefulWorkerTopologyUpgradePhase::greenBootstrap;
    operation.sourceWorkerCount = 1;
    operation.targetWorkerCount = 2;
    operation.sourceEpoch = 1;
    operation.targetEpoch = 400;
    operation.targetLogicalCores = 4;
    operation.targetMemoryMB = 768;
    operation.targetStorageMB = 96;
    operation.lockedShardGroups.push_back(0);
    suite.expect(deployment.restoreStatefulWorkerTopologyUpgradeOperation(operation), "stateful_autoscale_shard_growth_during_topology_upgrade_restores_active_topology_upgrade_fixture");

    const int64_t nowMs = Time::now<TimeResolution::ms>();
    brain.metrics.record(
        deployment.plan.config.deploymentID(),
        uint128_t(0x19072010),
        ProdigyMetrics::runtimeContainerCpuUtilPctKey(),
        nowMs,
        0.95);

    TimeoutPacket autoscalePacket = {};
    autoscalePacket.flags = uint64_t(DeploymentTimeoutFlags::autoscale);
    deployment.dispatchTimeout(&autoscalePacket);

    suite.expect(deployment.deferredStatefulTargetShardGroups == 2, "stateful_autoscale_shard_growth_during_topology_upgrade_defers_target_group_count");
    suite.expect(deployment.nShardGroups == 1, "stateful_autoscale_shard_growth_during_topology_upgrade_keeps_live_group_count");
    suite.expect(deployment.nTargetBase == 3, "stateful_autoscale_shard_growth_during_topology_upgrade_keeps_live_target_base");
    suite.expect(
        brain.deferredStatefulScaleIntentRuntimeState.size() == 1 && brain.deferredStatefulScaleIntentRuntimeState[0].targetShardGroups == 2,
        "stateful_autoscale_shard_growth_during_topology_upgrade_persists_deferred_growth_intent");

    deployment.clearStatefulWorkerTopologyUpgradeOperation();
    ProdigyDeferredStatefulScaleIntent deferredIntent = {};
    bool capturedIntent = deployment.captureDeferredStatefulScaleIntent(deferredIntent);
    suite.expect(capturedIntent, "stateful_autoscale_shard_growth_during_topology_upgrade_keeps_deferred_growth_after_unlock");
    suite.expect(deferredIntent.targetShardGroups == 2, "stateful_autoscale_shard_growth_during_topology_upgrade_preserves_target_group_count_after_unlock");
    suite.expect(brain.statefulWorkerTopologyUpgradeRuntimeState.empty(), "stateful_autoscale_shard_growth_during_topology_upgrade_clears_topology_runtime_state_after_unlock");

    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Whitehole existing = {};
    existing.transport = ExternalAddressTransport::tcp;
    existing.family = ExternalAddressFamily::ipv4;
    existing.hasAddress = true;
    existing.address = IPAddress("198.18.1.9", false);
    existing.sourcePort = 49'152;

    ContainerView owner {};
    owner.uuid = uint128_t(0x2001);
    owner.whiteholes.push_back(existing);
    brain.containers.insert_or_assign(owner.uuid, &owner);

    suite.expect(ApplicationDeployment::whiteholeAddressPortAlreadyInUse(existing.address, existing.sourcePort),
                 "whitehole_ip_port_conflict_is_cluster_wide_and_transport_independent");
    suite.expect(ApplicationDeployment::whiteholeAddressPortAlreadyInUse(existing.address, uint16_t(existing.sourcePort + 1)) == false,
                 "whitehole_same_ip_different_port_is_available");
    suite.expect(ApplicationDeployment::whiteholeAddressPortAlreadyInUse(IPAddress("198.18.1.10", false), existing.sourcePort) == false,
                 "whitehole_same_port_different_ip_is_available");

    Whitehole candidate = existing;
    candidate.transport = ExternalAddressTransport::quic;
    candidate.sourcePort = 0;
    candidate.bindingNonce = 0;

    suite.expect(ApplicationDeployment::allocateWhiteholeSourcePort(candidate),
                 "whitehole_source_port_allocator_skips_cluster_wide_ip_port_conflict");
    suite.expect(candidate.sourcePort == uint16_t(existing.sourcePort + 1),
                 "whitehole_source_port_allocator_reuses_ip_with_next_free_port");

    brain.containers.clear();

    RoutableResourceLeaseOwner leasedOwner = {};
    leasedOwner.applicationID = 7805;
    leasedOwner.deploymentID = (uint64_t(leasedOwner.applicationID) << 48) | 1;
    leasedOwner.lineageID = leasedOwner.applicationID;
    RoutableResourceLease leasedPort = {};
    leasedPort.kind = RoutableResourceLeaseKind::whiteholeAddressPort;
    leasedPort.owner = leasedOwner;
    leasedPort.address = existing.address;
    leasedPort.sourcePort = existing.sourcePort;
    brain.routableResourceLeaseRuntimeState.push_back(leasedPort);

    ApplicationDeployment leaseDeployment {};
    seedCommonPlan(leaseDeployment, false);
    leaseDeployment.plan.config.applicationID = 7806;
    leaseDeployment.plan.config.versionID = 1;
    RoutableResourceLeaseOwner leaseOwner = leaseDeployment.routableResourceLeaseOwner();
    RoutableResourceLeaseOwner transferOwner = leasedOwner;
    transferOwner.deploymentID += 1;

    suite.expect(ApplicationDeployment::whiteholeAddressPortAlreadyInUse(existing.address, existing.sourcePort),
                 "whitehole_ip_port_conflict_uses_runtime_lease_without_owner");
    suite.expect(ApplicationDeployment::whiteholeAddressPortAlreadyInUse(existing.address, existing.sourcePort, &leaseOwner),
                 "whitehole_ip_port_conflict_uses_runtime_lease_for_other_owner");
    suite.expect(ApplicationDeployment::whiteholeAddressPortAlreadyInUse(existing.address, existing.sourcePort, &transferOwner) == false,
                 "whitehole_ip_port_lease_allows_same_lineage_transfer");
    suite.expect(leaseDeployment.reserveWhiteholeAddressPortLease(existing, leaseOwner) == false,
                 "whitehole_ip_port_reserve_rejects_leased_tuple_for_other_owner");

    candidate.sourcePort = 0;
    suite.expect(ApplicationDeployment::allocateWhiteholeSourcePort(candidate),
                 "whitehole_source_port_allocator_skips_runtime_lease_conflict");
    suite.expect(candidate.sourcePort == uint16_t(existing.sourcePort + 1),
                 "whitehole_source_port_allocator_reuses_ip_after_leased_port");
    suite.expect(leaseDeployment.reserveWhiteholeAddressPortLease(candidate, leaseOwner),
                 "whitehole_ip_port_reserve_records_runtime_lease");
    suite.expect(brain.routableResourceLeaseRuntimeState.size() == 2,
                 "whitehole_ip_port_reserve_appends_one_runtime_lease");
    suite.expect(leaseDeployment.reserveWhiteholeAddressPortLease(candidate, leaseOwner) && brain.routableResourceLeaseRuntimeState.size() == 2,
                 "whitehole_ip_port_reserve_is_idempotent");
    suite.expect(leaseDeployment.releaseWhiteholeAddressPortLease(candidate, leaseOwner),
                 "whitehole_ip_port_release_removes_runtime_lease");
    suite.expect(brain.routableResourceLeaseRuntimeState.size() == 1,
                 "whitehole_ip_port_release_keeps_unrelated_lease");
    suite.expect(leaseDeployment.reserveWhiteholeAddressPortLease(candidate, leaseOwner),
                 "whitehole_ip_port_release_allows_reclaim");

    ContainerView *destroyed = new ContainerView();
    destroyed->uuid = uint128_t(0x2002);
    destroyed->applicationID = leaseDeployment.plan.config.applicationID;
    destroyed->deploymentID = leaseDeployment.plan.config.deploymentID();
    destroyed->state = ContainerState::destroying;
    destroyed->whiteholes.push_back(candidate);
    brain.containers.insert_or_assign(destroyed->uuid, destroyed);
    leaseDeployment.containerDestroyed(destroyed);
    suite.expect(brain.containers.contains(uint128_t(0x2002)) == false,
                 "whitehole_container_destroyed_erases_brain_container_index");
    suite.expect(brain.routableResourceLeaseRuntimeState.size() == 1,
                 "whitehole_container_destroyed_releases_lease");

    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment {};
    seedCommonPlan(deployment, true);
    deployment.nShardGroups = 1;
    deployment.recomputeStatefulBaseTargetFromShardGroups();
    deployment.deployingNewShardGroup = true;

    VerticalScaler scaler = {};
    scaler.name.assign(ProdigyMetrics::runtimeContainerCpuUtilPctName);
    scaler.percentile = 95.0;
    scaler.lookbackSeconds = 60;
    scaler.threshold = 0.50;
    scaler.direction = Scaler::Direction::upscale;
    scaler.resource = ScalingDimension::cpu;
    scaler.increment = 2;
    deployment.plan.verticalScalers.push_back(scaler);

    const int64_t nowMs = Time::now<TimeResolution::ms>();
    brain.metrics.record(
        deployment.plan.config.deploymentID(),
        uint128_t(0x19072011),
        ProdigyMetrics::runtimeContainerCpuUtilPctKey(),
        nowMs,
        0.99);

    TimeoutPacket autoscalePacket = {};
    autoscalePacket.flags = uint64_t(DeploymentTimeoutFlags::autoscale);
    deployment.dispatchTimeout(&autoscalePacket);

    suite.expect(deployment.statefulWorkerTopologyUpgradePendingForAnyShardGroup() == false, "stateful_autoscale_topology_upgrade_during_shard_growth_does_not_start_live_upgrade");
    suite.expect(deployment.deferredStatefulTargetLogicalCores == 4, "stateful_autoscale_topology_upgrade_during_shard_growth_defers_target_cores");
    suite.expect(
        brain.deferredStatefulScaleIntentRuntimeState.size() == 1 && brain.deferredStatefulScaleIntentRuntimeState[0].targetLogicalCores == 4,
        "stateful_autoscale_topology_upgrade_during_shard_growth_persists_deferred_topology_intent");

    thisBrain = nullptr;
    deployment.deployingNewShardGroup = false;
    bool dispatched = deployment.dispatchDeferredStatefulScaleIntent();

    suite.expect(dispatched, "stateful_autoscale_topology_upgrade_during_shard_growth_dispatches_after_unlock");
    suite.expect(deployment.statefulWorkerTopologyUpgradePendingForAnyShardGroup(), "stateful_autoscale_topology_upgrade_during_shard_growth_arms_topology_upgrade_after_unlock");
    suite.expect(deployment.statefulWorkerTopologyUpgradeTargetLogicalCores == 4, "stateful_autoscale_topology_upgrade_during_shard_growth_applies_deferred_target_cores");

    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment {};
    seedCommonPlan(deployment, true);
    deployment.nShardGroups = 1;
    deployment.recomputeStatefulBaseTargetFromShardGroups();

    ProdigyDeferredStatefulScaleIntent intent = {};
    intent.deploymentID = deployment.plan.config.deploymentID();
    intent.applicationID = deployment.plan.config.applicationID;
    intent.targetShardGroups = 3;
    intent.targetLogicalCores = 4;
    intent.targetMemoryMB = 768;
    intent.targetStorageMB = 96;
    intent.updatedAtMs = 123'456'789;
    brain.deferredStatefulScaleIntentRuntimeState.push_back(intent);

    bool restored = deployment.restorePersistedDeferredStatefulScaleIntent();
    thisBrain = nullptr;
    bool dispatchedTopology = deployment.dispatchDeferredStatefulScaleIntent();

    suite.expect(restored, "stateful_deferred_scale_intent_restore_recovers_persisted_intent");
    suite.expect(dispatchedTopology, "stateful_deferred_scale_intent_restore_dispatches_topology_first");
    suite.expect(deployment.statefulWorkerTopologyUpgradePendingForAnyShardGroup(), "stateful_deferred_scale_intent_restore_arms_topology_upgrade_first");
    suite.expect(deployment.nShardGroups == 1, "stateful_deferred_scale_intent_restore_defers_shard_growth_until_after_topology_upgrade");

    deployment.clearStatefulWorkerTopologyUpgradeOperation();
    deployment.plan.config.nLogicalCores = 4;
    deployment.plan.config.memoryMB = 768;
    deployment.plan.config.storageMB = 96;
    ProdigyDeferredStatefulScaleIntent restoredIntent = {};
    bool capturedIntent = deployment.captureDeferredStatefulScaleIntent(restoredIntent);
    suite.expect(capturedIntent, "stateful_deferred_scale_intent_restore_keeps_pending_growth_after_topology_completion");
    suite.expect(restoredIntent.targetShardGroups == 3, "stateful_deferred_scale_intent_restore_preserves_target_group_count_after_topology_completion");
    suite.expect(restoredIntent.targetLogicalCores == 4, "stateful_deferred_scale_intent_restore_preserves_target_cores_after_topology_completion");
    suite.expect(brain.deferredStatefulScaleIntentRuntimeState.size() == 1, "stateful_deferred_scale_intent_restore_keeps_persisted_intent_after_topology_completion");

    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment {};
    seedCommonPlan(deployment, true);
    deployment.nShardGroups = 2;

    deployment.armStatefulWorkerTopologyUpgrade(2, 4, 4, 512, 64);
    deployment.clearStatefulWorkerTopologyUpgradeOperation();

    suite.expect(deployment.statefulWorkerTopologyUpgradePendingForAnyShardGroup() == false, "stateful_worker_topology_upgrade_clear_resets_pending_state");
    suite.expect(brain.statefulWorkerTopologyUpgradeRuntimeState.empty(), "stateful_worker_topology_upgrade_clear_removes_runtime_state_record");

    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rack {};
    rack.uuid = 19'071'001;
    brain.racks.insert_or_assign(rack.uuid, &rack);

    Machine machine {};
    machine.uuid = uint128_t(0x19071001);
    machine.slug = "topology-green"_ctv;
    machine.rack = &rack;
    machine.state = MachineState::healthy;
    machine.lifetime = MachineLifetime::owned;
    rack.machines.insert(&machine);
    brain.machines.insert(&machine);

    ApplicationDeployment deployment {};
    seedCommonPlan(deployment, true);
    deployment.nShardGroups = 1;
    deployment.armStatefulWorkerTopologyUpgrade(2, 4, 4, 512, 64);

    DeploymentWork *work = deployment.planStatefulConstruction(&machine, uint32_t(0), DataStrategy::seeding);
    StatefulWork *stateful = std::get_if<StatefulWork>(work);
    ContainerView *container = stateful ? stateful->container : nullptr;
    StatefulMeshRoles roles = container ? container->effectiveStatefulMeshRoles(deployment.plan) : StatefulMeshRoles {};
    StatefulTopology topology = container ? container->effectiveStatefulTopology(deployment.plan) : StatefulTopology {};
    ApplicationConfig containerConfig = container ? deployment.resourceConfigForContainer(container) : ApplicationConfig {};

    suite.expect(container != nullptr, "stateful_worker_topology_upgrade_green_construction_creates_container");
    suite.expect(containerConfig.nLogicalCores == 4, "stateful_worker_topology_upgrade_green_construction_uses_target_boot_cores");
    suite.expect(topology.operationID == deployment.statefulWorkerTopologyUpgradeOperationID, "stateful_worker_topology_upgrade_green_construction_sets_operation_id");
    suite.expect(topology.workerCount == 4, "stateful_worker_topology_upgrade_green_construction_sets_target_worker_count");
    suite.expect(topology.servingMode == StatefulTopologyServingMode::catchupOnly, "stateful_worker_topology_upgrade_green_construction_sets_catchup_only");
    suite.expect(topology.bridgeMode == StatefulTopologyBridgeMode::sourceToTarget, "stateful_worker_topology_upgrade_green_construction_sets_source_to_target_bridge");
    suite.expect(topology.topologyEpoch == deployment.statefulWorkerTopologyUpgradeTargetEpoch, "stateful_worker_topology_upgrade_green_construction_sets_target_epoch");
    suite.expect(roles.topologyBridge != 0, "stateful_worker_topology_upgrade_green_construction_derives_bridge_role");

    if (container)
    {
      deployment.cancelDeploymentWork(container->plannedWork);
      deployment.containers.erase(container);
      while (deployment.containersByShardGroup.eraseEntry(container->shardGroup, container))
      {
      }
      machine.removeContainerIndexEntry(container->deploymentID, container);
      brain.containers.erase(container->uuid);
      delete container;
    }

    rack.machines.erase(&machine);
    brain.machines.erase(&machine);
    brain.racks.erase(rack.uuid);
    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rackA {};
    rackA.uuid = 19'013'101;
    Rack rackB {};
    rackB.uuid = 19'013'102;
    Rack rackC {};
    rackC.uuid = 19'013'103;
    brain.racks.insert_or_assign(rackA.uuid, &rackA);
    brain.racks.insert_or_assign(rackB.uuid, &rackB);
    brain.racks.insert_or_assign(rackC.uuid, &rackC);

    auto seedMachine = [&](Machine& machine, Rack& rack, uint128_t uuid, const String& slug) -> void {
      machine.uuid = uuid;
      machine.slug = slug;
      machine.rack = &rack;
      machine.state = MachineState::healthy;
      machine.lifetime = MachineLifetime::owned;
      machine.ownedLogicalCores = 8;
      machine.ownedMemoryMB = 8192;
      machine.ownedStorageMB = 4096;
      machine.totalLogicalCores = 8;
      machine.totalMemoryMB = 8192;
      machine.totalStorageMB = 4096;
      machine.isolatedLogicalCoresCommitted = 4;
      machine.nLogicalCores_available = 4;
      machine.memoryMB_available = 7680;
      machine.storageMB_available = 4032;
      rack.machines.insert(&machine);
      brain.machines.insert(&machine);
    };

    Machine machineA {};
    Machine machineB {};
    Machine machineC {};
    seedMachine(machineA, rackA, uint128_t(0x19013101), "measure-compaction-a"_ctv);
    seedMachine(machineB, rackB, uint128_t(0x19013102), "measure-compaction-b"_ctv);
    seedMachine(machineC, rackC, uint128_t(0x19013103), "measure-compaction-c"_ctv);

    auto seedDonorDeployment = [&](ApplicationDeployment& donor, uint32_t applicationID, uint32_t nBase) -> void {
      seedCommonPlan(donor, false);
      donor.plan.config.applicationID = applicationID;
      donor.plan.config.versionID = 1;
      donor.plan.config.nLogicalCores = 4;
      donor.plan.stateless.nBase = nBase;
      donor.plan.stateless.maxPerRackRatio = 1.0f;
      donor.plan.stateless.maxPerMachineRatio = 1.0f;
      donor.plan.stateless.moveableDuringCompaction = true;
      donor.state = DeploymentState::running;
      donor.nTargetBase = nBase;
      donor.nDeployedBase = nBase;
      donor.nHealthyBase = nBase;
      brain.deployments.insert_or_assign(donor.plan.config.deploymentID(), &donor);
    };

    ApplicationDeployment donorAB;
    ApplicationDeployment donorC;
    seedDonorDeployment(donorAB, 13'111, 2);
    seedDonorDeployment(donorC, 13'112, 1);

    auto seedContainer = [&](ApplicationDeployment& donor, ContainerView& container, Machine& machine, Rack& rack, uint128_t uuid) -> void {
      container.uuid = uuid;
      container.deploymentID = donor.plan.config.deploymentID();
      container.applicationID = donor.plan.config.applicationID;
      container.machine = &machine;
      container.lifetime = ApplicationLifetime::base;
      container.state = ContainerState::healthy;
      donor.containers.insert(&container);
      donor.countPerMachine[&machine] += 1;
      donor.countPerRack[&rack] += 1;
      brain.containers.insert_or_assign(container.uuid, &container);
      machine.upsertContainerIndexEntry(container.deploymentID, &container);
    };

    ContainerView donorAContainer {};
    ContainerView donorBContainer {};
    ContainerView donorCContainer {};
    seedContainer(donorAB, donorAContainer, machineA, rackA, uint128_t(0x19013121));
    seedContainer(donorAB, donorBContainer, machineB, rackB, uint128_t(0x19013122));
    seedContainer(donorC, donorCContainer, machineC, rackC, uint128_t(0x19013123));

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.applicationID = 13'199;
    deployment.plan.config.nLogicalCores = 8;
    deployment.plan.stateless.nBase = 1;
    deployment.plan.stateless.maxPerRackRatio = 1.0f;
    deployment.plan.stateless.maxPerMachineRatio = 1.0f;

    uint32_t measured = deployment.measure();
    suite.expect(measured == 1, "measure_stateless_counts_compaction_fit");
    suite.expect(deployment.containers.empty(), "measure_stateless_compaction_cleans_measured_containers");
    suite.expect(deployment.toSchedule.empty(), "measure_stateless_compaction_cleans_measured_work");
    suite.expect(donorAB.toSchedule.empty() && donorC.toSchedule.empty(), "measure_stateless_compaction_does_not_schedule_donor_work");
    suite.expect(donorAB.waitingOnCompactions == false && donorC.waitingOnCompactions == false, "measure_stateless_compaction_does_not_block_donors");
    suite.expect(donorAContainer.state == ContainerState::healthy && donorAContainer.plannedWork == nullptr, "measure_stateless_compaction_preserves_donor_a_container");
    suite.expect(donorBContainer.state == ContainerState::healthy && donorBContainer.plannedWork == nullptr, "measure_stateless_compaction_preserves_donor_b_container");
    suite.expect(donorCContainer.state == ContainerState::healthy && donorCContainer.plannedWork == nullptr, "measure_stateless_compaction_preserves_donor_c_container");
    suite.expect(machineA.nLogicalCores_available == 4 && machineB.nLogicalCores_available == 4 && machineC.nLogicalCores_available == 4, "measure_stateless_compaction_preserves_machine_capacity");
    suite.expect(brain.containers.size() == 3, "measure_stateless_compaction_preserves_brain_container_index");

    machineA.removeContainerIndexEntry(donorAContainer.deploymentID, &donorAContainer);
    machineB.removeContainerIndexEntry(donorBContainer.deploymentID, &donorBContainer);
    machineC.removeContainerIndexEntry(donorCContainer.deploymentID, &donorCContainer);
    brain.containers.erase(donorAContainer.uuid);
    brain.containers.erase(donorBContainer.uuid);
    brain.containers.erase(donorCContainer.uuid);
    brain.deployments.erase(donorAB.plan.config.deploymentID());
    brain.deployments.erase(donorC.plan.config.deploymentID());
    rackA.machines.erase(&machineA);
    rackB.machines.erase(&machineB);
    rackC.machines.erase(&machineC);
    brain.machines.erase(&machineA);
    brain.machines.erase(&machineB);
    brain.machines.erase(&machineC);
    brain.racks.erase(rackA.uuid);
    brain.racks.erase(rackB.uuid);
    brain.racks.erase(rackC.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rack = {};
    rack.uuid = 19'601'101;
    brain.racks.insert_or_assign(rack.uuid, &rack);

    ScopedSocketPair socket = {};
    Machine machine = {};
    bool machineReady =
        socket.create(suite, "deploy_task_single_attempt_creates_socketpair") &&
        seedSchedulableMachine(brain, rack, machine, uint128_t(0x19601101), 0x0a000118, "deploy-task"_ctv, socket);
    suite.expect(machineReady, "deploy_task_single_attempt_seeds_machine");

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.type = ApplicationType::task;
    deployment.plan.config.taskExecutionPolicy = TaskExecutionPolicy::untilSucceeded;
    deployment.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
    deployment.plan.stateless.nBase = 1;
    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

    if (machineReady)
    {
      deployment.deploy();
      ContainerView *container = deployment.containers.size() == 1 ? *deployment.containers.begin() : nullptr;
      ContainerPlan plan = container ? container->generatePlan(deployment.plan) : ContainerPlan {};

      suite.expect(deployment.state == DeploymentState::running, "deploy_task_single_attempt_runs_after_dispatch");
      suite.expect(deployment.waitingOnContainers.empty(), "deploy_task_single_attempt_skips_health_waiter");
      suite.expect(deployment.schedulingStack.execution == nullptr, "deploy_task_single_attempt_does_not_suspend_scheduler");
      suite.expect(machine.neuron.pendingSend && machine.neuron.wBuffer.size() > 0, "deploy_task_single_attempt_queues_neuron_spin");
      suite.expect(container && container->taskAttemptNumber == 1, "deploy_task_single_attempt_numbers_attempt");
      suite.expect(plan.restartOnFailure == false && plan.taskAttemptNumber == 1, "deploy_task_single_attempt_plan_disables_local_restart");
      suite.expect(brain.progressCount >= 1 && brain.lastProgressMessage.equal("task attempt dispatched"_ctv), "deploy_task_single_attempt_reports_dispatch");
      suite.expect(brain.finCount == 0 && brain.failureCount == 0, "deploy_task_single_attempt_waits_for_terminal_report");
    }

    brain.deployments.erase(deployment.plan.config.deploymentID());
    brain.machines.erase(&machine);
    brain.racks.erase(rack.uuid);
    rack.machines.erase(&machine);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;
    brain.brainConfig.sharedCPUOvercommitPermille = 1000;

    Rack rackA {};
    rackA.uuid = 19'013'201;
    Rack rackB {};
    rackB.uuid = 19'013'202;
    Rack rackC {};
    rackC.uuid = 19'013'203;
    brain.racks.insert_or_assign(rackA.uuid, &rackA);
    brain.racks.insert_or_assign(rackB.uuid, &rackB);
    brain.racks.insert_or_assign(rackC.uuid, &rackC);

    auto seedMachine = [&](Machine& machine, Rack& rack, uint128_t uuid, const String& slug) -> void {
      machine.uuid = uuid;
      machine.slug = slug;
      machine.rack = &rack;
      machine.state = MachineState::healthy;
      machine.lifetime = MachineLifetime::owned;
      machine.ownedLogicalCores = 6;
      machine.ownedMemoryMB = 8192;
      machine.ownedStorageMB = 4096;
      machine.totalLogicalCores = 8;
      machine.totalMemoryMB = 8192;
      machine.totalStorageMB = 4096;
      machine.sharedCPUMillisCommitted = 3000;
      prodigyRecomputeMachineCPUAvailability(&machine, 1000);
      machine.memoryMB_available = 7680;
      machine.storageMB_available = 4032;
      rack.machines.insert(&machine);
      brain.machines.insert(&machine);
    };

    Machine machineA {};
    Machine machineB {};
    Machine machineC {};
    seedMachine(machineA, rackA, uint128_t(0x19013201), "measure-shared-compaction-a"_ctv);
    seedMachine(machineB, rackB, uint128_t(0x19013202), "measure-shared-compaction-b"_ctv);
    seedMachine(machineC, rackC, uint128_t(0x19013203), "measure-shared-compaction-c"_ctv);

    auto seedDonorDeployment = [&](ApplicationDeployment& donor, uint32_t applicationID, uint32_t nBase) -> void {
      seedCommonPlan(donor, false);
      donor.plan.config.applicationID = applicationID;
      donor.plan.config.versionID = 1;
      donor.plan.config.cpuMode = ApplicationCPUMode::shared;
      donor.plan.config.nLogicalCores = 3;
      donor.plan.config.sharedCPUMillis = 3000;
      donor.plan.stateless.nBase = nBase;
      donor.plan.stateless.maxPerRackRatio = 1.0f;
      donor.plan.stateless.maxPerMachineRatio = 1.0f;
      donor.plan.stateless.moveableDuringCompaction = true;
      donor.state = DeploymentState::running;
      donor.nTargetBase = nBase;
      donor.nDeployedBase = nBase;
      donor.nHealthyBase = nBase;
      brain.deployments.insert_or_assign(donor.plan.config.deploymentID(), &donor);
    };

    ApplicationDeployment donorAB;
    ApplicationDeployment donorC;
    seedDonorDeployment(donorAB, 13'211, 2);
    seedDonorDeployment(donorC, 13'212, 1);

    auto seedContainer = [&](ApplicationDeployment& donor, ContainerView& container, Machine& machine, Rack& rack, uint128_t uuid) -> void {
      container.uuid = uuid;
      container.deploymentID = donor.plan.config.deploymentID();
      container.applicationID = donor.plan.config.applicationID;
      container.machine = &machine;
      container.lifetime = ApplicationLifetime::base;
      container.state = ContainerState::healthy;
      donor.containers.insert(&container);
      donor.countPerMachine[&machine] += 1;
      donor.countPerRack[&rack] += 1;
      brain.containers.insert_or_assign(container.uuid, &container);
      machine.upsertContainerIndexEntry(container.deploymentID, &container);
    };

    ContainerView donorAContainer {};
    ContainerView donorBContainer {};
    ContainerView donorCContainer {};
    seedContainer(donorAB, donorAContainer, machineA, rackA, uint128_t(0x19013221));
    seedContainer(donorAB, donorBContainer, machineB, rackB, uint128_t(0x19013222));
    seedContainer(donorC, donorCContainer, machineC, rackC, uint128_t(0x19013223));

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.applicationID = 13'299;
    deployment.plan.config.cpuMode = ApplicationCPUMode::shared;
    deployment.plan.config.nLogicalCores = 6;
    deployment.plan.config.sharedCPUMillis = 6000;
    deployment.plan.stateless.nBase = 1;
    deployment.plan.stateless.maxPerRackRatio = 1.0f;
    deployment.plan.stateless.maxPerMachineRatio = 1.0f;

    uint32_t measured = deployment.measure();
    suite.expect(measured == 1, "measure_stateless_shared_cpu_counts_compaction_fit");
    suite.expect(deployment.containers.empty(), "measure_stateless_shared_cpu_compaction_cleans_measured_containers");
    suite.expect(deployment.toSchedule.empty(), "measure_stateless_shared_cpu_compaction_cleans_measured_work");
    suite.expect(donorAB.toSchedule.empty() && donorC.toSchedule.empty(), "measure_stateless_shared_cpu_compaction_does_not_schedule_donor_work");
    suite.expect(machineA.sharedCPUMillis_available == 3000 && machineB.sharedCPUMillis_available == 3000 && machineC.sharedCPUMillis_available == 3000, "measure_stateless_shared_cpu_compaction_preserves_machine_capacity");

    machineA.removeContainerIndexEntry(donorAContainer.deploymentID, &donorAContainer);
    machineB.removeContainerIndexEntry(donorBContainer.deploymentID, &donorBContainer);
    machineC.removeContainerIndexEntry(donorCContainer.deploymentID, &donorCContainer);
    brain.containers.erase(donorAContainer.uuid);
    brain.containers.erase(donorBContainer.uuid);
    brain.containers.erase(donorCContainer.uuid);
    brain.deployments.erase(donorAB.plan.config.deploymentID());
    brain.deployments.erase(donorC.plan.config.deploymentID());
    rackA.machines.erase(&machineA);
    rackB.machines.erase(&machineB);
    rackC.machines.erase(&machineC);
    brain.machines.erase(&machineA);
    brain.machines.erase(&machineB);
    brain.machines.erase(&machineC);
    brain.racks.erase(rackA.uuid);
    brain.racks.erase(rackB.uuid);
    brain.racks.erase(rackC.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rack {};
    rack.uuid = 19'072'001;
    brain.racks.insert_or_assign(rack.uuid, &rack);

    ScopedSocketPair socket = {};
    bool socketReady = socket.create(suite, "stateful_worker_topology_upgrade_green_schedule_creates_socketpair");

    Machine machine {};
    machine.uuid = uint128_t(0x19072001);
    machine.slug = "topology-green-scheduled"_ctv;
    machine.rack = &rack;
    machine.state = MachineState::healthy;
    machine.lifetime = MachineLifetime::owned;
    machine.hardware.cpu.architecture = nametagCurrentBuildMachineArchitecture();
    machine.nLogicalCores_available = 8;
    machine.memoryMB_available = 8192;
    machine.storageMB_available = 4096;
    bool machineReady = socketReady && armNeuronControlStream(machine, socket);
    rack.machines.insert(&machine);
    brain.machines.insert(&machine);

    suite.expect(machineReady, "stateful_worker_topology_upgrade_green_schedule_arms_machine_neuron_control_stream");

    ApplicationDeployment deployment {};
    seedCommonPlan(deployment, true);
    deployment.nShardGroups = 1;
    deployment.plan.stateful.clientPrefix = MeshServices::generateStatefulService(999, 1);
    deployment.plan.stateful.siblingPrefix = MeshServices::generateStatefulService(999, 2);
    deployment.plan.stateful.cousinPrefix = MeshServices::generateStatefulService(999, 3);
    deployment.plan.stateful.seedingPrefix = MeshServices::generateStatefulService(999, 4);
    deployment.plan.stateful.shardingPrefix = MeshServices::generateStatefulService(999, 5);
    deployment.armStatefulWorkerTopologyUpgrade(2, 4, 4, 512, 64);

    ContainerView *container = nullptr;
    for (ContainerView *candidate : deployment.containers)
    {
      if (candidate != nullptr && candidate->shardGroup == 0 && candidate->explicitStatefulTopology.topologyEpoch == deployment.statefulWorkerTopologyUpgradeTargetEpoch)
      {
        container = candidate;
        break;
      }
    }

    StatefulMeshRoles roles = container ? container->effectiveStatefulMeshRoles(deployment.plan) : StatefulMeshRoles {};
    ApplicationConfig containerConfig = container ? deployment.resourceConfigForContainer(container) : ApplicationConfig {};
    ContainerPlan containerPlan = container ? container->generatePlan(deployment.plan, deployment.nShardGroups, &containerConfig) : ContainerPlan {};

    suite.expect(container != nullptr, "stateful_worker_topology_upgrade_green_schedule_creates_container");
    suite.expect(container && container->state == ContainerState::scheduled, "stateful_worker_topology_upgrade_green_schedule_schedules_container_immediately");
    suite.expect(container && container->advertisements.find(roles.client) == container->advertisements.end(), "stateful_worker_topology_upgrade_green_schedule_suppresses_client_advertisement");
    suite.expect(container && container->advertisements.find(roles.sibling) != container->advertisements.end(), "stateful_worker_topology_upgrade_green_schedule_preserves_sibling_advertisement");
    suite.expect(container && container->subscriptions.find(roles.sibling) != container->subscriptions.end(), "stateful_worker_topology_upgrade_green_schedule_preserves_sibling_subscription");
    suite.expect(container && container->advertisements.find(roles.topologyBridge) == container->advertisements.end(), "stateful_worker_topology_upgrade_green_schedule_does_not_advertise_bridge_on_target");
    suite.expect(container && container->subscriptions.find(roles.topologyBridge) != container->subscriptions.end(), "stateful_worker_topology_upgrade_green_schedule_subscribes_bridge_on_target");
    suite.expect(containerPlan.statefulMeshRoles.client == 0, "stateful_worker_topology_upgrade_green_schedule_plan_prunes_client_role");
    suite.expect(containerPlan.config.nLogicalCores == 4, "stateful_worker_topology_upgrade_green_schedule_plan_uses_target_boot_cores");
    suite.expect(containerPlan.statefulMeshRoles.topologyBridge == roles.topologyBridge, "stateful_worker_topology_upgrade_green_schedule_plan_preserves_bridge_role");
    suite.expect(containerPlan.statefulTopology.servingMode == StatefulTopologyServingMode::catchupOnly, "stateful_worker_topology_upgrade_green_schedule_plan_preserves_catchup_only");

    if (container)
    {
      deployment.waitingOnContainers.erase(container);
      deployment.containers.erase(container);
      while (deployment.containersByShardGroup.eraseEntry(container->shardGroup, container))
      {
      }
      machine.removeContainerIndexEntry(container->deploymentID, container);
      brain.containers.erase(container->uuid);
      delete container;
    }

    rack.machines.erase(&machine);
    brain.machines.erase(&machine);
    brain.racks.erase(rack.uuid);
    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment {};
    seedCommonPlan(deployment, true);
    deployment.nShardGroups = 1;
    deployment.plan.stateful.clientPrefix = MeshServices::generateStatefulService(999, 1);
    deployment.plan.stateful.siblingPrefix = MeshServices::generateStatefulService(999, 2);
    deployment.plan.stateful.cousinPrefix = MeshServices::generateStatefulService(999, 3);
    deployment.plan.stateful.seedingPrefix = MeshServices::generateStatefulService(999, 4);
    deployment.plan.stateful.shardingPrefix = MeshServices::generateStatefulService(999, 5);

    ProdigyStatefulWorkerTopologyUpgradeOperation operation = {};
    operation.deploymentID = deployment.plan.config.deploymentID();
    operation.applicationID = deployment.plan.config.applicationID;
    operation.operationID = 0x19073001ull;
    operation.phase = StatefulWorkerTopologyUpgradePhase::greenBootstrap;
    operation.sourceWorkerCount = 2;
    operation.targetWorkerCount = 4;
    operation.sourceEpoch = 2;
    operation.targetEpoch = 400;
    operation.lockedShardGroups.push_back(0);
    brain.statefulWorkerTopologyUpgradeRuntimeState.push_back(operation);

    bool restored = deployment.restorePersistedStatefulWorkerTopologyUpgradeOperation();
    suite.expect(restored, "stateful_worker_topology_upgrade_restore_recovers_persisted_operation");

    ContainerView source = {};
    source.uuid = uint128_t(0x19073002);
    source.deploymentID = deployment.plan.config.deploymentID();
    source.applicationID = deployment.plan.config.applicationID;
    source.isStateful = true;
    source.shardGroup = 0;
    source.lifetime = ApplicationLifetime::base;
    source.state = ContainerState::healthy;
    deployment.containers.insert(&source);
    deployment.containersByShardGroup.insert(0, &source);

    deployment.recoverAfterReboot();

    StatefulMeshRoles sourceRoles = source.effectiveStatefulMeshRoles(deployment.plan);
    suite.expect(source.explicitStatefulTopology.operationID == operation.operationID, "stateful_worker_topology_upgrade_restore_applies_source_operation_id");
    suite.expect(source.explicitStatefulTopology.servingMode == StatefulTopologyServingMode::serve, "stateful_worker_topology_upgrade_restore_applies_source_serving_mode");
    suite.expect(source.explicitStatefulTopology.topologyEpoch == operation.sourceEpoch, "stateful_worker_topology_upgrade_restore_applies_source_epoch");
    suite.expect(source.advertisements.find(sourceRoles.topologyBridge) != source.advertisements.end(), "stateful_worker_topology_upgrade_restore_adds_source_bridge_advertisement");
    suite.expect(source.subscriptions.find(sourceRoles.topologyBridge) == source.subscriptions.end(), "stateful_worker_topology_upgrade_restore_omits_source_bridge_subscription");

    deployment.containers.erase(&source);
    while (deployment.containersByShardGroup.eraseEntry(0, &source))
    {
    }
    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment {};
    seedCommonPlan(deployment, true);
    deployment.nShardGroups = 1;
    deployment.plan.stateful.clientPrefix = MeshServices::generateStatefulService(999, 1);
    deployment.plan.stateful.siblingPrefix = MeshServices::generateStatefulService(999, 2);
    deployment.plan.stateful.cousinPrefix = MeshServices::generateStatefulService(999, 3);
    deployment.plan.stateful.seedingPrefix = MeshServices::generateStatefulService(999, 4);
    deployment.plan.stateful.shardingPrefix = MeshServices::generateStatefulService(999, 5);

    ProdigyStatefulWorkerTopologyUpgradeOperation operation = {};
    operation.deploymentID = deployment.plan.config.deploymentID();
    operation.applicationID = deployment.plan.config.applicationID;
    operation.operationID = 0x19074001ull;
    operation.phase = StatefulWorkerTopologyUpgradePhase::greenBootstrap;
    operation.sourceWorkerCount = 2;
    operation.targetWorkerCount = 4;
    operation.sourceEpoch = 2;
    operation.targetEpoch = 400;
    operation.lockedShardGroups.push_back(0);
    brain.statefulWorkerTopologyUpgradeRuntimeState.push_back(operation);

    ContainerView target = {};
    target.uuid = uint128_t(0x19074002);
    target.deploymentID = deployment.plan.config.deploymentID();
    target.applicationID = deployment.plan.config.applicationID;
    target.isStateful = true;
    target.shardGroup = 0;
    target.lifetime = ApplicationLifetime::base;
    target.state = ContainerState::healthy;
    target.explicitStatefulMeshRoles = StatefulMeshRoles::forShardGroup(deployment.plan.stateful, deployment.plan.config.applicationID, 0);
    target.explicitStatefulTopology.operationID = operation.operationID;
    target.explicitStatefulTopology.shardGroup = 0;
    target.explicitStatefulTopology.topologyEpoch = operation.targetEpoch;
    target.explicitStatefulTopology.workerCount = operation.targetWorkerCount;
    target.explicitStatefulTopology.servingMode = StatefulTopologyServingMode::catchupOnly;
    target.explicitStatefulTopology.sourceEpoch = operation.sourceEpoch;
    target.explicitStatefulTopology.targetEpoch = operation.targetEpoch;
    target.explicitStatefulTopology.bridgeMode = StatefulTopologyBridgeMode::sourceToTarget;

    StatefulMeshRoles targetRoles = target.effectiveStatefulMeshRoles(deployment.plan);
    target.advertisements.emplace(targetRoles.client, Advertisement(targetRoles.client, ContainerState::healthy, ContainerState::destroying, 4200));
    target.advertisingOnPorts.insert(4200);
    deployment.containers.insert(&target);
    deployment.containersByShardGroup.insert(0, &target);

    bool restored = deployment.restorePersistedStatefulWorkerTopologyUpgradeOperation();

    suite.expect(restored, "stateful_worker_topology_upgrade_restore_recovers_target_operation");
    suite.expect(target.advertisements.find(targetRoles.client) == target.advertisements.end(), "stateful_worker_topology_upgrade_restore_removes_target_client_advertisement");
    suite.expect(target.advertisements.find(targetRoles.topologyBridge) == target.advertisements.end(), "stateful_worker_topology_upgrade_restore_omits_target_bridge_advertisement");
    suite.expect(target.subscriptions.find(targetRoles.topologyBridge) != target.subscriptions.end(), "stateful_worker_topology_upgrade_restore_adds_target_bridge_subscription");

    deployment.containers.erase(&target);
    while (deployment.containersByShardGroup.eraseEntry(0, &target))
    {
    }
    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment {};
    seedCommonPlan(deployment, true);
    deployment.nShardGroups = 1;
    deployment.plan.stateful.clientPrefix = MeshServices::generateStatefulService(999, 1);
    deployment.plan.stateful.siblingPrefix = MeshServices::generateStatefulService(999, 2);
    deployment.plan.stateful.cousinPrefix = MeshServices::generateStatefulService(999, 3);
    deployment.plan.stateful.seedingPrefix = MeshServices::generateStatefulService(999, 4);
    deployment.plan.stateful.shardingPrefix = MeshServices::generateStatefulService(999, 5);
    deployment.armStatefulWorkerTopologyUpgrade(2, 4, 4, 512, 64);

    StatefulMeshRoles roles = StatefulMeshRoles::forShardGroup(deployment.plan.stateful, deployment.plan.config.applicationID, 0);
    ContainerView sourceA = {};
    ContainerView sourceB = {};
    ContainerView sourceC = {};
    ContainerView targetA = {};
    ContainerView targetB = {};
    ContainerView targetC = {};
    ContainerView *sources[] = {&sourceA, &sourceB, &sourceC};
    ContainerView *targets[] = {&targetA, &targetB, &targetC};
    auto noteCutoverBarrier = [&](ContainerView *target) -> void {
      target->applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverSourceEpochKey(), deployment.statefulWorkerTopologyUpgradeSourceEpoch);
      target->applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverTargetEpochKey(), deployment.statefulWorkerTopologyUpgradeTargetEpoch);
      target->applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverReadyKey(), 1);
      deployment.containerStatefulTopologyCutoverBarrierUpdated(target);
    };

    uint16_t portSeed = 4100;
    for (ContainerView *source : sources)
    {
      source->uuid = ++portSeed;
      source->deploymentID = deployment.plan.config.deploymentID();
      source->applicationID = deployment.plan.config.applicationID;
      source->isStateful = true;
      source->shardGroup = 0;
      source->state = ContainerState::healthy;
      source->runtimeReady = true;
      source->explicitStatefulMeshRoles = roles;
      source->explicitStatefulTopology.operationID = deployment.statefulWorkerTopologyUpgradeOperationID;
      source->explicitStatefulTopology.shardGroup = 0;
      source->explicitStatefulTopology.topologyEpoch = deployment.statefulWorkerTopologyUpgradeSourceEpoch;
      source->explicitStatefulTopology.workerCount = deployment.statefulWorkerTopologyUpgradeSourceWorkerCount;
      source->explicitStatefulTopology.servingMode = StatefulTopologyServingMode::serve;
      source->explicitStatefulTopology.sourceEpoch = deployment.statefulWorkerTopologyUpgradeSourceEpoch;
      source->explicitStatefulTopology.targetEpoch = deployment.statefulWorkerTopologyUpgradeTargetEpoch;
      source->explicitStatefulTopology.bridgeMode = StatefulTopologyBridgeMode::sourceToTarget;
    }

    sourceA.advertisements.emplace(roles.client, Advertisement(roles.client, ContainerState::healthy, ContainerState::destroying, 4301));
    sourceA.advertisingOnPorts.insert(4301);
    deployment.masterForShardGroup.insert_or_assign(0, &sourceA);

    for (ContainerView *target : targets)
    {
      target->uuid = ++portSeed;
      target->deploymentID = deployment.plan.config.deploymentID();
      target->applicationID = deployment.plan.config.applicationID;
      target->isStateful = true;
      target->shardGroup = 0;
      target->state = ContainerState::healthy;
      target->explicitStatefulMeshRoles = roles;
      target->explicitStatefulTopology.operationID = deployment.statefulWorkerTopologyUpgradeOperationID;
      target->explicitStatefulTopology.shardGroup = 0;
      target->explicitStatefulTopology.topologyEpoch = deployment.statefulWorkerTopologyUpgradeTargetEpoch;
      target->explicitStatefulTopology.workerCount = deployment.statefulWorkerTopologyUpgradeTargetWorkerCount;
      target->explicitStatefulTopology.servingMode = StatefulTopologyServingMode::catchupOnly;
      target->explicitStatefulTopology.sourceEpoch = deployment.statefulWorkerTopologyUpgradeSourceEpoch;
      target->explicitStatefulTopology.targetEpoch = deployment.statefulWorkerTopologyUpgradeTargetEpoch;
      target->explicitStatefulTopology.bridgeMode = StatefulTopologyBridgeMode::sourceToTarget;
    }

    for (ContainerView *container : sources)
    {
      deployment.containers.insert(container);
      deployment.containersByShardGroup.insert(0, container);
    }

    for (ContainerView *container : targets)
    {
      deployment.containers.insert(container);
      deployment.containersByShardGroup.insert(0, container);
    }

    noteCutoverBarrier(&targetA);
    noteCutoverBarrier(&targetB);
    deployment.containerIsRuntimeReady(&targetA);
    deployment.containerIsRuntimeReady(&targetB);
    suite.expect(deployment.statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::greenBootstrap, "stateful_worker_topology_upgrade_cutover_waits_for_all_targets");
    deployment.containerIsRuntimeReady(&targetC);
    suite.expect(deployment.statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::greenBootstrap, "stateful_worker_topology_upgrade_cutover_waits_for_barrier_proof");
    noteCutoverBarrier(&targetC);

    uint32_t targetClientAdvertisements = 0;
    for (ContainerView *target : targets)
    {
      if (target->advertisements.find(roles.client) != target->advertisements.end())
      {
        ++targetClientAdvertisements;
      }
    }

    suite.expect(deployment.statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::blueDraining, "stateful_worker_topology_upgrade_cutover_enters_blue_draining");
    suite.expect(sourceA.explicitStatefulTopology.servingMode == StatefulTopologyServingMode::drainOnly, "stateful_worker_topology_upgrade_cutover_drains_blue");
    suite.expect(targetA.explicitStatefulTopology.servingMode == StatefulTopologyServingMode::serve, "stateful_worker_topology_upgrade_cutover_promotes_green");
    suite.expect(sourceA.subscriptions.find(roles.topologyBridge) != sourceA.subscriptions.end(), "stateful_worker_topology_upgrade_cutover_reverses_bridge_subscription_on_blue");
    suite.expect(targetA.advertisements.find(roles.topologyBridge) != targetA.advertisements.end(), "stateful_worker_topology_upgrade_cutover_reverses_bridge_advertisement_on_green");
    suite.expect(sourceA.advertisements.find(roles.client) == sourceA.advertisements.end(), "stateful_worker_topology_upgrade_cutover_removes_blue_client_advertisement");
    suite.expect(targetClientAdvertisements == 1, "stateful_worker_topology_upgrade_cutover_selects_one_green_client_master");
    suite.expect(targetA.statefulTopologyCutoverReady == false, "stateful_worker_topology_upgrade_cutover_clears_target_barrier_after_cutover");
    suite.expect(deployment.statefulWorkerTopologyUpgradeRollbackDeadlineMs() > 0, "stateful_worker_topology_upgrade_cutover_arms_rollback_deadline");
    suite.expect(
        brain.statefulWorkerTopologyUpgradeRuntimeState.size() == 1 && brain.statefulWorkerTopologyUpgradeRuntimeState[0].phase == StatefulWorkerTopologyUpgradePhase::blueDraining,
        "stateful_worker_topology_upgrade_cutover_persists_blue_draining_phase");
    suite.expect(
        brain.statefulWorkerTopologyUpgradeRuntimeState.size() == 1 && brain.statefulWorkerTopologyUpgradeRuntimeState[0].updatedAtMs > 0,
        "stateful_worker_topology_upgrade_cutover_persists_blue_draining_phase_time");
    suite.expect(
        brain.statefulWorkerTopologyUpgradeRuntimeState.size() == 1 && deployment.statefulWorkerTopologyUpgradeRollbackDeadlineMs() > brain.statefulWorkerTopologyUpgradeRuntimeState[0].updatedAtMs && uint64_t(deployment.statefulWorkerTopologyUpgradeRollbackDeadlineMs() - brain.statefulWorkerTopologyUpgradeRuntimeState[0].updatedAtMs) == ApplicationDeployment::statefulWorkerTopologyRollbackWindowMs,
        "stateful_worker_topology_upgrade_cutover_deadline_matches_window");

    for (ContainerView *container : sources)
    {
      deployment.containers.erase(container);
      while (deployment.containersByShardGroup.eraseEntry(0, container))
      {
      }
    }

    for (ContainerView *container : targets)
    {
      deployment.containers.erase(container);
      while (deployment.containersByShardGroup.eraseEntry(0, container))
      {
      }
    }

    deployment.masterForShardGroup.erase(0);
    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    bool waitedBeforeFinalEvent = true;
    bool committedOnFinalEvent = true;
    uint32_t permutations = 0;
    uint8_t order[] = {0, 1, 2, 3, 4, 5};

    do
    {
      ++permutations;

      ApplicationDeployment deployment {};
      seedCommonPlan(deployment, true);
      deployment.nShardGroups = 1;
      deployment.plan.stateful.clientPrefix = MeshServices::generateStatefulService(999, 1);
      deployment.plan.stateful.siblingPrefix = MeshServices::generateStatefulService(999, 2);
      deployment.plan.stateful.cousinPrefix = MeshServices::generateStatefulService(999, 3);
      deployment.plan.stateful.seedingPrefix = MeshServices::generateStatefulService(999, 4);
      deployment.plan.stateful.shardingPrefix = MeshServices::generateStatefulService(999, 5);
      deployment.armStatefulWorkerTopologyUpgrade(2, 4, 4, 512, 64);

      StatefulMeshRoles roles = StatefulMeshRoles::forShardGroup(deployment.plan.stateful, deployment.plan.config.applicationID, 0);
      ContainerView sourceA = {};
      ContainerView sourceB = {};
      ContainerView sourceC = {};
      ContainerView targetA = {};
      ContainerView targetB = {};
      ContainerView targetC = {};
      ContainerView *sources[] = {&sourceA, &sourceB, &sourceC};
      ContainerView *targets[] = {&targetA, &targetB, &targetC};

      auto noteCutoverBarrier = [&](ContainerView *target) -> void {
        target->applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverSourceEpochKey(), deployment.statefulWorkerTopologyUpgradeSourceEpoch);
        target->applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverTargetEpochKey(), deployment.statefulWorkerTopologyUpgradeTargetEpoch);
        target->applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverReadyKey(), 1);
        deployment.containerStatefulTopologyCutoverBarrierUpdated(target);
      };

      uint16_t portSeed = 5100;
      for (ContainerView *source : sources)
      {
        source->uuid = ++portSeed;
        source->deploymentID = deployment.plan.config.deploymentID();
        source->applicationID = deployment.plan.config.applicationID;
        source->isStateful = true;
        source->shardGroup = 0;
        source->state = ContainerState::healthy;
        source->runtimeReady = true;
        source->explicitStatefulMeshRoles = roles;
        source->explicitStatefulTopology.operationID = deployment.statefulWorkerTopologyUpgradeOperationID;
        source->explicitStatefulTopology.shardGroup = 0;
        source->explicitStatefulTopology.topologyEpoch = deployment.statefulWorkerTopologyUpgradeSourceEpoch;
        source->explicitStatefulTopology.workerCount = deployment.statefulWorkerTopologyUpgradeSourceWorkerCount;
        source->explicitStatefulTopology.servingMode = StatefulTopologyServingMode::serve;
        source->explicitStatefulTopology.sourceEpoch = deployment.statefulWorkerTopologyUpgradeSourceEpoch;
        source->explicitStatefulTopology.targetEpoch = deployment.statefulWorkerTopologyUpgradeTargetEpoch;
        source->explicitStatefulTopology.bridgeMode = StatefulTopologyBridgeMode::sourceToTarget;
        deployment.containers.insert(source);
        deployment.containersByShardGroup.insert(0, source);
      }

      sourceA.advertisements.emplace(roles.client, Advertisement(roles.client, ContainerState::healthy, ContainerState::destroying, 5301));
      sourceA.advertisingOnPorts.insert(5301);
      deployment.masterForShardGroup.insert_or_assign(0, &sourceA);

      for (ContainerView *target : targets)
      {
        target->uuid = ++portSeed;
        target->deploymentID = deployment.plan.config.deploymentID();
        target->applicationID = deployment.plan.config.applicationID;
        target->isStateful = true;
        target->shardGroup = 0;
        target->state = ContainerState::healthy;
        target->explicitStatefulMeshRoles = roles;
        target->explicitStatefulTopology.operationID = deployment.statefulWorkerTopologyUpgradeOperationID;
        target->explicitStatefulTopology.shardGroup = 0;
        target->explicitStatefulTopology.topologyEpoch = deployment.statefulWorkerTopologyUpgradeTargetEpoch;
        target->explicitStatefulTopology.workerCount = deployment.statefulWorkerTopologyUpgradeTargetWorkerCount;
        target->explicitStatefulTopology.servingMode = StatefulTopologyServingMode::catchupOnly;
        target->explicitStatefulTopology.sourceEpoch = deployment.statefulWorkerTopologyUpgradeSourceEpoch;
        target->explicitStatefulTopology.targetEpoch = deployment.statefulWorkerTopologyUpgradeTargetEpoch;
        target->explicitStatefulTopology.bridgeMode = StatefulTopologyBridgeMode::sourceToTarget;
        deployment.containers.insert(target);
        deployment.containersByShardGroup.insert(0, target);
      }

      for (uint32_t step = 0; step < 6; ++step)
      {
        const uint8_t event = order[step];
        if (event < 3)
        {
          deployment.containerIsRuntimeReady(targets[event]);
        }
        else
        {
          noteCutoverBarrier(targets[event - 3]);
        }

        if (step < 5)
        {
          waitedBeforeFinalEvent = waitedBeforeFinalEvent && deployment.statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::greenBootstrap;
        }
        else
        {
          committedOnFinalEvent = committedOnFinalEvent && deployment.statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::blueDraining;
        }
      }
    } while (std::next_permutation(order, order + 6));

    suite.expect(permutations == 720, "stateful_worker_topology_upgrade_cutover_permutation_count");
    suite.expect(waitedBeforeFinalEvent, "stateful_worker_topology_upgrade_cutover_waits_in_all_event_orders");
    suite.expect(committedOnFinalEvent, "stateful_worker_topology_upgrade_cutover_commits_in_all_event_orders");

    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment {};
    seedCommonPlan(deployment, true);
    deployment.nShardGroups = 1;
    deployment.plan.stateful.clientPrefix = MeshServices::generateStatefulService(999, 1);
    deployment.plan.stateful.siblingPrefix = MeshServices::generateStatefulService(999, 2);
    deployment.plan.stateful.cousinPrefix = MeshServices::generateStatefulService(999, 3);
    deployment.plan.stateful.seedingPrefix = MeshServices::generateStatefulService(999, 4);
    deployment.plan.stateful.shardingPrefix = MeshServices::generateStatefulService(999, 5);
    deployment.armStatefulWorkerTopologyUpgrade(2, 4, 4, 512, 64);

    StatefulMeshRoles roles = StatefulMeshRoles::forShardGroup(deployment.plan.stateful, deployment.plan.config.applicationID, 0);
    ContainerView sourceA = {};
    ContainerView sourceB = {};
    ContainerView sourceC = {};
    ContainerView targetA = {};
    ContainerView targetB = {};
    ContainerView targetC = {};
    ContainerView *sources[] = {&sourceA, &sourceB, &sourceC};
    ContainerView *targets[] = {&targetA, &targetB, &targetC};
    auto noteCutoverBarrier = [&](ContainerView *target) -> void {
      target->applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverSourceEpochKey(), deployment.statefulWorkerTopologyUpgradeSourceEpoch);
      target->applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverTargetEpochKey(), deployment.statefulWorkerTopologyUpgradeTargetEpoch);
      target->applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverReadyKey(), 1);
      deployment.containerStatefulTopologyCutoverBarrierUpdated(target);
    };
    auto configureSource = [&](ContainerView *source) -> void {
      source->explicitStatefulTopology.operationID = deployment.statefulWorkerTopologyUpgradeOperationID;
      source->explicitStatefulTopology.shardGroup = 0;
      source->explicitStatefulTopology.topologyEpoch = deployment.statefulWorkerTopologyUpgradeSourceEpoch;
      source->explicitStatefulTopology.workerCount = deployment.statefulWorkerTopologyUpgradeSourceWorkerCount;
      source->explicitStatefulTopology.servingMode = StatefulTopologyServingMode::serve;
      source->explicitStatefulTopology.sourceEpoch = deployment.statefulWorkerTopologyUpgradeSourceEpoch;
      source->explicitStatefulTopology.targetEpoch = deployment.statefulWorkerTopologyUpgradeTargetEpoch;
      source->explicitStatefulTopology.bridgeMode = StatefulTopologyBridgeMode::sourceToTarget;
    };
    auto configureTarget = [&](ContainerView *target) -> void {
      target->explicitStatefulTopology.operationID = deployment.statefulWorkerTopologyUpgradeOperationID;
      target->explicitStatefulTopology.shardGroup = 0;
      target->explicitStatefulTopology.topologyEpoch = deployment.statefulWorkerTopologyUpgradeTargetEpoch;
      target->explicitStatefulTopology.workerCount = deployment.statefulWorkerTopologyUpgradeTargetWorkerCount;
      target->explicitStatefulTopology.servingMode = StatefulTopologyServingMode::catchupOnly;
      target->explicitStatefulTopology.sourceEpoch = deployment.statefulWorkerTopologyUpgradeSourceEpoch;
      target->explicitStatefulTopology.targetEpoch = deployment.statefulWorkerTopologyUpgradeTargetEpoch;
      target->explicitStatefulTopology.bridgeMode = StatefulTopologyBridgeMode::sourceToTarget;
    };

    uint16_t portSeed = 6100;
    for (ContainerView *source : sources)
    {
      source->uuid = ++portSeed;
      source->deploymentID = deployment.plan.config.deploymentID();
      source->applicationID = deployment.plan.config.applicationID;
      source->isStateful = true;
      source->shardGroup = 0;
      source->state = ContainerState::healthy;
      source->runtimeReady = true;
      source->explicitStatefulMeshRoles = roles;
      configureSource(source);
      deployment.containers.insert(source);
      deployment.containersByShardGroup.insert(0, source);
    }

    sourceA.advertisements.emplace(roles.client, Advertisement(roles.client, ContainerState::healthy, ContainerState::destroying, 6301));
    sourceA.advertisingOnPorts.insert(6301);
    deployment.masterForShardGroup.insert_or_assign(0, &sourceA);

    for (ContainerView *target : targets)
    {
      target->uuid = ++portSeed;
      target->deploymentID = deployment.plan.config.deploymentID();
      target->applicationID = deployment.plan.config.applicationID;
      target->isStateful = true;
      target->shardGroup = 0;
      target->state = ContainerState::healthy;
      target->explicitStatefulMeshRoles = roles;
      configureTarget(target);
      deployment.containers.insert(target);
      deployment.containersByShardGroup.insert(0, target);
    }

    noteCutoverBarrier(&targetA);
    noteCutoverBarrier(&targetB);
    noteCutoverBarrier(&targetC);
    deployment.containerIsRuntimeReady(&targetA);
    deployment.containerIsRuntimeReady(&targetB);
    deployment.containerIsRuntimeReady(&targetC);

    deployment.nHealthyBase = 6;
    String report = "target failed after cutover"_ctv;
    deployment.containerFailed(&targetA, 1234, 9, report, true);

    uint32_t sourceClientAdvertisements = 0;
    for (ContainerView *source : sources)
    {
      if (source->advertisements.find(roles.client) != source->advertisements.end())
      {
        ++sourceClientAdvertisements;
      }
    }

    suite.expect(deployment.statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::greenBootstrap, "stateful_worker_topology_upgrade_target_failure_rolls_back_to_green_bootstrap");
    suite.expect(sourceA.explicitStatefulTopology.servingMode == StatefulTopologyServingMode::serve, "stateful_worker_topology_upgrade_target_failure_restores_blue_service");
    suite.expect(targetA.explicitStatefulTopology.servingMode == StatefulTopologyServingMode::catchupOnly, "stateful_worker_topology_upgrade_target_failure_demotes_green");
    suite.expect(sourceClientAdvertisements == 1, "stateful_worker_topology_upgrade_target_failure_restores_one_blue_client_advertisement");
    suite.expect(targetA.advertisements.find(roles.client) == targetA.advertisements.end(), "stateful_worker_topology_upgrade_target_failure_removes_green_client_advertisement");
    suite.expect(targetB.statefulTopologyCutoverReady == false, "stateful_worker_topology_upgrade_target_failure_clears_surviving_target_barrier");
    suite.expect(
        brain.statefulWorkerTopologyUpgradeRuntimeState.size() == 1 && brain.statefulWorkerTopologyUpgradeRuntimeState[0].phase == StatefulWorkerTopologyUpgradePhase::greenBootstrap,
        "stateful_worker_topology_upgrade_target_failure_persists_rollback_phase");

    targetA.state = ContainerState::healthy;
    configureTarget(&targetA);
    targetA.runtimeReady = true;
    deployment.containerIsRuntimeReady(&targetA);
    deployment.containerIsRuntimeReady(&targetB);
    deployment.containerIsRuntimeReady(&targetC);

    suite.expect(
        deployment.statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::greenBootstrap,
        "stateful_worker_topology_upgrade_target_failure_requires_fresh_barrier_before_recutover");

    noteCutoverBarrier(&targetA);
    noteCutoverBarrier(&targetB);
    noteCutoverBarrier(&targetC);

    suite.expect(
        deployment.statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::blueDraining,
        "stateful_worker_topology_upgrade_target_failure_recutover_after_fresh_barrier");

    for (ContainerView *container : sources)
    {
      deployment.containers.erase(container);
      while (deployment.containersByShardGroup.eraseEntry(0, container))
      {
      }
    }

    for (ContainerView *container : targets)
    {
      deployment.containers.erase(container);
      while (deployment.containersByShardGroup.eraseEntry(0, container))
      {
      }
    }

    deployment.masterForShardGroup.erase(0);
    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rack {};
    Machine machines[3] = {};
    for (uint32_t i = 0; i < 3; ++i)
    {
      machines[i].rack = &rack;
    }

    ApplicationDeployment deployment {};
    seedCommonPlan(deployment, true);
    deployment.nShardGroups = 1;
    deployment.plan.stateful.clientPrefix = MeshServices::generateStatefulService(999, 1);
    deployment.plan.stateful.siblingPrefix = MeshServices::generateStatefulService(999, 2);
    deployment.plan.stateful.cousinPrefix = MeshServices::generateStatefulService(999, 3);
    deployment.plan.stateful.seedingPrefix = MeshServices::generateStatefulService(999, 4);
    deployment.plan.stateful.shardingPrefix = MeshServices::generateStatefulService(999, 5);
    deployment.armStatefulWorkerTopologyUpgrade(2, 4, 4, 512, 64);

    StatefulMeshRoles roles = StatefulMeshRoles::forShardGroup(deployment.plan.stateful, deployment.plan.config.applicationID, 0);
    uint32_t targetEpoch = deployment.statefulWorkerTopologyUpgradeTargetEpoch;
    ContainerView *sourceA = new ContainerView();
    ContainerView *sourceB = new ContainerView();
    ContainerView *sourceC = new ContainerView();
    ContainerView targetA = {};
    ContainerView targetB = {};
    ContainerView targetC = {};
    ContainerView *sources[] = {sourceA, sourceB, sourceC};
    ContainerView *targets[] = {&targetA, &targetB, &targetC};
    auto noteCutoverBarrier = [&](ContainerView *target) -> void {
      target->applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverSourceEpochKey(), deployment.statefulWorkerTopologyUpgradeSourceEpoch);
      target->applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverTargetEpochKey(), deployment.statefulWorkerTopologyUpgradeTargetEpoch);
      target->applyStatefulTopologyCutoverMetric(ProdigyMetrics::runtimeStatefulTopologyCutoverReadyKey(), 1);
      deployment.containerStatefulTopologyCutoverBarrierUpdated(target);
    };
    auto configureSource = [&](ContainerView *source) -> void {
      source->explicitStatefulTopology.operationID = deployment.statefulWorkerTopologyUpgradeOperationID;
      source->explicitStatefulTopology.shardGroup = 0;
      source->explicitStatefulTopology.topologyEpoch = deployment.statefulWorkerTopologyUpgradeSourceEpoch;
      source->explicitStatefulTopology.workerCount = deployment.statefulWorkerTopologyUpgradeSourceWorkerCount;
      source->explicitStatefulTopology.servingMode = StatefulTopologyServingMode::serve;
      source->explicitStatefulTopology.sourceEpoch = deployment.statefulWorkerTopologyUpgradeSourceEpoch;
      source->explicitStatefulTopology.targetEpoch = deployment.statefulWorkerTopologyUpgradeTargetEpoch;
      source->explicitStatefulTopology.bridgeMode = StatefulTopologyBridgeMode::sourceToTarget;
    };
    auto configureTarget = [&](ContainerView *target) -> void {
      target->explicitStatefulTopology.operationID = deployment.statefulWorkerTopologyUpgradeOperationID;
      target->explicitStatefulTopology.shardGroup = 0;
      target->explicitStatefulTopology.topologyEpoch = deployment.statefulWorkerTopologyUpgradeTargetEpoch;
      target->explicitStatefulTopology.workerCount = deployment.statefulWorkerTopologyUpgradeTargetWorkerCount;
      target->explicitStatefulTopology.servingMode = StatefulTopologyServingMode::catchupOnly;
      target->explicitStatefulTopology.sourceEpoch = deployment.statefulWorkerTopologyUpgradeSourceEpoch;
      target->explicitStatefulTopology.targetEpoch = deployment.statefulWorkerTopologyUpgradeTargetEpoch;
      target->explicitStatefulTopology.bridgeMode = StatefulTopologyBridgeMode::sourceToTarget;
    };

    uint16_t portSeed = 7100;
    for (uint32_t i = 0; i < 3; ++i)
    {
      ContainerView *source = sources[i];
      source->uuid = ++portSeed;
      source->deploymentID = deployment.plan.config.deploymentID();
      source->applicationID = deployment.plan.config.applicationID;
      source->isStateful = true;
      source->shardGroup = 0;
      source->state = ContainerState::healthy;
      source->runtimeReady = true;
      source->machine = &machines[i];
      source->explicitStatefulMeshRoles = roles;
      configureSource(source);
      deployment.containers.insert(source);
      deployment.containersByShardGroup.insert(0, source);
    }

    sourceA->advertisements.emplace(roles.client, Advertisement(roles.client, ContainerState::healthy, ContainerState::destroying, 7301));
    sourceA->advertisingOnPorts.insert(7301);
    deployment.masterForShardGroup.insert_or_assign(0, sourceA);

    for (ContainerView *target : targets)
    {
      target->uuid = ++portSeed;
      target->deploymentID = deployment.plan.config.deploymentID();
      target->applicationID = deployment.plan.config.applicationID;
      target->isStateful = true;
      target->shardGroup = 0;
      target->state = ContainerState::healthy;
      target->runtimeReady = true;
      target->explicitStatefulMeshRoles = roles;
      configureTarget(target);
      deployment.containers.insert(target);
      deployment.containersByShardGroup.insert(0, target);
    }

    noteCutoverBarrier(&targetA);
    noteCutoverBarrier(&targetB);
    noteCutoverBarrier(&targetC);
    deployment.containerIsRuntimeReady(&targetA);
    deployment.containerIsRuntimeReady(&targetB);
    deployment.containerIsRuntimeReady(&targetC);
    deployment.destructContainer(sourceA);
    deployment.destructContainer(sourceB);
    deployment.destructContainer(sourceC);
    for (ContainerView *source : sources)
    {
      deployment.waitingOnContainers.insert_or_assign(source, ContainerState::destroyed);
    }

    suite.expect(deployment.statefulWorkerTopologyUpgradePendingForAnyShardGroup(), "stateful_worker_topology_upgrade_blue_retirement_waits_for_destroy_confirmations");
    deployment.containerDestroyed(sourceA);
    deployment.containerDestroyed(sourceB);
    suite.expect(deployment.statefulWorkerTopologyUpgradePendingForAnyShardGroup(), "stateful_worker_topology_upgrade_blue_retirement_waits_for_all_destroy_confirmations");
    deployment.containerDestroyed(sourceC);

    uint32_t targetClientAdvertisements = 0;
    for (ContainerView *target : targets)
    {
      if (target->advertisements.find(roles.client) != target->advertisements.end())
      {
        ++targetClientAdvertisements;
      }
    }

    suite.expect(deployment.statefulWorkerTopologyUpgradePendingForAnyShardGroup() == false, "stateful_worker_topology_upgrade_blue_retirement_completes_operation");
    suite.expect(deployment.plan.config.nLogicalCores == 4, "stateful_worker_topology_upgrade_blue_retirement_commits_target_cores");
    suite.expect(brain.statefulWorkerTopologyUpgradeRuntimeState.empty(), "stateful_worker_topology_upgrade_blue_retirement_clears_persisted_operation");
    suite.expect(targetA.explicitStatefulTopology.operationID == 0, "stateful_worker_topology_upgrade_blue_retirement_clears_target_operation_id");
    suite.expect(targetA.explicitStatefulTopology.workerCount == 4, "stateful_worker_topology_upgrade_blue_retirement_preserves_target_worker_count");
    suite.expect(targetA.explicitStatefulTopology.topologyEpoch == targetEpoch, "stateful_worker_topology_upgrade_blue_retirement_preserves_target_epoch");
    suite.expect(targetA.explicitStatefulTopology.bridgeMode == StatefulTopologyBridgeMode::none, "stateful_worker_topology_upgrade_blue_retirement_removes_bridge_mode");
    suite.expect(targetA.advertisements.find(roles.topologyBridge) == targetA.advertisements.end(), "stateful_worker_topology_upgrade_blue_retirement_removes_bridge_advertisement");
    suite.expect(targetA.subscriptions.find(roles.topologyBridge) == targetA.subscriptions.end(), "stateful_worker_topology_upgrade_blue_retirement_removes_bridge_subscription");
    suite.expect(targetClientAdvertisements == 1, "stateful_worker_topology_upgrade_blue_retirement_keeps_one_green_client_master");

    for (ContainerView *container : targets)
    {
      deployment.containers.erase(container);
      while (deployment.containersByShardGroup.eraseEntry(0, container))
      {
      }
    }

    deployment.masterForShardGroup.erase(0);
    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment {};
    seedCommonPlan(deployment, true);
    deployment.nShardGroups = 1;
    deployment.plan.stateful.clientPrefix = MeshServices::generateStatefulService(999, 1);
    deployment.plan.stateful.siblingPrefix = MeshServices::generateStatefulService(999, 2);
    deployment.plan.stateful.cousinPrefix = MeshServices::generateStatefulService(999, 3);
    deployment.plan.stateful.seedingPrefix = MeshServices::generateStatefulService(999, 4);
    deployment.plan.stateful.shardingPrefix = MeshServices::generateStatefulService(999, 5);

    ProdigyStatefulWorkerTopologyUpgradeOperation operation = {};
    operation.deploymentID = deployment.plan.config.deploymentID();
    operation.applicationID = deployment.plan.config.applicationID;
    operation.operationID = 0x19075001ull;
    operation.phase = StatefulWorkerTopologyUpgradePhase::blueDraining;
    operation.sourceWorkerCount = 2;
    operation.targetWorkerCount = 4;
    operation.sourceEpoch = 2;
    operation.targetEpoch = 400;
    operation.updatedAtMs = Time::now<TimeResolution::ms>();
    operation.lockedShardGroups.push_back(0);
    brain.statefulWorkerTopologyUpgradeRuntimeState.push_back(operation);

    ContainerView source = {};
    source.uuid = uint128_t(0x19075002);
    source.deploymentID = deployment.plan.config.deploymentID();
    source.applicationID = deployment.plan.config.applicationID;
    source.isStateful = true;
    source.shardGroup = 0;
    source.state = ContainerState::healthy;

    ContainerView target = {};
    target.uuid = uint128_t(0x19075003);
    target.deploymentID = deployment.plan.config.deploymentID();
    target.applicationID = deployment.plan.config.applicationID;
    target.isStateful = true;
    target.shardGroup = 0;
    target.state = ContainerState::healthy;
    target.explicitStatefulTopology.operationID = operation.operationID;
    target.explicitStatefulTopology.shardGroup = 0;
    target.explicitStatefulTopology.topologyEpoch = operation.targetEpoch;
    target.explicitStatefulTopology.workerCount = operation.targetWorkerCount;

    deployment.containers.insert(&source);
    deployment.containers.insert(&target);
    deployment.containersByShardGroup.insert(0, &source);
    deployment.containersByShardGroup.insert(0, &target);

    bool restored = deployment.restorePersistedStatefulWorkerTopologyUpgradeOperation();
    StatefulMeshRoles roles = StatefulMeshRoles::forShardGroup(deployment.plan.stateful, deployment.plan.config.applicationID, 0);

    suite.expect(restored, "stateful_worker_topology_upgrade_restore_blue_draining_recovers_operation");
    suite.expect(source.explicitStatefulTopology.servingMode == StatefulTopologyServingMode::drainOnly, "stateful_worker_topology_upgrade_restore_blue_draining_applies_source_drain_only");
    suite.expect(source.subscriptions.find(roles.topologyBridge) != source.subscriptions.end(), "stateful_worker_topology_upgrade_restore_blue_draining_adds_source_reverse_bridge_subscription");
    suite.expect(source.plannedWork == nullptr, "stateful_worker_topology_upgrade_restore_blue_draining_keeps_blue_retirement_waiting_for_deadline");
    suite.expect(target.explicitStatefulTopology.servingMode == StatefulTopologyServingMode::serve, "stateful_worker_topology_upgrade_restore_blue_draining_applies_target_serve");
    suite.expect(target.advertisements.find(roles.topologyBridge) != target.advertisements.end(), "stateful_worker_topology_upgrade_restore_blue_draining_adds_target_reverse_bridge_advertisement");
    suite.expect(target.advertisements.find(roles.client) != target.advertisements.end(), "stateful_worker_topology_upgrade_restore_blue_draining_restores_target_client_advertisement");

    deployment.containers.erase(&source);
    deployment.containers.erase(&target);
    while (deployment.containersByShardGroup.eraseEntry(0, &source))
    {
    }
    while (deployment.containersByShardGroup.eraseEntry(0, &target))
    {
    }
    deployment.masterForShardGroup.erase(0);
    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment {};
    seedCommonPlan(deployment, true);
    deployment.nShardGroups = 1;
    deployment.plan.stateful.clientPrefix = MeshServices::generateStatefulService(999, 1);
    deployment.plan.stateful.siblingPrefix = MeshServices::generateStatefulService(999, 2);
    deployment.plan.stateful.cousinPrefix = MeshServices::generateStatefulService(999, 3);
    deployment.plan.stateful.seedingPrefix = MeshServices::generateStatefulService(999, 4);
    deployment.plan.stateful.shardingPrefix = MeshServices::generateStatefulService(999, 5);

    ProdigyStatefulWorkerTopologyUpgradeOperation operation = {};
    operation.deploymentID = deployment.plan.config.deploymentID();
    operation.applicationID = deployment.plan.config.applicationID;
    operation.operationID = 0x19075011ull;
    operation.phase = StatefulWorkerTopologyUpgradePhase::blueDraining;
    operation.sourceWorkerCount = 2;
    operation.targetWorkerCount = 4;
    operation.sourceEpoch = 2;
    operation.targetEpoch = 400;
    operation.updatedAtMs = Time::now<TimeResolution::ms>() - int64_t(ApplicationDeployment::statefulWorkerTopologyRollbackWindowMs + 1);
    operation.lockedShardGroups.push_back(0);
    brain.statefulWorkerTopologyUpgradeRuntimeState.push_back(operation);

    ContainerView source = {};
    source.uuid = uint128_t(0x19075012);
    source.deploymentID = deployment.plan.config.deploymentID();
    source.applicationID = deployment.plan.config.applicationID;
    source.isStateful = true;
    source.shardGroup = 0;
    source.state = ContainerState::healthy;
    Machine sourceMachine = {};
    source.machine = &sourceMachine;

    ContainerView target = {};
    target.uuid = uint128_t(0x19075013);
    target.deploymentID = deployment.plan.config.deploymentID();
    target.applicationID = deployment.plan.config.applicationID;
    target.isStateful = true;
    target.shardGroup = 0;
    target.state = ContainerState::healthy;
    target.explicitStatefulTopology.operationID = operation.operationID;
    target.explicitStatefulTopology.shardGroup = 0;
    target.explicitStatefulTopology.topologyEpoch = operation.targetEpoch;
    target.explicitStatefulTopology.workerCount = operation.targetWorkerCount;

    deployment.containers.insert(&source);
    deployment.containers.insert(&target);
    deployment.containersByShardGroup.insert(0, &source);
    deployment.containersByShardGroup.insert(0, &target);

    bool restored = deployment.restorePersistedStatefulWorkerTopologyUpgradeOperation();
    String report = "target failed after rollback deadline"_ctv;
    deployment.containerFailed(&target, 1234, 9, report, true);

    suite.expect(restored, "stateful_worker_topology_upgrade_restore_blue_draining_expired_window_recovers_operation");
    suite.expect(deployment.statefulWorkerTopologyUpgradePhase == StatefulWorkerTopologyUpgradePhase::blueDraining, "stateful_worker_topology_upgrade_expired_window_does_not_roll_back");
    suite.expect(source.explicitStatefulTopology.servingMode == StatefulTopologyServingMode::drainOnly, "stateful_worker_topology_upgrade_expired_window_keeps_blue_drain_only");
    suite.expect(source.state == ContainerState::destroying, "stateful_worker_topology_upgrade_expired_window_schedules_blue_retirement");
    suite.expect(source.plannedWork == nullptr, "stateful_worker_topology_upgrade_expired_window_consumes_blue_retirement_work");
    suite.expect(target.explicitStatefulTopology.servingMode == StatefulTopologyServingMode::serve, "stateful_worker_topology_upgrade_expired_window_keeps_green_serving");

    deployment.containers.erase(&source);
    deployment.containers.erase(&target);
    while (deployment.containersByShardGroup.eraseEntry(0, &source))
    {
    }
    while (deployment.containersByShardGroup.eraseEntry(0, &target))
    {
    }
    deployment.masterForShardGroup.erase(0);
    thisBrain = savedBrain;
  }

  {
    ApplicationConfig config {};
    String json = "{\"minGPUs\":2,\"gpuMemoryGB\":24,\"nicSpeedGbps\":10,\"minInternetDownloadMbps\":500,\"minInternetUploadMbps\":250,\"maxInternetLatencyMs\":20}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool parsedField = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      String failure;
      parsedField = mothershipParseApplicationMachineSelectionObject(doc, config, "config"_ctv, &failure);
      suite.expect(failure.size() == 0, "mothership_parse_machine_resource_criteria_no_failure");
    }

    suite.expect(parsedField, "mothership_parse_machine_resource_criteria_parses");
    suite.expect(config.minGPUs == 2, "mothership_parse_machine_resource_fields_sets_min_gpus");
    suite.expect(config.gpuMemoryGB == 24, "mothership_parse_machine_resource_fields_sets_gpu_memory_gb");
    suite.expect(config.nicSpeedGbps == 10, "mothership_parse_machine_resource_fields_sets_nic_speed_gbps");
    suite.expect(config.minInternetDownloadMbps == 500, "mothership_parse_machine_resource_fields_sets_min_internet_download");
    suite.expect(config.minInternetUploadMbps == 250, "mothership_parse_machine_resource_fields_sets_min_internet_upload");
    suite.expect(config.maxInternetLatencyMs == 20, "mothership_parse_machine_resource_fields_sets_max_internet_latency");
  }

  {
    ApplicationConfig config {};
    String json = "{\"gpuMemoryGB\":24}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool rejected = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      String failure;
      rejected = (mothershipParseApplicationMachineSelectionObject(doc, config, "config"_ctv, &failure) == false);
      suite.expect(failure == "config.gpuMemoryGB requires minGPUs > 0"_ctv, "mothership_parse_machine_resource_fields_gpu_memory_requires_gpus_failure_text");
    }

    suite.expect(rejected, "mothership_parse_machine_resource_fields_gpu_memory_requires_gpus");
  }

  {
    ApplicationConfig config {};
    String json = "{\"minGPUMemoryMB\":24576}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool rejected = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      String failure;
      rejected = (mothershipParseApplicationMachineSelectionObject(doc, config, "config"_ctv, &failure) == false);
      suite.expect(failure == "config.minGPUMemoryMB is not recognized"_ctv, "mothership_parse_machine_resource_fields_old_gpu_memory_field_rejected_text");
    }

    suite.expect(rejected, "mothership_parse_machine_resource_fields_old_gpu_memory_field_rejected");
  }

  {
    ApplicationConfig config {};
    String json = "{\"nHugepages2MB\":1}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool rejected = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      uint32_t seenMask = 0;
      for (auto field : doc.get_object())
      {
        String key = {};
        key.setInvariant(field.key);

        String sizeFailure = {};
        if (mothershipParseApplicationConfigSizeField(key, field.value, config, seenMask, "config"_ctv, &sizeFailure))
        {
          continue;
        }

        suite.expect(sizeFailure.size() == 0, "mothership_parse_nhugepages_removed_size_failure_empty");

        String criteriaFailure = {};
        if (mothershipParseApplicationMachineSelectionField(key, field.value, config, &criteriaFailure))
        {
          continue;
        }

        suite.expect(criteriaFailure.size() == 0, "mothership_parse_nhugepages_removed_machine_failure_empty");

        if (key == "nHugepages2MB"_ctv)
        {
          rejected = true;
        }
      }
    }

    suite.expect(rejected, "mothership_parse_nhugepages_removed_field_rejected");
  }

  {
    ApplicationConfig config {};
    String json = "{\"nThreads\":4}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool rejected = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      uint32_t seenMask = 0;
      for (auto field : doc.get_object())
      {
        String key = {};
        key.setInvariant(field.key);

        String sizeFailure = {};
        if (mothershipParseApplicationConfigSizeField(key, field.value, config, seenMask, "config"_ctv, &sizeFailure))
        {
          continue;
        }

        suite.expect(sizeFailure.size() == 0, "mothership_parse_nthreads_removed_size_failure_empty");

        String criteriaFailure = {};
        if (mothershipParseApplicationMachineSelectionField(key, field.value, config, &criteriaFailure))
        {
          continue;
        }

        suite.expect(criteriaFailure.size() == 0, "mothership_parse_nthreads_removed_machine_failure_empty");

        if (key == "nThreads"_ctv)
        {
          rejected = true;
        }
      }
    }

    suite.expect(rejected, "mothership_parse_nthreads_removed_field_rejected");
  }

  {
    ApplicationConfig config {};
    String json = "{\"memoryGB\":2,\"filesystemMB\":512,\"storageGB\":10}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    uint32_t seenMask = 0;
    bool parsedAll = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      String failure = {};
      parsedAll = true;
      for (auto field : doc.get_object())
      {
        String key = {};
        key.setInvariant(field.key);
        if (mothershipParseApplicationConfigSizeField(key, field.value, config, seenMask, "config"_ctv, &failure) == false)
        {
          parsedAll = false;
          break;
        }
      }

      suite.expect(failure.size() == 0, "mothership_parse_application_size_fields_mb_or_gb_no_failure");
    }

    suite.expect(parsedAll, "mothership_parse_application_size_fields_mb_or_gb");
    suite.expect(config.memoryMB == 2u * 1024u, "mothership_parse_application_size_fields_memory_gb_to_mb");
    suite.expect(config.filesystemMB == 512u, "mothership_parse_application_size_fields_filesystem_mb_preserved");
    suite.expect(config.storageMB == 10u * 1024u, "mothership_parse_application_size_fields_storage_gb_to_mb");
  }

  {
    ApplicationConfig config {};
    String json = "{\"memoryMB\":512,\"memoryGB\":1}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool rejected = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      uint32_t seenMask = 0;
      String failure = {};
      for (auto field : doc.get_object())
      {
        String key = {};
        key.setInvariant(field.key);
        if (mothershipParseApplicationConfigSizeField(key, field.value, config, seenMask, "config"_ctv, &failure) == false)
        {
          rejected = true;
          suite.expect(failure.size() > 0, "mothership_parse_application_size_fields_rejects_mixed_units_reason");
          break;
        }
      }
    }

    suite.expect(rejected, "mothership_parse_application_size_fields_rejects_mixed_units");
  }

  {
    DeploymentPlan plan {};
    String json = "{\"useHostNetworkNamespace\":true}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    const bool parsedJSON = (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS);
    suite.expect(parsedJSON, "mothership_parse_use_host_network_namespace_json_valid");

    bool parsedField = false;
    if (parsedJSON)
    {
      for (auto field : doc.get_object())
      {
        String key;
        key.setInvariant(field.key.data(), field.key.size());
        if (key == "useHostNetworkNamespace"_ctv)
        {
          String failure;
          parsedField = mothershipParseDeploymentPlanUseHostNetworkNamespace(field.value, plan, &failure);
          suite.expect(parsedField, "mothership_parse_use_host_network_namespace_accepts_bool");
          suite.expect(failure.size() == 0, "mothership_parse_use_host_network_namespace_clears_failure");
        }
      }
    }

    suite.expect(parsedField && plan.useHostNetworkNamespace == true, "mothership_parse_use_host_network_namespace_sets_plan");
  }

  {
    DeploymentPlan plan {};
    String json = "{\"tls\":{\"applicationID\":42,\"enablePerContainerLeafs\":true,\"leafValidityDays\":15,\"identityNames\":[\"inbound_server_tls\"],\"dnsSans\":[\"nametag.social\",\"dev.nametag.social\"],\"ipSans\":[\"10.0.0.18\",\"fd7a:115c:a1e0::18\"]}}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    const bool parsedJSON = (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS);
    suite.expect(parsedJSON, "mothership_parse_tls_policy_json_valid");

    bool parsedField = false;
    if (parsedJSON)
    {
      for (auto field : doc.get_object())
      {
        String key;
        key.setInvariant(field.key.data(), field.key.size());
        if (key == "tls"_ctv)
        {
          String failure;
          auto resolver = [](const String& reference, uint16_t& applicationID) -> bool {
            (void)reference;
            applicationID = 0;
            return false;
          };
          parsedField = mothershipParseDeploymentPlanTlsPolicy(field.value, plan, resolver, &failure);
          suite.expect(parsedField, "mothership_parse_tls_policy_accepts_dns_and_ip_sans");
          suite.expect(failure.size() == 0, "mothership_parse_tls_policy_clears_failure");
        }
      }
    }

    suite.expect(parsedField && plan.hasTlsIssuancePolicy, "mothership_parse_tls_policy_sets_flag");
    suite.expect(plan.tlsIssuancePolicy.applicationID == 42, "mothership_parse_tls_policy_sets_application_id");
    suite.expect(plan.tlsIssuancePolicy.identityNames.size() == 1, "mothership_parse_tls_policy_sets_identity_names");
    suite.expect(plan.tlsIssuancePolicy.dnsSans.size() == 2, "mothership_parse_tls_policy_sets_dns_sans");
    suite.expect(plan.tlsIssuancePolicy.ipSans.size() == 2, "mothership_parse_tls_policy_sets_ip_sans");
    suite.expect(plan.tlsIssuancePolicy.ipSans.size() == 2 && plan.tlsIssuancePolicy.ipSans[0].equals(IPAddress("10.0.0.18", false)), "mothership_parse_tls_policy_sets_ipv4_san");
    suite.expect(plan.tlsIssuancePolicy.ipSans.size() == 2 && plan.tlsIssuancePolicy.ipSans[1].equals(IPAddress("fd7a:115c:a1e0::18", true)), "mothership_parse_tls_policy_sets_ipv6_san");
  }

  {
    DeploymentPlan plan {};
    String json = "{\"tls\":{\"applicationID\":42,\"enablePerContainerLeafs\":true,\"renewLeadPercent\":10,\"identityNames\":[\"inbound_server_tls\"]}}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    suite.expect(parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS, "mothership_parse_tls_policy_rejects_renew_lead_json_valid");
    for (auto field : doc.get_object())
    {
      String key;
      key.setInvariant(field.key.data(), field.key.size());
      if (key == "tls"_ctv)
      {
        String failure;
        auto resolver = [](const String& reference, uint16_t& applicationID) -> bool {
          (void)reference;
          applicationID = 0;
          return false;
        };
        suite.expect(mothershipParseDeploymentPlanTlsPolicy(field.value, plan, resolver, &failure) == false, "mothership_parse_tls_policy_rejects_renew_lead_percent");
        suite.expect(failure.equal("tls invalid field"_ctv), "mothership_parse_tls_policy_rejects_renew_lead_percent_failure");
      }
    }
  }

  {
    ApplicationConfig config {};
    String json = "{\"isolateCPUs\":true,\"nLogicalCores\":3}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool parsedIsolation = false;
    bool parsedCores = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      for (auto field : doc.get_object())
      {
        String key;
        key.setInvariant(field.key.data(), field.key.size());
        String failure;
        if (key == "isolateCPUs"_ctv)
        {
          parsedIsolation = mothershipParseApplicationCPUIsolationMode(field.value, config, &failure);
          suite.expect(parsedIsolation, "mothership_parse_isolated_cpu_mode_accepts_bool");
          suite.expect(failure.size() == 0, "mothership_parse_isolated_cpu_mode_no_failure");
        }
        else if (key == "nLogicalCores"_ctv)
        {
          parsedCores = mothershipParseApplicationCPURequest(field.value, config, &failure);
          suite.expect(parsedCores, "mothership_parse_isolated_cpu_request_accepts_integer");
          suite.expect(failure.size() == 0, "mothership_parse_isolated_cpu_request_no_failure");
        }
      }
    }

    suite.expect(parsedIsolation && parsedCores, "mothership_parse_isolated_cpu_fields_parse");
    suite.expect(config.cpuMode == ApplicationCPUMode::isolated, "mothership_parse_isolated_cpu_sets_mode");
    suite.expect(config.nLogicalCores == 3, "mothership_parse_isolated_cpu_sets_core_count");
    suite.expect(config.sharedCPUMillis == 0, "mothership_parse_isolated_cpu_clears_shared_millis");
  }

  {
    ApplicationConfig config {};
    String json = "{\"isolateCPUs\":false,\"nLogicalCores\":1.25}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool parsedIsolation = false;
    bool parsedCores = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      for (auto field : doc.get_object())
      {
        String key;
        key.setInvariant(field.key.data(), field.key.size());
        String failure;
        if (key == "isolateCPUs"_ctv)
        {
          parsedIsolation = mothershipParseApplicationCPUIsolationMode(field.value, config, &failure);
          suite.expect(parsedIsolation, "mothership_parse_shared_cpu_mode_accepts_bool");
          suite.expect(failure.size() == 0, "mothership_parse_shared_cpu_mode_no_failure");
        }
        else if (key == "nLogicalCores"_ctv)
        {
          parsedCores = mothershipParseApplicationCPURequest(field.value, config, &failure);
          suite.expect(parsedCores, "mothership_parse_shared_cpu_request_accepts_fractional_number");
          suite.expect(failure.size() == 0, "mothership_parse_shared_cpu_request_no_failure");
        }
      }
    }

    suite.expect(parsedIsolation && parsedCores, "mothership_parse_shared_cpu_fields_parse");
    suite.expect(config.cpuMode == ApplicationCPUMode::shared, "mothership_parse_shared_cpu_sets_mode");
    suite.expect(config.sharedCPUMillis == 1250, "mothership_parse_shared_cpu_sets_millis");
    suite.expect(config.nLogicalCores == 2, "mothership_parse_shared_cpu_sets_core_hint");
  }

  {
    ApplicationConfig config {};
    config.cpuMode = ApplicationCPUMode::isolated;
    String json = "{\"nLogicalCores\":128}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool parsedCores = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      for (auto field : doc.get_object())
      {
        String key;
        key.setInvariant(field.key.data(), field.key.size());
        if (key == "nLogicalCores"_ctv)
        {
          String failure;
          parsedCores = mothershipParseApplicationCPURequest(field.value, config, &failure);
          suite.expect(failure.size() == 0, "mothership_parse_large_isolated_cpu_no_failure");
        }
      }
    }

    suite.expect(parsedCores, "mothership_parse_large_isolated_cpu_accepts_integer");
    suite.expect(config.cpuMode == ApplicationCPUMode::isolated, "mothership_parse_large_isolated_cpu_keeps_mode");
    suite.expect(config.nLogicalCores == 128, "mothership_parse_large_isolated_cpu_sets_count");
    suite.expect(config.sharedCPUMillis == 0, "mothership_parse_large_isolated_cpu_clears_shared_millis");
  }

  {
    ApplicationConfig config {};
    config.cpuMode = ApplicationCPUMode::shared;
    String json = "{\"nLogicalCores\":64.5}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool parsedCores = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      for (auto field : doc.get_object())
      {
        String key;
        key.setInvariant(field.key.data(), field.key.size());
        if (key == "nLogicalCores"_ctv)
        {
          String failure;
          parsedCores = mothershipParseApplicationCPURequest(field.value, config, &failure);
          suite.expect(failure.size() == 0, "mothership_parse_large_shared_cpu_no_failure");
        }
      }
    }

    suite.expect(parsedCores, "mothership_parse_large_shared_cpu_accepts_fractional");
    suite.expect(config.cpuMode == ApplicationCPUMode::shared, "mothership_parse_large_shared_cpu_keeps_mode");
    suite.expect(config.sharedCPUMillis == 64'500, "mothership_parse_large_shared_cpu_sets_millis");
    suite.expect(config.nLogicalCores == 65, "mothership_parse_large_shared_cpu_sets_core_hint");
  }

  {
    ApplicationConfig config {};
    config.cpuMode = ApplicationCPUMode::isolated;
    String json = "{\"nLogicalCores\":1.25}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool rejected = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      for (auto field : doc.get_object())
      {
        String key;
        key.setInvariant(field.key.data(), field.key.size());
        if (key == "nLogicalCores"_ctv)
        {
          String failure;
          rejected = (mothershipParseApplicationCPURequest(field.value, config, &failure) == false);
          suite.expect(failure == "config.nLogicalCores requires an integer when isolateCPUs=true"_ctv, "mothership_parse_isolated_cpu_rejects_fractional_failure_text");
        }
      }
    }

    suite.expect(rejected, "mothership_parse_isolated_cpu_rejects_fractional");
  }

  {
    ApplicationConfig config {};
    suite.expect(config.maxPids == prodigyContainerRuntimeLimits.maxPids,
                 "application_config_max_pids_preserves_existing_default");
    String json = "{\"maxPids\":5}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);
    simdjson::dom::parser parser;
    simdjson::dom::element document;
    bool parsed = false;
    if (parser.parse(json.data(), json.size()).get(document) == simdjson::SUCCESS)
    {
      for (auto field : document.get_object())
      {
        String failure = {};
        parsed = mothershipParseApplicationMaxPids(
            field.value, config, "config"_ctv, &failure);
        suite.expect(failure.empty(), "mothership_parse_max_pids_no_failure");
      }
    }
    suite.expect(parsed && config.maxPids == 5,
                 "mothership_parse_max_pids_accepts_explicit_limit");

    String invalid = "{\"maxPids\":0}"_ctv;
    invalid.need(simdjson::SIMDJSON_PADDING);
    if (parser.parse(invalid.data(), invalid.size()).get(document) == simdjson::SUCCESS)
    {
      for (auto field : document.get_object())
      {
        String failure = {};
        suite.expect(mothershipParseApplicationMaxPids(
                         field.value, config, "config"_ctv, &failure) == false,
                     "mothership_parse_max_pids_rejects_zero");
      }
    }
  }

  for (const char *text : {
           "{\"isolatedChildMemoryMB\":64,\"maxPids\":5}",
           "{\"maxPids\":5,\"isolatedChildMemoryMB\":64}"})
  {
    ApplicationConfig config {};
    config.architecture = MachineCpuArchitecture::aarch64;
    String json(text);
    json.need(simdjson::SIMDJSON_PADDING);
    simdjson::dom::parser parser;
    simdjson::dom::element document;
    bool parsed = parser.parse(json.data(), json.size()).get(document) == simdjson::SUCCESS;
    if (parsed)
    {
      for (auto field : document.get_object())
      {
        String key;
        key.setInvariant(field.key.data(), field.key.size());
        String failure;
        parsed = key.equal("maxPids"_ctv)
                     ? mothershipParseApplicationMaxPids(
                           field.value, config, "config"_ctv, &failure)
                     : mothershipParseApplicationIsolatedChildMemoryMB(
                           field.value, config, "config"_ctv, &failure);
        if (parsed == false)
        {
          break;
        }
      }
    }
    String failure;
    suite.expect(parsed &&
                     mothershipValidateApplicationRuntimeRequirements(
                         config, "config"_ctv, &failure) &&
                     config.maxPids == 5 && config.isolatedChildMemoryMB == 64,
                 "isolated_child_config_is_field_order_independent");
  }

  {
    String json = "{\"sharedCpuOvercommit\":1.5}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    uint16_t permille = 0;
    bool parsedField = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      for (auto field : doc.get_object())
      {
        String key;
        key.setInvariant(field.key.data(), field.key.size());
        if (key == "sharedCpuOvercommit"_ctv)
        {
          String failure;
          parsedField = mothershipParseSharedCPUOvercommitValue(field.value, permille, &failure);
          suite.expect(failure.size() == 0, "mothership_parse_shared_cpu_overcommit_no_failure");
        }
      }
    }

    suite.expect(parsedField, "mothership_parse_shared_cpu_overcommit_parses");
    suite.expect(permille == 1500, "mothership_parse_shared_cpu_overcommit_sets_permille");
  }

  {
    String json = "{\"sharedCpuOvercommit\":2.1}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    uint16_t permille = 0;
    bool rejected = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      for (auto field : doc.get_object())
      {
        String key;
        key.setInvariant(field.key.data(), field.key.size());
        if (key == "sharedCpuOvercommit"_ctv)
        {
          String failure;
          rejected = (mothershipParseSharedCPUOvercommitValue(field.value, permille, &failure) == false);
          suite.expect(failure == "sharedCpuOvercommit must be in 1.0..2.0"_ctv, "mothership_parse_shared_cpu_overcommit_rejects_out_of_range_failure_text");
        }
      }
    }

    suite.expect(rejected, "mothership_parse_shared_cpu_overcommit_rejects_out_of_range");
  }

  {
    Wormhole wormhole {};
    String json = "{\"quicCidKeyRotationHours\":36}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool parsedField = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      for (auto field : doc.get_object())
      {
        String key;
        key.setInvariant(field.key.data(), field.key.size());
        if (key == "quicCidKeyRotationHours"_ctv)
        {
          String failure;
          parsedField = mothershipParseWormholeQuicCidKeyRotationHours(field.value, wormhole, &failure);
          suite.expect(failure.size() == 0, "mothership_parse_wormhole_quic_rotation_hours_no_failure");
        }
      }
    }

    suite.expect(parsedField, "mothership_parse_wormhole_quic_rotation_hours_parses");
    suite.expect(wormhole.quicCidKeyState.rotationHours == 36, "mothership_parse_wormhole_quic_rotation_hours_sets_value");
  }

  {
    Wormhole wormhole {};
    String json = "{\"quicCidKeyRotationHours\":0}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool rejected = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      for (auto field : doc.get_object())
      {
        String key;
        key.setInvariant(field.key.data(), field.key.size());
        if (key == "quicCidKeyRotationHours"_ctv)
        {
          String failure;
          rejected = (mothershipParseWormholeQuicCidKeyRotationHours(field.value, wormhole, &failure) == false);
          suite.expect(failure == "wormhole.quicCidKeyRotationHours must be > 0"_ctv, "mothership_parse_wormhole_quic_rotation_hours_zero_failure_text");
        }
      }
    }

    suite.expect(rejected, "mothership_parse_wormhole_quic_rotation_hours_rejects_zero");
  }

  {
    TlsResumptionWormholeConfig config {};
    String json = "{\"sniNames\":[\"api.example.com\"],\"alpns\":[\"h3\"]}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    String failure;
    const bool parsedJSON = (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS);
    suite.expect(parsedJSON, "mothership_parse_wormhole_tls_resumption_json_valid");

    bool parsedField = false;
    if (parsedJSON)
    {
      parsedField = mothershipParseWormholeTlsResumptionConfig(doc, config, &failure);
    }

    suite.expect(parsedField, "mothership_parse_wormhole_tls_resumption_parses");
    suite.expect(failure.size() == 0, "mothership_parse_wormhole_tls_resumption_no_failure");
    suite.expect(config.sniNames.size() == 1 && config.sniNames[0].equal("api.example.com"_ctv), "mothership_parse_wormhole_tls_resumption_sni");
    suite.expect(config.alpns.size() == 1 && config.alpns[0].equal("h3"_ctv), "mothership_parse_wormhole_tls_resumption_alpn");
  }

  {
    TlsResumptionWormholeConfig config {};
    String json = "{\"zeroRtt\":{\"enabled\":true}}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool rejected = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      String failure;
      rejected = (mothershipParseWormholeTlsResumptionConfig(doc, config, &failure) == false);
      suite.expect(failure == "wormhole.tlsResumption invalid field"_ctv, "mothership_parse_wormhole_tls_resumption_zero_rtt_failure_text");
    }

    suite.expect(rejected, "mothership_parse_wormhole_tls_resumption_rejects_zero_rtt");
  }

  {
    WormholeDNSConfig config {};
    String json = "{\"provider\":\"cloudflare\",\"credentialName\":\"cf-prod\",\"zone\":\"example.com\",\"name\":\"api.example.com\",\"type\":\"a\",\"ttl\":300}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    String failure;
    const bool parsedJSON = (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS);
    suite.expect(parsedJSON, "mothership_parse_wormhole_dns_json_valid");

    bool parsedField = false;
    if (parsedJSON)
    {
      parsedField = mothershipParseWormholeDNSConfig(doc, config, &failure);
    }

    suite.expect(parsedField, "mothership_parse_wormhole_dns_parses");
    suite.expect(failure.size() == 0, "mothership_parse_wormhole_dns_no_failure");
    suite.expect(config.provider.equal("cloudflare"_ctv), "mothership_parse_wormhole_dns_provider");
    suite.expect(config.credentialName.equal("cf-prod"_ctv), "mothership_parse_wormhole_dns_credential");
    suite.expect(config.type.equal("A"_ctv), "mothership_parse_wormhole_dns_normalizes_type");
    suite.expect(config.ttl == 300, "mothership_parse_wormhole_dns_ttl");
  }

  {
    WormholeDNSConfig config {};
    String json = "{\"bindingName\":\"api-binding\"}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    String failure;
    const bool parsedJSON = (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS);
    suite.expect(parsedJSON, "mothership_parse_wormhole_dns_binding_json_valid");

    bool parsedField = false;
    if (parsedJSON)
    {
      parsedField = mothershipParseWormholeDNSConfig(doc, config, &failure);
    }

    suite.expect(parsedField, "mothership_parse_wormhole_dns_binding_parses");
    suite.expect(failure.size() == 0, "mothership_parse_wormhole_dns_binding_no_failure");
    suite.expect(config.bindingName.equal("api-binding"_ctv), "mothership_parse_wormhole_dns_binding_name");
  }

  {
    WormholeDNSConfig config {};
    String json = "{\"provider\":\"cloudflare\",\"credentialName\":\"cf-prod\",\"zone\":\"example.com\",\"name\":\"api.example.com\",\"ttl\":0}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool rejected = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      String failure;
      rejected = (mothershipParseWormholeDNSConfig(doc, config, &failure) == false);
      suite.expect(failure == "wormhole.dns.ttl must be in 1..4294967295"_ctv, "mothership_parse_wormhole_dns_zero_ttl_failure_text");
    }

    suite.expect(rejected, "mothership_parse_wormhole_dns_rejects_zero_ttl");
  }

  {
    WormholeDNSConfig config {};
    String json = "{\"provider\":\"cloudflare\",\"credentialName\":\"cf-prod\",\"zone\":\"example.com\",\"name\":\"api.example.com\",\"ttl\":300,\"values\":[\"203.0.113.1\"]}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool rejected = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      String failure;
      rejected = (mothershipParseWormholeDNSConfig(doc, config, &failure) == false);
      suite.expect(failure == "wormhole.dns values are derived from the claimed address"_ctv, "mothership_parse_wormhole_dns_rejects_values_failure_text");
    }

    suite.expect(rejected, "mothership_parse_wormhole_dns_rejects_values");
  }

  {
    WormholePublicTLSConfig config {};
    bool enabled = false;
    String json = "true"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    String failure;
    bool parsedField = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      parsedField = mothershipParseWormholePublicTLSConfig(doc, config, enabled, &failure);
    }

    suite.expect(parsedField && enabled, "mothership_parse_wormhole_public_tls_bool_enables");
    suite.expect(config.issuer.equal("letsencrypt"_ctv), "mothership_parse_wormhole_public_tls_bool_default_issuer");
    suite.expect(config.keyType.equal("ecdsa"_ctv), "mothership_parse_wormhole_public_tls_bool_default_key_type");
    suite.expect(config.renewAfterLifetimePermille == prodigyDefaultCertificateRenewAfterLifetimePermille, "mothership_parse_wormhole_public_tls_bool_default_renew_after");
    suite.expect(failure.size() == 0, "mothership_parse_wormhole_public_tls_bool_no_failure");
  }

  {
    WormholePublicTLSConfig config {};
    bool enabled = false;
    String json =
        "{\"enabled\":true,\"identityName\":\"api-public\",\"issuer\":\"letsencrypt\",\"domains\":[\"api.example.com\",\"*.example.com\"],\"keyType\":\"ecdsa\",\"staging\":true,\"renewAfterLifetimePermille\":667}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    String failure;
    bool parsedField = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      parsedField = mothershipParseWormholePublicTLSConfig(doc, config, enabled, &failure);
    }

    suite.expect(parsedField && enabled, "mothership_parse_wormhole_public_tls_object_parses");
    suite.expect(config.identityName.equal("api-public"_ctv), "mothership_parse_wormhole_public_tls_identity");
    suite.expect(config.domains.size() == 2, "mothership_parse_wormhole_public_tls_domains");
    suite.expect(config.domains.size() == 2 && config.domains[1].equal("*.example.com"_ctv), "mothership_parse_wormhole_public_tls_wildcard_domain");
    suite.expect(config.staging, "mothership_parse_wormhole_public_tls_staging");
    suite.expect(config.renewAfterLifetimePermille == 667, "mothership_parse_wormhole_public_tls_renew_after");
    suite.expect(failure.size() == 0, "mothership_parse_wormhole_public_tls_no_failure");
  }

  {
    WormholePublicTLSConfig config {};
    bool enabled = false;
    String json = "{\"keyType\":\"ed25519\"}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool rejected = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      String failure;
      rejected = (mothershipParseWormholePublicTLSConfig(doc, config, enabled, &failure) == false);
      suite.expect(failure == "wormhole.publicTLS.keyType must be ecdsa or rsa"_ctv, "mothership_parse_wormhole_public_tls_key_type_failure_text");
    }

    suite.expect(rejected, "mothership_parse_wormhole_public_tls_rejects_key_type");
  }

  {
    WormholePublicTLSConfig config {};
    bool enabled = false;
    String json = "{\"identityName\":\"../bad\"}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool rejected = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      String failure;
      rejected = (mothershipParseWormholePublicTLSConfig(doc, config, enabled, &failure) == false);
      suite.expect(failure == "wormhole.publicTLS.identityName must be a safe path segment"_ctv, "mothership_parse_wormhole_public_tls_identity_name_failure_text");
    }

    suite.expect(rejected, "mothership_parse_wormhole_public_tls_rejects_unsafe_identity_name");
  }

  {
    WormholePublicTLSConfig config {};
    bool enabled = false;
    String json = "{\"renewAfterLifetimePermille\":1000}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    bool rejected = false;
    if (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS)
    {
      String failure;
      rejected = (mothershipParseWormholePublicTLSConfig(doc, config, enabled, &failure) == false);
      suite.expect(failure == "wormhole.publicTLS.renewAfterLifetimePermille must be in 1..999"_ctv, "mothership_parse_wormhole_public_tls_renew_after_failure_text");
    }

    suite.expect(rejected, "mothership_parse_wormhole_public_tls_rejects_renew_after");
  }

  {
    DeploymentPlan plan {};
    String json = "{\"useHostNetworkNamespace\":\"yes\"}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);

    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    const bool parsedJSON = (parser.parse(json.data(), json.size()).get(doc) == simdjson::SUCCESS);
    suite.expect(parsedJSON, "mothership_parse_use_host_network_namespace_invalid_json_valid");

    bool rejected = false;
    if (parsedJSON)
    {
      for (auto field : doc.get_object())
      {
        String key;
        key.setInvariant(field.key.data(), field.key.size());
        if (key == "useHostNetworkNamespace"_ctv)
        {
          String failure;
          rejected = (mothershipParseDeploymentPlanUseHostNetworkNamespace(field.value, plan, &failure) == false);
          suite.expect(rejected, "mothership_parse_use_host_network_namespace_rejects_non_bool");
          suite.expect(failure == "useHostNetworkNamespace requires a bool"_ctv, "mothership_parse_use_host_network_namespace_failure_text");
        }
      }
    }

    suite.expect(rejected, "mothership_parse_use_host_network_namespace_invalid_type_detected");
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.nTargetBase = 3;
    deployment.nTargetSurge = 2;
    deployment.nTargetCanary = 1;

    deployment.nDeployedBase = 2;
    deployment.nDeployedSurge = 1;
    deployment.nDeployedCanary = 1;

    deployment.nHealthyBase = 2;
    deployment.nHealthySurge = 1;
    deployment.nHealthyCanary = 0;

    suite.expect(deployment.nTarget() == 6, "deployment_nTarget_sum");
    suite.expect(deployment.nDeployed() == 4, "deployment_nDeployed_sum");
    suite.expect(deployment.nHealthy() == 3, "deployment_nHealthy_sum");
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);

    uint32_t fit = ApplicationDeployment::nFitOntoResources(&deployment, 9, 0, 4096, 4096, {}, 10);
    suite.expect(fit == 4, "nFitOntoResources_core_bound");

    fit = ApplicationDeployment::nFitOntoResources(&deployment, 99, 0, 0, 99, {}, 10);
    suite.expect(fit == 0, "nFitOntoResources_zero_memory");
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);

    Rack rack {};
    rack.uuid = 77;

    Machine machine;
    machine.slug = "dev-baremetal"_ctv;
    machine.rack = &rack;
    machine.nLogicalCores_available = 8;
    machine.memoryMB_available = 4096;
    machine.storageMB_available = 4096;

    uint32_t fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 20);
    suite.expect(fit == 4, "nFitOnMachine_resource_bound");

    MachineResourcesDelta negativeDelta {};
    negativeDelta.nLogicalCores = -16;
    fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 20, negativeDelta);
    suite.expect(fit == 0, "nFitOnMachine_negative_delta_clamped");
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.minGPUs = 2;
    deployment.plan.config.gpuMemoryGB = 16;

    Rack rack {};
    rack.uuid = 7701;

    Machine machine;
    machine.slug = "gpu-capable"_ctv;
    machine.rack = &rack;
    machine.nLogicalCores_available = 32;
    machine.memoryMB_available = 64'000;
    machine.storageMB_available = 64'000;
    machine.hardware.gpus.push_back(MachineGpuHardwareProfile {.memoryMB = 16 * 1024u});
    machine.hardware.gpus.push_back(MachineGpuHardwareProfile {.memoryMB = 16 * 1024u});
    machine.resetAvailableGPUMemoryMBsFromHardware();

    uint32_t fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 4);
    suite.expect(fit == 1, "nFitOnMachine_gpu_criteria_accepts_machine_capability_and_available_gpus");

    machine.availableGPUMemoryMBs.erase(machine.availableGPUMemoryMBs.begin());
    fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 4);
    suite.expect(fit == 0, "nFitOnMachine_gpu_criteria_rejects_when_available_gpus_consumed");

    machine.hardware.gpus[1].memoryMB = 12 * 1024u;
    machine.resetAvailableGPUMemoryMBsFromHardware();
    fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 4);
    suite.expect(fit == 0, "nFitOnMachine_gpu_criteria_rejects_machine_without_required_per_gpu_memory");
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.nicSpeedGbps = 10;
    deployment.plan.config.minInternetDownloadMbps = 800;
    deployment.plan.config.minInternetUploadMbps = 400;
    deployment.plan.config.maxInternetLatencyMs = 25;

    Rack rack {};
    rack.uuid = 7702;

    Machine machine;
    machine.slug = "network-qualified"_ctv;
    machine.rack = &rack;
    machine.nLogicalCores_available = 8;
    machine.memoryMB_available = 4096;
    machine.storageMB_available = 4096;
    machine.hasInternetAccess = true;
    machine.hardware.network.nics.push_back(MachineNicHardwareProfile {.linkSpeedMbps = 25'000});
    machine.hardware.network.internet.attempted = true;
    machine.hardware.network.internet.downloadMbps = 900;
    machine.hardware.network.internet.uploadMbps = 500;
    machine.hardware.network.internet.latencyMs = 15;

    uint32_t fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 4);
    suite.expect(fit == 4, "nFitOnMachine_machine_resource_criteria_accepts_matching_nic_and_internet_profile");

    machine.hardware.network.nics[0].linkSpeedMbps = 1000;
    fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 4);
    suite.expect(fit == 0, "nFitOnMachine_machine_resource_criteria_rejects_insufficient_nic_speed");

    machine.hardware.network.nics[0].linkSpeedMbps = 25'000;
    machine.hardware.network.internet.downloadMbps = 600;
    fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 4);
    suite.expect(fit == 0, "nFitOnMachine_machine_resource_criteria_rejects_insufficient_internet_download");

    machine.hardware.network.internet.downloadMbps = 900;
    machine.hardware.network.internet.latencyMs = 40;
    fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 4);
    suite.expect(fit == 0, "nFitOnMachine_machine_resource_criteria_rejects_excessive_internet_latency");
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rack {};
    rack.uuid = 7801;

    Machine worker;
    worker.uuid = uint128_t(0x1001);
    worker.fragment = 0x000011u;
    worker.slug = "worker-private"_ctv;
    worker.rack = &rack;
    worker.state = MachineState::healthy;
    worker.nLogicalCores_available = 8;
    worker.memoryMB_available = 4096;
    worker.storageMB_available = 4096;

    worker.hasInternetAccess = true;
    worker.hardware.network.internet.sourceAddress = IPAddress("192.168.50.10", false);
    brain.machines.insert(&worker);

    MachineConfig workerConfig = {};
    workerConfig.slug = worker.slug;
    brain.brainConfig.configBySlug.insert_or_assign(worker.slug, workerConfig);

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);

    Whitehole whitehole = {};
    whitehole.transport = ExternalAddressTransport::tcp;
    whitehole.family = ExternalAddressFamily::ipv4;
    whitehole.source = ExternalAddressSource::hostPublicAddress;
    deployment.plan.whiteholes.push_back(whitehole);

    uint32_t fit = ApplicationDeployment::nFitOnMachine(&deployment, &worker, 1);
    suite.expect(fit == 1, "nFitOnMachine_whitehole_host_public_accepts_machine_local_internet_source");

    worker.hasInternetAccess = false;
    fit = ApplicationDeployment::nFitOnMachine(&deployment, &worker, 1);
    suite.expect(fit == 0, "nFitOnMachine_whitehole_host_public_rejects_machine_without_internet_access");

    brain.brainConfig.runtimeEnvironment.test.enabled = true;
    worker.private4 = 0x0a00000a;
    worker.peerAddresses.push_back(ClusterMachinePeerAddress {"10.0.0.10"_ctv, 24});

    fit = ApplicationDeployment::nFitOnMachine(&deployment, &worker, 1);
    suite.expect(fit == 0, "nFitOnMachine_whitehole_host_public_rejects_private_test_peer_source");

    deployment.plan.whiteholes[0].family = ExternalAddressFamily::ipv6;
    worker.publicAddress = "2602:fac0:0:12ab:34cd::a"_ctv;
    fit = ApplicationDeployment::nFitOnMachine(&deployment, &worker, 1);
    suite.expect(fit == 1, "nFitOnMachine_whitehole_host_public_accepts_test_public_address_with_private_peers");

    deployment.plan.whiteholes[0].family = ExternalAddressFamily::ipv4;
    brain.brainConfig.runtimeEnvironment.test.enableFakeIpv4Boundary = true;
    fit = ApplicationDeployment::nFitOnMachine(&deployment, &worker, 1);
    suite.expect(fit == 1, "nFitOnMachine_whitehole_host_public_accepts_explicit_fake_ipv4_boundary");

    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rack {};
    rack.uuid = 7802;

    Machine worker;
    worker.uuid = uint128_t(0x1002);
    worker.fragment = 0x000012u;
    worker.slug = "worker-distributed"_ctv;
    worker.rack = &rack;
    worker.state = MachineState::healthy;
    worker.nLogicalCores_available = 8;
    worker.memoryMB_available = 4096;
    worker.storageMB_available = 4096;
    worker.hasInternetAccess = true;
    brain.machines.insert(&worker);

    MachineConfig workerConfig = {};
    workerConfig.slug = worker.slug;
    brain.brainConfig.configBySlug.insert_or_assign(worker.slug, workerConfig);

    DistributableExternalSubnet subnet = {};
    subnet.uuid = uint128_t(0x78020001);
    subnet.name = "whitehole-ipv4"_ctv;
    subnet.subnet.network = IPAddress("198.18.0.0", false);
    subnet.subnet.cidr = 24;
    subnet.subnet.canonicalize();
    subnet.usage = ExternalSubnetUsage::whiteholes;
    brain.brainConfig.distributableExternalSubnets.push_back(subnet);

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);

    Whitehole whitehole = {};
    whitehole.transport = ExternalAddressTransport::tcp;
    whitehole.family = ExternalAddressFamily::ipv4;
    whitehole.source = ExternalAddressSource::registeredRoutablePrefix;
    deployment.plan.whiteholes.push_back(whitehole);

    uint32_t fit = ApplicationDeployment::nFitOnMachine(&deployment, &worker, 1);
    suite.expect(fit == 1, "nFitOnMachine_whitehole_registered_prefix_accepts_whitehole_prefix_usage");

    RoutableResourceLeaseOwner ownerA = {};
    ownerA.applicationID = 7821;
    ownerA.deploymentID = 780'210'001;
    ownerA.lineageID = ownerA.applicationID;
    Whitehole first = whitehole;
    suite.expect(ApplicationDeployment::resolveWhiteholeSourceAddressForScheduling(&worker, first, nullptr, nullptr, &ownerA),
                 "whitehole_registered_prefix_resolves_address");
    suite.expect(first.address.equals(IPAddress("198.18.0.1", false)), "whitehole_registered_prefix_uses_first_host_address");
    suite.expect(ApplicationDeployment::allocateWhiteholeSourcePort(first), "whitehole_registered_prefix_allocates_first_source_port");
    suite.expect(first.sourcePort == 49'152, "whitehole_registered_prefix_first_port_is_ephemeral_floor");
    suite.expect(deployment.reserveWhiteholeAddressPortLease(first, ownerA), "whitehole_registered_prefix_reserves_ip_port");
    suite.expect(brain.routableResourceLeaseRuntimeState[0].registeredPrefixUUID == subnet.uuid, "whitehole_registered_prefix_lease_records_prefix_uuid");

    RoutableResourceLeaseOwner ownerB = {};
    ownerB.applicationID = 7822;
    ownerB.deploymentID = 780'220'001;
    ownerB.lineageID = ownerB.applicationID;
    Whitehole second = whitehole;
    suite.expect(ApplicationDeployment::resolveWhiteholeSourceAddressForScheduling(&worker, second, nullptr, nullptr, &ownerB),
                 "whitehole_registered_prefix_resolves_shared_address");
    suite.expect(second.address.equals(first.address), "whitehole_registered_prefix_shares_address");
    suite.expect(ApplicationDeployment::allocateWhiteholeSourcePort(second), "whitehole_registered_prefix_allocates_next_source_port");
    suite.expect(second.sourcePort == uint16_t(first.sourcePort + 1), "whitehole_registered_prefix_shares_address_with_unique_port");
    suite.expect(deployment.reserveWhiteholeAddressPortLease(second, ownerB), "whitehole_registered_prefix_reserves_shared_ip_distinct_port");

    brain.brainConfig.distributableExternalSubnets[0].usage = ExternalSubnetUsage::wormholes;
    fit = ApplicationDeployment::nFitOnMachine(&deployment, &worker, 1);
    suite.expect(fit == 0, "nFitOnMachine_whitehole_registered_prefix_rejects_wormhole_only_prefix_usage");

    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack hostRack {};
    hostRack.uuid = 7803;
    Rack otherRack {};
    otherRack.uuid = 7804;

    Machine host {};
    host.uuid = uint128_t(0x1003);
    host.fragment = 0x000013u;
    host.slug = "wormhole-host"_ctv;
    host.rack = &hostRack;
    host.state = MachineState::healthy;
    host.nLogicalCores_available = 8;
    host.memoryMB_available = 4096;
    host.storageMB_available = 4096;
    brain.machines.insert(&host);

    Machine other {};
    other.uuid = uint128_t(0x1004);
    other.fragment = 0x000014u;
    other.slug = "wormhole-other"_ctv;
    other.rack = &otherRack;
    other.state = MachineState::healthy;
    other.nLogicalCores_available = 8;
    other.memoryMB_available = 4096;
    other.storageMB_available = 4096;
    brain.machines.insert(&other);

    DistributableExternalSubnet registered = {};
    registered.uuid = uint128_t(0xABCD1004);
    registered.name = "wormhole-route"_ctv;
    registered.machineUUID = host.uuid;
    registered.ingressScope = RoutableIngressScope::singleMachine;
    registered.usage = ExternalSubnetUsage::wormholes;
    registered.subnet = IPPrefix("2001:db8:100::44", true, 128);
    brain.brainConfig.distributableExternalSubnets.push_back(registered);

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);

    Wormhole wormhole = {};
    wormhole.externalPort = 443;
    wormhole.containerPort = 8443;
    wormhole.layer4 = IPPROTO_UDP;
    wormhole.isQuic = true;
    wormhole.source = ExternalAddressSource::registeredRoutablePrefix;
    wormhole.routablePrefixUUID = registered.uuid;
    deployment.plan.wormholes.push_back(wormhole);

    uint32_t fit = ApplicationDeployment::nFitOnMachine(&deployment, &host, 1);
    suite.expect(fit == 1, "nFitOnMachine_wormhole_registered_routable_address_accepts_owning_machine");

    fit = ApplicationDeployment::nFitOnMachine(&deployment, &other, 1);
    suite.expect(fit == 0, "nFitOnMachine_wormhole_registered_routable_address_rejects_non_owning_machine");

    thisBrain = savedBrain;
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);

    Rack rack {};
    rack.uuid = 78;

    Machine machine;
    machine.slug = "dev-baremetal"_ctv;
    machine.rack = &rack;
    machine.nLogicalCores_available = 10'000;
    machine.memoryMB_available = 10'000'000;
    machine.storageMB_available = 10'000'000;

    Vector<ContainerView *> seededContainers;
    for (uint32_t index = 0; index < 255; ++index)
    {
      ContainerView *container = new ContainerView();
      container->deploymentID = deployment.plan.config.deploymentID();
      machine.upsertContainerIndexEntry(container->deploymentID, container);
      seededContainers.push_back(container);
    }

    uint32_t fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 10);
    suite.expect(fit == 1, "nFitOnMachine_container_slot_budget_one_remaining");

    ContainerView *finalContainer = new ContainerView();
    finalContainer->deploymentID = deployment.plan.config.deploymentID();
    machine.upsertContainerIndexEntry(finalContainer->deploymentID, finalContainer);
    seededContainers.push_back(finalContainer);

    fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 10);
    suite.expect(fit == 0, "nFitOnMachine_container_slot_budget_exhausted");

    for (ContainerView *container : seededContainers)
    {
      machine.removeContainerIndexEntry(container->deploymentID, container);
      delete container;
    }
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);

    Rack rack {};
    rack.uuid = 79;

    Machine machine;
    machine.slug = "dev-baremetal"_ctv;
    machine.rack = &rack;
    machine.nLogicalCores_available = 10'000;
    machine.memoryMB_available = 10'000'000;
    machine.storageMB_available = 10'000'000;

    Machine::Claim claim {};
    claim.nFit = 255;
    machine.claims.push_back(claim);

    uint32_t fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 10);
    suite.expect(fit == 1, "nFitOnMachine_pending_claims_consume_container_slots");

    machine.claims[0].nFit = Machine::maxSchedulableContainers;
    fit = ApplicationDeployment::nFitOnMachine(&deployment, &machine, 10);
    suite.expect(fit == 0, "nFitOnMachine_pending_claims_exhaust_container_slots");
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.nTargetBase = 10;
    deployment.plan.stateless.maxPerRackRatio = 0.5f; // ceil(10 * 0.5) = 5
    deployment.plan.stateless.maxPerMachineRatio = 0.2f; // ceil(10 * 0.2) = 2

    Rack rack {};
    rack.uuid = 88;

    Machine machine;
    machine.slug = "dev-baremetal"_ctv;
    machine.rack = &rack;

    deployment.countPerRack[&rack] = 3;
    deployment.countPerMachine[&machine] = 1;

    uint32_t budget = ApplicationDeployment::clampBudgetByRackAndMachine(&deployment, &machine, 99);
    suite.expect(budget == 2, "clampBudgetByRackAndMachine_min_budget");

    deployment.countPerRack[&rack] = 5;
    budget = ApplicationDeployment::clampBudgetByRackAndMachine(&deployment, &machine, 99);
    suite.expect(budget == 0, "clampBudgetByRackAndMachine_exhausted_rack");

    deployment.plan.stateless.maxPerRackRatio = 0.0f;
    deployment.plan.stateless.maxPerMachineRatio = 0.0f;
    budget = ApplicationDeployment::clampBudgetByRackAndMachine(&deployment, &machine, 99);
    suite.expect(budget == 0, "clampBudgetByRackAndMachine_zero_ratio");

    deployment.nTargetBase = 3;
    deployment.plan.stateless.maxPerRackRatio = 0.01f;
    deployment.plan.stateless.maxPerMachineRatio = 0.01f;
    deployment.countPerRack[&rack] = 0;
    deployment.countPerMachine[&machine] = 0;
    budget = ApplicationDeployment::clampBudgetByRackAndMachine(&deployment, &machine, 99);
    suite.expect(budget == 1, "clampBudgetByRackAndMachine_minimum_one_when_nonzero_ratio");
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.nTargetBase = 4;

    Rack rack {};
    rack.uuid = 99;

    Machine machine;
    machine.slug = "dev-baremetal"_ctv;
    machine.rack = &rack;
    machine.nLogicalCores_available = 8;
    machine.memoryMB_available = 4096;
    machine.storageMB_available = 4096;

    MachineTicket ticket {};
    uint32_t fit = deployment.nFitOnMachineClaim(&ticket, &machine, 3);

    suite.expect(fit == 3, "nFitOnMachineClaim_stateless_fit");
    suite.expect(machine.claims.size() == 1, "nFitOnMachineClaim_stateless_claim_recorded");
    suite.expect(machine.claims[0].ticket == &ticket, "nFitOnMachineClaim_stateless_ticket_linked");
    suite.expect(deployment.countPerMachine.getIf(&machine) == 3, "nFitOnMachineClaim_stateless_counts_machine");
    suite.expect(deployment.countPerRack.getIf(&rack) == 3, "nFitOnMachineClaim_stateless_counts_rack");
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack hostRack {};
    hostRack.uuid = 1002;
    Rack otherRack {};
    otherRack.uuid = 1003;

    Machine host {};
    host.uuid = uint128_t(0x2201);
    host.fragment = 0x000021u;
    host.slug = "claim-host"_ctv;
    host.rack = &hostRack;
    host.state = MachineState::healthy;
    host.nLogicalCores_available = 8;
    host.memoryMB_available = 4096;
    host.storageMB_available = 4096;

    Machine other {};
    other.uuid = uint128_t(0x2202);
    other.fragment = 0x000022u;
    other.slug = "claim-other"_ctv;
    other.rack = &otherRack;
    other.state = MachineState::healthy;
    other.nLogicalCores_available = 8;
    other.memoryMB_available = 4096;
    other.storageMB_available = 4096;

    DistributableExternalSubnet registered = {};
    registered.uuid = uint128_t(0x2203);
    registered.name = "claim-route"_ctv;
    registered.machineUUID = host.uuid;
    registered.ingressScope = RoutableIngressScope::singleMachine;
    registered.usage = ExternalSubnetUsage::wormholes;
    registered.subnet = IPPrefix("2001:db8:100::45", true, 128);
    brain.brainConfig.distributableExternalSubnets.push_back(registered);

    ApplicationDeployment hostDeployment;
    seedCommonPlan(hostDeployment, false);
    hostDeployment.nTargetBase = 2;

    Wormhole wormhole = {};
    wormhole.externalPort = 443;
    wormhole.containerPort = 8443;
    wormhole.layer4 = IPPROTO_UDP;
    wormhole.isQuic = true;
    wormhole.source = ExternalAddressSource::registeredRoutablePrefix;
    wormhole.routablePrefixUUID = registered.uuid;
    hostDeployment.plan.wormholes.push_back(wormhole);

    MachineTicket hostTicket {};
    uint32_t fit = hostDeployment.nFitOnMachineClaim(&hostTicket, &host, 2);
    suite.expect(fit == 2, "nFitOnMachineClaim_wormhole_registered_routable_address_claims_owning_machine");

    ApplicationDeployment otherDeployment;
    seedCommonPlan(otherDeployment, false);
    otherDeployment.nTargetBase = 2;
    otherDeployment.plan.wormholes.push_back(wormhole);

    MachineTicket otherTicket {};
    fit = otherDeployment.nFitOnMachineClaim(&otherTicket, &other, 2);
    suite.expect(fit == 0, "nFitOnMachineClaim_wormhole_registered_routable_address_rejects_non_owning_machine");

    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;
    brain.brainConfig.runtimeEnvironment.test.enabled = true;
    brain.brainConfig.architecture = nametagCurrentBuildMachineArchitecture();

    Rack hostRack {};
    hostRack.uuid = 19'603'001;
    Rack receiverRack {};
    receiverRack.uuid = 19'603'002;
    brain.racks.insert_or_assign(hostRack.uuid, &hostRack);
    brain.racks.insert_or_assign(receiverRack.uuid, &receiverRack);

    ScopedSocketPair hostSocket = {};
    ScopedSocketPair receiverSocket = {};
    Machine host {};
    Machine receiver {};
    bool machinesReady =
        hostSocket.create(suite, "deploy_single_machine_prefix_compaction_seeds_host_socket") &&
        seedSchedulableMachine(brain, hostRack, host, uint128_t(0x19603001), 0x0a000301, "single-prefix-host"_ctv, hostSocket) &&
        receiverSocket.create(suite, "deploy_single_machine_prefix_compaction_seeds_receiver_socket") &&
        seedSchedulableMachine(brain, receiverRack, receiver, uint128_t(0x19603002), 0x0a000302, "single-prefix-receiver"_ctv, receiverSocket);
    suite.expect(machinesReady, "deploy_single_machine_prefix_compaction_seeds_machines");

    host.fragment = 0x31;
    receiver.fragment = 0x32;
    host.isolatedLogicalCoresCommitted = host.ownedLogicalCores;
    prodigyRecomputeMachineCPUAvailability(&host, brain.brainConfig.sharedCPUOvercommitPermille);

    DistributableExternalSubnet registered = {};
    registered.uuid = uint128_t(0x19603003);
    registered.name = "single-prefix-compaction-route"_ctv;
    registered.machineUUID = host.uuid;
    registered.ingressScope = RoutableIngressScope::singleMachine;
    registered.usage = ExternalSubnetUsage::wormholes;
    registered.subnet = IPPrefix("2001:db8:196::1", true, 128);
    brain.brainConfig.distributableExternalSubnets.push_back(registered);

    ApplicationDeployment donor;
    seedCommonPlan(donor, false);
    donor.plan.config.applicationID = 19'604;
    donor.plan.config.versionID = 1;
    donor.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
    donor.plan.config.nLogicalCores = 1;
    donor.plan.stateless.nBase = 1;
    donor.plan.stateless.moveableDuringCompaction = true;
    donor.plan.moveConstructively = true;
    donor.state = DeploymentState::running;
    donor.nTargetBase = 1;
    donor.nDeployedBase = 1;
    donor.nHealthyBase = 1;
    brain.deployments.insert_or_assign(donor.plan.config.deploymentID(), &donor);

    ContainerView *donorOriginal = new ContainerView();
    donorOriginal->uuid = uint128_t(0x19603004);
    donorOriginal->deploymentID = donor.plan.config.deploymentID();
    donorOriginal->applicationID = donor.plan.config.applicationID;
    donorOriginal->machine = &host;
    donorOriginal->lifetime = ApplicationLifetime::base;
    donorOriginal->state = ContainerState::healthy;
    donor.containers.insert(donorOriginal);
    donor.countPerMachine[&host] += 1;
    donor.countPerRack[&hostRack] += 1;
    brain.containers.insert_or_assign(donorOriginal->uuid, donorOriginal);
    host.upsertContainerIndexEntry(donorOriginal->deploymentID, donorOriginal);

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.applicationID = 19'603;
    deployment.plan.config.versionID = 1;
    deployment.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
    deployment.plan.config.nLogicalCores = 1;
    deployment.plan.stateless.nBase = 1;
    deployment.plan.moveConstructively = true;

    Wormhole wormhole = {};
    wormhole.externalPort = 443;
    wormhole.containerPort = 8443;
    wormhole.layer4 = IPPROTO_UDP;
    wormhole.isQuic = true;
    wormhole.source = ExternalAddressSource::registeredRoutablePrefix;
    wormhole.routablePrefixUUID = registered.uuid;
    deployment.plan.wormholes.push_back(wormhole);
    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

    if (machinesReady)
    {
      deployment.deploy();

      suite.expect(brain.requestMachinesCount == 0, "deploy_single_machine_prefix_compaction_does_not_request_new_machine");
      suite.expect(deployment.nDeployedBase == 1, "deploy_single_machine_prefix_compaction_plans_pinned_base");
      suite.expect(deployment.waitingOnCompactions, "deploy_single_machine_prefix_compaction_waits_on_donor_move");

      if (donor.schedulingStack.execution == nullptr && donor.toSchedule.empty() == false)
      {
        donor.schedule(nullptr);
      }

      ContainerView *donorReplacement = nullptr;
      for (ContainerView *container : donor.containers)
      {
        if (container != donorOriginal && container->machine == &receiver)
        {
          donorReplacement = container;
          break;
        }
      }
      if (donorReplacement == nullptr)
      {
        for (const auto& [uuid, container] : brain.containers)
        {
          (void)uuid;
          if (container != donorOriginal && container != nullptr && container->deploymentID == donor.plan.config.deploymentID() && container->machine == &receiver)
          {
            donorReplacement = container;
            break;
          }
        }
      }
      if (donorReplacement == nullptr)
      {
        for (const auto& [container, targetState] : donor.waitingOnContainers)
        {
          if (targetState == ContainerState::healthy && container != donorOriginal && container != nullptr && container->machine == &receiver)
          {
            donorReplacement = container;
            break;
          }
        }
      }
      if (donorReplacement == nullptr)
      {
        for (DeploymentWork *work : donor.toSchedule)
        {
          StatelessWork *stateless = std::get_if<StatelessWork>(work);
          if (stateless != nullptr && stateless->container != nullptr && stateless->container != donorOriginal && stateless->container->machine == &receiver)
          {
            donorReplacement = stateless->container;
            break;
          }
        }
      }
      if (donorReplacement != nullptr && donorReplacement->state == ContainerState::planned && donor.schedulingStack.execution == nullptr)
      {
        donor.schedule(nullptr);
      }

      suite.expect(donorReplacement != nullptr, "deploy_single_machine_prefix_compaction_plans_donor_replacement");
      suite.expect(donorReplacement == nullptr || donorReplacement->state == ContainerState::scheduled, "deploy_single_machine_prefix_compaction_dispatches_donor_replacement");

      if (donorReplacement != nullptr)
      {
        donor.containerIsHealthy(donorReplacement);
      }

      ContainerView *pinnedContainer = nullptr;
      for (ContainerView *container : deployment.containers)
      {
        if (container->machine == &host)
        {
          pinnedContainer = container;
          break;
        }
      }

      suite.expect(deployment.waitingOnCompactions == false, "deploy_single_machine_prefix_compaction_ticket_releases_orchestrator");
      suite.expect(pinnedContainer != nullptr, "deploy_single_machine_prefix_compaction_creates_pinned_container");
      suite.expect(pinnedContainer == nullptr || pinnedContainer->state == ContainerState::scheduled, "deploy_single_machine_prefix_compaction_dispatches_pinned_container");
      suite.expect(pinnedContainer == nullptr || host.containersByDeploymentID.hasEntryFor(pinnedContainer->deploymentID, pinnedContainer), "deploy_single_machine_prefix_compaction_indexes_pinned_container");

      if (pinnedContainer != nullptr)
      {
        deployment.containerIsHealthy(pinnedContainer);
        deployment.destructContainer(pinnedContainer);
        deployment.containerDestroyed(pinnedContainer);
      }

      if (donorOriginal != nullptr && donorOriginal->state == ContainerState::destroying)
      {
        donor.containerDestroyed(donorOriginal);
        donorOriginal = nullptr;
      }

      if (donorReplacement != nullptr && donor.containers.contains(donorReplacement))
      {
        donor.destructContainer(donorReplacement);
        donor.containerDestroyed(donorReplacement);
      }
    }

    if (donorOriginal != nullptr)
    {
      if (donor.containers.contains(donorOriginal))
      {
        donor.destructContainer(donorOriginal);
      }
      donor.containerDestroyed(donorOriginal);
      donorOriginal = nullptr;
    }

    brain.deployments.erase(deployment.plan.config.deploymentID());
    brain.deployments.erase(donor.plan.config.deploymentID());
    brain.brainConfig.distributableExternalSubnets.clear();
    receiverRack.machines.erase(&receiver);
    hostRack.machines.erase(&host);
    brain.machines.erase(&receiver);
    brain.machines.erase(&host);
    brain.racks.erase(receiverRack.uuid);
    brain.racks.erase(hostRack.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;
    brain.brainConfig.runtimeEnvironment.test.enabled = true;
    brain.brainConfig.architecture = nametagCurrentBuildMachineArchitecture();

    Rack rack {};
    rack.uuid = 19'603'021;
    brain.racks.insert_or_assign(rack.uuid, &rack);

    ScopedSocketPair socket = {};
    Machine host {};
    bool machineReady =
        socket.create(suite, "compaction_ticket_complete_starts_orchestrator_scheduler_socket") &&
        seedSchedulableMachine(brain, rack, host, uint128_t(0x19603021), 0x0a000321, "compaction-ticket-host"_ctv, socket);
    suite.expect(machineReady, "compaction_ticket_complete_starts_orchestrator_scheduler_seeds_machine");

    ApplicationDeployment orchestrator;
    seedCommonPlan(orchestrator, false);
    orchestrator.plan.config.applicationID = 19'621;
    orchestrator.plan.config.versionID = 1;
    orchestrator.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
    orchestrator.plan.config.nLogicalCores = 1;
    orchestrator.plan.stateless.nBase = 1;
    orchestrator.nTargetBase = 1;
    orchestrator.state = DeploymentState::deploying;
    brain.deployments.insert_or_assign(orchestrator.plan.config.deploymentID(), &orchestrator);

    ApplicationDeployment donor;
    seedCommonPlan(donor, false);
    donor.plan.config.applicationID = 19'622;
    donor.plan.config.versionID = 1;
    donor.plan.config.architecture = nametagCurrentBuildMachineArchitecture();

    CompactionTicket *ticket = new CompactionTicket();
    ticket->orchestrator = &orchestrator;
    ticket->pendingCompactions[&donor] = 1;

    orchestrator.scheduleCompactionWait(ticket);
    orchestrator.toSchedule.push_back(orchestrator.planStatelessConstruction(&host, ApplicationLifetime::base));

    DeploymentWork *donorWork = donor.planStatelessConstruction(&host, ApplicationLifetime::base);
    std::get<StatelessWork>(*donorWork).ticket = ticket;
    donor.toSchedule.push_back(donorWork);
    donor.schedule(nullptr);

    suite.expect(orchestrator.waitingOnCompactions == false, "compaction_ticket_complete_starts_orchestrator_scheduler_releases_wait");
    suite.expect(orchestrator.toSchedule.empty(), "compaction_ticket_complete_starts_orchestrator_scheduler_drains_queue");
    suite.expect(orchestrator.waitingOnContainers.size() == 1, "compaction_ticket_complete_starts_orchestrator_scheduler_dispatches_construct");

    ContainerView *container = nullptr;
    for (const auto& [waiting, targetState] : orchestrator.waitingOnContainers)
    {
      (void)targetState;
      container = waiting;
      break;
    }
    suite.expect(container != nullptr && container->state == ContainerState::scheduled, "compaction_ticket_complete_starts_orchestrator_scheduler_schedules_container");

    if (container != nullptr)
    {
      orchestrator.containerIsHealthy(container);
      orchestrator.destructContainer(container);
      orchestrator.containerDestroyed(container);
    }
    ContainerView *donorContainer = nullptr;
    for (const auto& [waiting, targetState] : donor.waitingOnContainers)
    {
      (void)targetState;
      donorContainer = waiting;
      break;
    }
    if (donorContainer != nullptr)
    {
      donor.containerIsHealthy(donorContainer);
      donor.destructContainer(donorContainer);
      donor.containerDestroyed(donorContainer);
    }

    brain.deployments.erase(orchestrator.plan.config.deploymentID());
    rack.machines.erase(&host);
    brain.machines.erase(&host);
    brain.racks.erase(rack.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;
    brain.brainConfig.runtimeEnvironment.test.enabled = true;
    brain.brainConfig.architecture = nametagCurrentBuildMachineArchitecture();

    Rack hostRack {};
    hostRack.uuid = 19'603'011;
    Rack receiverRack {};
    receiverRack.uuid = 19'603'012;
    brain.racks.insert_or_assign(hostRack.uuid, &hostRack);
    brain.racks.insert_or_assign(receiverRack.uuid, &receiverRack);

    ScopedSocketPair hostSocket = {};
    ScopedSocketPair receiverSocket = {};
    Machine host {};
    Machine receiver {};
    bool machinesReady =
        hostSocket.create(suite, "deploy_host_public_whitehole_compaction_rejects_unusable_donor_host_socket") &&
        seedSchedulableMachine(brain, hostRack, host, uint128_t(0x19603011), 0x0a000311, "host-public-whitehole-donor"_ctv, hostSocket) &&
        receiverSocket.create(suite, "deploy_host_public_whitehole_compaction_rejects_unusable_donor_receiver_socket") &&
        seedSchedulableMachine(brain, receiverRack, receiver, uint128_t(0x19603012), 0x0a000312, "host-public-whitehole-receiver"_ctv, receiverSocket);
    suite.expect(machinesReady, "deploy_host_public_whitehole_compaction_rejects_unusable_donor_seeds_machines");

    host.fragment = 0x311;
    receiver.fragment = 0x312;
    host.hasInternetAccess = false;
    receiver.hasInternetAccess = false;
    host.hardware.network.internet.sourceAddress = {};
    receiver.hardware.network.internet.sourceAddress = {};
    host.peerAddresses.push_back(ClusterMachinePeerAddress {"10.0.3.17"_ctv, 24});
    receiver.peerAddresses.push_back(ClusterMachinePeerAddress {"10.0.3.18"_ctv, 24});
    host.isolatedLogicalCoresCommitted = host.ownedLogicalCores;
    prodigyRecomputeMachineCPUAvailability(&host, brain.brainConfig.sharedCPUOvercommitPermille);

    ApplicationDeployment donor;
    seedCommonPlan(donor, false);
    donor.plan.config.applicationID = 19'614;
    donor.plan.config.versionID = 1;
    donor.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
    donor.plan.config.nLogicalCores = 1;
    donor.plan.stateless.nBase = 1;
    donor.plan.stateless.moveableDuringCompaction = true;
    donor.plan.moveConstructively = true;
    donor.state = DeploymentState::running;
    donor.nTargetBase = 1;
    donor.nDeployedBase = 1;
    donor.nHealthyBase = 1;
    brain.deployments.insert_or_assign(donor.plan.config.deploymentID(), &donor);

    ContainerView *donorOriginal = new ContainerView();
    donorOriginal->uuid = uint128_t(0x19603014);
    donorOriginal->deploymentID = donor.plan.config.deploymentID();
    donorOriginal->applicationID = donor.plan.config.applicationID;
    donorOriginal->machine = &host;
    donorOriginal->lifetime = ApplicationLifetime::base;
    donorOriginal->state = ContainerState::healthy;
    donor.containers.insert(donorOriginal);
    donor.countPerMachine[&host] += 1;
    donor.countPerRack[&hostRack] += 1;
    brain.containers.insert_or_assign(donorOriginal->uuid, donorOriginal);
    host.upsertContainerIndexEntry(donorOriginal->deploymentID, donorOriginal);

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.applicationID = 19'613;
    deployment.plan.config.versionID = 1;
    deployment.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
    deployment.plan.config.nLogicalCores = 1;
    deployment.plan.stateless.nBase = 1;
    deployment.plan.moveConstructively = true;

    Whitehole whitehole = {};
    whitehole.transport = ExternalAddressTransport::tcp;
    whitehole.family = ExternalAddressFamily::ipv4;
    whitehole.source = ExternalAddressSource::hostPublicAddress;
    deployment.plan.whiteholes.push_back(whitehole);
    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

    if (machinesReady)
    {
      deployment.nTargetBase = 1;
      deployment.state = DeploymentState::deploying;
      deployment.architect(nullptr, false, true, false);

      suite.expect(deployment.nDeployedBase == 0, "deploy_host_public_whitehole_compaction_rejects_unusable_donor_deploys_zero");
      suite.expect(deployment.toSchedule.empty(), "deploy_host_public_whitehole_compaction_rejects_unusable_donor_has_no_sentinel");
      suite.expect(deployment.waitingOnCompactions == false, "deploy_host_public_whitehole_compaction_rejects_unusable_donor_does_not_wait");
      suite.expect(donor.toSchedule.empty(), "deploy_host_public_whitehole_compaction_rejects_unusable_donor_leaves_donor_queue_empty");
      suite.expect(donor.waitingOnContainers.empty(), "deploy_host_public_whitehole_compaction_rejects_unusable_donor_leaves_donor_waiters_empty");
      suite.expect(donorOriginal->state == ContainerState::healthy, "deploy_host_public_whitehole_compaction_rejects_unusable_donor_keeps_original_healthy");
    }

    donor.containers.erase(donorOriginal);
    host.removeContainerIndexEntry(donorOriginal->deploymentID, donorOriginal);
    brain.containers.erase(donorOriginal->uuid);
    delete donorOriginal;

    brain.deployments.erase(deployment.plan.config.deploymentID());
    brain.deployments.erase(donor.plan.config.deploymentID());
    receiverRack.machines.erase(&receiver);
    hostRack.machines.erase(&host);
    brain.machines.erase(&receiver);
    brain.machines.erase(&host);
    brain.racks.erase(receiverRack.uuid);
    brain.racks.erase(hostRack.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;
    brain.brainConfig.runtimeEnvironment.test.enabled = true;
    brain.brainConfig.architecture = nametagCurrentBuildMachineArchitecture();

    Rack hostRack {};
    hostRack.uuid = 19'603'041;
    Rack receiverRack {};
    receiverRack.uuid = 19'603'042;
    brain.racks.insert_or_assign(hostRack.uuid, &hostRack);
    brain.racks.insert_or_assign(receiverRack.uuid, &receiverRack);

    ScopedSocketPair hostSocket = {};
    ScopedSocketPair receiverSocket = {};
    Machine host {};
    Machine receiver {};
    bool machinesReady =
        hostSocket.create(suite, "deploy_compaction_rejects_final_target_fit_host_socket") &&
        seedSchedulableMachine(brain, hostRack, host, uint128_t(0x19603041), 0x0a000341, "target-fit-donor"_ctv, hostSocket) &&
        receiverSocket.create(suite, "deploy_compaction_rejects_final_target_fit_receiver_socket") &&
        seedSchedulableMachine(brain, receiverRack, receiver, uint128_t(0x19603042), 0x0a000342, "target-fit-receiver"_ctv, receiverSocket);
    suite.expect(machinesReady, "deploy_compaction_rejects_final_target_fit_seeds_machines");

    host.fragment = 0x341;
    receiver.fragment = 0x342;
    host.hasInternetAccess = true;
    host.hardware.network.internet.attempted = true;
    host.hardware.network.internet.latencyMs = 10;
    host.hardware.network.internet.downloadMbps = 0;
    host.hardware.network.internet.uploadMbps = 100;
    host.hardware.network.internet.sourceAddress = IPAddress("2001:db8:196::41", true);
    host.isolatedLogicalCoresCommitted = host.ownedLogicalCores;
    prodigyRecomputeMachineCPUAvailability(&host, brain.brainConfig.sharedCPUOvercommitPermille);

    ApplicationDeployment donor;
    seedCommonPlan(donor, false);
    donor.plan.config.applicationID = 19'634;
    donor.plan.config.versionID = 1;
    donor.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
    donor.plan.config.nLogicalCores = 1;
    donor.plan.stateless.nBase = 1;
    donor.plan.stateless.moveableDuringCompaction = true;
    donor.plan.moveConstructively = true;
    donor.state = DeploymentState::running;
    donor.nTargetBase = 1;
    donor.nDeployedBase = 1;
    donor.nHealthyBase = 1;
    brain.deployments.insert_or_assign(donor.plan.config.deploymentID(), &donor);

    ContainerView *donorOriginal = new ContainerView();
    donorOriginal->uuid = uint128_t(0x19603044);
    donorOriginal->deploymentID = donor.plan.config.deploymentID();
    donorOriginal->applicationID = donor.plan.config.applicationID;
    donorOriginal->machine = &host;
    donorOriginal->lifetime = ApplicationLifetime::base;
    donorOriginal->state = ContainerState::healthy;
    donor.containers.insert(donorOriginal);
    donor.countPerMachine[&host] += 1;
    donor.countPerRack[&hostRack] += 1;
    brain.containers.insert_or_assign(donorOriginal->uuid, donorOriginal);
    host.upsertContainerIndexEntry(donorOriginal->deploymentID, donorOriginal);

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.applicationID = 19'633;
    deployment.plan.config.versionID = 1;
    deployment.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
    deployment.plan.config.nLogicalCores = 1;
    deployment.plan.config.minInternetDownloadMbps = 1;
    deployment.plan.stateless.nBase = 1;
    deployment.plan.moveConstructively = true;

    Whitehole whitehole = {};
    whitehole.transport = ExternalAddressTransport::tcp;
    whitehole.family = ExternalAddressFamily::ipv6;
    whitehole.source = ExternalAddressSource::hostPublicAddress;
    deployment.plan.whiteholes.push_back(whitehole);
    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

    if (machinesReady)
    {
      deployment.nTargetBase = 1;
      deployment.state = DeploymentState::deploying;
      deployment.architect(nullptr, false, true, false);

      suite.expect(deployment.nDeployedBase == 0, "deploy_compaction_rejects_final_target_fit_deploys_zero");
      suite.expect(deployment.toSchedule.empty(), "deploy_compaction_rejects_final_target_fit_has_no_sentinel");
      suite.expect(deployment.waitingOnCompactions == false, "deploy_compaction_rejects_final_target_fit_does_not_wait");
      suite.expect(donor.toSchedule.empty(), "deploy_compaction_rejects_final_target_fit_leaves_donor_queue_empty");
      suite.expect(donor.waitingOnContainers.empty(), "deploy_compaction_rejects_final_target_fit_leaves_donor_waiters_empty");
      suite.expect(donorOriginal->state == ContainerState::healthy, "deploy_compaction_rejects_final_target_fit_keeps_original_healthy");
    }

    donor.containers.erase(donorOriginal);
    host.removeContainerIndexEntry(donorOriginal->deploymentID, donorOriginal);
    brain.containers.erase(donorOriginal->uuid);
    delete donorOriginal;

    brain.deployments.erase(deployment.plan.config.deploymentID());
    brain.deployments.erase(donor.plan.config.deploymentID());
    receiverRack.machines.erase(&receiver);
    hostRack.machines.erase(&host);
    brain.machines.erase(&receiver);
    brain.machines.erase(&host);
    brain.racks.erase(receiverRack.uuid);
    brain.racks.erase(hostRack.uuid);
    thisBrain = savedBrain;
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.nTargetBase = 300;

    Rack rack {};
    rack.uuid = 100;

    Machine machine;
    machine.slug = "dev-baremetal"_ctv;
    machine.rack = &rack;
    machine.nLogicalCores_available = 10'000;
    machine.memoryMB_available = 10'000'000;
    machine.storageMB_available = 10'000'000;

    Vector<ContainerView *> seededContainers;
    for (uint32_t index = 0; index < 255; ++index)
    {
      ContainerView *container = new ContainerView();
      container->deploymentID = deployment.plan.config.deploymentID();
      machine.upsertContainerIndexEntry(container->deploymentID, container);
      seededContainers.push_back(container);
    }

    MachineTicket firstTicket {};
    uint32_t fit = deployment.nFitOnMachineClaim(&firstTicket, &machine, 10);
    suite.expect(fit == 1, "nFitOnMachineClaim_container_slot_budget_last_slot");
    suite.expect(machine.claims.size() == 1 && machine.claims[0].nFit == 1, "nFitOnMachineClaim_records_last_slot_claim");

    MachineTicket secondTicket {};
    fit = deployment.nFitOnMachineClaim(&secondTicket, &machine, 10);
    suite.expect(fit == 0, "nFitOnMachineClaim_container_slot_budget_exhausted");

    for (ContainerView *container : seededContainers)
    {
      machine.removeContainerIndexEntry(container->deploymentID, container);
      delete container;
    }
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.minGPUs = 1;
    deployment.plan.config.gpuMemoryGB = 24;
    deployment.nTargetBase = 4;

    Rack rack {};
    rack.uuid = 1001;

    Machine machine;
    machine.slug = "gpu-claim"_ctv;
    machine.rack = &rack;
    machine.nLogicalCores_available = 64;
    machine.memoryMB_available = 128'000;
    machine.storageMB_available = 128'000;
    MachineGpuHardwareProfile firstGPU = {};
    firstGPU.vendor = "nvidia"_ctv;
    firstGPU.model = "A10"_ctv;
    firstGPU.busAddress = "0000:17:00.0"_ctv;
    firstGPU.memoryMB = 24 * 1024u;
    machine.hardware.gpus.push_back(firstGPU);
    MachineGpuHardwareProfile secondGPU = {};
    secondGPU.vendor = "nvidia"_ctv;
    secondGPU.model = "A16"_ctv;
    secondGPU.busAddress = "0000:65:00.0"_ctv;
    secondGPU.memoryMB = 48 * 1024u;
    machine.hardware.gpus.push_back(secondGPU);
    machine.resetAvailableGPUMemoryMBsFromHardware();

    MachineTicket firstTicket {};
    uint32_t fit = deployment.nFitOnMachineClaim(&firstTicket, &machine, 3);
    suite.expect(fit == 2, "nFitOnMachineClaim_gpu_capacity_uses_whole_gpus");
    suite.expect(machine.claims.size() == 1, "nFitOnMachineClaim_gpu_capacity_claim_recorded");
    suite.expect(machine.claims[0].reservedGPUMemoryMBs.size() == 2, "nFitOnMachineClaim_gpu_capacity_reserves_each_gpu_whole");
    suite.expect(machine.claims[0].reservedGPUDevices.size() == 2, "nFitOnMachineClaim_gpu_capacity_reserves_gpu_device_identity");
    suite.expect(machine.claims[0].reservedGPUDevices[0].busAddress == "0000:17:00.0"_ctv && machine.claims[0].reservedGPUDevices[1].busAddress == "0000:65:00.0"_ctv, "nFitOnMachineClaim_gpu_capacity_preserves_gpu_bus_addresses");
    suite.expect(machine.availableGPUMemoryMBs.empty(), "nFitOnMachineClaim_gpu_capacity_consumes_all_free_gpus");
    suite.expect(machine.availableGPUHardwareIndexes.empty(), "nFitOnMachineClaim_gpu_capacity_consumes_all_free_gpu_indexes");

    MachineTicket secondTicket {};
    fit = deployment.nFitOnMachineClaim(&secondTicket, &machine, 1);
    suite.expect(fit == 0, "nFitOnMachineClaim_gpu_capacity_rejects_shared_gpu_overcommit");
  }

  {
    bytell_hash_map<String, MachineConfig> configBySlug;

    MachineConfig wide {};
    wide.slug = "wide"_ctv;
    wide.nLogicalCores = 4;
    wide.nMemoryMB = 2048;
    wide.nStorageMB = 128;
    configBySlug.insert_or_assign(wide.slug, wide);

    MachineConfig dense {};
    dense.slug = "dense"_ctv;
    dense.nLogicalCores = 8;
    dense.nMemoryMB = 2048;
    dense.nStorageMB = 256;
    configBySlug.insert_or_assign(dense.slug, dense);

    MachineConfig denseTie {};
    denseTie.slug = "dense-a"_ctv;
    denseTie.nLogicalCores = 8;
    denseTie.nMemoryMB = 2048;
    denseTie.nStorageMB = 256;
    configBySlug.insert_or_assign(denseTie.slug, denseTie);

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);

    String selectedSlug;
    const MachineConfig *selectedConfig = nullptr;
    bool found = Brain::selectScaleOutMachineConfig(configBySlug, deployment.plan.config, 3, selectedSlug, selectedConfig);

    suite.expect(found, "selectScaleOutMachineConfig_finds_resource_fit");
    suite.expect(selectedConfig != nullptr, "selectScaleOutMachineConfig_returns_machine_config");
    suite.expect(selectedSlug == "dense"_ctv, "selectScaleOutMachineConfig_prefers_lowest_waste_then_slug");
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;
    brain.brainConfig.sharedCPUOvercommitPermille = 1500;

    bytell_hash_map<String, MachineConfig> configBySlug;

    MachineConfig compact {};
    compact.slug = "compact"_ctv;
    compact.nLogicalCores = 4;
    compact.nMemoryMB = 4096;
    compact.nStorageMB = 256;
    configBySlug.insert_or_assign(compact.slug, compact);

    MachineConfig wide {};
    wide.slug = "wide"_ctv;
    wide.nLogicalCores = 6;
    wide.nMemoryMB = 4096;
    wide.nStorageMB = 256;
    configBySlug.insert_or_assign(wide.slug, wide);

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.cpuMode = ApplicationCPUMode::shared;
    deployment.plan.config.sharedCPUMillis = 1200;
    deployment.plan.config.nLogicalCores = 2;

    String selectedSlug;
    const MachineConfig *selectedConfig = nullptr;
    bool found = Brain::selectScaleOutMachineConfig(configBySlug, deployment.plan.config, 5, selectedSlug, selectedConfig);

    suite.expect(found, "selectScaleOutMachineConfig_shared_cpu_finds_resource_fit");
    suite.expect(selectedConfig != nullptr, "selectScaleOutMachineConfig_shared_cpu_returns_machine_config");
    suite.expect(selectedSlug == "compact"_ctv, "selectScaleOutMachineConfig_shared_cpu_uses_overcommit_capacity");

    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;
    brain.brainConfig.sharedCPUOvercommitPermille = 1500;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.cpuMode = ApplicationCPUMode::shared;
    deployment.plan.config.sharedCPUMillis = 1000;
    deployment.plan.config.nLogicalCores = 1;

    Machine machine = {};
    machine.ownedLogicalCores = 4;
    prodigyRecomputeMachineCPUAvailability(&machine, 1500);
    suite.expect(machine.sharedCPUMillis_available == 6000, "shared_cpu_overcommit_initial_shared_capacity");
    suite.expect(machine.nLogicalCores_available == 4, "shared_cpu_overcommit_initial_isolated_capacity");

    machine.sharedCPUMillisCommitted = 6000;
    prodigyRecomputeMachineCPUAvailability(&machine, 1500);
    suite.expect(machine.sharedCPUMillis_available == 0, "shared_cpu_overcommit_full_capacity_consumed");
    suite.expect(machine.nLogicalCores_available == 0, "shared_cpu_overcommit_full_capacity_removes_isolated_headroom");

    prodigyRecomputeMachineCPUAvailability(&machine, 1000);
    suite.expect(prodigyMachineUsesCPUOvercommit(&machine), "shared_cpu_overcommit_lowered_marks_machine_overcommitted");
    suite.expect(machine.sharedCPUMillis_available < 0, "shared_cpu_overcommit_lowered_leaves_negative_headroom");
    suite.expect(machine.sharedCPUMillisCommitted == 6000, "shared_cpu_overcommit_lowered_does_not_change_committed_shared_cpu");
    suite.expect(machine.isolatedLogicalCoresCommitted == 0, "shared_cpu_overcommit_lowered_does_not_move_isolated_cpu_ownership");

    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;
    brain.brainConfig.sharedCPUOvercommitPermille = 1500;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.cpuMode = ApplicationCPUMode::shared;
    deployment.plan.config.sharedCPUMillis = 1000;
    deployment.plan.config.nLogicalCores = 1;

    Rack rackA {};
    rackA.uuid = 2001;
    Rack rackB {};
    rackB.uuid = 2002;

    Machine overcommitted = {};
    overcommitted.uuid = uint128_t(0x2001);
    overcommitted.slug = "overcommitted"_ctv;
    overcommitted.rack = &rackA;
    overcommitted.ownedLogicalCores = 4;
    overcommitted.sharedCPUMillisCommitted = 4500;
    overcommitted.memoryMB_available = 8192;
    overcommitted.storageMB_available = 8192;
    prodigyRecomputeMachineCPUAvailability(&overcommitted, 1500);

    Machine healthy = {};
    healthy.uuid = uint128_t(0x2002);
    healthy.slug = "healthy"_ctv;
    healthy.rack = &rackB;
    healthy.ownedLogicalCores = 4;
    healthy.memoryMB_available = 8192;
    healthy.storageMB_available = 8192;
    prodigyRecomputeMachineCPUAvailability(&healthy, 1500);

    suite.expect(
        prodigySharedCPUSchedulingMachineComesBefore(&healthy, nullptr, &overcommitted, nullptr),
        "shared_cpu_machine_order_prefers_non_overcommitted_machine");

    MachineResourcesDelta healthyDelta = {};
    healthyDelta.sharedCPUMillis = -7000;
    suite.expect(
        prodigySharedCPUSchedulingMachineComesBefore(&overcommitted, nullptr, &healthy, &healthyDelta),
        "shared_cpu_machine_order_uses_effective_post_delta_state");
    thisBrain = savedBrain;
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);

    Rack rack {};
    rack.uuid = 123;

    Machine machine;
    machine.slug = "dev-baremetal"_ctv;
    machine.rack = &rack;
    machine.nLogicalCores_available = 8;
    machine.memoryMB_available = 4096;
    machine.storageMB_available = 4096;

    MachineTicket ticket {};
    ticket.shardGroups.push_back(11);
    ticket.shardGroups.push_back(22);

    uint32_t fit = deployment.nFitOnMachineClaim(&ticket, &machine, 2);
    suite.expect(fit == 2, "nFitOnMachineClaim_stateful_fit");
    suite.expect(ticket.shardGroups.size() == 0, "nFitOnMachineClaim_stateful_consumes_ticket_groups");
    suite.expect(deployment.racksByShardGroup[11].contains(&rack), "nFitOnMachineClaim_stateful_tracks_rack_11");
    suite.expect(deployment.racksByShardGroup[22].contains(&rack), "nFitOnMachineClaim_stateful_tracks_rack_22");
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);

    Rack rack {};
    rack.uuid = 124;

    Machine machine;
    machine.slug = "dev-baremetal"_ctv;
    machine.rack = &rack;
    machine.nLogicalCores_available = 8;
    machine.memoryMB_available = 4096;
    machine.storageMB_available = 4096;

    MachineTicket ticket {};
    ticket.shardGroups.push_back(11);
    ticket.shardGroups.push_back(22);
    deployment.racksByShardGroup[11].insert(&rack);

    uint32_t fit = deployment.nFitOnMachineClaim(&ticket, &machine, 2);
    suite.expect(fit == 1, "nFitOnMachineClaim_stateful_skips_existing_rack_group");
    suite.expect(ticket.shardGroups.size() == 1, "nFitOnMachineClaim_stateful_leaves_unmoved_groups");
    suite.expect(ticket.shardGroups[0] == 11, "nFitOnMachineClaim_stateful_preserves_conflicting_group");
    suite.expect(deployment.racksByShardGroup[22].contains(&rack), "nFitOnMachineClaim_stateful_tracks_new_group_only");
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.nTargetBase = 4;
    deployment.plan.stateless.maxPerRackRatio = 1.0f;
    deployment.plan.stateless.maxPerMachineRatio = 0.25f;

    Rack rack {};
    rack.uuid = 125;

    Machine machine;
    machine.slug = "dev-baremetal"_ctv;
    machine.rack = &rack;
    machine.nLogicalCores_available = 8;
    machine.memoryMB_available = 4096;
    machine.storageMB_available = 4096;

    deployment.countPerMachine[&machine] = 1;
    deployment.countPerRack[&rack] = 0;

    MachineTicket ticket {};
    uint32_t fit = deployment.nFitOnMachineClaim(&ticket, &machine, 3);
    suite.expect(fit == 0, "nFitOnMachineClaim_stateless_machine_ratio_budget_zero");
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.nTargetBase = 2;

    Rack rack {};
    Machine machine;
    machine.slug = "other-type"_ctv;
    machine.rack = &rack;
    machine.nLogicalCores_available = 8;
    machine.memoryMB_available = 4096;
    machine.storageMB_available = 4096;

    MachineTicket ticket {};
    uint32_t fit = deployment.nFitOnMachineClaim(&ticket, &machine, 2);
    suite.expect(fit == 2, "nFitOnMachineClaim_ignores_machine_slug_when_resources_fit");
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);

    uint32_t fit = ApplicationDeployment::nFitOntoResources(&deployment, 200, 0, 200'000, 63, {}, 200);
    suite.expect(fit == 0, "nFitOntoResources_storage_bound");
  }

  {
    ApplicationDeployment deployment;
    deployment.plan.moveConstructively = true;

    DeploymentWork cwork;
    cwork.emplace<StatelessWork>();
    std::get<StatelessWork>(cwork).lifecycle = LifecycleOp::construct;
    DeploymentWork dwork;
    dwork.emplace<StatelessWork>();
    std::get<StatelessWork>(dwork).lifecycle = LifecycleOp::destruct;

    deployment.scheduleConstructionDestruction(&cwork, &dwork);

    suite.expect(deployment.toSchedule.size() == 2, "scheduleConstructionDestruction_constructive_count");
    suite.expect(deployment.toSchedule[0] == &cwork && deployment.toSchedule[1] == &dwork, "scheduleConstructionDestruction_constructive_order");
    suite.expect(std::get<StatelessWork>(cwork).next == &dwork, "scheduleConstructionDestruction_constructive_next");
    suite.expect(std::get<StatelessWork>(dwork).prev == &cwork, "scheduleConstructionDestruction_constructive_prev");
  }

  {
    ApplicationDeployment deployment;
    deployment.plan.moveConstructively = false;

    DeploymentWork cwork;
    cwork.emplace<StatelessWork>();
    std::get<StatelessWork>(cwork).lifecycle = LifecycleOp::construct;
    DeploymentWork dwork;
    dwork.emplace<StatelessWork>();
    std::get<StatelessWork>(dwork).lifecycle = LifecycleOp::destruct;

    deployment.scheduleConstructionDestruction(&cwork, &dwork);

    suite.expect(deployment.toSchedule.size() == 2, "scheduleConstructionDestruction_destructive_count");
    suite.expect(deployment.toSchedule[0] == &dwork && deployment.toSchedule[1] == &cwork, "scheduleConstructionDestruction_destructive_order");
    suite.expect(std::get<StatelessWork>(dwork).next == &cwork, "scheduleConstructionDestruction_destructive_next");
    suite.expect(std::get<StatelessWork>(cwork).prev == &dwork, "scheduleConstructionDestruction_destructive_prev");
  }

  {
    ApplicationDeployment deployment;
    deployment.plan.moveConstructively = true;

    DeploymentWork cwork;
    cwork.emplace<StatefulWork>();
    std::get<StatefulWork>(cwork).lifecycle = LifecycleOp::construct;
    DeploymentWork dwork;
    dwork.emplace<StatefulWork>();
    std::get<StatefulWork>(dwork).lifecycle = LifecycleOp::destruct;

    deployment.scheduleConstructionDestruction(&cwork, &dwork);

    suite.expect(deployment.toSchedule.size() == 2, "scheduleConstructionDestruction_stateful_constructive_count");
    suite.expect(deployment.toSchedule[0] == &cwork && deployment.toSchedule[1] == &dwork, "scheduleConstructionDestruction_stateful_constructive_order");
    suite.expect(std::get<StatefulWork>(cwork).next == &dwork, "scheduleConstructionDestruction_stateful_constructive_next");
    suite.expect(std::get<StatefulWork>(dwork).prev == &cwork, "scheduleConstructionDestruction_stateful_constructive_prev");
  }

  {
    ApplicationDeployment deployment;
    deployment.plan.moveConstructively = false;

    DeploymentWork cwork;
    cwork.emplace<StatefulWork>();
    std::get<StatefulWork>(cwork).lifecycle = LifecycleOp::construct;
    DeploymentWork dwork;
    dwork.emplace<StatefulWork>();
    std::get<StatefulWork>(dwork).lifecycle = LifecycleOp::destruct;

    deployment.scheduleConstructionDestruction(&cwork, &dwork);

    suite.expect(deployment.toSchedule.size() == 2, "scheduleConstructionDestruction_stateful_destructive_count");
    suite.expect(deployment.toSchedule[0] == &dwork && deployment.toSchedule[1] == &cwork, "scheduleConstructionDestruction_stateful_destructive_order");
    suite.expect(std::get<StatefulWork>(dwork).next == &cwork, "scheduleConstructionDestruction_stateful_destructive_next");
    suite.expect(std::get<StatefulWork>(cwork).prev == &dwork, "scheduleConstructionDestruction_stateful_destructive_prev");
  }

  {
    ApplicationDeployment deployment;

    DeploymentWork cwork;
    cwork.emplace<StatelessWork>();
    std::get<StatelessWork>(cwork).lifecycle = LifecycleOp::construct;

    deployment.scheduleConstructionDestruction(&cwork, nullptr);
    suite.expect(deployment.toSchedule.size() == 1 && deployment.toSchedule[0] == &cwork, "scheduleConstructionDestruction_construct_only");
  }

  {
    ApplicationDeployment deployment;
    deployment.state = DeploymentState::running;
    suite.expect(deployment.statelessCompactionDonorIsQuiescent(), "statelessCompactionDonorIsQuiescent_running_idle_true");

    deployment.state = DeploymentState::deploying;
    suite.expect(deployment.statelessCompactionDonorIsQuiescent() == false, "statelessCompactionDonorIsQuiescent_deploying_false");

    deployment.state = DeploymentState::running;
    ContainerView waiting;
    deployment.waitingOnContainers.insert_or_assign(&waiting, ContainerState::healthy);
    suite.expect(deployment.statelessCompactionDonorIsQuiescent() == false, "statelessCompactionDonorIsQuiescent_waiting_false");
    deployment.waitingOnContainers.clear();

    DeploymentWork pendingWork;
    pendingWork.emplace<StatelessWork>();
    deployment.toSchedule.push_back(&pendingWork);
    suite.expect(deployment.statelessCompactionDonorIsQuiescent() == false, "statelessCompactionDonorIsQuiescent_scheduled_work_false");
    deployment.toSchedule.clear();

    deployment.waitingOnCompactions = true;
    suite.expect(deployment.statelessCompactionDonorIsQuiescent() == false, "statelessCompactionDonorIsQuiescent_compaction_wait_false");
    deployment.waitingOnCompactions = false;

    CoroutineStack coro;
    deployment.schedulingStack.execution = &coro;
    suite.expect(deployment.statelessCompactionDonorIsQuiescent() == false, "statelessCompactionDonorIsQuiescent_active_scheduler_false");
    deployment.schedulingStack.execution = nullptr;
  }

  {
    ContainerView baseHealthy;
    baseHealthy.lifetime = ApplicationLifetime::base;
    baseHealthy.state = ContainerState::healthy;
    suite.expect(ApplicationDeployment::statelessCompactionContainerIsEligible(&baseHealthy), "statelessCompactionContainerIsEligible_base_healthy_true");

    ContainerView surgeHealthy;
    surgeHealthy.lifetime = ApplicationLifetime::surge;
    surgeHealthy.state = ContainerState::healthy;
    suite.expect(ApplicationDeployment::statelessCompactionContainerIsEligible(&surgeHealthy), "statelessCompactionContainerIsEligible_surge_healthy_true");

    ContainerView scheduledBase;
    scheduledBase.lifetime = ApplicationLifetime::base;
    scheduledBase.state = ContainerState::scheduled;
    suite.expect(ApplicationDeployment::statelessCompactionContainerIsEligible(&scheduledBase) == false, "statelessCompactionContainerIsEligible_scheduled_false");

    ContainerView destroyingBase;
    destroyingBase.lifetime = ApplicationLifetime::base;
    destroyingBase.state = ContainerState::destroying;
    suite.expect(ApplicationDeployment::statelessCompactionContainerIsEligible(&destroyingBase) == false, "statelessCompactionContainerIsEligible_destroying_false");

    ContainerView healthyCanary;
    healthyCanary.lifetime = ApplicationLifetime::canary;
    healthyCanary.state = ContainerState::healthy;
    suite.expect(ApplicationDeployment::statelessCompactionContainerIsEligible(&healthyCanary) == false, "statelessCompactionContainerIsEligible_canary_false");
  }

  {
    ApplicationDeployment deployment;
    deployment.state = DeploymentState::running;
    deployment.nTargetBase = 2;
    deployment.nTargetSurge = 0;
    deployment.nTargetCanary = 0;
    deployment.nDeployedBase = 99;
    deployment.nHealthyBase = 99;

    Machine machine = {};
    machine.state = MachineState::healthy;

    ContainerView healthy;
    healthy.machine = &machine;
    healthy.lifetime = ApplicationLifetime::base;
    healthy.state = ContainerState::healthy;

    ContainerView scheduled;
    scheduled.machine = &machine;
    scheduled.lifetime = ApplicationLifetime::base;
    scheduled.state = ContainerState::scheduled;

    deployment.containers.insert(&healthy);
    deployment.containers.insert(&scheduled);

    deployment.recoverAfterReboot();

    suite.expect(deployment.nDeployedBase == 2, "recoverAfterReboot_rebuilds_deployed_counts");
    suite.expect(deployment.nHealthyBase == 1, "recoverAfterReboot_rebuilds_healthy_counts");
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;
    brain.brainConfig.runtimeEnvironment.test.enabled = true;
    brain.brainConfig.architecture = nametagCurrentBuildMachineArchitecture();

    Rack rack = {};
    rack.uuid = 0x19602020;
    brain.racks.insert_or_assign(rack.uuid, &rack);

    Machine staleMachine = {};
    staleMachine.uuid = uint128_t(0x19602021);
    staleMachine.slug = "recover-stale-stateless-source"_ctv;
    staleMachine.private4 = 0x0a000021;
    staleMachine.rack = &rack;
    staleMachine.state = MachineState::healthy;
    staleMachine.lifetime = MachineLifetime::owned;
    staleMachine.hardware.cpu.architecture = nametagCurrentBuildMachineArchitecture();
    staleMachine.nLogicalCores_available = 8;
    staleMachine.memoryMB_available = 8192;
    staleMachine.storageMB_available = 4096;
    staleMachine.neuron.machine = &staleMachine;

    Machine readyMachine = {};
    readyMachine.uuid = uint128_t(0x19602022);
    readyMachine.slug = "recover-stale-stateless-target"_ctv;
    readyMachine.private4 = 0x0a000022;
    readyMachine.rack = &rack;
    readyMachine.state = MachineState::healthy;
    readyMachine.lifetime = MachineLifetime::owned;
    readyMachine.hardware.cpu.architecture = nametagCurrentBuildMachineArchitecture();
    readyMachine.nLogicalCores_available = 8;
    readyMachine.memoryMB_available = 8192;
    readyMachine.storageMB_available = 4096;

    ScopedSocketPair socket = {};
    bool machineReady = socket.create(suite, "recoverAfterReboot_stale_stateless_fixture_socketpair") && armNeuronControlStream(readyMachine, socket);

    rack.machines.insert(&staleMachine);
    rack.machines.insert(&readyMachine);
    brain.machines.insert(&staleMachine);
    brain.machines.insert(&readyMachine);

    suite.expect(machineReady, "recoverAfterReboot_stale_stateless_fixture_machine_ready");

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.type = ApplicationType::stateless;
    deployment.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
    deployment.plan.stateless.nBase = 1;
    deployment.plan.canaryCount = 0;
    deployment.plan.canariesMustLiveForMinutes = 0;
    deployment.plan.moveConstructively = true;
    deployment.plan.useHostNetworkNamespace = false;
    deployment.plan.requiresDatacenterUniqueTag = false;
    deployment.state = DeploymentState::none;
    deployment.nTargetBase = 1;
    deployment.nDeployedBase = 1;
    deployment.nHealthyBase = 1;
    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

    ContainerView *oldContainer = new ContainerView();
    uint128_t oldUUID = uint128_t(0x19602023);
    oldContainer->uuid = oldUUID;
    oldContainer->deploymentID = deployment.plan.config.deploymentID();
    oldContainer->applicationID = deployment.plan.config.applicationID;
    oldContainer->machine = &staleMachine;
    oldContainer->lifetime = ApplicationLifetime::base;
    oldContainer->state = ContainerState::healthy;
    deployment.containers.insert(oldContainer);
    brain.containers.insert_or_assign(oldUUID, oldContainer);
    staleMachine.upsertContainerIndexEntry(oldContainer->deploymentID, oldContainer);

    if (machineReady)
    {
      deployment.recoverAfterReboot();

      ContainerView *replacement = nullptr;
      for (ContainerView *container : deployment.containers)
      {
        replacement = container;
      }

      suite.expect(deployment.containers.size() == 1, "recoverAfterReboot_stale_stateless_replaces_one_container");
      suite.expect(replacement && replacement->machine == &readyMachine, "recoverAfterReboot_stale_stateless_schedules_on_live_machine");
      suite.expect(deployment.nDeployedBase == 1, "recoverAfterReboot_stale_stateless_restores_deployed_count");
      suite.expect(deployment.nHealthyBase == 0, "recoverAfterReboot_stale_stateless_does_not_count_stale_healthy");
      suite.expect(deployment.state == DeploymentState::deploying, "recoverAfterReboot_stale_stateless_enters_deploying");
      suite.expect(deployment.waitingOnContainers.size() == 1, "recoverAfterReboot_stale_stateless_waits_for_replacement_health");
      suite.expect(brain.containers.contains(oldUUID) == false, "recoverAfterReboot_stale_stateless_erases_old_brain_container");
      suite.expect(readyMachine.neuron.pendingSend && readyMachine.neuron.wBuffer.size() > 0, "recoverAfterReboot_stale_stateless_queues_replacement_spin");
    }

    Vector<ContainerView *> cleanupContainers;
    for (ContainerView *container : deployment.containers)
    {
      cleanupContainers.push_back(container);
    }

    for (ContainerView *container : cleanupContainers)
    {
      if (container && deployment.containers.contains(container))
      {
        deployment.destructContainer(container);
        deployment.containerDestroyed(container);
      }
    }

    brain.deployments.erase(deployment.plan.config.deploymentID());
    rack.machines.erase(&staleMachine);
    rack.machines.erase(&readyMachine);
    brain.machines.erase(&staleMachine);
    brain.machines.erase(&readyMachine);
    brain.racks.erase(rack.uuid);
    thisBrain = savedBrain;
  }

  {
    ApplicationDeployment deployment;
    deployment.state = DeploymentState::failed;
    deployment.nDeployedBase = 7;
    deployment.nHealthyBase = 5;
    deployment.recoverAfterReboot();
    suite.expect(deployment.nDeployedBase == 7 && deployment.nHealthyBase == 5, "recoverAfterReboot_skips_failed_state");
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.stateless.nBase = 1;
    deployment.state = DeploymentState::none;

    deployment.recoverAfterReboot();

    suite.expect(deployment.nTargetBase == 1, "recoverAfterReboot_materializes_stateless_target_for_pending_plan");
    suite.expect(deployment.nTarget() == 1, "recoverAfterReboot_materializes_stateless_total_target_for_pending_plan");
    suite.expect(deployment.nDeployed() == 0, "recoverAfterReboot_pending_plan_without_healthy_machines_does_not_schedule");
    suite.expect(deployment.state == DeploymentState::none, "recoverAfterReboot_pending_plan_without_healthy_machines_keeps_state");
    suite.expect(deployment.nSuspended == 0, "recoverAfterReboot_pending_plan_without_healthy_machines_does_not_leak_suspension");

    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;
    brain.brainConfig.runtimeEnvironment.test.enabled = true;
    brain.brainConfig.architecture = nametagCurrentBuildMachineArchitecture();

    Rack rack = {};
    rack.uuid = 0x19602001;
    brain.racks.insert_or_assign(rack.uuid, &rack);

    ScopedSocketPair socket = {};
    bool socketReady = socket.create(suite, "recoverAfterReboot_stale_suspension_fixture_socketpair");

    Machine machine = {};
    machine.uuid = uint128_t(0x19602002);
    machine.slug = "recover-stale-suspension-target"_ctv;
    machine.private4 = 0x0a000018;
    machine.rack = &rack;
    machine.state = MachineState::healthy;
    machine.lifetime = MachineLifetime::owned;
    machine.hardware.cpu.architecture = nametagCurrentBuildMachineArchitecture();
    machine.nLogicalCores_available = 8;
    machine.memoryMB_available = 8192;
    machine.storageMB_available = 4096;
    bool machineReady = socketReady && armNeuronControlStream(machine, socket);
    rack.machines.insert(&machine);
    brain.machines.insert(&machine);

    suite.expect(machineReady, "recoverAfterReboot_stale_suspension_fixture_machine_ready");

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.type = ApplicationType::stateless;
    deployment.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
    deployment.plan.stateless.nBase = 1;
    deployment.plan.canaryCount = 0;
    deployment.plan.canariesMustLiveForMinutes = 0;
    deployment.plan.moveConstructively = true;
    deployment.plan.useHostNetworkNamespace = false;
    deployment.plan.requiresDatacenterUniqueTag = false;
    deployment.state = DeploymentState::none;
    deployment.nTargetBase = 1;
    deployment.nSuspended = 3;
    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

    if (machineReady)
    {
      deployment.recoverAfterReboot();

      suite.expect(deployment.state == DeploymentState::deploying, "recoverAfterReboot_stale_suspension_schedules_underprovisioned");
      suite.expect(deployment.nDeployedBase == 1, "recoverAfterReboot_stale_suspension_deploys_missing_base");
      suite.expect(deployment.waitingOnContainers.size() == 1, "recoverAfterReboot_stale_suspension_waits_for_construct_health");
      suite.expect(deployment.schedulingStack.execution != nullptr, "recoverAfterReboot_stale_suspension_starts_scheduler");
      suite.expect(deployment.nSuspended == 1, "recoverAfterReboot_stale_suspension_replaces_stale_counter_with_live_wait");
      suite.expect(machine.neuron.pendingSend && machine.neuron.wBuffer.size() > 0, "recoverAfterReboot_stale_suspension_queues_neuron_spin");

      if (deployment.containers.empty() == false)
      {
        ContainerView *container = *deployment.containers.begin();
        deployment.containerIsHealthy(container);
      }
    }

    brain.deployments.erase(deployment.plan.config.deploymentID());
    rack.machines.erase(&machine);
    brain.machines.erase(&machine);
    brain.racks.erase(rack.uuid);
    thisBrain = savedBrain;
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.versionID = 42;
    deployment.state = DeploymentState::running;
    deployment.nTargetBase = 1;
    deployment.nDeployedBase = 1;
    deployment.nHealthyBase = 1;
    deployment.nCrashes = 4;

    ContainerView container;
    container.uuid = uint128_t(0xAA);
    container.runtime_nLogicalCores = 3;
    container.runtime_memoryMB = 777;
    container.runtime_storageMB = 222;
    deployment.containers.insert(&container);

    DeploymentStatusReport report = deployment.generateReport();
    suite.expect(report.versionID == 42, "generateReport_version");
    suite.expect(report.nTarget == 1 && report.nDeployed == 1 && report.nHealthy == 1, "generateReport_counts");
    suite.expect(report.nCrashes == 4, "generateReport_crash_count");
    suite.expect(report.containerRuntimes.size() == 1, "generateReport_runtime_count");
    suite.expect(report.containerRuntimes[0].nLogicalCores == 3, "generateReport_runtime_cores");
    suite.expect(report.containerRuntimes[0].memoryMB == 777, "generateReport_runtime_memory");
    suite.expect(report.containerRuntimes[0].storageMB == 222, "generateReport_runtime_storage");
  }

  {
    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);

    for (uint32_t index = 0; index < 80; index++)
    {
      FailureReport report {};
      report.containerUUID = uint128_t(index + 1);
      report.approxTimeMs = index;
      report.nthCrash = index;
      report.signal = 9;
      report.restarted = false;
      report.wasCanary = false;
      report.report.assignItoa(index);
      deployment.failureReports.push_back(report);
    }

    DeploymentStatusReport status = deployment.generateReport();
    suite.expect(status.failureReports.size() == 64, "generateReport_failure_reports_capped_to_max");
    suite.expect(status.failureReports[0].containerUUID == uint128_t(17), "generateReport_failure_reports_keep_most_recent_tail");
    suite.expect(status.failureReports[63].containerUUID == uint128_t(80), "generateReport_failure_reports_tail_end");
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);

    Rack rack {};
    rack.uuid = 901;

    Machine machine;
    machine.slug = "dev-baremetal"_ctv;
    machine.rack = &rack;

    ContainerView oldContainer;
    oldContainer.machine = &machine;
    oldContainer.shardGroup = 7;
    oldContainer.deploymentID = deployment.plan.config.deploymentID();
    oldContainer.state = ContainerState::planned;

    DeploymentWork *work = deployment.planStatefulUpdateInPlace(&oldContainer);
    StatefulWork *stateful = std::get_if<StatefulWork>(work);
    ContainerView *replacement = (stateful ? stateful->container : nullptr);

    suite.expect(stateful != nullptr, "planStatefulUpdateInPlace_returns_stateful_work");
    suite.expect(stateful && stateful->lifecycle == LifecycleOp::updateInPlace, "planStatefulUpdateInPlace_lifecycle");
    suite.expect(stateful && stateful->oldContainer == &oldContainer, "planStatefulUpdateInPlace_old_container_link");
    suite.expect(replacement != nullptr, "planStatefulUpdateInPlace_creates_replacement");
    suite.expect(replacement && replacement->machine == &machine, "planStatefulUpdateInPlace_replacement_machine");
    suite.expect(replacement && replacement->shardGroup == oldContainer.shardGroup, "planStatefulUpdateInPlace_preserves_shard_group");
    suite.expect(oldContainer.state == ContainerState::aboutToDestroy, "planStatefulUpdateInPlace_marks_old_about_to_destroy");
    suite.expect(oldContainer.plannedWork == work, "planStatefulUpdateInPlace_marks_old_plannedWork");
    suite.expect(replacement && replacement->plannedWork == work, "planStatefulUpdateInPlace_marks_new_plannedWork");

    deployment.cancelDeploymentWork(work);
    suite.expect(oldContainer.plannedWork == nullptr, "cancelDeploymentWork_updateInPlace_clears_old_plannedWork");
    suite.expect(replacement && replacement->plannedWork == nullptr, "cancelDeploymentWork_updateInPlace_clears_new_plannedWork");

    if (replacement)
    {
      deployment.containers.erase(replacement);
      while (deployment.containersByShardGroup.eraseEntry(replacement->shardGroup, replacement))
      {
      }
      brain.containers.erase(replacement->uuid);
      machine.removeContainerIndexEntry(replacement->deploymentID, replacement);
      delete replacement;
    }

    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment previous;
    seedCommonPlan(previous, false);
    previous.nTargetBase = 5;
    previous.nTargetSurge = 2;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.previous = &previous;
    deployment.plan.stateless.nBase = 6;
    deployment.plan.stateless.maxPerRackRatio = 1.0f;
    deployment.plan.stateless.maxPerMachineRatio = 1.0f;

    (void)deployment.measure();
    suite.expect(deployment.nTargetBase == 6, "measure_rehydrates_stateless_base_target_from_plan");
    suite.expect(deployment.nTargetSurge == 1, "measure_rehydrates_stateless_surge_target_after_base_raise");

    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment previous;
    seedCommonPlan(previous, false);
    previous.nTargetBase = 7;
    previous.nTargetSurge = 3;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.previous = &previous;
    deployment.plan.stateless.nBase = 4;
    deployment.plan.stateless.maxPerRackRatio = 1.0f;
    deployment.plan.stateless.maxPerMachineRatio = 1.0f;

    (void)deployment.measure();
    suite.expect(deployment.nTargetBase == 7, "measure_preserves_larger_previous_stateless_base_target");
    suite.expect(deployment.nTargetSurge == 3, "measure_preserves_stateless_surge_when_base_not_raised");

    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment previous;
    seedCommonPlan(previous, true);
    previous.nShardGroups = 4;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);
    deployment.previous = &previous;

    (void)deployment.measure();
    suite.expect(deployment.nShardGroups == 4, "measure_rehydrates_stateful_shard_group_count_from_previous");
    suite.expect(deployment.nTargetBase == 12, "measure_rehydrates_stateful_target_base_from_shards");

    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);

    (void)deployment.measure();
    suite.expect(deployment.nShardGroups == 1, "measure_stateful_defaults_to_single_shard_group");
    suite.expect(deployment.nTargetBase == 3, "measure_stateful_defaults_to_three_replicas");

    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rackA {};
    rackA.uuid = 19'500'001;
    Rack rackB {};
    rackB.uuid = 19'500'002;
    Rack rackC {};
    rackC.uuid = 19'500'003;
    brain.racks.insert_or_assign(rackA.uuid, &rackA);
    brain.racks.insert_or_assign(rackB.uuid, &rackB);
    brain.racks.insert_or_assign(rackC.uuid, &rackC);

    ScopedSocketPair socketA = {};
    ScopedSocketPair socketB = {};
    ScopedSocketPair socketC = {};
    bool socketsReady =
        socketA.create(suite, "measure_stateful_three_replica_creates_socketpair_a") && socketB.create(suite, "measure_stateful_three_replica_creates_socketpair_b") && socketC.create(suite, "measure_stateful_three_replica_creates_socketpair_c");

    Machine machineA = {};
    machineA.uuid = uint128_t(0x19500001);
    machineA.slug = "measure-a"_ctv;
    machineA.rack = &rackA;
    machineA.state = MachineState::healthy;
    machineA.lifetime = MachineLifetime::owned;
    machineA.nLogicalCores_available = 8;
    machineA.memoryMB_available = 8192;
    machineA.storageMB_available = 4096;
    bool machineAReady = socketsReady && armNeuronControlStream(machineA, socketA);
    rackA.machines.insert(&machineA);
    brain.machines.insert(&machineA);

    Machine machineB = {};
    machineB.uuid = uint128_t(0x19500002);
    machineB.slug = "measure-b"_ctv;
    machineB.rack = &rackB;
    machineB.state = MachineState::healthy;
    machineB.lifetime = MachineLifetime::owned;
    machineB.nLogicalCores_available = 8;
    machineB.memoryMB_available = 8192;
    machineB.storageMB_available = 4096;
    bool machineBReady = socketsReady && armNeuronControlStream(machineB, socketB);
    rackB.machines.insert(&machineB);
    brain.machines.insert(&machineB);

    Machine machineC = {};
    machineC.uuid = uint128_t(0x19500003);
    machineC.slug = "measure-c"_ctv;
    machineC.rack = &rackC;
    machineC.state = MachineState::healthy;
    machineC.lifetime = MachineLifetime::owned;
    machineC.nLogicalCores_available = 8;
    machineC.memoryMB_available = 8192;
    machineC.storageMB_available = 4096;
    bool machineCReady = socketsReady && armNeuronControlStream(machineC, socketC);
    rackC.machines.insert(&machineC);
    brain.machines.insert(&machineC);

    suite.expect(machineAReady && machineBReady && machineCReady, "measure_stateful_three_replica_seeds_machine_neuron_control_streams");

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);

    uint32_t measured = deployment.measure();
    suite.expect(measured == 3, "measure_stateful_reports_three_replica_fit");
    suite.expect(brain.containers.size() == 0, "measure_stateful_cleans_brain_container_index");
    suite.expect(machineA.containersByDeploymentID.size() == 0, "measure_stateful_cleans_machine_a_index");
    suite.expect(machineB.containersByDeploymentID.size() == 0, "measure_stateful_cleans_machine_b_index");
    suite.expect(machineC.containersByDeploymentID.size() == 0, "measure_stateful_cleans_machine_c_index");
    suite.expect(deployment.containers.size() == 0, "measure_stateful_cleans_deployment_container_set");
    suite.expect(deployment.containersByShardGroup.size() == 0, "measure_stateful_cleans_deployment_shard_bins");
    suite.expect(deployment.toSchedule.size() == 0, "measure_stateful_cleans_scheduled_work");

    rackA.machines.erase(&machineA);
    rackB.machines.erase(&machineB);
    rackC.machines.erase(&machineC);
    brain.machines.erase(&machineA);
    brain.machines.erase(&machineB);
    brain.machines.erase(&machineC);
    brain.racks.erase(rackA.uuid);
    brain.racks.erase(rackB.uuid);
    brain.racks.erase(rackC.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rackA {};
    rackA.uuid = 19'022'911;
    Rack rackB {};
    rackB.uuid = 19'022'912;
    Rack rackC {};
    rackC.uuid = 19'022'913;
    brain.racks.insert_or_assign(rackA.uuid, &rackA);
    brain.racks.insert_or_assign(rackB.uuid, &rackB);
    brain.racks.insert_or_assign(rackC.uuid, &rackC);

    ScopedSocketPair socketBrain = {};
    ScopedSocketPair socketWorkerA = {};
    ScopedSocketPair socketWorkerB = {};
    bool socketsReady =
        socketBrain.create(suite, "measure_stateful_runtime_not_ready_creates_socketpair_brain") && socketWorkerA.create(suite, "measure_stateful_runtime_not_ready_creates_socketpair_worker_a") && socketWorkerB.create(suite, "measure_stateful_runtime_not_ready_creates_socketpair_worker_b");

    Machine brainMachine = {};
    brainMachine.slug = "controller-brain-runtime-ready"_ctv;
    brainMachine.rack = &rackA;
    brainMachine.state = MachineState::healthy;
    brainMachine.lifetime = MachineLifetime::owned;
    brainMachine.isBrain = true;
    brainMachine.nLogicalCores_available = 8;
    brainMachine.memoryMB_available = 8192;
    brainMachine.storageMB_available = 4096;
    bool brainMachineArmed = socketsReady && armNeuronControlStream(brainMachine, socketBrain);
    rackA.machines.insert(&brainMachine);
    brain.machines.insert(&brainMachine);

    Machine workerA = {};
    workerA.slug = "worker-runtime-ready-a"_ctv;
    workerA.rack = &rackB;
    workerA.state = MachineState::healthy;
    workerA.lifetime = MachineLifetime::owned;
    workerA.nLogicalCores_available = 8;
    workerA.memoryMB_available = 8192;
    workerA.storageMB_available = 4096;
    bool workerAReady = socketsReady && armNeuronControlStream(workerA, socketWorkerA);
    rackB.machines.insert(&workerA);
    brain.machines.insert(&workerA);

    Machine workerB = {};
    workerB.slug = "worker-runtime-pending-b"_ctv;
    workerB.rack = &rackC;
    workerB.state = MachineState::healthy;
    workerB.lifetime = MachineLifetime::owned;
    workerB.nLogicalCores_available = 8;
    workerB.memoryMB_available = 8192;
    workerB.storageMB_available = 4096;
    bool workerBReady = socketsReady && armNeuronControlStream(workerB, socketWorkerB);
    workerB.runtimeReady = false;
    rackC.machines.insert(&workerB);
    brain.machines.insert(&workerB);

    suite.expect(brainMachineArmed && workerAReady && workerBReady, "measure_stateful_runtime_not_ready_seeds_neuron_control_streams");

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);

    uint32_t measured = deployment.measure();
    suite.expect(measured == 2, "measure_stateful_excludes_healthy_machine_without_runtime_ready");

    rackA.machines.erase(&brainMachine);
    rackB.machines.erase(&workerA);
    rackC.machines.erase(&workerB);
    brain.machines.erase(&brainMachine);
    brain.machines.erase(&workerA);
    brain.machines.erase(&workerB);
    brain.racks.erase(rackA.uuid);
    brain.racks.erase(rackB.uuid);
    brain.racks.erase(rackC.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rackA {};
    rackA.uuid = 19'022'901;
    Rack rackB {};
    rackB.uuid = 19'022'902;
    Rack rackC {};
    rackC.uuid = 19'022'903;
    brain.racks.insert_or_assign(rackA.uuid, &rackA);
    brain.racks.insert_or_assign(rackB.uuid, &rackB);
    brain.racks.insert_or_assign(rackC.uuid, &rackC);

    ScopedSocketPair socketBrain = {};
    ScopedSocketPair socketWorkerA = {};
    ScopedSocketPair socketWorkerB = {};
    bool socketsReady =
        socketBrain.create(suite, "measure_stateful_inactive_machine_creates_socketpair_brain") && socketWorkerA.create(suite, "measure_stateful_inactive_machine_creates_socketpair_worker_a") && socketWorkerB.create(suite, "measure_stateful_inactive_machine_creates_socketpair_worker_b");

    Machine brainMachine = {};
    brainMachine.slug = "controller-brain-inactive"_ctv;
    brainMachine.rack = &rackA;
    brainMachine.state = MachineState::healthy;
    brainMachine.lifetime = MachineLifetime::owned;
    brainMachine.isBrain = true;
    brainMachine.nLogicalCores_available = 8;
    brainMachine.memoryMB_available = 8192;
    brainMachine.storageMB_available = 4096;
    bool brainMachineArmed = socketsReady && armNeuronControlStream(brainMachine, socketBrain);
    brainMachine.neuron.connected = false;
    rackA.machines.insert(&brainMachine);
    brain.machines.insert(&brainMachine);

    Machine workerA = {};
    workerA.slug = "worker-active-a"_ctv;
    workerA.rack = &rackB;
    workerA.state = MachineState::healthy;
    workerA.lifetime = MachineLifetime::owned;
    workerA.nLogicalCores_available = 8;
    workerA.memoryMB_available = 8192;
    workerA.storageMB_available = 4096;
    bool workerAReady = socketsReady && armNeuronControlStream(workerA, socketWorkerA);
    rackB.machines.insert(&workerA);
    brain.machines.insert(&workerA);

    Machine workerB = {};
    workerB.slug = "worker-active-b"_ctv;
    workerB.rack = &rackC;
    workerB.state = MachineState::healthy;
    workerB.lifetime = MachineLifetime::owned;
    workerB.nLogicalCores_available = 8;
    workerB.memoryMB_available = 8192;
    workerB.storageMB_available = 4096;
    bool workerBReady = socketsReady && armNeuronControlStream(workerB, socketWorkerB);
    rackC.machines.insert(&workerB);
    brain.machines.insert(&workerB);

    suite.expect(brainMachineArmed && workerAReady && workerBReady, "measure_stateful_inactive_machine_seeds_neuron_control_streams");

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);

    uint32_t measured = deployment.measure();
    suite.expect(measured == 2, "measure_stateful_excludes_healthy_machine_without_neuron_control");

    rackA.machines.erase(&brainMachine);
    rackB.machines.erase(&workerA);
    rackC.machines.erase(&workerB);
    brain.machines.erase(&brainMachine);
    brain.machines.erase(&workerA);
    brain.machines.erase(&workerB);
    brain.racks.erase(rackA.uuid);
    brain.racks.erase(rackB.uuid);
    brain.racks.erase(rackC.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rack {};
    rack.uuid = 19'510'001;
    brain.racks.insert_or_assign(rack.uuid, &rack);

    ScopedSocketPair socket = {};
    bool socketReady = socket.create(suite, "measure_stateful_previous_creates_socketpair");

    Machine machine = {};
    machine.uuid = uint128_t(0x19510001);
    machine.slug = "measure-previous"_ctv;
    machine.rack = &rack;
    machine.state = MachineState::healthy;
    machine.lifetime = MachineLifetime::owned;
    machine.nLogicalCores_available = 8;
    machine.memoryMB_available = 8192;
    machine.storageMB_available = 4096;
    bool machineReady = socketReady && armNeuronControlStream(machine, socket);
    rack.machines.insert(&machine);
    brain.machines.insert(&machine);

    suite.expect(machineReady, "measure_stateful_previous_seeds_machine_neuron_control_stream");

    ApplicationDeployment previous;
    seedCommonPlan(previous, true);
    previous.plan.config.versionID = 1;
    previous.nShardGroups = 1;

    ContainerView oldContainer = {};
    oldContainer.uuid = uint128_t(0x19510010);
    oldContainer.deploymentID = previous.plan.config.deploymentID();
    oldContainer.applicationID = previous.plan.config.applicationID;
    oldContainer.machine = &machine;
    oldContainer.lifetime = ApplicationLifetime::base;
    oldContainer.state = ContainerState::healthy;
    oldContainer.isStateful = true;
    oldContainer.shardGroup = 0;
    previous.containers.insert(&oldContainer);
    previous.containersByShardGroup.insert(oldContainer.shardGroup, &oldContainer);
    brain.containers.insert_or_assign(oldContainer.uuid, &oldContainer);
    machine.upsertContainerIndexEntry(oldContainer.deploymentID, &oldContainer);

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);
    deployment.plan.config.versionID = 2;
    deployment.previous = &previous;

    uint32_t measured = deployment.measure();
    suite.expect(measured == 1, "measure_stateful_previous_fixture_updates_in_place_fit");
    suite.expect(oldContainer.state == ContainerState::healthy, "measure_stateful_restores_previous_container_state");
    suite.expect(oldContainer.plannedWork == nullptr, "measure_stateful_restores_previous_container_planned_work");
    suite.expect(brain.containers.size() == 1 && brain.containers.contains(oldContainer.uuid), "measure_stateful_keeps_previous_brain_container_only");
    suite.expect(machine.containersByDeploymentID.size() == 1, "measure_stateful_keeps_only_previous_machine_index");
    suite.expect(machine.containersByDeploymentID.hasEntryFor(previous.plan.config.deploymentID(), &oldContainer), "measure_stateful_preserves_previous_machine_entry");
    suite.expect(machine.containersByDeploymentID.find(deployment.plan.config.deploymentID()) == machine.containersByDeploymentID.end(), "measure_stateful_removes_new_deployment_machine_entry");
    suite.expect(deployment.containers.size() == 0, "measure_stateful_previous_cleanup_new_container_set");
    suite.expect(deployment.toSchedule.size() == 0, "measure_stateful_previous_cleanup_new_work");

    previous.containers.erase(&oldContainer);
    while (previous.containersByShardGroup.eraseEntry(oldContainer.shardGroup, &oldContainer))
    {
    }
    brain.containers.erase(oldContainer.uuid);
    machine.removeContainerIndexEntry(oldContainer.deploymentID, &oldContainer);
    rack.machines.erase(&machine);
    brain.machines.erase(&machine);
    brain.racks.erase(rack.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.stateless.nBase = 1;
    deployment.nDeployedBase = 9;
    deployment.nDeployedSurge = 7;
    deployment.nHealthyBase = 5;
    deployment.nHealthySurge = 3;
    deployment.nTargetSurge = 4;

    Machine machine = {};
    machine.slug = "takeover-worker"_ctv;
    machine.state = MachineState::healthy;
    machine.lifetime = MachineLifetime::owned;

    ContainerView base = {};
    base.uuid = uint128_t(0x19011902);
    base.deploymentID = deployment.plan.config.deploymentID();
    base.applicationID = deployment.plan.config.applicationID;
    base.machine = &machine;
    base.lifetime = ApplicationLifetime::base;
    base.state = ContainerState::healthy;

    ContainerView surge = {};
    surge.uuid = uint128_t(0x19011903);
    surge.deploymentID = deployment.plan.config.deploymentID();
    surge.applicationID = deployment.plan.config.applicationID;
    surge.machine = &machine;
    surge.lifetime = ApplicationLifetime::surge;
    surge.state = ContainerState::healthy;

    deployment.containers.insert(&base);
    deployment.containers.insert(&surge);

    deployment.evaluateAfterNewMaster();
    suite.expect(deployment.nTargetBase == 1, "evaluateAfterNewMaster_stateless_restores_base_target");
    suite.expect(deployment.nTargetSurge == 1, "evaluateAfterNewMaster_stateless_derives_surge_target_from_live_containers");
    suite.expect(deployment.nDeployedBase == 1, "evaluateAfterNewMaster_stateless_rebuilds_base_deployed_from_live_containers");
    suite.expect(deployment.nDeployedSurge == 1, "evaluateAfterNewMaster_stateless_rebuilds_surge_deployed_from_live_containers");
    suite.expect(deployment.nHealthyBase == 1, "evaluateAfterNewMaster_stateless_rebuilds_base_healthy_from_live_containers");
    suite.expect(deployment.nHealthySurge == 1, "evaluateAfterNewMaster_stateless_rebuilds_surge_healthy_from_live_containers");

    deployment.evaluateAfterNewMaster();
    suite.expect(deployment.nTargetSurge == 1, "evaluateAfterNewMaster_stateless_is_idempotent_for_surge_target");
    suite.expect(deployment.nDeployedBase == 1, "evaluateAfterNewMaster_stateless_is_idempotent_for_base_deployed");
    suite.expect(deployment.nDeployedSurge == 1, "evaluateAfterNewMaster_stateless_is_idempotent_for_surge_deployed");
    suite.expect(deployment.nHealthyBase == 1, "evaluateAfterNewMaster_stateless_is_idempotent_for_base_healthy");
    suite.expect(deployment.nHealthySurge == 1, "evaluateAfterNewMaster_stateless_is_idempotent_for_surge_healthy");

    deployment.containers.erase(&base);
    deployment.containers.erase(&surge);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);
    deployment.nShardGroups = 99;
    deployment.nTargetBase = 77;
    deployment.nTargetCanary = 6;
    deployment.nTargetSurge = 5;
    deployment.nDeployedBase = 9;
    deployment.nDeployedCanary = 8;
    deployment.nDeployedSurge = 7;
    deployment.nHealthyBase = 4;
    deployment.nHealthyCanary = 3;
    deployment.nHealthySurge = 2;

    Machine machine = {};
    machine.slug = "stateful-takeover-worker"_ctv;
    machine.state = MachineState::healthy;
    machine.lifetime = MachineLifetime::owned;

    ContainerView baseHealthy = {};
    baseHealthy.uuid = uint128_t(0x19011904);
    baseHealthy.deploymentID = deployment.plan.config.deploymentID();
    baseHealthy.applicationID = deployment.plan.config.applicationID;
    baseHealthy.machine = &machine;
    baseHealthy.lifetime = ApplicationLifetime::base;
    baseHealthy.state = ContainerState::healthy;
    baseHealthy.shardGroup = 0;

    ContainerView baseScheduled = {};
    baseScheduled.uuid = uint128_t(0x19011905);
    baseScheduled.deploymentID = deployment.plan.config.deploymentID();
    baseScheduled.applicationID = deployment.plan.config.applicationID;
    baseScheduled.machine = &machine;
    baseScheduled.lifetime = ApplicationLifetime::base;
    baseScheduled.state = ContainerState::scheduled;
    baseScheduled.shardGroup = 0;

    ContainerView baseHealthyTwo = {};
    baseHealthyTwo.uuid = uint128_t(0x19011908);
    baseHealthyTwo.deploymentID = deployment.plan.config.deploymentID();
    baseHealthyTwo.applicationID = deployment.plan.config.applicationID;
    baseHealthyTwo.machine = &machine;
    baseHealthyTwo.lifetime = ApplicationLifetime::base;
    baseHealthyTwo.state = ContainerState::healthy;
    baseHealthyTwo.shardGroup = 0;

    ContainerView surgeHealthy = {};
    surgeHealthy.uuid = uint128_t(0x19011906);
    surgeHealthy.deploymentID = deployment.plan.config.deploymentID();
    surgeHealthy.applicationID = deployment.plan.config.applicationID;
    surgeHealthy.machine = &machine;
    surgeHealthy.lifetime = ApplicationLifetime::surge;
    surgeHealthy.state = ContainerState::healthy;
    surgeHealthy.shardGroup = 0;

    ContainerView canaryHealthy = {};
    canaryHealthy.uuid = uint128_t(0x19011907);
    canaryHealthy.deploymentID = deployment.plan.config.deploymentID();
    canaryHealthy.applicationID = deployment.plan.config.applicationID;
    canaryHealthy.machine = &machine;
    canaryHealthy.lifetime = ApplicationLifetime::canary;
    canaryHealthy.state = ContainerState::healthy;
    canaryHealthy.shardGroup = 1;

    deployment.containers.insert(&baseHealthy);
    deployment.containers.insert(&baseScheduled);
    deployment.containers.insert(&baseHealthyTwo);
    deployment.containers.insert(&surgeHealthy);
    deployment.containers.insert(&canaryHealthy);
    deployment.containersByShardGroup.insert(0, &baseHealthy);

    deployment.evaluateAfterNewMaster();
    suite.expect(deployment.nShardGroups == 1, "evaluateAfterNewMaster_stateful_restores_shard_groups");
    suite.expect(deployment.nTargetBase == 3, "evaluateAfterNewMaster_stateful_restores_base_target_from_shard_groups");
    suite.expect(deployment.nTargetSurge == 1, "evaluateAfterNewMaster_stateful_rebuilds_surge_target_from_live_containers");
    suite.expect(deployment.nTargetCanary == 1, "evaluateAfterNewMaster_stateful_rebuilds_canary_target_from_live_containers");
    suite.expect(deployment.nDeployedBase == 3, "evaluateAfterNewMaster_stateful_rebuilds_base_deployed_from_live_containers");
    suite.expect(deployment.nDeployedSurge == 1, "evaluateAfterNewMaster_stateful_rebuilds_surge_deployed_from_live_containers");
    suite.expect(deployment.nDeployedCanary == 1, "evaluateAfterNewMaster_stateful_rebuilds_canary_deployed_from_live_containers");
    suite.expect(deployment.nHealthyBase == 2, "evaluateAfterNewMaster_stateful_rebuilds_base_healthy_from_live_containers");
    suite.expect(deployment.nHealthySurge == 1, "evaluateAfterNewMaster_stateful_rebuilds_surge_healthy_from_live_containers");
    suite.expect(deployment.nHealthyCanary == 1, "evaluateAfterNewMaster_stateful_rebuilds_canary_healthy_from_live_containers");

    deployment.evaluateAfterNewMaster();
    suite.expect(deployment.nTargetBase == 3, "evaluateAfterNewMaster_stateful_is_idempotent_for_base_target");
    suite.expect(deployment.nTargetSurge == 1, "evaluateAfterNewMaster_stateful_is_idempotent_for_surge_target");
    suite.expect(deployment.nTargetCanary == 1, "evaluateAfterNewMaster_stateful_is_idempotent_for_canary_target");
    suite.expect(deployment.nDeployedBase == 3, "evaluateAfterNewMaster_stateful_is_idempotent_for_base_deployed");
    suite.expect(deployment.nDeployedSurge == 1, "evaluateAfterNewMaster_stateful_is_idempotent_for_surge_deployed");
    suite.expect(deployment.nDeployedCanary == 1, "evaluateAfterNewMaster_stateful_is_idempotent_for_canary_deployed");
    suite.expect(deployment.nHealthyBase == 2, "evaluateAfterNewMaster_stateful_is_idempotent_for_base_healthy");
    suite.expect(deployment.nHealthySurge == 1, "evaluateAfterNewMaster_stateful_is_idempotent_for_surge_healthy");
    suite.expect(deployment.nHealthyCanary == 1, "evaluateAfterNewMaster_stateful_is_idempotent_for_canary_healthy");

    deployment.containers.erase(&baseHealthy);
    deployment.containers.erase(&baseScheduled);
    deployment.containers.erase(&baseHealthyTwo);
    deployment.containers.erase(&surgeHealthy);
    deployment.containers.erase(&canaryHealthy);
    while (deployment.containersByShardGroup.eraseEntry(0, &baseHealthy))
    {
    }
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rackA {};
    rackA.uuid = 19'511'001;
    Rack rackB {};
    rackB.uuid = 19'511'002;
    brain.racks.insert_or_assign(rackA.uuid, &rackA);
    brain.racks.insert_or_assign(rackB.uuid, &rackB);

    ScopedSocketPair socketB = {};
    bool socketReady = socketB.create(suite, "spin_stateless_move_creates_socketpair_target");

    Machine machineA = {};
    machineA.uuid = uint128_t(0x19511001);
    machineA.slug = "spin-stateless-source"_ctv;
    machineA.rack = &rackA;
    machineA.state = MachineState::healthy;
    machineA.lifetime = MachineLifetime::owned;
    machineA.nLogicalCores_available = 8;
    machineA.memoryMB_available = 8192;
    machineA.storageMB_available = 4096;
    rackA.machines.insert(&machineA);
    brain.machines.insert(&machineA);

    Machine machineB = {};
    machineB.uuid = uint128_t(0x19511002);
    machineB.slug = "spin-stateless-target"_ctv;
    machineB.rack = &rackB;
    machineB.state = MachineState::healthy;
    machineB.lifetime = MachineLifetime::owned;
    machineB.nLogicalCores_available = 8;
    machineB.memoryMB_available = 8192;
    machineB.storageMB_available = 4096;
    bool machineBReady = socketReady && armNeuronControlStream(machineB, socketB);
    rackB.machines.insert(&machineB);
    brain.machines.insert(&machineB);

    suite.expect(machineBReady, "spin_stateless_move_seeds_target_machine_neuron_control_stream");

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.nTargetBase = 1;
    deployment.nTargetCanary = 0;
    deployment.nTargetSurge = 0;

    DeploymentWork *work = deployment.planStatelessConstruction(&machineA, ApplicationLifetime::base);
    StatelessWork *stateless = std::get_if<StatelessWork>(work);
    ContainerView *container = stateless ? stateless->container : nullptr;

    suite.expect(container != nullptr, "spin_stateless_move_creates_planned_container");
    suite.expect(container && machineA.containersByDeploymentID.hasEntryFor(container->deploymentID, container), "spin_stateless_move_indexes_source_machine_before_move");

    deployment.countPerMachine[&machineA] = 1;
    deployment.countPerRack[&rackA] = 1;

    deployment.drainMachine(&machineA, false);

    suite.expect(container && container->machine == &machineB, "spin_stateless_move_retargets_container_machine");
    suite.expect(container && machineA.containersByDeploymentID.hasEntryFor(container->deploymentID, container) == false, "spin_stateless_move_removes_source_machine_index");
    suite.expect(container && machineB.containersByDeploymentID.hasEntryFor(container->deploymentID, container), "spin_stateless_move_indexes_target_machine");

    if (container)
    {
      if (container->plannedWork)
      {
        deployment.cancelDeploymentWork(container->plannedWork);
      }

      deployment.containers.erase(container);
      machineA.removeContainerIndexEntry(container->deploymentID, container);
      machineB.removeContainerIndexEntry(container->deploymentID, container);
      brain.containers.erase(container->uuid);
      delete container;
    }

    rackA.machines.erase(&machineA);
    rackB.machines.erase(&machineB);
    brain.machines.erase(&machineA);
    brain.machines.erase(&machineB);
    brain.racks.erase(rackA.uuid);
    brain.racks.erase(rackB.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rackA {};
    rackA.uuid = 19'512'001;
    Rack rackB {};
    rackB.uuid = 19'512'002;
    brain.racks.insert_or_assign(rackA.uuid, &rackA);
    brain.racks.insert_or_assign(rackB.uuid, &rackB);

    ScopedSocketPair socketB = {};
    bool socketReady = socketB.create(suite, "spin_stateful_move_creates_socketpair_target");

    Machine machineA = {};
    machineA.uuid = uint128_t(0x19512001);
    machineA.slug = "spin-stateful-source"_ctv;
    machineA.rack = &rackA;
    machineA.state = MachineState::healthy;
    machineA.lifetime = MachineLifetime::owned;
    machineA.nLogicalCores_available = 8;
    machineA.memoryMB_available = 8192;
    machineA.storageMB_available = 4096;
    rackA.machines.insert(&machineA);
    brain.machines.insert(&machineA);

    Machine machineB = {};
    machineB.uuid = uint128_t(0x19512002);
    machineB.slug = "spin-stateful-target"_ctv;
    machineB.rack = &rackB;
    machineB.state = MachineState::healthy;
    machineB.lifetime = MachineLifetime::owned;
    machineB.nLogicalCores_available = 8;
    machineB.memoryMB_available = 8192;
    machineB.storageMB_available = 4096;
    bool machineBReady = socketReady && armNeuronControlStream(machineB, socketB);
    rackB.machines.insert(&machineB);
    brain.machines.insert(&machineB);

    suite.expect(machineBReady, "spin_stateful_move_seeds_target_machine_neuron_control_stream");

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);
    deployment.nShardGroups = 1;
    deployment.nTargetBase = 1;
    deployment.nTargetCanary = 0;
    deployment.nTargetSurge = 0;

    DeploymentWork *work = deployment.planStatefulConstruction(&machineA, 7, DataStrategy::seeding);
    StatefulWork *stateful = std::get_if<StatefulWork>(work);
    ContainerView *container = stateful ? stateful->container : nullptr;

    suite.expect(container != nullptr, "spin_stateful_move_creates_planned_container");
    suite.expect(container && machineA.containersByDeploymentID.hasEntryFor(container->deploymentID, container), "spin_stateful_move_indexes_source_machine_before_move");

    deployment.countPerMachine[&machineA] = 1;
    deployment.countPerRack[&rackA] = 1;
    deployment.racksByShardGroup[7].insert(&rackA);

    deployment.drainMachine(&machineA, false);

    suite.expect(container && container->machine == &machineB, "spin_stateful_move_retargets_container_machine");
    suite.expect(container && machineA.containersByDeploymentID.hasEntryFor(container->deploymentID, container) == false, "spin_stateful_move_removes_source_machine_index");
    suite.expect(container && machineB.containersByDeploymentID.hasEntryFor(container->deploymentID, container), "spin_stateful_move_indexes_target_machine");
    suite.expect(deployment.racksByShardGroup[7].contains(&rackA) == false, "spin_stateful_move_releases_source_rack");
    suite.expect(deployment.racksByShardGroup[7].contains(&rackB), "spin_stateful_move_tracks_target_rack");

    if (container)
    {
      if (container->plannedWork)
      {
        deployment.cancelDeploymentWork(container->plannedWork);
      }

      deployment.containers.erase(container);
      while (deployment.containersByShardGroup.eraseEntry(container->shardGroup, container))
      {
      }
      machineA.removeContainerIndexEntry(container->deploymentID, container);
      machineB.removeContainerIndexEntry(container->deploymentID, container);
      brain.containers.erase(container->uuid);
      delete container;
    }

    rackA.machines.erase(&machineA);
    rackB.machines.erase(&machineB);
    brain.machines.erase(&machineA);
    brain.machines.erase(&machineB);
    brain.racks.erase(rackA.uuid);
    brain.racks.erase(rackB.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rack {};
    rack.uuid = 1901;
    brain.racks.insert_or_assign(rack.uuid, &rack);

    ScopedSocketPair socket = {};
    bool socketReady = socket.create(suite, "measure_stateless_capacity_creates_socketpair");

    Machine machine;
    machine.slug = "dev-baremetal"_ctv;
    machine.rack = &rack;
    machine.state = MachineState::healthy;
    machine.lifetime = MachineLifetime::owned;
    machine.nLogicalCores_available = 8;
    machine.memoryMB_available = 8192;
    machine.storageMB_available = 4096;
    bool machineReady = socketReady && armNeuronControlStream(machine, socket);
    rack.machines.insert(&machine);
    brain.machines.insert(&machine);

    suite.expect(machineReady, "measure_stateless_capacity_seeds_machine_neuron_control_stream");

    const int32_t initialCores = machine.nLogicalCores_available;
    const int32_t initialMemory = machine.memoryMB_available;
    const int32_t initialStorage = machine.storageMB_available;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.stateless.nBase = 2;
    deployment.plan.stateless.maxPerRackRatio = 1.0f;
    deployment.plan.stateless.maxPerMachineRatio = 1.0f;

    uint32_t measured = deployment.measure();
    suite.expect(measured >= 1, "measure_stateless_reports_fit_capacity");
    suite.expect(deployment.nTargetBase == deployment.plan.stateless.nBase, "measure_restores_target_base_after_measurement");
    suite.expect(deployment.nTargetSurge == 0, "measure_restores_target_surge_after_measurement");
    suite.expect(deployment.nDeployedBase == 0 && deployment.nDeployedSurge == 0, "measure_restores_deployed_counters");
    suite.expect(brain.containers.size() == 0, "measure_stateless_cleans_brain_container_index");
    suite.expect(deployment.containers.size() == 0, "measure_stateless_cleans_deployment_container_set");
    suite.expect(deployment.toSchedule.size() == 0, "measure_stateless_cleans_scheduled_work");
    suite.expect(deployment.waitingOnContainers.size() == 0, "measure_stateless_cleans_waiting_containers");
    suite.expect(machine.nLogicalCores_available == initialCores, "measure_restores_machine_cores");
    suite.expect(machine.memoryMB_available == initialMemory, "measure_restores_machine_memory");
    suite.expect(machine.storageMB_available == initialStorage, "measure_restores_machine_storage");

    rack.machines.erase(&machine);
    brain.machines.erase(&machine);
    brain.racks.erase(rack.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rack {};
    rack.uuid = 19'011'901;
    brain.racks.insert_or_assign(rack.uuid, &rack);

    ScopedSocketPair socket = {};
    bool socketReady = socket.create(suite, "measure_stateless_brain_machine_creates_socketpair");

    Machine brainMachine = {};
    brainMachine.slug = "controller-brain"_ctv;
    brainMachine.rack = &rack;
    brainMachine.state = MachineState::healthy;
    brainMachine.lifetime = MachineLifetime::owned;
    brainMachine.isBrain = true;
    brainMachine.nLogicalCores_available = 8;
    brainMachine.memoryMB_available = 8192;
    brainMachine.storageMB_available = 4096;
    bool brainMachineReady = socketReady && armNeuronControlStream(brainMachine, socket);
    rack.machines.insert(&brainMachine);
    brain.machines.insert(&brainMachine);

    suite.expect(brainMachineReady, "measure_stateless_brain_machine_seeds_neuron_control_stream");

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.stateless.nBase = 1;
    deployment.plan.stateless.maxPerRackRatio = 1.0f;
    deployment.plan.stateless.maxPerMachineRatio = 1.0f;

    brainMachine.isBrain = false;
    uint32_t workerMeasured = deployment.measure();
    suite.expect(workerMeasured >= 1, "measure_stateless_worker_fixture_has_fit_capacity");

    brainMachine.isBrain = true;
    uint32_t measured = deployment.measure();
    suite.expect(measured >= 1, "measure_stateless_includes_brain_machines_in_placement");
    suite.expect(measured == workerMeasured, "measure_stateless_brain_machine_matches_worker_capacity");

    rack.machines.erase(&brainMachine);
    brain.machines.erase(&brainMachine);
    brain.racks.erase(rack.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rackA {};
    rackA.uuid = 19'021'901;
    Rack rackB {};
    rackB.uuid = 19'021'902;
    Rack rackC {};
    rackC.uuid = 19'021'903;
    brain.racks.insert_or_assign(rackA.uuid, &rackA);
    brain.racks.insert_or_assign(rackB.uuid, &rackB);
    brain.racks.insert_or_assign(rackC.uuid, &rackC);

    ScopedSocketPair socketBrain = {};
    ScopedSocketPair socketWorkerA = {};
    ScopedSocketPair socketWorkerB = {};
    bool socketsReady =
        socketBrain.create(suite, "measure_stateful_brain_machine_creates_socketpair_brain") && socketWorkerA.create(suite, "measure_stateful_brain_machine_creates_socketpair_worker_a") && socketWorkerB.create(suite, "measure_stateful_brain_machine_creates_socketpair_worker_b");

    Machine brainMachine = {};
    brainMachine.slug = "controller-brain"_ctv;
    brainMachine.rack = &rackA;
    brainMachine.state = MachineState::healthy;
    brainMachine.lifetime = MachineLifetime::owned;
    brainMachine.isBrain = true;
    brainMachine.nLogicalCores_available = 8;
    brainMachine.memoryMB_available = 8192;
    brainMachine.storageMB_available = 4096;
    bool brainMachineReady = socketsReady && armNeuronControlStream(brainMachine, socketBrain);
    rackA.machines.insert(&brainMachine);
    brain.machines.insert(&brainMachine);

    Machine workerA = {};
    workerA.slug = "worker-a"_ctv;
    workerA.rack = &rackB;
    workerA.state = MachineState::healthy;
    workerA.lifetime = MachineLifetime::owned;
    workerA.nLogicalCores_available = 8;
    workerA.memoryMB_available = 8192;
    workerA.storageMB_available = 4096;
    bool workerAReady = socketsReady && armNeuronControlStream(workerA, socketWorkerA);
    rackB.machines.insert(&workerA);
    brain.machines.insert(&workerA);

    Machine workerB = {};
    workerB.slug = "worker-b"_ctv;
    workerB.rack = &rackC;
    workerB.state = MachineState::healthy;
    workerB.lifetime = MachineLifetime::owned;
    workerB.nLogicalCores_available = 8;
    workerB.memoryMB_available = 8192;
    workerB.storageMB_available = 4096;
    bool workerBReady = socketsReady && armNeuronControlStream(workerB, socketWorkerB);
    rackC.machines.insert(&workerB);
    brain.machines.insert(&workerB);

    suite.expect(brainMachineReady && workerAReady && workerBReady, "measure_stateful_brain_machine_seeds_neuron_control_streams");

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);

    brainMachine.isBrain = false;
    uint32_t workerMeasured = deployment.measure();
    suite.expect(workerMeasured == 3, "measure_stateful_worker_fixture_has_three_replica_fit");

    brainMachine.isBrain = true;
    uint32_t measured = deployment.measure();
    suite.expect(measured == 3, "measure_stateful_includes_brain_machines_in_placement");
    suite.expect(measured == workerMeasured, "measure_stateful_brain_machine_matches_worker_capacity");

    rackA.machines.erase(&brainMachine);
    rackB.machines.erase(&workerA);
    rackC.machines.erase(&workerB);
    brain.machines.erase(&brainMachine);
    brain.machines.erase(&workerA);
    brain.machines.erase(&workerB);
    brain.racks.erase(rackA.uuid);
    brain.racks.erase(rackB.uuid);
    brain.racks.erase(rackC.uuid);
    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);
    deployment.plan.stateful.allMasters = true;

    Rack rack {};
    rack.uuid = 1902;

    Machine machine;
    machine.slug = "dev-baremetal"_ctv;
    machine.rack = &rack;
    machine.state = MachineState::healthy;
    machine.lifetime = MachineLifetime::owned;
    machine.ownedLogicalCores = 12;
    machine.ownedMemoryMB = 4512;
    machine.ownedStorageMB = 2128;
    machine.isolatedLogicalCoresCommitted = deployment.plan.config.nLogicalCores;
    machine.nLogicalCores_available = 10;
    machine.sharedCPUMillis_available = 0;
    machine.memoryMB_available = 4000;
    machine.storageMB_available = 2000;

    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

    ContainerView *container = new ContainerView();
    container->uuid = uint128_t(0xD351);
    container->deploymentID = deployment.plan.config.deploymentID();
    container->machine = &machine;
    container->lifetime = ApplicationLifetime::base;
    container->state = ContainerState::aboutToDestroy;
    container->isStateful = true;
    container->shardGroup = 55;

    deployment.containers.insert(container);
    deployment.containersByShardGroup.insert(container->shardGroup, container);
    brain.containers.insert_or_assign(container->uuid, container);
    machine.upsertContainerIndexEntry(container->deploymentID, container);

    deployment.nHealthyBase = 1;

    const uint128_t uuid = container->uuid;
    const int32_t coresBefore = machine.nLogicalCores_available;
    const int32_t memoryBefore = machine.memoryMB_available;
    const int32_t storageBefore = machine.storageMB_available;

    deployment.planStatefulDestruction(container);
    deployment.destructContainer(container);

    suite.expect(container->state == ContainerState::destroying, "destructContainer_moves_state_to_destroying");
    suite.expect(deployment.nHealthyBase == 0, "destructContainer_decrements_healthy_counts");
    suite.expect(machine.nLogicalCores_available == (coresBefore + int32_t(deployment.plan.config.nLogicalCores)), "destructContainer_restores_machine_cores");
    suite.expect(machine.memoryMB_available == (memoryBefore + int32_t(deployment.plan.config.totalMemoryMB())), "destructContainer_restores_machine_memory");
    suite.expect(machine.storageMB_available == (storageBefore + int32_t(deployment.plan.config.totalStorageMB())), "destructContainer_restores_machine_storage");
    suite.expect(deployment.containers.contains(container) == false, "destructContainer_erases_from_deployment_container_set");
    suite.expect(machine.containersByDeploymentID.size() == 0, "destructContainer_erases_machine_index_entry");

    deployment.containerDestroyed(container);
    suite.expect(brain.containers.contains(uuid) == false, "containerDestroyed_erases_brain_container_index");

    brain.deployments.erase(deployment.plan.config.deploymentID());
    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);

    Rack rack {};
    rack.uuid = 19'021;

    Machine machine;
    machine.slug = "dev-baremetal"_ctv;
    machine.rack = &rack;
    machine.state = MachineState::healthy;
    machine.lifetime = MachineLifetime::owned;
    machine.nLogicalCores_available = 10;
    machine.sharedCPUMillis_available = 0;
    machine.memoryMB_available = 4000;
    machine.storageMB_available = 2000;

    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

    ContainerView *container = new ContainerView();
    container->uuid = uint128_t(0xD3511);
    container->deploymentID = deployment.plan.config.deploymentID();
    container->machine = &machine;
    container->lifetime = ApplicationLifetime::base;
    container->state = ContainerState::aboutToDestroy;
    container->isStateful = false;

    deployment.containers.insert(container);
    brain.containers.insert_or_assign(container->uuid, container);
    machine.upsertContainerIndexEntry(container->deploymentID, container);

    deployment.nHealthyBase = 0;

    const uint128_t uuid = container->uuid;

    deployment.planStatelessDestruction(container, "destructContainer_zero_guard");
    deployment.destructContainer(container);

    suite.expect(deployment.nHealthyBase == 0, "destructContainer_clamps_zero_healthy_base");
    suite.expect(container->state == ContainerState::destroying, "destructContainer_zero_guard_moves_state_to_destroying");
    suite.expect(deployment.containers.contains(container) == false, "destructContainer_zero_guard_erases_from_deployment_container_set");
    suite.expect(machine.containersByDeploymentID.size() == 0, "destructContainer_zero_guard_erases_machine_index_entry");

    deployment.containerDestroyed(container);
    suite.expect(brain.containers.contains(uuid) == false, "destructContainer_zero_guard_erases_brain_container_index");

    brain.deployments.erase(deployment.plan.config.deploymentID());
    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);
    deployment.plan.stateful.allMasters = true;

    Rack rack {};
    rack.uuid = 1903;

    Machine machine;
    machine.slug = "dev-baremetal"_ctv;
    machine.rack = &rack;
    machine.state = MachineState::healthy;
    machine.lifetime = MachineLifetime::owned;
    machine.nLogicalCores_available = 10;
    machine.memoryMB_available = 4000;
    machine.storageMB_available = 2000;

    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

    ContainerView *container = new ContainerView();
    container->uuid = uint128_t(0xD352);
    container->deploymentID = deployment.plan.config.deploymentID();
    container->machine = &machine;
    container->lifetime = ApplicationLifetime::base;
    container->state = ContainerState::aboutToDestroy;
    container->isStateful = true;
    container->shardGroup = 8;

    deployment.containers.insert(container);
    deployment.containersByShardGroup.insert(container->shardGroup, container);
    brain.containers.insert_or_assign(container->uuid, container);
    machine.upsertContainerIndexEntry(container->deploymentID, container);

    deployment.nHealthyBase = 1;

    const uint128_t uuid = container->uuid;

    deployment.drainMachine(&machine, true);

    suite.expect(deployment.containers.size() == 0, "drainMachine_failed_culls_about_to_destroy_container");
    suite.expect(brain.containers.contains(uuid) == false, "drainMachine_failed_removes_container_from_brain_index");
    suite.expect(machine.containersByDeploymentID.size() == 0, "drainMachine_failed_clears_machine_container_bin");
    suite.expect(deployment.nHealthyBase == 0, "drainMachine_failed_updates_healthy_counts");

    brain.deployments.erase(deployment.plan.config.deploymentID());
    thisBrain = savedBrain;
  }

  {
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);

    Rack rack {};
    rack.uuid = 1904;

    Machine machine;
    machine.slug = "dev-baremetal"_ctv;
    machine.rack = &rack;
    machine.state = MachineState::healthy;
    machine.lifetime = MachineLifetime::owned;

    ContainerView oldContainer;
    oldContainer.machine = &machine;
    oldContainer.shardGroup = 12;

    deployment.scheduleStatefulUpdateInPlace(&oldContainer);

    suite.expect(deployment.toSchedule.size() == 1, "scheduleStatefulUpdateInPlace_enqueues_single_work_item");
    DeploymentWork *work = deployment.toSchedule[0];
    StatefulWork *stateful = std::get_if<StatefulWork>(work);
    suite.expect(stateful != nullptr, "scheduleStatefulUpdateInPlace_enqueues_stateful_work");
    suite.expect(stateful && stateful->lifecycle == LifecycleOp::updateInPlace, "scheduleStatefulUpdateInPlace_lifecycle");

    ContainerView *replacement = (stateful ? stateful->container : nullptr);
    deployment.cancelDeploymentWork(work);

    if (replacement)
    {
      deployment.containers.erase(replacement);
      brain.containers.erase(replacement->uuid);
      machine.removeContainerIndexEntry(replacement->deploymentID, replacement);
      delete replacement;
    }

    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Mesh mesh = {};
    brain.mesh = &mesh;

    Rack rackA = {};
    rackA.uuid = 19'051'901;
    Rack rackB = {};
    rackB.uuid = 19'051'902;
    Rack rackC = {};
    rackC.uuid = 19'051'903;
    brain.racks.insert_or_assign(rackA.uuid, &rackA);
    brain.racks.insert_or_assign(rackB.uuid, &rackB);
    brain.racks.insert_or_assign(rackC.uuid, &rackC);

    ScopedSocketPair socketA = {};
    ScopedSocketPair socketB = {};
    ScopedSocketPair socketC = {};
    bool socketsReady =
        socketA.create(suite, "deploy_stateful_initial_schedule_creates_socketpair_a") && socketB.create(suite, "deploy_stateful_initial_schedule_creates_socketpair_b") && socketC.create(suite, "deploy_stateful_initial_schedule_creates_socketpair_c");

    auto seedMachine = [&](
                           Machine& machine,
                           Rack& rack,
                           uint128_t uuid,
                           uint32_t private4,
                           const String& slug,
                           ScopedSocketPair& sockets) -> bool {
      machine.uuid = uuid;
      machine.private4 = private4;
      machine.slug = slug;
      machine.rack = &rack;
      machine.state = MachineState::healthy;
      machine.lifetime = MachineLifetime::owned;
      machine.isBrain = true;
      machine.hardware.inventoryComplete = true;
      machine.hardware.cpu.architecture = nametagCurrentBuildMachineArchitecture();
      machine.hardware.cpu.logicalCores = 8;
      machine.hardware.memory.totalMB = 8192;
      machine.ownedLogicalCores = 8;
      machine.ownedMemoryMB = 8192;
      machine.ownedStorageMB = 4096;
      machine.totalLogicalCores = 8;
      machine.totalMemoryMB = 8192;
      machine.totalStorageMB = 4096;
      machine.nLogicalCores_available = 8;
      machine.sharedCPUMillis_available = 0;
      machine.memoryMB_available = 8192;
      machine.storageMB_available = 4096;
      machine.neuron.machine = &machine;
      machine.neuron.fd = 100 + int(private4 & 0xffu);
      machine.neuron.isFixedFile = true;
      machine.neuron.fslot = sockets.adoptLeftIntoFixedFileSlot();
      machine.neuron.connected = (machine.neuron.fslot >= 0);
      machine.runtimeReady = machine.neuron.connected;
      rack.machines.insert(&machine);
      brain.machines.insert(&machine);
      return machine.neuron.connected;
    };

    Machine machineA = {};
    Machine machineB = {};
    Machine machineC = {};
    bool machinesReady = socketsReady && seedMachine(machineA, rackA, uint128_t(0x19051901), 0x0a00000b, "deploy-stateful-a"_ctv, socketA) && seedMachine(machineB, rackB, uint128_t(0x19051902), 0x0a00000c, "deploy-stateful-b"_ctv, socketB) && seedMachine(machineC, rackC, uint128_t(0x19051903), 0x0a00000d, "deploy-stateful-c"_ctv, socketC);

    suite.expect(machinesReady, "deploy_stateful_initial_schedule_seeds_machine_neuron_control_streams");

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, true);
    deployment.plan.config.type = ApplicationType::stateful;
    deployment.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
    deployment.plan.stateful.clientPrefix = (uint64_t(991) << 48) | (uint64_t(1) << 40);
    deployment.plan.stateful.siblingPrefix = (uint64_t(991) << 48) | (uint64_t(2) << 40);
    deployment.plan.stateful.cousinPrefix = (uint64_t(991) << 48) | (uint64_t(3) << 40);
    deployment.plan.stateful.seedingPrefix = (uint64_t(991) << 48) | (uint64_t(4) << 40);
    deployment.plan.stateful.shardingPrefix = (uint64_t(991) << 48) | (uint64_t(5) << 40);
    deployment.plan.stateful.allMasters = true;
    deployment.plan.stateful.neverShard = false;
    deployment.plan.stateful.seedingAlways = false;
    deployment.plan.canaryCount = 0;
    deployment.plan.canariesMustLiveForMinutes = 0;
    deployment.plan.moveConstructively = true;
    deployment.plan.useHostNetworkNamespace = false;
    deployment.plan.requiresDatacenterUniqueTag = false;
    deployment.plan.config.msTilHealthy = 10'000;
    deployment.plan.config.sTilHealthcheck = 15;
    deployment.plan.config.sTilKillable = 30;
    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

    if (machinesReady)
    {
      deployment.deploy();

      uint32_t queuedMachineCount = 0;
      Machine *queuedMachine = nullptr;
      for (Machine *machine : {&machineA, &machineB, &machineC})
      {
        if (machine->neuron.pendingSend && machine->neuron.wBuffer.size() > 0)
        {
          queuedMachineCount += 1;
          queuedMachine = machine;
        }
      }

      suite.expect(deployment.state == DeploymentState::deploying, "deploy_stateful_initial_schedule_keeps_deployment_deploying_until_health_ack");
      suite.expect(deployment.nTargetBase == 3, "deploy_stateful_initial_schedule_targets_three_replicas");
      suite.expect(deployment.nDeployedBase == 3, "deploy_stateful_initial_schedule_architects_three_replicas");
      suite.expect(deployment.containers.size() == 3, "deploy_stateful_initial_schedule_tracks_three_planned_containers");
      suite.expect(deployment.waitingOnContainers.size() == 3, "deploy_stateful_initial_schedule_waits_on_all_initial_constructs");
      suite.expect(deployment.toSchedule.size() == 0, "deploy_stateful_initial_schedule_drains_construct_queue");
      suite.expect(deployment.schedulingStack.execution != nullptr, "deploy_stateful_initial_schedule_suspends_scheduler_while_waiting_on_health");
      suite.expect(queuedMachineCount == 3, "deploy_stateful_initial_schedule_queues_all_initial_neuron_spins");
      suite.expect(queuedMachine != nullptr && queuedMachine->neuron.pendingSendBytes > 0, "deploy_stateful_initial_schedule_marks_neuron_spins_pending_send");
      suite.expect(brain.finCount == 0, "deploy_stateful_initial_schedule_does_not_finish_before_first_health_ack");
      suite.expect(brain.failureCount == 0, "deploy_stateful_initial_schedule_does_not_fail_healthy_fixture");
    }

    brain.deployments.erase(deployment.plan.config.deploymentID());
    rackA.machines.erase(&machineA);
    rackB.machines.erase(&machineB);
    rackC.machines.erase(&machineC);
    brain.machines.erase(&machineA);
    brain.machines.erase(&machineB);
    brain.machines.erase(&machineC);
    brain.racks.erase(rackA.uuid);
    brain.racks.erase(rackB.uuid);
    brain.racks.erase(rackC.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rackA {};
    rackA.uuid = 19'601'001;
    Rack rackB {};
    rackB.uuid = 19'601'002;
    Rack rackC {};
    rackC.uuid = 19'601'003;
    brain.racks.insert_or_assign(rackA.uuid, &rackA);
    brain.racks.insert_or_assign(rackB.uuid, &rackB);
    brain.racks.insert_or_assign(rackC.uuid, &rackC);

    ScopedSocketPair socketA = {};
    ScopedSocketPair socketB = {};
    ScopedSocketPair socketC = {};
    bool socketsReady =
        socketA.create(suite, "deploy_stateless_single_instance_creates_socketpair_a") && socketB.create(suite, "deploy_stateless_single_instance_creates_socketpair_b") && socketC.create(suite, "deploy_stateless_single_instance_creates_socketpair_c");

    auto seedMachine = [&](
                           Machine& machine,
                           Rack& rack,
                           uint128_t uuid,
                           uint32_t private4,
                           const String& slug,
                           ScopedSocketPair& sockets) -> bool {
      machine.uuid = uuid;
      machine.private4 = private4;
      machine.slug = slug;
      machine.rack = &rack;
      machine.state = MachineState::healthy;
      machine.lifetime = MachineLifetime::owned;
      machine.isBrain = true;
      machine.hardware.inventoryComplete = true;
      machine.hardware.cpu.architecture = nametagCurrentBuildMachineArchitecture();
      machine.hardware.cpu.logicalCores = 8;
      machine.hardware.memory.totalMB = 8192;
      machine.ownedLogicalCores = 8;
      machine.ownedMemoryMB = 8192;
      machine.ownedStorageMB = 4096;
      machine.totalLogicalCores = 8;
      machine.totalMemoryMB = 8192;
      machine.totalStorageMB = 4096;
      machine.nLogicalCores_available = 8;
      machine.sharedCPUMillis_available = 0;
      machine.memoryMB_available = 8192;
      machine.storageMB_available = 4096;
      machine.neuron.machine = &machine;
      machine.neuron.fd = 150 + int(private4 & 0xffu);
      machine.neuron.isFixedFile = true;
      machine.neuron.fslot = sockets.adoptLeftIntoFixedFileSlot();
      machine.neuron.connected = (machine.neuron.fslot >= 0);
      machine.runtimeReady = machine.neuron.connected;
      rack.machines.insert(&machine);
      brain.machines.insert(&machine);
      return machine.neuron.connected;
    };

    Machine machineA = {};
    Machine machineB = {};
    Machine machineC = {};
    bool machinesReady = socketsReady && seedMachine(machineA, rackA, uint128_t(0x19601001), 0x0a000015, "deploy-stateless-a"_ctv, socketA) && seedMachine(machineB, rackB, uint128_t(0x19601002), 0x0a000016, "deploy-stateless-b"_ctv, socketB) && seedMachine(machineC, rackC, uint128_t(0x19601003), 0x0a000017, "deploy-stateless-c"_ctv, socketC);

    suite.expect(machinesReady, "deploy_stateless_single_instance_seeds_machine_neuron_control_streams");

    ApplicationDeployment deployment;
    seedCommonPlan(deployment, false);
    deployment.plan.config.type = ApplicationType::stateless;
    deployment.plan.config.architecture = nametagCurrentBuildMachineArchitecture();
    deployment.plan.stateless.nBase = 1;
    deployment.plan.stateless.maxPerRackRatio = 1.0f;
    deployment.plan.stateless.maxPerMachineRatio = 1.0f;
    deployment.plan.canaryCount = 0;
    deployment.plan.canariesMustLiveForMinutes = 0;
    deployment.plan.moveConstructively = true;
    deployment.plan.useHostNetworkNamespace = false;
    deployment.plan.requiresDatacenterUniqueTag = false;
    deployment.plan.config.msTilHealthy = 10'000;
    deployment.plan.config.sTilHealthcheck = 15;
    deployment.plan.config.sTilKillable = 30;
    brain.deployments.insert_or_assign(deployment.plan.config.deploymentID(), &deployment);

    if (machinesReady)
    {
      deployment.deploy();

      uint32_t queuedMachineCount = 0;
      for (Machine *machine : {&machineA, &machineB, &machineC})
      {
        if (machine->neuron.pendingSend && machine->neuron.wBuffer.size() > 0)
        {
          queuedMachineCount += 1;
        }
      }

      suite.expect(deployment.state == DeploymentState::deploying, "deploy_stateless_single_instance_keeps_deployment_deploying_until_health_ack");
      suite.expect(deployment.nTargetBase == 1, "deploy_stateless_single_instance_targets_one_base");
      suite.expect(deployment.nTargetSurge == 0, "deploy_stateless_single_instance_targets_zero_surge");
      suite.expect(deployment.nTargetCanary == 0, "deploy_stateless_single_instance_targets_zero_canary");
      suite.expect(deployment.nDeployedBase == 1, "deploy_stateless_single_instance_architects_one_base");
      suite.expect(deployment.nDeployedSurge == 0, "deploy_stateless_single_instance_architects_zero_surge");
      suite.expect(deployment.containers.size() == 1, "deploy_stateless_single_instance_tracks_one_planned_container");
      suite.expect(deployment.waitingOnContainers.size() == 1, "deploy_stateless_single_instance_waits_on_one_construct");
      suite.expect(deployment.toSchedule.size() == 0, "deploy_stateless_single_instance_drains_construct_queue");
      suite.expect(deployment.schedulingStack.execution != nullptr, "deploy_stateless_single_instance_suspends_scheduler_while_waiting_on_health");
      suite.expect(queuedMachineCount == 1, "deploy_stateless_single_instance_queues_one_neuron_spin");
      suite.expect(brain.finCount == 0, "deploy_stateless_single_instance_does_not_finish_before_health_ack");
      suite.expect(brain.failureCount == 0, "deploy_stateless_single_instance_does_not_fail_healthy_fixture");
    }

    brain.deployments.erase(deployment.plan.config.deploymentID());
    rackA.machines.erase(&machineA);
    rackB.machines.erase(&machineB);
    rackC.machines.erase(&machineC);
    brain.machines.erase(&machineA);
    brain.machines.erase(&machineB);
    brain.machines.erase(&machineC);
    brain.racks.erase(rackA.uuid);
    brain.racks.erase(rackB.uuid);
    brain.racks.erase(rackC.uuid);
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    Rack rack = {};
    rack.uuid = 19'610'101;

    ScopedSocketPair socket = {};
    bool socketReady = socket.create(suite, "previous_stateless_destruction_routes_waiter_creates_socketpair");

    Machine machine = {};
    machine.uuid = uint128_t(0x19610101);
    machine.private4 = 0x0a000031;
    machine.slug = "previous-destroy-owner"_ctv;
    machine.rack = &rack;
    machine.state = MachineState::healthy;
    machine.lifetime = MachineLifetime::owned;
    machine.hardware.inventoryComplete = true;
    machine.hardware.cpu.architecture = nametagCurrentBuildMachineArchitecture();
    machine.nLogicalCores_available = 8;
    machine.memoryMB_available = 8192;
    machine.storageMB_available = 4096;
    bool machineReady = socketReady && armNeuronControlStream(machine, socket);
    rack.machines.insert(&machine);
    brain.racks.insert_or_assign(rack.uuid, &rack);
    brain.machines.insert(&machine);

    suite.expect(machineReady, "previous_stateless_destruction_routes_waiter_seeds_neuron_control_stream");

    ApplicationDeployment *previous = new ApplicationDeployment();
    ApplicationDeployment *current = new ApplicationDeployment();
    seedCommonPlan(*previous, false);
    seedCommonPlan(*current, false);
    previous->plan.config.versionID = 1;
    current->plan.config.versionID = 2;
    previous->plan.stateless.nBase = 1;
    current->plan.stateless.nBase = 1;
    previous->state = DeploymentState::decommissioning;
    current->state = DeploymentState::deploying;
    previous->nTargetBase = 1;
    previous->nDeployedBase = 1;
    previous->nHealthyBase = 1;
    current->nTargetBase = 1;
    current->nDeployedBase = 1;
    current->nHealthyBase = 1;
    previous->next = current;
    current->previous = previous;

    ContainerView *oldContainer = new ContainerView();
    oldContainer->uuid = uint128_t(0x19610102);
    oldContainer->deploymentID = previous->plan.config.deploymentID();
    oldContainer->applicationID = previous->plan.config.applicationID;
    oldContainer->machine = &machine;
    oldContainer->lifetime = ApplicationLifetime::base;
    oldContainer->state = ContainerState::healthy;
    previous->containers.insert(oldContainer);
    machine.upsertContainerIndexEntry(oldContainer->deploymentID, oldContainer);
    brain.containers.insert_or_assign(oldContainer->uuid, oldContainer);
    brain.deployments.insert_or_assign(previous->plan.config.deploymentID(), previous);
    brain.deployments.insert_or_assign(current->plan.config.deploymentID(), current);
    brain.deploymentsByApp.insert_or_assign(current->plan.config.applicationID, current);

    current->toSchedule.push_back(current->planStatelessDestruction(oldContainer, "unit-previous-destroy"));
    current->schedule(nullptr);

    suite.expect(oldContainer->state == ContainerState::destroying, "previous_stateless_destruction_marks_old_container_destroying");
    suite.expect(oldContainer->destructionWaiterDeploymentID == current->plan.config.deploymentID(), "previous_stateless_destruction_records_current_waiter");
    suite.expect(previous->containers.contains(oldContainer) == false, "previous_stateless_destruction_removes_from_previous_container_set");
    suite.expect(previous->nHealthyBase == 0, "previous_stateless_destruction_decrements_previous_health");
    suite.expect(current->nHealthyBase == 1, "previous_stateless_destruction_preserves_current_health");
    suite.expect(current->waitingOnContainers.contains(oldContainer), "previous_stateless_destruction_waits_on_current_deployment");

    ApplicationDeployment *ackDeployment = nullptr;
    uint64_t waiterDeploymentID = oldContainer->destructionWaiterDeploymentID;
    if (auto deploymentIt = brain.deployments.find(waiterDeploymentID ? waiterDeploymentID : oldContainer->deploymentID); deploymentIt != brain.deployments.end())
    {
      ackDeployment = deploymentIt->second;
    }
    suite.expect(ackDeployment == current, "previous_stateless_destruction_ack_routes_to_current_deployment");

    current->containerDestroyed(oldContainer);

    suite.expect(current->state == DeploymentState::running, "previous_stateless_destruction_completion_runs_current_deployment");
    suite.expect(current->previous == nullptr, "previous_stateless_destruction_completion_culls_previous_deployment");
    suite.expect(current->waitingOnContainers.empty(), "previous_stateless_destruction_completion_clears_waiter");
    suite.expect(current->nHealthyBase == 1, "previous_stateless_destruction_completion_keeps_current_health");

    brain.deployments.erase(current->plan.config.deploymentID());
    brain.deploymentsByApp.erase(current->plan.config.applicationID);
    brain.machines.erase(&machine);
    brain.racks.erase(rack.uuid);
    rack.machines.erase(&machine);
    delete current;
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment *previous = new ApplicationDeployment();
    ApplicationDeployment *current = new ApplicationDeployment();
    seedCommonPlan(*previous, false);
    seedCommonPlan(*current, false);
    previous->plan.config.versionID = 1;
    current->plan.config.versionID = 2;
    previous->state = DeploymentState::running;
    current->state = DeploymentState::failed;
    previous->next = current;
    current->previous = previous;
    brain.deployments.insert_or_assign(previous->plan.config.deploymentID(), previous);
    brain.deployments.insert_or_assign(current->plan.config.deploymentID(), current);
    brain.deploymentsByApp.insert_or_assign(current->plan.config.applicationID, current);

    uint64_t failedDeploymentID = current->plan.config.deploymentID();
    current->debugRollbackForTest();

    suite.expect(brain.deploymentsByApp.contains(previous->plan.config.applicationID), "canary_rollback_restores_previous_head_entry");
    suite.expect(brain.deploymentsByApp[previous->plan.config.applicationID] == previous, "canary_rollback_restores_previous_head_pointer");
    suite.expect(previous->state == DeploymentState::running, "canary_rollback_keeps_previous_running");
    suite.expect(previous->next == nullptr, "canary_rollback_unlinks_failed_deployment");
    suite.expect(brain.deployments.contains(failedDeploymentID) == false, "canary_rollback_erases_failed_deployment_index");
    suite.expect(brain.failureCount == 1, "canary_rollback_reports_failed_deploy");
    suite.expect(brain.finCount == 1, "canary_rollback_finishes_mothership_stream");

    brain.deployments.erase(previous->plan.config.deploymentID());
    brain.deploymentsByApp.erase(previous->plan.config.applicationID);
    delete previous;
    thisBrain = savedBrain;
  }

  {
    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;

    ApplicationDeployment *current = new ApplicationDeployment();
    seedCommonPlan(*current, false);
    current->state = DeploymentState::failed;
    brain.deployments.insert_or_assign(current->plan.config.deploymentID(), current);
    brain.deploymentsByApp.insert_or_assign(current->plan.config.applicationID, current);

    uint16_t applicationID = current->plan.config.applicationID;
    uint64_t deploymentID = current->plan.config.deploymentID();
    current->debugRollbackForTest();

    suite.expect(brain.deploymentsByApp.contains(applicationID) == false, "canary_rollback_without_previous_erases_application_head");
    suite.expect(brain.deployments.contains(deploymentID) == false, "canary_rollback_without_previous_erases_failed_deployment_index");
    suite.expect(brain.failureCount == 1, "canary_rollback_without_previous_reports_failed_deploy");

    thisBrain = savedBrain;
  }

  {
    auto parseCount = [](const char *text, uint32_t& count) -> bool {
      String json = {};
      json.assign(text);
      json.need(simdjson::SIMDJSON_PADDING);
      simdjson::dom::parser parser;
      simdjson::dom::element document;
      if (parser.parse(json.data(), json.size()).get(document) != simdjson::SUCCESS)
      {
        return false;
      }
      for (auto field : document.get_object())
      {
        String failure = {};
        return mothershipParseWhiteholeCount(field.value, count, &failure);
      }
      return false;
    };

    uint32_t count = 0;
    suite.expect(parseCount("{\"count\":64}", count) && count == 64, "mothership_parse_whitehole_count_accepts_positive_integer");
    suite.expect(parseCount("{\"count\":0}", count) == false, "mothership_parse_whitehole_count_rejects_zero");
    suite.expect(parseCount("{\"count\":-1}", count) == false, "mothership_parse_whitehole_count_rejects_negative");
    suite.expect(parseCount("{\"count\":1.5}", count) == false, "mothership_parse_whitehole_count_rejects_fraction");
    suite.expect(parseCount("{\"count\":\"2\"}", count) == false, "mothership_parse_whitehole_count_rejects_string");
    suite.expect(parseCount("{\"count\":8193}", count) == false, "mothership_parse_whitehole_count_rejects_per_declaration_overflow");
    suite.expect(parseCount("{\"count\":18446744073709551616}", count) == false, "mothership_parse_whitehole_count_rejects_integer_overflow");

    Vector<Whitehole> expanded = {};
    Whitehole tcp4 = {};
    tcp4.transport = ExternalAddressTransport::tcp;
    tcp4.family = ExternalAddressFamily::ipv4;
    tcp4.source = ExternalAddressSource::hostPublicAddress;
    Whitehole tcp6 = tcp4;
    tcp6.family = ExternalAddressFamily::ipv6;
    Whitehole quic4 = tcp4;
    quic4.transport = ExternalAddressTransport::quic;
    Whitehole quic6 = quic4;
    quic6.family = ExternalAddressFamily::ipv6;
    String failure = {};
    bool expandedAll =
        mothershipAppendWhiteholeDeclaration(expanded, tcp4, 64, &failure) &&
        mothershipAppendWhiteholeDeclaration(expanded, tcp6, 64, &failure) &&
        mothershipAppendWhiteholeDeclaration(expanded, quic4, 2, &failure) &&
        mothershipAppendWhiteholeDeclaration(expanded, quic6, 2, &failure);
    suite.expect(expandedAll && expanded.size() == 132, "mothership_expand_whitehole_counts_creates_exact_allocation_needs");
    suite.expect(expandedAll && expanded[0].family == ExternalAddressFamily::ipv4 && expanded[63].transport == ExternalAddressTransport::tcp,
                 "mothership_expand_whitehole_counts_preserves_first_declaration");
    suite.expect(expandedAll && expanded[64].family == ExternalAddressFamily::ipv6 && expanded[127].transport == ExternalAddressTransport::tcp,
                 "mothership_expand_whitehole_counts_preserves_second_declaration");
    suite.expect(expandedAll && expanded[128].family == ExternalAddressFamily::ipv4 && expanded[128].transport == ExternalAddressTransport::quic,
                 "mothership_expand_whitehole_counts_preserves_third_declaration");
    suite.expect(expandedAll && expanded[130].family == ExternalAddressFamily::ipv6 && expanded[130].transport == ExternalAddressTransport::quic,
                 "mothership_expand_whitehole_counts_preserves_fourth_declaration");

    ScopedFreshRing ring;
    TestBrain brain;
    BrainBase *savedBrain = thisBrain;
    thisBrain = &brain;
    ApplicationDeployment deployment = {};
    seedCommonPlan(deployment, false);
    RoutableResourceLeaseOwner owner = deployment.routableResourceLeaseOwner();
    bool allocatedAll = expandedAll;
    for (Whitehole& whitehole : expanded)
    {
      whitehole.hasAddress = true;
      whitehole.address = whitehole.family == ExternalAddressFamily::ipv6
                              ? IPAddress("2606:4700:4700::1111", true)
                              : IPAddress("1.1.1.1", false);
      allocatedAll &= ApplicationDeployment::allocateWhiteholeSourcePort(whitehole) &&
                      deployment.reserveWhiteholeAddressPortLease(whitehole, owner);
    }
    suite.expect(allocatedAll && brain.routableResourceLeaseRuntimeState.size() == 132 && resolvedWhiteholesValid(expanded),
                 "mothership_expand_whitehole_counts_resolves_distinct_exact_tuples");
    thisBrain = savedBrain;

    expanded.clear();
    suite.expect(mothershipAppendWhiteholeDeclaration(expanded, tcp4, 1, &failure) && expanded.size() == 1,
                 "mothership_expand_whitehole_count_defaults_to_one");
    expanded.clear();
    suite.expect(mothershipAppendWhiteholeDeclaration(expanded, tcp4, mothershipMaximumWhiteholes, &failure),
                 "mothership_expand_whitehole_count_accepts_map_capacity");
    suite.expect(mothershipAppendWhiteholeDeclaration(expanded, tcp4, 1, &failure) == false,
                 "mothership_expand_whitehole_count_rejects_total_overflow");
  }

  {
    DeploymentPlan plan = {};
    String json = "{\"networkAccess\":\"declaredOnly\"}"_ctv;
    json.need(simdjson::SIMDJSON_PADDING);
    simdjson::dom::parser parser;
    simdjson::dom::element document;
    bool parsed = parser.parse(json.data(), json.size()).get(document) == simdjson::SUCCESS;
    if (parsed)
    {
      for (auto field : document.get_object())
      {
        String failure = {};
        parsed = mothershipParseDeploymentPlanNetworkAccess(field.value, plan, &failure);
      }
    }
    suite.expect(parsed && plan.networkAccess == ContainerNetworkAccess::declaredOnly,
                 "mothership_parse_network_access_accepts_declared_only");

    String invalidJSON = "{\"networkAccess\":true}"_ctv;
    invalidJSON.need(simdjson::SIMDJSON_PADDING);
    simdjson::dom::element invalidDocument;
    bool rejectedNonBool = false;
    if (parser.parse(invalidJSON.data(), invalidJSON.size()).get(invalidDocument) == simdjson::SUCCESS)
    {
      for (auto field : invalidDocument.get_object())
      {
        String failure = {};
        rejectedNonBool = mothershipParseDeploymentPlanNetworkAccess(field.value, plan, &failure) == false;
      }
    }
    suite.expect(rejectedNonBool, "mothership_parse_network_access_rejects_non_string");

    Whitehole whitehole = {};
    whitehole.transport = ExternalAddressTransport::tcp;
    whitehole.family = ExternalAddressFamily::ipv6;
    whitehole.source = ExternalAddressSource::hostPublicAddress;
    String failure = {};
    suite.expect(mothershipValidateDeploymentPlanNetworkAccess(plan, &failure),
                 "declared_network_deployment_validation_allows_service_only_policy");
    plan.whiteholes.push_back(whitehole);
    suite.expect(mothershipValidateDeploymentPlanNetworkAccess(plan, &failure),
                 "declared_network_deployment_validation_accepts_valid_whitehole");

    const int forbiddenCapabilities[] = {CAP_NET_RAW, CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_BPF};
    for (int capability : forbiddenCapabilities)
    {
      plan.config.capabilities.insert(capability);
      suite.expect(mothershipValidateDeploymentPlanNetworkAccess(plan, &failure) == false,
                   "declared_network_deployment_validation_rejects_privileged_capability");
      plan.config.capabilities.erase(capability);
    }
    plan.useHostNetworkNamespace = true;
    suite.expect(mothershipValidateDeploymentPlanNetworkAccess(plan, &failure) == false,
                 "declared_network_deployment_validation_rejects_host_netns");
    plan.useHostNetworkNamespace = false;
    plan.wormholes.emplace_back();
    suite.expect(mothershipValidateDeploymentPlanNetworkAccess(plan, &failure) == false,
                 "declared_network_deployment_validation_rejects_wormholes");
  }

  {
    Vector<Whitehole> whiteholes = {};
    Whitehole valid = {};
    valid.transport = ExternalAddressTransport::tcp;
    valid.family = ExternalAddressFamily::ipv6;
    valid.source = ExternalAddressSource::hostPublicAddress;
    valid.hasAddress = true;
    valid.address = IPAddress("2606:4700:4700::1111", true);
    valid.sourcePort = 41'337;
    valid.bindingNonce = 7;
    whiteholes.push_back(valid);
    suite.expect(resolvedWhiteholesValid(whiteholes), "whitehole_only_runtime_validation_accepts_resolved_tuple");

    auto rejects = [&](const char *name) -> void {
      suite.expect(resolvedWhiteholesValid(whiteholes) == false, name);
      whiteholes[0] = valid;
    };
    whiteholes[0].address = {};
    rejects("whitehole_only_runtime_validation_rejects_null_address");
    whiteholes[0].sourcePort = 0;
    rejects("whitehole_only_runtime_validation_rejects_zero_port");
    whiteholes[0].bindingNonce = 0;
    rejects("whitehole_only_runtime_validation_rejects_zero_nonce");
    whiteholes[0].transport = static_cast<ExternalAddressTransport>(UINT8_MAX);
    rejects("whitehole_only_runtime_validation_rejects_unsupported_transport");
    whiteholes[0].family = static_cast<ExternalAddressFamily>(UINT8_MAX);
    rejects("whitehole_only_runtime_validation_rejects_unsupported_family");
    whiteholes[0].source = ExternalAddressSource::distributableSubnet;
    rejects("whitehole_only_runtime_validation_rejects_unsupported_source");
    whiteholes[0].family = ExternalAddressFamily::ipv4;
    rejects("whitehole_only_runtime_validation_rejects_family_mismatch");

    whiteholes.push_back(valid);
    suite.expect(resolvedWhiteholesValid(whiteholes) == false, "whitehole_only_runtime_validation_rejects_duplicate_tuple");
    whiteholes[1].transport = ExternalAddressTransport::quic;
    suite.expect(resolvedWhiteholesValid(whiteholes), "whitehole_only_runtime_validation_allows_same_address_port_for_distinct_transport");
    whiteholes[1] = valid;
    whiteholes[1].sourcePort += 1;
    suite.expect(resolvedWhiteholesValid(whiteholes), "whitehole_only_runtime_validation_allows_distinct_source_port");
    whiteholes.pop_back();

    ContainerPlan plan = {};
    plan.networkAccess = ContainerNetworkAccess::declaredOnly;
    plan.fragment = 7;
    plan.whiteholes = whiteholes;
    suite.expect(declaredNetworkAccessValid(plan), "declared_network_runtime_validation_accepts_application_plan");

    constexpr uint64_t resolverService = 0x0100000000000042ULL;
    plan.whiteholes.clear();
    plan.subscriptions.emplace(resolverService,
                               Subscription(resolverService, ContainerState::scheduled, ContainerState::destroying, SubscriptionNature::any));
    plan.subscriptionPairings.insert(resolverService, SubscriptionPairing(11, 22, resolverService, 5353));
    plan.advertisements.emplace(resolverService,
                                Advertisement(resolverService, ContainerState::scheduled, ContainerState::destroying, 5353));
    plan.advertisementPairings.insert(resolverService, AdvertisementPairing(11, 33, resolverService));
    suite.expect(declaredNetworkAccessValid(plan), "declared_network_runtime_validation_accepts_exact_service_pairings");
    plan.subscriptionPairings.map[resolverService][0].port = 0;
    suite.expect(declaredNetworkAccessValid(plan) == false, "declared_network_runtime_validation_rejects_zero_subscription_port");
    plan.subscriptionPairings.map[resolverService][0].port = 5353;

    plan.system.kind = SystemContainerKind::mothershipTunnelProvider;
    suite.expect(declaredNetworkAccessValid(plan) == false, "declared_network_runtime_validation_rejects_system_mode");

    Vector<Whitehole> capacity = {};
    capacity.reserve(MAX_WHITEHOLE_BINDINGS + 1);
    for (uint32_t index = 1; index <= MAX_WHITEHOLE_BINDINGS; ++index)
    {
      Whitehole candidate = valid;
      candidate.sourcePort = uint16_t(index);
      candidate.bindingNonce = index;
      capacity.push_back(candidate);
    }
    suite.expect(resolvedWhiteholesValid(capacity), "whitehole_only_runtime_validation_accepts_map_capacity");
    Whitehole overflow = valid;
    overflow.sourcePort = uint16_t(MAX_WHITEHOLE_BINDINGS + 1);
    overflow.bindingNonce = MAX_WHITEHOLE_BINDINGS + 1;
    capacity.push_back(overflow);
    suite.expect(resolvedWhiteholesValid(capacity) == false, "whitehole_only_runtime_validation_rejects_map_capacity_overflow");

    plan.system.kind = SystemContainerKind::none;
    plan.whiteholes = capacity;
    suite.expect(declaredNetworkAccessValid(plan) == false, "declared_network_runtime_validation_rejects_map_capacity_overflow");
  }

  {
    auto public4 = [](const char *text) -> bool {
      in_addr address = {};
      return inet_pton(AF_INET, text, &address) == 1 && switchboardPublicDestinationIPv4(address.s_addr);
    };
    auto public6 = [](const char *text) -> bool {
      in6_addr address = {};
      return inet_pton(AF_INET6, text, &address) == 1 && switchboardPublicDestinationIPv6(address.s6_addr);
    };
    suite.expect(public4("1.1.1.1"), "public_destination_classifier_accepts_allocated_ipv4");
    suite.expect(public4("192.0.0.9"), "public_destination_classifier_accepts_global_ipv4_exception");
    suite.expect(public4("168.63.129.16") == false, "public_destination_classifier_rejects_cloud_metadata_ipv4");
    suite.expect(public4("198.51.100.1") == false, "public_destination_classifier_rejects_documentation_ipv4");
    suite.expect(public6("2606:4700:4700::1111"), "public_destination_classifier_accepts_allocated_ipv6");
    suite.expect(public6("2001:1::1"), "public_destination_classifier_accepts_global_ipv6_exception");
    suite.expect(public6("64:ff9b::101:101"), "public_destination_classifier_accepts_public_nat64_destination");
    suite.expect(public6("::ffff:127.0.0.1") == false, "public_destination_classifier_rejects_mapped_nonpublic_ipv4");
    suite.expect(public6("2001:db8::1") == false, "public_destination_classifier_rejects_documentation_ipv6");
    suite.expect(public6("3f00::1") == false, "public_destination_classifier_rejects_unallocated_ipv6");
    suite.expect(public6("fdf8:d94c:7c33:e26e:ca4b:f500::1") == false, "public_destination_classifier_rejects_container_prefix");
  }

  return (suite.failed == 0) ? 0 : 1;
}
