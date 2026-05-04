#pragma once

#include <prodigy/iaas/iaas.h>
#include <services/debug.h>
#include <prodigy/iaas/bootstrap.ssh.h>
#include <prodigy/brain/base.h>
#include <prodigy/cluster.machine.helpers.h>
#include <prodigy/netdev.detect.h>
#include <networking/bgp.h>
#include <services/base64.h>
#include <services/filesystem.h>
#include <services/random.h>
#include <simdjson.h>
#include <curl/curl.h>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

class VultrHttp {
public:
    static constexpr long connectTimeoutMs = 3000L;
    static constexpr long getTimeoutMs = 15000L;
    static constexpr long sendTimeoutMs = 20000L;
    static constexpr long createSendTimeoutMs = 8000L;

    static bool ensureGlobalInit(void)
    {
        static bool initialized = (curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK);
        return initialized;
    }

    static bool get(const char *url, const struct curl_slist *headers, String &out, long *httpCode = nullptr)
    {
        if (ensureGlobalInit() == false)
        {
            return false;
        }

        CURL *curl = curl_easy_init(); if (!curl) return false;
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, connectTimeoutMs);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, getTimeoutMs);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[] (char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
            String *s = (String*)userdata; s->append((uint8_t*)ptr, size * nmemb); return size * nmemb; });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
        CURLcode rc = curl_easy_perform(curl);
        long code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        if (httpCode) *httpCode = code;
        curl_easy_cleanup(curl);
        return rc == CURLE_OK;
    }

    static bool send(const char *method, const char *url, const struct curl_slist *headers, const String &body, String &out, long *httpCode = nullptr, long timeoutMs = sendTimeoutMs)
    {
        if (ensureGlobalInit() == false)
        {
            return false;
        }

        CURL *curl = curl_easy_init(); if (!curl) return false;
        String bodyText = {};
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, connectTimeoutMs);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeoutMs);
        if (body.size() > 0)
        {
            bodyText.assign(body);
            bodyText.addNullTerminator();
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, bodyText.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, long(body.size()));
        }
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[] (char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
            String *s = (String*)userdata; s->append((uint8_t*)ptr, size * nmemb); return size * nmemb; });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
        CURLcode rc = curl_easy_perform(curl);
        long code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        if (httpCode) *httpCode = code;
        curl_easy_cleanup(curl);
        return rc == CURLE_OK;
    }

    class MultiRequest {
    public:

        CURL *easy = nullptr;
        struct curl_slist *headers = nullptr;
        void *context = nullptr;
        String method = {};
        String url = {};
        String body = {};
        String response = {};
        long timeoutMs = sendTimeoutMs;
        long httpCode = 0;
        CURLcode curlCode = CURLE_OK;
        bool completed = false;
        bool added = false;

        void resetResult(void)
        {
            response.clear();
            httpCode = 0;
            curlCode = CURLE_OK;
            completed = false;
            added = false;
        }

        void clearTransport(void)
        {
            if (easy != nullptr)
            {
                curl_easy_cleanup(easy);
                easy = nullptr;
            }

            if (headers != nullptr)
            {
                curl_slist_free_all(headers);
                headers = nullptr;
            }
        }

        ~MultiRequest()
        {
            clearTransport();
        }
    };

    class MultiClient {
    private:

        CURLM *multi = nullptr;
        Vector<MultiRequest *> completed = {};
        uint32_t inFlight = 0;

        static size_t writeResponse(char *ptr, size_t size, size_t nmemb, void *userdata)
        {
            String *response = reinterpret_cast<String *>(userdata);
            response->append(reinterpret_cast<uint8_t *>(ptr), size * nmemb);
            return size * nmemb;
        }

        void collectCompleted(void)
        {
            int messagesRemaining = 0;
            while (CURLMsg *message = curl_multi_info_read(multi, &messagesRemaining))
            {
                if (message->msg != CURLMSG_DONE)
                {
                    continue;
                }

                MultiRequest *request = nullptr;
                (void)curl_easy_getinfo(message->easy_handle, CURLINFO_PRIVATE, &request);
                if (request == nullptr)
                {
                    curl_multi_remove_handle(multi, message->easy_handle);
                    curl_easy_cleanup(message->easy_handle);
                    continue;
                }

                request->curlCode = message->data.result;
                request->httpCode = 0;
                (void)curl_easy_getinfo(message->easy_handle, CURLINFO_RESPONSE_CODE, &request->httpCode);
                request->completed = true;
                request->added = false;

                curl_multi_remove_handle(multi, message->easy_handle);
                request->easy = nullptr;
                curl_easy_cleanup(message->easy_handle);
                completed.push_back(request);
                if (inFlight > 0)
                {
                    inFlight -= 1;
                }
            }
        }

    public:

        bool init(void)
        {
            if (multi != nullptr)
            {
                return true;
            }

            if (ensureGlobalInit() == false)
            {
                return false;
            }

            multi = curl_multi_init();
            return (multi != nullptr);
        }

        bool start(MultiRequest& request)
        {
            if (init() == false)
            {
                return false;
            }

            request.easy = curl_easy_init();
            if (request.easy == nullptr)
            {
                return false;
            }

            curl_easy_setopt(request.easy, CURLOPT_URL, request.url.c_str());
            curl_easy_setopt(request.easy, CURLOPT_CONNECTTIMEOUT_MS, connectTimeoutMs);
            curl_easy_setopt(request.easy, CURLOPT_TIMEOUT_MS, request.timeoutMs);
            curl_easy_setopt(request.easy, CURLOPT_WRITEFUNCTION, &writeResponse);
            curl_easy_setopt(request.easy, CURLOPT_WRITEDATA, &request.response);
            curl_easy_setopt(request.easy, CURLOPT_PRIVATE, &request);
            if (request.headers != nullptr)
            {
                curl_easy_setopt(request.easy, CURLOPT_HTTPHEADER, request.headers);
            }

            if (request.method == "GET"_ctv)
            {
                curl_easy_setopt(request.easy, CURLOPT_HTTPGET, 1L);
            }
            else
            {
                curl_easy_setopt(request.easy, CURLOPT_CUSTOMREQUEST, request.method.c_str());
                if (request.body.size() > 0)
                {
                    long bodySize = long(request.body.size());
                    request.body.addNullTerminator();
                    curl_easy_setopt(request.easy, CURLOPT_POSTFIELDS, request.body.c_str());
                    curl_easy_setopt(request.easy, CURLOPT_POSTFIELDSIZE, bodySize);
                }
                else
                {
                    curl_easy_setopt(request.easy, CURLOPT_POSTFIELDS, "");
                    curl_easy_setopt(request.easy, CURLOPT_POSTFIELDSIZE, 0L);
                }
            }

            CURLMcode addCode = curl_multi_add_handle(multi, request.easy);
            if (addCode != CURLM_OK)
            {
                request.clearTransport();
                return false;
            }

            request.added = true;
            inFlight += 1;
            int running = 0;
            (void)curl_multi_perform(multi, &running);
            collectCompleted();
            return true;
        }

        bool pump(int timeoutMs = 0)
        {
            if (multi == nullptr)
            {
                return false;
            }

            int running = 0;
            CURLMcode performCode = curl_multi_perform(multi, &running);
            if (performCode != CURLM_OK)
            {
                collectCompleted();
                return false;
            }

            collectCompleted();
            if (completed.empty() == false || inFlight == 0)
            {
                return true;
            }

            int nReady = 0;
            CURLMcode pollCode = curl_multi_poll(multi, nullptr, 0, timeoutMs, &nReady);
            if (pollCode != CURLM_OK)
            {
                collectCompleted();
                return false;
            }

            performCode = curl_multi_perform(multi, &running);
            collectCompleted();
            return (performCode == CURLM_OK);
        }

        MultiRequest *popCompleted(void)
        {
            if (completed.empty())
            {
                return nullptr;
            }

            MultiRequest *request = completed.back();
            completed.pop_back();
            return request;
        }

        uint32_t pendingCount(void) const
        {
            return inFlight;
        }

        ~MultiClient()
        {
            if (multi != nullptr)
            {
                curl_multi_cleanup(multi);
                multi = nullptr;
            }
        }
    };
};

// Vultr instance creation is asynchronous on the provider side. Keep the local
// poll cadence tight so we discover accepted creates and SSH readiness quickly
// Reissue detail polls immediately after an observed state change, and only
// back off when the remote state stays unchanged, so the hot path does not burn
// half-second idle gaps after every provisioning transition.
static inline constexpr uint32_t vultrCreateRecoveryPollSleepMs = 500u;
static inline constexpr uint32_t vultrCreateRecoveryMaxAttempts = 48u;
static inline constexpr uint32_t vultrMachineProvisioningUnchangedPollSleepMs = 250u;
static inline constexpr uint32_t vultrMachineProvisioningTimeoutMs = 180'000u;

static inline struct curl_slist* vultr_auth_headers(const ProdigyRuntimeEnvironmentConfig& runtimeEnvironment)
{
    if (runtimeEnvironment.providerCredentialMaterial.size() == 0) return nullptr;
    struct curl_slist *h = nullptr;
    String auth; auth.snprintf<"Authorization: Bearer {}"_ctv>(runtimeEnvironment.providerCredentialMaterial);
    h = curl_slist_append(h, auth.c_str());
    h = curl_slist_append(h, "Accept: application/json");
    return h;
}

static inline uint32_t vultrHashRackIdentity(std::string_view s)
{
    uint32_t h = 2166136261u;
    for (unsigned char c : s)
    {
        h ^= c;
        h *= 16777619u;
    }

    return h;
}

static inline uint32_t vultrExtractRackUUID(simdjson::dom::element dev)
{
    std::string_view candidates[] = { "rack", "rack_id", "switch_uuid", "host_id", "physical_host", "node", "chassis_id", "physicalHost" };
    for (auto key : candidates)
    {
        std::string_view value = {};
        if (!dev[key].get(value) && value.size() > 0)
        {
            return vultrHashRackIdentity(value);
        }
    }

    std::string_view region = {};
    std::string_view plan = {};
    (void)dev["region"].get(region);
    (void)dev["plan"].get(plan);
    if (region.size() > 0 || plan.size() > 0)
    {
        String combo = {};
        combo.snprintf<"{}/{}"_ctv>(String(region), String(plan));
        return vultrHashRackIdentity(std::string_view(combo.c_str(), combo.size()));
    }

    std::string_view id = {};
    (void)dev["id"].get(id);
    if (id.size() > 0)
    {
        return vultrHashRackIdentity(id);
    }

    return Random::generateNumberWithNBits<32, uint32_t>();
}

static inline bool vultrInferArchitectureFromText(std::string_view text, MachineCpuArchitecture& architecture)
{
    architecture = MachineCpuArchitecture::unknown;
    if (text.size() == 0)
    {
        return false;
    }

    String lower = {};
    for (char ch : text)
    {
        lower.append(char(std::tolower(static_cast<unsigned char>(ch))));
    }

    if (lower.equal("amd"_ctv)
        || lower.equal("intel"_ctv)
        || lower.equal("x86"_ctv)
        || lower.equal("x64"_ctv)
        || lower.equal("amd64"_ctv)
        || lower.equal("x86_64"_ctv))
    {
        architecture = MachineCpuArchitecture::x86_64;
        return true;
    }

    if (lower.equal("arm"_ctv)
        || lower.equal("arm64"_ctv)
        || lower.equal("aarch64"_ctv)
        || lower.equal("ampere"_ctv))
    {
        architecture = MachineCpuArchitecture::aarch64;
        return true;
    }

    return false;
}

static inline simdjson::dom::array vultrGetMachineArray(simdjson::dom::element doc, MachineConfig::MachineKind kind)
{
    if (kind == MachineConfig::MachineKind::vm && doc["instances"].is_array())
    {
        return doc["instances"].get_array();
    }

    if (kind == MachineConfig::MachineKind::bareMetal && doc["bare_metals"].is_array())
    {
        return doc["bare_metals"].get_array();
    }

    if (doc["items"].is_array())
    {
        return doc["items"].get_array();
    }

    return simdjson::dom::array();
}

static inline bool vultrFindMachineIDByLabel(simdjson::dom::element doc, MachineConfig::MachineKind kind, std::string_view label, String& idOut)
{
    idOut.clear();

    auto items = vultrGetMachineArray(doc, kind);
    for (auto item : items)
    {
        std::string_view itemLabel = {};
        if (item["label"].get(itemLabel) != simdjson::SUCCESS || itemLabel != label)
        {
            continue;
        }

        std::string_view itemID = {};
        if (item["id"].get(itemID) == simdjson::SUCCESS && itemID.size() > 0)
        {
            idOut.assign(itemID);
            return true;
        }
    }

    return false;
}

static inline bool vultrInferPlanCpuCapability(simdjson::dom::element plan, MachineSchemaCpuCapability& capability, String *error = nullptr)
{
    capability = {};
    if (error)
    {
        error->clear();
    }

    std::string_view cpuVendor = {};
    if (plan["cpu_vendor"].get(cpuVendor) == simdjson::SUCCESS && cpuVendor.size() > 0)
    {
        if (vultrInferArchitectureFromText(cpuVendor, capability.architecture))
        {
            capability.provenance = MachineSchemaCpuCapabilityProvenance::unavailable;
            return true;
        }

        if (error)
        {
            error->snprintf<"vultr cpu_vendor '{}' unsupported"_ctv>(String(cpuVendor));
        }
        return false;
    }

    std::string_view type = {};
    if (plan["type"].get(type) == simdjson::SUCCESS && type.size() > 0)
    {
        if (vultrInferArchitectureFromText(type, capability.architecture))
        {
            capability.provenance = MachineSchemaCpuCapabilityProvenance::unavailable;
            return true;
        }
    }

    std::string_view id = {};
    if (plan["id"].get(id) == simdjson::SUCCESS && id.size() > 0)
    {
        if (vultrInferArchitectureFromText(id, capability.architecture))
        {
            capability.provenance = MachineSchemaCpuCapabilityProvenance::unavailable;
            return true;
        }
    }

    if (error)
    {
        error->assign("vultr plan architecture missing or unsupported"_ctv);
    }
    return false;
}

static inline bool vultrInferPlanCpuCapability(const String& planID, const String& planType, const String& cpuVendor, MachineSchemaCpuCapability& capability, String *error = nullptr)
{
    capability = {};
    if (error)
    {
        error->clear();
    }

    if (cpuVendor.size() > 0)
    {
        std::string_view cpuVendorView(reinterpret_cast<const char *>(cpuVendor.data()), size_t(cpuVendor.size()));
        if (vultrInferArchitectureFromText(cpuVendorView, capability.architecture))
        {
            capability.provenance = MachineSchemaCpuCapabilityProvenance::unavailable;
            return true;
        }

        if (error)
        {
            error->snprintf<"vultr cpu_vendor '{}' unsupported"_ctv>(cpuVendor);
        }
        return false;
    }

    if (planType.size() > 0)
    {
        std::string_view typeView(reinterpret_cast<const char *>(planType.data()), size_t(planType.size()));
        if (vultrInferArchitectureFromText(typeView, capability.architecture))
        {
            capability.provenance = MachineSchemaCpuCapabilityProvenance::unavailable;
            return true;
        }
    }

    if (planID.size() > 0)
    {
        std::string_view idView(reinterpret_cast<const char *>(planID.data()), size_t(planID.size()));
        if (vultrInferArchitectureFromText(idView, capability.architecture))
        {
            capability.provenance = MachineSchemaCpuCapabilityProvenance::unavailable;
            return true;
        }
    }

    if (error)
    {
        error->assign("vultr plan architecture missing or unsupported"_ctv);
    }
    return false;
}

static inline bool vultrParseAssignedIPv4(std::string_view value, uint32_t& out)
{
    out = 0;
    if (inet_pton(AF_INET, String(value).c_str(), &out) != 1)
    {
        return false;
    }

    return out != 0;
}

static inline bool vultrExtractPublicIPv6(simdjson::dom::element dev, String& publicAddress)
{
    publicAddress.clear();

    std::string_view mainIP = {};
    if (!dev["v6_main_ip"].get(mainIP) && mainIP.size() > 0)
    {
        struct in6_addr parsed = {};
        String address = {};
        address.assign(mainIP);
        if (inet_pton(AF_INET6, address.c_str(), &parsed) == 1)
        {
            publicAddress = address;
            return true;
        }
    }

    return false;
}

static inline bool vultrExtractInternalIPv4(simdjson::dom::element dev, String& privateAddress)
{
    privateAddress.clear();

    std::string_view internalIP = {};
    if (!dev["internal_ip"].get(internalIP) && internalIP.size() > 0)
    {
        uint32_t parsed = 0;
        if (vultrParseAssignedIPv4(internalIP, parsed))
        {
            privateAddress.assign(internalIP);
            return true;
        }
    }

    return false;
}

static inline bool vultrExtractAttachedVPCIPv4(simdjson::dom::element doc, String& privateAddress)
{
    privateAddress.clear();

    simdjson::dom::array vpcs = {};
    if (doc["vpcs"].get(vpcs) != simdjson::SUCCESS)
    {
        return false;
    }

    for (auto vpc : vpcs)
    {
        std::string_view ipAddress = {};
        if (!vpc["ip_address"].get(ipAddress) && ipAddress.size() > 0)
        {
            uint32_t parsed = 0;
            if (vultrParseAssignedIPv4(ipAddress, parsed))
            {
                privateAddress.assign(ipAddress);
                return true;
            }
        }
    }

    return false;
}

static inline void vultrAppendManagedVPCCreateFields(MachineConfig::MachineKind kind, const String& vpcID, String& body)
{
    if (vpcID.size() == 0)
    {
        return;
    }

    if (kind == MachineConfig::MachineKind::vm)
    {
        // Vultr instances require enable_vpc plus attach_vpc at create time; an
        // unknown field is ignored, which silently leaves the VM without a
        // private address and strands bootstrap.
        body.append(",\"enable_vpc\":true,\"attach_vpc\":["_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, vpcID);
        body.append("]"_ctv);
    }
}

static inline void vultrManagedVPCDescription(const String& region, String& description)
{
    description.snprintf<"prodigy-managed-vpc-{}"_ctv>(region);
}

static inline uint32_t vultrManagedVPCPrefixLength(void)
{
    // /20 yields 4096 private IPv4 addresses, which is ample headroom for
    // mixed brain/worker replacement and future VM expansion in one region.
    return 20;
}

static inline void vultrManagedVPCSubnet(const String& region, String& subnet, uint32_t& prefixLength)
{
    uint32_t regionHash = vultrHashRackIdentity(std::string_view(reinterpret_cast<const char *>(region.data()), size_t(region.size())));
    uint32_t secondOctet = (regionHash % 254u) + 1u;
    uint32_t thirdOctet = ((regionHash >> 8) & 0x0fu) * 16u;
    prefixLength = vultrManagedVPCPrefixLength();
    subnet.snprintf<"10.{}.{}.0"_ctv>(secondOctet, thirdOctet);
}

static inline bool vultrMachineKindUsesManagedVPC(MachineConfig::MachineKind kind)
{
    return kind == MachineConfig::MachineKind::vm || kind == MachineConfig::MachineKind::bareMetal;
}

static inline bool vultrExtractVPCSubnetPlan(simdjson::dom::element vpc, String& subnet, uint32_t& prefixLength)
{
    subnet.clear();
    prefixLength = 0;

    std::string_view v4Subnet = {};
    uint64_t mask = 0;
    if (vpc["v4_subnet"].get(v4Subnet) == simdjson::SUCCESS && v4Subnet.size() > 0)
    {
        subnet.assign(v4Subnet);
    }
    if (vpc["v4_subnet_mask"].get(mask) == simdjson::SUCCESS && mask > 0 && mask <= 32)
    {
        prefixLength = uint32_t(mask);
    }

    if (subnet.size() > 0 && prefixLength > 0)
    {
        return true;
    }

    std::string_view ipBlock = {};
    mask = 0;
    if (vpc["ip_block"].get(ipBlock) == simdjson::SUCCESS && ipBlock.size() > 0)
    {
        subnet.assign(ipBlock);
    }
    if (vpc["prefix_length"].get(mask) == simdjson::SUCCESS && mask > 0 && mask <= 32)
    {
        prefixLength = uint32_t(mask);
    }

    return subnet.size() > 0 && prefixLength > 0;
}

static inline bool vultrExtractResourceLabel(simdjson::dom::element dev, String& label)
{
    label.clear();

    std::string_view value = {};
    if (!dev["label"].get(value) && value.size() > 0)
    {
        label.assign(value);
        return true;
    }

    return false;
}

static inline bool vultrBlockMatchesMachineLabel(simdjson::dom::element block, std::string_view machineLabel)
{
    if (machineLabel.size() == 0)
    {
        return false;
    }

    std::string_view attachedLabel = {};
    if (!block["attached_to_instance_label"].get(attachedLabel) && attachedLabel == machineLabel)
    {
        return true;
    }

    std::string_view blockLabel = {};
    if (!block["label"].get(blockLabel) && blockLabel.size() > 0)
    {
        String prefix = {};
        prefix.assign(machineLabel.data(), machineLabel.size());
        prefix.append("-boot"_ctv);
        std::string_view prefixView(reinterpret_cast<const char *>(prefix.data()), size_t(prefix.size()));
        if (blockLabel.size() >= prefixView.size() && blockLabel.substr(0, prefixView.size()) == prefixView)
        {
            return true;
        }
    }

    return false;
}

static inline uint32_t vultrDefaultBlockStorageMB(void)
{
    return 50u * 1024u;
}

static inline uint32_t vultrRequestedBlockStorageMB(const MachineConfig& config)
{
    return config.nStorageMB > 0 ? config.nStorageMB : vultrDefaultBlockStorageMB();
}

static inline bool vultrExtractPaginationNextCursor(simdjson::dom::element doc, String& nextCursor)
{
    nextCursor.clear();

    simdjson::dom::element meta = {};
    if (doc["meta"].get(meta) != simdjson::SUCCESS || meta.is_null())
    {
        return false;
    }

    simdjson::dom::element links = {};
    if (meta["links"].get(links) != simdjson::SUCCESS || links.is_null())
    {
        return false;
    }

    std::string_view next = {};
    if (links["next"].get(next) == simdjson::SUCCESS && next.size() > 0)
    {
        nextCursor.assign(next);
        return true;
    }

    return false;
}

static inline bool vultrAppendURLEncodedQueryValue(String& output, const String& value, String *error = nullptr)
{
    if (error)
    {
        error->clear();
    }

    CURL *curl = curl_easy_init();
    if (curl == nullptr)
    {
        if (error)
        {
            error->assign("vultr url encoder init failed"_ctv);
        }
        return false;
    }

    String text = {};
    text.assign(value);
    text.addNullTerminator();

    char *escaped = curl_easy_escape(curl, text.c_str(), int(value.size()));
    if (escaped == nullptr)
    {
        curl_easy_cleanup(curl);
        if (error)
        {
            error->assign("vultr url encoder escape failed"_ctv);
        }
        return false;
    }

    output.append(escaped);
    curl_free(escaped);
    curl_easy_cleanup(curl);
    return true;
}

static inline bool vultrBuildPlansLookupURL(const String& cursor, String& url, String *error = nullptr)
{
    if (error)
    {
        error->clear();
    }

    url.assign("https://api.vultr.com/v2/plans?per_page=100"_ctv);
    if (cursor.size() == 0)
    {
        return true;
    }

    url.append("&cursor="_ctv);
    return vultrAppendURLEncodedQueryValue(url, cursor, error);
}

static inline bool vultrExtractPlanMetadata(
    simdjson::dom::element doc,
    const String& planID,
    String& storageType,
    String& planType,
    String& cpuVendor,
    bool& found,
    String& nextCursor,
    String *error = nullptr)
{
    storageType.clear();
    planType.clear();
    cpuVendor.clear();
    found = false;
    nextCursor.clear();
    if (error)
    {
        error->clear();
    }

    simdjson::dom::array plans = {};
    if (doc["plans"].get(plans) != simdjson::SUCCESS)
    {
        if (error)
        {
            error->assign("vultr plans response missing plans array"_ctv);
        }
        return false;
    }

    std::string_view wantedPlan(reinterpret_cast<const char *>(planID.data()), size_t(planID.size()));
    for (auto plan : plans)
    {
        std::string_view id = {};
        if (plan["id"].get(id) != simdjson::SUCCESS || id != wantedPlan)
        {
            continue;
        }

        found = true;

        std::string_view extractedStorageType = {};
        if (plan["storage_type"].get(extractedStorageType) == simdjson::SUCCESS && extractedStorageType.size() > 0)
        {
            storageType.assign(extractedStorageType);
        }

        std::string_view extractedType = {};
        if (plan["type"].get(extractedType) == simdjson::SUCCESS && extractedType.size() > 0)
        {
            planType.assign(extractedType);
        }

        std::string_view extractedCpuVendor = {};
        if (plan["cpu_vendor"].get(extractedCpuVendor) == simdjson::SUCCESS && extractedCpuVendor.size() > 0)
        {
            cpuVendor.assign(extractedCpuVendor);
        }

        break;
    }

    (void)vultrExtractPaginationNextCursor(doc, nextCursor);
    return true;
}

class VultrNeuronIaaS : public NeuronIaaS {
private:
    ProdigyRuntimeEnvironmentConfig runtimeEnvironment;
    IPAddress gatewayPrivate4;
    String bgpMD5;
    uint32_t remoteASN{0};

    void reportBGPUnhealthy(const char *reason)
    {
        basics_log("%s\n", reason);
    }

    bool fetchBGPAccount()
    {
        struct curl_slist *h = vultr_auth_headers(runtimeEnvironment); if (!h) return false;
        String resp; bool ok = VultrHttp::get("https://api.vultr.com/v2/account/bgp", h, resp);
        curl_slist_free_all(h);
        if (!ok) return false;

        simdjson::dom::parser parser; simdjson::dom::element doc; if (parser.parse(resp.c_str(), resp.size()).get(doc)) return false;
        // The docs example shows {"enabled":true, "asn":20473, "pasword":"..."}
        // Be permissive: accept both "password" and the misspelled "pasword".
        bool enabled = false; (void)doc["enabled"].get(enabled);
        uint64_t asnVal = 0; (void)doc["asn"].get(asnVal);
        std::string_view pw;
        if (doc["password"].get(pw))
        {
            (void)doc["pasword"].get(pw);
        }
        if (!enabled || pw.size() == 0 || asnVal == 0) return false;
        bgpMD5.assign(pw);
        remoteASN = (uint32_t)asnVal;
        return true;
    }

public:
    void configureRuntimeEnvironment(const ProdigyRuntimeEnvironmentConfig& config) override
    {
        prodigyOwnRuntimeEnvironmentConfig(config, runtimeEnvironment);
    }

    void gatherSelfData(uint128_t& uuid, String& metro, bool& isBrain, EthDevice& eth, IPAddress& private4) override
    {
        String deviceName;
        if (prodigyResolvePrimaryNetworkDevice(deviceName))
        {
            eth.setDevice(deviceName);
        }

        // Private IPv4 and default gateway
        private4.is6 = false; private4.v4 = eth.getPrivate4();
        gatewayPrivate4.is6 = false; gatewayPrivate4.v4 = eth.getPrivate4Gateway(private4.v4);

        // Runtime persistence owns the canonical brain UUID.
        uuid = 0;
        if (runtimeEnvironment.providerScope.size() > 0) metro = runtimeEnvironment.providerScope;
        isBrain = false; // Neuron IaaS side does not assert brain role
    }

    void gatherBGPConfig(NeuronBGPConfig& config, EthDevice& eth, const IPAddress& private4) override
    {
        config = {};

        if (fetchBGPAccount() == false)
        {
            reportBGPUnhealthy("vultr: /v2/account/bgp disabled or fetch failed");
            return;
        }

        IPAddress public6 = eth.getGlobal6();

        config.enabled = true;
        config.ourBGPID = private4.v4;
        config.community = (uint32_t(20473) << 16) | 6000u;
        config.nextHop4 = gatewayPrivate4;
        config.nextHop6 = public6;

        // Static peers from Vultr docs (bare metal):
        // IPv4 neighbor 169.254.1.1, IPv6 neighbor 2001:19f0:ffff::1, multihop (TTL) 2
        IPAddress gateway4 = gatewayPrivate4;
        IPAddress source4 = private4;
        eth.addIndirectRoute("169.254.0.0"_ctv, 16, AF_INET, gateway4, source4);

        NeuronBGPPeerConfig peer4 = {};
        peer4.peerASN = static_cast<uint16_t>(remoteASN);
        peer4.peerAddress = IPAddress("169.254.1.1", false);
        peer4.sourceAddress = private4;
        peer4.md5Password = bgpMD5;
        peer4.hopLimit = 2;
        config.peers.push_back(peer4);

        NeuronBGPPeerConfig peer6 = {};
        peer6.peerASN = static_cast<uint16_t>(remoteASN);
        peer6.peerAddress = IPAddress("2001:19f0:ffff::1", true);
        peer6.sourceAddress = public6;
        peer6.md5Password = bgpMD5;
        peer6.hopLimit = 2;
        config.peers.push_back(peer6);
    }

    void downloadContainerToPath(CoroutineStack *coro, uint64_t deploymentID, const String& path) override
    {
        (void)coro; (void)deploymentID; (void)path;
    }
};

class VultrBrainIaaS : public BrainIaaS {
private:
    ProdigyRuntimeEnvironmentConfig runtimeEnvironment;
    String bootstrapSSHUser;
    String bootstrapSSHPrivateKeyPath;
    String bootstrapSSHPublicKey;
    Vault::SSHKeyPackage bootstrapSSHHostKeyPackage;
    String provisioningClusterUUIDTagValue;
    BrainIaaSMachineProvisioningProgressReporter provisioningProgress;
    // Helpers
    static uint128_t hash_uuid(std::string_view s)
    { uint128_t u = 0; for (char c : s) { u = (u * 131) + (uint8_t)c; } return u; }

    static int64_t parse_rfc3339_ms(std::string_view v)
    {
        if (v.size() < 20) return Time::now<TimeResolution::ms>();
        struct tm tmv{}; tmv.tm_year = (v[0]-'0')*1000+(v[1]-'0')*100+(v[2]-'0')*10+(v[3]-'0') - 1900;
        tmv.tm_mon  = (v[5]-'0')*10+(v[6]-'0') - 1; tmv.tm_mday = (v[8]-'0')*10+(v[9]-'0');
        tmv.tm_hour = (v[11]-'0')*10+(v[12]-'0'); tmv.tm_min   = (v[14]-'0')*10+(v[15]-'0');
        tmv.tm_sec  = (v[17]-'0')*10+(v[18]-'0'); tmv.tm_isdst  = 0;
#ifdef _GNU_SOURCE
        time_t secs = timegm(&tmv);
#else
        char *oldtz = getenv("TZ"); setenv("TZ","UTC",1); tzset(); time_t secs = mktime(&tmv); if (oldtz) setenv("TZ",oldtz,1); else unsetenv("TZ"); tzset();
#endif
        return (int64_t)secs * 1000LL;
    }

    static bool parse_ipv4(std::string_view v, uint32_t &out)
    { return inet_pton(AF_INET, String(v).c_str(), &out) == 1; }

    static bool parse_ipv4(String v, uint32_t &out)
    { return inet_pton(AF_INET, v.c_str(), &out) == 1; }

    struct curl_slist* auth_headers()
    {
        if (runtimeEnvironment.providerCredentialMaterial.size() == 0) return nullptr;
        struct curl_slist *h = nullptr;
        String auth; auth.snprintf<"Authorization: Bearer {}"_ctv>(runtimeEnvironment.providerCredentialMaterial);
        h = curl_slist_append(h, auth.c_str());
        h = curl_slist_append(h, "Content-Type: application/json");
        h = curl_slist_append(h, "Accept: application/json");
        return h;
    }

    class PendingMachineProvisioning
    {
    public:

        String hostname;
        String createdID;
        uint32_t requestedStorageMB = 0;
        bool managedVPCRequestedAtCreate = false;
    };

    class ConcurrentWaitCoordinator;

public:

    enum class MachineProvisioningPollPhase : uint8_t
    {
        waitingForActiveBeforeVPCAttach = 0,
        waitingForVPCPrivateIP = 1,
        waitingForPublicSSHAddress = 2,
        waitingForInstanceAddresses = 3,
        waitingForSSHAccept = 4,
        transportRetry = 5
    };

    class MachineProvisioningPollObservation
    {
    public:

        MachineProvisioningPollPhase phase = MachineProvisioningPollPhase::waitingForInstanceAddresses;
        bool vpcAttachSubmitted = false;
        String providerStatus = {};

        bool operator==(const MachineProvisioningPollObservation& other) const
        {
            return phase == other.phase
                && vpcAttachSubmitted == other.vpcAttachSubmitted
                && providerStatus.equals(other.providerStatus);
        }

        bool operator!=(const MachineProvisioningPollObservation& other) const
        {
            return (*this == other) == false;
        }
    };

    static uint32_t nextMachineProvisioningPollDelayMs(
        const MachineProvisioningPollObservation *previous,
        const MachineProvisioningPollObservation& current)
    {
        if (previous == nullptr || *previous != current)
        {
            return 0;
        }

        return vultrMachineProvisioningUnchangedPollSleepMs;
    }

private:

    class ConcurrentWaitTask : public CoroutineStack
    {
    public:

        ConcurrentWaitCoordinator *coordinator = nullptr;
        PendingMachineProvisioning pending = {};
        String schema = {};
        String providerMachineType = {};
        MachineConfig::MachineKind kind = MachineConfig::MachineKind::vm;
        const String *requiredVMVPCID = nullptr;
        bool vpcAttachSubmitted = false;
        bool sleeping = false;
        int64_t wakeAtMs = 0;
        bool done = false;
        bool success = false;
        String error = {};
        Machine *machine = nullptr;
        VultrHttp::MultiRequest detailRequest = {};

        ~ConcurrentWaitTask()
        {
            if (machine != nullptr)
            {
                delete machine;
                machine = nullptr;
            }
        }

        void sleepForMs(uint32_t delayMs)
        {
            sleeping = true;
            wakeAtMs = Time::now<TimeResolution::ms>() + int64_t(delayMs);
        }

        bool startDetailRequest(void)
        {
            detailRequest.clearTransport();
            detailRequest.resetResult();
            detailRequest.context = this;
            detailRequest.method.assign("GET"_ctv);
            detailRequest.url.snprintf<"https://api.vultr.com/v2/{}/{}"_ctv>(String(coordinator->owner->resourcePath(kind)), pending.createdID);
            detailRequest.timeoutMs = VultrHttp::getTimeoutMs;
            detailRequest.headers = coordinator->owner->auth_headers();
            if (detailRequest.headers == nullptr)
            {
                error.assign("vultr api key missing"_ctv);
                return false;
            }

            if (coordinator->http.start(detailRequest) == false)
            {
                error.assign("vultr detail request start failed"_ctv);
                return false;
            }

            return true;
        }

        void execute(void)
        {
            bool waitingForVPCPrivateAddress = requiredVMVPCID != nullptr
                && requiredVMVPCID->size() > 0;
            vpcAttachSubmitted = pending.managedVPCRequestedAtCreate;
            int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(vultrMachineProvisioningTimeoutMs);
            String lastStatus = {};
            lastStatus.assign("launch-submitted"_ctv);
            MachineProvisioningPollObservation previousObservation = {};
            bool havePreviousObservation = false;

            auto nextDelayMs = [&] (MachineProvisioningPollPhase phase, std::string_view providerStatus) -> uint32_t {

                MachineProvisioningPollObservation current = {};
                current.phase = phase;
                current.vpcAttachSubmitted = vpcAttachSubmitted;
                current.providerStatus.assign(providerStatus);
                uint32_t delayMs = nextMachineProvisioningPollDelayMs(havePreviousObservation ? &previousObservation : nullptr, current);
                previousObservation = std::move(current);
                havePreviousObservation = true;
                return delayMs;
            };

            while (Time::now<TimeResolution::ms>() < deadlineMs)
            {
                if (startDetailRequest() == false)
                {
                    done = true;
                    success = false;
                    co_return;
                }

                co_await suspend();

                if (detailRequest.curlCode != CURLE_OK || detailRequest.httpCode < 200 || detailRequest.httpCode >= 300)
                {
                    uint32_t delayMs = nextDelayMs(MachineProvisioningPollPhase::transportRetry, {});
                    if (delayMs > 0)
                    {
                        sleepForMs(delayMs);
                        co_await suspend();
                    }
                    continue;
                }

                simdjson::dom::parser parser;
                simdjson::dom::element doc = {};
                if (parser.parse(detailRequest.response.c_str(), detailRequest.response.size()).get(doc))
                {
                    error.assign("vultr detail parse failed"_ctv);
                    done = true;
                    success = false;
                    co_return;
                }

                simdjson::dom::element dev = {};
                if (coordinator->owner->extractResourceObject(doc, kind, dev) == false)
                {
                    error.assign("vultr detail response missing resource object"_ctv);
                    done = true;
                    success = false;
                    co_return;
                }

                bool hasInternalVPCAddress = true;
                std::string_view providerStatus = {};
                (void)dev["status"].get(providerStatus);
                if (waitingForVPCPrivateAddress)
                {
                    String internalVPCAddress = {};
                    hasInternalVPCAddress = vultrExtractInternalIPv4(dev, internalVPCAddress);
                    if (hasInternalVPCAddress == false)
                    {
                        if (providerStatus == "active" && vpcAttachSubmitted == false)
                        {
                            if (coordinator->owner->attachMachineToVPC(pending.createdID, kind, *requiredVMVPCID, error) == false)
                            {
                                done = true;
                                success = false;
                                co_return;
                            }

                            vpcAttachSubmitted = true;
                        }
                    }
                }

                if (machine != nullptr)
                {
                    delete machine;
                    machine = nullptr;
                }

                machine = coordinator->owner->buildMachineFromVultr(dev, kind);
                MachineProvisioningProgress& progress = coordinator->owner->provisioningProgress.upsert(schema, providerMachineType, pending.createdID, pending.createdID);
                if (machine != nullptr)
                {
                    prodigyPopulateMachineProvisioningProgressFromMachine(progress, *machine);
                }

                if (waitingForVPCPrivateAddress && hasInternalVPCAddress == false && machine != nullptr)
                {
                    hasInternalVPCAddress = coordinator->owner->populateMachineAttachedVPCIPv4(kind, *machine);
                    if (hasInternalVPCAddress)
                    {
                        prodigyPopulateMachineProvisioningProgressFromMachine(progress, *machine);
                    }
                }

                if (waitingForVPCPrivateAddress && hasInternalVPCAddress == false)
                {
                    if (vpcAttachSubmitted)
                    {
                        lastStatus.assign("waiting-for-vpc-private-ip"_ctv);
                        progress.status.assign("waiting-for-vpc-private-ip"_ctv);
                    }
                    else
                    {
                        lastStatus.assign("waiting-for-active-before-vpc-attach"_ctv);
                        progress.status.assign("waiting-for-active-before-vpc-attach"_ctv);
                    }
                    progress.ready = false;
                    if (machine != nullptr)
                    {
                        delete machine;
                        machine = nullptr;
                    }
                    coordinator->owner->provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
                    uint32_t delayMs = nextDelayMs(
                        vpcAttachSubmitted ? MachineProvisioningPollPhase::waitingForVPCPrivateIP
                                           : MachineProvisioningPollPhase::waitingForActiveBeforeVPCAttach,
                        providerStatus);
                    if (delayMs > 0)
                    {
                        sleepForMs(delayMs);
                        co_await suspend();
                    }
                    continue;
                }

                if (machine != nullptr && machine->sshAddress.size() == 0)
                {
                    lastStatus.assign("waiting-for-public-ssh-address"_ctv);
                    progress.status.assign("waiting-for-public-ssh-address"_ctv);
                    progress.ready = false;
                    delete machine;
                    machine = nullptr;
                    coordinator->owner->provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
                    uint32_t delayMs = nextDelayMs(MachineProvisioningPollPhase::waitingForPublicSSHAddress, providerStatus);
                    if (delayMs > 0)
                    {
                        sleepForMs(delayMs);
                        co_await suspend();
                    }
                    continue;
                }

                bool machineAddressesReady = (machine != nullptr) && prodigyMachineProvisioningReady(*machine);
                bool machineSSHReady = machineAddressesReady && prodigyMachineProvisioningSSHReady(*machine);
                if (machineSSHReady)
                {
                    lastStatus.assign("active"_ctv);
                    progress.status.assign("active"_ctv);
                    progress.ready = true;
                    coordinator->owner->provisioningProgress.notifyMachineProvisioned(*machine);
                    coordinator->owner->provisioningProgress.emitNow();
                    done = true;
                    success = true;
                    co_return;
                }

                if (machineAddressesReady == false)
                {
                    lastStatus.assign("waiting-for-instance-addresses"_ctv);
                    progress.status.assign("waiting-for-instance-addresses"_ctv);
                }
                else
                {
                    lastStatus.assign("waiting-for-ssh-accept"_ctv);
                    progress.status.assign("waiting-for-ssh-accept"_ctv);
                }
                progress.ready = false;
                if (machine != nullptr)
                {
                    delete machine;
                    machine = nullptr;
                }
                coordinator->owner->provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
                uint32_t delayMs = nextDelayMs(
                    machineAddressesReady ? MachineProvisioningPollPhase::waitingForSSHAccept
                                          : MachineProvisioningPollPhase::waitingForInstanceAddresses,
                    providerStatus);
                if (delayMs > 0)
                {
                    sleepForMs(delayMs);
                    co_await suspend();
                }
            }

            error.snprintf<"vultr machine provisioning timed out status={}"_ctv>(lastStatus);
            done = true;
            success = false;
        }
    };

    class ConcurrentWaitCoordinator
    {
    public:

        VultrBrainIaaS *owner = nullptr;
        VultrHttp::MultiClient http = {};
        Vector<ConcurrentWaitTask *> tasks = {};

        explicit ConcurrentWaitCoordinator(VultrBrainIaaS *thisOwner) : owner(thisOwner)
        {
        }

        ~ConcurrentWaitCoordinator()
        {
            for (ConcurrentWaitTask *task : tasks)
            {
                delete task;
            }
            tasks.clear();
        }

        bool allDone(void) const
        {
            for (ConcurrentWaitTask *task : tasks)
            {
                if (task != nullptr && task->done == false)
                {
                    return false;
                }
            }

            return true;
        }

        int64_t nextWakeAtMs(void) const
        {
            int64_t nextWake = 0;
            for (ConcurrentWaitTask *task : tasks)
            {
                if (task == nullptr || task->done || task->sleeping == false)
                {
                    continue;
                }

                if (nextWake == 0 || task->wakeAtMs < nextWake)
                {
                    nextWake = task->wakeAtMs;
                }
            }

            return nextWake;
        }

        static void resumeTaskOnce(ConcurrentWaitTask *task)
        {
            if (task == nullptr || task->hasSuspendedCoroutines() == false)
            {
                return;
            }

            task->runNextSuspended();
        }

        void wakeReadySleepers(void)
        {
            int64_t nowMs = Time::now<TimeResolution::ms>();
            for (ConcurrentWaitTask *task : tasks)
            {
                if (task == nullptr || task->done || task->sleeping == false || task->wakeAtMs > nowMs)
                {
                    continue;
                }

                task->sleeping = false;
                resumeTaskOnce(task);
            }
        }

        bool nudgeDormantTasks(void)
        {
            bool nudged = false;
            for (ConcurrentWaitTask *task : tasks)
            {
                if (task == nullptr || task->done || task->sleeping || task->hasSuspendedCoroutines() == false)
                {
                    continue;
                }

                resumeTaskOnce(task);
                nudged = true;
            }

            return nudged;
        }

        bool run(const String& schema, const String& providerMachineType, MachineConfig::MachineKind kind, const Vector<PendingMachineProvisioning>& pendingMachines, const String *requiredVMVPCID, Vector<Machine *>& readyMachines, String& error)
        {
            error.clear();
            readyMachines.clear();
            uint32_t dormantNudges = 0;

            for (const PendingMachineProvisioning& pending : pendingMachines)
            {
                ConcurrentWaitTask *task = new ConcurrentWaitTask();
                task->coordinator = this;
                task->pending = pending;
                task->schema = schema;
                task->providerMachineType = providerMachineType;
                task->kind = kind;
                task->requiredVMVPCID = requiredVMVPCID;
                tasks.push_back(task);
                task->execute();
            }

            while (allDone() == false)
            {
                wakeReadySleepers();

                while (VultrHttp::MultiRequest *completed = http.popCompleted())
                {
                    ConcurrentWaitTask *task = reinterpret_cast<ConcurrentWaitTask *>(completed->context);
                    if (task != nullptr && task->done == false)
                    {
                        resumeTaskOnce(task);
                    }
                }

                if (allDone())
                {
                    break;
                }

                int64_t nowMs = Time::now<TimeResolution::ms>();
                int64_t nextWakeMs = nextWakeAtMs();
                int timeoutMs = 50;
                if (nextWakeMs > nowMs)
                {
                    int64_t delayMs = nextWakeMs - nowMs;
                    timeoutMs = int(delayMs > 50 ? 50 : delayMs);
                }
                else if (nextWakeMs == 0 && http.pendingCount() == 0)
                {
                    if (nudgeDormantTasks())
                    {
                        dormantNudges += 1;
                        if (dormantNudges < 8)
                        {
                            continue;
                        }
                    }

                    error.assign("vultr concurrent wait stalled with no pending work"_ctv);
                    return false;
                }
                else
                {
                    dormantNudges = 0;
                }

                if (http.pendingCount() > 0)
                {
                    if (http.pump(timeoutMs) == false)
                    {
                        error.assign("vultr detail request pump failed"_ctv);
                        return false;
                    }
                }
                else
                {
                    usleep(useconds_t(timeoutMs) * 1000u);
                }
            }

            for (ConcurrentWaitTask *task : tasks)
            {
                if (task == nullptr)
                {
                    continue;
                }

                if (task->success == false)
                {
                    error = task->error;
                    return false;
                }

                if (task->machine != nullptr && task->pending.requestedStorageMB > 0 && task->machine->totalStorageMB == 0)
                {
                    task->machine->totalStorageMB = task->pending.requestedStorageMB;
                }

                readyMachines.push_back(task->machine);
                task->machine = nullptr;
            }

            return true;
        }
    };

    bool lookupPlanMetadata(const String& planID, String& storageType, String& planType, String& cpuVendor, String& error)
    {
        storageType.clear();
        planType.clear();
        cpuVendor.clear();
        error.clear();

        if (planID.size() == 0)
        {
            error.assign("vultr plan id missing"_ctv);
            return false;
        }

        struct curl_slist *h = auth_headers();
        if (!h)
        {
            error.assign("vultr api key missing"_ctv);
            return false;
        }

        String cursor = {};
        for (uint32_t page = 0; page < 16; ++page)
        {
            String url = {};
            if (vultrBuildPlansLookupURL(cursor, url, &error) == false)
            {
                curl_slist_free_all(h);
                return false;
            }

            String response = {};
            long httpCode = 0;
            bool ok = VultrHttp::get(url.c_str(), h, response, &httpCode);
            if (ok == false || httpCode < 200 || httpCode >= 300)
            {
                curl_slist_free_all(h);
                error.assign("vultr plans lookup failed"_ctv);
                return false;
            }

            simdjson::dom::parser parser;
            simdjson::dom::element doc = {};
            String padded = {};
            padded.assign(response);
            padded.need(simdjson::SIMDJSON_PADDING);
            if (parser.parse(padded.c_str(), padded.size()).get(doc))
            {
                curl_slist_free_all(h);
                error.assign("vultr plans response parse failed"_ctv);
                return false;
            }

            bool found = false;
            String nextCursor = {};
            if (vultrExtractPlanMetadata(doc, planID, storageType, planType, cpuVendor, found, nextCursor, &error) == false)
            {
                curl_slist_free_all(h);
                return false;
            }

            if (found)
            {
                curl_slist_free_all(h);
                return true;
            }

            if (nextCursor.size() == 0)
            {
                break;
            }

            cursor = std::move(nextCursor);
        }

        curl_slist_free_all(h);
        error.snprintf<"vultr plan '{}' not found"_ctv>(planID);
        return false;
    }

    static const char *resourcePath(MachineConfig::MachineKind kind)
    {
        return (kind == MachineConfig::MachineKind::vm) ? "instances" : "bare-metals";
    }

    static const char *resourceObjectKey(MachineConfig::MachineKind kind)
    {
        return (kind == MachineConfig::MachineKind::vm) ? "instance" : "bare_metal";
    }

    static bool extractResourceObject(simdjson::dom::element doc, MachineConfig::MachineKind kind, simdjson::dom::element& resource)
    {
        resource = {};
        if (doc[resourceObjectKey(kind)].get(resource) == simdjson::SUCCESS && resource.is_null() == false)
        {
            return true;
        }

        if (doc.is_null() == false)
        {
            resource = doc;
            return true;
        }

        return false;
    }

    static bool hasTag(simdjson::dom::element dev, std::string_view wantedTag)
    {
        if (auto tags = dev["tags"]; tags.is_array())
        {
            for (auto tag : tags.get_array())
            {
                std::string_view value;
                if (!tag.get(value) && value == wantedTag)
                {
                    return true;
                }
            }
        }

        return false;
    }

    // Try to extract private4 + gateway from machine JSON
    bool extract_ipv4_and_gateway(simdjson::dom::element dev, uint32_t &private4, uint32_t &gateway4)
    {
        // Common fields
        std::string_view ip, gw;
        if (!dev["internal_ip"].get(ip) && vultrParseAssignedIPv4(ip, private4))
        {
            if (!dev["default_gateway"].get(gw) && vultrParseAssignedIPv4(gw, gateway4)) return true;
        }

        // Nested interfaces/ip_addresses style seen on some provider payloads
        if (auto ips = dev["ip_addresses"]; ips.is_array())
        {
            for (auto v : ips.get_array())
            {
                uint64_t fam = 0; bool isPriv = false; std::string_view a, g;
                (void)v["address_family"].get(fam);
                (void)v["public"].get(isPriv); isPriv = !isPriv;
                if (fam == 4 && isPriv)
                {
                    if (!v["address"].get(a) && vultrParseAssignedIPv4(a, private4))
                    {
                        if (!v["gateway"].get(g) && vultrParseAssignedIPv4(g, gateway4)) return true;
                    }
                }
            }
        }

        // VPC2/Private-Network style attachments with per-interface gateway
        if (auto nics = dev["interfaces"]; nics.is_array())
        {
            for (auto nic : nics.get_array())
            {
                std::string_view a, g; uint64_t fam = 4; (void)nic["address_family"].get(fam);
                if (fam == 4)
                {
                    if (!nic["ip"].get(a) && vultrParseAssignedIPv4(a, private4))
                    {
                        if (!nic["gateway"].get(g) && vultrParseAssignedIPv4(g, gateway4)) return true;
                    }
                }
            }
        }
        return false;
    }

    bool extract_public_ipv4(simdjson::dom::element dev, String& publicAddress, uint32_t &public4)
    {
        publicAddress.clear();
        public4 = 0;

        std::string_view mainIP;
        if (!dev["main_ip"].get(mainIP) && vultrParseAssignedIPv4(mainIP, public4))
        {
            publicAddress.assign(mainIP);
            return true;
        }

        if (!dev["v4_main_ip"].get(mainIP) && vultrParseAssignedIPv4(mainIP, public4))
        {
            publicAddress.assign(mainIP);
            return true;
        }

        if (!dev["public_ip"].get(mainIP) && vultrParseAssignedIPv4(mainIP, public4))
        {
            publicAddress.assign(mainIP);
            return true;
        }

        return false;
    }

    static simdjson::dom::array getMachineArray(simdjson::dom::element doc, MachineConfig::MachineKind kind)
    {
        return vultrGetMachineArray(doc, kind);
    }

    Machine* buildMachineFromVultr(simdjson::dom::element dev, MachineConfig::MachineKind kind)
    {
        Machine *m = new Machine();
        std::string_view id; (void)dev["id"].get(id); m->cloudID.assign(id);
        m->uuid = hash_uuid(id);
        std::string_view created; if (!dev["date_created"].get(created)) m->creationTimeMs = parse_rfc3339_ms(created);

        std::string_view plan;
        if (!dev["plan"].get(plan))
        {
            m->type.assign(plan);
            m->slug.assign(plan);
        }

        uint64_t vcpuCount = 0;
        if (dev["vcpu_count"].get(vcpuCount) == simdjson::SUCCESS && vcpuCount > 0 && vcpuCount <= UINT32_MAX)
        {
            m->totalLogicalCores = uint32_t(vcpuCount);
        }

        uint64_t ramMB = 0;
        if (dev["ram"].get(ramMB) == simdjson::SUCCESS && ramMB > 0 && ramMB <= UINT32_MAX)
        {
            m->totalMemoryMB = uint32_t(ramMB);
        }

        std::string_view region;
        if (!dev["region"].get(region))
        {
            m->region.assign(region);
        }

        // private4 + gatewayPrivate4 (mandatory by contract in this environment)
        uint32_t p4 = 0, g4 = 0; extract_ipv4_and_gateway(dev, p4, g4);
        uint32_t public4 = 0;
        extract_public_ipv4(dev, m->publicAddress, public4);
        String public6Address = {};
        (void)vultrExtractPublicIPv6(dev, public6Address);
        if (m->publicAddress.size() > 0)
        {
            m->sshAddress = m->publicAddress;
        }

        String privateAddress = {};
        if (vultrExtractInternalIPv4(dev, privateAddress))
        {
            m->privateAddress = privateAddress;
        }
        else if (public6Address.size() == 0 && p4 == 0 && m->publicAddress.size() > 0)
        {
            m->privateAddress = m->publicAddress;
        }

        if (m->privateAddress.size() == 0 && public6Address.size() > 0)
        {
            prodigyAppendUniqueClusterMachinePeerAddress(m->peerAddresses, ClusterMachinePeerAddress{public6Address, 0, {}});
            if (m->publicAddress.size() > 0)
            {
                prodigyAppendUniqueClusterMachinePeerAddress(m->peerAddresses, ClusterMachinePeerAddress{m->publicAddress, 0, {}});
            }
        }

        if (p4 == 0 && public4 != 0)
        {
            p4 = public4;
        }
        m->private4 = p4; m->gatewayPrivate4 = g4;

        // isBrain tag
        m->isBrain = hasTag(dev, "brain");

        std::string_view imageID;
        if (!dev["image_id"].get(imageID))
        {
            m->currentImageURI.assign(imageID);
        }
        else if (!dev["os_id"].get(imageID))
        {
            m->currentImageURI.assign(imageID);
        }

        if (bootstrapSSHPrivateKeyPath.size() > 0)
        {
            m->sshUser = bootstrapSSHUser;
            m->sshPrivateKeyPath = bootstrapSSHPrivateKeyPath;
            m->sshHostPublicKeyOpenSSH = bootstrapSSHHostKeyPackage.publicKeyOpenSSH;
        }

        // rack UUID
        m->rackUUID = vultrExtractRackUUID(dev);

        // Configure the Neuron path from the resolved machine peer address.
        prodigyConfigureMachineNeuronEndpoint(*m, thisNeuron);
        return m;
    }

    bool fetchMachineDetail(const String& id, MachineConfig::MachineKind kind, String& response)
    {
        struct curl_slist *h = auth_headers();
        if (!h) return false;
        String url;
        url.snprintf<"https://api.vultr.com/v2/{}/{}"_ctv>(String(resourcePath(kind)), id);
        long httpCode = 0;
        bool ok = VultrHttp::get(url.c_str(), h, response, &httpCode);
        curl_slist_free_all(h);
        return ok && httpCode >= 200 && httpCode < 300;
    }

    bool recoverCreatedMachineIDByLabel(const struct curl_slist *headers, MachineConfig::MachineKind kind, const String& label, String& createdID)
    {
        createdID.clear();

        String url = {};
        url.snprintf<"https://api.vultr.com/v2/{}?per_page=200"_ctv>(String(resourcePath(kind)));
        std::string_view wantedLabel(reinterpret_cast<const char *>(label.data()), size_t(label.size()));
        for (uint32_t attempt = 0; attempt < vultrCreateRecoveryMaxAttempts; ++attempt)
        {
            String response = {};
            long httpCode = 0;
            if (VultrHttp::get(url.c_str(), headers, response, &httpCode) && httpCode >= 200 && httpCode < 300)
            {
                simdjson::dom::parser parser;
                simdjson::dom::element doc = {};
                if (parser.parse(response.c_str(), response.size()).get(doc) == simdjson::SUCCESS
                    && vultrFindMachineIDByLabel(doc, kind, wantedLabel, createdID))
                {
                    return true;
                }
            }

            usleep(useconds_t(vultrCreateRecoveryPollSleepMs) * 1000u);
        }

        return false;
    }

    bool ensureManagedMachineVPC(const String& region, String& vpcID, String& error)
    {
        vpcID.clear();
        error.clear();

        if (region.size() == 0)
        {
            error.assign("vultr managed vpc region missing"_ctv);
            return false;
        }

        struct curl_slist *h = auth_headers();
        if (!h)
        {
            error.assign("vultr api key missing"_ctv);
            return false;
        }

        String description = {};
        vultrManagedVPCDescription(region, description);
        String wantedSubnet = {};
        uint32_t wantedPrefixLength = 0;
        vultrManagedVPCSubnet(region, wantedSubnet, wantedPrefixLength);
        std::string_view wantedRegion(reinterpret_cast<const char *>(region.data()), size_t(region.size()));
        std::string_view wantedDescription(reinterpret_cast<const char *>(description.data()), size_t(description.size()));

        auto extractExistingVPC = [&] (const String& response) -> bool {
            simdjson::dom::parser parser;
            simdjson::dom::element doc = {};
            String padded = {};
            padded.assign(response);
            padded.need(simdjson::SIMDJSON_PADDING);
            if (parser.parse(padded.c_str(), padded.size()).get(doc))
            {
                error.assign("vultr vpc list parse failed"_ctv);
                return false;
            }

            simdjson::dom::array vpcs = {};
            if (doc["vpcs"].get(vpcs) != simdjson::SUCCESS)
            {
                error.assign("vultr vpc list missing vpcs array"_ctv);
                return false;
            }

            for (auto vpc : vpcs)
            {
                std::string_view vpcRegion = {};
                std::string_view vpcDescription = {};
                if (vpc["region"].get(vpcRegion) != simdjson::SUCCESS
                   || vpc["description"].get(vpcDescription) != simdjson::SUCCESS
                   || vpcRegion != wantedRegion
                   || vpcDescription != wantedDescription)
                {
                    continue;
                }

                std::string_view id = {};
                if (!vpc["id"].get(id) && id.size() > 0)
                {
                    String existingSubnet = {};
                    uint32_t existingPrefixLength = 0;
                    if (vultrExtractVPCSubnetPlan(vpc, existingSubnet, existingPrefixLength))
                    {
                        if (existingPrefixLength > wantedPrefixLength)
                        {
                            error.snprintf<"vultr managed vpc '{}' in region '{}' is too small: {}/{} requires at least /{itoa}"_ctv>(
                                description,
                                region,
                                existingSubnet,
                                existingPrefixLength,
                                wantedPrefixLength);
                            return false;
                        }
                    }

                    vpcID.assign(id);
                    return true;
                }
            }

            return true;
        };

        String listResponse = {};
        long httpCode = 0;
        bool ok = VultrHttp::get("https://api.vultr.com/v2/vpcs?per_page=200", h, listResponse, &httpCode);
        if (ok == false || httpCode < 200 || httpCode >= 300)
        {
            curl_slist_free_all(h);
            error.assign("vultr vpc list failed"_ctv);
            return false;
        }

        if (extractExistingVPC(listResponse) == false)
        {
            curl_slist_free_all(h);
            return false;
        }

        if (vpcID.size() > 0)
        {
            curl_slist_free_all(h);
            return true;
        }

        String body = {};
        body.append("{\"region\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, region);
        body.append(",\"description\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, description);
        body.append(",\"v4_subnet\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, wantedSubnet);
        body.append(",\"v4_subnet_mask\":"_ctv);
        body.append(String(wantedPrefixLength));
        body.append("}"_ctv);

        String createResponse = {};
        httpCode = 0;
        ok = VultrHttp::send("POST", "https://api.vultr.com/v2/vpcs", h, body, createResponse, &httpCode);
        curl_slist_free_all(h);
        if (ok == false || httpCode < 200 || httpCode >= 300)
        {
            error.assign("vultr vpc create failed"_ctv);
            return false;
        }

        simdjson::dom::parser parser;
        simdjson::dom::element doc = {};
        if (parser.parse(createResponse.c_str(), createResponse.size()).get(doc))
        {
            error.assign("vultr vpc create parse failed"_ctv);
            return false;
        }

        simdjson::dom::element vpc = {};
        if (doc["vpc"].get(vpc) != simdjson::SUCCESS || vpc.is_null())
        {
            error.assign("vultr vpc create missing vpc object"_ctv);
            return false;
        }

        std::string_view id = {};
        if (!vpc["id"].get(id) && id.size() > 0)
        {
            vpcID.assign(id);
            return true;
        }

        error.assign("vultr vpc create missing id"_ctv);
        return false;
    }

    bool attachMachineToVPC(const String& id, MachineConfig::MachineKind kind, const String& vpcID, String& error)
    {
        error.clear();

        if (id.size() == 0 || vpcID.size() == 0)
        {
            error.assign("vultr machine vpc attach requires machine id and vpc id"_ctv);
            return false;
        }

        struct curl_slist *h = auth_headers();
        if (!h)
        {
            error.assign("vultr api key missing"_ctv);
            return false;
        }

        String body = {};
        body.append("{\"vpc_id\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, vpcID);
        body.append("}"_ctv);

        Vector<String> urls = {};
        String primaryURL = {};
        primaryURL.snprintf<"https://api.vultr.com/v2/{}/{}/vpcs/attach"_ctv>(String(resourcePath(kind)), id);
        urls.push_back(primaryURL);
        if (kind == MachineConfig::MachineKind::bareMetal)
        {
            String fallbackURL = {};
            fallbackURL.snprintf<"https://api.vultr.com/v2/instances/{}/vpcs/attach"_ctv>(id);
            urls.push_back(fallbackURL);
        }

        String response = {};
        long httpCode = 0;
        bool attached = false;
        for (String& url : urls)
        {
            response.clear();
            httpCode = 0;
            bool ok = VultrHttp::send("POST", url.c_str(), h, body, response, &httpCode);
            if (ok && httpCode >= 200 && httpCode < 300)
            {
                attached = true;
                break;
            }
        }

        curl_slist_free_all(h);
        if (attached == false)
        {
            error.snprintf<"vultr machine vpc attach failed http={itoa} body={}"_ctv>(uint32_t(httpCode), response);
            return false;
        }

        return true;
    }

    bool fetchAttachedVPCIPv4(const String& id, MachineConfig::MachineKind kind, String& privateAddress, String& error)
    {
        privateAddress.clear();
        error.clear();

        if (id.size() == 0)
        {
            error.assign("vultr machine vpc lookup requires machine id"_ctv);
            return false;
        }

        struct curl_slist *h = auth_headers();
        if (!h)
        {
            error.assign("vultr api key missing"_ctv);
            return false;
        }

        Vector<String> urls = {};
        String primaryURL = {};
        primaryURL.snprintf<"https://api.vultr.com/v2/{}/{}/vpcs"_ctv>(String(resourcePath(kind)), id);
        urls.push_back(primaryURL);
        if (kind == MachineConfig::MachineKind::bareMetal)
        {
            String fallbackURL = {};
            fallbackURL.snprintf<"https://api.vultr.com/v2/instances/{}/vpcs"_ctv>(id);
            urls.push_back(fallbackURL);
        }

        String response = {};
        long httpCode = 0;
        bool fetched = false;
        for (String& url : urls)
        {
            response.clear();
            httpCode = 0;
            bool ok = VultrHttp::get(url.c_str(), h, response, &httpCode);
            if (ok && httpCode >= 200 && httpCode < 300)
            {
                fetched = true;
                break;
            }
        }

        curl_slist_free_all(h);
        if (fetched == false)
        {
            error.assign("vultr machine vpc lookup failed"_ctv);
            return false;
        }

        simdjson::dom::parser parser;
        simdjson::dom::element doc = {};
        if (parser.parse(response.c_str(), response.size()).get(doc))
        {
            error.assign("vultr machine vpc lookup parse failed"_ctv);
            return false;
        }

        return vultrExtractAttachedVPCIPv4(doc, privateAddress);
    }

    bool populateMachineAttachedVPCIPv4(MachineConfig::MachineKind kind, Machine& machine)
    {
        if (vultrMachineKindUsesManagedVPC(kind) == false || machine.cloudID.size() == 0)
        {
            return false;
        }

        String privateAddress = {};
        String failure = {};
        if (fetchAttachedVPCIPv4(machine.cloudID, kind, privateAddress, failure) == false || privateAddress.size() == 0)
        {
            return false;
        }

        machine.privateAddress = privateAddress;
        prodigyAppendUniqueClusterMachinePeerAddress(machine.peerAddresses, ClusterMachinePeerAddress{privateAddress, 0, {}});
        uint32_t parsedPrivate4 = 0;
        if (parse_ipv4(privateAddress, parsedPrivate4))
        {
            machine.private4 = parsedPrivate4;
        }
        prodigyConfigureMachineNeuronEndpoint(machine, thisNeuron);
        return true;
    }

    bool waitForMachine(const String& id, const String& schema, const String& providerMachineType, MachineConfig::MachineKind kind, Machine *&machine, String& error, const String *requiredVMVPCID = nullptr, bool vpcRequestedAtCreate = false)
    {
        machine = nullptr;
        bool waitingForVPCPrivateAddress = requiredVMVPCID != nullptr
            && requiredVMVPCID->size() > 0;
        bool vpcAttachSubmitted = vpcRequestedAtCreate;
        int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(vultrMachineProvisioningTimeoutMs);
        String lastStatus = {};
        lastStatus.assign("launch-submitted"_ctv);
        MachineProvisioningPollObservation previousObservation = {};
        bool havePreviousObservation = false;

        auto nextDelayMs = [&] (MachineProvisioningPollPhase phase, std::string_view providerStatus) -> uint32_t {

            MachineProvisioningPollObservation current = {};
            current.phase = phase;
            current.vpcAttachSubmitted = vpcAttachSubmitted;
            current.providerStatus.assign(providerStatus);
            uint32_t delayMs = nextMachineProvisioningPollDelayMs(havePreviousObservation ? &previousObservation : nullptr, current);
            previousObservation = std::move(current);
            havePreviousObservation = true;
            return delayMs;
        };

        while (Time::now<TimeResolution::ms>() < deadlineMs)
        {
            String detailResponse;
            if (fetchMachineDetail(id, kind, detailResponse) == false)
            {
                uint32_t delayMs = nextDelayMs(MachineProvisioningPollPhase::transportRetry, {});
                if (delayMs > 0)
                {
                    usleep(useconds_t(delayMs) * 1000u);
                }
                continue;
            }

            simdjson::dom::parser parser;
            simdjson::dom::element doc;
            if (parser.parse(detailResponse.c_str(), detailResponse.size()).get(doc))
            {
                error.assign("vultr detail parse failed"_ctv);
                return false;
            }

            simdjson::dom::element dev = {};
            if (extractResourceObject(doc, kind, dev) == false)
            {
                error.assign("vultr detail response missing resource object"_ctv);
                return false;
            }

            bool hasInternalVPCAddress = true;
            std::string_view providerStatus = {};
            (void)dev["status"].get(providerStatus);
            if (waitingForVPCPrivateAddress)
            {
                String internalVPCAddress = {};
                hasInternalVPCAddress = vultrExtractInternalIPv4(dev, internalVPCAddress);
                if (hasInternalVPCAddress == false)
                {
                    if (providerStatus == "active" && vpcAttachSubmitted == false)
                    {
                        if (attachMachineToVPC(id, kind, *requiredVMVPCID, error) == false)
                        {
                            return false;
                        }

                        vpcAttachSubmitted = true;
                    }
                }
            }

            machine = buildMachineFromVultr(dev, kind);
            MachineProvisioningProgress& progress = provisioningProgress.upsert(schema, providerMachineType, id, id);
            if (machine != nullptr)
            {
                prodigyPopulateMachineProvisioningProgressFromMachine(progress, *machine);
            }
            if (waitingForVPCPrivateAddress && hasInternalVPCAddress == false && machine != nullptr)
            {
                hasInternalVPCAddress = populateMachineAttachedVPCIPv4(kind, *machine);
                if (hasInternalVPCAddress)
                {
                    prodigyPopulateMachineProvisioningProgressFromMachine(progress, *machine);
                }
            }
            if (waitingForVPCPrivateAddress && hasInternalVPCAddress == false)
            {
                if (vpcAttachSubmitted)
                {
                    lastStatus.assign("waiting-for-vpc-private-ip"_ctv);
                    progress.status.assign("waiting-for-vpc-private-ip"_ctv);
                }
                else
                {
                    lastStatus.assign("waiting-for-active-before-vpc-attach"_ctv);
                    progress.status.assign("waiting-for-active-before-vpc-attach"_ctv);
                }
                progress.ready = false;
                delete machine;
                machine = nullptr;
                provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
                uint32_t delayMs = nextDelayMs(
                    vpcAttachSubmitted ? MachineProvisioningPollPhase::waitingForVPCPrivateIP
                                       : MachineProvisioningPollPhase::waitingForActiveBeforeVPCAttach,
                    providerStatus);
                if (delayMs > 0)
                {
                    usleep(useconds_t(delayMs) * 1000u);
                }
                continue;
            }

            if (machine != nullptr && machine->sshAddress.size() == 0)
            {
                lastStatus.assign("waiting-for-public-ssh-address"_ctv);
                progress.status.assign("waiting-for-public-ssh-address"_ctv);
                progress.ready = false;
                delete machine;
                machine = nullptr;
                provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
                uint32_t delayMs = nextDelayMs(MachineProvisioningPollPhase::waitingForPublicSSHAddress, providerStatus);
                if (delayMs > 0)
                {
                    usleep(useconds_t(delayMs) * 1000u);
                }
                continue;
            }

            bool machineAddressesReady = prodigyMachineProvisioningReady(*machine);
            bool machineSSHReady = machineAddressesReady && prodigyMachineProvisioningSSHReady(*machine);
            if (machineSSHReady)
            {
                lastStatus.assign("active"_ctv);
                progress.status.assign("active"_ctv);
                progress.ready = true;
                provisioningProgress.notifyMachineProvisioned(*machine);
                provisioningProgress.emitNow();
                return true;
            }

            if (machineAddressesReady == false)
            {
                lastStatus.assign("waiting-for-instance-addresses"_ctv);
                progress.status.assign("waiting-for-instance-addresses"_ctv);
            }
            else
            {
                lastStatus.assign("waiting-for-ssh-accept"_ctv);
                progress.status.assign("waiting-for-ssh-accept"_ctv);
            }
            progress.ready = false;
            delete machine;
            machine = nullptr;
            provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
            uint32_t delayMs = nextDelayMs(
                machineAddressesReady ? MachineProvisioningPollPhase::waitingForSSHAccept
                                      : MachineProvisioningPollPhase::waitingForInstanceAddresses,
                providerStatus);
            if (delayMs > 0)
            {
                usleep(useconds_t(delayMs) * 1000u);
            }
        }

        error.snprintf<"vultr machine provisioning timed out status={}"_ctv>(lastStatus);
        return false;
    }

    bool ensureMachineTagsForKind(const String& cloudID, MachineConfig::MachineKind kind, const String& clusterUUID, String& error)
    {
        error.clear();

        String detailResponse = {};
        if (fetchMachineDetail(cloudID, kind, detailResponse) == false)
        {
            error.assign("vultr machine detail fetch failed"_ctv);
            return false;
        }

        simdjson::dom::parser parser;
        simdjson::dom::element doc;
        if (parser.parse(detailResponse.c_str(), detailResponse.size()).get(doc))
        {
            error.assign("vultr detail parse failed"_ctv);
            return false;
        }

        simdjson::dom::element dev = {};
        if (extractResourceObject(doc, kind, dev) == false)
        {
            error.assign("vultr detail response missing resource object"_ctv);
            return false;
        }

        String clusterTag = {};
        clusterTag.snprintf<"prodigy-cluster-{}"_ctv>(clusterUUID);
        std::string_view clusterTagView(reinterpret_cast<const char *>(clusterTag.data()), size_t(clusterTag.size()));

        bool hasProdigyTag = hasTag(dev, "prodigy");
        bool hasClusterTag = hasTag(dev, clusterTagView);
        if (hasProdigyTag && hasClusterTag)
        {
            return true;
        }

        String body = {};
        body.append("{\"tags\":["_ctv);

        bool first = true;
        if (auto tags = dev["tags"]; tags.is_array())
        {
            for (auto tag : tags.get_array())
            {
                std::string_view value;
                if (tag.get(value))
                {
                    continue;
                }

                if (value == "prodigy" || value == clusterTagView)
                {
                    continue;
                }

                if (first == false)
                {
                    body.append(","_ctv);
                }

                String tagText = {};
                tagText.assign(value.data(), value.size());
                prodigyAppendEscapedJSONStringLiteral(body, tagText);
                first = false;
            }
        }

        if (first == false)
        {
            body.append(","_ctv);
        }
        prodigyAppendEscapedJSONStringLiteral(body, "prodigy"_ctv);
        body.append(","_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, clusterTag);
        body.append("]}"_ctv);

        struct curl_slist *h = auth_headers();
        if (!h)
        {
            error.assign("vultr api key missing"_ctv);
            return false;
        }

        h = curl_slist_append(h, "Content-Type: application/json");

        String url = {};
        url.snprintf<"https://api.vultr.com/v2/{}/{}"_ctv>(String(resourcePath(kind)), cloudID);

        String response = {};
        long httpCode = 0;
        bool ok = VultrHttp::send("PATCH", url.c_str(), h, body, response, &httpCode);
        curl_slist_free_all(h);
        if (ok == false || httpCode < 200 || httpCode >= 300)
        {
            error.assign("vultr tag update failed"_ctv);
            return false;
        }

        return true;
    }

    bool appendCreateImageFields(const MachineConfig& config, String& body, String& error)
    {
        if (config.vmImageURI.size() == 0)
        {
            error.assign("vultr vmImageURI missing"_ctv);
            return false;
        }

        String key = "image_id"_ctv;
        String value = config.vmImageURI;
        if (config.vmImageURI.size() >= 3 && memcmp(config.vmImageURI.data(), "os:", 3) == 0)
        {
            key = "os_id"_ctv;
            value.assign(config.vmImageURI.substr(3, config.vmImageURI.size() - 3, Copy::yes));
        }
        else if (config.vmImageURI.size() >= 6 && memcmp(config.vmImageURI.data(), "image:", 6) == 0)
        {
            value.assign(config.vmImageURI.substr(6, config.vmImageURI.size() - 6, Copy::yes));
        }
        else if (config.vmImageURI.size() >= 9 && memcmp(config.vmImageURI.data(), "snapshot:", 9) == 0)
        {
            key = "snapshot_id"_ctv;
            value.assign(config.vmImageURI.substr(9, config.vmImageURI.size() - 9, Copy::yes));
        }
        else
        {
            bool numeric = true;
            for (uint64_t index = 0; index < config.vmImageURI.size(); ++index)
            {
                if (config.vmImageURI[index] < '0' || config.vmImageURI[index] > '9')
                {
                    numeric = false;
                    break;
                }
            }

            if (numeric)
            {
                key = "os_id"_ctv;
            }
        }

        body.append(",\""_ctv);
        body.append(key);
        body.append("\":"_ctv);
        if (key.equal("os_id"_ctv))
        {
            body.append(value);
        }
        else
        {
            prodigyAppendEscapedJSONStringLiteral(body, value);
        }

        return true;
    }

    bool appendCreateStorageFields(const String& hostname, const MachineConfig& config, String& body, String& error, uint32_t *requestedStorageMB = nullptr)
    {
        error.clear();
        if (requestedStorageMB)
        {
            *requestedStorageMB = 0;
        }

        if (config.kind != MachineConfig::MachineKind::vm || config.providerMachineType.size() == 0)
        {
            return true;
        }

        String storageType = {};
        String planType = {};
        String cpuVendor = {};
        if (lookupPlanMetadata(config.providerMachineType, storageType, planType, cpuVendor, error) == false)
        {
            return false;
        }

        if (storageType.equal("block_storage"_ctv))
        {
            uint32_t storageMB = vultrRequestedBlockStorageMB(config);
            uint32_t diskGB = (storageMB + 1023u) / 1024u;
            if (diskGB == 0)
            {
                diskGB = 1;
            }

            if (requestedStorageMB)
            {
                *requestedStorageMB = diskGB * 1024u;
            }

            String blockLabel = {};
            blockLabel.snprintf<"{}-boot"_ctv>(hostname);
            body.append(",\"block_devices\":[{"_ctv);
            body.snprintf_add<"\"disk_size\":{itoa},\"label\":"_ctv>(uint64_t(diskGB));
            prodigyAppendEscapedJSONStringLiteral(body, blockLabel);
            body.append(",\"bootable\":true}]"_ctv);
        }

        return true;
    }

    bool destroyBootBlocksForMachineLabels(const Vector<String>& machineLabels, String& error)
    {
        error.clear();

        if (machineLabels.empty())
        {
            return true;
        }

        struct curl_slist *h = auth_headers();
        if (!h)
        {
            error.assign("vultr api key missing"_ctv);
            return false;
        }

        auto collectMatchingBlocks = [&] (Vector<String>& deletableBlockIDs, bool& hasAttachedBlocks) -> bool {
            deletableBlockIDs.clear();
            hasAttachedBlocks = false;

            String response = {};
            long httpCode = 0;
            bool ok = VultrHttp::get("https://api.vultr.com/v2/blocks?per_page=200", h, response, &httpCode);
            if (ok == false || httpCode < 200 || httpCode >= 300)
            {
                error.assign("vultr block list failed"_ctv);
                return false;
            }

            simdjson::dom::parser parser;
            simdjson::dom::element doc = {};
            if (parser.parse(response.c_str(), response.size()).get(doc))
            {
                error.assign("vultr block list parse failed"_ctv);
                return false;
            }

            simdjson::dom::array blocks = {};
            if (doc["blocks"].get(blocks) != simdjson::SUCCESS)
            {
                error.assign("vultr block list missing blocks array"_ctv);
                return false;
            }

            for (auto block : blocks)
            {
                bool matched = false;
                for (const String& machineLabel : machineLabels)
                {
                    std::string_view machineLabelView(reinterpret_cast<const char *>(machineLabel.data()), size_t(machineLabel.size()));
                    if (vultrBlockMatchesMachineLabel(block, machineLabelView))
                    {
                        matched = true;
                        break;
                    }
                }

                if (matched == false)
                {
                    continue;
                }

                std::string_view attachedInstance = {};
                if (!block["attached_to_instance"].get(attachedInstance) && attachedInstance.size() > 0)
                {
                    hasAttachedBlocks = true;
                    continue;
                }

                std::string_view blockID = {};
                if (!block["id"].get(blockID) && blockID.size() > 0)
                {
                    deletableBlockIDs.push_back(String(blockID));
                }
            }

            return true;
        };

        for (uint32_t attempt = 0; attempt < 30; ++attempt)
        {
            Vector<String> blockIDs = {};
            bool hasAttachedBlocks = false;
            if (collectMatchingBlocks(blockIDs, hasAttachedBlocks) == false)
            {
                curl_slist_free_all(h);
                return false;
            }

            if (hasAttachedBlocks == false && blockIDs.empty())
            {
                curl_slist_free_all(h);
                return true;
            }

            bool deletedAny = false;
            for (const String& blockID : blockIDs)
            {
                String url = {};
                url.snprintf<"https://api.vultr.com/v2/blocks/{}"_ctv>(blockID);
                String response = {};
                long httpCode = 0;
                if (VultrHttp::send("DELETE", url.c_str(), h, String(), response, &httpCode) == false || httpCode < 200 || httpCode >= 300)
                {
                    error.assign("vultr delete boot block failed"_ctv);
                    curl_slist_free_all(h);
                    return false;
                }

                deletedAny = true;
            }

            if (deletedAny == false || hasAttachedBlocks)
            {
                usleep(2 * 1000 * 1000);
            }
        }

        curl_slist_free_all(h);
        error.assign("timed out waiting for vultr boot blocks to delete"_ctv);
        return false;
    }

public:
    void configureRuntimeEnvironment(const ProdigyRuntimeEnvironmentConfig& config) override
    {
        prodigyOwnRuntimeEnvironmentConfig(config, runtimeEnvironment);
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

    void boot(void) override {}
    uint32_t supportedMachineKindsMask() const override { return 3u; }
    bool supportsAutoProvision() const override { return true; }
    bool supportsIncrementalProvisioningCallbacks() const override { return true; }
    bool bgpEnabledForEnvironment(void) const override { return true; }

    bool inferMachineSchemaCpuCapability(const MachineConfig& config, MachineSchemaCpuCapability& capability, String& error) override
    {
        capability = {};
        error.clear();

        if (config.providerMachineType.size() == 0)
        {
            error.assign("vultr schema cpu inference requires providerMachineType"_ctv);
            return false;
        }

        String storageType = {};
        String planType = {};
        String cpuVendor = {};
        if (lookupPlanMetadata(config.providerMachineType, storageType, planType, cpuVendor, error) == false)
        {
            return false;
        }

        return vultrInferPlanCpuCapability(config.providerMachineType, planType, cpuVendor, capability, &error);
    }

    void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bytell_hash_set<Machine *>& newMachines, String& error) override
    {
        (void)coro;
        provisioningProgress.reset();
        if (lifetime == MachineLifetime::owned) { error.assign("vultr auto provisioning does not support MachineLifetime::owned"_ctv); return; }
        struct curl_slist *h = auth_headers(); if (!h) { error.assign("vultr api key missing"_ctv); return; }

        // Region and plan: assume Brain metro = VULTR region; fallback to configured provider scope if needed
        String region = thisNeuron && thisNeuron->metro.size() ? thisNeuron->metro : runtimeEnvironment.providerScope;
        if (region.size() == 0) { curl_slist_free_all(h); error.assign("region/metro missing"_ctv); return; }

        String url = {};
        url.snprintf<"https://api.vultr.com/v2/{}"_ctv>(String(resourcePath(config.kind)));
        String managedVPCID = {};
        if (vultrMachineKindUsesManagedVPC(config.kind))
        {
            if (ensureManagedMachineVPC(region, managedVPCID, error) == false)
            {
                curl_slist_free_all(h);
                return;
            }
        }

        String userData = {};
        if (bootstrapSSHPublicKey.size() > 0)
        {
            prodigyBuildBootstrapSSHUserData(bootstrapSSHUser, bootstrapSSHPublicKey, bootstrapSSHHostKeyPackage, userData);
            String encodedUserData = {};
            Base64::encodePadded(userData.data(), userData.size(), encodedUserData);
            userData = std::move(encodedUserData);
        }

        if (config.slug.size() == 0)
        {
            error.assign("vultr machine schema slug missing"_ctv);
            curl_slist_free_all(h);
            return;
        }

        if (config.providerMachineType.size() == 0)
        {
            error.assign("vultr providerMachineType missing"_ctv);
            curl_slist_free_all(h);
            return;
        }

        class PendingCreateSubmission
        {
        public:

            String hostname = {};
            uint32_t requestedStorageMB = 0;
            bool managedVPCRequestedAtCreate = false;
            VultrHttp::MultiRequest request = {};
            bool processed = false;
        };

        Vector<PendingMachineProvisioning> pendingMachines = {};
        Vector<Machine *> readyMachines = {};
        Vector<PendingCreateSubmission> createRequests = {};
        createRequests.reserve(count);

        auto destroyPendingMachine = [&] (const PendingMachineProvisioning& pending) -> void {

            if (pending.createdID.size() == 0)
            {
                return;
            }

            String destroyURL = {};
            destroyURL.snprintf<"https://api.vultr.com/v2/{}/{}"_ctv>(String(resourcePath(config.kind)), pending.createdID);
            String destroyResponse = {};
            (void)VultrHttp::send("DELETE", destroyURL.c_str(), h, String(), destroyResponse);
        };

        auto cleanupProvisioningFailure = [&] () -> void {

            for (Machine *machine : readyMachines)
            {
                destroyMachine(machine);
                delete machine;
            }

            readyMachines.clear();
            for (const PendingMachineProvisioning& pending : pendingMachines)
            {
                destroyPendingMachine(pending);
            }
            pendingMachines.clear();
        };

        auto parseCreateResponse = [&] (const String& response, MachineConfig::MachineKind kind, String& createdID, String& parseFailure) -> bool {

            createdID.clear();
            parseFailure.clear();

            String responseText = {};
            responseText.assign(response);
            simdjson::dom::parser parser;
            simdjson::dom::element doc = {};
            if (parser.parse(responseText.c_str(), responseText.size()).get(doc))
            {
                parseFailure.assign("create parse failed"_ctv);
                return false;
            }

            simdjson::dom::element dev = {};
            if (extractResourceObject(doc, kind, dev) == false)
            {
                parseFailure.snprintf<"vultr create response missing resource object body={}"_ctv>(response);
                return false;
            }

            std::string_view createdIDView = {};
            if (dev["id"].get(createdIDView) != simdjson::SUCCESS || createdIDView.size() == 0)
            {
                parseFailure.snprintf<"vultr create response missing id body={}"_ctv>(response);
                return false;
            }

            createdID.assign(createdIDView);
            return true;
        };

        auto processCreateCompletion = [&] (PendingCreateSubmission& submission) -> void {

            if (submission.processed)
            {
                return;
            }
            submission.processed = true;

            String createdID = {};
            String createFailure = {};
            bool ok = submission.request.curlCode == CURLE_OK
                && submission.request.httpCode >= 200
                && submission.request.httpCode < 300;
            if (ok)
            {
                (void)parseCreateResponse(submission.request.response, config.kind, createdID, createFailure);
            }
            else
            {
                createFailure.snprintf<"vultr create failed curl={itoa} http={itoa} body={}"_ctv>(
                    uint32_t(submission.request.curlCode),
                    uint32_t(submission.request.httpCode),
                    submission.request.response);
            }

            if (createdID.size() == 0 && recoverCreatedMachineIDByLabel(h, config.kind, submission.hostname, createdID))
            {
                basics_log("vultr create recovered label=%s cloudID=%s http=%ld\n", submission.hostname.c_str(), createdID.c_str(), submission.request.httpCode);
                createFailure.clear();
            }

            if (createdID.size() == 0)
            {
                if (error.size() == 0)
                {
                    error.assign(createFailure.size() > 0 ? createFailure : "vultr create failed"_ctv);
                }
                return;
            }

            MachineProvisioningProgress& progress = provisioningProgress.upsert(config.slug, config.providerMachineType, submission.hostname, createdID);
            progress.status.assign("launch-submitted"_ctv);
            progress.ready = false;
            provisioningProgress.notifyMachineProvisioningAccepted(createdID);
            provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());

            PendingMachineProvisioning& pending = pendingMachines.emplace_back();
            pending.hostname = submission.hostname;
            pending.createdID = createdID;
            pending.requestedStorageMB = submission.requestedStorageMB;
            pending.managedVPCRequestedAtCreate = submission.managedVPCRequestedAtCreate;
        };

        auto drainCreateCompletions = [&] (VultrHttp::MultiClient& createClient) -> void {

            for (;;)
            {
                VultrHttp::MultiRequest *completed = createClient.popCompleted();
                if (completed == nullptr)
                {
                    break;
                }

                PendingCreateSubmission *submission = reinterpret_cast<PendingCreateSubmission *>(completed->context);
                if (submission != nullptr)
                {
                    processCreateCompletion(*submission);
                }
            }
        };

        VultrHttp::MultiClient createClient = {};
        bool createSubmissionFailed = false;
        for (uint32_t i = 0; i < count; ++i)
        {
            int64_t nowMs = Time::now<TimeResolution::ms>();
            String hostname;
            hostname.snprintf<"ntg-vultr-{}-{itoa}-{itoa}"_ctv>(config.slug, uint64_t(nowMs), uint64_t(i));
            uint32_t requestedStorageMB = 0;
            String body = {};
            body.append("{\"region\":"_ctv);
            prodigyAppendEscapedJSONStringLiteral(body, region);
            body.append(",\"plan\":"_ctv);
            prodigyAppendEscapedJSONStringLiteral(body, config.providerMachineType);
            body.append(",\"label\":"_ctv);
            prodigyAppendEscapedJSONStringLiteral(body, hostname);
            body.append(",\"hostname\":"_ctv);
            prodigyAppendEscapedJSONStringLiteral(body, hostname);
            body.append(",\"enable_ipv6\":true,\"tags\":[\"prodigy\""_ctv);
            if (provisioningClusterUUIDTagValue.size() > 0)
            {
                String clusterTag = {};
                clusterTag.snprintf<"prodigy-cluster-{}"_ctv>(provisioningClusterUUIDTagValue);
                body.append(","_ctv);
                prodigyAppendEscapedJSONStringLiteral(body, clusterTag);
            }
            body.append("]"_ctv);
            if (appendCreateImageFields(config, body, error) == false)
            {
                curl_slist_free_all(h);
                return;
            }
            if (appendCreateStorageFields(hostname, config, body, error, &requestedStorageMB) == false)
            {
                curl_slist_free_all(h);
                return;
            }
            bool managedVPCRequestedAtCreate = false;
            if (managedVPCID.size() > 0)
            {
                vultrAppendManagedVPCCreateFields(config.kind, managedVPCID, body);
                managedVPCRequestedAtCreate = config.kind == MachineConfig::MachineKind::vm;
            }
            if (userData.size() > 0)
            {
                body.append(",\"user_data\":"_ctv);
                prodigyAppendEscapedJSONStringLiteral(body, userData);
            }
            body.append("}"_ctv);

            PendingCreateSubmission& submission = createRequests.emplace_back();
            submission.hostname = std::move(hostname);
            submission.requestedStorageMB = requestedStorageMB;
            submission.managedVPCRequestedAtCreate = managedVPCRequestedAtCreate;
            submission.request.context = &submission;
            submission.request.method.assign("POST"_ctv);
            submission.request.url.assign(url);
            submission.request.body.assign(body);
            submission.request.timeoutMs = VultrHttp::createSendTimeoutMs;
            submission.request.headers = auth_headers();
            if (submission.request.headers == nullptr)
            {
                error.assign("vultr api key missing"_ctv);
                createSubmissionFailed = true;
                break;
            }

            if (createClient.start(submission.request) == false)
            {
                error.assign("vultr create request start failed"_ctv);
                createSubmissionFailed = true;
                break;
            }

            drainCreateCompletions(createClient);
        }

        drainCreateCompletions(createClient);
        while (createClient.pendingCount() > 0)
        {
            if (createClient.pump(1000) == false)
            {
                if (error.size() == 0)
                {
                    error.assign("vultr create request pump failed"_ctv);
                }
                break;
            }

            drainCreateCompletions(createClient);
        }

        if (createSubmissionFailed)
        {
            drainCreateCompletions(createClient);
        }

        if (error.size() == 0)
        {
            if (pendingMachines.size() == 1)
            {
                Machine *machine = nullptr;
                if (waitForMachine(
                        pendingMachines[0].createdID,
                        config.slug,
                        config.providerMachineType,
                        config.kind,
                        machine,
                        error,
                        managedVPCID.size() > 0 ? &managedVPCID : nullptr,
                        pendingMachines[0].managedVPCRequestedAtCreate))
                {
                    if (machine != nullptr && pendingMachines[0].requestedStorageMB > 0 && machine->totalStorageMB == 0)
                    {
                        machine->totalStorageMB = pendingMachines[0].requestedStorageMB;
                    }

                    readyMachines.push_back(machine);
                }
            }
            else
            {
                ConcurrentWaitCoordinator coordinator(this);
                (void)coordinator.run(
                    config.slug,
                    config.providerMachineType,
                    config.kind,
                    pendingMachines,
                    managedVPCID.size() > 0 ? &managedVPCID : nullptr,
                    readyMachines,
                    error);
            }
        }

        if (error.size() != 0)
        {
            cleanupProvisioningFailure();
        }

        if (error.size() == 0)
        {
            for (Machine *machine : readyMachines)
            {
                newMachines.insert(machine);
            }
        }

        curl_slist_free_all(h);
    }

    void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines) override
    {
        (void)coro; struct curl_slist *h = auth_headers(); if (!h) return;
        for (MachineConfig::MachineKind kind : { MachineConfig::MachineKind::bareMetal, MachineConfig::MachineKind::vm })
        {
            String url = {};
            url.snprintf<"https://api.vultr.com/v2/{}?per_page=200"_ctv>(String(resourcePath(kind)));
            String resp; if (!VultrHttp::get(url.c_str(), h, resp)) { continue; }
            simdjson::dom::parser parser; simdjson::dom::element doc; if (parser.parse(resp.c_str(), resp.size()).get(doc)) { continue; }
            auto arr = getMachineArray(doc, kind);
            for (auto v : arr)
            {
                if (hasTag(v, "prodigy") == false) continue;
                std::string_view r; (void)v["region"].get(r);
                if (metro.size() > 0 && String(r).equals(metro) == false) continue;
                Machine *m = buildMachineFromVultr(v, kind);
                (void)populateMachineAttachedVPCIPv4(kind, *m);
                if (m && prodigyMachineProvisioningReady(*m) == false)
                {
                    String detailResponse;
                    if (fetchMachineDetail(m->cloudID, kind, detailResponse))
                    {
                        simdjson::dom::parser detailParser;
                        simdjson::dom::element detailDoc;
                        if (!detailParser.parse(detailResponse.c_str(), detailResponse.size()).get(detailDoc))
                        {
                            simdjson::dom::element detail = {};
                            if (extractResourceObject(detailDoc, kind, detail))
                            {
                                delete m;
                                m = buildMachineFromVultr(detail, kind);
                                (void)populateMachineAttachedVPCIPv4(kind, *m);
                            }
                        }
                    }
                }
                machines.insert(m);
            }
        }
        curl_slist_free_all(h);
    }

    void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains) override
    {
        (void)coro; struct curl_slist *h = auth_headers(); if (!h) { selfIsBrain = false; return; }
        selfIsBrain = false;
        for (MachineConfig::MachineKind kind : { MachineConfig::MachineKind::bareMetal, MachineConfig::MachineKind::vm })
        {
            String url = {};
            url.snprintf<"https://api.vultr.com/v2/{}?per_page=200"_ctv>(String(resourcePath(kind)));
            String resp; if (!VultrHttp::get(url.c_str(), h, resp)) { continue; }
            simdjson::dom::parser parser; simdjson::dom::element doc; if (parser.parse(resp.c_str(), resp.size()).get(doc)) { continue; }
            auto arr = getMachineArray(doc, kind);
            for (auto v : arr)
            {
                if (hasTag(v, "brain") == false) continue;
                Machine *machine = buildMachineFromVultr(v, kind);
                (void)populateMachineAttachedVPCIPv4(kind, *machine);
                if (machine->uuid == selfUUID)
                {
                    selfIsBrain = true;
                    delete machine;
                    continue;
                }

                IPAddress peerAddress = {};
                String peerAddressText = {};
                if (prodigyResolveMachinePeerAddress(*machine, peerAddress, &peerAddressText) == false)
                {
                    String detailResponse;
                    if (fetchMachineDetail(machine->cloudID, kind, detailResponse))
                    {
                        simdjson::dom::parser detailParser;
                        simdjson::dom::element detailDoc;
                        if (!detailParser.parse(detailResponse.c_str(), detailResponse.size()).get(detailDoc))
                        {
                            simdjson::dom::element detail = {};
                            if (extractResourceObject(detailDoc, kind, detail))
                            {
                                delete machine;
                                machine = buildMachineFromVultr(detail, kind);
                                (void)populateMachineAttachedVPCIPv4(kind, *machine);
                                (void)prodigyResolveMachinePeerAddress(*machine, peerAddress, &peerAddressText);
                            }
                        }
                    }
                }

                BrainView *bv = new BrainView();
                bv->uuid = machine->uuid;
                bv->private4 = machine->private4;
                bv->gatewayPrivate4 = machine->gatewayPrivate4;
                bv->peerAddress = peerAddress;
                bv->peerAddressText = peerAddressText;
                bv->connectTimeoutMs = BrainBase::controlPlaneConnectTimeoutMs();
                bv->nDefaultAttemptsBudget = BrainBase::controlPlaneConnectAttemptsBudget();
                brains.insert(bv);
                delete machine;
            }
        }
        curl_slist_free_all(h);
    }

    void hardRebootMachine(uint128_t uuid) override
    {
        struct curl_slist *h = auth_headers(); if (!h) return;
        for (MachineConfig::MachineKind kind : { MachineConfig::MachineKind::bareMetal, MachineConfig::MachineKind::vm })
        {
            String listURL = {};
            listURL.snprintf<"https://api.vultr.com/v2/{}?per_page=200"_ctv>(String(resourcePath(kind)));
            String list; if (!VultrHttp::get(listURL.c_str(), h, list)) { continue; }
            simdjson::dom::parser parser; simdjson::dom::element doc; if (parser.parse(list.c_str(), list.size()).get(doc)) { continue; }
            String target;
            auto arr = getMachineArray(doc, kind);
            for (auto v : arr) { std::string_view id; if (!v["id"].get(id) && hash_uuid(id) == uuid) { target.assign(id); break; } }
            if (target.size() == 0) { continue; }
            String url; url.snprintf<"https://api.vultr.com/v2/{}/{}/reboot"_ctv>(String(resourcePath(kind)), target);
            String out; VultrHttp::send("POST", url.c_str(), h, String(), out);
            basics_log("vultr hardRebootMachine uuid=%llu kind=%s cloudID=%s\n",
                (unsigned long long)uuid,
                resourcePath(kind),
                target.c_str());
            break;
        }
        curl_slist_free_all(h);
    }

    void reportHardwareFailure(uint128_t uuid, const String& report) override
    {
        struct curl_slist *h = auth_headers(); if (!h) return;
        String uuidHex = {};
        uuidHex.assignItoh(uuid);
        String subject; subject.snprintf<"Hardware failure report for {}"_ctv>(uuidHex);
        String body; body.snprintf<"{\"subject\":\"{}\",\"description\":\"{}\"}"_ctv>(subject, report);
        String out; VultrHttp::send("POST", "https://api.vultr.com/v2/support/tickets", h, body, out);
        curl_slist_free_all(h);
    }

    void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) override
    {
        (void)coro;
        (void)decommissionedIDs;
    }

    void destroyMachine(Machine *machine) override
    {
        if (!machine || machine->cloudID.size() == 0) return;
        basics_log("vultr destroyMachine begin uuid=%llu cloudID=%s private4=%u isBrain=%d\n",
            (unsigned long long)machine->uuid,
            machine->cloudID.c_str(),
            unsigned(machine->private4),
            int(machine->isBrain));
        struct curl_slist *h = auth_headers(); if (!h) return;
        Vector<String> vmLabels = {};
        for (MachineConfig::MachineKind kind : { MachineConfig::MachineKind::bareMetal, MachineConfig::MachineKind::vm })
        {
            String detailResponse;
            if (fetchMachineDetail(machine->cloudID, kind, detailResponse) == false)
            {
                continue;
            }
            if (kind == MachineConfig::MachineKind::vm)
            {
                simdjson::dom::parser parser;
                simdjson::dom::element doc = {};
                if (!parser.parse(detailResponse.c_str(), detailResponse.size()).get(doc))
                {
                    simdjson::dom::element detail = {};
                    if (extractResourceObject(doc, kind, detail))
                    {
                        String label = {};
                        if (vultrExtractResourceLabel(detail, label))
                        {
                            vmLabels.push_back(std::move(label));
                        }
                    }
                }
            }
            String url; url.snprintf<"https://api.vultr.com/v2/{}/{}"_ctv>(String(resourcePath(kind)), machine->cloudID);
            String out;
            long httpCode = 0;
            if (VultrHttp::send("DELETE", url.c_str(), h, String(), out, &httpCode) && httpCode >= 200 && httpCode < 300)
            {
                basics_log("vultr destroyMachine delete ok uuid=%llu kind=%s cloudID=%s http=%ld\n",
                    (unsigned long long)machine->uuid,
                    resourcePath(kind),
                    machine->cloudID.c_str(),
                    httpCode);
                curl_slist_free_all(h);
                if (vmLabels.empty() == false)
                {
                    String blockFailure = {};
                    if (destroyBootBlocksForMachineLabels(vmLabels, blockFailure) == false)
                    {
                        basics_log("vultr delete boot block failed: %s\n", blockFailure.c_str());
                    }
                }
                return;
            }
        }
        basics_log("vultr destroyMachine miss uuid=%llu cloudID=%s\n",
            (unsigned long long)machine->uuid,
            machine->cloudID.c_str());
        curl_slist_free_all(h);
    }

    bool destroyClusterMachines(const String& clusterUUID, uint32_t& destroyed, String& error) override
    {
        destroyed = 0;
        error.clear();

        if (clusterUUID.size() == 0)
        {
            error.assign("vultr clusterUUID tag value required"_ctv);
            return false;
        }

        struct curl_slist *h = auth_headers();
        if (!h)
        {
            error.assign("vultr auth failed"_ctv);
            return false;
        }

        String clusterTag = {};
        clusterTag.snprintf<"prodigy-cluster-{}"_ctv>(clusterUUID);
        std::string_view clusterTagView(reinterpret_cast<const char *>(clusterTag.data()), size_t(clusterTag.size()));

        Vector<String> vmCloudIDs = {};
        Vector<String> vmLabels = {};
        Vector<String> bareMetalCloudIDs = {};
        auto collectCloudIDs = [&] (MachineConfig::MachineKind kind, Vector<String>& cloudIDs, Vector<String> *machineLabels = nullptr) -> bool {
            cloudIDs.clear();
            if (machineLabels != nullptr)
            {
                machineLabels->clear();
            }

            String url = {};
            url.snprintf<"https://api.vultr.com/v2/{}?per_page=200"_ctv>(String(resourcePath(kind)));

            String response = {};
            if (!VultrHttp::get(url.c_str(), h, response))
            {
                error.assign("vultr list machines failed"_ctv);
                return false;
            }

            simdjson::dom::parser parser;
            simdjson::dom::element doc;
            if (parser.parse(response.c_str(), response.size()).get(doc))
            {
                error.assign("vultr machine list json parse failed"_ctv);
                return false;
            }

            auto machines = getMachineArray(doc, kind);
            for (auto machine : machines)
            {
                if (hasTag(machine, "prodigy") == false || hasTag(machine, clusterTagView) == false)
                {
                    continue;
                }

                std::string_view cloudIDView = {};
                if (!machine["id"].get(cloudIDView) && cloudIDView.size() > 0)
                {
                    cloudIDs.push_back(String(cloudIDView));
                }

                if (machineLabels != nullptr)
                {
                    String label = {};
                    if (vultrExtractResourceLabel(machine, label))
                    {
                        machineLabels->push_back(std::move(label));
                    }
                }
            }

            return true;
        };

        if (collectCloudIDs(MachineConfig::MachineKind::vm, vmCloudIDs, &vmLabels) == false
           || collectCloudIDs(MachineConfig::MachineKind::bareMetal, bareMetalCloudIDs) == false)
        {
            curl_slist_free_all(h);
            return false;
        }

        if (vmCloudIDs.size() == 0 && bareMetalCloudIDs.size() == 0)
        {
            curl_slist_free_all(h);
            return true;
        }

        destroyed = uint32_t(vmCloudIDs.size() + bareMetalCloudIDs.size());

        auto destroyCloudIDs = [&] (MachineConfig::MachineKind kind, const Vector<String>& cloudIDs) -> bool {
            for (const String& cloudID : cloudIDs)
            {
                String url = {};
                url.snprintf<"https://api.vultr.com/v2/{}/{}"_ctv>(String(resourcePath(kind)), cloudID);
                String response = {};
                long httpCode = 0;
                if (VultrHttp::send("DELETE", url.c_str(), h, String(), response, &httpCode) == false || httpCode < 200 || httpCode >= 300)
                {
                    error.assign("vultr delete machine failed"_ctv);
                    return false;
                }
            }

            return true;
        };

        if (destroyCloudIDs(MachineConfig::MachineKind::vm, vmCloudIDs) == false
           || destroyCloudIDs(MachineConfig::MachineKind::bareMetal, bareMetalCloudIDs) == false)
        {
            curl_slist_free_all(h);
            return false;
        }

        for (uint32_t attempt = 0; attempt < 30; ++attempt)
        {
            if (collectCloudIDs(MachineConfig::MachineKind::vm, vmCloudIDs) == false
               || collectCloudIDs(MachineConfig::MachineKind::bareMetal, bareMetalCloudIDs) == false)
            {
                curl_slist_free_all(h);
                return false;
            }

            if (vmCloudIDs.size() == 0 && bareMetalCloudIDs.size() == 0)
            {
                curl_slist_free_all(h);
                if (vmLabels.empty() == false && destroyBootBlocksForMachineLabels(vmLabels, error) == false)
                {
                    return false;
                }
                return true;
            }

            usleep(2 * 1000 * 1000);
        }

        curl_slist_free_all(h);
        error.assign("timed out waiting for vultr cluster machines to terminate"_ctv);
        return false;
    }

    bool ensureProdigyMachineTags(const String& clusterUUID, Machine *machine, String& error) override
    {
        error.clear();

        if (machine == nullptr || machine->cloudID.size() == 0)
        {
            error.assign("vultr machine cloudID required"_ctv);
            return false;
        }

        if (clusterUUID.size() == 0)
        {
            error.assign("vultr clusterUUID tag value required"_ctv);
            return false;
        }

        for (MachineConfig::MachineKind kind : { MachineConfig::MachineKind::bareMetal, MachineConfig::MachineKind::vm })
        {
            String kindFailure = {};
            if (ensureMachineTagsForKind(machine->cloudID, kind, clusterUUID, kindFailure))
            {
                return true;
            }
        }

        error.assign("vultr failed to update machine tags"_ctv);
        return false;
    }
};
