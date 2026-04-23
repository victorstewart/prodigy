#pragma once

#include <prodigy/iaas/iaas.h>
#include <services/debug.h>
#include <prodigy/iaas/bootstrap.ssh.h>
#include <prodigy/brain/base.h>
#include <prodigy/cluster.machine.helpers.h>
#include <prodigy/netdev.detect.h>
#include <services/filesystem.h>
#include <simdjson.h>
#include <curl/curl.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <limits>
#include <sys/wait.h>
#include <unistd.h>

class GcpHttp {
public:
    static constexpr long connectTimeoutMs = 3000L;
    static constexpr long getTimeoutMs = 3000L;
    static constexpr long sendTimeoutMs = 8000L;

    static bool ensureGlobalInit(void)
    {
        static bool initialized = (curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK);
        return initialized;
    }

    static void populateTransportFailure(CURLcode rc, const char *errorBuffer, String *transportFailure)
    {
        if (transportFailure == nullptr)
        {
            return;
        }

        transportFailure->clear();
        if (rc == CURLE_OK)
        {
            return;
        }

        if (errorBuffer && errorBuffer[0] != '\0')
        {
            transportFailure->assign(errorBuffer);
        }
        else if (const char *text = curl_easy_strerror(rc); text && text[0] != '\0')
        {
            transportFailure->assign(text);
        }
        else
        {
            transportFailure->assign("curl request failed"_ctv);
        }

        transportFailure->snprintf_add<" (curl rc={itoa})"_ctv>(uint32_t(rc));
    }

    static bool get(const char *url, const struct curl_slist *headers, String &out, long *httpStatus = nullptr, String *transportFailure = nullptr)
    {
        if (ensureGlobalInit() == false)
        {
            return false;
        }

        out.clear();
        CURL *curl = curl_easy_init(); if (!curl) return false;
        char errorBuffer[CURL_ERROR_SIZE];
        errorBuffer[0] = '\0';
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, connectTimeoutMs);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, getTimeoutMs);
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[] (char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
            String *s = (String*)userdata; s->append((uint8_t*)ptr, size * nmemb); return size * nmemb; });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
        CURLcode rc = curl_easy_perform(curl);
        long status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        populateTransportFailure(rc, errorBuffer, transportFailure);
        curl_easy_cleanup(curl);
        if (httpStatus) *httpStatus = status;
        return rc == CURLE_OK && status >= 200 && status < 300;
    }

    static bool send(const char *method, const char *url, const struct curl_slist *headers, const String &body, String &out, long *httpStatus = nullptr, String *transportFailure = nullptr)
    {
        if (ensureGlobalInit() == false)
        {
            return false;
        }

        out.clear();
        CURL *curl = curl_easy_init(); if (!curl) return false;
        char errorBuffer[CURL_ERROR_SIZE];
        errorBuffer[0] = '\0';
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, connectTimeoutMs);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, sendTimeoutMs);
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);
        String bodyText = {};
        if (body.size() > 0) {
            bodyText.assign(body);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, bodyText.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, long(bodyText.size()));
        }
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[] (char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
            String *s = (String*)userdata; s->append((uint8_t*)ptr, size * nmemb); return size * nmemb; });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
        CURLcode rc = curl_easy_perform(curl);
        long status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        populateTransportFailure(rc, errorBuffer, transportFailure);
        curl_easy_cleanup(curl);
        if (httpStatus) *httpStatus = status;
        return rc == CURLE_OK && status >= 200 && status < 300;
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
        String transportFailure = {};
        long timeoutMs = sendTimeoutMs;
        long httpStatus = 0;
        CURLcode curlCode = CURLE_OK;
        bool completed = false;
        bool added = false;

        void resetResult(void)
        {
            response.clear();
            transportFailure.clear();
            httpStatus = 0;
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
                request->httpStatus = 0;
                (void)curl_easy_getinfo(message->easy_handle, CURLINFO_RESPONSE_CODE, &request->httpStatus);
                populateTransportFailure(request->curlCode, nullptr, &request->transportFailure);
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
            curl_easy_setopt(request.easy, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
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
            }

            CURLMcode addCode = curl_multi_add_handle(multi, request.easy);
            if (addCode != CURLM_OK)
            {
                request.clearTransport();
                return false;
            }

            request.added = true;
            inFlight += 1;
            int runningHandles = 0;
            return curl_multi_perform(multi, &runningHandles) == CURLM_OK;
        }

        bool pump(int timeoutMs)
        {
            if (multi == nullptr)
            {
                return true;
            }

            int runningHandles = 0;
            if (curl_multi_perform(multi, &runningHandles) != CURLM_OK)
            {
                return false;
            }

            collectCompleted();
            if (inFlight == 0)
            {
                return true;
            }

            int activeFDs = 0;
            CURLMcode waitCode = curl_multi_wait(multi, nullptr, 0, timeoutMs, &activeFDs);
            if (waitCode != CURLM_OK)
            {
                return false;
            }

            if (curl_multi_perform(multi, &runningHandles) != CURLM_OK)
            {
                return false;
            }

            collectCompleted();
            return true;
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

class GcpNeuronIaaS : public NeuronIaaS {
public:
	    void gatherSelfData(uint128_t& uuid, String& metro, bool& isBrain, EthDevice& eth, IPAddress& private4) override
	    {
        // Runtime persistence owns the canonical brain UUID.
        struct curl_slist *headers = nullptr;
        headers = curl_slist_append(headers, "Metadata-Flavor: Google");

        uuid = 0;

        String zone; GcpHttp::get("http://metadata.google.internal/computeMetadata/v1/instance/zone", headers, zone);
        // zone like: projects/123456/zones/us-central1-a -> metro = full zone (us-central1-a)
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
            ? zone.substr(uint64_t(slash + 1), zone.size() - uint64_t(slash + 1), Copy::no)
            : zone;

        // Network: use EthDevice to compute gateway and private IPv4
        String deviceName;
        if (prodigyResolvePrimaryNetworkDevice(deviceName) == false)
        {
            basics_log("gcp primary network device detection failed\n");
            std::abort();
        }
        eth.setDevice(deviceName);
        private4.is6 = false; private4.v4 = eth.getPrivate4();

        // Brain role via instance attribute "brain" == "true"
        String brainAttr; GcpHttp::get("http://metadata.google.internal/computeMetadata/v1/instance/attributes/brain", headers, brainAttr);
        isBrain = (brainAttr.size() > 0 && (brainAttr[0] == '1' || brainAttr == "true"_ctv));

	        curl_slist_free_all(headers);
	    }

	    void downloadContainerToPath(CoroutineStack *coro, uint64_t deploymentID, const String& path) override {}
	};

static inline uint32_t gcpHashRackIdentity(std::string_view s)
{
    uint32_t u = 0;
    for (char c : s)
    {
        u = (u * 131u) + uint8_t(c);
    }

    return u;
}

static inline bool gcpGetNestedElement(simdjson::dom::element root, std::initializer_list<std::string_view> path, simdjson::dom::element& value)
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

static inline bool gcpExtractZoneName(std::string_view zoneURL, String& zoneText)
{
    zoneText.clear();
    if (zoneURL.size() == 0)
    {
        return false;
    }

    uint64_t start = 0;
    for (uint64_t index = 0; index < zoneURL.size(); ++index)
    {
        if (zoneURL[index] == '/')
        {
            start = index + 1;
        }
    }

    if (start >= zoneURL.size())
    {
        return false;
    }

    zoneText.assign(String(zoneURL.substr(start)));
    return zoneText.size() > 0;
}

static inline uint32_t gcpExtractRackUUID(simdjson::dom::element inst, const String& zoneText)
{
    std::string_view physicalHost = {};
    simdjson::dom::element value = {};
    if (gcpGetNestedElement(inst, { "resourceStatus", "physicalHost" }, value) && !value.get(physicalHost) && physicalHost.size() > 0)
    {
        return gcpHashRackIdentity(physicalHost);
    }

    if (!inst["physicalHost"].get(physicalHost) && physicalHost.size() > 0)
    {
        return gcpHashRackIdentity(physicalHost);
    }

    std::string_view cluster = {};
    std::string_view block = {};
    std::string_view subblock = {};
    bool hasCluster = gcpGetNestedElement(inst, { "resourceStatus", "physicalHostTopology", "cluster" }, value) && !value.get(cluster) && cluster.size() > 0;
    bool hasBlock = gcpGetNestedElement(inst, { "resourceStatus", "physicalHostTopology", "block" }, value) && !value.get(block) && block.size() > 0;
    bool hasSubblock = gcpGetNestedElement(inst, { "resourceStatus", "physicalHostTopology", "subblock" }, value) && !value.get(subblock) && subblock.size() > 0;
    if (hasCluster || hasBlock || hasSubblock)
    {
        String topology = {};
        topology.snprintf<"{}/{}/{}"_ctv>(String(cluster), String(block), String(subblock));
        return gcpHashRackIdentity(std::string_view(topology.c_str(), topology.size()));
    }

    if (zoneText.size() > 0)
    {
        return gcpHashRackIdentity(std::string_view(reinterpret_cast<const char *>(zoneText.data()), size_t(zoneText.size())));
    }

    std::string_view id = {};
    if (!inst["id"].get(id) && id.size() > 0)
    {
        return gcpHashRackIdentity(id);
    }

    return 0;
}

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
    int64_t tokenExpiryMs{0};
    int64_t tokenResolvedAtMs{0};
    String lastAuthFailure;

    static void appendPercentEncoded(String& output, const String& value)
    {
        static constexpr char hex[] = "0123456789ABCDEF";

        for (uint64_t index = 0; index < value.size(); ++index)
        {
            uint8_t byte = value[index];
            bool unreserved = (byte >= 'A' && byte <= 'Z')
                || (byte >= 'a' && byte <= 'z')
                || (byte >= '0' && byte <= '9')
                || byte == '-'
                || byte == '_'
                || byte == '.'
                || byte == '~';

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
            return stringContainsInsensitive(cpuPlatform, "ampere")
                || stringContainsInsensitive(cpuPlatform, "arm");
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

            if (stringContainsInsensitive(cpuPlatform, "haswell")
                || stringContainsInsensitive(cpuPlatform, "broadwell")
                || stringContainsInsensitive(cpuPlatform, "skylake")
                || stringContainsInsensitive(cpuPlatform, "cascade")
                || stringContainsInsensitive(cpuPlatform, "ice")
                || stringContainsInsensitive(cpuPlatform, "sapphire")
                || stringContainsInsensitive(cpuPlatform, "genoa")
                || stringContainsInsensitive(cpuPlatform, "turin")
                || stringContainsInsensitive(cpuPlatform, "rome")
                || stringContainsInsensitive(cpuPlatform, "milan")
                || stringContainsInsensitive(cpuPlatform, "epyc")
                || stringContainsInsensitive(cpuPlatform, "zen"))
            {
                prodigyAppendNormalizedIsaFeature(features, "avx2"_ctv);
            }

            if (stringContainsInsensitive(cpuPlatform, "skylake")
                || stringContainsInsensitive(cpuPlatform, "cascade")
                || stringContainsInsensitive(cpuPlatform, "ice")
                || stringContainsInsensitive(cpuPlatform, "sapphire")
                || stringContainsInsensitive(cpuPlatform, "genoa")
                || stringContainsInsensitive(cpuPlatform, "turin"))
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

    bool ensureProjectZone()
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

        if (projectId.size() == 0 || zone.size() == 0)
        {
            struct curl_slist *mh = nullptr;
            mh = curl_slist_append(mh, "Metadata-Flavor: Google");
            if (projectId.size() == 0)
            {
                GcpHttp::get("http://metadata.google.internal/computeMetadata/v1/project/project-id", mh, projectId);
                trimTrailingAsciiWhitespace(projectId);
            }

            if (zone.size() == 0)
            {
                String metadataZone = {};
                GcpHttp::get("http://metadata.google.internal/computeMetadata/v1/instance/zone", mh, metadataZone);
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

                zone = (slash >= 0)
                    ? metadataZone.substr(uint64_t(slash + 1), metadataZone.size() - uint64_t(slash + 1), Copy::yes)
                    : metadataZone;
                trimTrailingAsciiWhitespace(zone);
            }
            curl_slist_free_all(mh);
        }

        return projectId.size() > 0 && zone.size() > 0;
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

    static bool runCommandCaptureOutput(const String& command, String& output, String *failure = nullptr)
    {
        output.clear();
        if (failure) failure->clear();

        String ownedCommand = {};
        ownedCommand.assign(command);
        ownedCommand.addNullTerminator();

        FILE *pipe = ::popen(ownedCommand.c_str(), "r");
        if (pipe == nullptr)
        {
            if (failure) failure->assign("failed to spawn command"_ctv);
            return false;
        }

        char buffer[4096];
        while (true)
        {
            size_t nRead = fread(buffer, 1, sizeof(buffer), pipe);
            if (nRead > 0)
            {
                output.append(reinterpret_cast<const uint8_t *>(buffer), nRead);
            }

            if (nRead < sizeof(buffer))
            {
                break;
            }
        }

        int status = ::pclose(pipe);
        trimTrailingAsciiWhitespace(output);
        if (status == 0)
        {
            return true;
        }

        if (failure)
        {
            if (output.size() > 0)
            {
                failure->assign(output);
            }
            else if (WIFEXITED(status))
            {
                failure->snprintf<"command exited with status {itoa}"_ctv>(uint32_t(WEXITSTATUS(status)));
            }
            else
            {
                failure->assign("command failed"_ctv);
            }
        }

        return false;
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
    }

    bool resolveRefreshableBootstrapAccessToken(String *failure = nullptr)
    {
        if (failure) failure->clear();
        lastAuthFailure.clear();

        String refreshedToken = {};
        String detail = {};
        if (runCommandCaptureOutput(runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand, refreshedToken, &detail) == false)
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

            if (failure) failure->assign(lastAuthFailure);
            return false;
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

            if (failure) failure->assign(lastAuthFailure);
            return false;
        }

        int64_t now = Time::now<TimeResolution::ms>();
        token.assign(refreshedToken);
        tokenResolvedAtMs = now;
        tokenExpiryMs = now + 30 * 1000;
        lastAuthFailure.clear();
        if (failure) failure->clear();
        return true;
    }

protected:

    bool ensureToken(String *failure = nullptr)
    {
        if (failure) failure->clear();
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

            return resolveRefreshableBootstrapAccessToken(failure);
        }

        if (runtimeEnvironment.providerCredentialMaterial.size() > 0)
        {
            token = runtimeEnvironment.providerCredentialMaterial;
            tokenResolvedAtMs = std::numeric_limits<int64_t>::max();
            tokenExpiryMs = std::numeric_limits<int64_t>::max();
            return true;
        }

        if (Time::now<TimeResolution::ms>() + 30 * 1000 < tokenExpiryMs && token.size() > 0) return true;

        struct curl_slist *mh = nullptr; mh = curl_slist_append(mh, "Metadata-Flavor: Google");
        String resp; if (!GcpHttp::get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", mh, resp)) { curl_slist_free_all(mh); if (failure) failure->assign("gcp metadata token fetch failed"_ctv); return false; }
        curl_slist_free_all(mh);
        simdjson::dom::parser parser; simdjson::dom::element e;
        if (parser.parse(resp.c_str(), resp.size()).get(e)) { if (failure) failure->assign("gcp metadata token parse failed"_ctv); return false; }
        std::string_view at; uint64_t exp;
        if (e["access_token"].get(at) || e["expires_in"].get(exp)) { if (failure) failure->assign("gcp metadata token response missing fields"_ctv); return false; }
        token.assign(at);
        tokenResolvedAtMs = Time::now<TimeResolution::ms>();
        tokenExpiryMs = Time::now<TimeResolution::ms>() + (int64_t)exp * 1000 - 30 * 1000;
        return true;
    }

    bool ensureProviderAccessToken(String& failure)
    {
        return ensureToken(&failure);
    }

    void invalidateProviderAccessTokenCache()
    {
        clearCachedProviderAccessToken();
    }

public:

    void configureRuntimeEnvironment(const ProdigyRuntimeEnvironmentConfig& config) override
    {
        prodigyOwnRuntimeEnvironmentConfig(config, runtimeEnvironment);
        projectId.clear();
        zone.clear();
        region.clear();
        token.clear();
        tokenExpiryMs = 0;
        tokenResolvedAtMs = 0;
        lastAuthFailure.clear();
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

    void buildAuthHeaders(struct curl_slist *&h)
    {
        h = curl_slist_append(h, "Content-Type: application/json");
        String b; b.snprintf<"Authorization: Bearer {}"_ctv>(token);
        h = curl_slist_append(h, b.c_str());
    }

    class PendingMachineProvisioning
    {
    public:

        String instanceName = {};
        String operationName = {};
    };

    class ConcurrentWaitCoordinator;

    class ConcurrentWaitTask : public CoroutineStack
    {
    public:

        ConcurrentWaitCoordinator *coordinator = nullptr;
        PendingMachineProvisioning pending = {};
        String schema = {};
        String providerMachineType = {};
        MachineLifetime lifetime = MachineLifetime::spot;
        bool operationComplete = false;
        bool authRefreshPending = false;
        bool sleeping = false;
        int64_t wakeAtMs = 0;
        bool requestPending = false;
        bool done = false;
        bool success = false;
        bool provisioningReported = false;
        bool lastMetadataReady = false;
        bool lastSSHReady = false;
        bool observedInstance = false;
        String error = {};
        Machine *machine = nullptr;
        GcpHttp::MultiRequest request = {};

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

        bool startRequest(const String& url)
        {
            request.clearTransport();
            request.resetResult();
            request.context = this;
            request.method.assign("GET"_ctv);
            request.url.assign(url);
            request.timeoutMs = GcpHttp::getTimeoutMs;
            if (authRefreshPending)
            {
                authRefreshPending = false;
                String authFailure = {};
                if (coordinator->owner->ensureProviderAccessToken(authFailure) == false)
                {
                    error.assign(authFailure.size() > 0 ? authFailure : "gcp auth refresh failed"_ctv);
                    return false;
                }
            }
            coordinator->owner->buildAuthHeaders(request.headers);
            if (request.headers == nullptr)
            {
                error.assign("gcp auth headers missing"_ctv);
                return false;
            }

            if (coordinator->http.start(request) == false)
            {
                error.assign("gcp concurrent request start failed"_ctv);
                return false;
            }

            requestPending = true;
            return true;
        }

        void execute(void)
        {
            int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(prodigyMachineProvisioningTimeoutMs);
            String operationURL = {};
            operationURL.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/operations/{}?fields=status,error,httpErrorMessage,statusMessage"_ctv>(
                coordinator->owner->projectId,
                coordinator->owner->zone,
                pending.operationName);
            String instanceURL = {};
            instanceURL.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}"_ctv>(
                coordinator->owner->projectId,
                coordinator->owner->zone,
                pending.instanceName);

            while (Time::now<TimeResolution::ms>() < deadlineMs)
            {
                MachineProvisioningProgress& progress = coordinator->owner->provisioningProgress.upsert(
                    schema,
                    providerMachineType,
                    pending.instanceName,
                    machine != nullptr ? machine->cloudID : String());

                if (startRequest(instanceURL) == false)
                {
                    progress.status = error;
                    progress.ready = false;
                    coordinator->owner->provisioningProgress.emitNow();
                    done = true;
                    success = false;
                    co_return;
                }

                co_await suspend();
                if (requestPending)
                {
                    error.assign("gcp concurrent wait resumed before request completion"_ctv);
                    progress.status = error;
                    progress.ready = false;
                    coordinator->owner->provisioningProgress.emitNow();
                    done = true;
                    success = false;
                    co_return;
                }

                if (request.curlCode == CURLE_OK && request.httpStatus >= 200 && request.httpStatus < 300)
                {
                    simdjson::dom::parser parser;
                    simdjson::dom::element doc = {};
                    if (parser.parse(request.response.c_str(), request.response.size()).get(doc))
                    {
                        error.assign("gcp instance response parse failed"_ctv);
                        progress.status = error;
                        progress.ready = false;
                        coordinator->owner->provisioningProgress.emitNow();
                        done = true;
                        success = false;
                        co_return;
                    }

                    if (machine != nullptr)
                    {
                        delete machine;
                        machine = nullptr;
                    }
                    machine = coordinator->owner->buildMachineFromInstance(doc);
                    if (machine != nullptr)
                    {
                        observedInstance = true;
                        progress.cloud.cloudID = machine->cloudID;
                        prodigyPopulateMachineProvisioningProgressFromMachine(progress, *machine);
                    }

                    bool metadataReady = (machine != nullptr) && prodigyMachineProvisioningReady(*machine);
                    bool sshReady = metadataReady && (machine != nullptr) && prodigyMachineSSHSocketAcceptingConnections(*machine);
#if PRODIGY_DEBUG
                    if ((metadataReady != lastMetadataReady) || (sshReady != lastSSHReady))
                    {
                        basics_log("gcp wait-task transition instance=%s cloudID=%s metadataReady=%d sshReady=%d observedInstance=%d public=%s private=%s operation=%s\n",
                            pending.instanceName.c_str(),
                            (machine != nullptr ? machine->cloudID.c_str() : ""),
                            int(metadataReady),
                            int(sshReady),
                            int(observedInstance),
                            (machine != nullptr ? machine->publicAddress.c_str() : ""),
                            (machine != nullptr ? machine->privateAddress.c_str() : ""),
                            pending.operationName.c_str());
                    }
#endif
                    lastMetadataReady = metadataReady;
                    lastSSHReady = sshReady;
                    if (machine != nullptr && lastSSHReady)
                    {
#if PRODIGY_DEBUG
                        basics_log("gcp incremental ready instance=%s cloudID=%s public=%s private4=%u schema=%s providerType=%s operation=%s\n",
                            pending.instanceName.c_str(),
                            machine->cloudID.c_str(),
                            machine->publicAddress.c_str(),
                            unsigned(machine->private4),
                            schema.c_str(),
                            providerMachineType.c_str(),
                            pending.operationName.c_str());
#endif
                        progress.status.assign("running"_ctv);
                        progress.ready = true;
                        if (provisioningReported == false)
                        {
#if PRODIGY_DEBUG
                            basics_log("gcp wait-task provisioned-callback instance=%s cloudID=%s ssh=%s:%u private=%s operation=%s\n",
                                pending.instanceName.c_str(),
                                machine->cloudID.c_str(),
                                machine->sshAddress.c_str(),
                                unsigned(machine->sshPort),
                                machine->privateAddress.c_str(),
                                pending.operationName.c_str());
#endif
#if PRODIGY_DEBUG
                            uint64_t callbackStartNs = Time::now<TimeResolution::ns>();
#endif
                            coordinator->owner->provisioningProgress.notifyMachineProvisioned(*machine);
                            provisioningReported = true;
#if PRODIGY_DEBUG
                            uint64_t callbackTotalNs = (Time::now<TimeResolution::ns>() - callbackStartNs);
                            basics_log("gcp wait-task provisioned-callback-done instance=%s cloudID=%s operation=%s totalNs=%llu totalMs=%.3f\n",
                                pending.instanceName.c_str(),
                                machine->cloudID.c_str(),
                                pending.operationName.c_str(),
                                (unsigned long long)callbackTotalNs,
                                double(callbackTotalNs) / 1.0e6);
#endif
                        }
                        coordinator->owner->provisioningProgress.emitNow();
                        machine->lifetime = lifetime;
                        done = true;
                        success = true;
                        co_return;
                    }

                    if (lastMetadataReady)
                    {
                        progress.status.assign("waiting-for-ssh-ready"_ctv);
                    }
                    else
                    {
                        progress.status.assign("waiting-for-instance-addresses"_ctv);
                    }
                    progress.ready = false;
                    if (machine != nullptr)
                    {
                        delete machine;
                        machine = nullptr;
                    }
                    coordinator->owner->provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
                    sleepForMs(prodigyMachineProvisioningPollSleepMs);
                    co_await suspend();
                    continue;
                }

                if (request.httpStatus != 404 && request.transportFailure.size() > 0)
                {
                    if (request.httpStatus == 401 || request.httpStatus == 403)
                    {
                        coordinator->owner->invalidateProviderAccessTokenCache();
                        authRefreshPending = true;
                    }
                    progress.status = request.transportFailure;
                    progress.ready = false;
                    coordinator->owner->provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
                }

                if (operationComplete == false)
                {
                    if (startRequest(operationURL) == false)
                    {
                        progress.status = error;
                        progress.ready = false;
                        coordinator->owner->provisioningProgress.emitNow();
                        done = true;
                        success = false;
                        co_return;
                    }

                    co_await suspend();

                    if (request.curlCode == CURLE_OK && request.httpStatus >= 200 && request.httpStatus < 300)
                    {
                        simdjson::dom::parser parser;
                        simdjson::dom::element doc = {};
                        if (parser.parse(request.response.c_str(), request.response.size()).get(doc))
                        {
                            error.assign("gcp operation response parse failed"_ctv);
                            progress.status = error;
                            progress.ready = false;
                            coordinator->owner->provisioningProgress.emitNow();
                            done = true;
                            success = false;
                            co_return;
                        }

                        std::string_view status = {};
                        (void)doc["status"].get(status);
                        if (status == "DONE")
                        {
                            if (coordinator->owner->extractOperationFailure(doc, error))
                            {
                                progress.status = error;
                                progress.ready = false;
                                coordinator->owner->provisioningProgress.emitNow();
                                done = true;
                                success = false;
                                co_return;
                            }

                            operationComplete = true;
                            progress.status.assign("operation-complete"_ctv);
                            progress.ready = false;
                            coordinator->owner->provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
                        }
                        else
                        {
                            progress.status.assign("waiting-for-create-operation"_ctv);
                            progress.ready = false;
                            coordinator->owner->provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
                        }
                    }
                    else
                    {
                        String opFailure = {};
                        if (request.transportFailure.size() > 0)
                        {
                            opFailure = request.transportFailure;
                        }
                        else
                        {
                            (void)coordinator->owner->parseAPIErrorMessage(request.response, opFailure);
                        }

                        if (request.httpStatus == 404)
                        {
                            operationComplete = true;
                        }
                        else if (opFailure.size() > 0)
                        {
                            if (request.httpStatus == 401 || request.httpStatus == 403)
                            {
                                coordinator->owner->invalidateProviderAccessTokenCache();
                                authRefreshPending = true;
                            }
                            progress.status = opFailure;
                            progress.ready = false;
                            coordinator->owner->provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
                        }
                    }
                }

                sleepForMs(prodigyMachineProvisioningPollSleepMs);
                co_await suspend();
            }

            basics_log("gcp concurrent wait timeout instance=%s operation=%s observedInstance=%d metadataReady=%d sshReady=%d\n",
                pending.instanceName.c_str(),
                pending.operationName.c_str(),
                int(observedInstance),
                int(lastMetadataReady),
                int(lastSSHReady));
            error.snprintf<"timed out waiting for gcp instance '{}'"_ctv>(pending.instanceName);
            done = true;
            success = false;
        }
    };

    class ConcurrentWaitCoordinator
    {
    public:

        GcpBrainIaaS *owner = nullptr;
        GcpHttp::MultiClient http = {};
        Vector<ConcurrentWaitTask *> tasks = {};

        explicit ConcurrentWaitCoordinator(GcpBrainIaaS *thisOwner) : owner(thisOwner)
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

        bool anyRequestPending(void) const
        {
            for (ConcurrentWaitTask *task : tasks)
            {
                if (task != nullptr && task->done == false && task->requestPending)
                {
                    return true;
                }
            }

            return false;
        }

        static void resumeTaskOnce(ConcurrentWaitTask *task)
        {
            if (task == nullptr || task->hasSuspendedCoroutines() == false)
            {
                return;
            }

            task->runNextSuspended();
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
                if (task == nullptr || task->done || task->sleeping == true || task->requestPending)
                {
                    continue;
                }

                resumeTaskOnce(task);
                nudged = true;
            }

            return nudged;
        }

        bool run(const String& schema, const String& providerMachineType, MachineLifetime lifetime, const Vector<PendingMachineProvisioning>& pendingMachines, Vector<Machine *>& readyMachines, String& error)
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
                task->lifetime = lifetime;
                tasks.push_back(task);
                task->execute();
            }

            while (allDone() == false)
            {
                wakeReadySleepers();

                while (GcpHttp::MultiRequest *completed = http.popCompleted())
                {
                    ConcurrentWaitTask *task = reinterpret_cast<ConcurrentWaitTask *>(completed->context);
                    if (task != nullptr && task->done == false)
                    {
                        task->requestPending = false;
#if PRODIGY_DEBUG
                        uint64_t resumeStartNs = Time::now<TimeResolution::ns>();
                        basics_log("gcp coordinator resume-begin instance=%s operation=%s tasks=%u nextWakeAtMs=%lld\n",
                           task->pending.instanceName.c_str(),
                           task->pending.operationName.c_str(),
                           unsigned(tasks.size()),
                           (long long)nextWakeAtMs());
#endif
                        resumeTaskOnce(task);
#if PRODIGY_DEBUG
                        uint64_t resumeTotalNs = (Time::now<TimeResolution::ns>() - resumeStartNs);
                        basics_log("gcp coordinator resume-done instance=%s operation=%s totalNs=%llu totalMs=%.3f done=%d success=%d requestPending=%d tasks=%u nextWakeAtMs=%lld\n",
                           task->pending.instanceName.c_str(),
                           task->pending.operationName.c_str(),
                           (unsigned long long)resumeTotalNs,
                           double(resumeTotalNs) / 1.0e6,
                           int(task->done),
                           int(task->success),
                           int(task->requestPending),
                           unsigned(tasks.size()),
                           (long long)nextWakeAtMs());
#endif
                    }
                }

                if (allDone())
                {
                    break;
                }

                int64_t nowMs = Time::now<TimeResolution::ms>();
                int64_t nextWakeMs = nextWakeAtMs();
                bool requestPending = anyRequestPending();
                int timeoutMs = 50;
                if (nextWakeMs > nowMs)
                {
                    int64_t delayMs = nextWakeMs - nowMs;
                    timeoutMs = int(delayMs > 50 ? 50 : delayMs);
                }
                else if (nextWakeMs == 0 && http.pendingCount() == 0 && requestPending == false)
                {
                    if (nudgeDormantTasks())
                    {
                        dormantNudges += 1;
                        if (dormantNudges < 8)
                        {
                            continue;
                        }
                    }

                    error.assign("gcp concurrent wait stalled with no pending work"_ctv);
                    return false;
                }
                else
                {
                    dormantNudges = 0;
                }

                if (http.pendingCount() > 0 || requestPending)
                {
                    if (http.pump(timeoutMs) == false)
                    {
                        error.assign("gcp concurrent wait pump failed"_ctv);
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

                readyMachines.push_back(task->machine);
                task->machine = nullptr;
            }

            return true;
        }
    };

    static uint128_t hash_uuid(std::string_view s)
    {
        uint128_t u = 0; for (char c : s) { u = (u * 131) + (uint8_t)c; } return u;
    }

    static int64_t parseRFC3339Ms(std::string_view v)
    {
        if (v.size() < 19)
        {
            return Time::now<TimeResolution::ms>();
        }

        auto parseDecimalRange = [&] (size_t offset, size_t count, int& out) -> bool {

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
        if (parseDecimalRange(0, 4, year) == false
            || parseDecimalRange(5, 2, month) == false
            || parseDecimalRange(8, 2, day) == false
            || parseDecimalRange(11, 2, hour) == false
            || parseDecimalRange(14, 2, minute) == false
            || parseDecimalRange(17, 2, second) == false)
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

    static bool isHTTPMethodGET(const char *method)
    {
        return method != nullptr
            && method[0] == 'G'
            && method[1] == 'E'
            && method[2] == 'T'
            && method[3] == '\0';
    }

    static bool containsCString(const String& value, const char *needle)
    {
        if (needle == nullptr)
        {
            return false;
        }

        String text = {};
        text.assign(value);
        return strstr(text.c_str(), needle) != nullptr;
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

    bool ensureRegion(String& failure)
    {
        failure.clear();
        if (ensureProjectZone() == false)
        {
            failure.assign("gcp project/zone missing"_ctv);
            return false;
        }

        if (region.size() == 0 && deriveRegionFromZone(zone, region) == false)
        {
            failure.assign("gcp region derivation failed"_ctv);
            return false;
        }

        return region.size() > 0;
    }

protected:

    virtual bool sendElasticComputeRequest(const char *method, const String& url, const String *body, String& response, long *httpStatus, String& failure)
    {
        response.clear();
        failure.clear();
        if (!ensureProjectZone() || !ensureToken(&failure))
        {
            if (httpStatus) *httpStatus = 0;
            if (failure.size() == 0)
            {
                failure.assign("gcp auth failed"_ctv);
            }
            return false;
        }

        struct curl_slist *headers = nullptr;
        buildAuthHeaders(headers);
        String urlText = {};
        urlText.assign(url);
        bool ok = false;
        if (isHTTPMethodGET(method) && body == nullptr)
        {
            ok = GcpHttp::get(urlText.c_str(), headers, response, httpStatus, &failure);
        }
        else
        {
            String payload = {};
            if (body != nullptr)
            {
                payload.assign(*body);
            }

            ok = GcpHttp::send(method, urlText.c_str(), headers, payload, response, httpStatus, &failure);
        }
        curl_slist_free_all(headers);
        if (ok == false && failure.size() == 0 && (!httpStatus || *httpStatus == 0))
        {
            failure.assign("gcp request transport failed"_ctv);
        }
        return ok;
    }

private:

    bool resolveInstanceNameForCloudID(const String& cloudID, String& name)
    {
        name.clear();

        if (!ensureProjectZone() || !ensureToken() || cloudID.size() == 0)
        {
            return false;
        }

        struct curl_slist *h = nullptr;
        buildAuthHeaders(h);

        String nextPageToken = {};
        for (;;)
        {
            String url;
            url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances?fields=items(name,id),nextPageToken"_ctv>(projectId, zone);
            appendPageTokenQuery(url, nextPageToken);

            String resp;
            if (!GcpHttp::get(url.c_str(), h, resp))
            {
                break;
            }

            simdjson::dom::parser parser;
            simdjson::dom::element doc;
            if (parser.parse(resp.c_str(), resp.size()).get(doc))
            {
                break;
            }

            if (auto items = doc["items"]; items.is_array())
            {
                for (auto v : items.get_array())
                {
                    std::string_view instanceID;
                    if (v["id"].get(instanceID))
                    {
                        continue;
                    }

                    if (cloudID == String(instanceID))
                    {
                        std::string_view instanceName;
                        if (!v["name"].get(instanceName))
                        {
                            name.assign(instanceName);
                        }

                        break;
                    }
                }
            }

            if (name.size() > 0)
            {
                break;
            }

            std::string_view pageToken;
            if (doc["nextPageToken"].get(pageToken))
            {
                break;
            }

            nextPageToken.assign(pageToken);
            if (nextPageToken.size() == 0)
            {
                break;
            }
        }

        curl_slist_free_all(h);
        return name.size() > 0;
    }

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
            if (!reservationAffinity["consumeReservationType"].get(consumeReservationType)
                && consumeReservationType != "NO_RESERVATION")
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

    static bool parseOperationName(const String& response, String& operationName, String *error = nullptr)
    {
        operationName.clear();
        if (error) error->clear();

        simdjson::dom::parser parser;
        simdjson::dom::element doc;
        String responseText = {};
        responseText.assign(response);
        if (parser.parse(responseText.c_str(), responseText.size()).get(doc))
        {
            if (error) error->assign("gcp operation response parse failed"_ctv);
            return false;
        }

        std::string_view name;
        if (doc["name"].get(name))
        {
            if (error) error->assign("gcp operation response missing name"_ctv);
            return false;
        }

        operationName.assign(name);
        return true;
    }

    static bool extractOperationFailure(simdjson::dom::element operation, String& error)
    {
        error.clear();

        if (auto nestedError = operation["error"]; nestedError.is_object())
        {
            if (auto errors = nestedError["errors"]; errors.is_array())
            {
                for (auto entry : errors.get_array())
                {
                    std::string_view message;
                    if (!entry["message"].get(message))
                    {
                        error.assign(message);
                        return true;
                    }
                }
            }
        }

        std::string_view message;
        if (!operation["httpErrorMessage"].get(message))
        {
            error.assign(message);
            return true;
        }

        if (!operation["statusMessage"].get(message))
        {
            error.assign(message);
            return true;
        }

        return false;
    }

    bool waitForZoneOperation(const String& operationName, const String& schema, const String& providerMachineType, const String& providerName, String& error)
    {
        error.clear();

        if (!ensureProjectZone() || !ensureToken(&error))
        {
            if (error.size() == 0)
            {
                error.assign("gcp auth failed"_ctv);
            }
            return false;
        }

        struct curl_slist *h = nullptr;
        buildAuthHeaders(h);

        String url;
        url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/operations/{}?fields=status,error,httpErrorMessage,statusMessage"_ctv>(projectId, zone, operationName);

        bool ok = false;
        int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(prodigyMachineProvisioningTimeoutMs);
        while (Time::now<TimeResolution::ms>() < deadlineMs)
        {
            long httpStatus = 0;
            String response;
            bool success = GcpHttp::get(url.c_str(), h, response, &httpStatus);
            if (success == false)
            {
                if (parseAPIErrorMessage(response, error) == false)
                {
                    error.snprintf<"gcp operation poll failed with HTTP {itoa}"_ctv>(uint32_t(httpStatus));
                }
                break;
            }

            simdjson::dom::parser parser;
            simdjson::dom::element operation;
            if (parser.parse(response.c_str(), response.size()).get(operation))
            {
                error.assign("gcp operation response parse failed"_ctv);
                break;
            }

            std::string_view status;
            if (operation["status"].get(status) == false && status == "DONE")
            {
                if (extractOperationFailure(operation, error))
                {
                    MachineProvisioningProgress& progress = provisioningProgress.upsert(schema, providerMachineType, providerName, String());
                    progress.status = error;
                    progress.ready = false;
                    provisioningProgress.emitNow();
                    break;
                }

                MachineProvisioningProgress& progress = provisioningProgress.upsert(schema, providerMachineType, providerName, String());
                progress.status.assign("operation-complete"_ctv);
                progress.ready = false;
                provisioningProgress.emitNow();
                ok = true;
                break;
            }

            MachineProvisioningProgress& progress = provisioningProgress.upsert(schema, providerMachineType, providerName, String());
            progress.status.assign("waiting-for-create-operation"_ctv);
            progress.ready = false;
            provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
            usleep(useconds_t(prodigyMachineProvisioningPollSleepMs) * 1000u);
        }

        if (ok == false && error.size() == 0)
        {
            error.snprintf<"timed out waiting for gcp operation '{}'"_ctv>(operationName);
        }

        curl_slist_free_all(h);
        return ok;
    }

    bool fetchInstanceByName(const String& instanceName, Machine *&machine, long *httpStatus = nullptr, String *error = nullptr)
    {
        machine = nullptr;
        if (error) error->clear();

        String authFailure = {};
        if (!ensureProjectZone() || !ensureToken(&authFailure))
        {
            if (error) *error = authFailure.size() > 0 ? authFailure : "gcp auth failed"_ctv;
            return false;
        }

        String url;
        url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}"_ctv>(projectId, zone, instanceName);

        struct curl_slist *h = nullptr;
        buildAuthHeaders(h);

        String response;
        long status = 0;
        bool success = GcpHttp::get(url.c_str(), h, response, &status);
        curl_slist_free_all(h);

        if (httpStatus) *httpStatus = status;

        if (success == false)
        {
            if (error && status != 404)
            {
                if (parseAPIErrorMessage(response, *error) == false)
                {
                    error->snprintf<"gcp instance fetch failed with HTTP {itoa}"_ctv>(uint32_t(status));
                }
            }
            return false;
        }

        simdjson::dom::parser parser;
        simdjson::dom::element instance;
        if (parser.parse(response.c_str(), response.size()).get(instance))
        {
            if (error) error->assign("gcp instance response parse failed"_ctv);
            return false;
        }

        machine = buildMachineFromInstance(instance);
        return true;
    }

    bool fetchInstanceDocument(const String& instanceName, const String& fields, String& response, simdjson::dom::parser& parser, simdjson::dom::element& instance, String& error)
    {
        error.clear();

        if (!ensureProjectZone() || !ensureToken(&error))
        {
            if (error.size() == 0)
            {
                error.assign("gcp auth failed"_ctv);
            }
            return false;
        }

        String url;
        if (fields.size() > 0)
        {
            url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}?fields={}"_ctv>(projectId, zone, instanceName, fields);
        }
        else
        {
            url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}"_ctv>(projectId, zone, instanceName);
        }

        struct curl_slist *h = nullptr;
        buildAuthHeaders(h);

        long httpStatus = 0;
        bool success = GcpHttp::get(url.c_str(), h, response, &httpStatus);
        curl_slist_free_all(h);

        if (success == false)
        {
            if (parseAPIErrorMessage(response, error) == false)
            {
                error.snprintf<"gcp instance fetch failed with HTTP {itoa}"_ctv>(uint32_t(httpStatus));
            }
            return false;
        }

        if (parser.parse(response.c_str(), response.size()).get(instance))
        {
            error.assign("gcp instance response parse failed"_ctv);
            return false;
        }

        return true;
    }

    bool fetchInstanceTemplate(const String& templateName, String& response, simdjson::dom::parser& parser, simdjson::dom::element& instanceTemplate, String& error)
    {
        error.clear();

        if (!ensureProjectZone() || !ensureToken(&error))
        {
            if (error.size() == 0)
            {
                error.assign("gcp auth failed"_ctv);
            }
            return false;
        }

        String url;
        url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/global/instanceTemplates/{}"_ctv>(projectId, templateName);

        struct curl_slist *h = nullptr;
        buildAuthHeaders(h);

        long httpStatus = 0;
        bool success = GcpHttp::get(url.c_str(), h, response, &httpStatus);
        curl_slist_free_all(h);

        if (success == false)
        {
            if (parseAPIErrorMessage(response, error) == false)
            {
                error.snprintf<"gcp instance template fetch failed with HTTP {itoa}"_ctv>(uint32_t(httpStatus));
            }
            return false;
        }

        if (parser.parse(response.c_str(), response.size()).get(instanceTemplate))
        {
            error.assign("gcp instance template response parse failed"_ctv);
            return false;
        }

        return true;
    }

    bool instanceTemplateExists(const String& templateName, bool& exists, String& error)
    {
        exists = false;
        error.clear();

        if (templateName.size() == 0)
        {
            error.assign("gcp instance template name required"_ctv);
            return false;
        }

        if (!ensureProjectZone() || !ensureToken(&error))
        {
            if (error.size() == 0)
            {
                error.assign("gcp auth failed"_ctv);
            }
            return false;
        }

        String url = {};
        url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/global/instanceTemplates/{}"_ctv>(projectId, templateName);

        struct curl_slist *h = nullptr;
        buildAuthHeaders(h);

        String response = {};
        long httpStatus = 0;
        bool success = GcpHttp::get(url.c_str(), h, response, &httpStatus);
        curl_slist_free_all(h);

        if (success)
        {
            exists = true;
            return true;
        }

        if (httpStatus == 404 || containsCString(response, "notFound"))
        {
            exists = false;
            return true;
        }

        if (parseAPIErrorMessage(response, error) == false)
        {
            error.snprintf<"gcp instance template probe failed with HTTP {itoa}"_ctv>(uint32_t(httpStatus));
        }

        return false;
    }

    bool deleteInstanceTemplateIfExists(const String& templateName, String& error)
    {
        error.clear();
        bool exists = false;
        if (instanceTemplateExists(templateName, exists, error) == false)
        {
            return false;
        }

        if (exists == false)
        {
            return true;
        }

        String url = {};
        url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/global/instanceTemplates/{}"_ctv>(projectId, templateName);

        String response = {};
        String transportFailure = {};
        long httpStatus = 0;
        if (sendElasticComputeRequest("DELETE", url, nullptr, response, &httpStatus, transportFailure) == false)
        {
            if (httpStatus == 404 || containsCString(response, "notFound"))
            {
                return true;
            }

            if (parseAPIErrorMessage(response, error) == false)
            {
                error = transportFailure.size() > 0 ? transportFailure : "gcp instance template delete failed"_ctv;
            }
            return false;
        }

        String operationName = {};
        if (parseOperationName(response, operationName, &error) == false)
        {
            return false;
        }

        return waitForGlobalOperation(operationName, error);
    }

    static bool appendTemplateBootDiskOverride(String& body, simdjson::dom::element instanceTemplate, const String& vmImageURI, uint32_t diskGb, String& error)
    {
        error.clear();

        auto disks = instanceTemplate["properties"]["disks"].get_array();
        if (disks.error())
        {
            error.assign("gcp instance template missing disks"_ctv);
            return false;
        }

        uint32_t diskCount = 0;
        bool foundBootDisk = false;
        simdjson::dom::element bootDisk;
        for (auto disk : disks)
        {
            diskCount += 1;

            bool boot = false;
            (void)disk["boot"].get(boot);
            if (boot)
            {
                bootDisk = disk;
                foundBootDisk = true;
            }
        }

        if (diskCount != 1 || foundBootDisk == false)
        {
            error.assign("gcp spinMachines currently requires an instance template with exactly one boot disk"_ctv);
            return false;
        }

        body.append(",\"disks\":[{\"boot\":true"_ctv);

        bool autoDelete = true;
        if (!bootDisk["autoDelete"].get(autoDelete))
        {
            body.append(",\"autoDelete\":"_ctv);
            if (autoDelete)
            {
                body.append("true"_ctv);
            }
            else
            {
                body.append("false"_ctv);
            }
        }

        std::string_view attachmentMode;
        if (!bootDisk["mode"].get(attachmentMode))
        {
            body.append(",\"mode\":"_ctv);
            appendEscapedJSONStringLiteral(body, attachmentMode);
        }

        std::string_view attachmentType;
        if (!bootDisk["type"].get(attachmentType))
        {
            body.append(",\"type\":"_ctv);
            appendEscapedJSONStringLiteral(body, attachmentType);
        }

        std::string_view deviceName;
        if (!bootDisk["deviceName"].get(deviceName))
        {
            body.append(",\"deviceName\":"_ctv);
            appendEscapedJSONStringLiteral(body, deviceName);
        }

        std::string_view interfaceName;
        if (!bootDisk["interface"].get(interfaceName))
        {
            body.append(",\"interface\":"_ctv);
            appendEscapedJSONStringLiteral(body, interfaceName);
        }

        body.append(",\"initializeParams\":{\"sourceImage\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, vmImageURI);
        body.snprintf_add<",\"diskSizeGb\":{itoa}"_ctv>(diskGb);

        if (auto initializeParams = bootDisk["initializeParams"]; initializeParams.is_object())
        {
            std::string_view diskType;
            if (!initializeParams["diskType"].get(diskType))
            {
                body.append(",\"diskType\":"_ctv);
                appendEscapedJSONStringLiteral(body, diskType);
            }
        }

        body.append("}}]"_ctv);
        return true;
    }

    bool ensureInstanceLabel(const String& instanceName, const String& key, const String& value, String& error)
    {
        error.clear();

        String response;
        simdjson::dom::parser parser;
        simdjson::dom::element instance;
        if (fetchInstanceDocument(instanceName, "labelFingerprint,labels", response, parser, instance, error) == false)
        {
            return false;
        }

        std::string_view labelFingerprint;
        if (instance["labelFingerprint"].get(labelFingerprint))
        {
            error.assign("gcp instance missing labelFingerprint"_ctv);
            return false;
        }

        if (auto labels = instance["labels"]; labels.is_object())
        {
            String keyText = {};
            keyText.assign(key);

            std::string_view existingValue;
            if (!labels[keyText.c_str()].get(existingValue) && existingValue == stringViewFor(value))
            {
                return true;
            }
        }

        String body = {};
        body.append("{\"labelFingerprint\":"_ctv);
        appendEscapedJSONStringLiteral(body, labelFingerprint);
        body.append(",\"labels\":{"_ctv);

        bool first = true;
        if (auto labels = instance["labels"]; labels.is_object())
        {
            for (auto field : labels.get_object())
            {
                std::string_view existingKey = field.key;
                if (existingKey == stringViewFor(key))
                {
                    continue;
                }

                std::string_view existingValue;
                if (field.value.get(existingValue))
                {
                    continue;
                }

                if (first == false)
                {
                    body.append(","_ctv);
                }

                appendEscapedJSONStringLiteral(body, existingKey);
                body.append(":"_ctv);
                appendEscapedJSONStringLiteral(body, existingValue);
                first = false;
            }
        }

        if (first == false)
        {
            body.append(","_ctv);
        }
        prodigyAppendEscapedJSONStringLiteral(body, key);
        body.append(":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, value);
        body.append("}}"_ctv);

        struct curl_slist *h = nullptr;
        buildAuthHeaders(h);

        String url;
        url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}/setLabels"_ctv>(projectId, zone, instanceName);

        long httpStatus = 0;
        String setLabelsResponse;
        bool success = GcpHttp::send("POST", url.c_str(), h, body, setLabelsResponse, &httpStatus);
        curl_slist_free_all(h);

        if (success == false)
        {
            if (parseAPIErrorMessage(setLabelsResponse, error) == false)
            {
                error.snprintf<"gcp setLabels failed with HTTP {itoa}"_ctv>(uint32_t(httpStatus));
            }
            return false;
        }

        String operationName;
        if (parseOperationName(setLabelsResponse, operationName, &error) == false)
        {
            return false;
        }

        return waitForZoneOperation(operationName, String(), String(), String(), error);
    }

    bool ensureInstanceMetadataItem(const String& instanceName, const String& key, const String& value, String& error)
    {
        error.clear();

        String response;
        simdjson::dom::parser parser;
        simdjson::dom::element instance;
        if (fetchInstanceDocument(instanceName, "metadata/fingerprint,metadata/items", response, parser, instance, error) == false)
        {
            return false;
        }

        std::string_view fingerprint;
        if (instance["metadata"]["fingerprint"].get(fingerprint))
        {
            error.assign("gcp instance missing metadata fingerprint"_ctv);
            return false;
        }

        if (auto items = instance["metadata"]["items"]; items.is_array())
        {
            for (auto item : items.get_array())
            {
                std::string_view existingKey;
                if (item["key"].get(existingKey) || existingKey != stringViewFor(key))
                {
                    continue;
                }

                std::string_view existingValue;
                if (!item["value"].get(existingValue) && existingValue == stringViewFor(value))
                {
                    return true;
                }

                break;
            }
        }

        String body = {};
        body.append("{\"fingerprint\":"_ctv);
        appendEscapedJSONStringLiteral(body, fingerprint);
        body.append(",\"items\":["_ctv);

        bool first = true;
        if (auto items = instance["metadata"]["items"]; items.is_array())
        {
            for (auto item : items.get_array())
            {
                std::string_view existingKey;
                if (item["key"].get(existingKey))
                {
                    continue;
                }

                if (existingKey == stringViewFor(key))
                {
                    continue;
                }

                std::string_view existingValue = {};
                (void)item["value"].get(existingValue);

                if (first == false)
                {
                    body.append(","_ctv);
                }

                body.append("{\"key\":"_ctv);
                appendEscapedJSONStringLiteral(body, existingKey);
                body.append(",\"value\":"_ctv);
                appendEscapedJSONStringLiteral(body, existingValue);
                body.append("}"_ctv);
                first = false;
            }
        }

        if (first == false)
        {
            body.append(","_ctv);
        }

        body.append("{\"key\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, key);
        body.append(",\"value\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, value);
        body.append("}]}"_ctv);

        struct curl_slist *h = nullptr;
        buildAuthHeaders(h);

        String url;
        url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}/setMetadata"_ctv>(projectId, zone, instanceName);

        long httpStatus = 0;
        String setMetadataResponse;
        bool success = GcpHttp::send("POST", url.c_str(), h, body, setMetadataResponse, &httpStatus);
        curl_slist_free_all(h);

        if (success == false)
        {
            if (parseAPIErrorMessage(setMetadataResponse, error) == false)
            {
                error.snprintf<"gcp setMetadata failed with HTTP {itoa}"_ctv>(uint32_t(httpStatus));
            }
            return false;
        }

        String operationName;
        if (parseOperationName(setMetadataResponse, operationName, &error) == false)
        {
            return false;
        }

        return waitForZoneOperation(operationName, String(), String(), String(), error);
    }

    bool waitForInstanceByName(const String& instanceName, const String& schema, const String& providerMachineType, MachineLifetime lifetime, Machine *&machine, String& error)
    {
        machine = nullptr;
        error.clear();

        int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(prodigyMachineProvisioningTimeoutMs);
        while (Time::now<TimeResolution::ms>() < deadlineMs)
        {
            long httpStatus = 0;
            String fetchError;
            Machine *candidate = nullptr;
            if (fetchInstanceByName(instanceName, candidate, &httpStatus, &fetchError))
            {
                MachineProvisioningProgress& progress = provisioningProgress.upsert(schema, providerMachineType, instanceName, candidate ? candidate->cloudID : String());
                if (candidate != nullptr)
                {
                    prodigyPopulateMachineProvisioningProgressFromMachine(progress, *candidate);
                }
                if (candidate != nullptr && prodigyMachineProvisioningReady(*candidate))
                {
                    progress.status.assign("running"_ctv);
                    progress.ready = true;
                    provisioningProgress.emitNow();
                    candidate->lifetime = lifetime;
                    machine = candidate;
                    return true;
                }

                progress.status.assign("waiting-for-instance-addresses"_ctv);
                progress.ready = false;
                if (candidate != nullptr)
                {
                    delete candidate;
                }
            }
            else if (httpStatus != 404 && fetchError.size() > 0)
            {
                MachineProvisioningProgress& progress = provisioningProgress.upsert(schema, providerMachineType, instanceName, String());
                progress.status = fetchError;
                progress.ready = false;
                provisioningProgress.emitNow();
                error = fetchError;
                return false;
            }

            provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
            usleep(useconds_t(prodigyMachineProvisioningPollSleepMs) * 1000u);
        }

        error.snprintf<"timed out waiting for gcp instance '{}'"_ctv>(instanceName);
        return false;
    }

    Machine* buildMachineFromInstance(simdjson::dom::element inst)
    {
        Machine *m = new Machine();
        std::string_view id = {};
        (void)inst["id"].get(id);
        m->cloudID.assign(id);
        m->uuid = hash_uuid(id);
        m->lifetime = deriveLifetimeFromInstance(inst);
        std::string_view creationTimestamp;
        if (!inst["creationTimestamp"].get(creationTimestamp))
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
                std::string_view nip;
                if (!nic["networkIP"].get(nip))
                {
                    String privateText = String(nip);
                    m->privateAddress.assign(privateText);
                    IPAddress p;
                    inet_pton(AF_INET, privateText.c_str(), &p.v4);
                    m->private4 = p.v4;
                }

                std::string_view ipv6Address;
                if (m->privateAddress.size() == 0 && !nic["ipv6Address"].get(ipv6Address))
                {
                    m->privateAddress.assign(ipv6Address);
                }

                if (auto accessConfigs = nic["accessConfigs"]; accessConfigs.is_array())
                {
                    for (auto access : accessConfigs.get_array())
                    {
                        std::string_view natIP;
                        if (!access["natIP"].get(natIP))
                        {
                            m->publicAddress.assign(natIP);
                            m->sshAddress.assign(natIP);
                            break;
                        }

                        std::string_view externalIpv6;
                        if (m->publicAddress.size() == 0 && !access["externalIpv6"].get(externalIpv6))
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
        std::string_view zoneURL = {};
        if (!inst["zone"].get(zoneURL))
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
                if (!boot) continue;
                // Prefer initializeParams.sourceImage (template image) but fall back to source
                if (auto ip = d["initializeParams"]; ip.is_object())
                {
                    std::string_view img; if (!ip["sourceImage"].get(img)) m->currentImageURI.assign(img);
                }
                if (m->currentImageURI.size() == 0)
                {
                    std::string_view src; if (!d["source"].get(src)) m->currentImageURI.assign(src);
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

    static bool extractInstanceNameFromUserURL(const String& userURL, String& instanceName)
    {
        instanceName.clear();
        String needle = "instances/"_ctv;
        uint64_t offset = findSubstring(userURL, needle);
        if (offset == uint64_t(-1))
        {
            return false;
        }

        uint64_t start = offset + needle.size();
        uint64_t end = userURL.size();
        for (uint64_t index = start; index < userURL.size(); ++index)
        {
            if (userURL[index] == '/' || userURL[index] == '?')
            {
                end = index;
                break;
            }
        }

        if (end <= start)
        {
            return false;
        }

        instanceName.assign(userURL.substr(start, end - start, Copy::yes));
        return instanceName.size() > 0;
    }

    bool waitForElasticZoneOperation(const String& operationName, String& error)
    {
        error.clear();
        if (operationName.size() == 0)
        {
            error.assign("gcp zone operation name missing"_ctv);
            return false;
        }

        String url = {};
        url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/operations/{}?fields=status,error,httpErrorMessage,statusMessage"_ctv>(
            projectId,
            zone,
            operationName);

        int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(prodigyMachineProvisioningTimeoutMs);
        while (Time::now<TimeResolution::ms>() < deadlineMs)
        {
            String response = {};
            String transportFailure = {};
            long httpStatus = 0;
            bool ok = sendElasticComputeRequest("GET", url, nullptr, response, &httpStatus, transportFailure);
            if (ok == false)
            {
                if (parseAPIErrorMessage(response, error) == false)
                {
                    error = transportFailure.size() > 0 ? transportFailure : "gcp zone operation poll failed"_ctv;
                }
                return false;
            }

            simdjson::dom::parser parser;
            simdjson::dom::element operation = {};
            if (parser.parse(response.c_str(), response.size()).get(operation))
            {
                error.assign("gcp zone operation response parse failed"_ctv);
                return false;
            }

            std::string_view status = {};
            if (!operation["status"].get(status) && status == "DONE")
            {
                if (extractOperationFailure(operation, error))
                {
                    return false;
                }

                return true;
            }

            usleep(500 * 1000);
        }

        error.snprintf<"timed out waiting for gcp zone operation '{}'"_ctv>(operationName);
        return false;
    }

    bool waitForElasticRegionOperation(const String& operationName, String& error)
    {
        error.clear();
        if (operationName.size() == 0)
        {
            error.assign("gcp region operation name missing"_ctv);
            return false;
        }

        String regionFailure = {};
        if (ensureRegion(regionFailure) == false)
        {
            error.assign(regionFailure);
            return false;
        }

        String url = {};
        url.snprintf<"https://compute.googleapis.com/compute/beta/projects/{}/regions/{}/operations/{}?fields=status,error,httpErrorMessage,statusMessage"_ctv>(
            projectId,
            region,
            operationName);

        int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(prodigyMachineProvisioningTimeoutMs);
        while (Time::now<TimeResolution::ms>() < deadlineMs)
        {
            String response = {};
            String transportFailure = {};
            long httpStatus = 0;
            bool ok = sendElasticComputeRequest("GET", url, nullptr, response, &httpStatus, transportFailure);
            if (ok == false)
            {
                if (parseAPIErrorMessage(response, error) == false)
                {
                    error = transportFailure.size() > 0 ? transportFailure : "gcp region operation poll failed"_ctv;
                }
                return false;
            }

            simdjson::dom::parser parser;
            simdjson::dom::element operation = {};
            if (parser.parse(response.c_str(), response.size()).get(operation))
            {
                error.assign("gcp region operation response parse failed"_ctv);
                return false;
            }

            std::string_view status = {};
            if (!operation["status"].get(status) && status == "DONE")
            {
                if (extractOperationFailure(operation, error))
                {
                    return false;
                }

                return true;
            }

            usleep(500 * 1000);
        }

        error.snprintf<"timed out waiting for gcp region operation '{}'"_ctv>(operationName);
        return false;
    }

    bool waitForGlobalOperation(const String& operationName, String& error)
    {
        error.clear();
        if (operationName.size() == 0)
        {
            error.assign("gcp global operation name missing"_ctv);
            return false;
        }

        if (!ensureProjectZone() || !ensureToken(&error))
        {
            if (error.size() == 0)
            {
                error.assign("gcp auth failed"_ctv);
            }
            return false;
        }

        String url = {};
        url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/global/operations/{}?fields=status,error,httpErrorMessage,statusMessage"_ctv>(
            projectId,
            operationName);

        int64_t deadlineMs = Time::now<TimeResolution::ms>() + int64_t(prodigyMachineProvisioningTimeoutMs);
        while (Time::now<TimeResolution::ms>() < deadlineMs)
        {
            String response = {};
            String transportFailure = {};
            long httpStatus = 0;
            if (sendElasticComputeRequest("GET", url, nullptr, response, &httpStatus, transportFailure) == false)
            {
                if (parseAPIErrorMessage(response, error) == false)
                {
                    error = transportFailure.size() > 0 ? transportFailure : "gcp global operation poll failed"_ctv;
                }
                return false;
            }

            simdjson::dom::parser parser;
            simdjson::dom::element operation = {};
            if (parser.parse(response.c_str(), response.size()).get(operation))
            {
                error.assign("gcp global operation response parse failed"_ctv);
                return false;
            }

            std::string_view status = {};
            if (!operation["status"].get(status) && status == "DONE")
            {
                if (extractOperationFailure(operation, error))
                {
                    return false;
                }

                return true;
            }

            usleep(500 * 1000);
        }

        error.snprintf<"timed out waiting for gcp global operation '{}'"_ctv>(operationName);
        return false;
    }

    bool fetchElasticInstanceNameForCloudID(const String& cloudID, String& name, String& failure)
    {
        name.clear();
        failure.clear();
        if (cloudID.size() == 0)
        {
            failure.assign("gcp instance cloudID required"_ctv);
            return false;
        }

        String nextPageToken = {};
        for (;;)
        {
            String url = {};
            url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances?fields=items(name,id),nextPageToken"_ctv>(projectId, zone);
            appendPageTokenQuery(url, nextPageToken);

            String response = {};
            String transportFailure = {};
            long httpStatus = 0;
            if (sendElasticComputeRequest("GET", url, nullptr, response, &httpStatus, transportFailure) == false)
            {
                if (parseAPIErrorMessage(response, failure) == false)
                {
                    failure = transportFailure.size() > 0 ? transportFailure : "gcp instance listing failed"_ctv;
                }
                return false;
            }

            simdjson::dom::parser parser;
            simdjson::dom::element doc = {};
            if (parser.parse(response.c_str(), response.size()).get(doc))
            {
                failure.assign("gcp instance list response parse failed"_ctv);
                return false;
            }

            if (auto items = doc["items"]; items.is_array())
            {
                for (auto item : items.get_array())
                {
                    std::string_view instanceID = {};
                    if (item["id"].get(instanceID) || cloudID != String(instanceID))
                    {
                        continue;
                    }

                    std::string_view instanceName = {};
                    if (!item["name"].get(instanceName) && instanceName.size() > 0)
                    {
                        name.assign(instanceName);
                        return true;
                    }
                }
            }

            std::string_view pageToken = {};
            if (doc["nextPageToken"].get(pageToken))
            {
                break;
            }

            nextPageToken.assign(pageToken);
            if (nextPageToken.size() == 0)
            {
                break;
            }
        }

        failure.assign("gcp target instance not found"_ctv);
        return false;
    }

    bool fetchElasticInstanceDocument(const String& instanceName, const String& fields, String& response, simdjson::dom::parser& parser, simdjson::dom::element& instance, String& error)
    {
        response.clear();
        error.clear();
        if (instanceName.size() == 0)
        {
            error.assign("gcp instanceName required"_ctv);
            return false;
        }

        String url = {};
        if (fields.size() > 0)
        {
            url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}?fields={}"_ctv>(projectId, zone, instanceName, fields);
        }
        else
        {
            url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}"_ctv>(projectId, zone, instanceName);
        }

        String transportFailure = {};
        long httpStatus = 0;
        if (sendElasticComputeRequest("GET", url, nullptr, response, &httpStatus, transportFailure) == false)
        {
            if (parseAPIErrorMessage(response, error) == false)
            {
                error = transportFailure.size() > 0 ? transportFailure : "gcp instance fetch failed"_ctv;
            }
            return false;
        }

        if (parser.parse(response.c_str(), response.size()).get(instance))
        {
            error.assign("gcp instance response parse failed"_ctv);
            return false;
        }

        return true;
    }

    bool findElasticInterfaceForAddress(const String& instanceName, const String& addressText, String& nicName, String& accessConfigName, String& error)
    {
        nicName.clear();
        accessConfigName.clear();
        error.clear();

        String response = {};
        simdjson::dom::parser parser;
        simdjson::dom::element instance = {};
        if (fetchElasticInstanceDocument(instanceName, "networkInterfaces(name,accessConfigs(name,natIP,externalIpv6))", response, parser, instance, error) == false)
        {
            return false;
        }

        if (auto nics = instance["networkInterfaces"]; nics.is_array())
        {
            for (auto nic : nics.get_array())
            {
                std::string_view nicNameView = {};
                (void)nic["name"].get(nicNameView);
                if (auto accessConfigs = nic["accessConfigs"]; accessConfigs.is_array())
                {
                    for (auto access : accessConfigs.get_array())
                    {
                        std::string_view natIP = {};
                        if (!access["natIP"].get(natIP) && natIP == stringViewFor(addressText))
                        {
                            nicName.assign(nicNameView);
                            std::string_view accessName = {};
                            if (!access["name"].get(accessName) && accessName.size() > 0)
                            {
                                accessConfigName.assign(accessName);
                            }
                            else
                            {
                                accessConfigName.assign("External NAT"_ctv);
                            }
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    bool describeElasticTargetInterface(const String& instanceName, String& nicName, String& accessConfigName, String& existingPublicAddress, bool& hasAccessConfig, String& error)
    {
        nicName.clear();
        accessConfigName.assign("External NAT"_ctv);
        existingPublicAddress.clear();
        hasAccessConfig = false;
        error.clear();

        String response = {};
        simdjson::dom::parser parser;
        simdjson::dom::element instance = {};
        if (fetchElasticInstanceDocument(instanceName, "networkInterfaces(name,accessConfigs(name,natIP,externalIpv6))", response, parser, instance, error) == false)
        {
            return false;
        }

        auto nics = instance["networkInterfaces"].get_array();
        if (nics.error())
        {
            error.assign("gcp instance missing networkInterfaces"_ctv);
            return false;
        }

        for (auto nic : nics)
        {
            std::string_view nicNameView = {};
            if (!nic["name"].get(nicNameView) && nicNameView.size() > 0)
            {
                nicName.assign(nicNameView);
            }

            if (auto accessConfigs = nic["accessConfigs"]; accessConfigs.is_array())
            {
                for (auto access : accessConfigs.get_array())
                {
                    hasAccessConfig = true;
                    std::string_view accessName = {};
                    if (!access["name"].get(accessName) && accessName.size() > 0)
                    {
                        accessConfigName.assign(accessName);
                    }

                    std::string_view natIP = {};
                    if (!access["natIP"].get(natIP) && natIP.size() > 0)
                    {
                        existingPublicAddress.assign(natIP);
                    }
                    return true;
                }
            }

            return true;
        }

        error.assign("gcp instance missing network interface name"_ctv);
        return false;
    }

    bool deleteElasticAccessConfig(const String& instanceName, const String& nicName, const String& accessConfigName, String& error)
    {
        error.clear();
        if (instanceName.size() == 0 || nicName.size() == 0 || accessConfigName.size() == 0)
        {
            return true;
        }

        String url = {};
        url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}/deleteAccessConfig?networkInterface="_ctv>(
            projectId,
            zone,
            instanceName);
        appendPercentEncoded(url, nicName);
        url.append("&accessConfig="_ctv);
        appendPercentEncoded(url, accessConfigName);

        String response = {};
        String transportFailure = {};
        long httpStatus = 0;
        String emptyBody = {};
        if (sendElasticComputeRequest("POST", url, &emptyBody, response, &httpStatus, transportFailure) == false)
        {
            if (httpStatus == 404 || containsCString(response, "notFound") || containsCString(response, "was not found"))
            {
                error.clear();
                return true;
            }

            if (parseAPIErrorMessage(response, error) == false)
            {
                error = transportFailure.size() > 0 ? transportFailure : "gcp deleteAccessConfig failed"_ctv;
            }
            return false;
        }

        String operationName = {};
        if (parseOperationName(response, operationName, &error) == false)
        {
            return false;
        }

        return waitForElasticZoneOperation(operationName, error);
    }

    bool attachElasticAccessConfig(const String& instanceName, const String& nicName, const String& accessConfigName, const String& publicAddress, String& associationID, String& error)
    {
        associationID.clear();
        error.clear();
        if (instanceName.size() == 0 || nicName.size() == 0 || accessConfigName.size() == 0 || publicAddress.size() == 0)
        {
            error.assign("gcp attach elastic address requires instance, nic, access config, and address"_ctv);
            return false;
        }

        String url = {};
        url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}/addAccessConfig?networkInterface="_ctv>(
            projectId,
            zone,
            instanceName);
        appendPercentEncoded(url, nicName);

        String body = {};
        body.append("{\"name\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, accessConfigName);
        body.append(",\"type\":\"ONE_TO_ONE_NAT\",\"natIP\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, publicAddress);
        body.append("}"_ctv);

        String response = {};
        String transportFailure = {};
        long httpStatus = 0;
        if (sendElasticComputeRequest("POST", url, &body, response, &httpStatus, transportFailure) == false)
        {
            if (parseAPIErrorMessage(response, error) == false)
            {
                error = transportFailure.size() > 0 ? transportFailure : "gcp addAccessConfig failed"_ctv;
            }
            return false;
        }

        String operationName = {};
        if (parseOperationName(response, operationName, &error) == false)
        {
            return false;
        }

        if (waitForElasticZoneOperation(operationName, error) == false)
        {
            return false;
        }

        associationID.snprintf<"{}|{}|{}"_ctv>(instanceName, nicName, accessConfigName);
        return true;
    }

    static bool parseElasticAssociationID(const String& associationID, String& instanceName, String& nicName, String& accessConfigName)
    {
        instanceName.clear();
        nicName.clear();
        accessConfigName.clear();

        int64_t first = -1;
        for (uint64_t index = 0; index < associationID.size(); ++index)
        {
            if (associationID[index] == '|')
            {
                first = int64_t(index);
                break;
            }
        }
        if (first < 0)
        {
            return false;
        }

        int64_t second = -1;
        for (uint64_t index = uint64_t(first + 1); index < associationID.size(); ++index)
        {
            if (associationID[index] == '|')
            {
                second = int64_t(index);
                break;
            }
        }
        if (second < 0)
        {
            return false;
        }

        instanceName.assign(associationID.substr(0, uint64_t(first), Copy::yes));
        nicName.assign(associationID.substr(uint64_t(first + 1), uint64_t(second - first - 1), Copy::yes));
        accessConfigName.assign(associationID.substr(uint64_t(second + 1), associationID.size() - uint64_t(second + 1), Copy::yes));
        return instanceName.size() > 0 && nicName.size() > 0 && accessConfigName.size() > 0;
    }

    bool fetchElasticAddressByName(const String& addressName, String& publicAddress, String& userInstanceName, String& error)
    {
        publicAddress.clear();
        userInstanceName.clear();
        error.clear();
        if (addressName.size() == 0)
        {
            error.assign("gcp address resource name required"_ctv);
            return false;
        }

        String regionFailure = {};
        if (ensureRegion(regionFailure) == false)
        {
            error.assign(regionFailure);
            return false;
        }

        String url = {};
        url.snprintf<"https://compute.googleapis.com/compute/beta/projects/{}/regions/{}/addresses/{}?fields=name,address,users"_ctv>(
            projectId,
            region,
            addressName);

        String response = {};
        String transportFailure = {};
        long httpStatus = 0;
        if (sendElasticComputeRequest("GET", url, nullptr, response, &httpStatus, transportFailure) == false)
        {
            if (parseAPIErrorMessage(response, error) == false)
            {
                error = transportFailure.size() > 0 ? transportFailure : "gcp address fetch failed"_ctv;
            }
            return false;
        }

        simdjson::dom::parser parser;
        simdjson::dom::element doc = {};
        if (parser.parse(response.c_str(), response.size()).get(doc))
        {
            error.assign("gcp address response parse failed"_ctv);
            return false;
        }

        std::string_view addressView = {};
        if (doc["address"].get(addressView))
        {
            error.assign("gcp address resource missing address"_ctv);
            return false;
        }
        publicAddress.assign(addressView);

        if (auto users = doc["users"]; users.is_array())
        {
            for (auto user : users.get_array())
            {
                std::string_view userURL = {};
                if (!user.get(userURL) && userURL.size() > 0)
                {
                    String userText = {};
                    userText.assign(userURL);
                    (void)extractInstanceNameFromUserURL(userText, userInstanceName);
                    break;
                }
            }
        }

        return true;
    }

    bool findElasticAddressByPublicIP(const String& requestedAddress, String& addressName, String& publicAddress, String& userInstanceName, String& error)
    {
        addressName.clear();
        publicAddress.clear();
        userInstanceName.clear();
        error.clear();

        String regionFailure = {};
        if (ensureRegion(regionFailure) == false)
        {
            error.assign(regionFailure);
            return false;
        }

        String nextPageToken = {};
        for (;;)
        {
            String url = {};
            url.snprintf<"https://compute.googleapis.com/compute/beta/projects/{}/regions/{}/addresses?fields=items(name,address,users),nextPageToken"_ctv>(
                projectId,
                region);
            appendPageTokenQuery(url, nextPageToken);

            String response = {};
            String transportFailure = {};
            long httpStatus = 0;
            if (sendElasticComputeRequest("GET", url, nullptr, response, &httpStatus, transportFailure) == false)
            {
                if (parseAPIErrorMessage(response, error) == false)
                {
                    error = transportFailure.size() > 0 ? transportFailure : "gcp address listing failed"_ctv;
                }
                return false;
            }

            simdjson::dom::parser parser;
            simdjson::dom::element doc = {};
            if (parser.parse(response.c_str(), response.size()).get(doc))
            {
                error.assign("gcp address list response parse failed"_ctv);
                return false;
            }

            if (auto items = doc["items"]; items.is_array())
            {
                for (auto item : items.get_array())
                {
                    std::string_view addressView = {};
                    if (item["address"].get(addressView) || addressView != stringViewFor(requestedAddress))
                    {
                        continue;
                    }

                    std::string_view nameView = {};
                    if (item["name"].get(nameView))
                    {
                        error.assign("gcp address resource missing name"_ctv);
                        return false;
                    }

                    addressName.assign(nameView);
                    publicAddress.assign(addressView);
                    if (auto users = item["users"]; users.is_array())
                    {
                        for (auto user : users.get_array())
                        {
                            std::string_view userURL = {};
                            if (!user.get(userURL) && userURL.size() > 0)
                            {
                                String userText = {};
                                userText.assign(userURL);
                                (void)extractInstanceNameFromUserURL(userText, userInstanceName);
                                break;
                            }
                        }
                    }
                    return true;
                }
            }

            std::string_view pageToken = {};
            if (doc["nextPageToken"].get(pageToken))
            {
                break;
            }

            nextPageToken.assign(pageToken);
            if (nextPageToken.size() == 0)
            {
                break;
            }
        }

        error.snprintf<"gcp elastic address {} not found"_ctv>(requestedAddress);
        return false;
    }

    bool allocateElasticAddress(const String& providerPool, String& addressName, String& publicAddress, String& error)
    {
        addressName.clear();
        publicAddress.clear();
        error.clear();

        String regionFailure = {};
        if (ensureRegion(regionFailure) == false)
        {
            error.assign(regionFailure);
            return false;
        }

        addressName.snprintf<"ntg-eip-{itoa}"_ctv>(Random::generateNumberWithNBits<24, uint32_t>());

        String url = {};
        url.snprintf<"https://compute.googleapis.com/compute/beta/projects/{}/regions/{}/addresses"_ctv>(projectId, region);

        String body = {};
        body.append("{\"name\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, addressName);
        body.append(",\"addressType\":\"EXTERNAL\",\"networkTier\":\"PREMIUM\""_ctv);
        if (providerPool.size() > 0)
        {
            body.append(",\"ipCollection\":"_ctv);
            prodigyAppendEscapedJSONStringLiteral(body, providerPool);
        }
        body.append("}"_ctv);

        String response = {};
        String transportFailure = {};
        long httpStatus = 0;
        if (sendElasticComputeRequest("POST", url, &body, response, &httpStatus, transportFailure) == false)
        {
            if (parseAPIErrorMessage(response, error) == false)
            {
                error = transportFailure.size() > 0 ? transportFailure : "gcp address allocation failed"_ctv;
            }
            return false;
        }

        String operationName = {};
        if (parseOperationName(response, operationName, &error) == false)
        {
            return false;
        }

        if (waitForElasticRegionOperation(operationName, error) == false)
        {
            return false;
        }

        String userInstanceName = {};
        return fetchElasticAddressByName(addressName, publicAddress, userInstanceName, error);
    }

    bool releaseElasticAddressAllocation(const String& addressName, String& error)
    {
        error.clear();
        if (addressName.size() == 0)
        {
            return true;
        }

        String regionFailure = {};
        if (ensureRegion(regionFailure) == false)
        {
            error.assign(regionFailure);
            return false;
        }

        String url = {};
        url.snprintf<"https://compute.googleapis.com/compute/beta/projects/{}/regions/{}/addresses/{}"_ctv>(
            projectId,
            region,
            addressName);

        String response = {};
        String transportFailure = {};
        long httpStatus = 0;
        String emptyBody = {};
        if (sendElasticComputeRequest("DELETE", url, &emptyBody, response, &httpStatus, transportFailure) == false)
        {
            if (httpStatus == 404 || containsCString(response, "notFound") || containsCString(response, "was not found"))
            {
                error.clear();
                return true;
            }

            if (parseAPIErrorMessage(response, error) == false)
            {
                error = transportFailure.size() > 0 ? transportFailure : "gcp address release failed"_ctv;
            }
            return false;
        }

        String operationName = {};
        if (parseOperationName(response, operationName, &error) == false)
        {
            return false;
        }

        return waitForElasticRegionOperation(operationName, error);
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

    bool inferMachineSchemaCpuCapability(const MachineConfig& config, MachineSchemaCpuCapability& capability, String& error) override
    {
        capability = {};
        error.clear();

        if (config.providerMachineType.size() == 0)
        {
            error.assign("gcp schema cpu inference requires providerMachineType"_ctv);
            return false;
        }

        if (ensureProjectZone() == false || ensureToken(&error) == false)
        {
            if (error.size() == 0)
            {
                error.assign("gcp auth failed"_ctv);
            }
            return false;
        }

        String machineTypeUrl = {};
        machineTypeUrl.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/machineTypes/{}?fields=name,architecture"_ctv>(
            projectId,
            zone,
            config.providerMachineType);

        String machineTypeResponse = {};
        String transportFailure = {};
        long httpStatus = 0;
        if (sendElasticComputeRequest("GET", machineTypeUrl, nullptr, machineTypeResponse, &httpStatus, transportFailure) == false)
        {
            if (parseAPIErrorMessage(machineTypeResponse, error) == false)
            {
                error = transportFailure.size() > 0 ? transportFailure : "gcp machineTypes lookup failed"_ctv;
            }
            return false;
        }

        simdjson::dom::parser parser;
        simdjson::dom::element doc = {};
        if (parser.parse(machineTypeResponse.c_str(), machineTypeResponse.size()).get(doc))
        {
            error.assign("gcp machineTypes response parse failed"_ctv);
            return false;
        }

        String architectureText = {};
        std::string_view architectureView = {};
        if (doc["architecture"].get(architectureView) == simdjson::SUCCESS)
        {
            architectureText.assign(architectureView);
        }
        if (resolveMachineArchitecture(config.providerMachineType, architectureText, capability.architecture) == false)
        {
            error.snprintf<"gcp machineTypes architecture '{}' unsupported for machineType '{}'"_ctv>(architectureText, config.providerMachineType);
            return false;
        }

        String zoneUrl = {};
        zoneUrl.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}?fields=availableCpuPlatforms"_ctv>(projectId, zone);

        String zoneResponse = {};
        transportFailure.clear();
        httpStatus = 0;
        if (sendElasticComputeRequest("GET", zoneUrl, nullptr, zoneResponse, &httpStatus, transportFailure) == false)
        {
            if (parseAPIErrorMessage(zoneResponse, error) == false)
            {
                error = transportFailure.size() > 0 ? transportFailure : "gcp zone cpu platform lookup failed"_ctv;
            }
            return false;
        }

        simdjson::dom::parser zoneParser;
        simdjson::dom::element zoneDoc = {};
        if (zoneParser.parse(zoneResponse.c_str(), zoneResponse.size()).get(zoneDoc))
        {
            error.assign("gcp zone cpu platform response parse failed"_ctv);
            return false;
        }

        Vector<String> compatiblePlatforms = {};
        if (zoneDoc["availableCpuPlatforms"].is_array())
        {
            for (auto item : zoneDoc["availableCpuPlatforms"].get_array())
            {
                std::string_view platformView = {};
                if (item.get(platformView) != simdjson::SUCCESS || platformView.size() == 0)
                {
                    continue;
                }

                String platform = {};
                platform.assign(platformView);
                if (gcpCpuPlatformMatchesArchitecture(platform, capability.architecture) == false)
                {
                    continue;
                }

                compatiblePlatforms.push_back(platform);
            }
        }

        if (compatiblePlatforms.empty())
        {
            capability.provenance = MachineSchemaCpuCapabilityProvenance::unavailable;
            return true;
        }

        Vector<String> intersected = {};
        for (uint32_t index = 0; index < compatiblePlatforms.size(); ++index)
        {
            Vector<String> platformFeatures = {};
            gcpAppendCpuPlatformIsaFeatures(capability.architecture, compatiblePlatforms[index], platformFeatures);
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
            capability.cpuPlatform = compatiblePlatforms[0];
        }

        capability.isaFeatures = std::move(intersected);
        capability.provenance = MachineSchemaCpuCapabilityProvenance::providerAuthoritative;
        return true;
    }

    bool ensureManagedInstanceTemplate(const String& templateName,
        const String& serviceAccountEmail,
        const String& network,
        const String& subnetwork,
        const MachineConfig& config,
        bool spot,
        String& error)
    {
        error.clear();

        if (templateName.size() == 0)
        {
            error.assign("gcp managed instance template name required"_ctv);
            return false;
        }

        if (serviceAccountEmail.size() == 0)
        {
            error.assign("gcp managed instance template requires serviceAccountEmail"_ctv);
            return false;
        }

        if (config.providerMachineType.size() == 0)
        {
            error.assign("gcp managed instance template requires providerMachineType"_ctv);
            return false;
        }

        if (config.vmImageURI.size() == 0)
        {
            error.assign("gcp managed instance template requires vmImageURI"_ctv);
            return false;
        }

        if (!ensureProjectZone() || !ensureToken(&error))
        {
            if (error.size() == 0)
            {
                error.assign("gcp auth failed"_ctv);
            }
            return false;
        }

        if (deleteInstanceTemplateIfExists(templateName, error) == false)
        {
            return false;
        }

        String body = {};
        body.append("{\"name\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, templateName);
        body.append(",\"properties\":{\"machineType\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, config.providerMachineType);
        if (config.cpu.cpuPlatform.size() > 0)
        {
            body.append(",\"minCpuPlatform\":"_ctv);
            prodigyAppendEscapedJSONStringLiteral(body, config.cpu.cpuPlatform);
        }

        body.append(",\"labels\":{\"app\":\"prodigy\",\"brain\":\"false\"}"_ctv);
        body.append(",\"tags\":{\"items\":[\"prodigy\"]}"_ctv);
        body.append(",\"metadata\":{\"items\":[{\"key\":\"brain\",\"value\":\"false\"}]}"_ctv);
        body.append(",\"serviceAccounts\":[{\"email\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, serviceAccountEmail);
        body.append(",\"scopes\":[\"https://www.googleapis.com/auth/cloud-platform\"]}]"_ctv);
        body.append(",\"networkInterfaces\":[{\"network\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, network);
        if (subnetwork.size() > 0)
        {
            body.append(",\"subnetwork\":"_ctv);
            prodigyAppendEscapedJSONStringLiteral(body, subnetwork);
        }
        body.append(",\"accessConfigs\":[{\"name\":\"External NAT\",\"type\":\"ONE_TO_ONE_NAT\"}]}]"_ctv);
        body.append(",\"disks\":[{\"boot\":true,\"autoDelete\":true,\"type\":\"PERSISTENT\",\"initializeParams\":{\"sourceImage\":"_ctv);
        prodigyAppendEscapedJSONStringLiteral(body, config.vmImageURI);
        body.append(",\"diskSizeGb\":20}}]"_ctv);

        if (spot)
        {
            body.append(",\"scheduling\":{\"provisioningModel\":\"SPOT\",\"instanceTerminationAction\":\"DELETE\",\"automaticRestart\":false}"_ctv);
        }

        body.append("}}"_ctv);

        String url = {};
        url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/global/instanceTemplates"_ctv>(projectId);

        String response = {};
        String transportFailure = {};
        long httpStatus = 0;
        if (sendElasticComputeRequest("POST", url, &body, response, &httpStatus, transportFailure) == false)
        {
            if (parseAPIErrorMessage(response, error) == false)
            {
                error = transportFailure.size() > 0 ? transportFailure : "gcp instance template create failed"_ctv;
            }
            return false;
        }

        String operationName = {};
        if (parseOperationName(response, operationName, &error) == false)
        {
            return false;
        }

        return waitForGlobalOperation(operationName, error);
    }

    void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bytell_hash_set<Machine *>& newMachines, String& error) override
    {
        spinMachines(coro, lifetime, config, count, false, newMachines, error);
    }

    void spinMachines(CoroutineStack *coro, MachineLifetime lifetime, const MachineConfig& config, uint32_t count, bool isBrain, bytell_hash_set<Machine *>& newMachines, String& error) override
    {
        provisioningProgress.reset();
        if (lifetime == MachineLifetime::owned) { error.assign("gcp auto provisioning does not support MachineLifetime::owned"_ctv); return; }
        if (config.kind != MachineConfig::MachineKind::vm) { error.assign("gcp auto provisioning only supports vm machine kinds"_ctv); return; }
        (void)coro; if (!ensureProjectZone() || !ensureToken(&error)) { if (error.size() == 0) error.assign("gcp auth failed"_ctv); return; }
        if (config.vmImageURI.size() == 0) { error.assign("vmImageURI missing"_ctv); return; }
        if (config.providerMachineType.size() == 0) { error.assign("providerMachineType missing"_ctv); return; }
        const String& instanceTemplateName = (lifetime == MachineLifetime::spot) ? config.gcpInstanceTemplateSpot : config.gcpInstanceTemplate;
        if (instanceTemplateName.size() == 0)
        {
            if (lifetime == MachineLifetime::spot)
            {
                error.assign("gcpInstanceTemplateSpot missing"_ctv);
            }
            else
            {
                error.assign("gcpInstanceTemplate missing"_ctv);
            }
            return;
        }
        String base; base.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances"_ctv>(projectId, zone);
        String instanceTemplateResponse = {};
        simdjson::dom::parser templateParser;
        simdjson::dom::element instanceTemplate;
        if (fetchInstanceTemplate(instanceTemplateName, instanceTemplateResponse, templateParser, instanceTemplate, error) == false)
        {
            return;
        }

        class PendingCreateSubmission
        {
        public:

            String instanceName = {};
            GcpHttp::MultiRequest request = {};
            bool processed = false;
        };

        Vector<PendingMachineProvisioning> pendingMachines = {};
        Vector<Machine *> readyMachines = {};
        Vector<PendingCreateSubmission> createRequests = {};
        createRequests.reserve(count);
        auto destroyPendingMachineByName = [&] (const String& instanceName) -> void {

            if (instanceName.size() == 0)
            {
                return;
            }

            basics_log("gcp spinMachines destroy-pending instance=%.*s\n",
                int(instanceName.size()),
                reinterpret_cast<const char *>(instanceName.data()));

            struct curl_slist *headers = nullptr;
            buildAuthHeaders(headers);
            String url = {};
            url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}"_ctv>(projectId, zone, instanceName);
            String response = {};
            long httpStatus = 0;
            if (GcpHttp::send("DELETE", url.c_str(), headers, String(), response, &httpStatus))
            {
                String operationName = {};
                String deleteError = {};
                if (parseOperationName(response, operationName, &deleteError))
                {
                    basics_log("gcp spinMachines destroy-pending-accepted instance=%.*s operation=%s\n",
                        int(instanceName.size()),
                        reinterpret_cast<const char *>(instanceName.data()),
                        operationName.c_str());
                    (void)waitForZoneOperation(operationName, String(), String(), String(), deleteError);
                }
            }
            curl_slist_free_all(headers);
        };
        auto cleanupProvisioningFailure = [&] () -> void {

            basics_log("gcp spinMachines cleanup ready=%u pending=%u\n",
                uint32_t(readyMachines.size()),
                uint32_t(createRequests.size()));

            for (Machine *machine : readyMachines)
            {
                destroyMachine(machine);
                delete machine;
            }

            readyMachines.clear();
            for (const PendingCreateSubmission& submission : createRequests)
            {
                destroyPendingMachineByName(submission.instanceName);
            }
            createRequests.clear();
            pendingMachines.clear();
        };

        auto processCreateCompletion = [&] (PendingCreateSubmission& submission) -> void {

            if (submission.processed)
            {
                return;
            }
            submission.processed = true;

            if (submission.request.curlCode != CURLE_OK || submission.request.httpStatus < 200 || submission.request.httpStatus >= 300)
            {
                if (error.size() == 0)
                {
                    if (parseAPIErrorMessage(submission.request.response, error) == false)
                    {
                        error.assign(submission.request.transportFailure.size() > 0 ? submission.request.transportFailure : "gcp instance create failed"_ctv);
                    }
                }
                return;
            }

            String operationName = {};
            if (parseOperationName(submission.request.response, operationName, &error) == false)
            {
                return;
            }

            PendingMachineProvisioning& pending = pendingMachines.emplace_back();
            pending.instanceName = submission.instanceName;
            pending.operationName = std::move(operationName);
#if PRODIGY_DEBUG
            basics_log("gcp create accepted instance=%s operation=%s schema=%.*s providerType=%.*s\n",
               pending.instanceName.c_str(),
               pending.operationName.c_str(),
               int(config.slug.size()),
               reinterpret_cast<const char *>(config.slug.data()),
               int(config.providerMachineType.size()),
               reinterpret_cast<const char *>(config.providerMachineType.data()));
#endif
        };

        auto drainCreateCompletions = [&] (GcpHttp::MultiClient& createClient) -> void {

            while (GcpHttp::MultiRequest *completed = createClient.popCompleted())
            {
                PendingCreateSubmission *submission = reinterpret_cast<PendingCreateSubmission *>(completed->context);
                if (submission != nullptr)
                {
                    processCreateCompletion(*submission);
                }
            }
        };

        GcpHttp::MultiClient createClient = {};
        for (uint32_t i = 0; i < count; ++i)
        {
            String name; name.snprintf<"ntg-{itoa}"_ctv>(Random::generateNumberWithNBits<24,uint32_t>());
            MachineProvisioningProgress& progress = provisioningProgress.upsert(config.slug, config.providerMachineType, name, String());
            progress.status.assign("launch-submitted"_ctv);
            progress.ready = false;
            provisioningProgress.emitMaybe(Time::now<TimeResolution::ms>());
            String brainText = {};
            if (isBrain)
            {
                brainText.assign("true"_ctv);
            }
            else
            {
                brainText.assign("false"_ctv);
            }

            String body;
            uint32_t diskGb = (config.nStorageMB + 1023) / 1024; if (diskGb == 0) diskGb = 20;
            body.append("{\"name\":"_ctv);
            prodigyAppendEscapedJSONStringLiteral(body, name);
            if (appendTemplateBootDiskOverride(body, instanceTemplate, config.vmImageURI, diskGb, error) == false)
            {
                break;
            }
            body.append(",\"machineType\":"_ctv);
            String machineTypeURL = {};
            machineTypeURL.snprintf<"zones/{}/machineTypes/{}"_ctv>(zone, config.providerMachineType);
            prodigyAppendEscapedJSONStringLiteral(body, machineTypeURL);
            if (config.cpu.cpuPlatform.size() > 0)
            {
                body.append(",\"minCpuPlatform\":"_ctv);
                prodigyAppendEscapedJSONStringLiteral(body, config.cpu.cpuPlatform);
            }
            body.append(",\"labels\":{\"app\":\"prodigy\",\"brain\":"_ctv);
            prodigyAppendEscapedJSONStringLiteral(body, brainText);
            if (provisioningClusterUUIDTagValue.size() > 0)
            {
                body.append(",\"prodigy_cluster_uuid\":"_ctv);
                prodigyAppendEscapedJSONStringLiteral(body, provisioningClusterUUIDTagValue);
            }
            body.append("},\"metadata\":{\"items\":[{\"key\":\"brain\",\"value\":"_ctv);
            prodigyAppendEscapedJSONStringLiteral(body, brainText);
            body.append("}"_ctv);
            if (bootstrapSSHPublicKey.size() > 0)
            {
                String startupScript = {};
                prodigyBuildBootstrapSSHUserData(bootstrapSSHUser, bootstrapSSHPublicKey, bootstrapSSHHostKeyPackage, startupScript);
                body.append(",{\"key\":\"startup-script\",\"value\":"_ctv);
                prodigyAppendEscapedJSONStringLiteral(body, startupScript);
                body.append("}"_ctv);
            }
            body.append("]}}"_ctv);

            String requestURL = {};
            requestURL.snprintf<"{}?sourceInstanceTemplate=projects/{}/global/instanceTemplates/{}"_ctv>(base, projectId, instanceTemplateName);

            PendingCreateSubmission& submission = createRequests.emplace_back();
            submission.instanceName = name;
            submission.request.resetResult();
            submission.request.context = &submission;
            submission.request.method.assign("POST"_ctv);
            submission.request.url = requestURL;
            submission.request.body = body;
            submission.request.timeoutMs = GcpHttp::sendTimeoutMs;
            buildAuthHeaders(submission.request.headers);
            if (submission.request.headers == nullptr)
            {
                error.assign("gcp auth headers missing"_ctv);
                break;
            }

            if (createClient.start(submission.request) == false)
            {
                error.assign("gcp create request start failed"_ctv);
                break;
            }
        }

        while (error.size() == 0 && createClient.pendingCount() > 0)
        {
            if (createClient.pump(50) == false)
            {
                error.assign("gcp create request pump failed"_ctv);
                break;
            }

            drainCreateCompletions(createClient);
        }

        if (error.size() == 0)
        {
            drainCreateCompletions(createClient);
        }

        if (error.size() == 0 && pendingMachines.size() != count)
        {
            error.snprintf<"gcp create returned {itoa} accepted machines but {itoa} were requested"_ctv>(
                uint32_t(pendingMachines.size()),
                count);
        }

        if (error.size() == 0 && pendingMachines.size() > 0)
        {
            ConcurrentWaitCoordinator coordinator(this);
            (void)coordinator.run(
                config.slug,
                config.providerMachineType,
                lifetime,
                pendingMachines,
                readyMachines,
                error);
        }

        if (error.size() != 0)
        {
            basics_log("gcp spinMachines failure error=%s\n", error.c_str());
            cleanupProvisioningFailure();
            return;
        }

        for (Machine *machine : readyMachines)
        {
            newMachines.insert(machine);
        }
    }

    void getMachines(CoroutineStack *coro, const String& metro, bytell_hash_set<Machine *>& machines) override
    {
        (void)coro; (void)metro; if (!ensureProjectZone() || !ensureToken()) return;
        struct curl_slist *h = nullptr;
        buildAuthHeaders(h);

        String nextPageToken = {};
        for (;;)
        {
            String url;
            url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances?filter=labels.app%3Aprodigy"_ctv>(projectId, zone);
            appendPageTokenQuery(url, nextPageToken);

            String response;
            if (GcpHttp::get(url.c_str(), h, response) == false)
            {
                break;
            }

            simdjson::dom::parser parser;
            simdjson::dom::element doc;
            if (parser.parse(response.c_str(), response.size()).get(doc))
            {
                break;
            }

            if (auto items = doc["items"]; items.is_array())
            {
                for (auto instance : items.get_array())
                {
                    if (isProdigyInstance(instance) == false)
                    {
                        continue;
                    }

                    machines.insert(buildMachineFromInstance(instance));
                }
            }

            std::string_view pageToken;
            if (doc["nextPageToken"].get(pageToken))
            {
                break;
            }

            nextPageToken.assign(pageToken);
            if (nextPageToken.size() == 0)
            {
                break;
            }
        }

        curl_slist_free_all(h);
    }

    void getBrains(CoroutineStack *coro, uint128_t selfUUID, bool& selfIsBrain, bytell_hash_set<BrainView *>& brains) override
    {
        selfIsBrain = false;
        (void)coro; (void)selfUUID; if (!ensureProjectZone() || !ensureToken()) return;

        struct curl_slist *h = nullptr;
        buildAuthHeaders(h);

        String nextPageToken = {};
        for (;;)
        {
            String url;
            url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances?filter=labels.app%3Aprodigy"_ctv>(projectId, zone);
            appendPageTokenQuery(url, nextPageToken);

            String response;
            if (GcpHttp::get(url.c_str(), h, response) == false)
            {
                break;
            }

            simdjson::dom::parser parser;
            simdjson::dom::element doc;
            if (parser.parse(response.c_str(), response.size()).get(doc))
            {
                break;
            }

            if (auto items = doc["items"]; items.is_array())
            {
                for (auto instance : items.get_array())
                {
                    if (isProdigyInstance(instance) == false || isBrainInstance(instance) == false)
                    {
                        continue;
                    }

                    std::string_view nip;
                    auto nics = instance["networkInterfaces"].get_array();
                    if (nics.error())
                    {
                        continue;
                    }

                    for (auto nic : nics)
                    {
                        if (nic["networkIP"].get(nip))
                        {
                            continue;
                        }

                        String privateText = String(nip);
                        uint32_t ip = 0;
                        if (inet_pton(AF_INET, privateText.c_str(), &ip) != 1)
                        {
                            continue;
                        }

                        if (thisNeuron != nullptr && ip == thisNeuron->private4.v4)
                        {
                            selfIsBrain = true;
                            continue;
                        }

                        BrainView *bv = new BrainView();
                        bv->private4 = ip;
                        bv->peerAddress.is6 = false;
                        bv->peerAddress.v4 = ip;
                        bv->peerAddressText.assign(privateText);
                        bv->connectTimeoutMs = BrainBase::controlPlaneConnectTimeoutMs();
                        bv->nDefaultAttemptsBudget = BrainBase::controlPlaneConnectAttemptsBudget();
                        brains.insert(bv);
                        break;
                    }
                }
            }

            std::string_view pageToken;
            if (doc["nextPageToken"].get(pageToken))
            {
                break;
            }

            nextPageToken.assign(pageToken);
            if (nextPageToken.size() == 0)
            {
                break;
            }
        }

        curl_slist_free_all(h);
    }

    void hardRebootMachine(uint128_t uuid) override
    {
        if (!ensureProjectZone() || !ensureToken()) return;
        // Find instance by matching hashed id -> uuid
        String name;

        struct curl_slist *h = nullptr;
        buildAuthHeaders(h);

        String nextPageToken = {};
        for (;;)
        {
            String url;
            url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances?fields=items(name,id),nextPageToken"_ctv>(projectId, zone);
            appendPageTokenQuery(url, nextPageToken);

            String response;
            if (GcpHttp::get(url.c_str(), h, response) == false)
            {
                break;
            }

            simdjson::dom::parser parser;
            simdjson::dom::element doc;
            if (parser.parse(response.c_str(), response.size()).get(doc))
            {
                break;
            }

            if (auto items = doc["items"]; items.is_array())
            {
                for (auto instance : items.get_array())
                {
                    std::string_view id;
                    if (instance["id"].get(id))
                    {
                        continue;
                    }

                    if (hash_uuid(id) == uuid)
                    {
                        std::string_view nm;
                        if (!instance["name"].get(nm))
                        {
                            name.assign(nm);
                        }
                        break;
                    }
                }
            }

            if (name.size() > 0)
            {
                break;
            }

            std::string_view pageToken;
            if (doc["nextPageToken"].get(pageToken))
            {
                break;
            }

            nextPageToken.assign(pageToken);
            if (nextPageToken.size() == 0)
            {
                break;
            }
        }

        if (name.size() == 0) { curl_slist_free_all(h); return; }
        // POST reset
        String resetUrl; resetUrl.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}/reset"_ctv>(projectId, zone, name);
        String out;
        long httpStatus = 0;
        if (GcpHttp::send("POST", resetUrl.c_str(), h, String(), out, &httpStatus))
        {
            String operationName;
            String operationError;
            if (parseOperationName(out, operationName, &operationError))
            {
                (void)waitForZoneOperation(operationName, String(), String(), String(), operationError);
            }
        }
        curl_slist_free_all(h);
    }

    void reportHardwareFailure(uint128_t uuid, const String& report) override { (void)uuid; (void)report; }

    void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) override
    {
        (void)coro; if (!ensureProjectZone() || !ensureToken()) return;
        struct curl_slist *h = nullptr;
        buildAuthHeaders(h);

        String nextPageToken = {};
        for (;;)
        {
            String url;
            url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances?filter=labels.app%3Aprodigy"_ctv>(projectId, zone);
            appendPageTokenQuery(url, nextPageToken);

            String response;
            if (!GcpHttp::get(url.c_str(), h, response))
            {
                break;
            }

            simdjson::dom::parser parser;
            simdjson::dom::element doc;
            if (parser.parse(response.c_str(), response.size()).get(doc))
            {
                break;
            }

            if (auto items = doc["items"]; items.is_array())
            {
                for (auto instance : items.get_array())
                {
                    if (isProdigyInstance(instance) == false || isSpotInstance(instance) == false)
                    {
                        continue;
                    }

                    std::string_view status;
                    if (instance["status"].get(status))
                    {
                        continue;
                    }

                    if (status == "TERMINATED")
                    {
                        std::string_view id;
                        if (!instance["id"].get(id))
                        {
                            decommissionedIDs.emplace_back(String(id));
                        }
                    }
                }
            }

            std::string_view pageToken;
            if (doc["nextPageToken"].get(pageToken))
            {
                break;
            }

            nextPageToken.assign(pageToken);
            if (nextPageToken.size() == 0)
            {
                break;
            }
        }

        curl_slist_free_all(h);
    }

    void destroyMachine(Machine *machine) override
    {
        if (!ensureProjectZone() || !ensureToken() || machine == nullptr || machine->cloudID.size() == 0) return;
        String instanceName;
        if (resolveInstanceNameForCloudID(machine->cloudID, instanceName) == false) return;
        basics_log("gcp destroyMachine cloudID=%s instance=%s\n", machine->cloudID.c_str(), instanceName.c_str());
        String url; url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}"_ctv>(projectId, zone, instanceName);
        struct curl_slist *h = nullptr; buildAuthHeaders(h);
        String resp;
        long httpStatus = 0;
        if (GcpHttp::send("DELETE", url.c_str(), h, String(), resp, &httpStatus))
        {
            String operationName;
            String error;
            if (parseOperationName(resp, operationName, &error))
            {
                basics_log("gcp destroyMachine accepted cloudID=%s instance=%s operation=%s\n", machine->cloudID.c_str(), instanceName.c_str(), operationName.c_str());
                (void)waitForZoneOperation(operationName, String(), String(), String(), error);
            }
        }
        curl_slist_free_all(h);
    }

    bool destroyClusterMachines(const String& clusterUUID, uint32_t& destroyed, String& error) override
    {
        destroyed = 0;
        error.clear();

        if (!ensureProjectZone() || !ensureToken(&error))
        {
            if (error.size() == 0)
            {
                error.assign("gcp auth failed"_ctv);
            }
            return false;
        }

        if (clusterUUID.size() == 0)
        {
            error.assign("gcp clusterUUID tag value required"_ctv);
            return false;
        }

        Vector<String> instanceNames = {};
        struct curl_slist *h = nullptr;
        buildAuthHeaders(h);

        String nextPageToken = {};
        for (;;)
        {
            String url = {};
            url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances?filter=labels.app%3Aprodigy"_ctv>(projectId, zone);
            appendPageTokenQuery(url, nextPageToken);

            String response = {};
            if (GcpHttp::get(url.c_str(), h, response) == false)
            {
                curl_slist_free_all(h);
                if (parseAPIErrorMessage(response, error) == false && error.size() == 0)
                {
                    error.assign("gcp list instances failed"_ctv);
                }
                return false;
            }

            simdjson::dom::parser parser;
            simdjson::dom::element doc;
            if (parser.parse(response.c_str(), response.size()).get(doc))
            {
                curl_slist_free_all(h);
                error.assign("gcp instance list json parse failed"_ctv);
                return false;
            }

            if (auto items = doc["items"]; items.is_array())
            {
                for (auto instance : items.get_array())
                {
                    if (isProdigyInstance(instance) == false)
                    {
                        continue;
                    }

                    std::string_view clusterValue = {};
                    if (instance["labels"]["prodigy_cluster_uuid"].get(clusterValue) || clusterValue != stringViewFor(clusterUUID))
                    {
                        continue;
                    }

                    std::string_view instanceName = {};
                    if (!instance["name"].get(instanceName) && instanceName.size() > 0)
                    {
                        instanceNames.push_back(String(instanceName));
                    }
                }
            }

            std::string_view pageToken = {};
            if (doc["nextPageToken"].get(pageToken))
            {
                break;
            }

            nextPageToken.assign(pageToken);
            if (nextPageToken.size() == 0)
            {
                break;
            }
        }

        if (instanceNames.size() == 0)
        {
            curl_slist_free_all(h);
            return true;
        }

        destroyed = uint32_t(instanceNames.size());

        Vector<String> operations = {};
        for (const String& instanceName : instanceNames)
        {
            String url = {};
            url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}"_ctv>(projectId, zone, instanceName);

            String response = {};
            long httpStatus = 0;
            if (GcpHttp::send("DELETE", url.c_str(), h, String(), response, &httpStatus) == false)
            {
                curl_slist_free_all(h);
                if (parseAPIErrorMessage(response, error) == false)
                {
                    error.snprintf<"gcp delete instance failed with HTTP {itoa}"_ctv>(uint32_t(httpStatus));
                }
                return false;
            }

            String operationName = {};
            if (parseOperationName(response, operationName, &error) == false)
            {
                curl_slist_free_all(h);
                return false;
            }

            operations.push_back(operationName);
        }

        curl_slist_free_all(h);

        for (const String& operationName : operations)
        {
            if (waitForZoneOperation(operationName, String(), String(), String(), error) == false)
            {
                return false;
            }
        }

        for (uint32_t attempt = 0; attempt < 30; ++attempt)
        {
            instanceNames.clear();
            nextPageToken.clear();

            struct curl_slist *pollHeaders = nullptr;
            buildAuthHeaders(pollHeaders);

            bool pollFailed = false;
            for (;;)
            {
                String url = {};
                url.snprintf<"https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances?filter=labels.app%3Aprodigy"_ctv>(projectId, zone);
                appendPageTokenQuery(url, nextPageToken);

                String response = {};
                if (GcpHttp::get(url.c_str(), pollHeaders, response) == false)
                {
                    pollFailed = true;
                    if (parseAPIErrorMessage(response, error) == false && error.size() == 0)
                    {
                        error.assign("gcp poll instances failed"_ctv);
                    }
                    break;
                }

                simdjson::dom::parser parser;
                simdjson::dom::element doc;
                if (parser.parse(response.c_str(), response.size()).get(doc))
                {
                    pollFailed = true;
                    error.assign("gcp poll instance list json parse failed"_ctv);
                    break;
                }

                if (auto items = doc["items"]; items.is_array())
                {
                    for (auto instance : items.get_array())
                    {
                        std::string_view clusterValue = {};
                        if (instance["labels"]["prodigy_cluster_uuid"].get(clusterValue) || clusterValue != stringViewFor(clusterUUID))
                        {
                            continue;
                        }

                        std::string_view instanceName = {};
                        if (!instance["name"].get(instanceName) && instanceName.size() > 0)
                        {
                            instanceNames.push_back(String(instanceName));
                        }
                    }
                }

                std::string_view pageToken = {};
                if (doc["nextPageToken"].get(pageToken))
                {
                    break;
                }

                nextPageToken.assign(pageToken);
                if (nextPageToken.size() == 0)
                {
                    break;
                }
            }

            curl_slist_free_all(pollHeaders);

            if (pollFailed)
            {
                return false;
            }

            if (instanceNames.size() == 0)
            {
                return true;
            }

            usleep(1000 * 1000);
         }

         error.assign("timed out waiting for gcp cluster machines to terminate"_ctv);
         return false;
    }

    bool ensureProdigyMachineTags(const String& clusterUUID, Machine *machine, String& error) override
    {
        error.clear();

        if (!ensureProjectZone() || !ensureToken(&error))
        {
            if (error.size() == 0)
            {
                error.assign("gcp auth failed"_ctv);
            }
            return false;
        }

        if (machine == nullptr || machine->cloudID.size() == 0)
        {
            error.assign("gcp machine cloudID required"_ctv);
            return false;
        }

        if (clusterUUID.size() == 0)
        {
            error.assign("gcp clusterUUID tag value required"_ctv);
            return false;
        }

        String instanceName = {};
        if (resolveInstanceNameForCloudID(machine->cloudID, instanceName) == false || instanceName.size() == 0)
        {
            error.assign("gcp failed to resolve instance name from cloudID"_ctv);
            return false;
        }

        if (ensureInstanceLabel(instanceName, "app"_ctv, "prodigy"_ctv, error) == false)
        {
            return false;
        }

        return ensureInstanceLabel(instanceName, "prodigy_cluster_uuid"_ctv, clusterUUID, error);
    }

    bool assignProviderElasticAddress(Machine *machine,
        ExternalAddressFamily family,
        const String& requestedAddress,
        const String& providerPool,
        IPAddress& assignedAddress,
        String& allocationID,
        String& associationID,
        bool& releaseOnRemove,
        String& error) override
    {
        assignedAddress = {};
        allocationID.clear();
        associationID.clear();
        releaseOnRemove = false;
        error.clear();

        if (machine == nullptr || machine->cloudID.size() == 0)
        {
            error.assign("gcp elastic address requires a cloud-backed target machine"_ctv);
            return false;
        }

        if (family != ExternalAddressFamily::ipv4)
        {
            error.assign("gcp elastic addresses currently support only ipv4"_ctv);
            return false;
        }

        if (requestedAddress.size() > 0 && providerPool.size() > 0)
        {
            error.assign("gcp elastic address cannot combine requestedAddress with providerPool"_ctv);
            return false;
        }

        String instanceName = {};
        if (fetchElasticInstanceNameForCloudID(machine->cloudID, instanceName, error) == false)
        {
            return false;
        }

        String publicAddress = {};
        String existingUserInstance = {};
        if (requestedAddress.size() > 0)
        {
            if (findElasticAddressByPublicIP(requestedAddress, allocationID, publicAddress, existingUserInstance, error) == false)
            {
                return false;
            }

            releaseOnRemove = false;
        }
        else
        {
            if (allocateElasticAddress(providerPool, allocationID, publicAddress, error) == false)
            {
                return false;
            }

            releaseOnRemove = true;
        }

        bool attached = false;
        auto cleanupOnFailure = [&] () -> void {
            if (attached && associationID.size() > 0)
            {
                String cleanupInstance = {};
                String cleanupNic = {};
                String cleanupAccessConfig = {};
                if (parseElasticAssociationID(associationID, cleanupInstance, cleanupNic, cleanupAccessConfig))
                {
                    String detachFailure = {};
                    (void)deleteElasticAccessConfig(cleanupInstance, cleanupNic, cleanupAccessConfig, detachFailure);
                }
            }

            if (releaseOnRemove && allocationID.size() > 0)
            {
                String releaseFailure = {};
                (void)releaseElasticAddressAllocation(allocationID, releaseFailure);
            }
        };

        if (existingUserInstance.size() > 0 && existingUserInstance.equals(instanceName) == false)
        {
            String oldNic = {};
            String oldAccessConfig = {};
            String detachFailure = {};
            if (findElasticInterfaceForAddress(existingUserInstance, publicAddress, oldNic, oldAccessConfig, detachFailure)
                && oldNic.size() > 0
                && oldAccessConfig.size() > 0)
            {
                if (deleteElasticAccessConfig(existingUserInstance, oldNic, oldAccessConfig, error) == false)
                {
                    cleanupOnFailure();
                    return false;
                }
            }
        }

        String nicName = {};
        String accessConfigName = {};
        String existingPublicAddress = {};
        bool hasAccessConfig = false;
        if (describeElasticTargetInterface(instanceName, nicName, accessConfigName, existingPublicAddress, hasAccessConfig, error) == false)
        {
            cleanupOnFailure();
            return false;
        }

        if (hasAccessConfig && existingPublicAddress.equals(publicAddress))
        {
            associationID.snprintf<"{}|{}|{}"_ctv>(instanceName, nicName, accessConfigName);
            attached = true;
        }
        else
        {
            if (hasAccessConfig)
            {
                if (deleteElasticAccessConfig(instanceName, nicName, accessConfigName, error) == false)
                {
                    cleanupOnFailure();
                    return false;
                }
            }

            if (attachElasticAccessConfig(instanceName, nicName, accessConfigName, publicAddress, associationID, error) == false)
            {
                cleanupOnFailure();
                return false;
            }

            attached = true;
        }

        if (ClusterMachine::parseIPAddressLiteral(publicAddress, assignedAddress) == false)
        {
            error.assign("gcp elastic address parse failed"_ctv);
            cleanupOnFailure();
            return false;
        }

        return true;
    }

    bool releaseProviderElasticAddress(const RegisteredRoutableAddress& address, String& error) override
    {
        error.clear();
        if (address.kind != RoutableAddressKind::providerElasticAddress)
        {
            return true;
        }

        if (address.providerAssociationID.size() > 0)
        {
            String instanceName = {};
            String nicName = {};
            String accessConfigName = {};
            if (parseElasticAssociationID(address.providerAssociationID, instanceName, nicName, accessConfigName) == false)
            {
                error.assign("gcp elastic address associationID parse failed"_ctv);
                return false;
            }

            if (deleteElasticAccessConfig(instanceName, nicName, accessConfigName, error) == false)
            {
                return false;
            }
        }

        if (address.releaseOnRemove)
        {
            if (releaseElasticAddressAllocation(address.providerAllocationID, error) == false)
            {
                return false;
            }
        }

        return true;
    }
};
