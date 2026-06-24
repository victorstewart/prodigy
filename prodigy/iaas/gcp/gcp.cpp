#include <prodigy/iaas/gcp/gcp.h>

bool GcpHttp::ensureGlobalInit(void)
{
  static bool initialized = (curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK);
  return initialized;
}

void GcpHttp::populateTransportFailure(CURLcode rc, const char *errorBuffer, String *transportFailure)
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

bool GcpHttp::get(const char *url, const struct curl_slist *headers, String& out, long *httpStatus, String *transportFailure)
{
  if (ensureGlobalInit() == false)
  {
    return false;
  }

  out.clear();
  CURL *curl = curl_easy_init();
  if (!curl)
  {
    return false;
  }
  char errorBuffer[CURL_ERROR_SIZE];
  errorBuffer[0] = '\0';
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, connectTimeoutMs);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, getTimeoutMs);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
    String *s = (String *)userdata;
    s->append((uint8_t *)ptr, size * nmemb);
    return size * nmemb;
  });
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
  CURLcode rc = curl_easy_perform(curl);
  long status = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
  populateTransportFailure(rc, errorBuffer, transportFailure);
  curl_easy_cleanup(curl);
  if (httpStatus)
  {
    *httpStatus = status;
  }
  return rc == CURLE_OK && status >= 200 && status < 300;
}

bool GcpHttp::send(const char *method, const char *url, const struct curl_slist *headers, const String& body, String& out, long *httpStatus, String *transportFailure)
{
  if (ensureGlobalInit() == false)
  {
    return false;
  }

  out.clear();
  CURL *curl = curl_easy_init();
  if (!curl)
  {
    return false;
  }
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
  if (body.size() > 0)
  {
    bodyText.assign(body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, bodyText.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, long(bodyText.size()));
  }
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
    String *s = (String *)userdata;
    s->append((uint8_t *)ptr, size * nmemb);
    return size * nmemb;
  });
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
  CURLcode rc = curl_easy_perform(curl);
  long status = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
  populateTransportFailure(rc, errorBuffer, transportFailure);
  curl_easy_cleanup(curl);
  if (httpStatus)
  {
    *httpStatus = status;
  }
  return rc == CURLE_OK && status >= 200 && status < 300;
}

void GcpHttp::MultiRequest::resetResult(void)
{
  response.clear();
  transportFailure.clear();
  httpStatus = 0;
  curlCode = CURLE_OK;
  completed = false;
  added = false;
}

void GcpHttp::MultiRequest::clearTransport(void)
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

GcpHttp::MultiRequest::~MultiRequest()
{
  clearTransport();
}

size_t GcpHttp::MultiClient::writeResponse(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  String *response = reinterpret_cast<String *>(userdata);
  response->append(reinterpret_cast<uint8_t *>(ptr), size * nmemb);
  return size * nmemb;
}

void GcpHttp::MultiClient::collectCompleted(void)
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

bool GcpHttp::MultiClient::init(void)
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

bool GcpHttp::MultiClient::start(MultiRequest& request)
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

bool GcpHttp::MultiClient::pump(int timeoutMs)
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

GcpHttp::MultiRequest *GcpHttp::MultiClient::popCompleted(void)
{
  if (completed.empty())
  {
    return nullptr;
  }

  MultiRequest *request = completed.back();
  completed.pop_back();
  return request;
}

uint32_t GcpHttp::MultiClient::pendingCount(void) const
{
  return inFlight;
}

GcpHttp::MultiClient::~MultiClient()
{
  if (multi != nullptr)
  {
    curl_multi_cleanup(multi);
    multi = nullptr;
  }
}

uint32_t gcpHashRackIdentity(std::string_view s)
{
  uint32_t u = 0;
  for (char c : s)
  {
    u = (u * 131u) + uint8_t(c);
  }

  return u;
}

bool gcpGetNestedElement(simdjson::dom::element root, std::initializer_list<std::string_view> path, simdjson::dom::element& value)
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

bool gcpExtractZoneName(std::string_view zoneURL, String& zoneText)
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

uint32_t gcpExtractRackUUID(simdjson::dom::element inst, const String& zoneText)
{
  std::string_view physicalHost = {};
  simdjson::dom::element value = {};
  if (gcpGetNestedElement(inst, {"resourceStatus", "physicalHost"}, value) && !value.get(physicalHost) && physicalHost.size() > 0)
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
  bool hasCluster = gcpGetNestedElement(inst, {"resourceStatus", "physicalHostTopology", "cluster"}, value) && !value.get(cluster) && cluster.size() > 0;
  bool hasBlock = gcpGetNestedElement(inst, {"resourceStatus", "physicalHostTopology", "block"}, value) && !value.get(block) && block.size() > 0;
  bool hasSubblock = gcpGetNestedElement(inst, {"resourceStatus", "physicalHostTopology", "subblock"}, value) && !value.get(subblock) && subblock.size() > 0;
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
