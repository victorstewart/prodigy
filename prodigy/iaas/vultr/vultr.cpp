#include <prodigy/iaas/vultr/vultr.h>

bool VultrHttp::ensureGlobalInit(void)
{
  static bool initialized = (curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK);
  return initialized;
}

bool VultrHttp::get(const char *url, const struct curl_slist *headers, String& out, long *httpCode)
{
  if (ensureGlobalInit() == false)
  {
    return false;
  }

  CURL *curl = curl_easy_init();
  if (!curl)
  {
    return false;
  }
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, connectTimeoutMs);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, getTimeoutMs);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
    String *s = (String *)userdata;
    s->append((uint8_t *)ptr, size * nmemb);
    return size * nmemb;
  });
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
  CURLcode rc = curl_easy_perform(curl);
  long code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
  if (httpCode)
  {
    *httpCode = code;
  }
  curl_easy_cleanup(curl);
  return rc == CURLE_OK;
}

bool VultrHttp::send(const char *method, const char *url, const struct curl_slist *headers, const String& body, String& out, long *httpCode, long timeoutMs)
{
  if (ensureGlobalInit() == false)
  {
    return false;
  }

  CURL *curl = curl_easy_init();
  if (!curl)
  {
    return false;
  }
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
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
    String *s = (String *)userdata;
    s->append((uint8_t *)ptr, size * nmemb);
    return size * nmemb;
  });
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
  CURLcode rc = curl_easy_perform(curl);
  long code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
  if (httpCode)
  {
    *httpCode = code;
  }
  curl_easy_cleanup(curl);
  return rc == CURLE_OK;
}

void VultrHttp::MultiRequest::resetResult(void)
{
  response.clear();
  httpCode = 0;
  curlCode = CURLE_OK;
  completed = false;
  added = false;
}

void VultrHttp::MultiRequest::clearTransport(void)
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

VultrHttp::MultiRequest::~MultiRequest()
{
  clearTransport();
}

size_t VultrHttp::MultiClient::writeResponse(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  String *response = reinterpret_cast<String *>(userdata);
  response->append(reinterpret_cast<uint8_t *>(ptr), size * nmemb);
  return size * nmemb;
}

void VultrHttp::MultiClient::collectCompleted(void)
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

bool VultrHttp::MultiClient::init(void)
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

bool VultrHttp::MultiClient::start(MultiRequest& request)
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

bool VultrHttp::MultiClient::pump(int timeoutMs)
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

VultrHttp::MultiRequest *VultrHttp::MultiClient::popCompleted(void)
{
  if (completed.empty())
  {
    return nullptr;
  }

  MultiRequest *request = completed.back();
  completed.pop_back();
  return request;
}

uint32_t VultrHttp::MultiClient::pendingCount(void) const
{
  return inFlight;
}

VultrHttp::MultiClient::~MultiClient()
{
  if (multi != nullptr)
  {
    curl_multi_cleanup(multi);
    multi = nullptr;
  }
}
