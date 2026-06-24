#include <prodigy/iaas/azure/azure.h>

bool AzureHttp::ensureGlobalInit(void)
{
  static bool initialized = (curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK);
  return initialized;
}

bool AzureHttp::appendResponseBytes(String& out, const uint8_t *bytes, uint64_t bytesSize)
{
  if (bytesSize == 0)
  {
    return true;
  }

  uint64_t before = out.size();
  out.append(bytes, bytesSize);
  return (out.size() - before) == bytesSize;
}

void AzureHttp::populateTransportFailure(CURLcode rc, const char *errorBuffer, String *transportFailure)
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

bool AzureHttp::send(const char *method, const String& url, const struct curl_slist *headers, const String *body, String& out, long *httpCode, String *transportFailure)
{
  if (ensureGlobalInit() == false)
  {
    return false;
  }

  CURL *curl = curl_easy_init();
  if (curl == nullptr)
  {
    return false;
  }

  out.clear();
  String urlText = {};
  urlText.assign(url);
  char errorBuffer[CURL_ERROR_SIZE];
  errorBuffer[0] = '\0';
  struct WriteState {
    String *out = nullptr;
    bool appendFailed = false;
  } writeState = {.out = &out, .appendFailed = false};

  curl_easy_setopt(curl, CURLOPT_URL, urlText.c_str());
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, connectTimeoutMs);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeoutMs);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
    WriteState *state = reinterpret_cast<WriteState *>(userdata);
    size_t bytesSize = size * nmemb;
    if (AzureHttp::appendResponseBytes(*state->out, reinterpret_cast<uint8_t *>(ptr), bytesSize))
    {
      return bytesSize;
    }

    state->appendFailed = true;
    return 0;
  });
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &writeState);

  String bodyText = {};
  if (body != nullptr && body->size() > 0)
  {
    bodyText.assign(*body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, bodyText.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, long(bodyText.size()));
  }

  CURLcode rc = curl_easy_perform(curl);
  long code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
  if (httpCode)
  {
    *httpCode = code;
  }
  if (writeState.appendFailed && transportFailure != nullptr)
  {
    transportFailure->assign("azure response buffer append failed"_ctv);
    transportFailure->snprintf_add<" (curl rc={itoa})"_ctv>(uint32_t(rc));
  }
  else
  {
    populateTransportFailure(rc, errorBuffer, transportFailure);
  }
  curl_easy_cleanup(curl);
  return rc == CURLE_OK;
}

void AzureHttp::MultiRequest::resetResult(void)
{
  response.clear();
  transportFailure.clear();
  httpCode = 0;
  curlCode = CURLE_OK;
  completed = false;
  added = false;
}

void AzureHttp::MultiRequest::clearTransport(void)
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

AzureHttp::MultiRequest::~MultiRequest()
{
  clearTransport();
}

size_t AzureHttp::MultiClient::writeResponse(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  MultiRequest *request = reinterpret_cast<MultiRequest *>(userdata);
  size_t bytesSize = size * nmemb;
  if (AzureHttp::appendResponseBytes(request->response, reinterpret_cast<uint8_t *>(ptr), bytesSize))
  {
    return bytesSize;
  }

  request->transportFailure.assign("azure response buffer append failed"_ctv);
  return 0;
}

void AzureHttp::MultiClient::collectCompleted(void)
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
    if (request->transportFailure.size() == 0)
    {
      populateTransportFailure(request->curlCode, nullptr, &request->transportFailure);
    }
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

bool AzureHttp::MultiClient::init(void)
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

bool AzureHttp::MultiClient::start(MultiRequest& request)
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
  curl_easy_setopt(request.easy, CURLOPT_CUSTOMREQUEST, request.method.c_str());
  curl_easy_setopt(request.easy, CURLOPT_CONNECTTIMEOUT_MS, connectTimeoutMs);
  curl_easy_setopt(request.easy, CURLOPT_TIMEOUT_MS, request.timeoutMs);
  curl_easy_setopt(request.easy, CURLOPT_HTTPHEADER, request.headers);
  curl_easy_setopt(request.easy, CURLOPT_WRITEFUNCTION, &writeResponse);
  curl_easy_setopt(request.easy, CURLOPT_WRITEDATA, &request);
  curl_easy_setopt(request.easy, CURLOPT_PRIVATE, &request);

  if (request.body.size() > 0)
  {
    long bodySize = long(request.body.size());
    request.body.addNullTerminator();
    curl_easy_setopt(request.easy, CURLOPT_POSTFIELDS, request.body.c_str());
    curl_easy_setopt(request.easy, CURLOPT_POSTFIELDSIZE, bodySize);
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

bool AzureHttp::MultiClient::pump(int timeoutMs)
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

AzureHttp::MultiRequest *AzureHttp::MultiClient::popCompleted(void)
{
  if (completed.empty())
  {
    return nullptr;
  }

  MultiRequest *request = completed.back();
  completed.pop_back();
  return request;
}

uint32_t AzureHttp::MultiClient::pendingCount(void) const
{
  return inFlight;
}

AzureHttp::MultiClient::~MultiClient()
{
  if (multi != nullptr)
  {
    curl_multi_cleanup(multi);
    multi = nullptr;
  }
}
