#pragma once

#include <prodigy/host.delay.operation.h>
#include <prodigy/host.http.operation.h>
#include <prodigy/json.h>

class GcpComputeTransaction
{
public:

  enum class OperationState : uint8_t
  {
    pending,
    done,
    failed,
    invalid
  };

  constexpr static uint32_t maximumPages = 256;
  constexpr static uint32_t maximumInstances = 128'000;
  constexpr static uint32_t maximumObservations = 240;
  constexpr static uint32_t maximumPageTokenBytes = 2048;
  constexpr static uint64_t pollDelayUs = 500 * 1000;
  constexpr static size_t responseBytes = 1024 * 1024;
  constexpr static uint64_t notFound = UINT64_MAX;

private:

  ProdigyHostHttpOperation::Submission http;
  ProdigyHostDelayOperation::Submission delay;
  String project;
  String zone;
  String token;
  MultiCurlClient::TimePoint deadline;

public:

  GcpComputeTransaction(ProdigyHostHttpOperation::Submission http,
                        ProdigyHostDelayOperation::Submission delay,
                        String project,
                        String zone,
                        String token,
                        MultiCurlClient::TimePoint deadline)
      : http(http),
        delay(delay),
        deadline(deadline)
  {
    this->project.assign(project);
    this->zone.assign(zone);
    this->token.assign(token);
  }

  bool runtimeAvailable(void) const
  {
    return http.submit != nullptr && http.cancel != nullptr && delay.queue != nullptr &&
           delay.cancel != nullptr;
  }

  bool identityAvailable(void) const
  {
    return project.empty() == false && zone.empty() == false && token.empty() == false;
  }

  bool expired(void) const
  {
    return MultiCurlClient::Clock::now() >= deadline;
  }

  bool canWait(void) const
  {
    const MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now();
    return now < deadline && deadline - now >= std::chrono::microseconds(pollDelayUs);
  }

  static const String& view(const String& value)
  {
    return value;
  }

  template <StringType Text>
  static bool startsWith(const String& value, const Text& prefix)
  {
    return prefix.size() <= value.size() &&
           (prefix.size() == 0 || memcmp(value.data(), prefix.data(), prefix.size()) == 0);
  }

  template <StringType Text>
  static uint64_t find(const String& value, const Text& needle, uint64_t offset = 0)
  {
    if (offset > value.size() || needle.size() > value.size() - offset)
    {
      return notFound;
    }
    if (needle.size() == 0)
    {
      return offset;
    }
    const uint64_t terminal = value.size() - needle.size();
    for (uint64_t index = offset; index <= terminal; ++index)
    {
      if (memcmp(value.data() + index, needle.data(), needle.size()) == 0)
      {
        return index;
      }
    }
    return notFound;
  }

  static uint64_t find(const String& value, uint8_t byte, uint64_t offset = 0)
  {
    if (offset >= value.size())
    {
      return notFound;
    }
    const void *match = memchr(value.data() + offset, byte, value.size() - offset);
    return match == nullptr ? notFound : uint64_t(static_cast<const uint8_t *>(match) - value.data());
  }

  static String slice(const String& value, uint64_t offset, uint64_t size = UINT64_MAX)
  {
    if (offset >= value.size())
    {
      return {};
    }
    const uint64_t available = value.size() - offset;
    const uint64_t length = size < available ? size : available;
    return value.substr(offset, length);
  }

  static bool validDecimalID(const String& value)
  {
    if (value.empty() || value.size() > 20)
    {
      return false;
    }
    for (uint64_t index = 0; index < value.size(); ++index)
    {
      if (value[index] < '0' || value[index] > '9')
      {
        return false;
      }
    }
    return value.size() < 20 || memcmp(value.data(), "18446744073709551615", 20) <= 0;
  }

  static void appendPercentEncoded(String& output, const String& value)
  {
    constexpr static char hex[] = "0123456789ABCDEF";
    for (uint64_t index = 0; index < value.size(); ++index)
    {
      const uint8_t byte = value[index];
      const bool unreserved = (byte >= 'A' && byte <= 'Z') ||
                              (byte >= 'a' && byte <= 'z') ||
                              (byte >= '0' && byte <= '9') ||
                              byte == '-' || byte == '_' || byte == '.' || byte == '~';
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

  static bool parseApiFailure(const String& response, String& failure)
  {
    simdjson::dom::parser parser;
    simdjson::dom::element document;
    String text = response;
    if (parser.parse(text.c_str(), text.size()).get(document))
    {
      return false;
    }
    simdjson::dom::element error;
    String message;
    if (document["error"].get(error) == simdjson::SUCCESS && error.is_object() &&
        prodigyJSONString(error["message"], message) == simdjson::SUCCESS && message.empty() == false)
    {
      failure.assign(message);
      return true;
    }
    return false;
  }

  static void assignRequestFailure(const MultiCurlClient::Result& result,
                                   const String& operation,
                                   String& failure)
  {
    if (parseApiFailure(result.body, failure))
    {
      return;
    }
    if (result.status == MultiCurlClient::Status::deadlineExceeded)
    {
      failure.assign("gcp compute transaction deadline exceeded"_ctv);
    }
    else if (result.status == MultiCurlClient::Status::responseTooLarge)
    {
      failure.assign("gcp compute transaction response exceeds 1 MiB"_ctv);
    }
    else if (result.status == MultiCurlClient::Status::success)
    {
      failure.snprintf<"{} failed with HTTP {itoa}"_ctv>(operation, uint32_t(result.statusCode));
    }
    else
    {
      failure.assign(operation);
      failure.append(" transport failed"_ctv);
    }
  }

  static bool mutationMayBeAccepted(const MultiCurlClient::Result& result)
  {
    if (result.statusCode >= 200 && result.statusCode < 300)
    {
      return true;
    }
    if (result.statusCode >= 300 || result.status == MultiCurlClient::Status::success ||
        result.status == MultiCurlClient::Status::invalidRequest ||
        result.status == MultiCurlClient::Status::unsupportedProtocol ||
        result.status == MultiCurlClient::Status::overloaded ||
        result.status == MultiCurlClient::Status::dnsFailure ||
        result.status == MultiCurlClient::Status::addressRejected ||
        result.status == MultiCurlClient::Status::initializationFailure ||
        result.status == MultiCurlClient::Status::requestTooLarge ||
        result.status == MultiCurlClient::Status::headersTooLarge)
    {
      return false;
    }
    return true;
  }

  static void appendPartial(const String& name, String& failure)
  {
    failure.append("; gcp compute cloud state may be partial for: "_ctv);
    failure.append(name);
  }

  static bool parseOperationName(const String& response, String& name, String& failure)
  {
    simdjson::dom::parser parser;
    simdjson::dom::element document;
    String parsed;
    String text = response;
    if (parser.parse(text.c_str(), text.size()).get(document))
    {
      failure.assign("gcp compute operation response parse failed"_ctv);
      return false;
    }
    if (prodigyJSONString(document["name"], parsed) != simdjson::SUCCESS || parsed.empty())
    {
      failure.assign("gcp compute operation response missing name"_ctv);
      return false;
    }
    name.assign(parsed);
    return true;
  }

  static OperationState parseOperation(const String& response, String& failure)
  {
    simdjson::dom::parser parser;
    simdjson::dom::element operation;
    String status;
    String text = response;
    if (parser.parse(text.c_str(), text.size()).get(operation) || operation.is_object() == false)
    {
      failure.assign("gcp compute operation poll response parse failed"_ctv);
      return OperationState::invalid;
    }
    if (prodigyJSONString(operation["status"], status) != simdjson::SUCCESS)
    {
      failure.assign("gcp compute operation poll response missing status"_ctv);
      return OperationState::invalid;
    }
    if (status == "PENDING"_ctv || status == "RUNNING"_ctv)
    {
      return OperationState::pending;
    }
    if (status != "DONE"_ctv)
    {
      failure.assign("gcp compute operation poll response has invalid status"_ctv);
      return OperationState::invalid;
    }

    simdjson::dom::element nestedError;
    const simdjson::error_code nestedErrorCode = operation["error"].get(nestedError);
    if (nestedErrorCode != simdjson::SUCCESS && nestedErrorCode != simdjson::NO_SUCH_FIELD)
    {
      failure.assign("gcp compute operation error payload malformed"_ctv);
      return OperationState::invalid;
    }
    if (nestedErrorCode == simdjson::SUCCESS)
    {
      if (nestedError.is_object() == false)
      {
        failure.assign("gcp compute operation error payload malformed"_ctv);
        return OperationState::invalid;
      }
      simdjson::dom::element errors;
      if (nestedError["errors"].get(errors) == simdjson::SUCCESS && errors.is_array())
      {
        for (simdjson::dom::element entry : errors.get_array())
        {
          String message;
          if (prodigyJSONString(entry["message"], message) == simdjson::SUCCESS)
          {
            if (message.empty())
            {
              failure.assign("gcp compute operation failed"_ctv);
            }
            else
            {
              failure.assign(message);
            }
            return OperationState::failed;
          }
        }
      }
      failure.assign("gcp compute operation failed"_ctv);
      return OperationState::failed;
    }

    int64_t httpErrorStatusCode = 0;
    const simdjson::error_code statusCodeError =
        operation["httpErrorStatusCode"].get(httpErrorStatusCode);
    if (statusCodeError != simdjson::SUCCESS && statusCodeError != simdjson::NO_SUCH_FIELD)
    {
      failure.assign("gcp compute operation http error status malformed"_ctv);
      return OperationState::invalid;
    }
    String message;
    const simdjson::error_code messageError = prodigyJSONString(operation["httpErrorMessage"], message);
    if (messageError != simdjson::SUCCESS && messageError != simdjson::NO_SUCH_FIELD)
    {
      failure.assign("gcp compute operation http error message malformed"_ctv);
      return OperationState::invalid;
    }
    if (httpErrorStatusCode != 0 || (messageError == simdjson::SUCCESS && message.empty() == false))
    {
      if (message.empty())
      {
        failure.snprintf<"gcp compute operation failed with HTTP {itoa}"_ctv>(uint32_t(httpErrorStatusCode));
      }
      else
      {
        failure.assign(message);
      }
      return OperationState::failed;
    }
    return OperationState::done;
  }

  static MultiCurlClient::Request request(MultiCurlClient::Method method,
                                          String url,
                                          const String *body,
                                          const String& token,
                                          MultiCurlClient::TimePoint deadline,
                                          size_t maximumResponseBytes = responseBytes)
  {
    MultiCurlClient::Request request;
    request.url = std::move(url);
    request.resolveHost.assign("compute.googleapis.com"_ctv);
    request.authority.assign("compute.googleapis.com"_ctv);
    request.method = method;
    request.family = AsyncDnsResolver::Family::ipv4;
    request.caSource = MultiCurlClient::CaSource::system;
    request.connectTimeout = std::chrono::seconds(3);
    const MultiCurlClient::TimePoint requestLimit = MultiCurlClient::Clock::now() +
        (method == MultiCurlClient::Method::get ? std::chrono::seconds(3) : std::chrono::seconds(8));
    request.overallDeadline = deadline < requestLimit ? deadline : requestLimit;
    request.responseBytes = maximumResponseBytes;
    String authorization;
    authorization.snprintf<"Bearer {}"_ctv>(token);
    request.headers.push_back({"Authorization"_ctv, std::move(authorization)});
    if (body)
    {
      request.body = *body;
      request.headers.push_back({"Content-Type"_ctv, "application/json"_ctv});
    }
    request.originPolicy.requiredScheme.assign("https"_ctv);
    request.originPolicy.requiredHost.assign("compute.googleapis.com"_ctv);
    request.originPolicy.requiredAuthority.assign("compute.googleapis.com"_ctv);
    request.originPolicy.requiredService.assign("443"_ctv);
    request.originPolicy.requiredResolveHost.assign("compute.googleapis.com"_ctv);
    return request;
  }

  MultiCurlClient::Request request(MultiCurlClient::Method method,
                                   String url,
                                   const String *body = nullptr) const
  {
    return request(method, std::move(url), body, token, deadline);
  }

  String instancesUrl(const String *name = nullptr) const
  {
    String url;
    url.assign("https://compute.googleapis.com/compute/v1/projects/"_ctv);
    appendPercentEncoded(url, project);
    url.append("/zones/"_ctv);
    appendPercentEncoded(url, zone);
    url.append("/instances"_ctv);
    if (name)
    {
      url.append('/');
      appendPercentEncoded(url, *name);
    }
    return url;
  }

  String instanceUrl(const String& name, const String& fields) const
  {
    String url = instancesUrl(&name);
    if (fields.empty() == false)
    {
      url.append("?fields="_ctv);
      url.append(fields);
    }
    return url;
  }

  String operationUrl(const String& name) const
  {
    String url;
    url.assign("https://compute.googleapis.com/compute/v1/projects/"_ctv);
    appendPercentEncoded(url, project);
    url.append("/zones/"_ctv);
    appendPercentEncoded(url, zone);
    url.append("/operations/"_ctv);
    appendPercentEncoded(url, name);
    url.append("?fields=status,error,httpErrorStatusCode,httpErrorMessage,statusMessage"_ctv);
    return url;
  }

  static void submit(ProdigyHostHttpOperation::Submission http,
                     CoroutineStack *coro,
                     MultiCurlClient::Request request,
                     MultiCurlClient::Result& result,
                     bool& complete)
  {
    complete = false;
    if (coro == nullptr || http.submit == nullptr || http.cancel == nullptr)
    {
      co_return;
    }
    ProdigyHostHttpOperation operation(http, *coro);
    if (operation.submit(std::move(request)) == false)
    {
      co_return;
    }
    if (operation.mustSuspend())
    {
      co_await coro->suspend();
    }
    if (operation.hasResult())
    {
      result = operation.takeResult();
      complete = true;
    }
  }

  void submit(CoroutineStack *coro,
              MultiCurlClient::Request request,
              MultiCurlClient::Result& result,
              bool& complete)
  {
    complete = false;
    if (coro == nullptr)
    {
      co_return;
    }
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          submit(http, coro, std::move(request), result, complete);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }

  static void wait(ProdigyHostDelayOperation::Submission delay,
                   CoroutineStack *coro,
                   uint64_t microseconds,
                   bool& complete)
  {
    complete = false;
    if (coro == nullptr || delay.queue == nullptr || delay.cancel == nullptr)
    {
      co_return;
    }
    ProdigyHostDelayOperation operation(delay, *coro);
    if (operation.scheduleUs(microseconds) == false)
    {
      co_return;
    }
    if (operation.mustSuspend())
    {
      co_await coro->suspend();
    }
    complete = operation.takeCompletion();
  }

  void wait(CoroutineStack *coro, bool& complete)
  {
    complete = false;
    if (coro == nullptr)
    {
      co_return;
    }
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          wait(delay, coro, pollDelayUs, complete);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }

  static bool parseIdentityResult(const String& response,
                                  const String& cloudID,
                                  String& name,
                                  String& failure)
  {
    simdjson::dom::parser parser;
    simdjson::dom::element document;
    String text = response;
    if (parser.parse(text.c_str(), text.size()).get(document) || document.is_object() == false)
    {
      failure.assign("gcp compute instance list response parse failed"_ctv);
      return false;
    }

    name.clear();
    simdjson::dom::element items;
    const simdjson::error_code itemsError = document["items"].get(items);
    if (itemsError != simdjson::SUCCESS && itemsError != simdjson::NO_SUCH_FIELD)
    {
      failure.assign("gcp compute instance list items malformed"_ctv);
      return false;
    }
    if (itemsError == simdjson::SUCCESS)
    {
      if (items.is_array() == false)
      {
        failure.assign("gcp compute instance list items malformed"_ctv);
        return false;
      }
      for (simdjson::dom::element item : items.get_array())
      {
        if (name.empty() == false)
        {
          failure.assign("gcp compute cloud id resolves to multiple instances"_ctv);
          return false;
        }
        String id;
        String parsedName;
        if (prodigyJSONString(item["id"], id) != simdjson::SUCCESS ||
            prodigyJSONString(item["name"], parsedName) != simdjson::SUCCESS ||
            id.empty() || parsedName.empty())
        {
          failure.assign("gcp compute instance identity malformed"_ctv);
          return false;
        }
        if (id != view(cloudID))
        {
          failure.assign("gcp compute id filter returned unexpected instance"_ctv);
          return false;
        }
        name.assign(parsedName);
      }
    }

    String token;
    const simdjson::error_code tokenError = prodigyJSONString(document["nextPageToken"], token);
    if (tokenError != simdjson::SUCCESS && tokenError != simdjson::NO_SUCH_FIELD)
    {
      failure.assign("gcp compute instance list page token malformed"_ctv);
      return false;
    }
    if (tokenError == simdjson::SUCCESS && token.empty() == false)
    {
      failure.assign("gcp compute id filter returned more than one page"_ctv);
      return false;
    }
    return true;
  }

  void resolveName(CoroutineStack *coro,
                   const String& cloudID,
                   String& name,
                   bool& complete,
                   String& failure)
  {
    name.clear();
    complete = false;
    if (validDecimalID(cloudID) == false)
    {
      failure.assign("gcp compute instance id must be a decimal uint64"_ctv);
      co_return;
    }
    if (MultiCurlClient::Clock::now() >= deadline)
    {
      failure.assign("gcp compute transaction deadline exceeded"_ctv);
      co_return;
    }

    String url = instancesUrl();
    url.append("?maxResults=2&filter=id%3D"_ctv);
    url.append(cloudID);
    url.append("&fields=items(id,name),nextPageToken"_ctv);
    MultiCurlClient::Result result;
    bool requestComplete = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          submit(coro, request(MultiCurlClient::Method::get, std::move(url)), result, requestComplete);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (requestComplete == false || result.status != MultiCurlClient::Status::success ||
        result.statusCode < 200 || result.statusCode >= 300)
    {
      assignRequestFailure(result, "gcp compute instance list"_ctv, failure);
      co_return;
    }
    if (parseIdentityResult(result.body, cloudID, name, failure) == false)
    {
      co_return;
    }
    complete = true;
  }

  void fetchInstance(CoroutineStack *coro,
                     const String& name,
                     const String& fields,
                     MultiCurlClient::Result& result,
                     bool& complete,
                     String& failure)
  {
    complete = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          submit(coro, request(MultiCurlClient::Method::get, instanceUrl(name, fields)), result, complete);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (complete == false)
    {
      failure.assign("gcp compute instance request failed"_ctv);
      co_return;
    }
    if (result.status == MultiCurlClient::Status::success && result.statusCode == 404)
    {
      co_return;
    }
    if (result.status != MultiCurlClient::Status::success || result.statusCode < 200 || result.statusCode >= 300)
    {
      assignRequestFailure(result, "gcp compute instance request"_ctv, failure);
      complete = false;
    }
  }

  void observeIdentity(CoroutineStack *coro,
                       const String& name,
                       const String& cloudID,
                       bool& exists,
                       bool& matches,
                       String& failure)
  {
    exists = false;
    matches = false;
    MultiCurlClient::Result result;
    bool complete = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          fetchInstance(coro, name, "id"_ctv, result, complete, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (failure.empty() == false || complete == false || result.statusCode == 404)
    {
      co_return;
    }

    simdjson::dom::parser parser;
    simdjson::dom::element document;
    String id;
    String text = result.body;
    if (parser.parse(text.c_str(), text.size()).get(document) ||
        prodigyJSONString(document["id"], id) != simdjson::SUCCESS || id.empty())
    {
      failure.assign("gcp compute instance identity response malformed"_ctv);
      co_return;
    }
    exists = true;
    matches = id == view(cloudID);
  }

  void pollOperationAtUrl(CoroutineStack *coro,
                          const String& operationUrl,
                          OperationState& state,
                          bool& missing,
                          String& failure)
  {
    String targetUrl;
    targetUrl.assign(operationUrl);
    state = OperationState::invalid;
    missing = false;
    for (uint32_t observation = 0; observation < maximumObservations; ++observation)
    {
      MultiCurlClient::Result result;
      bool complete = false;
      String requestUrl;
      requestUrl.assign(targetUrl);
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            submit(coro, request(MultiCurlClient::Method::get, std::move(requestUrl)), result, complete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (complete == false)
      {
        failure.assign("gcp compute operation observation failed"_ctv);
        co_return;
      }
      if (result.status == MultiCurlClient::Status::success && result.statusCode == 404)
      {
        missing = true;
        co_return;
      }
      if (result.status != MultiCurlClient::Status::success || result.statusCode < 200 || result.statusCode >= 300)
      {
        assignRequestFailure(result, "gcp compute operation observation"_ctv, failure);
        co_return;
      }

      state = parseOperation(result.body, failure);
      if (state != OperationState::pending)
      {
        co_return;
      }
      if (observation + 1 >= maximumObservations || canWait() == false)
      {
        state = OperationState::invalid;
        failure.assign("gcp compute operation deadline exceeded"_ctv);
        co_return;
      }
      bool delayComplete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            wait(coro, delayComplete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (delayComplete == false)
      {
        state = OperationState::invalid;
        failure.assign("gcp compute operation delay failed"_ctv);
        co_return;
      }
    }
  }

  void pollOperation(CoroutineStack *coro,
                     const String& operationName,
                     OperationState& state,
                     bool& missing,
                     String& failure)
  {
    String url = operationUrl(operationName);
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          pollOperationAtUrl(coro, url, state, missing, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }
};
