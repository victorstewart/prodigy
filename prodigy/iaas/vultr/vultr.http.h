#pragma once

#include <chrono>

#include <prodigy/host.async.task.h>
#include <prodigy/host.delay.operation.h>
#include <prodigy/host.http.operation.h>

class VultrHttpTransport final
{
public:

  constexpr static size_t maximumResponseBytes = 8 * 1024 * 1024;
  constexpr static std::chrono::milliseconds getTimeout = std::chrono::seconds(15);
  constexpr static std::chrono::milliseconds sendTimeout = std::chrono::seconds(20);
  constexpr static std::chrono::milliseconds createTimeout = std::chrono::seconds(8);

private:

  ProdigyHostHttpSubmission http;
  ProdigyHostDelayOperation::Submission delay;
  MultiCurlClient::TimePoint deadline;
  // Provider-owned runtimeEnvironment outlives each stack-nested transport and awaited operation.
  const String *credential;

public:

  VultrHttpTransport(ProdigyHostHttpSubmission requestedHttp,
                     ProdigyHostDelayOperation::Submission requestedDelay,
                     MultiCurlClient::TimePoint requestedDeadline,
                     const String& requestedCredential)
      : http(requestedHttp),
        delay(requestedDelay),
        deadline(requestedDeadline),
        credential(&requestedCredential)
  {}

  bool available(void) const
  {
    return http.submit != nullptr && http.cancel != nullptr &&
           credential != nullptr && credential->empty() == false;
  }

  MultiCurlClient::Request request(MultiCurlClient::Method method,
                                   const String& url,
                                   const String *body = nullptr,
                                   std::chrono::milliseconds timeout = sendTimeout) const
  {
    MultiCurlClient::Request request = {};
    request.url.assign(url);
    request.method = method;
    request.connectTimeout = std::chrono::seconds(3);
    request.firstByteTimeout = timeout;
    request.idleTimeout = timeout;
    const MultiCurlClient::TimePoint requestDeadline = MultiCurlClient::Clock::now() + timeout;
    request.overallDeadline = deadline < requestDeadline ? deadline : requestDeadline;
    request.responseBytes = maximumResponseBytes;
    request.originPolicy.requiredScheme.assign("https"_ctv);
    request.originPolicy.requiredHost.assign("api.vultr.com"_ctv);
    request.originPolicy.requiredAuthority.assign("api.vultr.com"_ctv);
    request.originPolicy.requiredService.assign("443"_ctv);
    String authorization;
    authorization.snprintf<"Bearer {}"_ctv>(*credential);
    request.headers.push_back({"Authorization"_ctv, std::move(authorization)});
    request.headers.push_back({"Accept"_ctv, "application/json"_ctv});
    if (body)
    {
      request.body.assign(*body);
      request.headers.push_back({"Content-Type"_ctv, "application/json"_ctv});
    }
    return request;
  }

  ProdigyHostTask<MultiCurlClient::Result> send(CoroutineStack *coro,
                                                MultiCurlClient::Request request) const
  {
    MultiCurlClient::Result result = {};
    if (coro == nullptr || available() == false || MultiCurlClient::Clock::now() >= deadline)
    {
      result.status = MultiCurlClient::Status::initializationFailure;
      co_return result;
    }

    ProdigyHostHttpOperation operation(http, *coro);
    if (operation.submit(std::move(request)) == false)
    {
      result.status = MultiCurlClient::Status::initializationFailure;
      co_return result;
    }
    if (operation.mustSuspend())
    {
      co_await ProdigyHostSuspend(*coro);
    }
    if (operation.hasResult())
    {
      co_return operation.takeResult();
    }
    result.status = MultiCurlClient::Status::canceled;
    co_return result;
  }

  ProdigyHostTask<Vector<MultiCurlClient::Result>> sendBatch(
      CoroutineStack *coro,
      Vector<MultiCurlClient::Request> requests) const
  {
    Vector<MultiCurlClient::Result> results;
    if (coro == nullptr || available() == false || MultiCurlClient::Clock::now() >= deadline)
    {
      co_return results;
    }

    ProdigyHostHttpBatchOperation operation(http, *coro);
    if (operation.submit(std::move(requests)) == false)
    {
      co_return results;
    }
    if (operation.mustSuspend())
    {
      co_await ProdigyHostSuspend(*coro);
    }
    (void)operation.takeResults(results);
    co_return results;
  }

  ProdigyHostTask<bool> wait(CoroutineStack *coro, std::chrono::microseconds duration) const
  {
    if (coro == nullptr || delay.queue == nullptr || delay.cancel == nullptr)
    {
      co_return false;
    }
    const MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now();
    if (now >= deadline || deadline - now < duration)
    {
      co_return false;
    }

    ProdigyHostDelayOperation operation(delay, *coro);
    if (operation.scheduleUs(uint64_t(duration.count())) == false)
    {
      co_return false;
    }
    if (operation.mustSuspend())
    {
      co_await ProdigyHostSuspend(*coro);
    }
    co_return operation.takeCompletion();
  }

  static bool succeeded(const MultiCurlClient::Result& result)
  {
    return result.status == MultiCurlClient::Status::success &&
           result.statusCode >= 200 && result.statusCode < 300;
  }
};
