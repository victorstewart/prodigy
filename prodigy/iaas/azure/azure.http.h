#pragma once

#include <chrono>

#include <prodigy/host.async.task.h>
#include <prodigy/host.delay.operation.h>
#include <prodigy/host.http.operation.h>

class AzureHttpTransport final
{
public:

  constexpr static size_t maximumResponseBytes = 8 * 1024 * 1024;
  constexpr static uint32_t maximumPages = 256;
  constexpr static uint32_t maximumRequestsPerWave = 64;
  constexpr static uint64_t defaultDelayUs = 500 * 1000;

private:

  ProdigyHostHttpOperation::Submission http;
  ProdigyHostDelayOperation::Submission delay;
  MultiCurlClient::TimePoint deadline;

public:

  AzureHttpTransport(ProdigyHostHttpOperation::Submission requestedHttp,
                     ProdigyHostDelayOperation::Submission requestedDelay,
                     MultiCurlClient::TimePoint requestedDeadline)
      : http(requestedHttp),
        delay(requestedDelay),
        deadline(requestedDeadline)
  {}

  bool available(void) const
  {
    return http.submit != nullptr && http.cancel != nullptr;
  }

  MultiCurlClient::Request request(MultiCurlClient::Method requestedMethod,
                                   const String& url,
                                   const String& requiredHost,
                                   const String *body = nullptr) const
  {
    MultiCurlClient::Request request = {};
    request.url.assign(url);
    request.method = requestedMethod;
    request.connectTimeout = std::chrono::seconds(10);
    request.firstByteTimeout = std::chrono::seconds(60);
    request.idleTimeout = std::chrono::seconds(60);
    request.overallDeadline = deadline;
    request.responseBytes = maximumResponseBytes;
    request.originPolicy.requiredScheme.assign("https"_ctv);
    request.originPolicy.requiredHost.assign(requiredHost);
    request.originPolicy.requiredAuthority.assign(requiredHost);
    request.originPolicy.requiredService.assign("443"_ctv);
    if (body)
    {
      request.body.assign(*body);
    }
    return request;
  }

  static MultiCurlClient::Request metadataRequest(const String& path,
                                                  MultiCurlClient::TimePoint deadline)
  {
    MultiCurlClient::Request request = {};
    request.url.assign("http://169.254.169.254"_ctv);
    request.url.append(path);
    request.resolveHost.assign("169.254.169.254"_ctv);
    request.authority.assign("169.254.169.254"_ctv);
    request.method = MultiCurlClient::Method::get;
    request.httpPolicy = MultiCurlClient::HttpPolicy::requireHttp1;
    request.family = AsyncDnsResolver::Family::ipv4;
    request.requireTls = false;
    request.connectTimeout = std::chrono::seconds(3);
    request.firstByteTimeout = std::chrono::seconds(3);
    request.idleTimeout = std::chrono::seconds(3);
    const MultiCurlClient::TimePoint requestDeadline = MultiCurlClient::Clock::now() + std::chrono::seconds(3);
    request.overallDeadline = deadline < requestDeadline ? deadline : requestDeadline;
    request.responseBytes = 64 * 1024;
    request.headers.push_back({"Metadata"_ctv, "true"_ctv});
    request.originPolicy.requiredScheme.assign("http"_ctv);
    request.originPolicy.requiredHost.assign("169.254.169.254"_ctv);
    request.originPolicy.requiredAuthority.assign("169.254.169.254"_ctv);
    request.originPolicy.requiredService.assign("80"_ctv);
    request.originPolicy.requiredResolveHost.assign("169.254.169.254"_ctv);
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

  ProdigyHostTask<bool> wait(CoroutineStack *coro, uint64_t microseconds = defaultDelayUs) const
  {
    if (coro == nullptr || delay.queue == nullptr || delay.cancel == nullptr)
    {
      co_return false;
    }
    const MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now();
    if (now >= deadline || deadline - now < std::chrono::microseconds(microseconds))
    {
      co_return false;
    }

    ProdigyHostDelayOperation operation(delay, *coro);
    if (operation.scheduleUs(microseconds) == false)
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

  static void assignTransportFailure(const MultiCurlClient::Result& result, String& failure)
  {
    failure.clear();
    switch (result.status)
    {
      case MultiCurlClient::Status::deadlineExceeded:
        failure.assign("azure request deadline exceeded"_ctv);
        break;
      case MultiCurlClient::Status::responseTooLarge:
        failure.assign("azure response exceeded limit"_ctv);
        break;
      case MultiCurlClient::Status::overloaded:
        failure.assign("azure request transport overloaded"_ctv);
        break;
      case MultiCurlClient::Status::dnsFailure:
        failure.assign("azure request dns failed"_ctv);
        break;
      case MultiCurlClient::Status::canceled:
      case MultiCurlClient::Status::shutdown:
        failure.assign("azure request canceled"_ctv);
        break;
      default:
        failure.assign("azure request transport failed"_ctv);
        break;
    }
  }
};
