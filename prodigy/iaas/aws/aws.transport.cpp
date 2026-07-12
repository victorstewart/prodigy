#include <prodigy/iaas/aws/aws.http.h>

#include <openssl/crypto.h>

#include <algorithm>
#include <utility>

AwsHttpTransport::AwsHttpTransport(ProdigyHostHttpOperation::Submission requestedHttp,
                                   ProdigyHostDelayOperation::Submission requestedDelay,
                                   MultiCurlClient::TimePoint requestedDeadline)
    : http(requestedHttp),
      delay(requestedDelay),
      operationDeadline(requestedDeadline)
{}

bool AwsHttpTransport::available(void) const
{
  return http.submit != nullptr && http.cancel != nullptr;
}

bool AwsHttpTransport::signedRequest(const AwsHttpRequest::Target& target,
                                     MultiCurlClient::Method method,
                                     const Vector<MultiCurlClient::Header>& headers,
                                     const String *body,
                                     const AwsCredentialMaterial& credential,
                                     MultiCurlClient::Request& request,
                                     String *failure) const
{
  if (failure)
  {
    failure->clear();
  }
  const String empty;
  AwsHttpRequest::Error error = AwsHttpRequest::Error::none;
  const int64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
  if (!AwsHttpRequest::build(target,
                             method,
                             headers,
                             body ? *body : empty,
                             credential,
                             timestamp,
                             operationDeadline,
                             request,
                             &error))
  {
    if (failure)
    {
      if (error == AwsHttpRequest::Error::invalidCredential)
      {
        failure->assign("aws credential invalid"_ctv);
      }
      else
      {
        failure->assign("aws signed request invalid"_ctv);
      }
    }
    return false;
  }
  request.connectTimeout = std::chrono::seconds(10);
  request.firstByteTimeout = std::chrono::seconds(60);
  request.idleTimeout = std::chrono::seconds(60);
  request.responseBytes = maximumResponseBytes;
  return true;
}

static MultiCurlClient::Request awsMetadataRequest(const String& path,
                                                   MultiCurlClient::Method method,
                                                   MultiCurlClient::TimePoint deadline)
{
  MultiCurlClient::Request request;
  request.url.assign("http://169.254.169.254"_ctv);
  request.url.append(path);
  request.resolveHost.assign("169.254.169.254"_ctv);
  request.authority.assign("169.254.169.254"_ctv);
  request.method = method;
  request.httpPolicy = MultiCurlClient::HttpPolicy::requireHttp1;
  request.family = AsyncDnsResolver::Family::ipv4;
  request.requireTls = false;
  request.connectTimeout = std::chrono::seconds(3);
  request.firstByteTimeout = std::chrono::seconds(3);
  request.idleTimeout = std::chrono::seconds(3);
  const MultiCurlClient::TimePoint localDeadline = MultiCurlClient::Clock::now() +
                                                   std::chrono::seconds(3);
  request.overallDeadline = deadline < localDeadline ? deadline : localDeadline;
  request.responseBytes = AwsHttpTransport::maximumMetadataResponseBytes;
  request.originPolicy.requiredScheme.assign("http"_ctv);
  request.originPolicy.requiredHost.assign("169.254.169.254"_ctv);
  request.originPolicy.requiredAuthority.assign("169.254.169.254"_ctv);
  request.originPolicy.requiredService.assign("80"_ctv);
  request.originPolicy.requiredResolveHost.assign("169.254.169.254"_ctv);
  return request;
}

MultiCurlClient::Request AwsHttpTransport::metadataTokenRequest(MultiCurlClient::TimePoint deadline)
{
  MultiCurlClient::Request request = awsMetadataRequest(
      "/latest/api/token"_ctv,
      MultiCurlClient::Method::put,
      deadline);
  request.headers.push_back({"X-aws-ec2-metadata-token-ttl-seconds"_ctv, "21600"_ctv});
  return request;
}

MultiCurlClient::Request AwsHttpTransport::metadataGetRequest(const String& path,
                                                              const String& token,
                                                              MultiCurlClient::TimePoint deadline)
{
  MultiCurlClient::Request request = awsMetadataRequest(path, MultiCurlClient::Method::get, deadline);
  request.headers.push_back({"X-aws-ec2-metadata-token"_ctv, token});
  return request;
}

ProdigyHostTask<MultiCurlClient::Result> AwsHttpTransport::send(
    CoroutineStack *coro,
    MultiCurlClient::Request request) const
{
  MultiCurlClient::Result result;
  if (coro == nullptr || !available() || MultiCurlClient::Clock::now() >= operationDeadline)
  {
    result.status = MultiCurlClient::Status::initializationFailure;
    co_return result;
  }
  if (request.overallDeadline > operationDeadline)
  {
    request.overallDeadline = operationDeadline;
  }

  ProdigyHostHttpOperation operation(http, *coro);
  if (!operation.submit(std::move(request)))
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

ProdigyHostTask<MultiCurlClient::Result> AwsHttpTransport::sendSigned(
    CoroutineStack *coro,
    const AwsHttpRequest::Target& target,
    MultiCurlClient::Method method,
    const Vector<MultiCurlClient::Header>& headers,
    const String *body,
    const AwsCredentialMaterial& credential,
    String *failure) const
{
  MultiCurlClient::Request request;
  if (!signedRequest(target, method, headers, body, credential, request, failure))
  {
    MultiCurlClient::Result result;
    result.status = MultiCurlClient::Status::invalidRequest;
    co_return result;
  }
  co_return co_await send(coro, std::move(request));
}

ProdigyHostTask<bool> AwsHttpTransport::wait(CoroutineStack *coro, uint64_t microseconds) const
{
  if (coro == nullptr || delay.queue == nullptr || delay.cancel == nullptr)
  {
    co_return false;
  }
  const MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now();
  if (now >= operationDeadline || operationDeadline - now < std::chrono::microseconds(microseconds))
  {
    co_return false;
  }
  ProdigyHostDelayOperation operation(delay, *coro);
  if (!operation.scheduleUs(microseconds))
  {
    co_return false;
  }
  if (operation.mustSuspend())
  {
    co_await ProdigyHostSuspend(*coro);
  }
  co_return operation.takeCompletion();
}

bool AwsHttpTransport::succeeded(const MultiCurlClient::Result& result)
{
  return result.status == MultiCurlClient::Status::success &&
         result.statusCode >= 200 && result.statusCode < 300;
}

void AwsHttpTransport::assignTransportFailure(const MultiCurlClient::Result& result, String& failure)
{
  if (!failure.empty())
  {
    return;
  }
  switch (result.status)
  {
    case MultiCurlClient::Status::deadlineExceeded:
      failure.assign("aws request deadline exceeded"_ctv);
      break;
    case MultiCurlClient::Status::responseTooLarge:
      failure.assign("aws response exceeded limit"_ctv);
      break;
    case MultiCurlClient::Status::overloaded:
      failure.assign("aws request transport overloaded"_ctv);
      break;
    case MultiCurlClient::Status::dnsFailure:
      failure.assign("aws request dns failed"_ctv);
      break;
    case MultiCurlClient::Status::canceled:
    case MultiCurlClient::Status::shutdown:
      failure.assign("aws request canceled"_ctv);
      break;
    default:
      failure.assign("aws request transport failed"_ctv);
      break;
  }
}

void AwsHttpTransport::assignHttpFailure(const String& context,
                                         long statusCode,
                                         const String& response,
                                         String& failure)
{
  if (!failure.empty())
  {
    return;
  }
  failure.assign(context);
  String status;
  status.snprintf<" [http={itoa}]"_ctv>(uint32_t(statusCode));
  failure.append(status);
  if (!response.empty())
  {
    failure.append(": "_ctv);
    failure.append(response.substr(0,
                                   std::min<uint64_t>(response.size(), maximumDiagnosticBytes),
                                   Copy::yes));
  }
}

AwsMetadataSession::~AwsMetadataSession()
{
  reset();
}

void AwsMetadataSession::reset(void)
{
  if (!token.isInvariant() && token.data() != nullptr && token.reservedBytes() > 0)
  {
    OPENSSL_cleanse(token.data(), size_t(token.reservedBytes()));
  }
  token.reset();
  expires = MultiCurlClient::TimePoint::min();
}

ProdigyHostTask<bool> AwsMetadataSession::ensureToken(CoroutineStack *coro,
                                                      const AwsHttpTransport& transport,
                                                      String *failure)
{
  if (!token.empty() && MultiCurlClient::Clock::now() < expires)
  {
    co_return true;
  }
  reset();
  MultiCurlClient::Result result = co_await transport.send(
      coro,
      AwsHttpTransport::metadataTokenRequest(MultiCurlClient::TimePoint::max()));
  if (!AwsHttpTransport::succeeded(result) || result.body.empty() ||
      result.body.size() > AwsCredentialMaterial::maximumSessionTokenBytes)
  {
    if (failure)
    {
      AwsHttpTransport::assignTransportFailure(result, *failure);
    }
    co_return false;
  }
  token = std::move(result.body);
  expires = MultiCurlClient::Clock::now() + std::chrono::seconds(21'540);
  co_return true;
}

ProdigyHostTask<MultiCurlClient::Result> AwsMetadataSession::get(
    CoroutineStack *coro,
    const AwsHttpTransport& transport,
    const String& path,
    String *failure)
{
  MultiCurlClient::Result result;
  for (uint32_t attempt = 0; attempt < 2; ++attempt)
  {
    if (!co_await ensureToken(coro, transport, failure))
    {
      result.status = MultiCurlClient::Status::transportFailure;
      co_return result;
    }
    result = co_await transport.send(
        coro,
        AwsHttpTransport::metadataGetRequest(path, token, MultiCurlClient::TimePoint::max()));
    if (AwsHttpTransport::succeeded(result))
    {
      co_return result;
    }
    if (result.statusCode != 401 && result.statusCode != 403)
    {
      if (failure)
      {
        AwsHttpTransport::assignTransportFailure(result, *failure);
      }
      co_return result;
    }
    reset();
  }
  if (failure)
  {
    failure->assign("aws metadata authorization failed"_ctv);
  }
  co_return result;
}
