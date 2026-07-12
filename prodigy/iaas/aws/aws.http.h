#pragma once

#include <prodigy/host.async.task.h>
#include <prodigy/host.delay.operation.h>
#include <prodigy/host.http.operation.h>

#include <networking/multi.curl.client.h>

#include <chrono>
#include <cstdint>

class AwsCredentialMaterial final
{
private:

  String accessKeyIDValue;
  String secretAccessKeyValue;
  String sessionTokenValue;
  int64_t expirationMsValue = 0;

public:

  constexpr static uint64_t maximumAccessKeyIDBytes = 128;
  constexpr static uint64_t maximumSecretAccessKeyBytes = 256;
  constexpr static uint64_t maximumSessionTokenBytes = 4096;

  AwsCredentialMaterial() = default;
  AwsCredentialMaterial(const AwsCredentialMaterial& other);
  AwsCredentialMaterial(AwsCredentialMaterial&& other) noexcept;
  ~AwsCredentialMaterial();

  AwsCredentialMaterial& operator=(const AwsCredentialMaterial& other);
  AwsCredentialMaterial& operator=(AwsCredentialMaterial&& other) noexcept;

  bool valid(void) const;

  bool assign(const uint8_t *accessKeyID,
              uint64_t accessKeyIDSize,
              const uint8_t *secretAccessKey,
              uint64_t secretAccessKeySize,
              const uint8_t *sessionToken,
              uint64_t sessionTokenSize,
              int64_t expirationMs = 0);

  bool assign(const String& accessKeyID,
              const String& secretAccessKey,
              const String& sessionToken = {},
              int64_t expirationMs = 0);

  const String& accessKeyID(void) const;
  const String& secretAccessKey(void) const;
  const String& sessionToken(void) const;
  int64_t expirationMs(void) const;
  void secureReset(void);
  static void secureReset(String& value);
};

class AwsSecretStringScope final
{
private:

  String *value;

public:

  explicit AwsSecretStringScope(String& requested)
      : value(&requested)
  {}

  ~AwsSecretStringScope()
  {
    AwsCredentialMaterial::secureReset(*value);
  }

  AwsSecretStringScope(const AwsSecretStringScope&) = delete;
  AwsSecretStringScope& operator=(const AwsSecretStringScope&) = delete;
};

class AwsHttpRequest final
{
public:

  using Header = MultiCurlClient::Header;
  using Method = MultiCurlClient::Method;
  using Request = MultiCurlClient::Request;
  using TimePoint = MultiCurlClient::TimePoint;

  struct QueryParameter
  {
    String name;
    String value;
  };

  struct Target
  {
    String scheme = "https"_ctv;
    String authority;
    String path = "/"_ctv;
    Vector<QueryParameter> query;
    String region;
    String service;
  };

  enum class Error : uint8_t
  {
    none,
    invalidTarget,
    invalidMethod,
    invalidHeaders,
    invalidCredential,
    invalidTimestamp,
    requestTooLarge,
    allocationFailure,
    signingFailure
  };

  static void secureReset(Request& request);
  static bool idempotencyToken(const Vector<String>& components, String& token);

  static bool build(const Target& target,
                    Method method,
                    const Vector<Header>& headers,
                    const String& body,
                    const AwsCredentialMaterial& credential,
                    int64_t unixTimestampSeconds,
                    TimePoint deadline,
                    Request& output,
                    Error *error = nullptr);
};

class AwsHttpTransport final
{
public:

  constexpr static size_t maximumResponseBytes = 8 * 1024 * 1024;
  constexpr static size_t maximumMetadataResponseBytes = 64 * 1024;
  constexpr static size_t maximumDiagnosticBytes = 512;
  constexpr static uint32_t maximumPages = 256;
  constexpr static uint64_t defaultDelayUs = 500 * 1000;

private:

  ProdigyHostHttpOperation::Submission http;
  ProdigyHostDelayOperation::Submission delay;
  MultiCurlClient::TimePoint operationDeadline;

public:

  AwsHttpTransport(ProdigyHostHttpOperation::Submission requestedHttp,
                   ProdigyHostDelayOperation::Submission requestedDelay,
                   MultiCurlClient::TimePoint requestedDeadline);

  bool available(void) const;

  bool signedRequest(const AwsHttpRequest::Target& target,
                     MultiCurlClient::Method method,
                     const Vector<MultiCurlClient::Header>& headers,
                     const String *body,
                     const AwsCredentialMaterial& credential,
                     MultiCurlClient::Request& request,
                     String *failure = nullptr) const;

  static MultiCurlClient::Request metadataTokenRequest(MultiCurlClient::TimePoint deadline);
  static MultiCurlClient::Request metadataGetRequest(const String& path,
                                                     const String& token,
                                                     MultiCurlClient::TimePoint deadline);

  ProdigyHostTask<MultiCurlClient::Result> send(CoroutineStack *coro,
                                                MultiCurlClient::Request request) const;

  ProdigyHostTask<MultiCurlClient::Result> sendSigned(
      CoroutineStack *coro,
      const AwsHttpRequest::Target& target,
      MultiCurlClient::Method method,
      const Vector<MultiCurlClient::Header>& headers,
      const String *body,
      const AwsCredentialMaterial& credential,
      String *failure = nullptr) const;

  ProdigyHostTask<bool> wait(CoroutineStack *coro,
                             uint64_t microseconds = defaultDelayUs) const;

  static bool succeeded(const MultiCurlClient::Result& result);
  static void assignTransportFailure(const MultiCurlClient::Result& result, String& failure);
  static void assignHttpFailure(const String& context,
                                long statusCode,
                                const String& response,
                                String& failure);
};

class AwsMetadataSession final
{
private:

  String token;
  MultiCurlClient::TimePoint expires = MultiCurlClient::TimePoint::min();

  ProdigyHostTask<bool> ensureToken(CoroutineStack *coro,
                                    const AwsHttpTransport& transport,
                                    String *failure);

public:

  AwsMetadataSession() = default;
  ~AwsMetadataSession();

  AwsMetadataSession(const AwsMetadataSession&) = delete;
  AwsMetadataSession& operator=(const AwsMetadataSession&) = delete;

  void reset(void);

  ProdigyHostTask<MultiCurlClient::Result> get(CoroutineStack *coro,
                                               const AwsHttpTransport& transport,
                                               const String& path,
                                               String *failure = nullptr);
};
