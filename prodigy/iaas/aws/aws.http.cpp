#include <prodigy/iaas/aws/aws.http.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <limits>
#include <utility>

void AwsCredentialMaterial::secureReset(String& value)
{
  if (value.data() != nullptr && value.reservedBytes() > 0)
  {
    OPENSSL_cleanse(value.data(), size_t(value.reservedBytes()));
  }
  value.secureReset();
}

AwsCredentialMaterial::AwsCredentialMaterial(const AwsCredentialMaterial& other)
{
  (void)assign(other.accessKeyID(),
               other.secretAccessKey(),
               other.sessionToken(),
               other.expirationMs());
}

AwsCredentialMaterial::AwsCredentialMaterial(AwsCredentialMaterial&& other) noexcept
    : accessKeyIDValue(std::move(other.accessKeyIDValue)),
      secretAccessKeyValue(std::move(other.secretAccessKeyValue)),
      sessionTokenValue(std::move(other.sessionTokenValue)),
      expirationMsValue(other.expirationMsValue)
{
  other.expirationMsValue = 0;
}

AwsCredentialMaterial::~AwsCredentialMaterial()
{
  secureReset();
}

AwsCredentialMaterial& AwsCredentialMaterial::operator=(const AwsCredentialMaterial& other)
{
  if (this != &other)
  {
    (void)assign(other.accessKeyID(),
                 other.secretAccessKey(),
                 other.sessionToken(),
                 other.expirationMs());
  }
  return *this;
}

AwsCredentialMaterial& AwsCredentialMaterial::operator=(AwsCredentialMaterial&& other) noexcept
{
  if (this != &other)
  {
    secureReset();
    accessKeyIDValue = std::move(other.accessKeyIDValue);
    secretAccessKeyValue = std::move(other.secretAccessKeyValue);
    sessionTokenValue = std::move(other.sessionTokenValue);
    expirationMsValue = other.expirationMsValue;
    other.expirationMsValue = 0;
  }
  return *this;
}

bool AwsCredentialMaterial::valid(void) const
{
  return !accessKeyIDValue.empty() && accessKeyIDValue.size() <= maximumAccessKeyIDBytes &&
         !secretAccessKeyValue.empty() && secretAccessKeyValue.size() <= maximumSecretAccessKeyBytes &&
         sessionTokenValue.size() <= maximumSessionTokenBytes;
}

bool AwsCredentialMaterial::assign(const uint8_t *accessKeyID,
                                   uint64_t accessKeyIDSize,
                                   const uint8_t *secretAccessKey,
                                   uint64_t secretAccessKeySize,
                                   const uint8_t *sessionToken,
                                   uint64_t sessionTokenSize,
                                   int64_t expirationMs)
{
  if (accessKeyID == nullptr || secretAccessKey == nullptr ||
      accessKeyIDSize == 0 || accessKeyIDSize > maximumAccessKeyIDBytes ||
      secretAccessKeySize == 0 || secretAccessKeySize > maximumSecretAccessKeyBytes ||
      sessionTokenSize > maximumSessionTokenBytes ||
      (sessionTokenSize > 0 && sessionToken == nullptr))
  {
    return false;
  }

  struct InputCopy
  {
    uint8_t accessKeyID[maximumAccessKeyIDBytes] = {};
    uint8_t secretAccessKey[maximumSecretAccessKeyBytes] = {};
    uint8_t sessionToken[maximumSessionTokenBytes] = {};

    ~InputCopy()
    {
      OPENSSL_cleanse(this, sizeof(*this));
    }
  } input;
  std::memcpy(input.accessKeyID, accessKeyID, size_t(accessKeyIDSize));
  std::memcpy(input.secretAccessKey, secretAccessKey, size_t(secretAccessKeySize));
  if (sessionTokenSize > 0)
  {
    std::memcpy(input.sessionToken, sessionToken, size_t(sessionTokenSize));
  }

  secureReset();
  accessKeyIDValue.assign(input.accessKeyID, accessKeyIDSize);
  secretAccessKeyValue.assign(input.secretAccessKey, secretAccessKeySize);
  sessionTokenValue.assign(input.sessionToken, sessionTokenSize);
  if (accessKeyIDValue.size() != accessKeyIDSize ||
      secretAccessKeyValue.size() != secretAccessKeySize ||
      sessionTokenValue.size() != sessionTokenSize)
  {
    secureReset();
    return false;
  }
  expirationMsValue = expirationMs;
  return true;
}

bool AwsCredentialMaterial::assign(const String& accessKeyID,
                                   const String& secretAccessKey,
                                   const String& sessionToken,
                                   int64_t expirationMs)
{
  return assign(accessKeyID.data(), accessKeyID.size(),
                secretAccessKey.data(), secretAccessKey.size(),
                sessionToken.data(), sessionToken.size(), expirationMs);
}

const String& AwsCredentialMaterial::accessKeyID(void) const
{
  return accessKeyIDValue;
}

const String& AwsCredentialMaterial::secretAccessKey(void) const
{
  return secretAccessKeyValue;
}

const String& AwsCredentialMaterial::sessionToken(void) const
{
  return sessionTokenValue;
}

int64_t AwsCredentialMaterial::expirationMs(void) const
{
  return expirationMsValue;
}

void AwsCredentialMaterial::secureReset(void)
{
  secureReset(accessKeyIDValue);
  secureReset(secretAccessKeyValue);
  secureReset(sessionTokenValue);
  expirationMsValue = 0;
}

class AwsHttpRequestImplementation final
{
public:

  using Header = AwsHttpRequest::Header;
  using Method = AwsHttpRequest::Method;
  using Request = AwsHttpRequest::Request;
  using TimePoint = AwsHttpRequest::TimePoint;
  using QueryParameter = AwsHttpRequest::QueryParameter;
  using Target = AwsHttpRequest::Target;
  using Error = AwsHttpRequest::Error;

private:

  class SecureText final
  {
  private:

    String value;

  public:

    SecureText() = default;
    SecureText(const SecureText&) = delete;
    SecureText& operator=(const SecureText&) = delete;

    SecureText(SecureText&& other) noexcept
        : value(std::move(other.value))
    {}

    SecureText& operator=(SecureText&& other) noexcept
    {
      if (this != &other)
      {
        reset();
        value = std::move(other.value);
      }
      return *this;
    }

    ~SecureText()
    {
      reset();
    }

    bool reserve(uint64_t bytes)
    {
      return bytes == 0 || value.reserve(bytes);
    }

    bool append(const uint8_t *bytes, uint64_t size)
    {
      if (size > value.reservedBytes() - value.size())
      {
        return false;
      }
      const uint64_t before = value.size();
      value.append(bytes, size);
      return value.size() == before + size;
    }

    bool append(const String& text)
    {
      return append(text.data(), text.size());
    }

    bool append(const char *text, uint64_t size)
    {
      return append(reinterpret_cast<const uint8_t *>(text), size);
    }

    bool append(char byte)
    {
      return append(reinterpret_cast<const uint8_t *>(&byte), 1);
    }

    const String& get(void) const
    {
      return value;
    }

    void reset(void)
    {
      if (value.data() != nullptr && value.reservedBytes() > 0)
      {
        OPENSSL_cleanse(value.data(), size_t(value.reservedBytes()));
      }
      value.secureReset();
    }
  };

  struct CanonicalHeader
  {
    String name;
    SecureText value;

    CanonicalHeader() = default;
    CanonicalHeader(CanonicalHeader&&) noexcept = default;
    CanonicalHeader& operator=(CanonicalHeader&&) noexcept = default;
    CanonicalHeader(const CanonicalHeader&) = delete;
    CanonicalHeader& operator=(const CanonicalHeader&) = delete;
  };

  struct CanonicalQuery
  {
    SecureText name;
    SecureText value;

    CanonicalQuery() = default;
    CanonicalQuery(CanonicalQuery&&) noexcept = default;
    CanonicalQuery& operator=(CanonicalQuery&&) noexcept = default;
    CanonicalQuery(const CanonicalQuery&) = delete;
    CanonicalQuery& operator=(const CanonicalQuery&) = delete;
  };

  struct SensitiveState
  {
    uint8_t prefixedSecret[4 + AwsCredentialMaterial::maximumSecretAccessKeyBytes] = {};
    uint8_t dateKey[EVP_MAX_MD_SIZE] = {};
    uint8_t regionKey[EVP_MAX_MD_SIZE] = {};
    uint8_t serviceKey[EVP_MAX_MD_SIZE] = {};
    uint8_t signingKey[EVP_MAX_MD_SIZE] = {};
    uint8_t payloadHash[EVP_MAX_MD_SIZE] = {};
    uint8_t canonicalHash[EVP_MAX_MD_SIZE] = {};
    uint8_t signature[EVP_MAX_MD_SIZE] = {};

    ~SensitiveState()
    {
      OPENSSL_cleanse(this, sizeof(*this));
    }
  };

  struct RequestScrubber
  {
    Request *request = nullptr;

    ~RequestScrubber()
    {
      if (request)
      {
        AwsHttpRequest::secureReset(*request);
      }
    }

    void release(void)
    {
      request = nullptr;
    }
  };

  static bool add(uint64_t& total, uint64_t amount)
  {
    if (amount > std::numeric_limits<uint64_t>::max() - total)
    {
      return false;
    }
    total += amount;
    return true;
  }

  static bool multiply(uint64_t value, uint64_t multiplier, uint64_t& result)
  {
    if (value != 0 && multiplier > std::numeric_limits<uint64_t>::max() / value)
    {
      return false;
    }
    result = value * multiplier;
    return true;
  }

  static bool asciiEqual(const String& left, const char *right)
  {
    uint64_t size = 0;
    while (right[size] != '\0')
    {
      ++size;
    }
    if (left.size() != size)
    {
      return false;
    }
    for (uint64_t index = 0; index < size; ++index)
    {
      uint8_t byte = left[index];
      if (byte >= 'A' && byte <= 'Z')
      {
        byte = uint8_t(byte + ('a' - 'A'));
      }
      if (byte != uint8_t(right[index]))
      {
        return false;
      }
    }
    return true;
  }

  static bool containsCRLF(const String& value)
  {
    for (uint8_t byte : value)
    {
      if (byte == '\r' || byte == '\n')
      {
        return true;
      }
    }
    return false;
  }

  static bool less(const String& left, const String& right)
  {
    const uint64_t shared = std::min(left.size(), right.size());
    const int comparison = shared == 0 ? 0 : std::memcmp(left.data(), right.data(), size_t(shared));
    return comparison < 0 || (comparison == 0 && left.size() < right.size());
  }

  static bool validToken(const String& value)
  {
    if (value.empty())
    {
      return false;
    }
    for (uint8_t byte : value)
    {
      if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
            (byte >= '0' && byte <= '9') || byte == '!' || byte == '#' || byte == '$' ||
            byte == '%' || byte == '&' || byte == '\'' || byte == '*' || byte == '+' ||
            byte == '-' || byte == '.' || byte == '^' || byte == '_' || byte == '`' ||
            byte == '|' || byte == '~'))
      {
        return false;
      }
    }
    return true;
  }

  static bool validHeaderValue(const String& value)
  {
    for (uint8_t byte : value)
    {
      if (byte == '\r' || byte == '\n' || byte == 0 ||
          (byte < 0x20 && byte != '\t') || byte == 0x7f)
      {
        return false;
      }
    }
    return true;
  }

  static bool validAuthority(const String& authority)
  {
    if (authority.empty() || authority.size() > MultiCurlClient::maximumUrlBytes)
    {
      return false;
    }
    for (uint8_t byte : authority)
    {
      if (byte <= 0x20 || byte == 0x7f || byte == '/' || byte == '\\' ||
          byte == '@' || byte == '#' || byte == '?')
      {
        return false;
      }
    }
    return true;
  }

  static bool validScopePart(const String& value)
  {
    if (value.empty() || value.size() > 64 || containsCRLF(value))
    {
      return false;
    }
    for (uint8_t byte : value)
    {
      if (!((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') || byte == '-'))
      {
        return false;
      }
    }
    return true;
  }

  static bool validCredential(const AwsCredentialMaterial& credential)
  {
    if (!credential.valid() || containsCRLF(credential.accessKeyID()) ||
        containsCRLF(credential.secretAccessKey()) || containsCRLF(credential.sessionToken()))
    {
      return false;
    }
    for (uint8_t byte : credential.accessKeyID())
    {
      if (!((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
            (byte >= '0' && byte <= '9')))
      {
        return false;
      }
    }
    for (uint8_t byte : credential.secretAccessKey())
    {
      if (byte < 0x20 || byte == 0x7f)
      {
        return false;
      }
    }
    for (uint8_t byte : credential.sessionToken())
    {
      if (byte < 0x20 || byte == 0x7f)
      {
        return false;
      }
    }
    return true;
  }

  static bool reservedHeader(const String& name)
  {
    return asciiEqual(name, "authorization") || asciiEqual(name, "host") ||
           asciiEqual(name, "x-amz-content-sha256") || asciiEqual(name, "x-amz-date") ||
           asciiEqual(name, "x-amz-security-token") || asciiEqual(name, "connection") ||
           asciiEqual(name, "content-length") || asciiEqual(name, "proxy-authorization") ||
           asciiEqual(name, "proxy-connection") || asciiEqual(name, "te") ||
           asciiEqual(name, "transfer-encoding") || asciiEqual(name, "upgrade");
  }

  static bool normalizeHeaderValue(const String& input, SecureText& output)
  {
    uint64_t first = 0;
    while (first < input.size() && (input[first] == ' ' || input[first] == '\t'))
    {
      ++first;
    }
    uint64_t last = input.size();
    while (last > first && (input[last - 1] == ' ' || input[last - 1] == '\t'))
    {
      --last;
    }

    uint64_t normalizedSize = 0;
    bool whitespace = false;
    for (uint64_t index = first; index < last; ++index)
    {
      if (input[index] == ' ' || input[index] == '\t')
      {
        whitespace = normalizedSize > 0;
      }
      else
      {
        if (whitespace && !add(normalizedSize, 1))
        {
          return false;
        }
        whitespace = false;
        if (!add(normalizedSize, 1))
        {
          return false;
        }
      }
    }
    if (!output.reserve(normalizedSize))
    {
      return false;
    }

    whitespace = false;
    for (uint64_t index = first; index < last; ++index)
    {
      const char byte = char(input[index]);
      if (byte == ' ' || byte == '\t')
      {
        whitespace = output.get().size() > 0;
      }
      else
      {
        if (whitespace && !output.append(' '))
        {
          return false;
        }
        whitespace = false;
        if (!output.append(byte))
        {
          return false;
        }
      }
    }
    return output.get().size() == normalizedSize;
  }

  static bool lowercase(const String& input, String& output)
  {
    if (!output.reserve(input.size()))
    {
      return false;
    }
    for (uint8_t byte : input)
    {
      if (byte >= 'A' && byte <= 'Z')
      {
        byte = uint8_t(byte + ('a' - 'A'));
      }
      output.append(byte);
    }
    return output.size() == input.size();
  }

  static bool percentEncode(const String& input, bool preserveSlash, SecureText& output)
  {
    uint64_t capacity = 0;
    if (!multiply(input.size(), 3, capacity) || !output.reserve(capacity))
    {
      return false;
    }
    constexpr static char hex[] = "0123456789ABCDEF";
    for (uint8_t byte : input)
    {
      const bool unreserved = (byte >= 'A' && byte <= 'Z') ||
                              (byte >= 'a' && byte <= 'z') ||
                              (byte >= '0' && byte <= '9') || byte == '-' ||
                              byte == '_' || byte == '.' || byte == '~' ||
                              (preserveSlash && byte == '/');
      if (unreserved)
      {
        if (!output.append(char(byte)))
        {
          return false;
        }
      }
      else if (!output.append('%') || !output.append(hex[byte >> 4]) ||
               !output.append(hex[byte & 0x0f]))
      {
        return false;
      }
    }
    return true;
  }

  static bool sha256(const uint8_t *data, uint64_t size, uint8_t digest[EVP_MAX_MD_SIZE])
  {
    static constexpr uint8_t empty = 0;
    const uint8_t *source = size > 0 ? data : &empty;
    unsigned int digestSize = 0;
    return size <= std::numeric_limits<size_t>::max() &&
           EVP_Digest(source, size_t(size), digest, &digestSize, EVP_sha256(), nullptr) == 1 &&
           digestSize == 32;
  }

  static bool hmac(const uint8_t *key,
                   uint64_t keySize,
                   const uint8_t *data,
                   uint64_t size,
                   uint8_t digest[EVP_MAX_MD_SIZE])
  {
    static constexpr uint8_t empty = 0;
    const uint8_t *source = size > 0 ? data : &empty;
    unsigned int digestSize = 0;
    return keySize <= uint64_t(std::numeric_limits<int>::max()) &&
           size <= std::numeric_limits<size_t>::max() &&
           HMAC(EVP_sha256(), key, int(keySize), source, size_t(size), digest, &digestSize) != nullptr &&
           digestSize == 32;
  }

  static bool appendHex(SecureText& output, const uint8_t *bytes, uint64_t size)
  {
    uint64_t outputSize = 0;
    if (!multiply(size, 2, outputSize) || !output.reserve(outputSize))
    {
      return false;
    }
    constexpr static char hex[] = "0123456789abcdef";
    for (uint64_t index = 0; index < size; ++index)
    {
      if (!output.append(hex[bytes[index] >> 4]) || !output.append(hex[bytes[index] & 0x0f]))
      {
        return false;
      }
    }
    return true;
  }

  static const char *methodName(Method method)
  {
    switch (method)
    {
      case Method::get:
        return "GET";
      case Method::head:
        return "HEAD";
      case Method::post:
        return "POST";
      case Method::put:
        return "PUT";
      case Method::patch:
        return "PATCH";
      case Method::delete_:
        return "DELETE";
    }
    return nullptr;
  }

  static bool assign(String& output, const String& input)
  {
    output.assign(input);
    return output.size() == input.size();
  }

  static bool appendHeader(Request& request, const String& name, const String& value)
  {
    request.headers.emplace_back();
    Header& header = request.headers.back();
    return assign(header.name, name) && assign(header.value, value);
  }

  static bool appendHeader(Request& request, const char *name, uint64_t nameSize, const String& value)
  {
    String nameText;
    nameText.append(reinterpret_cast<const uint8_t *>(name), nameSize);
    return nameText.size() == nameSize && appendHeader(request, nameText, value);
  }

  static void setError(Error *error, Error value)
  {
    if (error)
    {
      *error = value;
    }
  }

  static void secureResetString(String& value)
  {
    if (value.isInvariant())
    {
      value.reset();
    }
    else
    {
      if (value.data() != nullptr && value.reservedBytes() > 0)
      {
        OPENSSL_cleanse(value.data(), size_t(value.reservedBytes()));
      }
      value.secureReset();
    }
  }

public:

  static void secureReset(Request& request)
  {
    secureResetString(request.url);
    secureResetString(request.resolveHost);
    secureResetString(request.authority);
    secureResetString(request.body);
    for (Header& header : request.headers)
    {
      secureResetString(header.name);
      secureResetString(header.value);
    }
    request.headers.clear();
    secureResetString(request.originPolicy.requiredScheme);
    secureResetString(request.originPolicy.requiredHost);
    secureResetString(request.originPolicy.requiredAuthority);
    secureResetString(request.originPolicy.requiredService);
    secureResetString(request.originPolicy.requiredResolveHost);
    secureResetString(request.caFile);
    secureResetString(request.caPath);
    secureResetString(request.caBlob);
    secureResetString(request.clientCertificateFile);
    secureResetString(request.clientKeyFile);
    secureResetString(request.clientCertificateBlob);
    secureResetString(request.clientKeyBlob);
    request = {};
  }

  static bool build(const Target& target,
                    Method method,
                    const Vector<Header>& headers,
                    const String& body,
                    const AwsCredentialMaterial& credential,
                    int64_t unixTimestampSeconds,
                    TimePoint deadline,
                    Request& output,
                    Error *error = nullptr)
  {
    setError(error, Error::none);
    secureReset(output);

    const char *verb = methodName(method);
    if (verb == nullptr || ((!body.empty()) && (method == Method::get || method == Method::head)))
    {
      setError(error, Error::invalidMethod);
      return false;
    }
    if (!asciiEqual(target.scheme, "https") || !validAuthority(target.authority) ||
        !validScopePart(target.region) || !validScopePart(target.service) ||
        target.path.empty() || target.path[0] != '/' || containsCRLF(target.path))
    {
      setError(error, Error::invalidTarget);
      return false;
    }
    for (uint8_t byte : target.path)
    {
      if (byte == 0 || byte == '?' || byte == '#')
      {
        setError(error, Error::invalidTarget);
        return false;
      }
    }
    if (!validCredential(credential))
    {
      setError(error, Error::invalidCredential);
      return false;
    }
    if (body.size() > MultiCurlClient::maximumRequestBytes)
    {
      setError(error, Error::requestTooLarge);
      return false;
    }

    const uint64_t generatedHeaders = credential.sessionToken().empty() ? 3 : 4;
    if (headers.size() > MultiCurlClient::maximumRequestHeaders - generatedHeaders - 1)
    {
      setError(error, Error::invalidHeaders);
      return false;
    }

    Vector<CanonicalHeader> canonicalHeaders;
    canonicalHeaders.reserve(headers.size() + generatedHeaders);
    uint64_t headerBytes = 0;
    for (const Header& header : headers)
    {
      if (!validToken(header.name) || reservedHeader(header.name) || !validHeaderValue(header.value) ||
          header.name.size() + header.value.size() + 2 > MultiCurlClient::maximumHeaderLineBytes)
      {
        setError(error, Error::invalidHeaders);
        return false;
      }
      canonicalHeaders.emplace_back();
      CanonicalHeader& normalized = canonicalHeaders.back();
      if (!lowercase(header.name, normalized.name) ||
          !normalizeHeaderValue(header.value, normalized.value) ||
          !add(headerBytes, normalized.name.size() + normalized.value.get().size() + 2))
      {
        setError(error, Error::allocationFailure);
        return false;
      }
    }

    std::sort(canonicalHeaders.begin(), canonicalHeaders.end(),
              [](const CanonicalHeader& left, const CanonicalHeader& right) {
                return less(left.name, right.name);
              });
    for (uint64_t index = 1; index < canonicalHeaders.size(); ++index)
    {
      if (canonicalHeaders[index - 1].name == canonicalHeaders[index].name)
      {
        setError(error, Error::invalidHeaders);
        return false;
      }
    }

    struct tm timestamp = {};
    const time_t rawTimestamp = time_t(unixTimestampSeconds);
    if (int64_t(rawTimestamp) != unixTimestampSeconds || gmtime_r(&rawTimestamp, &timestamp) == nullptr ||
        timestamp.tm_year + 1900 < 1970 || timestamp.tm_year + 1900 > 9999)
    {
      setError(error, Error::invalidTimestamp);
      return false;
    }
    char amzDateBytes[17] = {};
    char shortDateBytes[9] = {};
    if (std::snprintf(amzDateBytes, sizeof(amzDateBytes), "%04d%02d%02dT%02d%02d%02dZ",
                      timestamp.tm_year + 1900, timestamp.tm_mon + 1, timestamp.tm_mday,
                      timestamp.tm_hour, timestamp.tm_min, timestamp.tm_sec) != 16 ||
        std::snprintf(shortDateBytes, sizeof(shortDateBytes), "%04d%02d%02d",
                      timestamp.tm_year + 1900, timestamp.tm_mon + 1, timestamp.tm_mday) != 8)
    {
      setError(error, Error::invalidTimestamp);
      return false;
    }

    SensitiveState sensitive;
    SecureText payloadHex;
    if (!sha256(body.data(), body.size(), sensitive.payloadHash) ||
        !appendHex(payloadHex, sensitive.payloadHash, 32))
    {
      setError(error, Error::signingFailure);
      return false;
    }

    auto addGeneratedHeader = [&](const char *name, uint64_t nameSize, const String& value) -> bool {
      canonicalHeaders.emplace_back();
      CanonicalHeader& header = canonicalHeaders.back();
      header.name.append(reinterpret_cast<const uint8_t *>(name), nameSize);
      return header.name.size() == nameSize && header.value.reserve(value.size()) &&
             header.value.append(value) && add(headerBytes, nameSize + value.size() + 2);
    };

    String authority;
    if (!lowercase(target.authority, authority))
    {
      setError(error, Error::allocationFailure);
      return false;
    }
    String amzDate;
    amzDate.append(reinterpret_cast<const uint8_t *>(amzDateBytes), 16);
    if (amzDate.size() != 16 ||
        !addGeneratedHeader("host", 4, authority) ||
        !addGeneratedHeader("x-amz-content-sha256", 20, payloadHex.get()) ||
        !addGeneratedHeader("x-amz-date", 10, amzDate) ||
        (!credential.sessionToken().empty() &&
         !addGeneratedHeader("x-amz-security-token", 20, credential.sessionToken())))
    {
      setError(error, Error::allocationFailure);
      return false;
    }
    std::sort(canonicalHeaders.begin(), canonicalHeaders.end(),
              [](const CanonicalHeader& left, const CanonicalHeader& right) {
                return less(left.name, right.name);
              });

    SecureText canonicalUri;
    if (!percentEncode(target.path, true, canonicalUri))
    {
      setError(error, Error::allocationFailure);
      return false;
    }

    Vector<CanonicalQuery> query;
    query.reserve(target.query.size());
    for (const QueryParameter& parameter : target.query)
    {
      if (containsCRLF(parameter.name) || containsCRLF(parameter.value))
      {
        setError(error, Error::invalidTarget);
        return false;
      }
      query.emplace_back();
      if (!percentEncode(parameter.name, false, query.back().name) ||
          !percentEncode(parameter.value, false, query.back().value))
      {
        setError(error, Error::allocationFailure);
        return false;
      }
    }
    std::sort(query.begin(), query.end(), [](const CanonicalQuery& left, const CanonicalQuery& right) {
      if (left.name.get() == right.name.get())
      {
        return less(left.value.get(), right.value.get());
      }
      return less(left.name.get(), right.name.get());
    });

    uint64_t querySize = query.empty() ? 0 : query.size() - 1;
    for (const CanonicalQuery& parameter : query)
    {
      if (!add(querySize, parameter.name.get().size()) || !add(querySize, 1) ||
          !add(querySize, parameter.value.get().size()))
      {
        setError(error, Error::requestTooLarge);
        return false;
      }
    }
    SecureText canonicalQuery;
    if (!canonicalQuery.reserve(querySize))
    {
      setError(error, Error::allocationFailure);
      return false;
    }
    for (uint64_t index = 0; index < query.size(); ++index)
    {
      if ((index > 0 && !canonicalQuery.append('&')) ||
          !canonicalQuery.append(query[index].name.get()) || !canonicalQuery.append('=') ||
          !canonicalQuery.append(query[index].value.get()))
      {
        setError(error, Error::allocationFailure);
        return false;
      }
    }

    uint64_t canonicalHeaderSize = 0;
    uint64_t signedHeaderSize = canonicalHeaders.empty() ? 0 : canonicalHeaders.size() - 1;
    for (const CanonicalHeader& header : canonicalHeaders)
    {
      if (!add(canonicalHeaderSize, header.name.size()) || !add(canonicalHeaderSize, 1) ||
          !add(canonicalHeaderSize, header.value.get().size()) || !add(canonicalHeaderSize, 1) ||
          !add(signedHeaderSize, header.name.size()))
      {
        setError(error, Error::requestTooLarge);
        return false;
      }
    }
    SecureText canonicalHeaderText;
    SecureText signedHeaderText;
    if (!canonicalHeaderText.reserve(canonicalHeaderSize) ||
        !signedHeaderText.reserve(signedHeaderSize))
    {
      setError(error, Error::allocationFailure);
      return false;
    }
    for (uint64_t index = 0; index < canonicalHeaders.size(); ++index)
    {
      const CanonicalHeader& header = canonicalHeaders[index];
      if (!canonicalHeaderText.append(header.name) || !canonicalHeaderText.append(':') ||
          !canonicalHeaderText.append(header.value.get()) || !canonicalHeaderText.append('\n') ||
          (index > 0 && !signedHeaderText.append(';')) || !signedHeaderText.append(header.name))
      {
        setError(error, Error::allocationFailure);
        return false;
      }
    }

    const uint64_t verbSize = std::strlen(verb);
    uint64_t canonicalRequestSize = verbSize + 1;
    if (!add(canonicalRequestSize, canonicalUri.get().size() + 1) ||
        !add(canonicalRequestSize, canonicalQuery.get().size() + 1) ||
        !add(canonicalRequestSize, canonicalHeaderText.get().size() + 1) ||
        !add(canonicalRequestSize, signedHeaderText.get().size() + 1) ||
        !add(canonicalRequestSize, payloadHex.get().size()))
    {
      setError(error, Error::requestTooLarge);
      return false;
    }
    SecureText canonicalRequest;
    if (!canonicalRequest.reserve(canonicalRequestSize) ||
        !canonicalRequest.append(verb, verbSize) || !canonicalRequest.append('\n') ||
        !canonicalRequest.append(canonicalUri.get()) || !canonicalRequest.append('\n') ||
        !canonicalRequest.append(canonicalQuery.get()) || !canonicalRequest.append('\n') ||
        !canonicalRequest.append(canonicalHeaderText.get()) || !canonicalRequest.append('\n') ||
        !canonicalRequest.append(signedHeaderText.get()) || !canonicalRequest.append('\n') ||
        !canonicalRequest.append(payloadHex.get()) ||
        !sha256(canonicalRequest.get().data(), canonicalRequest.get().size(), sensitive.canonicalHash))
    {
      setError(error, Error::signingFailure);
      return false;
    }

    SecureText canonicalHashHex;
    if (!appendHex(canonicalHashHex, sensitive.canonicalHash, 32))
    {
      setError(error, Error::allocationFailure);
      return false;
    }

    uint64_t scopeSize = 8 + 1 + target.region.size() + 1 + target.service.size() + 13;
    SecureText scope;
    if (!scope.reserve(scopeSize) || !scope.append(shortDateBytes, 8) || !scope.append('/') ||
        !scope.append(target.region) || !scope.append('/') || !scope.append(target.service) ||
        !scope.append("/aws4_request", 13))
    {
      setError(error, Error::allocationFailure);
      return false;
    }

    const uint64_t stringToSignSize = 17 + 16 + 1 + scope.get().size() + 1 + 64;
    SecureText stringToSign;
    if (!stringToSign.reserve(stringToSignSize) ||
        !stringToSign.append("AWS4-HMAC-SHA256\n", 17) ||
        !stringToSign.append(amzDateBytes, 16) || !stringToSign.append('\n') ||
        !stringToSign.append(scope.get()) || !stringToSign.append('\n') ||
        !stringToSign.append(canonicalHashHex.get()))
    {
      setError(error, Error::allocationFailure);
      return false;
    }

    const uint64_t prefixedSecretSize = 4 + credential.secretAccessKey().size();
    std::memcpy(sensitive.prefixedSecret, "AWS4", 4);
    std::memcpy(sensitive.prefixedSecret + 4,
                credential.secretAccessKey().data(),
                size_t(credential.secretAccessKey().size()));
    if (!hmac(sensitive.prefixedSecret, prefixedSecretSize,
              reinterpret_cast<const uint8_t *>(shortDateBytes), 8, sensitive.dateKey) ||
        !hmac(sensitive.dateKey, 32, target.region.data(), target.region.size(), sensitive.regionKey) ||
        !hmac(sensitive.regionKey, 32, target.service.data(), target.service.size(), sensitive.serviceKey) ||
        !hmac(sensitive.serviceKey, 32,
              reinterpret_cast<const uint8_t *>("aws4_request"), 12, sensitive.signingKey) ||
        !hmac(sensitive.signingKey, 32, stringToSign.get().data(), stringToSign.get().size(), sensitive.signature))
    {
      setError(error, Error::signingFailure);
      return false;
    }

    SecureText signatureHex;
    if (!appendHex(signatureHex, sensitive.signature, 32))
    {
      setError(error, Error::allocationFailure);
      return false;
    }

    uint64_t authorizationSize = 28;
    if (!add(authorizationSize, credential.accessKeyID().size()) || !add(authorizationSize, 1) ||
        !add(authorizationSize, scope.get().size()) || !add(authorizationSize, 16) ||
        !add(authorizationSize, signedHeaderText.get().size()) || !add(authorizationSize, 12) ||
        !add(authorizationSize, signatureHex.get().size()))
    {
      setError(error, Error::requestTooLarge);
      return false;
    }
    SecureText authorization;
    if (!authorization.reserve(authorizationSize) ||
        !authorization.append("AWS4-HMAC-SHA256 Credential=", 28) ||
        !authorization.append(credential.accessKeyID()) || !authorization.append('/') ||
        !authorization.append(scope.get()) || !authorization.append(", SignedHeaders=", 16) ||
        !authorization.append(signedHeaderText.get()) || !authorization.append(", Signature=", 12) ||
        !authorization.append(signatureHex.get()))
    {
      setError(error, Error::allocationFailure);
      return false;
    }
    if (!add(headerBytes, 13 + authorization.get().size() + 2) ||
        headerBytes > MultiCurlClient::maximumHeaderBytes)
    {
      setError(error, Error::invalidHeaders);
      return false;
    }

    uint64_t urlSize = target.scheme.size() + 3 + authority.size() + canonicalUri.get().size();
    if (!query.empty() && !add(urlSize, 1 + canonicalQuery.get().size()))
    {
      setError(error, Error::requestTooLarge);
      return false;
    }
    if (urlSize > MultiCurlClient::maximumUrlBytes)
    {
      setError(error, Error::requestTooLarge);
      return false;
    }

    Request built;
    RequestScrubber scrubber {&built};
    built.method = method;
    built.httpPolicy = MultiCurlClient::HttpPolicy::preferHttp2;
    built.tlsMinimum = MultiCurlClient::TlsMinimum::tls12;
    built.overallDeadline = deadline;
    built.requireTls = true;
    built.pathAsIs = true;
    built.headers.reserve(headers.size() + generatedHeaders);
    if (!assign(built.authority, authority) || !assign(built.body, body))
    {
      setError(error, Error::allocationFailure);
      return false;
    }
    built.originPolicy.requiredScheme.assign("https"_ctv);
    built.originPolicy.requiredHost.assign(authority);
    built.originPolicy.requiredAuthority.assign(authority);
    built.originPolicy.requiredService.assign("443"_ctv);
    built.originPolicy.requiredResolveHost.assign(authority);
    built.url.reserve(urlSize);
    built.url.append(target.scheme);
    built.url.append("://"_ctv);
    built.url.append(authority);
    built.url.append(canonicalUri.get());
    if (!query.empty())
    {
      built.url.append('?');
      built.url.append(canonicalQuery.get());
    }
    if (built.url.size() != urlSize)
    {
      setError(error, Error::allocationFailure);
      return false;
    }

    for (const CanonicalHeader& header : canonicalHeaders)
    {
      if (!asciiEqual(header.name, "host") &&
          !appendHeader(built, header.name, header.value.get()))
      {
        setError(error, Error::allocationFailure);
        return false;
      }
    }
    if (!appendHeader(built, "Authorization", 13, authorization.get()))
    {
      setError(error, Error::allocationFailure);
      return false;
    }

    scrubber.release();
    output = std::move(built);
    return true;
  }
};

void AwsHttpRequest::secureReset(Request& request)
{
  AwsHttpRequestImplementation::secureReset(request);
}

bool AwsHttpRequest::idempotencyToken(const Vector<String>& components, String& token)
{
  String input;
  uint64_t capacity = uint64_t(components.size()) * 24;
  for (const String& component : components)
  {
    if (component.size() > UINT64_MAX - capacity)
    {
      token.clear();
      return false;
    }
    capacity += component.size();
  }
  if (!input.reserve(capacity))
  {
    token.clear();
    return false;
  }
  for (const String& component : components)
  {
    String size;
    size.assignItoa(component.size());
    input.append(size);
    input.append(':');
    input.append(component);
    input.append(';');
  }
  uint8_t digest[EVP_MAX_MD_SIZE];
  unsigned int digestSize = 0;
  const bool hashed = EVP_Digest(input.data(),
                                 size_t(input.size()),
                                 digest,
                                 &digestSize,
                                 EVP_sha256(),
                                 nullptr) == 1 && digestSize == 32;
  input.secureReset();
  token.clear();
  constexpr static char hex[] = "0123456789abcdef";
  if (hashed && token.reserve(64))
  {
    for (uint32_t index = 0; index < 32; ++index)
    {
      token.append(hex[digest[index] >> 4]);
      token.append(hex[digest[index] & 0x0f]);
    }
  }
  OPENSSL_cleanse(digest, sizeof(digest));
  return token.size() == 64;
}

bool AwsHttpRequest::build(const Target& target,
                           Method method,
                           const Vector<Header>& headers,
                           const String& body,
                           const AwsCredentialMaterial& credential,
                           int64_t unixTimestampSeconds,
                           TimePoint deadline,
                           Request& output,
                           Error *error)
{
  return AwsHttpRequestImplementation::build(target,
                                             method,
                                             headers,
                                             body,
                                             credential,
                                             unixTimestampSeconds,
                                             deadline,
                                             output,
                                             error);
}
