#include <prodigy/iaas/aws/aws.h>

bool parseAwsCredentialMaterial(const String& material, AwsCredentialMaterial& credential, String *failure)
{
  credential = {};
  if (failure)
  {
    failure->clear();
  }

  if (material.size() == 0)
  {
    if (failure)
    {
      failure->assign("aws credential material required"_ctv);
    }
    return false;
  }

  if (material[0] == '{')
  {
    String materialText = {};
    materialText.assign(material);
    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    if (parser.parse(materialText.c_str(), materialText.size()).get(doc))
    {
      AwsCredentialMaterial::secureReset(materialText);
      if (failure)
      {
        failure->assign("aws credential material json parse failed"_ctv);
      }
      return false;
    }

    std::string_view accessKeyID;
    std::string_view secretAccessKey;
    std::string_view sessionToken;
    std::string_view expiration;
    if (doc["accessKeyId"].get(accessKeyID) && doc["accessKeyID"].get(accessKeyID) && doc["AccessKeyId"].get(accessKeyID) && doc["awsAccessKeyId"].get(accessKeyID))
    {
      accessKeyID = {};
    }

    if (doc["secretAccessKey"].get(secretAccessKey) && doc["SecretAccessKey"].get(secretAccessKey) && doc["awsSecretAccessKey"].get(secretAccessKey))
    {
      secretAccessKey = {};
    }

    if (doc["sessionToken"].get(sessionToken) && doc["SessionToken"].get(sessionToken) && doc["Token"].get(sessionToken) && doc["token"].get(sessionToken))
    {
      sessionToken = {};
    }

    if (doc["expiration"].get(expiration) && doc["Expiration"].get(expiration))
    {
      expiration = {};
    }

    int64_t expirationMs = 0;
    if (expiration.size() > 0)
    {
      expirationMs = awsParseRFC3339Ms(String(expiration));
    }
    const bool assigned = credential.assign(
        reinterpret_cast<const uint8_t *>(accessKeyID.data()), accessKeyID.size(),
        reinterpret_cast<const uint8_t *>(secretAccessKey.data()), secretAccessKey.size(),
        reinterpret_cast<const uint8_t *>(sessionToken.data()), sessionToken.size(), expirationMs);
    AwsCredentialMaterial::secureReset(materialText);
    if (!assigned)
    {
      if (failure)
      {
        failure->assign("aws credential material missing access key or secret key"_ctv);
      }
      return false;
    }
  }
  else
  {
    int64_t firstColon = -1;
    int64_t secondColon = -1;
    for (uint64_t index = 0; index < material.size(); ++index)
    {
      if (material[index] == ':')
      {
        if (firstColon < 0)
        {
          firstColon = int64_t(index);
        }
        else
        {
          secondColon = int64_t(index);
          break;
        }
      }
    }
    if (firstColon < 0)
    {
      if (failure)
      {
        failure->assign("aws credential material requires accessKeyId:secretAccessKey or json"_ctv);
      }
      return false;
    }

    const uint64_t secretOffset = uint64_t(firstColon + 1);
    uint64_t secretSize = material.size() - secretOffset;
    const uint8_t *sessionToken = nullptr;
    uint64_t sessionTokenSize = 0;
    if (secondColon < 0)
    {
      secondColon = int64_t(material.size());
    }
    else
    {
      sessionToken = material.data() + uint64_t(secondColon + 1);
      sessionTokenSize = material.size() - uint64_t(secondColon + 1);
    }
    secretSize = uint64_t(secondColon) - secretOffset;
    if (!credential.assign(material.data(), uint64_t(firstColon),
                           material.data() + secretOffset, secretSize,
                           sessionToken, sessionTokenSize))
    {
      if (failure)
      {
        failure->assign("aws credential material missing access key or secret key"_ctv);
      }
      return false;
    }
  }

  if (credential.valid() == false)
  {
    if (failure)
    {
      failure->assign("aws credential material missing access key or secret key"_ctv);
    }
    return false;
  }

  return true;
}

uint32_t awsHashRackIdentity(const String& value)
{
  uint32_t hash = 0;
  for (uint64_t index = 0; index < value.size(); ++index)
  {
    hash = (hash * 131u) + uint8_t(value[index]);
  }

  return hash;
}

uint32_t awsRackUUIDFromAvailabilityZone(const String& availabilityZone)
{
  return awsHashRackIdentity(availabilityZone);
}

bool awsParseRFC3339Ms(const String& value, int64_t& timestampMs)
{
  timestampMs = 0;
  if (value.size() < 20 || value[4] != '-' || value[7] != '-' ||
      value[10] != 'T' || value[13] != ':' || value[16] != ':')
  {
    return false;
  }

  auto digit = [&](uint64_t index) -> int32_t {
    return index < value.size() && value[index] >= '0' && value[index] <= '9'
               ? int32_t(value[index] - '0')
               : -1;
  };
  auto number = [&](uint64_t offset, uint32_t count, int32_t& result) -> bool {
    result = 0;
    for (uint32_t index = 0; index < count; ++index)
    {
      const int32_t component = digit(offset + index);
      if (component < 0)
      {
        return false;
      }
      result = result * 10 + component;
    }
    return true;
  };

  int32_t year, month, day, hour, minute, second;
  if (!number(0, 4, year) || !number(5, 2, month) || !number(8, 2, day) ||
      !number(11, 2, hour) || !number(14, 2, minute) || !number(17, 2, second) ||
      month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59)
  {
    return false;
  }

  constexpr uint8_t daysByMonth[] = {31, 28, 31, 30, 31, 30,
                                      31, 31, 30, 31, 30, 31};
  const bool leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
  const uint32_t maximumDay = daysByMonth[month - 1] +
                              uint32_t(month == 2 && leap);
  if (day < 1 || uint32_t(day) > maximumDay)
  {
    return false;
  }

  uint64_t cursor = 19;
  int32_t fractionalMs = 0;
  if (cursor < value.size() && value[cursor] == '.')
  {
    ++cursor;
    const uint64_t fractionalStart = cursor;
    uint32_t digits = 0;
    while (cursor < value.size() && digit(cursor) >= 0)
    {
      if (digits < 3)
      {
        fractionalMs = fractionalMs * 10 + digit(cursor);
      }
      ++digits;
      ++cursor;
    }
    if (cursor == fractionalStart || digits == 0)
    {
      return false;
    }
    while (digits++ < 3)
    {
      fractionalMs *= 10;
    }
  }

  int32_t offsetSeconds = 0;
  if (cursor < value.size() && value[cursor] == 'Z')
  {
    ++cursor;
  }
  else if (cursor + 6 == value.size() &&
           (value[cursor] == '+' || value[cursor] == '-') &&
           value[cursor + 3] == ':')
  {
    int32_t offsetHour, offsetMinute;
    if (!number(cursor + 1, 2, offsetHour) ||
        !number(cursor + 4, 2, offsetMinute) ||
        offsetHour > 23 || offsetMinute > 59)
    {
      return false;
    }
    offsetSeconds = (offsetHour * 60 + offsetMinute) * 60;
    if (value[cursor] == '-')
    {
      offsetSeconds = -offsetSeconds;
    }
    cursor += 6;
  }
  else
  {
    return false;
  }
  if (cursor != value.size())
  {
    return false;
  }

  int32_t adjustedYear = year - int32_t(month <= 2);
  const int32_t era = (adjustedYear >= 0 ? adjustedYear : adjustedYear - 399) / 400;
  const uint32_t yearOfEra = uint32_t(adjustedYear - era * 400);
  const uint32_t adjustedMonth = uint32_t(month + (month > 2 ? -3 : 9));
  const uint32_t dayOfYear = (153 * adjustedMonth + 2) / 5 + uint32_t(day - 1);
  const uint32_t dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear;
  const int64_t daysSinceEpoch = int64_t(era) * 146097 + int64_t(dayOfEra) - 719468;
  const int64_t secondsSinceEpoch =
      daysSinceEpoch * 86400 + hour * 3600 + minute * 60 + second - offsetSeconds;
  timestampMs = secondsSinceEpoch * 1000 + fractionalMs;
  return true;
}

int64_t awsParseRFC3339Ms(const String& value)
{
  int64_t timestampMs = 0;
  return awsParseRFC3339Ms(value, timestampMs)
             ? timestampMs
             : Time::now<TimeResolution::ms>();
}

bool awsFormatRFC3339Seconds(int64_t unixSeconds, String& value)
{
  time_t raw = time_t(unixSeconds);
  struct tm utc = {};
  char buffer[21];
  if (int64_t(raw) != unixSeconds || gmtime_r(&raw, &utc) == nullptr ||
      std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &utc) != 20)
  {
    value.clear();
    return false;
  }
  value.assign(reinterpret_cast<const uint8_t *>(buffer), 20);
  return true;
}
