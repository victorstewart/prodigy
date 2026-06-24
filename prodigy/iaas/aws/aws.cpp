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

    credential.accessKeyID.assign(accessKeyID);
    credential.secretAccessKey.assign(secretAccessKey);
    credential.sessionToken.assign(sessionToken);
    if (expiration.size() > 0)
    {
      credential.expirationMs = awsParseRFC3339Ms(String(expiration));
    }
  }
  else
  {
    String materialText = {};
    materialText.assign(material);
    int64_t firstColon = materialText.findChar(':');
    if (firstColon < 0)
    {
      if (failure)
      {
        failure->assign("aws credential material requires accessKeyId:secretAccessKey or json"_ctv);
      }
      return false;
    }

    int64_t secondColon = materialText.findChar(':', uint64_t(firstColon + 1));
    credential.accessKeyID.assign(material.substr(0, uint64_t(firstColon), Copy::yes));
    if (secondColon < 0)
    {
      credential.secretAccessKey.assign(material.substr(uint64_t(firstColon + 1), material.size() - uint64_t(firstColon + 1), Copy::yes));
    }
    else
    {
      credential.secretAccessKey.assign(material.substr(uint64_t(firstColon + 1), uint64_t(secondColon - firstColon - 1), Copy::yes));
      credential.sessionToken.assign(material.substr(uint64_t(secondColon + 1), material.size() - uint64_t(secondColon + 1), Copy::yes));
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

int64_t awsParseRFC3339Ms(const String& value)
{
  if (value.size() < 20)
  {
    return Time::now<TimeResolution::ms>();
  }

  struct tm tmv = {};
  tmv.tm_year = (value[0] - '0') * 1000 + (value[1] - '0') * 100 + (value[2] - '0') * 10 + (value[3] - '0') - 1900;
  tmv.tm_mon = (value[5] - '0') * 10 + (value[6] - '0') - 1;
  tmv.tm_mday = (value[8] - '0') * 10 + (value[9] - '0');
  tmv.tm_hour = (value[11] - '0') * 10 + (value[12] - '0');
  tmv.tm_min = (value[14] - '0') * 10 + (value[15] - '0');
  tmv.tm_sec = (value[17] - '0') * 10 + (value[18] - '0');
  tmv.tm_isdst = 0;
#ifdef _GNU_SOURCE
  time_t secs = timegm(&tmv);
#else
  char *oldtz = getenv("TZ");
  setenv("TZ", "UTC", 1);
  tzset();
  time_t secs = mktime(&tmv);
  if (oldtz)
  {
    setenv("TZ", oldtz, 1);
  }
  else
  {
    unsetenv("TZ");
  }
  tzset();
#endif
  return int64_t(secs) * 1000LL;
}
