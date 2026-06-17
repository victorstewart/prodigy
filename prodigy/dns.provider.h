#pragma once

#include <prodigy/types.h>

class ProdigyDNSRecordBinding {
public:

  String provider;
  String credentialName;
  String zone;
  String name;
  String type;
  Vector<String> values;
  uint32_t ttl = 0;
};

static inline bool prodigyDNSRecordSingleValue(const ProdigyDNSRecordBinding& record, String& value, String& failure)
{
  if (record.values.size() != 1 || record.values[0].size() == 0)
  {
    failure.assign("DNS record requires exactly one value"_ctv);
    return false;
  }
  value = record.values[0];
  return true;
}

static inline bool prodigyDNSRecordSingleTXTValue(const ProdigyDNSRecordBinding& record, String& value, String& failure)
{
  if (routableResourceDNSPartEquals(record.type, "TXT"_ctv, false) == false)
  {
    failure.assign("DNS TXT operation requires type TXT"_ctv);
    return false;
  }
  return prodigyDNSRecordSingleValue(record, value, failure);
}

static inline bool prodigyBuildDNSRecordBinding(const RoutableResourceLease& lease, ProdigyDNSRecordBinding& binding, String *failure = nullptr)
{
  binding = {};
  if (failure)
  {
    failure->clear();
  }
  if (lease.kind != RoutableResourceLeaseKind::dnsRecord || lease.address.isNull())
  {
    if (failure)
    {
      failure->assign("DNS binding requires a DNS record lease with a concrete address"_ctv);
    }
    return false;
  }
  String value = {};
  if (ClusterMachine::renderIPAddressLiteral(lease.address, value) == false)
  {
    if (failure)
    {
      failure->assign("DNS binding address render failed"_ctv);
    }
    return false;
  }
  binding.values.push_back(value);

  binding.provider = lease.dnsProvider;
  binding.credentialName = lease.dnsCredentialName;
  binding.zone = lease.dnsZone;
  binding.name = lease.dnsName;
  binding.type = lease.dnsType;
  binding.ttl = lease.dnsTTL;
  return true;
}

class ProdigyDNSProvider {
public:

  virtual ~ProdigyDNSProvider() = default;

  virtual bool supportsProvider(const String& provider) const = 0;
  virtual bool upsert(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) = 0;
  virtual bool remove(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) = 0;
  virtual bool presentTXT(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure)
  {
    String ignored = {};
    if (prodigyDNSRecordSingleTXTValue(record, ignored, failure) == false)
    {
      return false;
    }
    (void)credential;
    failure.assign("DNS provider does not implement ACME TXT present"_ctv);
    return false;
  }
  virtual bool cleanupTXT(const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure)
  {
    String ignored = {};
    if (prodigyDNSRecordSingleTXTValue(record, ignored, failure) == false)
    {
      return false;
    }
    (void)credential;
    failure.assign("DNS provider does not implement ACME TXT cleanup"_ctv);
    return false;
  }
};
