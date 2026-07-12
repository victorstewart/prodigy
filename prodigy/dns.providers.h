#pragma once

#include <prodigy/dns/azure/azure.h>
#include <prodigy/dns/cloudflare/cloudflare.h>
#include <prodigy/dns/gcp/gcp.h>
#include <prodigy/dns/route53/route53.h>
#include <prodigy/dns/vultr/vultr.h>

class ProdigyDefaultDNSProvider final : public ProdigyDNSProvider {
public:

  void configureRuntime(ProdigyDNSProviderRuntime requestedRuntime) override
  {
    ProdigyDNSProvider::configureRuntime(requestedRuntime);
    cloudflare.configureRuntime(requestedRuntime);
    route53.configureRuntime(requestedRuntime);
    gcp.configureRuntime(requestedRuntime);
    azure.configureRuntime(requestedRuntime);
    vultr.configureRuntime(requestedRuntime);
  }

  bool supportsProvider(const String& provider) const override
  {
    return cloudflare.supportsProvider(provider) ||
           route53.supportsProvider(provider) ||
           gcp.supportsProvider(provider) ||
           azure.supportsProvider(provider) ||
           vultr.supportsProvider(provider);
  }

  ProdigyHostTask<bool> upsert(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    ProdigyDNSProvider *provider = resolve(record.provider);
    if (provider == nullptr)
    {
      failure.assign("DNS provider is not configured"_ctv);
      co_return false;
    }
    co_return co_await provider->upsert(coro, record, credential, failure);
  }

  ProdigyHostTask<bool> remove(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    ProdigyDNSProvider *provider = resolve(record.provider);
    if (provider == nullptr)
    {
      failure.assign("DNS provider is not configured"_ctv);
      co_return false;
    }
    co_return co_await provider->remove(coro, record, credential, failure);
  }

  ProdigyHostTask<bool> presentTXT(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    ProdigyDNSProvider *provider = resolve(record.provider);
    if (provider == nullptr)
    {
      failure.assign("DNS provider is not configured"_ctv);
      co_return false;
    }
    co_return co_await provider->presentTXT(coro, record, credential, failure);
  }

  ProdigyHostTask<bool> cleanupTXT(CoroutineStack *coro, const ProdigyDNSRecordBinding& record, const ApiCredential& credential, String& failure) override
  {
    ProdigyDNSProvider *provider = resolve(record.provider);
    if (provider == nullptr)
    {
      failure.assign("DNS provider is not configured"_ctv);
      co_return false;
    }
    co_return co_await provider->cleanupTXT(coro, record, credential, failure);
  }

private:

  CloudflareDNSProvider cloudflare;
  Route53DNSProvider route53;
  GcpCloudDNSProvider gcp;
  AzureDNSProvider azure;
  VultrDNSProvider vultr;

  ProdigyDNSProvider *resolve(const String& provider)
  {
    if (cloudflare.supportsProvider(provider))
    {
      return &cloudflare;
    }
    if (route53.supportsProvider(provider))
    {
      return &route53;
    }
    if (gcp.supportsProvider(provider))
    {
      return &gcp;
    }
    if (azure.supportsProvider(provider))
    {
      return &azure;
    }
    if (vultr.supportsProvider(provider))
    {
      return &vultr;
    }
    return nullptr;
  }
};
