#pragma once

#include <networking/async.dns.cares.h>
#include <prodigy/host.http.admission.h>

#include <utility>

class ProdigyHostControlNetwork final {
private:

  RingAsyncDnsResolver resolver;
  MultiCurlClient client;
  ProdigyHostHttpAdmission admission;
  bool stopping = false;

  static MultiCurlClient::Config clientConfig(void)
  {
    MultiCurlClient::Config config;
    config.transfers = ProdigyHostHttpAdmission::defaultCapacity;
    return config;
  }

public:

  ProdigyHostControlNetwork()
      : client(resolver, clientConfig()),
        admission(ProdigyHostHttpOperation::submission(client),
                  ProdigyHostDelayOperation::submission())
  {}

  explicit ProdigyHostControlNetwork(RingAsyncDnsResolver::BackendConfig config)
      : resolver({}, std::move(config)),
        client(resolver, clientConfig()),
        admission(ProdigyHostHttpOperation::submission(client),
                  ProdigyHostDelayOperation::submission())
  {}

  ProdigyHostControlNetwork(const ProdigyHostControlNetwork&) = delete;
  ProdigyHostControlNetwork& operator=(const ProdigyHostControlNetwork&) = delete;

  bool ready(void) const
  {
    return resolver.ready() && client.ready();
  }

  ProdigyHostHttpSubmission http(void)
  {
    return admission.submission();
  }

  bool shutdown(void)
  {
    stopping = true;
    admission.shutdown();
    if (client.shutdown() == false)
    {
      return false;
    }
    if (resolver.shutdown() == false)
    {
      return false;
    }
    return shutdownSafe();
  }

  bool shutdownSafe(void) const
  {
    return stopping && admission.shutdownSafe() && client.shutdownSafe() && resolver.shutdownSafe();
  }
};
