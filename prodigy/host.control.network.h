#pragma once

#include <prodigy/dns/control.client.h>
#include <prodigy/host.http.admission.h>

class ProdigyHostControlNetwork final {
private:

  String initializationFailure;
  ProdigyDns::ControlClient resolver;
  MultiCurlClient client;
  ProdigyHostHttpAdmission admission;
  bool stopping = false;

  static MultiCurlClient::Config clientConfig(void)
  {
    MultiCurlClient::Config config;
    config.transfers = ProdigyHostHttpAdmission::defaultCapacity;
    return config;
  }

  static ProdigyDns::ControlBootstrap loadBootstrap(
      ProdigyDnsControlClientRole role,
      String& failure)
  {
    ProdigyDns::ControlBootstrap bootstrap;
    if (ProdigyDns::readControlBootstrap(
            String(ProdigyDns::controlBootstrapPath(role)),
            bootstrap,
            Time::now<TimeResolution::ms>(),
            &failure) == false)
    {
      return {};
    }
    if (bootstrap.valid(Time::now<TimeResolution::ms>(), &failure, &role) == false)
    {
      return {};
    }
    return bootstrap;
  }

public:

  ProdigyHostControlNetwork()
      : resolver(loadBootstrap(ProdigyDnsControlClientRole::prodigy,
                               initializationFailure)),
        client(resolver.resolver(), clientConfig()),
        admission(ProdigyHostHttpOperation::submission(client),
                  ProdigyHostDelayOperation::submission())
  {}

  explicit ProdigyHostControlNetwork(ProdigyDnsControlClientRole role)
      : resolver(loadBootstrap(role, initializationFailure)),
        client(resolver.resolver(), clientConfig()),
        admission(ProdigyHostHttpOperation::submission(client),
                  ProdigyHostDelayOperation::submission())
  {}

  explicit ProdigyHostControlNetwork(ProdigyDns::ControlBootstrap bootstrap)
      : resolver(std::move(bootstrap)),
        client(resolver.resolver(), clientConfig()),
        admission(ProdigyHostHttpOperation::submission(client),
                  ProdigyHostDelayOperation::submission())
  {}

  ProdigyHostControlNetwork(const ProdigyHostControlNetwork&) = delete;
  ProdigyHostControlNetwork& operator=(const ProdigyHostControlNetwork&) = delete;

  bool ready(void) const
  {
    return resolver.ready() && client.ready();
  }

  bool sessionReady(void) const
  {
    return resolver.sessionReady() && client.ready();
  }

  String& failure(void)
  {
    return initializationFailure;
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
