#pragma once

#include <prodigy/mothership/mothership.cluster.types.h>
#include <prodigy/system.container.policy.h>

using MothershipConnectivityRuntimeConfig = MothershipConnectivity;

struct MothershipTunnelProviderConfigureRequest {
  MothershipTunnelProviderDesiredState desired;
  String artifactBlob;
};

template <typename S>
static void serialize(S&& serializer, MothershipTunnelProviderConfigureRequest& request)
{
  serializer.object(request.desired);
  serializer.text1b(request.artifactBlob, UINT32_MAX);
}

template <typename Text>
static inline bool mothershipTunnelPolicyFail(String *failure, const Text& text)
{
  if (failure)
  {
    failure->assign(text);
  }
  return false;
}

static inline bool mothershipTunnelPolicyOk(String *failure)
{
  if (failure)
  {
    failure->clear();
  }
  return true;
}

static inline bool mothershipTunnelProviderSpecValid(const MothershipTunnelProviderSpec& spec, String *failure = nullptr)
{
  if (prodigyIsSHA256HexDigest(spec.artifactSha256) == false || spec.artifactBytes == 0)
  {
    return mothershipTunnelPolicyFail(failure, "mothership tunnel-provider artifact identity invalid"_ctv);
  }

  if (spec.dialEndpoint.size() == 0)
  {
    return mothershipTunnelPolicyFail(failure, "mothership tunnel-provider dial config invalid"_ctv);
  }

  if (spec.egressHost.size() == 0 || spec.egressPort == 0)
  {
    return mothershipTunnelPolicyFail(failure, "mothership tunnel-provider egress endpoint invalid"_ctv);
  }
  uint32_t egressAddress = 0;
  if (prodigySystemEgressIPv4Literal(spec.egressHost, egressAddress) == false)
  {
    return mothershipTunnelPolicyFail(failure, "mothership tunnel-provider egress literal invalid"_ctv);
  }
  if (prodigySystemEgressIPv4HostAddressIsDenied(egressAddress))
  {
    return mothershipTunnelPolicyFail(failure, "mothership tunnel-provider egress literal denied"_ctv);
  }

  return mothershipTunnelPolicyOk(failure);
}

static inline void mothershipStripMothershipOnlyConnectivityFields(MothershipConnectivityRuntimeConfig& config)
{
  if (config.kind != MothershipConnectivityKind::tunnelProvider)
  {
    config.tunnelProvider = {};
    return;
  }

  config.tunnelProvider.clientAuth = {};
}

static inline bool mothershipConnectivityRuntimeConfigValid(const MothershipConnectivityRuntimeConfig& config, String *failure = nullptr)
{
  if (config.kind == MothershipConnectivityKind::ssh)
  {
    return mothershipTunnelPolicyOk(failure);
  }

  if (config.kind != MothershipConnectivityKind::tunnelProvider)
  {
    return mothershipTunnelPolicyFail(failure, "mothership connectivity kind invalid"_ctv);
  }

  if (config.tunnelProvider.clientAuth.configured())
  {
    return mothershipTunnelPolicyFail(failure, "mothership tunnel-provider runtime config contains mothership-only fields"_ctv);
  }

  return mothershipTunnelProviderSpecValid(config.tunnelProvider, failure);
}
