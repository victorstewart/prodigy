#include <prodigy/ingress.validation.h>
#include <prodigy/wire.h>
#include <services/debug.h>

#include <cstdio>
#include <cstdlib>
#include <thread>
#include <unistd.h>

class TestSuite {
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    if (condition)
    {
      basics_log("PASS: %s\n", name);
    }
    else
    {
      basics_log("FAIL: %s\n", name);
      String line;
      line.append("FAIL: "_ctv);
      line.append(name);
      line.append('\n');
      (void)write(STDERR_FILENO, line.data(), line.size());
      failed += 1;
    }
  }
};

static bool equalStringVector(const Vector<String>& lhs, const Vector<String>& rhs)
{
  if (lhs.size() != rhs.size())
  {
    return false;
  }

  for (uint32_t index = 0; index < lhs.size(); index += 1)
  {
    if (lhs[index].equal(rhs[index]) == false)
    {
      return false;
    }
  }

  return true;
}

static bool equalIPAddressVector(const Vector<IPAddress>& lhs, const Vector<IPAddress>& rhs)
{
  if (lhs.size() != rhs.size())
  {
    return false;
  }

  for (uint32_t index = 0; index < lhs.size(); index += 1)
  {
    if (lhs[index].equals(rhs[index]) == false)
    {
      return false;
    }
  }

  return true;
}

static bool equalTlsIdentity(const TlsIdentity& lhs, const TlsIdentity& rhs)
{
  return lhs.name.equal(rhs.name) &&
         lhs.generation == rhs.generation &&
         lhs.notBeforeMs == rhs.notBeforeMs &&
         lhs.notAfterMs == rhs.notAfterMs &&
         lhs.certPem.equal(rhs.certPem) &&
         lhs.keyPem.equal(rhs.keyPem) &&
         lhs.chainPem.equal(rhs.chainPem) &&
         equalStringVector(lhs.dnsSans, rhs.dnsSans) &&
         equalIPAddressVector(lhs.ipSans, rhs.ipSans) &&
         equalStringVector(lhs.tags, rhs.tags);
}

static bool equalApiCredential(const ApiCredential& lhs, const ApiCredential& rhs)
{
  if (lhs.name.equal(rhs.name) == false ||
      lhs.provider.equal(rhs.provider) == false ||
      lhs.generation != rhs.generation ||
      lhs.expiresAtMs != rhs.expiresAtMs ||
      lhs.activeFromMs != rhs.activeFromMs ||
      lhs.sunsetAtMs != rhs.sunsetAtMs ||
      lhs.material.equal(rhs.material) == false ||
      lhs.metadata.size() != rhs.metadata.size())
  {
    return false;
  }

  for (const auto& [key, value] : lhs.metadata)
  {
    auto it = rhs.metadata.find(key);
    if (it == rhs.metadata.end() || it->second.equal(value) == false)
    {
      return false;
    }
  }

  return true;
}

static bool equalTlsResumptionWormholeConfig(const TlsResumptionWormholeConfig& lhs, const TlsResumptionWormholeConfig& rhs)
{
  return equalStringVector(lhs.alpns, rhs.alpns) &&
         equalStringVector(lhs.sniNames, rhs.sniNames);
}

static bool equalWormholeDNSConfig(const WormholeDNSConfig& lhs, const WormholeDNSConfig& rhs)
{
  return lhs.provider.equal(rhs.provider) &&
         lhs.credentialName.equal(rhs.credentialName) &&
         lhs.zone.equal(rhs.zone) &&
         lhs.name.equal(rhs.name) &&
         lhs.type.equal(rhs.type) &&
         lhs.ttl == rhs.ttl &&
         lhs.allowSingleMachine == rhs.allowSingleMachine;
}

static bool equalTlsResumptionSnapshots(const Vector<TlsResumptionSnapshot>& lhs, const Vector<TlsResumptionSnapshot>& rhs)
{
  if (lhs.size() != rhs.size())
  {
    return false;
  }

  for (uint32_t index = 0; index < lhs.size(); index += 1)
  {
    if (prodigyTlsResumptionSnapshotsEqual(lhs[index], rhs[index]) == false)
    {
      return false;
    }
  }

  return true;
}

static bool equalTlsResumptionApplyResult(const TlsResumptionApplyResult& lhs, const TlsResumptionApplyResult& rhs)
{
  return lhs.wormholeName.equal(rhs.wormholeName) &&
         lhs.generation == rhs.generation &&
         lhs.success == rhs.success &&
         lhs.failureReason.equal(rhs.failureReason);
}

static bool equalTlsIdentityApplyResult(const TlsIdentityApplyResult& lhs, const TlsIdentityApplyResult& rhs)
{
  return lhs.identityName.equal(rhs.identityName) &&
         lhs.generation == rhs.generation &&
         lhs.success == rhs.success &&
         lhs.failureReason.equal(rhs.failureReason);
}

static bool equalCredentialApplyAck(const CredentialApplyAck& lhs, const CredentialApplyAck& rhs)
{
  if (lhs.tlsResults.size() != rhs.tlsResults.size() ||
      lhs.resumptionResults.size() != rhs.resumptionResults.size())
  {
    return false;
  }
  for (uint32_t index = 0; index < lhs.tlsResults.size(); index += 1)
  {
    if (equalTlsIdentityApplyResult(lhs.tlsResults[index], rhs.tlsResults[index]) == false)
    {
      return false;
    }
  }
  for (uint32_t index = 0; index < lhs.resumptionResults.size(); index += 1)
  {
    if (equalTlsResumptionApplyResult(lhs.resumptionResults[index], rhs.resumptionResults[index]) == false)
    {
      return false;
    }
  }
  return true;
}

static bool equalCredentialBundle(const CredentialBundle& lhs, const CredentialBundle& rhs)
{
  if (lhs.bundleGeneration != rhs.bundleGeneration ||
      lhs.tlsIdentities.size() != rhs.tlsIdentities.size() ||
      lhs.apiCredentials.size() != rhs.apiCredentials.size() ||
      equalTlsResumptionSnapshots(lhs.tlsResumptionSnapshots, rhs.tlsResumptionSnapshots) == false)
  {
    return false;
  }

  for (uint32_t index = 0; index < lhs.tlsIdentities.size(); index += 1)
  {
    if (equalTlsIdentity(lhs.tlsIdentities[index], rhs.tlsIdentities[index]) == false)
    {
      return false;
    }
  }

  for (uint32_t index = 0; index < lhs.apiCredentials.size(); index += 1)
  {
    if (equalApiCredential(lhs.apiCredentials[index], rhs.apiCredentials[index]) == false)
    {
      return false;
    }
  }

  return true;
}

static bool equalCredentialDelta(const CredentialDelta& lhs, const CredentialDelta& rhs)
{
  if (lhs.bundleGeneration != rhs.bundleGeneration ||
      lhs.updatedTls.size() != rhs.updatedTls.size() ||
      lhs.updatedApi.size() != rhs.updatedApi.size() ||
      equalTlsResumptionSnapshots(lhs.updatedResumptionSnapshots, rhs.updatedResumptionSnapshots) == false ||
      lhs.reason.equal(rhs.reason) == false ||
      equalStringVector(lhs.removedTlsNames, rhs.removedTlsNames) == false ||
      equalStringVector(lhs.removedApiNames, rhs.removedApiNames) == false ||
      equalStringVector(lhs.removedResumptionWormholeNames, rhs.removedResumptionWormholeNames) == false)
  {
    return false;
  }

  for (uint32_t index = 0; index < lhs.updatedTls.size(); index += 1)
  {
    if (equalTlsIdentity(lhs.updatedTls[index], rhs.updatedTls[index]) == false)
    {
      return false;
    }
  }

  for (uint32_t index = 0; index < lhs.updatedApi.size(); index += 1)
  {
    if (equalApiCredential(lhs.updatedApi[index], rhs.updatedApi[index]) == false)
    {
      return false;
    }
  }

  return true;
}

static bool equalRoutableResourceLeaseReport(const RoutableResourceLeaseReport& lhs, const RoutableResourceLeaseReport& rhs)
{
  if (lhs.success != rhs.success || lhs.failure.equal(rhs.failure) == false || lhs.leases.size() != rhs.leases.size())
  {
    return false;
  }
  for (uint32_t index = 0; index < lhs.leases.size(); index += 1)
  {
    if ((lhs.leases[index] == rhs.leases[index]) == false)
    {
      return false;
    }
  }
  return true;
}

static bool equalWhitehole(const Whitehole& lhs, const Whitehole& rhs)
{
  return lhs.transport == rhs.transport &&
         lhs.family == rhs.family &&
         lhs.source == rhs.source &&
         lhs.hasAddress == rhs.hasAddress &&
         lhs.address.equals(rhs.address) &&
         lhs.sourcePort == rhs.sourcePort &&
         lhs.bindingNonce == rhs.bindingNonce;
}

static bool equalWormhole(const Wormhole& lhs, const Wormhole& rhs)
{
  return lhs.name.equal(rhs.name) &&
         lhs.externalAddress.equals(rhs.externalAddress) &&
         lhs.deliveryAddress.equals(rhs.deliveryAddress) &&
         lhs.externalPort == rhs.externalPort &&
         lhs.containerPort == rhs.containerPort &&
         lhs.layer4 == rhs.layer4 &&
         lhs.isQuic == rhs.isQuic &&
         lhs.userCapacity.minimum == rhs.userCapacity.minimum &&
         lhs.userCapacity.maximum == rhs.userCapacity.maximum &&
         lhs.hasQuicCidKeyState == rhs.hasQuicCidKeyState &&
         lhs.source == rhs.source &&
         lhs.routablePrefixUUID == rhs.routablePrefixUUID &&
         lhs.hasTlsResumptionConfig == rhs.hasTlsResumptionConfig &&
         equalTlsResumptionWormholeConfig(lhs.tlsResumption, rhs.tlsResumption) &&
         lhs.hasDNSConfig == rhs.hasDNSConfig &&
         equalWormholeDNSConfig(lhs.dns, rhs.dns) &&
         lhs.quicCidKeyState.rotationHours == rhs.quicCidKeyState.rotationHours &&
         lhs.quicCidKeyState.activeKeyIndex == rhs.quicCidKeyState.activeKeyIndex &&
         lhs.quicCidKeyState.rotatedAtMs == rhs.quicCidKeyState.rotatedAtMs &&
         lhs.quicCidKeyState.keyMaterialByIndex[0] == rhs.quicCidKeyState.keyMaterialByIndex[0] &&
         lhs.quicCidKeyState.keyMaterialByIndex[1] == rhs.quicCidKeyState.keyMaterialByIndex[1];
}

static bool equalContainerParameters(const ContainerParameters& lhs, const ContainerParameters& rhs)
{
  auto hasSubscriptionPairing = [](const ContainerParameters& parameters, const SubscriptionPairing& pairing) {
    auto it = parameters.subscriptionPairings.map.find(pairing.service);
    if (it == parameters.subscriptionPairings.map.end())
    {
      return false;
    }

    for (const SubscriptionPairing& candidate : it->second)
    {
      if (candidate == pairing)
      {
        return true;
      }
    }

    return false;
  };

  auto hasAdvertisementPairing = [](const ContainerParameters& parameters, const AdvertisementPairing& pairing) {
    auto it = parameters.advertisementPairings.map.find(pairing.service);
    if (it == parameters.advertisementPairings.map.end())
    {
      return false;
    }

    for (const AdvertisementPairing& candidate : it->second)
    {
      if (candidate == pairing)
      {
        return true;
      }
    }

    return false;
  };

  if (lhs.uuid != rhs.uuid ||
      lhs.memoryMB != rhs.memoryMB ||
      lhs.storageMB != rhs.storageMB ||
      lhs.nLogicalCores != rhs.nLogicalCores ||
      lhs.neuronFD != rhs.neuronFD ||
      lhs.lowCPU != rhs.lowCPU ||
      lhs.highCPU != rhs.highCPU ||
      lhs.private6.equals(rhs.private6) == false ||
      lhs.wormholes.size() != rhs.wormholes.size() ||
      lhs.whiteholes.size() != rhs.whiteholes.size() ||
      lhs.justCrashed != rhs.justCrashed ||
      lhs.datacenterUniqueTag != rhs.datacenterUniqueTag ||
      lhs.statefulMeshRoles.client != rhs.statefulMeshRoles.client ||
      lhs.statefulMeshRoles.sibling != rhs.statefulMeshRoles.sibling ||
      lhs.statefulMeshRoles.cousin != rhs.statefulMeshRoles.cousin ||
      lhs.statefulMeshRoles.seeding != rhs.statefulMeshRoles.seeding ||
      lhs.statefulMeshRoles.sharding != rhs.statefulMeshRoles.sharding ||
      lhs.flags.size() != rhs.flags.size() ||
      lhs.advertisesOnPorts.size() != rhs.advertisesOnPorts.size() ||
      lhs.hasCredentialBundle != rhs.hasCredentialBundle)
  {
    return false;
  }

  for (uint32_t index = 0; index < lhs.flags.size(); index += 1)
  {
    if (lhs.flags[index] != rhs.flags[index])
    {
      return false;
    }
  }

  for (const auto& [service, port] : lhs.advertisesOnPorts)
  {
    auto it = rhs.advertisesOnPorts.find(service);
    if (it == rhs.advertisesOnPorts.end() || it->second != port)
    {
      return false;
    }
  }

  uint32_t lhsSubscriptionCount = 0;
  uint32_t rhsSubscriptionCount = 0;
  for (const auto& [service, pairings] : lhs.subscriptionPairings.map)
  {
    auto rhsIt = rhs.subscriptionPairings.map.find(service);
    rhsSubscriptionCount += rhsIt == rhs.subscriptionPairings.map.end() ? 0 : rhsIt->second.size();
    lhsSubscriptionCount += pairings.size();
    for (const SubscriptionPairing& pairing : pairings)
    {
      if (hasSubscriptionPairing(rhs, pairing) == false)
      {
        return false;
      }
    }
  }

  if (lhsSubscriptionCount != rhsSubscriptionCount)
  {
    return false;
  }

  uint32_t lhsAdvertisementCount = 0;
  uint32_t rhsAdvertisementCount = 0;
  for (const auto& [service, pairings] : lhs.advertisementPairings.map)
  {
    auto rhsIt = rhs.advertisementPairings.map.find(service);
    rhsAdvertisementCount += rhsIt == rhs.advertisementPairings.map.end() ? 0 : rhsIt->second.size();
    lhsAdvertisementCount += pairings.size();
    for (const AdvertisementPairing& pairing : pairings)
    {
      if (hasAdvertisementPairing(rhs, pairing) == false)
      {
        return false;
      }
    }
  }

  if (lhsAdvertisementCount != rhsAdvertisementCount)
  {
    return false;
  }

  for (uint32_t index = 0; index < lhs.wormholes.size(); index += 1)
  {
    if (equalWormhole(lhs.wormholes[index], rhs.wormholes[index]) == false)
    {
      return false;
    }
  }

  for (uint32_t index = 0; index < lhs.whiteholes.size(); index += 1)
  {
    if (equalWhitehole(lhs.whiteholes[index], rhs.whiteholes[index]) == false)
    {
      return false;
    }
  }

  if (lhs.hasCredentialBundle)
  {
    return equalCredentialBundle(lhs.credentialBundle, rhs.credentialBundle);
  }

  return true;
}

static TlsIdentity makeTlsIdentity(void)
{
  TlsIdentity identity;
  identity.name.assign("container.internal"_ctv);
  identity.generation = 7;
  identity.notBeforeMs = 111;
  identity.notAfterMs = 222;
  identity.certPem.assign("cert"_ctv);
  identity.keyPem.assign("key"_ctv);
  identity.chainPem.assign("chain"_ctv);
  identity.dnsSans.push_back("a.internal"_ctv);
  identity.dnsSans.push_back("b.internal"_ctv);
  identity.ipSans.push_back(IPAddress("fd00::1", true));
  identity.tags.push_back("inbound"_ctv);
  return identity;
}

static ApiCredential makeApiCredential(void)
{
  ApiCredential credential;
  credential.name.assign("telnyx_bearer"_ctv);
  credential.provider.assign("telnyx"_ctv);
  credential.generation = 5;
  credential.expiresAtMs = 999;
  credential.activeFromMs = 333;
  credential.sunsetAtMs = 1111;
  credential.material.assign("secret-token"_ctv);
  credential.metadata.insert_or_assign("scope"_ctv, "sms"_ctv);
  credential.metadata.insert_or_assign("region"_ctv, "global"_ctv);
  return credential;
}

static TlsResumptionKeyEpoch makeTlsResumptionKeyEpoch(uint8_t seed)
{
  TlsResumptionKeyEpoch epoch;
  epoch.generation = 9000 + seed;
  epoch.role = (seed % 2) == 0 ? TlsResumptionKeyRole::issueAndAccept : TlsResumptionKeyRole::acceptOnly;
  for (uint32_t index = 0; index < sizeof(epoch.keyID); index += 1)
  {
    epoch.keyID[index] = uint8_t(seed + index);
  }
  for (uint32_t index = 0; index < sizeof(epoch.masterSecret); index += 1)
  {
    epoch.masterSecret[index] = uint8_t(0x80u + seed + index);
  }
  epoch.issueUntilMs = 222'000 + seed;
  epoch.acceptUntilMs = 333'000 + seed;
  return epoch;
}

static TlsResumptionWormholeConfig makeTlsResumptionWormholeConfig(void)
{
  TlsResumptionWormholeConfig config;
  config.alpns.push_back("h3"_ctv);
  config.sniNames.push_back("api.example.com"_ctv);
  return config;
}

static TlsResumptionSnapshot makeTlsResumptionSnapshot(void)
{
  TlsResumptionSnapshot snapshot;
  snapshot.generation = 12'345;
  snapshot.wormholeName.assign("public-api-quic"_ctv);
  snapshot.keyRing.push_back(makeTlsResumptionKeyEpoch(1));
  snapshot.keyRing.push_back(makeTlsResumptionKeyEpoch(2));
  return snapshot;
}

static TlsResumptionApplyResult makeTlsResumptionApplyResult(void)
{
  TlsResumptionApplyResult result;
  result.wormholeName.assign("public-api-quic"_ctv);
  result.generation = 12'346;
  result.success = false;
  result.failureReason.assign("stale generation"_ctv);
  return result;
}

static TlsResumptionApplyAck makeTlsResumptionApplyAck(void)
{
  TlsResumptionApplyAck ack;
  ack.results.push_back(makeTlsResumptionApplyResult());
  return ack;
}

static TlsIdentityApplyResult makeTlsIdentityApplyResult(void)
{
  TlsIdentityApplyResult tls;
  tls.identityName.assign("api-public"_ctv);
  tls.generation = 77;
  tls.success = false;
  tls.failureReason.assign("key rejected"_ctv);
  return tls;
}

static CredentialApplyAck makeCredentialApplyAck(void)
{
  CredentialApplyAck ack;
  ack.tlsResults.push_back(makeTlsIdentityApplyResult());
  ack.resumptionResults.push_back(makeTlsResumptionApplyResult());
  return ack;
}

static ContainerParameters makeContainerParameters(void)
{
  ContainerParameters parameters;
  parameters.uuid = uint128_t(0x1122334455667788ULL);
  parameters.uuid <<= 64;
  parameters.uuid |= uint128_t(0x99AABBCCDDEEFF00ULL);
  parameters.memoryMB = 1024;
  parameters.storageMB = 2048;
  parameters.nLogicalCores = 3;
  parameters.neuronFD = 5;
  parameters.lowCPU = 7;
  parameters.highCPU = 9;
  parameters.advertisesOnPorts[0xABCDEF0000000001ULL] = 19'111;
  parameters.advertisesOnPorts[0xABCDEF0000000002ULL] = 19'112;
  parameters.subscriptionPairings.insert(0xABCDEF0000000003ULL, SubscriptionPairing(uint128_t(11), uint128_t(12), 0xABCDEF0000000003ULL, 3210));
  parameters.subscriptionPairings.insert(0xABCDEF0000000004ULL, SubscriptionPairing(uint128_t(21), uint128_t(22), 0xABCDEF0000000004ULL, 6543));
  parameters.advertisementPairings.insert(0xABCDEF0000000005ULL, AdvertisementPairing(uint128_t(31), uint128_t(32), 0xABCDEF0000000005ULL));
  parameters.private6 = IPPrefix("fd00::10", true, 64);
  parameters.justCrashed = true;
  parameters.datacenterUniqueTag = 17;
  parameters.flags.push_back(44);
  parameters.flags.push_back(55);
  parameters.hasCredentialBundle = true;
  parameters.credentialBundle.bundleGeneration = 1234;
  parameters.credentialBundle.tlsIdentities.push_back(makeTlsIdentity());
  parameters.credentialBundle.apiCredentials.push_back(makeApiCredential());
  parameters.credentialBundle.tlsResumptionSnapshots.push_back(makeTlsResumptionSnapshot());
  return parameters;
}

static Wormhole makeContainerParametersWormhole(void)
{
  Wormhole wormhole = {};
  wormhole.name.assign("public-api-quic"_ctv);
  wormhole.externalAddress = IPAddress("2001:db8::44", true);
  wormhole.deliveryAddress = IPAddress("2001:db8:1::44", true);
  wormhole.externalPort = 443;
  wormhole.containerPort = 8443;
  wormhole.layer4 = IPPROTO_UDP;
  wormhole.isQuic = true;
  wormhole.userCapacity.minimum = 1;
  wormhole.userCapacity.maximum = 32;
  wormhole.hasQuicCidKeyState = true;
  wormhole.source = ExternalAddressSource::registeredRoutablePrefix;
  wormhole.routablePrefixUUID = uint128_t(0xAABBCCDD0011);
  wormhole.hasTlsResumptionConfig = true;
  wormhole.tlsResumption = makeTlsResumptionWormholeConfig();
  wormhole.hasDNSConfig = true;
  wormhole.dns.provider = "cloudflare"_ctv;
  wormhole.dns.credentialName = "cf-prod"_ctv;
  wormhole.dns.zone = "example.com"_ctv;
  wormhole.dns.name = "api.example.com"_ctv;
  wormhole.dns.type = "AAAA"_ctv;
  wormhole.dns.ttl = 300;
  wormhole.quicCidKeyState.rotationHours = 12;
  wormhole.quicCidKeyState.activeKeyIndex = 1;
  wormhole.quicCidKeyState.rotatedAtMs = 123'456'789;
  wormhole.quicCidKeyState.keyMaterialByIndex[0] = uint128_t(0x1111222233334444ULL);
  wormhole.quicCidKeyState.keyMaterialByIndex[1] = uint128_t(0xAAAABBBBCCCCDDDDULL);
  return wormhole;
}

static StatefulMeshRoles makeStatefulMeshRoles(void)
{
  StatefulDeploymentPlan plan = {};
  plan.clientPrefix = MeshServices::generateStatefulService(501, 1);
  plan.siblingPrefix = MeshServices::generateStatefulService(501, 2);
  plan.cousinPrefix = MeshServices::generateStatefulService(501, 3);
  plan.seedingPrefix = MeshServices::generateStatefulService(501, 4);
  plan.shardingPrefix = MeshServices::generateStatefulService(501, 5);
  return StatefulMeshRoles::forShardGroup(plan, 501, 7);
}

static CredentialDelta makeCredentialDelta(void)
{
  CredentialDelta delta;
  delta.bundleGeneration = 4321;
  delta.updatedTls.push_back(makeTlsIdentity());
  delta.removedTlsNames.push_back("old.internal"_ctv);
  delta.updatedApi.push_back(makeApiCredential());
  delta.removedApiNames.push_back("legacy_token"_ctv);
  delta.updatedResumptionSnapshots.push_back(makeTlsResumptionSnapshot());
  delta.removedResumptionWormholeNames.push_back("old-api-quic"_ctv);
  delta.reason.assign("rotation"_ctv);
  return delta;
}

static RoutableResourceLeaseReport makeRoutableResourceLeaseReport(void)
{
  RoutableResourceLeaseReport report = {};
  report.success = true;

  RoutableResourceLease lease = {};
  lease.kind = RoutableResourceLeaseKind::dnsRecord;
  lease.owner.applicationID = 501;
  lease.owner.deploymentID = 6001;
  lease.owner.lineageID = 7001;
  lease.owner.name.assign("api"_ctv);
  lease.registeredPrefixUUID = uint128_t(0x8888);
  lease.address = IPAddress("203.0.113.10", false);
  lease.dnsProvider.assign("cloudflare"_ctv);
  lease.dnsCredentialName.assign("cf-prod"_ctv);
  lease.dnsZone.assign("example.com"_ctv);
  lease.dnsName.assign("api.example.com"_ctv);
  lease.dnsType.assign("A"_ctv);
  lease.dnsTTL = 300;
  report.leases.push_back(std::move(lease));
  return report;
}

template <typename T, typename Equal>
static void expectWireRoundTrip(TestSuite& suite, const T& expected, const char *decodeName, const char *roundTripName, Equal equal)
{
  String encoded;
  BitseryEngine::serialize(encoded, expected);

  T decoded;
  suite.expect(BitseryEngine::deserializeSafe(encoded, decoded), decodeName);
  suite.expect(equal(expected, decoded), roundTripName);
}

int main(void)
{
  TestSuite suite;

  expectWireRoundTrip(suite, makeTlsResumptionKeyEpoch(9), "tls_resumption_key_epoch_decode_state", "tls_resumption_key_epoch_roundtrip_state", prodigyTlsResumptionKeyEpochsEqual);
  expectWireRoundTrip(suite, makeTlsResumptionSnapshot(), "tls_resumption_snapshot_decode_state", "tls_resumption_snapshot_roundtrip_state", prodigyTlsResumptionSnapshotsEqual);
  expectWireRoundTrip(suite, makeTlsResumptionApplyResult(), "tls_resumption_apply_result_decode_state", "tls_resumption_apply_result_roundtrip_state", equalTlsResumptionApplyResult);
  expectWireRoundTrip(suite, makeTlsIdentityApplyResult(), "tls_identity_apply_result_decode_state", "tls_identity_apply_result_roundtrip_state", equalTlsIdentityApplyResult);
  expectWireRoundTrip(suite, makeRoutableResourceLeaseReport(), "routable_resource_lease_report_decode_state", "routable_resource_lease_report_roundtrip_state", equalRoutableResourceLeaseReport);

  {
    ProdigyResumptionRegistry registry;
    TlsResumptionSnapshot snapshot = makeTlsResumptionSnapshot();
    TlsResumptionApplyResult applyResult = {};

    suite.expect(registry.applySnapshot(snapshot, &applyResult), "tls_resumption_registry_applies_valid_snapshot");
    suite.expect(
        applyResult.success &&
            applyResult.wormholeName.equal(snapshot.wormholeName) &&
            applyResult.generation == snapshot.generation &&
            applyResult.failureReason.empty(),
        "tls_resumption_registry_apply_result_has_no_secret_material");
    suite.expect(registry.snapshotsByWormhole.size() == 1, "tls_resumption_registry_stores_by_wormhole");

    const TlsResumptionSnapshot *found = registry.find(snapshot.wormholeName);
    suite.expect(found != nullptr && found->generation == snapshot.generation, "tls_resumption_registry_lookup_matches_bindings");

    const TlsResumptionKeyEpoch *issueKey = registry.currentIssueKey(snapshot.wormholeName, 111'002);
    suite.expect(issueKey != nullptr && issueKey->generation == snapshot.keyRing[1].generation, "tls_resumption_registry_selects_issue_key");

    bool crossThreadFound = false;
    std::thread lookupThread([&]() {
      const TlsResumptionKeyEpoch *threadIssueKey = registry.currentIssueKey(snapshot.wormholeName, 111'002);
      crossThreadFound = threadIssueKey != nullptr && threadIssueKey->generation == snapshot.keyRing[1].generation;
    });
    lookupThread.join();
    suite.expect(crossThreadFound, "tls_resumption_registry_lookup_is_thread_stable");

    const TlsResumptionKeyEpoch *acceptKey = registry.acceptKeyByID(
        snapshot.wormholeName,
        snapshot.keyRing[0].keyID,
        111'001);
    suite.expect(acceptKey != nullptr && acceptKey->generation == snapshot.keyRing[0].generation, "tls_resumption_registry_selects_accept_key_by_id");

    TlsResumptionSnapshot stale = snapshot;
    stale.generation -= 1;
    TlsResumptionApplyResult staleResult = {};
    suite.expect(registry.applySnapshot(stale, &staleResult) == false, "tls_resumption_registry_rejects_stale_generation");
    suite.expect(
        staleResult.success == false &&
            staleResult.failureReason.equal("stale generation"_ctv),
        "tls_resumption_registry_reports_stale_generation");

    TlsResumptionSnapshot invalid = snapshot;
    invalid.wormholeName.assign("invalid-secret"_ctv);
    invalid.generation += 1;
    for (uint8_t& byte : invalid.keyRing[0].masterSecret)
    {
      byte = 0;
    }
    TlsResumptionApplyResult invalidResult = {};
    suite.expect(registry.applySnapshot(invalid, &invalidResult) == false, "tls_resumption_registry_rejects_empty_secret");
    suite.expect(
        invalidResult.success == false &&
            invalidResult.failureReason.equal("epoch master secret required"_ctv),
        "tls_resumption_registry_reports_empty_secret");

    Vector<String> removedWormholeNames = {};
    removedWormholeNames.push_back(snapshot.wormholeName);
    const uint64_t removalGeneration = snapshot.generation + 2;
    Vector<TlsResumptionApplyResult> removalResults;
    suite.expect(registry.applyDelta({}, removedWormholeNames, removalGeneration, &removalResults), "tls_resumption_registry_applies_removal_delta");
    suite.expect(
        removalResults.size() == 1 &&
            removalResults[0].success &&
            removalResults[0].wormholeName.equal(snapshot.wormholeName) &&
            removalResults[0].generation == removalGeneration,
        "tls_resumption_registry_reports_removal_delta");
    suite.expect(registry.find(snapshot.wormholeName) == nullptr, "tls_resumption_registry_removes_wormhole");
  }

  {
    TlsResumptionApplyAck expected = makeTlsResumptionApplyAck();
    String encoded;
    suite.expect(ProdigyWire::serializeTlsResumptionApplyAck(encoded, expected), "tls_resumption_apply_ack_encode_wire");

    TlsResumptionApplyAck decoded;
    suite.expect(ProdigyWire::deserializeTlsResumptionApplyAck(encoded, decoded), "tls_resumption_apply_ack_decode_wire");
    suite.expect(
        decoded.results.size() == 1 &&
            equalTlsResumptionApplyResult(expected.results[0], decoded.results[0]),
        "tls_resumption_apply_ack_roundtrip_wire");

    String frame;
    suite.expect(
        ProdigyWire::constructPackedFrame(frame, ContainerTopic::credentialsRefresh, encoded),
        "tls_resumption_apply_ack_frame_encode_wire");
    Message *message = reinterpret_cast<Message *>(frame.data());

    suite.expect(
        ProdigyIngressValidation::validateContainerPayloadForNeuron(message->topic, message->args, message->terminal()),
        "tls_resumption_apply_ack_ack_valid_for_neuron");
    suite.expect(
        ProdigyIngressValidation::validateContainerPayloadForHub(message->topic, message->args, message->terminal()) == false,
        "tls_resumption_apply_ack_ack_not_valid_as_hub_delta");

    TlsResumptionApplyAck decodedFromFrame;
    suite.expect(
        ProdigyWire::deserializeTlsResumptionApplyAckFramePayload(message->args, uint64_t(message->terminal() - message->args), decodedFromFrame),
        "tls_resumption_apply_ack_frame_decode_wire");
    suite.expect(
        decodedFromFrame.results.size() == 1 &&
            equalTlsResumptionApplyResult(expected.results[0], decodedFromFrame.results[0]),
        "tls_resumption_apply_ack_frame_roundtrip_wire");
  }

  {
    CredentialApplyAck expected = makeCredentialApplyAck();
    String encoded;
    suite.expect(ProdigyWire::serializeCredentialApplyAck(encoded, expected), "credential_apply_ack_encode_wire");

    CredentialApplyAck decoded;
    suite.expect(ProdigyWire::deserializeCredentialApplyAck(encoded, decoded), "credential_apply_ack_decode_wire");
    suite.expect(equalCredentialApplyAck(expected, decoded), "credential_apply_ack_roundtrip_wire");

    String frame;
    suite.expect(
        ProdigyWire::constructPackedFrame(frame, ContainerTopic::credentialsRefresh, encoded),
        "credential_apply_ack_frame_encode_wire");
    Message *message = reinterpret_cast<Message *>(frame.data());

    suite.expect(
        ProdigyIngressValidation::validateContainerPayloadForNeuron(message->topic, message->args, message->terminal()),
        "credential_apply_ack_valid_for_neuron");
    suite.expect(
        ProdigyIngressValidation::validateContainerPayloadForHub(message->topic, message->args, message->terminal()) == false,
        "credential_apply_ack_not_valid_as_hub_delta");

    CredentialApplyAck decodedFromFrame;
    suite.expect(
        ProdigyWire::deserializeCredentialApplyAckFramePayload(message->args, uint64_t(message->terminal() - message->args), decodedFromFrame),
        "credential_apply_ack_frame_decode_wire");
    suite.expect(equalCredentialApplyAck(expected, decodedFromFrame), "credential_apply_ack_frame_roundtrip_wire");
  }

  {
    ContainerParameters expected = makeContainerParameters();
    String encoded;
    suite.expect(ProdigyWire::serializeContainerParameters(encoded, expected), "container_params_encode_wire");

    ContainerParameters decoded;
    suite.expect(ProdigyWire::deserializeContainerParameters(encoded, decoded), "container_params_decode_wire");
    suite.expect(equalContainerParameters(expected, decoded), "container_params_roundtrip_wire");
  }

  {
    ContainerParameters expected = makeContainerParameters();
    expected.wormholes.push_back(makeContainerParametersWormhole());

    String encoded;
    BitseryEngine::serialize(encoded, expected);
    int fd = Memfd::create("test.container.params"_ctv);
    suite.expect(fd >= 0 && Memfd::writeAll(fd, encoded), "container_params_full_payload_memfd_write");

    char fdText[32] = {};
    snprintf(fdText, sizeof(fdText), "%d", fd);
    setenv("PRODIGY_PARAMS_FD", fdText, 1);

    char arg0[] = "prodigy_wire_unit";
    char *argv[] = {arg0, nullptr};
    ContainerParameters decoded;
    suite.expect(
        ProdigyWire::readContainerParametersFromProcessArgs(1, argv, decoded),
        "container_params_process_args_decode_full_wormhole_payload");
    suite.expect(equalContainerParameters(expected, decoded), "container_params_process_args_full_wormhole_roundtrip");

    unsetenv("PRODIGY_PARAMS_FD");
    if (fd >= 0)
    {
      close(fd);
    }
  }

  {
    StatefulMeshRoles roles = makeStatefulMeshRoles();
    suite.expect(roles.classify(roles.client) == StatefulMeshRole::client, "stateful_mesh_roles_classify_client");
    suite.expect(roles.classify(roles.sibling) == StatefulMeshRole::sibling, "stateful_mesh_roles_classify_sibling");
    suite.expect(roles.classify(roles.cousin) == StatefulMeshRole::cousin, "stateful_mesh_roles_classify_cousin");
    suite.expect(roles.classify(roles.seeding) == StatefulMeshRole::seeding, "stateful_mesh_roles_classify_seeding");
    suite.expect(roles.classify(roles.sharding) == StatefulMeshRole::sharding, "stateful_mesh_roles_classify_sharding");
  }

  {
    CredentialBundle expected = makeContainerParameters().credentialBundle;
    String encoded;
    suite.expect(ProdigyWire::serializeCredentialBundle(encoded, expected), "credential_bundle_encode_wire");

    CredentialBundle decoded;
    suite.expect(ProdigyWire::deserializeCredentialBundle(encoded, decoded), "credential_bundle_decode_wire");
    suite.expect(equalCredentialBundle(expected, decoded), "credential_bundle_roundtrip_wire");

    CredentialBundle invalidRole = expected;
    invalidRole.tlsResumptionSnapshots[0].keyRing[0].role = TlsResumptionKeyRole(99);
    suite.expect(
        ProdigyWire::serializeCredentialBundle(encoded, invalidRole) == false,
        "credential_bundle_rejects_invalid_tls_resumption_key_role");
  }

  {
    CredentialDelta expected = makeCredentialDelta();
    String encoded;
    suite.expect(ProdigyWire::serializeCredentialDelta(encoded, expected), "credential_delta_encode_wire");

    CredentialDelta decoded;
    suite.expect(ProdigyWire::deserializeCredentialDelta(encoded, decoded), "credential_delta_decode_wire");
    suite.expect(equalCredentialDelta(expected, decoded), "credential_delta_roundtrip_wire");
  }

  {
    String encoded;
    suite.expect(
        ProdigyWire::serializeResourceDeltaPayload(encoded, uint16_t(4), uint32_t(1024), uint32_t(2048), true, uint32_t(30)),
        "resource_delta_encode_wire");

    uint16_t logicalCores = 0;
    uint32_t memoryMB = 0;
    uint32_t storageMB = 0;
    bool isDownscale = false;
    uint32_t graceSeconds = 0;
    suite.expect(
        ProdigyWire::deserializeResourceDeltaPayload(encoded.data(), encoded.size(), logicalCores, memoryMB, storageMB, isDownscale, graceSeconds),
        "resource_delta_decode_wire");
    suite.expect(
        logicalCores == 4 && memoryMB == 1024 && storageMB == 2048 && isDownscale && graceSeconds == 30,
        "resource_delta_roundtrip_wire");
  }

  {
    String encoded;
    suite.expect(
        ProdigyWire::serializeAdvertisementPairingPayload(
            encoded,
            uint128_t(0x101),
            uint128_t(0x202),
            0xABCD000000000111ULL,
            uint16_t(0xABCD),
            true),
        "advertisement_pairing_encode_wire");

    uint128_t secret = 0;
    uint128_t address = 0;
    uint64_t service = 0;
    uint16_t applicationID = 0;
    bool activate = false;
    suite.expect(
        ProdigyWire::deserializeAdvertisementPairingPayload(encoded.data(), encoded.size(), secret, address, service, applicationID, activate),
        "advertisement_pairing_decode_wire");
    suite.expect(
        secret == uint128_t(0x101) &&
            address == uint128_t(0x202) &&
            service == 0xABCD000000000111ULL &&
            applicationID == uint16_t(0xABCD) &&
            activate,
        "advertisement_pairing_roundtrip_wire");
  }

  {
    String encoded;
    suite.expect(
        ProdigyWire::serializeSubscriptionPairingPayload(
            encoded,
            uint128_t(0x505),
            uint128_t(0x606),
            0x4321000000000333ULL,
            uint16_t(19'111),
            uint16_t(0x4321),
            false),
        "subscription_pairing_encode_wire");

    uint128_t secret = 0;
    uint128_t address = 0;
    uint64_t service = 0;
    uint16_t port = 0;
    uint16_t applicationID = 0;
    bool activate = true;
    suite.expect(
        ProdigyWire::deserializeSubscriptionPairingPayload(encoded.data(), encoded.size(), secret, address, service, port, applicationID, activate),
        "subscription_pairing_decode_wire");
    suite.expect(
        secret == uint128_t(0x505) &&
            address == uint128_t(0x606) &&
            service == 0x4321000000000333ULL &&
            port == uint16_t(19'111) &&
            applicationID == uint16_t(0x4321) &&
            activate == false,
        "subscription_pairing_roundtrip_wire");
  }

  {
    CredentialDelta expected = makeCredentialDelta();
    String encoded;
    suite.expect(ProdigyWire::serializeCredentialDelta(encoded, expected), "credential_delta_frame_encode_wire_payload");

    String frame;
    suite.expect(
        ProdigyWire::constructPackedFrame(frame, ContainerTopic::credentialsRefresh, encoded),
        "credential_delta_frame_encode_wire");
    Message *message = reinterpret_cast<Message *>(frame.data());

    CredentialDelta decoded;
    suite.expect(
        ProdigyWire::deserializeCredentialDeltaFramePayload(message->args, uint64_t(message->terminal() - message->args), decoded),
        "credential_delta_frame_decode_wire");
    suite.expect(equalCredentialDelta(expected, decoded), "credential_delta_frame_roundtrip_wire");
  }

  return (suite.failed == 0) ? 0 : 1;
}
