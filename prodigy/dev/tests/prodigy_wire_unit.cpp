#include <prodigy/wire.h>
#include <services/debug.h>

#include <cstdio>
#include <unistd.h>

class TestSuite
{
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

static bool equalCredentialBundle(const CredentialBundle& lhs, const CredentialBundle& rhs)
{
   if (lhs.bundleGeneration != rhs.bundleGeneration ||
      lhs.tlsIdentities.size() != rhs.tlsIdentities.size() ||
      lhs.apiCredentials.size() != rhs.apiCredentials.size())
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
      lhs.reason.equal(rhs.reason) == false ||
      equalStringVector(lhs.removedTlsNames, rhs.removedTlsNames) == false ||
      equalStringVector(lhs.removedApiNames, rhs.removedApiNames) == false)
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
   return lhs.externalAddress.equals(rhs.externalAddress) &&
      lhs.externalPort == rhs.externalPort &&
      lhs.containerPort == rhs.containerPort &&
      lhs.layer4 == rhs.layer4 &&
      lhs.isQuic == rhs.isQuic &&
      lhs.userCapacity.minimum == rhs.userCapacity.minimum &&
      lhs.userCapacity.maximum == rhs.userCapacity.maximum &&
      lhs.hasQuicCidKeyState == rhs.hasQuicCidKeyState &&
      lhs.source == rhs.source &&
      lhs.routableAddressUUID == rhs.routableAddressUUID &&
      lhs.quicCidKeyState.rotationHours == rhs.quicCidKeyState.rotationHours &&
      lhs.quicCidKeyState.activeKeyIndex == rhs.quicCidKeyState.activeKeyIndex &&
      lhs.quicCidKeyState.rotatedAtMs == rhs.quicCidKeyState.rotatedAtMs &&
      lhs.quicCidKeyState.keyMaterialByIndex[0] == rhs.quicCidKeyState.keyMaterialByIndex[0] &&
      lhs.quicCidKeyState.keyMaterialByIndex[1] == rhs.quicCidKeyState.keyMaterialByIndex[1];
}

static bool equalContainerParameters(const ContainerParameters& lhs, const ContainerParameters& rhs)
{
   auto hasSubscriptionPairing = [](const ContainerParameters& parameters, const SubscriptionPairing& pairing)
   {
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

   auto hasAdvertisementPairing = [](const ContainerParameters& parameters, const AdvertisementPairing& pairing)
   {
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
   credential.sunsetAtMs = 1'111;
   credential.material.assign("secret-token"_ctv);
   credential.metadata.insert_or_assign("scope"_ctv, "sms"_ctv);
   credential.metadata.insert_or_assign("region"_ctv, "global"_ctv);
   return credential;
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
   parameters.advertisesOnPorts[0xABCDEF0000000001ULL] = 19111;
   parameters.advertisesOnPorts[0xABCDEF0000000002ULL] = 19112;
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
   return parameters;
}

static ContainerParameters makeLegacyContainerParametersWithIngress(void)
{
   ContainerParameters parameters = makeContainerParameters();

   Wormhole wormhole;
   wormhole.externalAddress = IPAddress("2602:fac0:0:12ab:34cd::1", true);
   wormhole.externalPort = 443;
   wormhole.containerPort = 443;
   wormhole.layer4 = IPPROTO_UDP;
   wormhole.isQuic = true;
   wormhole.userCapacity.minimum = 40'000;
   wormhole.userCapacity.maximum = 50'000;
   wormhole.hasQuicCidKeyState = true;
   wormhole.source = ExternalAddressSource::registeredRoutableAddress;
   wormhole.routableAddressUUID = uint128_t(0x1234567890ABCDEFULL);
   wormhole.routableAddressUUID <<= 64;
   wormhole.routableAddressUUID |= uint128_t(0x0FEDCBA098765432ULL);
   wormhole.quicCidKeyState.rotationHours = 24;
   wormhole.quicCidKeyState.activeKeyIndex = 1;
   wormhole.quicCidKeyState.rotatedAtMs = 123456789;
   wormhole.quicCidKeyState.keyMaterialByIndex[0] = uint128_t(0x0102030405060708ULL);
   wormhole.quicCidKeyState.keyMaterialByIndex[0] <<= 64;
   wormhole.quicCidKeyState.keyMaterialByIndex[0] |= uint128_t(0x1112131415161718ULL);
   wormhole.quicCidKeyState.keyMaterialByIndex[1] = uint128_t(0x2122232425262728ULL);
   wormhole.quicCidKeyState.keyMaterialByIndex[1] <<= 64;
   wormhole.quicCidKeyState.keyMaterialByIndex[1] |= uint128_t(0x3132333435363738ULL);
   parameters.wormholes.push_back(wormhole);

   Whitehole whitehole;
   whitehole.transport = ExternalAddressTransport::tcp;
   whitehole.family = ExternalAddressFamily::ipv6;
   whitehole.source = ExternalAddressSource::hostPublicAddress;
   whitehole.hasAddress = true;
   whitehole.address = IPAddress("2602:fac0:0:beef::7", true);
   whitehole.sourcePort = 8443;
   whitehole.bindingNonce = 77;
   parameters.whiteholes.push_back(whitehole);
   return parameters;
}

static StatefulMeshRoles makeStatefulMeshRoles(void)
{
   StatefulDeploymentPlan plan = {};
   plan.clientPrefix = MeshServices::generateStatefulService(501, 1);
   plan.siblingPrefix = MeshServices::generateStatefulService(501, 2);
   plan.cousinPrefix = MeshServices::generateStatefulService(501, 3);
   plan.seedingPrefix = MeshServices::generateStatefulService(501, 4);
   plan.shardingPrefix = MeshServices::generateStatefulService(501, 5);
   return StatefulMeshRoles::forShardGroup(plan, 7);
}

static CredentialDelta makeCredentialDelta(void)
{
   CredentialDelta delta;
   delta.bundleGeneration = 4321;
   delta.updatedTls.push_back(makeTlsIdentity());
   delta.removedTlsNames.push_back("old.internal"_ctv);
   delta.updatedApi.push_back(makeApiCredential());
   delta.removedApiNames.push_back("legacy_token"_ctv);
   delta.reason.assign("rotation"_ctv);
   return delta;
}

int main(void)
{
   TestSuite suite;

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
      String encoded;
      BitseryEngine::serialize(encoded, expected);

      ContainerParameters decoded;
      suite.expect(ProdigyWire::deserializeContainerParametersAuto(encoded, decoded), "container_params_decode_legacy");
      suite.expect(equalContainerParameters(expected, decoded), "container_params_roundtrip_legacy");
   }

   {
      ContainerParameters expected = makeLegacyContainerParametersWithIngress();
      String encoded;
      BitseryEngine::serialize(encoded, expected);

      ContainerParameters decoded;
      suite.expect(ProdigyWire::deserializeContainerParametersAuto(encoded, decoded), "container_params_decode_legacy_ingress");
      suite.expect(equalContainerParameters(expected, decoded), "container_params_roundtrip_legacy_ingress");
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
      ContainerParameters expected = makeContainerParameters();
      expected.statefulMeshRoles = makeStatefulMeshRoles();
      String encoded;
      BitseryEngine::serialize(encoded, expected);

      ContainerParameters decoded;
      suite.expect(ProdigyWire::deserializeContainerParametersAuto(encoded, decoded), "container_params_decode_legacy_stateful_mesh_roles");
      suite.expect(equalContainerParameters(expected, decoded), "container_params_roundtrip_legacy_stateful_mesh_roles");
   }

   {
      CredentialBundle expected = makeContainerParameters().credentialBundle;
      String encoded;
      suite.expect(ProdigyWire::serializeCredentialBundle(encoded, expected), "credential_bundle_encode_wire");

      CredentialBundle decoded;
      suite.expect(ProdigyWire::deserializeCredentialBundle(encoded, decoded), "credential_bundle_decode_wire");
      suite.expect(equalCredentialBundle(expected, decoded), "credential_bundle_roundtrip_wire");
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
      CredentialDelta expected = makeCredentialDelta();
      String encoded;
      BitseryEngine::serialize(encoded, expected);

      CredentialDelta decoded;
      suite.expect(ProdigyWire::deserializeCredentialDeltaAuto(encoded, decoded), "credential_delta_decode_legacy");
      suite.expect(equalCredentialDelta(expected, decoded), "credential_delta_roundtrip_legacy");
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
      String frame;
      Message::construct(frame, uint16_t(ContainerTopic::resourceDelta), uint16_t(6), uint32_t(4096), uint32_t(8192), false, uint32_t(45));
      Message *message = reinterpret_cast<Message *>(frame.data());

      uint16_t logicalCores = 0;
      uint32_t memoryMB = 0;
      uint32_t storageMB = 0;
      bool isDownscale = true;
      uint32_t graceSeconds = 0;
      suite.expect(
         ProdigyWire::deserializeResourceDeltaPayloadAuto(message->args, uint64_t(message->terminal() - message->args), logicalCores, memoryMB, storageMB, isDownscale, graceSeconds),
         "resource_delta_decode_legacy");
      suite.expect(
         logicalCores == 6 && memoryMB == 4096 && storageMB == 8192 && isDownscale == false && graceSeconds == 45,
         "resource_delta_roundtrip_legacy");
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
      String frame;
      Message::construct(
         frame,
         uint16_t(ContainerTopic::advertisementPairing),
         uint128_t(0x303),
         uint128_t(0x404),
         uint64_t(0x1234000000000222ULL),
         uint16_t(0x1234),
         true);
      Message *message = reinterpret_cast<Message *>(frame.data());

      uint128_t secret = 0;
      uint128_t address = 0;
      uint64_t service = 0;
      uint16_t applicationID = 0;
      bool activate = false;
      suite.expect(
         ProdigyWire::deserializeAdvertisementPairingPayloadAuto(message->args, uint64_t(message->terminal() - message->args), secret, address, service, applicationID, activate),
         "advertisement_pairing_decode_legacy");
      suite.expect(
         secret == uint128_t(0x303) &&
            address == uint128_t(0x404) &&
            service == 0x1234000000000222ULL &&
            applicationID == uint16_t(0x1234) &&
            activate,
         "advertisement_pairing_roundtrip_legacy");
   }

   {
      String encoded;
      suite.expect(
         ProdigyWire::serializeSubscriptionPairingPayload(
            encoded,
            uint128_t(0x505),
            uint128_t(0x606),
            0x4321000000000333ULL,
            uint16_t(19111),
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
            port == uint16_t(19111) &&
            applicationID == uint16_t(0x4321) &&
            activate == false,
         "subscription_pairing_roundtrip_wire");
   }

   {
      String frame;
      Message::construct(
         frame,
         uint16_t(ContainerTopic::subscriptionPairing),
         uint128_t(0x707),
         uint128_t(0x808),
         uint64_t(0x5678000000000444ULL),
         uint16_t(3210),
         uint16_t(0x5678),
         true);
      Message *message = reinterpret_cast<Message *>(frame.data());

      uint128_t secret = 0;
      uint128_t address = 0;
      uint64_t service = 0;
      uint16_t port = 0;
      uint16_t applicationID = 0;
      bool activate = false;
      suite.expect(
         ProdigyWire::deserializeSubscriptionPairingPayloadAuto(message->args, uint64_t(message->terminal() - message->args), secret, address, service, port, applicationID, activate),
         "subscription_pairing_decode_legacy");
      suite.expect(
         secret == uint128_t(0x707) &&
            address == uint128_t(0x808) &&
            service == 0x5678000000000444ULL &&
            port == uint16_t(3210) &&
            applicationID == uint16_t(0x5678) &&
            activate,
         "subscription_pairing_roundtrip_legacy");
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
         ProdigyWire::deserializeCredentialDeltaFramePayloadAuto(message->args, uint64_t(message->terminal() - message->args), decoded),
         "credential_delta_frame_decode_wire");
      suite.expect(equalCredentialDelta(expected, decoded), "credential_delta_frame_roundtrip_wire");
   }

   {
      CredentialDelta expected = makeCredentialDelta();
      String encoded;
      suite.expect(ProdigyWire::serializeCredentialDelta(encoded, expected), "credential_delta_frame_encode_legacy_payload");

      String frame;
      Message::construct(frame, uint16_t(ContainerTopic::credentialsRefresh), encoded);
      Message *message = reinterpret_cast<Message *>(frame.data());

      CredentialDelta decoded;
      suite.expect(
         ProdigyWire::deserializeCredentialDeltaFramePayloadAuto(message->args, uint64_t(message->terminal() - message->args), decoded),
         "credential_delta_frame_decode_legacy");
      suite.expect(equalCredentialDelta(expected, decoded), "credential_delta_frame_roundtrip_legacy");
   }

   return (suite.failed == 0) ? 0 : 1;
}
