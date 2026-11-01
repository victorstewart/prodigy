#include <prodigy/pair.private.bgp.secret.h>
#include <cstdio>

static int failures = 0;
static void expect(bool value, const char *message)
{ if (!value) { std::fprintf(stderr, "FAIL: %s\n", message); ++failures; } }

int main()
{
  ProdigyPairPrivateBGPSecretScope scope = {};
  scope.pairUUID = 1; scope.operationUUID = 2; scope.keyEpoch = 3; scope.tunnelSlot = 1;
  scope.clusterUUID = 4; scope.machineUUID = 5; scope.authorityGeneration = 6; scope.gatewayGeneration = 7;
  uint8_t enrollmentRoot[ProdigyClusterPairEnrollmentRootBytes] = {}; enrollmentRoot[0] = 9;
  MothershipPairPrivateBGPVault vault = {}; String digest = {}, secondDigest = {}, localIdentity = {}, peerIdentity = {}, trustIdentity = {};
  const IPAddress listenerEndpoint("203.0.113.10", false);
  expect(vault.configurePairRoot(enrollmentRoot), "derive vault key from persistent enrollment root");
  expect(vault.mintAfterActiveEnrollment(scope, 8, 5, listenerEndpoint, digest, localIdentity, peerIdentity, trustIdentity), "mint encrypted pair credential and TLS material");
  expect(digest.size() == 64 && localIdentity.size() == 64 && peerIdentity.size() == 64 && trustIdentity.size() == 64 &&
             vault.mintAfterActiveEnrollment(scope, 8, 5, listenerEndpoint, secondDigest, localIdentity, peerIdentity, trustIdentity) && digest == secondDigest,
         "resume returns existing digest without reminting");
  ProdigyPairPrivateBGPSecretDeliveryRequest request = {};
  request.scope = scope; request.controlIdentitySHA256.assign("identity"_ctv);
  ProdigyPairPrivateBGPSecretDeliveryResponse response = {};
  expect(vault.deliver(request, "identity"_ctv, digest, response), "exact scope delivery");
  expect(response.accepted && response.credential.size() == 32 && response.credential != digest &&
             !response.gatewayRootCertPem.empty() && !response.localLeafCertPem.empty() && !response.localLeafKeyPem.empty() && !response.peerLeafCertDERHex.empty(),
         "delivery has private BGP and gateway TLS material rather than public digests");
  CrossClusterMasqueGatewayAuthority authority = {};
  authority.pairUUID = scope.pairUUID; authority.pairOperationUUID = scope.operationUUID;
  authority.localClusterUUID = scope.clusterUUID; authority.peerClusterUUID = 6;
  authority.localMachineUUID = scope.machineUUID; authority.peerMachineUUID = 8;
  authority.localDatacenterFragment = 1; authority.peerDatacenterFragment = 2;
  authority.localSitePrefix = prodigyContainerDatacenterSitePrefix(authority.localDatacenterFragment);
  authority.peerSitePrefix = prodigyContainerDatacenterSitePrefix(authority.peerDatacenterFragment);
  authority.artifactSHA256.assign("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv); authority.artifactBytes = 1;
  authority.listenerPublicUDPEndpoint = listenerEndpoint; authority.listenerPublicUDPPort = 443;
  authority.tunnelSlot = scope.tunnelSlot; authority.gatewaySlot = 1; authority.privateTunnelInterface.assign("masque1"_ctv);
  authority.privateTunnelLocalIPv6 = IPAddress("fd00::1", true); authority.privateTunnelPeerIPv6 = IPAddress("fd00::2", true);
  authority.privateLocalASN = 64512; authority.privatePeerASN = 64513; authority.privateLocalBGPID = 1; authority.privatePeerBGPID = 2;
  authority.privateSessionCredentialSHA256 = digest; authority.localIdentitySHA256 = localIdentity; authority.peerIdentitySHA256 = peerIdentity;
  authority.peerTrustSHA256 = trustIdentity; authority.generation = scope.gatewayGeneration;
  authority.pairAuthorityGeneration = scope.authorityGeneration; authority.keyGeneration = scope.keyEpoch;
  authority.localRole = CrossClusterMasqueGatewayRole::listener; authority.state = CrossClusterMasqueGatewayState::active;
  expect(prodigyPairPrivateGatewayTLSMaterialMatchesAuthority(authority, response.gatewayRootCertPem,
             response.localLeafCertPem, response.localLeafKeyPem, response.peerLeafCertDERHex),
         "gateway TLS material matches leaf DER hashes CA trust listener SAN and local key");
  auto wrongPeer = authority; wrongPeer.peerMachineUUID = 9;
  expect(!prodigyPairPrivateGatewayTLSMaterialMatchesAuthority(wrongPeer, response.gatewayRootCertPem,
             response.localLeafCertPem, response.localLeafKeyPem, response.peerLeafCertDERHex), "gateway TLS rejects wrong peer certificate identity");
  auto wrongHash = authority; wrongHash.localIdentitySHA256.assign("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"_ctv);
  expect(!prodigyPairPrivateGatewayTLSMaterialMatchesAuthority(wrongHash, response.gatewayRootCertPem,
             response.localLeafCertPem, response.localLeafKeyPem, response.peerLeafCertDERHex), "gateway TLS rejects wrong authority DER hash");
  auto wrongEndpoint = authority; wrongEndpoint.listenerPublicUDPEndpoint = IPAddress("203.0.113.11", false);
  expect(!prodigyPairPrivateGatewayTLSMaterialMatchesAuthority(wrongEndpoint, response.gatewayRootCertPem,
             response.localLeafCertPem, response.localLeafKeyPem, response.peerLeafCertDERHex), "gateway TLS rejects listener endpoint SAN mismatch");
  auto peerScope = scope; peerScope.clusterUUID = 6; peerScope.machineUUID = 8;
  String peerLocalIdentity = {}, peerPeerIdentity = {}, peerTrustIdentity = {};
  expect(vault.mintAfterActiveEnrollment(peerScope, scope.machineUUID, scope.machineUUID, listenerEndpoint,
             secondDigest, peerLocalIdentity, peerPeerIdentity, peerTrustIdentity), "mint authorizes reciprocal machine delivery");
  ProdigyPairPrivateBGPSecretDeliveryRequest peerRequest = {}; peerRequest.scope = peerScope; peerRequest.controlIdentitySHA256.assign("peer-identity"_ctv);
  ProdigyPairPrivateBGPSecretDeliveryResponse peerResponse = {};
  expect(vault.deliver(peerRequest, "peer-identity"_ctv, digest, peerResponse), "reciprocal machine receives the same pair slot material");
  expect(!prodigyPairPrivateGatewayTLSMaterialMatchesAuthority(authority, response.gatewayRootCertPem,
             response.localLeafCertPem, peerResponse.localLeafKeyPem, response.peerLeafCertDERHex),
         "gateway TLS rejects a valid but wrong local key");
  auto reciprocal = authority; reciprocal.localClusterUUID = authority.peerClusterUUID; reciprocal.peerClusterUUID = authority.localClusterUUID;
  reciprocal.localMachineUUID = authority.peerMachineUUID; reciprocal.peerMachineUUID = authority.localMachineUUID;
  reciprocal.localDatacenterFragment = authority.peerDatacenterFragment; reciprocal.peerDatacenterFragment = authority.localDatacenterFragment;
  reciprocal.localSitePrefix = authority.peerSitePrefix; reciprocal.peerSitePrefix = authority.localSitePrefix;
  reciprocal.localIdentitySHA256 = authority.peerIdentitySHA256; reciprocal.peerIdentitySHA256 = authority.localIdentitySHA256;
  reciprocal.localRole = CrossClusterMasqueGatewayRole::connector;
  expect(prodigyPairPrivateGatewayTLSMaterialMatchesAuthority(reciprocal, peerResponse.gatewayRootCertPem,
             peerResponse.localLeafCertPem, peerResponse.localLeafKeyPem, peerResponse.peerLeafCertDERHex),
         "reciprocal delivery swaps exact local and peer certificate identities");
  Vault::secureClearString(response.credential);
  Vector<MothershipPairPrivateBGPVault::Record> persisted = {}; vault.exportRecords(persisted);
  MothershipPairPrivateBGPVault reopened = {};
  expect(reopened.configurePairRoot(enrollmentRoot) && reopened.importRecords(persisted), "rehydrate encrypted vault record");
  expect(reopened.deliver(request, "identity"_ctv, digest, response) && response.credential.size() == 32,
         "rehydrated vault delivers exact scope");
  Vault::secureClearString(response.credential);
  auto reactivatedScope = scope; reactivatedScope.gatewayGeneration += 2;
  MothershipPairPrivateBGPVault generationAdvance = {};
  expect(generationAdvance.configurePairRoot(enrollmentRoot) && generationAdvance.importRecords(persisted) &&
             generationAdvance.acknowledgeRevocation(scope) &&
             generationAdvance.acknowledgeRevocation(peerScope) &&
             generationAdvance.mintAfterActiveEnrollment(reactivatedScope, 8, 5, listenerEndpoint,
                 secondDigest, localIdentity, peerIdentity, trustIdentity),
         "new local gateway generation replaces its acknowledged delivery half");
  Vector<MothershipPairPrivateBGPVault::Record> advanced = {};
  generationAdvance.exportRecords(advanced);
  expect(advanced.size() == 1 && advanced[0].authorizedDeliveries.size() == 2 &&
             !generationAdvance.revocationAcknowledged(reactivatedScope) &&
             generationAdvance.revocationAcknowledged(peerScope) &&
             !generationAdvance.acknowledgeRevocation(scope) &&
             !generationAdvance.deleteAfterBothRevocationAcknowledgements(reactivatedScope),
         "generation replacement keeps two halves and resets only its acknowledgement");
  expect(generationAdvance.mintAfterActiveEnrollment(reactivatedScope, 8, 5, listenerEndpoint,
             secondDigest, localIdentity, peerIdentity, trustIdentity) && secondDigest == digest,
         "exact current generation mint remains idempotent");
  auto regressedGateway = reactivatedScope;
  ++regressedGateway.authorityGeneration; --regressedGateway.gatewayGeneration;
  auto regressedAuthority = reactivatedScope;
  --regressedAuthority.authorityGeneration; ++regressedAuthority.gatewayGeneration;
  expect(!generationAdvance.mintAfterActiveEnrollment(regressedGateway, 8, 5, listenerEndpoint,
             secondDigest, localIdentity, peerIdentity, trustIdentity) &&
             !generationAdvance.mintAfterActiveEnrollment(regressedAuthority, 8, 5, listenerEndpoint,
             secondDigest, localIdentity, peerIdentity, trustIdentity),
         "generation advancement cannot regress either authority or gateway generation");
  auto persistedWithSupersededLocalHalf = persisted;
  persistedWithSupersededLocalHalf[0].authorizedDeliveries.push_back(reactivatedScope);
  persistedWithSupersededLocalHalf[0].localAck = true;
  persistedWithSupersededLocalHalf[0].peerAck = true;
  String encodedPersisted = {};
  BitseryEngine::serialize(encodedPersisted, persistedWithSupersededLocalHalf[0]);
  MothershipPairPrivateBGPVault::Record decodedPersisted = {};
  expect(BitseryEngine::deserializeSafe(encodedPersisted, decodedPersisted) &&
             decodedPersisted.authorizedDeliveries.size() == 3,
         "bounded compatibility decoder reads one superseded local delivery");
  MothershipPairPrivateBGPVault recoveredGeneration = {};
  Vector<MothershipPairPrivateBGPVault::Record> decodedRecords = {};
  decodedRecords.push_back(std::move(decodedPersisted));
  expect(recoveredGeneration.configurePairRoot(enrollmentRoot) && recoveredGeneration.importRecords(decodedRecords),
         "rehydration canonicalizes superseded delivery generation");
  Vector<MothershipPairPrivateBGPVault::Record> canonical = {};
  recoveredGeneration.exportRecords(canonical);
  expect(canonical.size() == 1 && canonical[0].authorizedDeliveries.size() == 2 &&
             std::any_of(canonical[0].authorizedDeliveries.begin(), canonical[0].authorizedDeliveries.end(), [&](const auto& value) {
               return prodigyPairPrivateBGPSecretScopeEqual(value, reactivatedScope);
             }), "canonical export retains exactly the current local and peer halves");
  encodedPersisted.clear(); BitseryEngine::serialize(encodedPersisted, canonical[0]);
  MothershipPairPrivateBGPVault::Record roundTrippedCanonical = {};
  expect(BitseryEngine::deserializeSafe(encodedPersisted, roundTrippedCanonical) &&
             roundTrippedCanonical.authorizedDeliveries.size() == 2,
         "canonical two-half export round trips after compatibility repair");
  request.scope = reactivatedScope;
  expect(recoveredGeneration.deliver(request, "identity"_ctv, digest, response) && response.credential.size() == 32,
         "canonical generation delivers current local half");
  Vault::secureClearString(response.credential);
  request.scope = scope;
  expect(!recoveredGeneration.deliver(request, "identity"_ctv, digest, response),
         "superseded local generation cannot receive current credential");
  expect(!recoveredGeneration.revocationAcknowledged(reactivatedScope),
         "superseded local ACK cannot acknowledge current local generation");
  expect(recoveredGeneration.revocationAcknowledged(peerScope) &&
             !recoveredGeneration.deleteAfterBothRevocationAcknowledgements(reactivatedScope),
         "canonical repair preserves the peer ACK without deleting the unacknowledged new local scope");
  auto thirdHalf = peerScope; thirdHalf.clusterUUID = 10; thirdHalf.machineUUID = 11;
  auto invalidHalves = canonical; invalidHalves[0].authorizedDeliveries.push_back(thirdHalf);
  MothershipPairPrivateBGPVault invalidImport = {};
  expect(!invalidImport.importRecords(invalidHalves), "compatibility decoder cannot authorize a third machine half");
  expect(recoveredGeneration.acknowledgeRevocation(reactivatedScope) &&
             recoveredGeneration.revocationAcknowledged(reactivatedScope) &&
             recoveredGeneration.acknowledgeRevocation(peerScope) &&
             recoveredGeneration.deleteAfterBothRevocationAcknowledgements(reactivatedScope),
         "current generation halves acknowledge and delete the canonical record");
  request.scope.machineUUID += 1;
  expect(!vault.deliver(request, "identity"_ctv, digest, response), "wrong half rejected by caller scope");
  request.scope = scope; request.scope.gatewayGeneration += 1;
  expect(!vault.deliver(request, "identity"_ctv, digest, response), "wrong generation rejected by caller scope");
  ProdigyCrossClusterMasqueGatewayReadinessQuery readinessQuery = {}; readinessQuery.scope = scope;
  String encoded = {}; BitseryEngine::serialize(encoded, readinessQuery);
  ProdigyCrossClusterMasqueGatewayReadinessQuery decodedReadinessQuery = {};
  expect(BitseryEngine::deserializeSafe(encoded, decodedReadinessQuery) && prodigyPairPrivateBGPSecretScopeEqual(decodedReadinessQuery.scope, scope),
         "readiness query round trips exact full scope");
  ProdigyCrossClusterPrivateBGPReadiness privateReadiness = {};
  privateReadiness.scope = scope; privateReadiness.peerMachineUUID = 8;
  privateReadiness.localSitePrefix = IPPrefix("fd5a:4d53:1::", true, 96);
  privateReadiness.peerSitePrefix = IPPrefix("fd5a:4d53:2::", true, 96);
  privateReadiness.localSitePrefixAnnounced = true; privateReadiness.sessionEstablished = true;
  privateReadiness.peerSitePrefixImported = true; privateReadiness.switchboardFallbackInstalled = true;
  expect(prodigyCrossClusterPrivateBGPReady(privateReadiness),
         "private BGP readiness requires announcement session import and route");
  auto missingImport = privateReadiness; missingImport.peerSitePrefixImported = false;
  expect(!prodigyCrossClusterPrivateBGPReady(missingImport),
         "private BGP readiness rejects MASQUE-only path");
  ProdigyCrossClusterMasqueGatewayReadinessResponse readinessResponse = {};
  readinessResponse.success = true; readinessResponse.privateBGPFound = true;
  readinessResponse.privateBGPReceipt = privateReadiness;
  encoded.clear(); BitseryEngine::serialize(encoded, readinessResponse);
  ProdigyCrossClusterMasqueGatewayReadinessResponse decodedReadinessResponse = {};
  expect(BitseryEngine::deserializeSafe(encoded, decodedReadinessResponse) &&
             decodedReadinessResponse.protocolVersion == ProdigyCrossClusterMasqueGatewayReadinessResponse::version &&
             decodedReadinessResponse.privateBGPFound &&
             prodigyCrossClusterPrivateBGPReady(decodedReadinessResponse.privateBGPReceipt),
         "combined MASQUE and private BGP response round trips bounded routing proof");
  ProdigyCrossClusterPrivateBGPWithdrawalReceiptQuery withdrawalQuery = {}; withdrawalQuery.scope = scope;
  encoded.clear(); BitseryEngine::serialize(encoded, withdrawalQuery);
  ProdigyCrossClusterPrivateBGPWithdrawalReceiptQuery decodedWithdrawalQuery = {};
  expect(BitseryEngine::deserializeSafe(encoded, decodedWithdrawalQuery) && prodigyPairPrivateBGPSecretScopeEqual(decodedWithdrawalQuery.scope, scope),
         "withdrawal query round trips exact scope");
  encoded.resize(encoded.size() - 1);
  expect(!BitseryEngine::deserializeSafe(encoded, decodedWithdrawalQuery), "withdrawal query rejects truncated scope");
  expect(reopened.acknowledgeRevocation(scope), "first half acknowledges");
  expect(reopened.revocationAcknowledged(scope), "persisted first-half acknowledgement supports retry");
  expect(!reopened.deleteAfterBothRevocationAcknowledgements(scope), "first ACK cannot delete");
  expect(!reopened.acknowledgeRevocation(request.scope), "unenrolled ACK scope is rejected");
  expect(reopened.acknowledgeRevocation(peerScope) &&
         reopened.deleteAfterBothRevocationAcknowledgements(scope), "two authenticated enrolled halves delete encrypted record");
  return failures == 0 ? 0 : 1;
}
