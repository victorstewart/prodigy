#pragma once

// This is deliberately a Mothership/Vault boundary.  The pair authority is a
// public, durable descriptor and carries only credentialDigest; neither Brain
// snapshots nor the descriptor codec can acquire the BGP password.

#include <array>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <prodigy/types.h>
#include <prodigy/transport.tls.h>

static inline bool prodigyPairPrivateBGPSecretScopeValid(const ProdigyPairPrivateBGPSecretScope& scope)
{
  return scope.pairUUID != 0 && scope.operationUUID != 0 && scope.keyEpoch != 0 && scope.tunnelSlot < 3 &&
      scope.clusterUUID != 0 && scope.machineUUID != 0 && scope.authorityGeneration != 0 && scope.gatewayGeneration != 0;
}

static inline bool prodigyPairPrivateBGPSecretScopeEqual(const ProdigyPairPrivateBGPSecretScope& a,
                                                          const ProdigyPairPrivateBGPSecretScope& b)
{
  return a.pairUUID == b.pairUUID && a.operationUUID == b.operationUUID &&
      a.keyEpoch == b.keyEpoch && a.tunnelSlot == b.tunnelSlot &&
      a.clusterUUID == b.clusterUUID && a.machineUUID == b.machineUUID &&
      a.authorityGeneration == b.authorityGeneration &&
      a.gatewayGeneration == b.gatewayGeneration;
}

static inline bool prodigyPairPrivateCertificateDER(
    X509 *certificate, String& der, String& sha256, String *failure = nullptr)
{
  der.clear(); sha256.clear();
  const int length = certificate == nullptr ? 0 : i2d_X509(certificate, nullptr);
  if (length <= 0) { if (failure) failure->assign("pair private gateway certificate DER encoding failed"_ctv); return false; }
  der.reserve(uint64_t(length));
  unsigned char *cursor = reinterpret_cast<unsigned char *>(der.pTail());
  if (i2d_X509(certificate, &cursor) != length) { der.clear(); if (failure) failure->assign("pair private gateway certificate DER serialization failed"_ctv); return false; }
  der.advance(uint64_t(length));
  if (!prodigyComputeSHA256Hex(der, sha256)) { Vault::secureClearString(der); if (failure) failure->assign("pair private gateway certificate hash failed"_ctv); return false; }
  return true;
}

static inline bool prodigyPairPrivateHexEncode(const String& bytes, String& output)
{
  output.reserve(bytes.size() * 2);
  static constexpr char digits[] = "0123456789abcdef";
  for (uint64_t i = 0; i < bytes.size(); ++i) {
    const uint8_t byte = uint8_t(bytes.data()[i]);
    output.append(digits[byte >> 4]); output.append(digits[byte & 15]);
  }
  return output.size() == bytes.size() * 2;
}

static inline bool prodigyPairPrivateHexDecode(const String& input, String& output)
{
  output.clear();
  if (input.empty() || (input.size() & 1u) != 0) return false;
  const auto digit = [](char value) -> int {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
  };
  output.reserve(input.size() / 2);
  for (uint64_t i = 0; i < input.size(); i += 2) {
    const int high = digit(input.data()[i]), low = digit(input.data()[i + 1]);
    if (high < 0 || low < 0) { Vault::secureClearString(output); return false; }
    output.append(char((high << 4) | low));
  }
  return true;
}

static inline bool prodigyPairPrivateGatewayTLSMaterialMatchesAuthority(
    const CrossClusterMasqueGatewayAuthority& authority, const String& gatewayRootCertPem,
    const String& localLeafCertPem, const String& localLeafKeyPem,
    const String& peerLeafCertDERHex, String *failure = nullptr)
{
  if (!prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(authority) || gatewayRootCertPem.empty() ||
      localLeafCertPem.empty() || localLeafKeyPem.empty() || peerLeafCertDERHex.empty())
    { if (failure) failure->assign("pair private gateway TLS material is incomplete"_ctv); return false; }
  X509 *root = VaultPem::x509FromPem(gatewayRootCertPem);
  X509 *local = VaultPem::x509FromPem(localLeafCertPem);
  EVP_PKEY *localKey = VaultPem::privateKeyFromPem(localLeafKeyPem);
  String peerDER = {}; X509 *peer = nullptr; EVP_PKEY *rootKey = nullptr;
  bool valid = root != nullptr && local != nullptr && localKey != nullptr && prodigyPairPrivateHexDecode(peerLeafCertDERHex, peerDER);
  const unsigned char *cursor = valid ? reinterpret_cast<const unsigned char *>(peerDER.data()) : nullptr;
  if (valid) peer = d2i_X509(nullptr, &cursor, long(peerDER.size()));
  if (valid) rootKey = X509_get_pubkey(root);
  String rootDER = {}, localDER = {}, peerDERActual = {}, rootSHA = {}, localSHA = {}, peerSHA = {};
  uint128_t localUUID = 0, peerUUID = 0;
  valid = valid && peer != nullptr && cursor == reinterpret_cast<const unsigned char *>(peerDER.data() + peerDER.size()) &&
      rootKey != nullptr && X509_check_ca(root) > 0 &&
      X509_cmp_current_time(X509_get0_notBefore(root)) <= 0 && X509_cmp_current_time(X509_get0_notAfter(root)) >= 0 &&
      X509_check_private_key(local, localKey) == 1 &&
      X509_check_issued(root, local) == X509_V_OK && X509_check_issued(root, peer) == X509_V_OK &&
      X509_verify(local, rootKey) == 1 && X509_verify(peer, rootKey) == 1 &&
      X509_cmp_current_time(X509_get0_notBefore(local)) <= 0 && X509_cmp_current_time(X509_get0_notAfter(local)) >= 0 &&
      X509_cmp_current_time(X509_get0_notBefore(peer)) <= 0 && X509_cmp_current_time(X509_get0_notAfter(peer)) >= 0 &&
      Vault::extractTransportCertificateUUID(local, localUUID) && Vault::extractTransportCertificateUUID(peer, peerUUID) &&
      localUUID == authority.localMachineUUID && peerUUID == authority.peerMachineUUID &&
      prodigyPairPrivateCertificateDER(root, rootDER, rootSHA, failure) &&
      prodigyPairPrivateCertificateDER(local, localDER, localSHA, failure) &&
      prodigyPairPrivateCertificateDER(peer, peerDERActual, peerSHA, failure) &&
      localSHA == authority.localIdentitySHA256 && peerSHA == authority.peerIdentitySHA256 && rootSHA == authority.peerTrustSHA256;
  if (valid) {
    char endpoint[INET6_ADDRSTRLEN] = {};
    X509 *listener = authority.localRole == CrossClusterMasqueGatewayRole::listener ? local : peer;
    valid = inet_ntop(authority.listenerPublicUDPEndpoint.is6 ? AF_INET6 : AF_INET,
        authority.listenerPublicUDPEndpoint.v6, endpoint, sizeof(endpoint)) != nullptr && X509_check_ip_asc(listener, endpoint, 0) == 1;
  }
  if (rootKey) EVP_PKEY_free(rootKey); if (peer) X509_free(peer); if (localKey) EVP_PKEY_free(localKey);
  if (local) X509_free(local); if (root) X509_free(root);
  Vault::secureClearString(peerDER); Vault::secureClearString(rootDER); Vault::secureClearString(localDER); Vault::secureClearString(peerDERActual);
  if (!valid && failure && failure->empty()) failure->assign("pair private gateway TLS material does not match authority"_ctv);
  return valid;
}

// These live-receipt codecs deliberately carry the complete delivery scope.
// A pair or machine match alone could otherwise accept a stale key rotation.
class ProdigyCrossClusterMasqueGatewayReadinessQuery { public: static constexpr uint32_t version = 1; uint32_t protocolVersion = version; ProdigyPairPrivateBGPSecretScope scope; };
template <typename S> static void serialize(S&& s, ProdigyCrossClusterMasqueGatewayReadinessQuery& value) { s.value4b(value.protocolVersion); s.object(value.scope); }

// A MASQUE process receipt proves only the authenticated QUIC underlay.  This
// second, Neuron-owned receipt proves that the private routing plane actually
// became usable for the same immutable authority tuple.  It is volatile live
// evidence; neither Brain snapshots nor Mothership's durable pair authority
// acquire it as a source of truth.
class ProdigyCrossClusterPrivateBGPReadiness {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  ProdigyPairPrivateBGPSecretScope scope;
  uint128_t peerMachineUUID = 0;
  IPPrefix localSitePrefix = {};
  IPPrefix peerSitePrefix = {};
  bool localSitePrefixAnnounced = false;
  bool sessionEstablished = false;
  bool peerSitePrefixImported = false;
  bool switchboardFallbackInstalled = false;
};
template <typename S> static void serialize(S&& s, ProdigyCrossClusterPrivateBGPReadiness& value)
{
  s.value4b(value.protocolVersion); s.object(value.scope); s.value16b(value.peerMachineUUID);
  s.object(value.localSitePrefix); s.object(value.peerSitePrefix);
  s.value1b(value.localSitePrefixAnnounced); s.value1b(value.sessionEstablished);
  s.value1b(value.peerSitePrefixImported); s.value1b(value.switchboardFallbackInstalled);
}

static inline bool prodigyCrossClusterPrivateBGPReadinessValid(
    const ProdigyCrossClusterPrivateBGPReadiness& value)
{
  return value.protocolVersion == ProdigyCrossClusterPrivateBGPReadiness::version &&
      prodigyPairPrivateBGPSecretScopeValid(value.scope) && value.peerMachineUUID != 0 &&
      value.peerMachineUUID != value.scope.machineUUID && value.localSitePrefix.network.is6 &&
      value.localSitePrefix.cidr == 96 && value.localSitePrefix.equals(value.localSitePrefix.canonicalized()) &&
      value.peerSitePrefix.network.is6 && value.peerSitePrefix.cidr == 96 &&
      value.peerSitePrefix.equals(value.peerSitePrefix.canonicalized()) &&
      !value.localSitePrefix.equals(value.peerSitePrefix) &&
      (!value.peerSitePrefixImported || value.sessionEstablished) &&
      (!value.switchboardFallbackInstalled ||
          (value.localSitePrefixAnnounced && value.sessionEstablished && value.peerSitePrefixImported));
}

static inline bool prodigyCrossClusterPrivateBGPReady(
    const ProdigyCrossClusterPrivateBGPReadiness& value)
{
  return prodigyCrossClusterPrivateBGPReadinessValid(value) && value.localSitePrefixAnnounced &&
      value.sessionEstablished && value.peerSitePrefixImported && value.switchboardFallbackInstalled;
}

static inline bool prodigyCrossClusterPrivateBGPReadinessMatchesAuthority(
    const ProdigyCrossClusterPrivateBGPReadiness& value,
    const CrossClusterMasqueGatewayAuthority& authority)
{
  return prodigyCrossClusterPrivateBGPReadinessValid(value) &&
      prodigyCrossClusterMasqueGatewayAuthorityStructurallyValid(authority) &&
      authority.state == CrossClusterMasqueGatewayState::active &&
      value.scope.pairUUID == authority.pairUUID &&
      value.scope.operationUUID == authority.pairOperationUUID &&
      value.scope.keyEpoch == authority.keyGeneration &&
      value.scope.tunnelSlot == authority.tunnelSlot &&
      value.scope.clusterUUID == authority.localClusterUUID &&
      value.scope.machineUUID == authority.localMachineUUID &&
      value.scope.authorityGeneration == authority.pairAuthorityGeneration &&
      value.scope.gatewayGeneration == authority.generation &&
      value.peerMachineUUID == authority.peerMachineUUID &&
      value.localSitePrefix.equals(authority.localSitePrefix) &&
      value.peerSitePrefix.equals(authority.peerSitePrefix);
}

class ProdigyCrossClusterMasqueGatewayReadinessResponse : public MothershipResponse {
public:
  static constexpr uint32_t version = 2;
  uint32_t protocolVersion = version;
  bool found = false;
  ProdigyCrossClusterMasqueGatewayReadiness receipt;
  bool privateBGPFound = false;
  ProdigyCrossClusterPrivateBGPReadiness privateBGPReceipt;
};
template <typename S> static void serialize(S&& s, ProdigyCrossClusterMasqueGatewayReadinessResponse& value)
{
  s.value4b(value.protocolVersion); s.value1b(value.success); s.text1b(value.failure, 1024);
  s.value1b(value.found); s.object(value.receipt); s.value1b(value.privateBGPFound);
  s.object(value.privateBGPReceipt);
}
class ProdigyCrossClusterPrivateBGPWithdrawalReceiptQuery { public: static constexpr uint32_t version = 1; uint32_t protocolVersion = version; ProdigyPairPrivateBGPSecretScope scope; };
template <typename S> static void serialize(S&& s, ProdigyCrossClusterPrivateBGPWithdrawalReceiptQuery& value) { s.value4b(value.protocolVersion); s.object(value.scope); }
class ProdigyCrossClusterPrivateBGPWithdrawalReceiptResponse : public MothershipResponse { public: static constexpr uint32_t version = 1; uint32_t protocolVersion = version; bool found = false; ProdigyPairPrivateBGPSecretScope receipt; };
template <typename S> static void serialize(S&& s, ProdigyCrossClusterPrivateBGPWithdrawalReceiptResponse& value) { s.value4b(value.protocolVersion); s.value1b(value.success); s.text1b(value.failure, 1024); s.value1b(value.found); s.object(value.receipt); }

// Request and response are intended for the existing authenticated Neuron
// control channel.  The response has no serializer by design: serializing it
// into a Brain journal/snapshot is a boundary violation.
class ProdigyPairPrivateBGPSecretDeliveryRequest {
public:
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  ProdigyPairPrivateBGPSecretScope scope;
  String controlIdentitySHA256; // mTLS peer identity, never a credential
};
template <typename S> static void serialize(S&& s, ProdigyPairPrivateBGPSecretDeliveryRequest& request)
{
  s.value4b(request.protocolVersion); s.value16b(request.scope.pairUUID); s.value16b(request.scope.operationUUID);
  s.value8b(request.scope.keyEpoch); s.value1b(request.scope.tunnelSlot); s.value16b(request.scope.clusterUUID);
  s.value16b(request.scope.machineUUID); s.value8b(request.scope.authorityGeneration); s.value8b(request.scope.gatewayGeneration);
  s.text1b(request.controlIdentitySHA256, 64);
}

class ProdigyPairPrivateBGPSecretDeliveryResponse {
public:
  bool accepted = false;
  ProdigyPairPrivateBGPSecretScope scope;
  String credential; // transient only; secure-cleared by its consumer
  String gatewayRootCertPem;
  String localLeafCertPem;
  String localLeafKeyPem;
  String peerLeafCertDERHex;
  ~ProdigyPairPrivateBGPSecretDeliveryResponse()
  { Vault::secureClearString(credential); Vault::secureClearString(gatewayRootCertPem); Vault::secureClearString(localLeafCertPem); Vault::secureClearString(localLeafKeyPem); Vault::secureClearString(peerLeafCertDERHex); }
  ProdigyPairPrivateBGPSecretDeliveryResponse() = default;
  ProdigyPairPrivateBGPSecretDeliveryResponse(const ProdigyPairPrivateBGPSecretDeliveryResponse&) = delete;
  ProdigyPairPrivateBGPSecretDeliveryResponse& operator=(const ProdigyPairPrivateBGPSecretDeliveryResponse&) = delete;
};

// These codecs are used solely by the live Mothership<->Brain mTLS RPC. They
// are intentionally not members of persistent state and clear their buffer
// immediately after the relay frame is queued.
class ProdigyPairPrivateBGPSecretMothershipRequest { public: uint32_t protocolVersion = 1; ProdigyPairPrivateBGPSecretDeliveryRequest request; };
template <typename S> static void serialize(S&& s, ProdigyPairPrivateBGPSecretMothershipRequest& value) { s.value4b(value.protocolVersion); s.object(value.request); }
class ProdigyPairPrivateBGPSecretMothershipResponse : public MothershipResponse { public: static constexpr uint32_t version = 2; uint32_t protocolVersion = version; ProdigyPairPrivateBGPSecretDeliveryResponse delivery; ~ProdigyPairPrivateBGPSecretMothershipResponse() = default; };
template <typename S> static void serialize(S&& s, ProdigyPairPrivateBGPSecretMothershipResponse& value) {
  s.value4b(value.protocolVersion); s.value1b(value.success); s.text1b(value.failure, 1024); s.value1b(value.delivery.accepted);
  s.object(value.delivery.scope); s.text1b(value.delivery.credential, 32); s.text1b(value.delivery.gatewayRootCertPem, 4096);
  s.text1b(value.delivery.localLeafCertPem, 4096); s.text1b(value.delivery.localLeafKeyPem, 4096); s.text1b(value.delivery.peerLeafCertDERHex, 4096);
}
// Wire-only copyable carrier. It exists only in the live TLS command buffer;
// the Vault and Neuron cache continue to use the move-only delivery object.
class ProdigyPairPrivateBGPSecretInstallCommand { public: static constexpr uint32_t version = 2; uint32_t protocolVersion = version; ProdigyPairPrivateBGPSecretScope scope; String credential; String gatewayRootCertPem; String localLeafCertPem; String localLeafKeyPem; String peerLeafCertDERHex; ~ProdigyPairPrivateBGPSecretInstallCommand() { Vault::secureClearString(credential); Vault::secureClearString(gatewayRootCertPem); Vault::secureClearString(localLeafCertPem); Vault::secureClearString(localLeafKeyPem); Vault::secureClearString(peerLeafCertDERHex); } };
template <typename S> static void serialize(S&& s, ProdigyPairPrivateBGPSecretInstallCommand& value) { s.value4b(value.protocolVersion); s.object(value.scope); s.text1b(value.credential, 32); s.text1b(value.gatewayRootCertPem, 4096); s.text1b(value.localLeafCertPem, 4096); s.text1b(value.localLeafKeyPem, 4096); s.text1b(value.peerLeafCertDERHex, 4096); }
class ProdigyPairPrivateBGPSecretWithdrawalResponse : public MothershipResponse { public: static constexpr uint32_t version = 1; uint32_t protocolVersion = version; ProdigyPairPrivateBGPSecretScope scope; bool acknowledged = false; };
template <typename S> static void serialize(S&& s, ProdigyPairPrivateBGPSecretWithdrawalResponse& value) { s.value4b(value.protocolVersion); s.value1b(value.success); s.text1b(value.failure, 1024); s.object(value.scope); s.value1b(value.acknowledged); }

// This object is only ever serialized inside the Vault's authenticated
// ciphertext.  The clear delivery carrier above intentionally contains only
// the receiving machine's private key.
class MothershipPairPrivateGatewayTLSMaterial {
public:
  uint128_t firstMachineUUID = 0;
  uint128_t secondMachineUUID = 0;
  String rootCertPem;
  String rootKeyPem;
  String firstLeafCertPem;
  String firstLeafKeyPem;
  String secondLeafCertPem;
  String secondLeafKeyPem;
  String firstLeafCertDERHex;
  String secondLeafCertDERHex;
  String firstLeafCertSHA256;
  String secondLeafCertSHA256;
  String rootCertSHA256;
  ~MothershipPairPrivateGatewayTLSMaterial()
  { Vault::secureClearString(rootCertPem); Vault::secureClearString(rootKeyPem); Vault::secureClearString(firstLeafCertPem); Vault::secureClearString(firstLeafKeyPem); Vault::secureClearString(secondLeafCertPem); Vault::secureClearString(secondLeafKeyPem); Vault::secureClearString(firstLeafCertDERHex); Vault::secureClearString(secondLeafCertDERHex); Vault::secureClearString(firstLeafCertSHA256); Vault::secureClearString(secondLeafCertSHA256); Vault::secureClearString(rootCertSHA256); }
};
template <typename S> static void serialize(S&& s, MothershipPairPrivateGatewayTLSMaterial& value)
{
  s.value16b(value.firstMachineUUID); s.value16b(value.secondMachineUUID); s.text1b(value.rootCertPem, 4096); s.text1b(value.rootKeyPem, 4096);
  s.text1b(value.firstLeafCertPem, 4096); s.text1b(value.firstLeafKeyPem, 4096); s.text1b(value.secondLeafCertPem, 4096); s.text1b(value.secondLeafKeyPem, 4096);
  s.text1b(value.firstLeafCertDERHex, 4096); s.text1b(value.secondLeafCertDERHex, 4096); s.text1b(value.firstLeafCertSHA256, 64); s.text1b(value.secondLeafCertSHA256, 64); s.text1b(value.rootCertSHA256, 64);
}

// A compact encrypted record.  ciphertext is the only persistable portion;
// vaultKey is process-private Vault material and is never encoded or exposed.
class MothershipPairPrivateBGPVault final {
public:
  // Intent v5 encoded this pre-TLS record.  The registry consumes and drops it
  // while migrating an enrollment to v6; it must never be interpreted as a
  // credential bundle because no authenticated gateway TLS material exists.
  struct LegacyRecord {
    ProdigyPairPrivateBGPSecretScope scope;
    std::array<uint8_t, 12> nonce = {};
    std::array<uint8_t, 16> tag = {};
    std::array<uint8_t, 32> ciphertext = {};
    String digest;
    Vector<ProdigyPairPrivateBGPSecretScope> authorizedDeliveries;
    bool localAck = false, peerAck = false;
  };
  struct Record {
    ProdigyPairPrivateBGPSecretScope scope;
    std::array<uint8_t, 12> nonce = {};
    std::array<uint8_t, 16> tag = {};
    std::array<uint8_t, 32> ciphertext = {};
    std::array<uint8_t, 12> tlsNonce = {};
    std::array<uint8_t, 16> tlsTag = {};
    String tlsCiphertext;
    String digest;
    Vector<ProdigyPairPrivateBGPSecretScope> authorizedDeliveries;
    bool localAck = false, peerAck = false;
  };
private:
  std::array<uint8_t, 32> vaultKey = {};
  Vector<Record> records;

  static bool sameKey(const ProdigyPairPrivateBGPSecretScope& a, const ProdigyPairPrivateBGPSecretScope& b)
  { return a.pairUUID == b.pairUUID && a.keyEpoch == b.keyEpoch && a.tunnelSlot == b.tunnelSlot; }
  static bool sameDeliveryScope(const ProdigyPairPrivateBGPSecretScope& a, const ProdigyPairPrivateBGPSecretScope& b)
  { return sameKey(a, b) && a.operationUUID == b.operationUUID && a.clusterUUID == b.clusterUUID && a.machineUUID == b.machineUUID && a.authorityGeneration == b.authorityGeneration && a.gatewayGeneration == b.gatewayGeneration; }
  static bool sameDeliveryHalf(const ProdigyPairPrivateBGPSecretScope& a, const ProdigyPairPrivateBGPSecretScope& b)
  { return sameKey(a, b) && a.operationUUID == b.operationUUID && a.clusterUUID == b.clusterUUID && a.machineUUID == b.machineUUID; }
  static bool deliveryScopeNewer(const ProdigyPairPrivateBGPSecretScope& candidate,
                                 const ProdigyPairPrivateBGPSecretScope& prior)
  {
    return candidate.authorityGeneration >= prior.authorityGeneration &&
        candidate.gatewayGeneration >= prior.gatewayGeneration &&
        (candidate.authorityGeneration > prior.authorityGeneration ||
         candidate.gatewayGeneration > prior.gatewayGeneration);
  }
  static void clearRecord(Record& record)
  { OPENSSL_cleanse(record.nonce.data(), record.nonce.size()); OPENSSL_cleanse(record.tag.data(), record.tag.size()); OPENSSL_cleanse(record.ciphertext.data(), record.ciphertext.size()); OPENSSL_cleanse(record.tlsNonce.data(), record.tlsNonce.size()); OPENSSL_cleanse(record.tlsTag.data(), record.tlsTag.size()); Vault::secureClearString(record.tlsCiphertext); Vault::secureClearString(record.digest); record.authorizedDeliveries.clear(); record.scope = {}; record.localAck = record.peerAck = false; }
  static bool normalizeRecordDeliveries(Record& record)
  {
    if (!prodigyPairPrivateBGPSecretScopeValid(record.scope) || record.digest.size() != 64 ||
        record.tlsCiphertext.empty() || record.authorizedDeliveries.empty()) return false;
    Vector<ProdigyPairPrivateBGPSecretScope> normalized = {};
    for (const auto& candidate : record.authorizedDeliveries)
    {
      if (!prodigyPairPrivateBGPSecretScopeValid(candidate) || !sameKey(candidate, record.scope) ||
          candidate.operationUUID != record.scope.operationUUID) return false;
      auto sameMachine = std::find_if(normalized.begin(), normalized.end(), [&](const auto& current) {
        return current.machineUUID == candidate.machineUUID;
      });
      if (sameMachine == normalized.end())
      {
        if (normalized.size() >= 2) return false;
        normalized.push_back(candidate);
        continue;
      }
      if (sameMachine->clusterUUID != candidate.clusterUUID) return false;
      if (sameDeliveryScope(*sameMachine, candidate)) continue;
      const bool local = sameDeliveryHalf(*sameMachine, record.scope);
      if (deliveryScopeNewer(candidate, *sameMachine)) *sameMachine = candidate;
      else if (!deliveryScopeNewer(*sameMachine, candidate)) return false;
      // The persisted Boolean cannot identify which of two generations
      // acknowledged this half.  A recovered duplicate must re-acknowledge.
      if (local) record.localAck = false; else record.peerAck = false;
    }
    const auto local = std::find_if(normalized.begin(), normalized.end(), [&](const auto& candidate) {
      return sameDeliveryHalf(candidate, record.scope);
    });
    if (local == normalized.end()) return false;
    record.authorizedDeliveries = std::move(normalized);
    return true;
  }
  bool crypt(bool encrypt, Record& record, uint8_t bytes[32], String *failure = nullptr) const
  {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); if (ctx == nullptr) return false;
    int written = 0, tail = 0;
    bool ok = (encrypt ? EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) : EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, int(record.nonce.size()), nullptr) == 1 &&
      (encrypt ? EVP_EncryptInit_ex(ctx, nullptr, nullptr, vaultKey.data(), record.nonce.data()) : EVP_DecryptInit_ex(ctx, nullptr, nullptr, vaultKey.data(), record.nonce.data())) == 1;
    if (ok && !encrypt) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, int(record.tag.size()), const_cast<uint8_t *>(record.tag.data())) == 1;
    if (ok) ok = (encrypt ? EVP_EncryptUpdate(ctx, bytes, &written, bytes, 32) : EVP_DecryptUpdate(ctx, bytes, &written, record.ciphertext.data(), 32)) == 1 && written == 32;
    if (ok) ok = (encrypt ? EVP_EncryptFinal_ex(ctx, bytes + written, &tail) : EVP_DecryptFinal_ex(ctx, bytes + written, &tail)) == 1 && tail == 0;
    if (ok && encrypt) {
      std::memcpy(record.ciphertext.data(), bytes, record.ciphertext.size());
      ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, int(record.tag.size()), record.tag.data()) == 1;
    }
    EVP_CIPHER_CTX_free(ctx); if (!ok && failure) failure->assign("pair private BGP vault cryptographic operation failed"_ctv); return ok;
  }
  bool cryptTLS(bool encrypt, Record& record, String& bytes, String *failure = nullptr) const
  {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); if (ctx == nullptr) return false;
    const uint64_t size = encrypt ? bytes.size() : record.tlsCiphertext.size();
    if (size == 0 || size > 16 * 1024) { EVP_CIPHER_CTX_free(ctx); return false; }
    String output = {}; if (!output.reserve(size)) { EVP_CIPHER_CTX_free(ctx); if (failure) failure->assign("pair private gateway TLS vault buffer allocation failed"_ctv); return false; } int written = 0, tail = 0;
    bool ok = (encrypt ? EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) : EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, int(record.tlsNonce.size()), nullptr) == 1 &&
      (encrypt ? EVP_EncryptInit_ex(ctx, nullptr, nullptr, vaultKey.data(), record.tlsNonce.data()) : EVP_DecryptInit_ex(ctx, nullptr, nullptr, vaultKey.data(), record.tlsNonce.data())) == 1;
    if (ok && !encrypt) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, int(record.tlsTag.size()), record.tlsTag.data()) == 1;
    if (ok) ok = (encrypt ? EVP_EncryptUpdate(ctx, reinterpret_cast<uint8_t *>(output.pTail()), &written, reinterpret_cast<const uint8_t *>(bytes.data()), int(size)) : EVP_DecryptUpdate(ctx, reinterpret_cast<uint8_t *>(output.pTail()), &written, reinterpret_cast<const uint8_t *>(record.tlsCiphertext.data()), int(size))) == 1 && uint64_t(written) == size;
    if (written > 0) output.advance(uint64_t(written));
    if (ok) ok = (encrypt ? EVP_EncryptFinal_ex(ctx, reinterpret_cast<uint8_t *>(output.pTail()), &tail) : EVP_DecryptFinal_ex(ctx, reinterpret_cast<uint8_t *>(output.pTail()), &tail)) == 1 && tail == 0;
    if (tail > 0) output.advance(uint64_t(tail));
    if (ok && encrypt) { record.tlsCiphertext = std::move(output); ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, int(record.tlsTag.size()), record.tlsTag.data()) == 1; }
    else if (ok) bytes = std::move(output);
    else Vault::secureClearString(output);
    EVP_CIPHER_CTX_free(ctx); if (!ok && failure) failure->assign("pair private gateway TLS vault cryptographic operation failed"_ctv); return ok;
  }
  bool loadTLS(const Record& stored, MothershipPairPrivateGatewayTLSMaterial& material, String *failure = nullptr) const
  {
    Record record = stored; String plaintext = {};
    const bool ok = cryptTLS(false, record, plaintext, failure) && BitseryEngine::deserializeSafe(plaintext, material) &&
        material.firstMachineUUID != 0 && material.secondMachineUUID != 0 && material.firstMachineUUID != material.secondMachineUUID &&
        !material.rootCertPem.empty() && !material.rootKeyPem.empty() && !material.firstLeafCertPem.empty() && !material.firstLeafKeyPem.empty() &&
        !material.secondLeafCertPem.empty() && !material.secondLeafKeyPem.empty() && material.rootCertSHA256.size() == 64;
    Vault::secureClearString(plaintext); return ok;
  }
  bool mintTLS(Record& record, uint128_t firstMachineUUID, uint128_t secondMachineUUID,
               uint128_t listenerMachineUUID, const IPAddress& listenerEndpoint, String *failure = nullptr) const
  {
    if (firstMachineUUID == 0 || secondMachineUUID == 0 || firstMachineUUID == secondMachineUUID ||
        (listenerMachineUUID != firstMachineUUID && listenerMachineUUID != secondMachineUUID) || listenerEndpoint.isNull()) return false;
    MothershipPairPrivateGatewayTLSMaterial material = {}; material.firstMachineUUID = firstMachineUUID; material.secondMachineUUID = secondMachineUUID;
    char endpoint[INET6_ADDRSTRLEN] = {};
    if (inet_ntop(listenerEndpoint.is6 ? AF_INET6 : AF_INET, listenerEndpoint.v6, endpoint, sizeof(endpoint)) == nullptr) return false;
    Vector<String> firstSANs = {}, secondSANs = {};
    if (listenerMachineUUID == firstMachineUUID) firstSANs.push_back(String(endpoint)); else secondSANs.push_back(String(endpoint));
    bool ok = Vault::generateTransportRootCertificateEd25519(material.rootCertPem, material.rootKeyPem, failure) &&
        Vault::generateTransportNodeCertificateEd25519(material.rootCertPem, material.rootKeyPem, firstMachineUUID, firstSANs, material.firstLeafCertPem, material.firstLeafKeyPem, failure) &&
        Vault::generateTransportNodeCertificateEd25519(material.rootCertPem, material.rootKeyPem, secondMachineUUID, secondSANs, material.secondLeafCertPem, material.secondLeafKeyPem, failure);
    X509 *root = ok ? VaultPem::x509FromPem(material.rootCertPem) : nullptr;
    X509 *first = ok ? VaultPem::x509FromPem(material.firstLeafCertPem) : nullptr;
    X509 *second = ok ? VaultPem::x509FromPem(material.secondLeafCertPem) : nullptr;
    String rootDER = {}, firstDER = {}, secondDER = {};
    ok = ok && root != nullptr && first != nullptr && second != nullptr &&
        prodigyPairPrivateCertificateDER(root, rootDER, material.rootCertSHA256, failure) &&
        prodigyPairPrivateCertificateDER(first, firstDER, material.firstLeafCertSHA256, failure) && prodigyPairPrivateHexEncode(firstDER, material.firstLeafCertDERHex) &&
        prodigyPairPrivateCertificateDER(second, secondDER, material.secondLeafCertSHA256, failure) && prodigyPairPrivateHexEncode(secondDER, material.secondLeafCertDERHex) &&
        RAND_bytes(record.tlsNonce.data(), int(record.tlsNonce.size())) == 1;
    if (root) X509_free(root); if (first) X509_free(first); if (second) X509_free(second);
    Vault::secureClearString(rootDER); Vault::secureClearString(firstDER); Vault::secureClearString(secondDER);
    String plaintext = {}; if (ok) BitseryEngine::serialize(plaintext, material);
    if (ok) ok = cryptTLS(true, record, plaintext, failure);
    Vault::secureClearString(plaintext); return ok;
  }
public:
  // The immutable enrollment root is already Mothership's private durable
  // pair master key.  Deriving a domain-separated AES key from it avoids a
  // second key store and lets encrypted records rehydrate after restart.
  bool configurePairRoot(const uint8_t root[ProdigyClusterPairEnrollmentRootBytes])
  {
    if (root == nullptr) return false;
    uint8_t nonzero = 0; for (uint32_t i = 0; i < ProdigyClusterPairEnrollmentRootBytes; ++i) nonzero |= root[i];
    if (nonzero == 0) return false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); unsigned int size = 0;
    static constexpr char label[] = "prodigy/mothership/pair-private-bgp-v1";
    const bool ok = ctx != nullptr && EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(ctx, label, sizeof(label) - 1) == 1 &&
        EVP_DigestUpdate(ctx, root, ProdigyClusterPairEnrollmentRootBytes) == 1 &&
        EVP_DigestFinal_ex(ctx, vaultKey.data(), &size) == 1 && size == vaultKey.size();
    if (ctx) EVP_MD_CTX_free(ctx); return ok;
  }
  MothershipPairPrivateBGPVault() = default;
  ~MothershipPairPrivateBGPVault() { for (auto& record : records) clearRecord(record); OPENSSL_cleanse(vaultKey.data(), vaultKey.size()); }
  bool mintAfterActiveEnrollment(const ProdigyPairPrivateBGPSecretScope& scope, uint128_t peerMachineUUID,
      uint128_t listenerMachineUUID, const IPAddress& listenerEndpoint, String& digest,
      String& localLeafSHA256, String& peerLeafSHA256, String& rootSHA256, String *failure = nullptr)
  {
    digest.clear(); localLeafSHA256.clear(); peerLeafSHA256.clear(); rootSHA256.clear();
    if (!prodigyPairPrivateBGPSecretScopeValid(scope) || peerMachineUUID == 0 || peerMachineUUID == scope.machineUUID) return false;
    for (auto& record : records) if (sameKey(record.scope, scope)) {
      MothershipPairPrivateGatewayTLSMaterial material = {};
      if (!loadTLS(record, material, failure)) return false;
      const bool firstLocal = material.firstMachineUUID == scope.machineUUID && material.secondMachineUUID == peerMachineUUID;
      const bool secondLocal = material.secondMachineUUID == scope.machineUUID && material.firstMachineUUID == peerMachineUUID;
      if (firstLocal == secondLocal || scope.operationUUID != record.scope.operationUUID) return false;
      digest = record.digest; localLeafSHA256 = firstLocal ? material.firstLeafCertSHA256 : material.secondLeafCertSHA256;
      peerLeafSHA256 = firstLocal ? material.secondLeafCertSHA256 : material.firstLeafCertSHA256; rootSHA256 = material.rootCertSHA256;
      if (localLeafSHA256.size() != 64 || peerLeafSHA256.size() != 64 || rootSHA256.size() != 64) return false;
      auto delivery = std::find_if(record.authorizedDeliveries.begin(), record.authorizedDeliveries.end(), [&](const auto& allowed) {
        return sameDeliveryHalf(allowed, scope);
      });
      if (delivery == record.authorizedDeliveries.end())
      {
        if (record.authorizedDeliveries.size() >= 2) return false;
        record.authorizedDeliveries.push_back(scope);
      }
      else if (!sameDeliveryScope(*delivery, scope))
      {
        if (!deliveryScopeNewer(scope, *delivery)) return false;
        const bool local = sameDeliveryHalf(*delivery, record.scope);
        *delivery = scope;
        if (local) record.localAck = false; else record.peerAck = false;
      }
      return true;
    }
    Record record = {}; record.scope = scope; uint8_t material[32] = {};
    bool ok = RAND_bytes(material, sizeof(material)) == 1 && RAND_bytes(record.nonce.data(), int(record.nonce.size())) == 1;
    String plaintext = {}; plaintext.assign(reinterpret_cast<const char *>(material), sizeof(material));
    if (ok) ok = prodigyComputeSHA256Hex(plaintext, record.digest) && crypt(true, record, material, failure);
    OPENSSL_cleanse(material, sizeof(material)); Vault::secureClearString(plaintext);
    if (ok) ok = mintTLS(record, scope.machineUUID, peerMachineUUID, listenerMachineUUID, listenerEndpoint, failure);
    if (!ok) { clearRecord(record); return false; }
    MothershipPairPrivateGatewayTLSMaterial tlsMaterial = {};
    if (!loadTLS(record, tlsMaterial, failure)) { clearRecord(record); return false; }
    localLeafSHA256 = tlsMaterial.firstLeafCertSHA256; peerLeafSHA256 = tlsMaterial.secondLeafCertSHA256; rootSHA256 = tlsMaterial.rootCertSHA256;
    if (localLeafSHA256.size() != 64 || peerLeafSHA256.size() != 64 || rootSHA256.size() != 64) { clearRecord(record); return false; }
    record.authorizedDeliveries.push_back(scope); digest = record.digest; records.push_back(std::move(record)); return true;
  }
  bool deliver(const ProdigyPairPrivateBGPSecretDeliveryRequest& request, const String& expectedControlIdentitySHA256,
               const String& expectedDigest, ProdigyPairPrivateBGPSecretDeliveryResponse& response, String *failure = nullptr) const
  {
    response.accepted = false; Vault::secureClearString(response.credential); Vault::secureClearString(response.gatewayRootCertPem); Vault::secureClearString(response.localLeafCertPem); Vault::secureClearString(response.localLeafKeyPem); Vault::secureClearString(response.peerLeafCertDERHex); response.scope = {};
    if (request.protocolVersion != ProdigyPairPrivateBGPSecretDeliveryRequest::version || !prodigyPairPrivateBGPSecretScopeValid(request.scope) ||
        request.controlIdentitySHA256 != expectedControlIdentitySHA256) return false;
    for (const auto& stored : records) if (sameKey(stored.scope, request.scope)) {
      // EVP's decrypt API is non-const only because it accepts mutable tag
      // storage; make a stack copy so authenticated delivery never mutates
      // the encrypted Vault record.
      Record record = stored;
      // One pair/epoch/slot secret can have exactly the enrolled delivery
      // scopes registered by active authority commits; another half/machine
      // or a stale generation cannot borrow it.
      if (record.digest != expectedDigest || std::none_of(record.authorizedDeliveries.begin(), record.authorizedDeliveries.end(),
          [&](const auto& allowed) { return sameDeliveryScope(allowed, request.scope); })) return false;
      uint8_t material[32] = {}; if (!crypt(false, record, material, failure)) { OPENSSL_cleanse(material, sizeof(material)); return false; }
      MothershipPairPrivateGatewayTLSMaterial tls = {};
      if (!loadTLS(stored, tls, failure)) { OPENSSL_cleanse(material, sizeof(material)); return false; }
      const bool firstLocal = tls.firstMachineUUID == request.scope.machineUUID;
      const bool secondLocal = tls.secondMachineUUID == request.scope.machineUUID;
      if (firstLocal == secondLocal) { OPENSSL_cleanse(material, sizeof(material)); return false; }
      response.credential.assign(reinterpret_cast<const char *>(material), sizeof(material)); OPENSSL_cleanse(material, sizeof(material));
      response.gatewayRootCertPem = std::move(tls.rootCertPem);
      response.localLeafCertPem = firstLocal ? std::move(tls.firstLeafCertPem) : std::move(tls.secondLeafCertPem);
      response.localLeafKeyPem = firstLocal ? std::move(tls.firstLeafKeyPem) : std::move(tls.secondLeafKeyPem);
      response.peerLeafCertDERHex = firstLocal ? std::move(tls.secondLeafCertDERHex) : std::move(tls.firstLeafCertDERHex);
      response.scope = request.scope; response.accepted = true; return true;
    }
    return false;
  }
  bool acknowledgeRevocation(const ProdigyPairPrivateBGPSecretScope& scope)
  {
    for (auto& record : records) if (sameKey(record.scope, scope)) {
      // The acknowledging half is derived from a delivery scope that was
      // enrolled with this encrypted record; a transport caller cannot claim
      // the opposite half with a Boolean.
      if (std::none_of(record.authorizedDeliveries.begin(), record.authorizedDeliveries.end(),
          [&](const auto& allowed) { return sameDeliveryScope(allowed, scope); })) return false;
      if (sameDeliveryHalf(record.scope, scope)) record.localAck = true;
      else record.peerAck = true;
      return true;
    }
    return false;
  }
  bool revocationAcknowledged(const ProdigyPairPrivateBGPSecretScope& scope) const
  { for (const auto& record : records) if (sameKey(record.scope, scope)) {
      if (std::none_of(record.authorizedDeliveries.begin(), record.authorizedDeliveries.end(), [&](const auto& allowed) { return sameDeliveryScope(allowed, scope); })) return false;
      return sameDeliveryHalf(record.scope, scope) ? record.localAck : record.peerAck;
    } return false; }
  bool deleteAfterBothRevocationAcknowledgements(const ProdigyPairPrivateBGPSecretScope& scope)
  { for (uint32_t i = 0; i < records.size(); ++i) if (sameKey(records[i].scope, scope)) { if (!records[i].localAck || !records[i].peerAck) return false; clearRecord(records[i]); records.erase(records.begin() + i); return true; } return true; }
  void exportRecords(Vector<Record>& output) const { output = records; }
  bool importRecords(const Vector<Record>& input)
  {
    Vector<Record> normalized = input;
    for (auto& record : normalized) if (!normalizeRecordDeliveries(record)) return false;
    records = std::move(normalized); return true;
  }
};

template <typename S> static void serialize(S&& s, MothershipPairPrivateBGPVault::LegacyRecord& record)
{
  s.object(record.scope); for (auto& byte : record.nonce) s.value1b(byte); for (auto& byte : record.tag) s.value1b(byte);
  for (auto& byte : record.ciphertext) s.value1b(byte); s.text1b(record.digest, 64);
  s.container(record.authorizedDeliveries, 2, [](auto& nested, auto& scope) { nested.object(scope); });
  s.value1b(record.localAck); s.value1b(record.peerAck);
}

template <typename S> static void serialize(S&& s, MothershipPairPrivateBGPVault::Record& record)
{
  s.object(record.scope); for (auto& byte : record.nonce) s.value1b(byte); for (auto& byte : record.tag) s.value1b(byte);
  for (auto& byte : record.ciphertext) s.value1b(byte); for (auto& byte : record.tlsNonce) s.value1b(byte); for (auto& byte : record.tlsTag) s.value1b(byte); s.text1b(record.tlsCiphertext, 16 * 1024); s.text1b(record.digest, 64);
  // Version-six records accidentally persisted one superseded half during a
  // withdrawn-to-active generation transition. Decode that bounded shape so
  // the Vault can canonicalize it on its next authenticated use; export is
  // always limited to the two current machine halves.
  s.container(record.authorizedDeliveries, 3, [](auto& nested, auto& scope) { nested.object(scope); });
  s.value1b(record.localAck); s.value1b(record.peerAck);
}
