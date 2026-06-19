#pragma once

#include <memory>

#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include <prodigy/mothership/mothership.cluster.types.h>
#include <services/random.h>
#include <services/vault.h>

using MothershipTunnelX509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using MothershipTunnelPKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

template <typename Text>
static inline bool mothershipTunnelAuthFail(String *failure, const Text& text)
{
  if (failure)
  {
    failure->assign(text);
  }
  return false;
}

static inline bool mothershipTunnelAuthOk(String *failure)
{
  if (failure)
  {
    failure->clear();
  }
  return true;
}

static inline bool mothershipTunnelGatewayLeafIssuedByRoot(X509 *rootCert, EVP_PKEY *rootPublicKey, X509 *leafCert)
{
  return rootCert != nullptr && rootPublicKey != nullptr && leafCert != nullptr &&
      X509_check_issued(rootCert, leafCert) == X509_V_OK &&
      X509_verify(leafCert, rootPublicKey) == 1;
}

static inline bool mothershipTunnelGatewayLeafHasExtendedKeyUsage(X509 *leafCert, int nid)
{
  EXTENDED_KEY_USAGE *usage = leafCert == nullptr ? nullptr : static_cast<EXTENDED_KEY_USAGE *>(X509_get_ext_d2i(leafCert, NID_ext_key_usage, nullptr, nullptr));
  if (usage == nullptr)
  {
    return false;
  }

  bool found = false;
  for (int index = 0; index < sk_ASN1_OBJECT_num(usage); ++index)
  {
    const ASN1_OBJECT *object = sk_ASN1_OBJECT_value(usage, index);
    if (object != nullptr && OBJ_obj2nid(object) == nid)
    {
      found = true;
      break;
    }
  }
  sk_ASN1_OBJECT_pop_free(usage, ASN1_OBJECT_free);
  return found;
}

static inline bool mothershipTunnelGatewayLeafKeyMatches(X509 *rootCert, EVP_PKEY *rootPublicKey, X509 *leafCert, EVP_PKEY *leafKey, int extendedKeyUsageNid)
{
  return leafCert != nullptr && leafKey != nullptr &&
      X509_check_private_key(leafCert, leafKey) == 1 &&
      mothershipTunnelGatewayLeafIssuedByRoot(rootCert, rootPublicKey, leafCert) &&
      mothershipTunnelGatewayLeafHasExtendedKeyUsage(leafCert, extendedKeyUsageNid);
}

static inline bool mothershipTunnelGatewayClientAuthMaterialValid(const MothershipTunnelGatewayClientAuth& auth, String *failure = nullptr)
{
  MothershipTunnelX509Ptr rootCert(VaultPem::x509FromPem(auth.rootCertPem), X509_free);
  MothershipTunnelX509Ptr clientCert(VaultPem::x509FromPem(auth.clientCertPem), X509_free);
  MothershipTunnelPKeyPtr clientKey(VaultPem::privateKeyFromPem(auth.clientKeyPem), EVP_PKEY_free);
  MothershipTunnelPKeyPtr rootPublicKey(rootCert ? X509_get_pubkey(rootCert.get()) : nullptr, EVP_PKEY_free);
  bool ok = auth.configured() && mothershipTunnelGatewayLeafKeyMatches(rootCert.get(), rootPublicKey.get(), clientCert.get(), clientKey.get(), NID_client_auth);

  if (ok == false)
  {
    return mothershipTunnelAuthFail(failure, "mothership tunnel gateway client auth certificate material invalid"_ctv);
  }
  return mothershipTunnelAuthOk(failure);
}

static inline bool mothershipTunnelGatewayAuthMaterialValid(const MothershipTunnelGatewayAuth& auth, String *failure = nullptr)
{
  MothershipTunnelX509Ptr rootCert(VaultPem::x509FromPem(auth.rootCertPem), X509_free);
  MothershipTunnelX509Ptr serverCert(VaultPem::x509FromPem(auth.serverCertPem), X509_free);
  MothershipTunnelPKeyPtr serverKey(VaultPem::privateKeyFromPem(auth.serverKeyPem), EVP_PKEY_free);
  MothershipTunnelPKeyPtr rootPublicKey(rootCert ? X509_get_pubkey(rootCert.get()) : nullptr, EVP_PKEY_free);
  bool ok = auth.configured() &&
      rootCert != nullptr &&
      mothershipTunnelGatewayLeafKeyMatches(rootCert.get(), rootPublicKey.get(), serverCert.get(), serverKey.get(), NID_server_auth);

  if (ok == false)
  {
    return mothershipTunnelAuthFail(failure, "mothership tunnel gateway auth certificate material invalid"_ctv);
  }
  return mothershipTunnelAuthOk(failure);
}

static inline bool mothershipTunnelGatewayAuthorizeClientCertificate(const MothershipTunnelGatewayAuth& auth, const String& presentedClientCertPem, String *failure = nullptr)
{
  if (mothershipTunnelGatewayAuthMaterialValid(auth, failure) == false)
  {
    return false;
  }

  MothershipTunnelX509Ptr rootCert(VaultPem::x509FromPem(auth.rootCertPem), X509_free);
  MothershipTunnelX509Ptr clientCert(VaultPem::x509FromPem(presentedClientCertPem), X509_free);
  MothershipTunnelPKeyPtr rootPublicKey(rootCert ? X509_get_pubkey(rootCert.get()) : nullptr, EVP_PKEY_free);
  bool validClient = mothershipTunnelGatewayLeafIssuedByRoot(rootCert.get(), rootPublicKey.get(), clientCert.get()) && mothershipTunnelGatewayLeafHasExtendedKeyUsage(clientCert.get(), NID_client_auth);

  if (validClient == false)
  {
    return mothershipTunnelAuthFail(failure, "mothership tunnel gateway client certificate invalid"_ctv);
  }
  return mothershipTunnelAuthOk(failure);
}

static inline bool mothershipIssueTunnelGatewayLeaf(
    const String& rootCertPem,
    const String& rootKeyPem,
    uint128_t uuid,
    bool serverAuth,
    bool clientAuth,
    String& certPem,
    String& keyPem,
    String *failure = nullptr)
{
  certPem.clear();
  keyPem.clear();
  String commonName = {};
  if (Vault::buildNodeCommonName(uuid, commonName) == false)
  {
    return mothershipTunnelAuthFail(failure, "invalid mothership tunnel gateway auth uuid"_ctv);
  }

  MothershipTunnelX509Ptr rootCert(VaultPem::x509FromPem(rootCertPem), X509_free);
  MothershipTunnelPKeyPtr rootKey(VaultPem::privateKeyFromPem(rootKeyPem), EVP_PKEY_free);
  X509 *rawCert = nullptr;
  EVP_PKEY *rawKey = nullptr;
  Vector<String> ipAddresses = {};
  bool ok = rootCert != nullptr && rootKey != nullptr &&
      Vault::issueTransportCertificateEd25519(
          commonName,
          "Prodigy Mothership Tunnel"_ctv,
          false,
          serverAuth,
          clientAuth,
          825,
          ipAddresses,
          rootCert.get(),
          rootKey.get(),
          rawCert,
          rawKey,
          failure) &&
      VaultPem::x509ToPem(rawCert, certPem) &&
      VaultPem::privateKeyToPem(rawKey, keyPem);
  MothershipTunnelX509Ptr cert(rawCert, X509_free);
  MothershipTunnelPKeyPtr key(rawKey, EVP_PKEY_free);

  if (ok == false)
  {
    certPem.clear();
    keyPem.clear();
    if (failure && failure->size() == 0)
    {
      failure->assign("failed to issue mothership tunnel gateway certificate"_ctv);
    }
    return false;
  }

  return mothershipTunnelAuthOk(failure);
}

static inline bool mothershipGenerateTunnelGatewayAuth(
    MothershipTunnelGatewayClientAuth& clientAuth,
    MothershipTunnelGatewayAuth& gatewayAuth,
    String *failure = nullptr)
{
  clientAuth = {};
  gatewayAuth = {};

  Vault::TransportCertificateOptions options = {};
  options.subjectOrganization = "Prodigy Mothership Tunnel"_ctv;
  options.rootCommonName = "mothership-tunnel-gateway-root"_ctv;
  String rootKeyPem = {};
  if (Vault::generateTransportRootCertificateEd25519(gatewayAuth.rootCertPem, rootKeyPem, options, failure) == false)
  {
    return false;
  }

  clientAuth.rootCertPem = gatewayAuth.rootCertPem;

  if (mothershipIssueTunnelGatewayLeaf(gatewayAuth.rootCertPem, rootKeyPem, Random::generateNumberWithNBits<128, uint128_t>(), false, true, clientAuth.clientCertPem, clientAuth.clientKeyPem, failure) == false ||
      mothershipIssueTunnelGatewayLeaf(gatewayAuth.rootCertPem, rootKeyPem, Random::generateNumberWithNBits<128, uint128_t>(), true, false, gatewayAuth.serverCertPem, gatewayAuth.serverKeyPem, failure) == false)
  {
    clientAuth = {};
    gatewayAuth = {};
    Vault::secureClearString(rootKeyPem);
    return false;
  }
  Vault::secureClearString(rootKeyPem);

  return mothershipTunnelAuthOk(failure);
}
