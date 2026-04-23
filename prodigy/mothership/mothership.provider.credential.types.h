#pragma once

#include <cstdint>
#include <cstdlib>

#include <prodigy/mothership/mothership.cluster.types.h>

enum class MothershipProviderCredentialMode : uint8_t
{
   staticMaterial = 0,
   gcloud = 1,
   gcloudImpersonation = 2,
   externalAccountFile = 3,
   azureCli = 4,
   awsCli = 5,
   awsImds = 6
};

static inline const char *mothershipProviderCredentialModeName(MothershipProviderCredentialMode mode)
{
   switch (mode)
   {
      case MothershipProviderCredentialMode::staticMaterial:
      {
         return "staticMaterial";
      }
      case MothershipProviderCredentialMode::gcloud:
      {
         return "gcloud";
      }
      case MothershipProviderCredentialMode::gcloudImpersonation:
      {
         return "gcloudImpersonation";
      }
      case MothershipProviderCredentialMode::externalAccountFile:
      {
         return "externalAccountFile";
      }
      case MothershipProviderCredentialMode::azureCli:
      {
         return "azureCli";
      }
      case MothershipProviderCredentialMode::awsCli:
      {
         return "awsCli";
      }
      case MothershipProviderCredentialMode::awsImds:
      {
         return "awsImds";
      }
   }

   return "staticMaterial";
}

static inline bool parseMothershipProviderCredentialMode(const String& value, MothershipProviderCredentialMode& mode)
{
   if (value.equal("staticMaterial"_ctv))
   {
      mode = MothershipProviderCredentialMode::staticMaterial;
      return true;
   }

   if (value.equal("gcloud"_ctv))
   {
      mode = MothershipProviderCredentialMode::gcloud;
      return true;
   }

   if (value.equal("gcloudImpersonation"_ctv))
   {
      mode = MothershipProviderCredentialMode::gcloudImpersonation;
      return true;
   }

   if (value.equal("externalAccountFile"_ctv))
   {
      mode = MothershipProviderCredentialMode::externalAccountFile;
      return true;
   }

   if (value.equal("azureCli"_ctv))
   {
      mode = MothershipProviderCredentialMode::azureCli;
      return true;
   }

   if (value.equal("awsCli"_ctv))
   {
      mode = MothershipProviderCredentialMode::awsCli;
      return true;
   }

   if (value.equal("awsImds"_ctv))
   {
      mode = MothershipProviderCredentialMode::awsImds;
      return true;
   }

   return false;
}

class MothershipProviderCredential
{
public:

   String name;
   MothershipClusterProvider provider = MothershipClusterProvider::unknown;
   MothershipProviderCredentialMode mode = MothershipProviderCredentialMode::staticMaterial;
   String material;
   String impersonateServiceAccount;
   String credentialPath;
   String scope;
   bool allowPropagateToProdigy = false;
   int64_t createdAtMs = 0;
   int64_t updatedAtMs = 0;
};

template <typename S>
static void serialize(S&& serializer, MothershipProviderCredential& credential)
{
   serializer.text1b(credential.name, UINT32_MAX);
   serializer.value1b(credential.provider);
   serializer.value1b(credential.mode);
   serializer.text1b(credential.material, UINT32_MAX);
    serializer.text1b(credential.impersonateServiceAccount, UINT32_MAX);
   serializer.text1b(credential.credentialPath, UINT32_MAX);
   serializer.text1b(credential.scope, UINT32_MAX);
   serializer.value1b(credential.allowPropagateToProdigy);
   serializer.value8b(credential.createdAtMs);
   serializer.value8b(credential.updatedAtMs);
}

static inline bool resolveMothershipClusterInlineProviderCredentialOverride(MothershipProdigyCluster& cluster, MothershipProviderCredential& credential, String *failure = nullptr)
{
   if (cluster.deploymentMode == MothershipClusterDeploymentMode::local
      || cluster.deploymentMode == MothershipClusterDeploymentMode::test)
   {
      if (failure) failure->assign("providerless clusters must not include providerCredentialOverride");
      return false;
   }

   if (cluster.provider == MothershipClusterProvider::unknown)
   {
      cluster.provider = credential.provider;
   }
   else if (credential.provider == MothershipClusterProvider::unknown)
   {
      credential.provider = cluster.provider;
   }
   else if (cluster.provider != credential.provider)
   {
      if (failure) failure->assign("providerCredentialOverride provider does not match cluster provider");
      return false;
   }

   if (cluster.providerScope.size() == 0)
   {
      cluster.providerScope = credential.scope;
   }
   else if (credential.scope.size() == 0)
   {
      credential.scope = cluster.providerScope;
   }
   else if (cluster.providerScope.equals(credential.scope) == false)
   {
      if (failure) failure->assign("providerCredentialOverride scope does not match providerScope");
      return false;
   }

   if (cluster.providerCredentialName.size() == 0)
   {
      if (credential.name.size() > 0)
      {
         cluster.providerCredentialName = credential.name;
      }
      else if (cluster.name.size() > 0)
      {
         cluster.providerCredentialName.snprintf<"{}-provider"_ctv>(cluster.name);
      }
   }

   if (credential.name.size() == 0)
   {
      credential.name = cluster.providerCredentialName;
   }
   else if (cluster.providerCredentialName.size() == 0)
   {
      cluster.providerCredentialName = credential.name;
   }
   else if (credential.name.equals(cluster.providerCredentialName) == false)
   {
      if (failure) failure->assign("providerCredentialOverride name does not match providerCredentialName");
      return false;
   }

   if (cluster.propagateProviderCredentialToProdigy)
   {
      credential.allowPropagateToProdigy = true;
   }

   if (failure) failure->clear();
   return true;
}
