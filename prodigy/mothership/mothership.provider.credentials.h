#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>

#include <networking/includes.h>
#include <services/time.h>
#include <types/types.containers.h>
#include <databases/embedded/tidesdb.h>
#include <prodigy/runtime.environment.h>
#include <prodigy/mothership/mothership.provider.credential.types.h>

class MothershipProviderCredentialRegistry
{
private:

   TidesDB db;

   static constexpr auto credentialsColumnFamily = "provider_credentials"_ctv;

   static void resolveDefaultDBPath(String& path)
   {
      if (const char *overridePath = getenv("PRODIGY_MOTHERSHIP_TIDESDB_PATH"); overridePath && overridePath[0] != '\0')
      {
         path.snprintf<"{}/provider_credentials"_ctv>(String(overridePath));
         return;
      }

      if (const char *home = getenv("HOME"); home && home[0] != '\0')
      {
         path.snprintf<"{}/.prodigy/mothership/provider_credentials"_ctv>(String(home));
         return;
      }

      path.assign("/tmp/prodigy-mothership/provider_credentials"_ctv);
   }

   static bool deserializeCredentialValue(const uint8_t *value, size_t valueSize, MothershipProviderCredential& credential)
   {
      String serialized;
      serialized.append(value, valueSize);
      return BitseryEngine::deserializeSafe(serialized, credential);
   }

   static bool stringHasContent(const String& value)
   {
      return value.size() > 0 && value[0] != '\0';
   }

   static void trimTrailingAsciiWhitespace(String& value)
   {
      while (value.size() > 0)
      {
         uint8_t ch = value[value.size() - 1];
         if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t')
         {
            break;
         }

         value.resize(value.size() - 1);
      }
   }

   static void appendShellSingleQuoted(String& command, const String& value)
   {
      command.append('\'' );
      for (uint64_t index = 0; index < value.size(); ++index)
      {
         if (value[index] == '\'')
         {
            command.append("'\\''"_ctv);
         }
         else
         {
            command.append(value[index]);
         }
      }
      command.append('\'');
   }

   static bool runCommandCaptureOutput(const String& command, String& output, String *failure)
   {
      output.clear();
      if (failure) failure->clear();

      String ownedCommand = {};
      ownedCommand.assign(command);
      ownedCommand.addNullTerminator();

      FILE *pipe = ::popen(ownedCommand.c_str(), "r");
      if (pipe == nullptr)
      {
         if (failure) failure->assign("failed to spawn command"_ctv);
         return false;
      }

      char buffer[4096];
      while (true)
      {
         size_t nRead = fread(buffer, 1, sizeof(buffer), pipe);
         if (nRead > 0)
         {
            output.append(reinterpret_cast<const uint8_t *>(buffer), nRead);
         }

         if (nRead < sizeof(buffer))
         {
            break;
         }
      }

      int status = ::pclose(pipe);
      trimTrailingAsciiWhitespace(output);
      if (status == 0)
      {
         return true;
      }

      if (failure)
      {
         if (output.size() > 0)
         {
            failure->assign(output);
         }
         else if (WIFEXITED(status))
         {
            failure->snprintf<"command exited with status {itoa}"_ctv>(uint32_t(WEXITSTATUS(status)));
         }
         else
         {
            failure->assign("command failed"_ctv);
         }
      }

      return false;
   }

   static bool resolveGcpBootstrapAccessToken(const MothershipProviderCredential& credential, String& material, String *failure)
   {
      material.clear();
      if (failure) failure->clear();

      String command = {};
      if (buildGcpBootstrapAccessTokenRefreshCommand(credential, command, failure) == false)
      {
         return false;
      }

      if (command.size() == 0)
      {
         material = credential.material;
         return true;
      }

      if (runCommandCaptureOutput(command, material, failure) == false)
      {
         return false;
      }

      if (stringHasContent(material) == false)
      {
         if (failure) failure->assign("gcp access token resolution returned empty output"_ctv);
         return false;
      }

      return true;
   }

   static bool resolveExecutablePath(const char *program, String& resolved)
   {
      resolved.clear();
      if (program == nullptr || program[0] == '\0')
      {
         return false;
      }

      const char *path = getenv("PATH");
      if (path == nullptr || path[0] == '\0')
      {
         return false;
      }

      const char *segment = path;
      while (true)
      {
         const char *separator = std::strchr(segment, ':');
         size_t segmentLength = separator ? size_t(separator - segment) : std::strlen(segment);

         resolved.clear();
         if (segmentLength == 0)
         {
            resolved.assign("./"_ctv);
            resolved.append(String(program));
         }
         else
         {
            resolved.append(reinterpret_cast<const uint8_t *>(segment), segmentLength);
            if (resolved.size() == 0 || resolved[resolved.size() - 1] != '/')
            {
               resolved.append("/"_ctv);
            }
            resolved.append(String(program));
         }

         if (::access(resolved.c_str(), X_OK) == 0)
         {
            return true;
         }

         if (separator == nullptr)
         {
            break;
         }

         segment = separator + 1;
      }

      resolved.clear();
      return false;
   }

   static bool buildAzureBootstrapAccessTokenRefreshCommand(const MothershipProviderCredential& credential, String& command, String *failure = nullptr)
   {
      command.clear();
      if (failure) failure->clear();

      if (credential.mode == MothershipProviderCredentialMode::staticMaterial)
      {
         return true;
      }

      if (credential.mode == MothershipProviderCredentialMode::azureCli)
      {
         String azPath = {};
         if (resolveExecutablePath("az", azPath))
         {
            command.snprintf<"'{}' account get-access-token --resource-type arm --query accessToken -o tsv 2>&1"_ctv>(azPath);
         }
         else if (const char *home = getenv("HOME"); home && home[0] != '\0')
         {
            azPath.snprintf<"{}/.local/azure-cli-venv/bin/az"_ctv>(String(home));
            if (::access(azPath.c_str(), X_OK) == 0)
            {
               command.snprintf<"'{}' account get-access-token --resource-type arm --query accessToken -o tsv 2>&1"_ctv>(azPath);
            }
            else
            {
               command.assign("az account get-access-token --resource-type arm --query accessToken -o tsv 2>&1"_ctv);
            }
         }
         else
         {
            command.assign("az account get-access-token --resource-type arm --query accessToken -o tsv 2>&1"_ctv);
         }
         return true;
      }

      if (failure) failure->assign("provider credential mode invalid");
      return false;
   }

   static bool buildAwsBootstrapCredentialRefreshCommand(const MothershipProviderCredential& credential, String& command, String *failure = nullptr)
   {
      command.clear();
      if (failure) failure->clear();

      if (credential.mode == MothershipProviderCredentialMode::staticMaterial)
      {
         return true;
      }

      if (credential.mode == MothershipProviderCredentialMode::awsCli)
      {
         command.assign("aws configure export-credentials --format process 2>&1"_ctv);
         return true;
      }

      if (credential.mode == MothershipProviderCredentialMode::awsImds)
      {
         return true;
      }

      if (failure) failure->assign("provider credential mode invalid");
      return false;
   }

   static bool resolveAzureBootstrapAccessToken(const MothershipProviderCredential& credential, String& material, String *failure)
   {
      material.clear();
      if (failure) failure->clear();

      String command = {};
      if (buildAzureBootstrapAccessTokenRefreshCommand(credential, command, failure) == false)
      {
         return false;
      }

      if (command.size() == 0)
      {
         material = credential.material;
         return true;
      }

      if (runCommandCaptureOutput(command, material, failure) == false)
      {
         return false;
      }

      if (stringHasContent(material) == false)
      {
         if (failure) failure->assign("azure access token resolution returned empty output"_ctv);
         return false;
      }

      return true;
   }

   static bool resolveAwsBootstrapCredentialMaterial(const MothershipProviderCredential& credential, String& material, String *failure)
   {
      material.clear();
      if (failure) failure->clear();

      String command = {};
      if (buildAwsBootstrapCredentialRefreshCommand(credential, command, failure) == false)
      {
         return false;
      }

      if (command.size() == 0)
      {
         material = credential.material;
         return true;
      }

      if (runCommandCaptureOutput(command, material, failure) == false)
      {
         return false;
      }

      if (stringHasContent(material) == false)
      {
         if (failure) failure->assign("aws credential resolution returned empty output"_ctv);
         return false;
      }

      return true;
   }

   static bool buildGcpBootstrapAccessTokenRefreshCommand(const MothershipProviderCredential& credential, String& command, String *failure = nullptr)
   {
      command.clear();
      if (failure) failure->clear();

      switch (credential.mode)
      {
         case MothershipProviderCredentialMode::staticMaterial:
         {
            return true;
         }
         case MothershipProviderCredentialMode::gcloud:
         {
            command.assign("gcloud auth print-access-token 2>&1"_ctv);
            return true;
         }
         case MothershipProviderCredentialMode::gcloudImpersonation:
         {
            command.assign("gcloud auth print-access-token --impersonate-service-account="_ctv);
            appendShellSingleQuoted(command, credential.impersonateServiceAccount);
            command.append(" 2>&1"_ctv);
            return true;
         }
         case MothershipProviderCredentialMode::externalAccountFile:
         {
            command.assign("GOOGLE_APPLICATION_CREDENTIALS="_ctv);
            appendShellSingleQuoted(command, credential.credentialPath);
            command.append(" gcloud auth application-default print-access-token 2>&1"_ctv);
            return true;
         }
         case MothershipProviderCredentialMode::azureCli:
         {
            if (failure) failure->assign("azureCli provider credential mode is invalid for GCP refresh");
            return false;
         }
         case MothershipProviderCredentialMode::awsCli:
         {
            if (failure) failure->assign("awsCli provider credential mode is invalid for GCP refresh");
            return false;
         }
         case MothershipProviderCredentialMode::awsImds:
         {
            if (failure) failure->assign("awsImds provider credential mode is invalid for GCP refresh");
            return false;
         }
      }

      if (failure) failure->assign("provider credential mode invalid");
      return false;
   }

   static void describeGcpBootstrapAccessTokenRefreshHint(const MothershipProviderCredential& credential, String& hint)
   {
      hint.clear();
      switch (credential.mode)
      {
         case MothershipProviderCredentialMode::gcloud:
         {
            hint.assign("run `gcloud auth login` or refresh the active local gcloud session"_ctv);
            return;
         }
         case MothershipProviderCredentialMode::gcloudImpersonation:
         {
            hint.assign("refresh the local gcloud session or restore impersonation access for the configured service account"_ctv);
            return;
         }
         case MothershipProviderCredentialMode::externalAccountFile:
         {
            hint.assign("refresh the configured external-account credential or local ADC session"_ctv);
            return;
         }
         case MothershipProviderCredentialMode::staticMaterial:
         {
            return;
         }
         case MothershipProviderCredentialMode::azureCli:
         {
            return;
         }
         case MothershipProviderCredentialMode::awsCli:
         {
            return;
         }
         case MothershipProviderCredentialMode::awsImds:
         {
            return;
         }
      }
   }

   static void describeAzureBootstrapAccessTokenRefreshHint(const MothershipProviderCredential& credential, String& hint)
   {
      hint.clear();
      switch (credential.mode)
      {
         case MothershipProviderCredentialMode::azureCli:
         {
            hint.assign("run `az login` or refresh the active local Azure CLI session"_ctv);
            return;
         }
         case MothershipProviderCredentialMode::staticMaterial:
         case MothershipProviderCredentialMode::gcloud:
         case MothershipProviderCredentialMode::gcloudImpersonation:
         case MothershipProviderCredentialMode::externalAccountFile:
         case MothershipProviderCredentialMode::awsCli:
         case MothershipProviderCredentialMode::awsImds:
         {
            return;
         }
      }
   }

   static void describeAwsBootstrapCredentialRefreshHint(const MothershipProviderCredential& credential, String& hint)
   {
      hint.clear();
      switch (credential.mode)
      {
         case MothershipProviderCredentialMode::awsCli:
         {
            hint.assign("run `aws sso login` or refresh the active local AWS CLI session/profile"_ctv);
            return;
         }
         case MothershipProviderCredentialMode::staticMaterial:
         case MothershipProviderCredentialMode::gcloud:
         case MothershipProviderCredentialMode::gcloudImpersonation:
         case MothershipProviderCredentialMode::externalAccountFile:
         case MothershipProviderCredentialMode::azureCli:
         case MothershipProviderCredentialMode::awsImds:
         {
            return;
         }
      }
   }

   static bool normalizeCredentialForStorage(MothershipProviderCredential& credential, bool creating, String *failure)
   {
      if (stringHasContent(credential.name) == false)
      {
         if (failure) failure->assign("provider credential name required");
         return false;
      }

      if (credential.provider == MothershipClusterProvider::unknown)
      {
         if (failure) failure->assign("provider credential provider required");
         return false;
      }

      if ((credential.mode == MothershipProviderCredentialMode::gcloud
         || credential.mode == MothershipProviderCredentialMode::gcloudImpersonation
         || credential.mode == MothershipProviderCredentialMode::externalAccountFile)
         && credential.provider != MothershipClusterProvider::gcp)
      {
         if (failure) failure->assign("non-static provider credential modes currently require provider=gcp");
         return false;
      }

      if (credential.mode == MothershipProviderCredentialMode::azureCli
         && credential.provider != MothershipClusterProvider::azure)
      {
         if (failure) failure->assign("azureCli provider credential mode requires provider=azure");
         return false;
      }

      if (credential.mode == MothershipProviderCredentialMode::awsCli
         && credential.provider != MothershipClusterProvider::aws)
      {
         if (failure) failure->assign("awsCli provider credential mode requires provider=aws");
         return false;
      }

      if (credential.mode == MothershipProviderCredentialMode::awsImds
         && credential.provider != MothershipClusterProvider::aws)
      {
         if (failure) failure->assign("awsImds provider credential mode requires provider=aws");
         return false;
      }

      if (credential.mode == MothershipProviderCredentialMode::staticMaterial)
      {
         if (stringHasContent(credential.material) == false)
         {
            if (failure) failure->assign("provider credential material required");
            return false;
         }
      }
      else
      {
         credential.material.clear();
      }

      if (credential.mode == MothershipProviderCredentialMode::gcloudImpersonation
         && stringHasContent(credential.impersonateServiceAccount) == false)
      {
         if (failure) failure->assign("provider credential impersonateServiceAccount required");
         return false;
      }

      if (credential.mode != MothershipProviderCredentialMode::gcloudImpersonation)
      {
         credential.impersonateServiceAccount.clear();
      }

      if (credential.mode == MothershipProviderCredentialMode::externalAccountFile)
      {
         if (stringHasContent(credential.credentialPath) == false)
         {
            if (failure) failure->assign("provider credential credentialPath required");
            return false;
         }
         if (credential.credentialPath[0] != '/')
         {
            if (failure) failure->assign("provider credential credentialPath must be absolute");
            return false;
         }
      }
      else
      {
         credential.credentialPath.clear();
      }

      if (credential.allowPropagateToProdigy && credential.mode != MothershipProviderCredentialMode::staticMaterial)
      {
         if (failure) failure->assign("only staticMaterial provider credentials may propagate to Prodigy");
         return false;
      }

      int64_t now = Time::now<TimeResolution::ms>();
      if (creating && credential.createdAtMs == 0)
      {
         credential.createdAtMs = now;
      }

      credential.updatedAtMs = now;
      return true;
   }

public:

   explicit MothershipProviderCredentialRegistry(const String& path = ""_ctv)
      : db(path.size() > 0 ? path : [] () -> String {
         String resolved;
         resolveDefaultDBPath(resolved);
         return resolved;
      }())
   {
   }

   static bool resolveCredentialMaterial(const MothershipProviderCredential& credential, String& material, String *failure = nullptr)
   {
      material.clear();
      if (failure) failure->clear();

      switch (credential.mode)
      {
         case MothershipProviderCredentialMode::staticMaterial:
         {
            material = credential.material;
            if (stringHasContent(material) == false)
            {
               if (failure) failure->assign("provider credential material required");
               return false;
            }
            return true;
         }
         case MothershipProviderCredentialMode::gcloud:
         case MothershipProviderCredentialMode::gcloudImpersonation:
         case MothershipProviderCredentialMode::externalAccountFile:
         {
            if (credential.provider != MothershipClusterProvider::gcp)
            {
               if (failure) failure->assign("non-static provider credential modes currently require provider=gcp");
               return false;
            }
            return resolveGcpBootstrapAccessToken(credential, material, failure);
         }
         case MothershipProviderCredentialMode::azureCli:
         {
            if (credential.provider != MothershipClusterProvider::azure)
            {
               if (failure) failure->assign("azureCli provider credential mode requires provider=azure");
               return false;
            }
            return resolveAzureBootstrapAccessToken(credential, material, failure);
         }
         case MothershipProviderCredentialMode::awsCli:
         {
            if (credential.provider != MothershipClusterProvider::aws)
            {
               if (failure) failure->assign("awsCli provider credential mode requires provider=aws");
               return false;
            }
            return resolveAwsBootstrapCredentialMaterial(credential, material, failure);
         }
         case MothershipProviderCredentialMode::awsImds:
         {
            if (credential.provider != MothershipClusterProvider::aws)
            {
               if (failure) failure->assign("awsImds provider credential mode requires provider=aws");
               return false;
            }
            return true;
         }
      }

      if (failure) failure->assign("provider credential mode invalid");
      return false;
   }

   static bool applyCredentialToRuntimeEnvironment(const MothershipProviderCredential& credential, ProdigyRuntimeEnvironmentConfig& runtimeEnvironment, String *failure = nullptr)
   {
      runtimeEnvironment.providerCredentialMaterial.clear();
      runtimeEnvironment.aws.bootstrapCredentialRefreshCommand.clear();
      runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint.clear();
      runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand.clear();
      runtimeEnvironment.gcp.bootstrapAccessTokenRefreshFailureHint.clear();
      runtimeEnvironment.azure.bootstrapAccessTokenRefreshCommand.clear();
      runtimeEnvironment.azure.bootstrapAccessTokenRefreshFailureHint.clear();
      if (failure) failure->clear();

      if (resolveCredentialMaterial(credential, runtimeEnvironment.providerCredentialMaterial, failure) == false)
      {
         return false;
      }

      if (credential.provider == MothershipClusterProvider::gcp
         && credential.mode != MothershipProviderCredentialMode::staticMaterial)
      {
         if (buildGcpBootstrapAccessTokenRefreshCommand(credential, runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand, failure) == false)
         {
            runtimeEnvironment.providerCredentialMaterial.clear();
            runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand.clear();
            return false;
         }

         describeGcpBootstrapAccessTokenRefreshHint(credential, runtimeEnvironment.gcp.bootstrapAccessTokenRefreshFailureHint);
      }
      else if (credential.provider == MothershipClusterProvider::azure
         && credential.mode == MothershipProviderCredentialMode::azureCli)
      {
         if (buildAzureBootstrapAccessTokenRefreshCommand(credential, runtimeEnvironment.azure.bootstrapAccessTokenRefreshCommand, failure) == false)
         {
            runtimeEnvironment.providerCredentialMaterial.clear();
            runtimeEnvironment.azure.bootstrapAccessTokenRefreshCommand.clear();
            return false;
         }

         describeAzureBootstrapAccessTokenRefreshHint(credential, runtimeEnvironment.azure.bootstrapAccessTokenRefreshFailureHint);
      }
      else if (credential.provider == MothershipClusterProvider::aws
         && credential.mode == MothershipProviderCredentialMode::awsCli)
      {
         if (buildAwsBootstrapCredentialRefreshCommand(credential, runtimeEnvironment.aws.bootstrapCredentialRefreshCommand, failure) == false)
         {
            runtimeEnvironment.providerCredentialMaterial.clear();
            runtimeEnvironment.aws.bootstrapCredentialRefreshCommand.clear();
            return false;
         }

         describeAwsBootstrapCredentialRefreshHint(credential, runtimeEnvironment.aws.bootstrapCredentialRefreshFailureHint);
      }

      return true;
   }

   bool credentialExists(const String& name, bool& exists, String *failure = nullptr)
   {
      exists = false;

      if (name.size() == 0)
      {
         if (failure) failure->assign("provider credential name required");
         return false;
      }

      String serialized;
      String readFailure;
      if (db.read(credentialsColumnFamily, name, serialized, &readFailure))
      {
         exists = true;
         if (failure) failure->clear();
         return true;
      }

      if (readFailure == "record not found"_ctv)
      {
         if (failure) failure->clear();
         return true;
      }

      if (failure) *failure = readFailure;
      return false;
   }

   bool upsertCredential(const MothershipProviderCredential& credential, MothershipProviderCredential *storedCredential = nullptr, String *failure = nullptr)
   {
      MothershipProviderCredential stored = credential;

      bool exists = false;
      if (credentialExists(stored.name, exists, failure) == false)
      {
         return false;
      }

      if (exists)
      {
         MothershipProviderCredential existing = {};
         if (getCredential(stored.name, existing, failure) == false)
         {
            return false;
         }

         stored.createdAtMs = existing.createdAtMs;
      }

      if (normalizeCredentialForStorage(stored, !exists, failure) == false)
      {
         return false;
      }

      String serialized;
      BitseryEngine::serialize(serialized, stored);
      if (db.write(credentialsColumnFamily, stored.name, serialized, failure) == false)
      {
         return false;
      }

      if (storedCredential != nullptr)
      {
         *storedCredential = stored;
      }

      return true;
   }

   bool createCredential(const MothershipProviderCredential& credential, MothershipProviderCredential *storedCredential = nullptr, String *failure = nullptr)
   {
      bool exists = false;
      if (credentialExists(credential.name, exists, failure) == false)
      {
         return false;
      }

      if (exists)
      {
         if (failure) failure->assign("provider credential already exists");
         return false;
      }

      String serialized;
      MothershipProviderCredential stored = credential;
      if (normalizeCredentialForStorage(stored, true, failure) == false)
      {
         return false;
      }

      BitseryEngine::serialize(serialized, stored);
      if (db.write(credentialsColumnFamily, stored.name, serialized, failure) == false)
      {
         return false;
      }

      if (storedCredential != nullptr)
      {
         *storedCredential = stored;
      }

      return true;
   }

   bool getCredential(const String& name, MothershipProviderCredential& credential, String *failure = nullptr)
   {
      if (name.size() == 0)
      {
         if (failure) failure->assign("provider credential name required");
         return false;
      }

      String serialized;
      if (db.read(credentialsColumnFamily, name, serialized, failure) == false)
      {
         return false;
      }

      if (deserializeCredentialValue(reinterpret_cast<const uint8_t *>(serialized.data()), serialized.size(), credential) == false)
      {
         if (failure) failure->assign("provider credential decode failed");
         return false;
      }

      return true;
   }

   bool removeCredential(const String& name, String *failure = nullptr)
   {
      if (name.size() == 0)
      {
         if (failure) failure->assign("provider credential name required");
         return false;
      }

      return db.remove(credentialsColumnFamily, name, failure);
   }

   bool listCredentials(Vector<MothershipProviderCredential>& credentials, String *failure = nullptr)
   {
      credentials.clear();

      Vector<String> serializedCredentials;
      if (db.listValues(credentialsColumnFamily, serializedCredentials, failure) == false)
      {
         return false;
      }

      for (const String& serialized : serializedCredentials)
      {
         MothershipProviderCredential credential = {};
         if (deserializeCredentialValue(reinterpret_cast<const uint8_t *>(serialized.data()), serialized.size(), credential) == false)
         {
            if (failure) failure->assign("provider credential decode failed");
            return false;
         }

         credentials.push_back(credential);
      }

      return true;
   }
};
