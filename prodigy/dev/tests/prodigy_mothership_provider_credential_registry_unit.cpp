#include <prodigy/mothership/mothership.provider.credentials.h>
#include <services/debug.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>

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
         failed += 1;
      }
   }
};

static bool equalCredentials(const MothershipProviderCredential& lhs, const MothershipProviderCredential& rhs)
{
   return lhs.name.equals(rhs.name)
      && lhs.provider == rhs.provider
      && lhs.mode == rhs.mode
      && lhs.material.equals(rhs.material)
      && lhs.impersonateServiceAccount.equals(rhs.impersonateServiceAccount)
      && lhs.credentialPath.equals(rhs.credentialPath)
      && lhs.scope.equals(rhs.scope)
      && lhs.allowPropagateToProdigy == rhs.allowPropagateToProdigy
      && lhs.createdAtMs == rhs.createdAtMs
      && lhs.updatedAtMs == rhs.updatedAtMs;
}

static bool listContainsCredential(const Vector<MothershipProviderCredential>& credentials, const MothershipProviderCredential& needle)
{
   for (const MothershipProviderCredential& credential : credentials)
   {
      if (equalCredentials(credential, needle))
      {
         return true;
      }
   }

   return false;
}

static bool writeExecutableScript(const std::filesystem::path& path, const char *text)
{
   FILE *file = std::fopen(path.c_str(), "wb");
   if (file == nullptr)
   {
      return false;
   }

   size_t textLength = std::strlen(text);
   bool ok = std::fwrite(text, 1, textLength, file) == textLength;
   ok = std::fclose(file) == 0 && ok;
   if (ok == false)
   {
      return false;
   }

   std::filesystem::permissions(path,
      std::filesystem::perms::owner_read
         | std::filesystem::perms::owner_write
         | std::filesystem::perms::owner_exec,
      std::filesystem::perm_options::replace);
   return true;
}

static bool writeFile(const std::filesystem::path& path, const char *text)
{
   FILE *file = std::fopen(path.c_str(), "wb");
   if (file == nullptr)
   {
      return false;
   }

   size_t textLength = std::strlen(text);
   bool ok = std::fwrite(text, 1, textLength, file) == textLength;
   return std::fclose(file) == 0 && ok;
}

static bool stringContains(const String& value, const char *needle)
{
   if (needle == nullptr)
   {
      return false;
   }

   String text = {};
   text.assign(value);
   return std::strstr(text.c_str(), needle) != nullptr;
}

int main(void)
{
   TestSuite suite;

   char scratch[] = "/tmp/nametag-mothership-provider-creds-XXXXXX";
   char *created = mkdtemp(scratch);
   suite.expect(created != nullptr, "mkdtemp_created");
   if (created == nullptr)
   {
      return EXIT_FAILURE;
   }

   String dbPath;
   dbPath.assign(created);

   std::filesystem::path fakeGcloudDir = std::filesystem::path(created) / "fake-gcloud-bin";
   std::error_code pathError = {};
   std::filesystem::create_directories(fakeGcloudDir, pathError);
   suite.expect(!pathError, "create_fake_gcloud_dir");

   std::filesystem::path fakeGcloudPath = fakeGcloudDir / "gcloud";
   suite.expect(writeExecutableScript(fakeGcloudPath,
      "#!/usr/bin/env bash\n"
      "set -e\n"
      "if [ \"$1\" = \"auth\" ] && [ \"$2\" = \"print-access-token\" ]; then\n"
      "  if [ \"$3\" = \"--impersonate-service-account=bootstrap@example.iam.gserviceaccount.com\" ]; then\n"
      "    printf 'impersonated-token\\n'\n"
      "    exit 0\n"
      "  fi\n"
      "  printf 'gcloud-token\\n'\n"
      "  exit 0\n"
      "fi\n"
      "if [ \"$1\" = \"auth\" ] && [ \"$2\" = \"application-default\" ] && [ \"$3\" = \"print-access-token\" ]; then\n"
      "  printf 'external-token\\n'\n"
      "  exit 0\n"
      "fi\n"
      "printf 'unexpected gcloud args: %s\\n' \"$*\" >&2\n"
      "exit 9\n"),
      "write_fake_gcloud");

   std::filesystem::path fakeAwsPath = fakeGcloudDir / "aws";
   suite.expect(writeExecutableScript(fakeAwsPath,
      "#!/usr/bin/env bash\n"
      "set -e\n"
      "if [ \"$1\" = \"configure\" ] && [ \"$2\" = \"export-credentials\" ] && [ \"$3\" = \"--format\" ] && [ \"$4\" = \"process\" ]; then\n"
      "  printf '%s\\n' '{\"Version\":1,\"AccessKeyId\":\"ASIAEXAMPLE\",\"SecretAccessKey\":\"secret\",\"SessionToken\":\"session\",\"Expiration\":\"2026-03-22T10:00:00Z\"}'\n"
      "  exit 0\n"
      "fi\n"
      "printf 'unexpected aws args: %s\\n' \"$*\" >&2\n"
      "exit 9\n"),
      "write_fake_aws");

   std::filesystem::path fakeAzPath = fakeGcloudDir / "az";
   suite.expect(writeExecutableScript(fakeAzPath,
      "#!/usr/bin/env bash\n"
      "set -e\n"
      "if [ \"$1\" = \"account\" ] && [ \"$2\" = \"get-access-token\" ]; then\n"
      "  printf 'azure-token\\n'\n"
      "  exit 0\n"
      "fi\n"
      "printf 'unexpected az args: %s\\n' \"$*\" >&2\n"
      "exit 9\n"),
      "write_fake_az");

   std::string originalPath = [] () -> std::string {
      const char *value = std::getenv("PATH");
      return value ? std::string(value) : std::string();
   }();

   std::string fakePath = fakeGcloudDir.string();
   if (!originalPath.empty())
   {
      fakePath.append(":");
      fakePath.append(originalPath);
   }
   suite.expect(::setenv("PATH", fakePath.c_str(), 1) == 0, "set_fake_gcloud_path");

   std::filesystem::path externalAccountPath = std::filesystem::path(created) / "gcp-external-account.json";
   suite.expect(writeFile(externalAccountPath, "{}\n"), "write_gcp_external_account_file");

   MothershipProviderCredential aws = {};
   aws.name = "aws-prod"_ctv;
   aws.provider = MothershipClusterProvider::aws;
   aws.material = "aws-secret-1"_ctv;
   aws.scope = "acct-prod/us-east-1"_ctv;
   aws.allowPropagateToProdigy = false;

   MothershipProviderCredential azure = {};
   azure.name = "azure-prod"_ctv;
   azure.provider = MothershipClusterProvider::azure;
   azure.material = "azure-secret-1"_ctv;
   azure.scope = "sub/prod/eastus"_ctv;
   azure.allowPropagateToProdigy = true;

   MothershipProviderCredential storedAws = {};
   MothershipProviderCredential storedAwsCli = {};
   MothershipProviderCredential storedAwsImds = {};
   MothershipProviderCredential storedAzure = {};
   MothershipProviderCredential storedGcpGcloud = {};
   MothershipProviderCredential storedGcpImpersonation = {};
   MothershipProviderCredential storedGcpExternalAccount = {};

   {
      String failure;

      MothershipProdigyCluster inlineNamed = {};
      inlineNamed.name = "managed-inline"_ctv;
      inlineNamed.deploymentMode = MothershipClusterDeploymentMode::remote;
      inlineNamed.provider = MothershipClusterProvider::aws;
      inlineNamed.providerScope = "acct-inline/us-east-1"_ctv;
      inlineNamed.propagateProviderCredentialToProdigy = true;

      MothershipProviderCredential inlineNamedOverride = {};
      inlineNamedOverride.material = "inline-secret"_ctv;

      bool resolveInlineNamed = resolveMothershipClusterInlineProviderCredentialOverride(inlineNamed, inlineNamedOverride, &failure);
      suite.expect(resolveInlineNamed, "resolve_inline_named");
      suite.expect(inlineNamed.providerCredentialName.equals("managed-inline-provider"_ctv), "resolve_inline_named_cluster_credential_name");
      suite.expect(inlineNamedOverride.name.equals("managed-inline-provider"_ctv), "resolve_inline_named_override_name");
      suite.expect(inlineNamedOverride.provider == MothershipClusterProvider::aws, "resolve_inline_named_provider");
      suite.expect(inlineNamedOverride.scope.equals("acct-inline/us-east-1"_ctv), "resolve_inline_named_scope");
      suite.expect(inlineNamedOverride.allowPropagateToProdigy, "resolve_inline_named_propagate");

      MothershipProdigyCluster inlineFromOverride = {};
      inlineFromOverride.name = "managed-inline-override"_ctv;
      inlineFromOverride.deploymentMode = MothershipClusterDeploymentMode::remote;

      MothershipProviderCredential inlineFromOverrideCredential = {};
      inlineFromOverrideCredential.name = "azure-prod-inline"_ctv;
      inlineFromOverrideCredential.provider = MothershipClusterProvider::azure;
      inlineFromOverrideCredential.material = "azure-inline-secret"_ctv;
      inlineFromOverrideCredential.scope = "sub/prod/eastus"_ctv;

      bool resolveInlineFromOverride = resolveMothershipClusterInlineProviderCredentialOverride(inlineFromOverride, inlineFromOverrideCredential, &failure);
      suite.expect(resolveInlineFromOverride, "resolve_inline_from_override");
      suite.expect(inlineFromOverride.provider == MothershipClusterProvider::azure, "resolve_inline_from_override_provider");
      suite.expect(inlineFromOverride.providerCredentialName.equals("azure-prod-inline"_ctv), "resolve_inline_from_override_name");
      suite.expect(inlineFromOverride.providerScope.equals("sub/prod/eastus"_ctv), "resolve_inline_from_override_scope");

      MothershipProdigyCluster invalidLocal = {};
      invalidLocal.name = "local-inline"_ctv;
      invalidLocal.deploymentMode = MothershipClusterDeploymentMode::local;

      MothershipProviderCredential invalidLocalOverride = {};
      invalidLocalOverride.name = "local-inline-provider"_ctv;
      invalidLocalOverride.provider = MothershipClusterProvider::aws;
      invalidLocalOverride.material = "local-inline-secret"_ctv;

      bool resolveInvalidLocal = resolveMothershipClusterInlineProviderCredentialOverride(invalidLocal, invalidLocalOverride, &failure);
      suite.expect(resolveInvalidLocal == false, "resolve_inline_local_rejected");
      suite.expect(failure.equals("providerless clusters must not include providerCredentialOverride"_ctv), "resolve_inline_local_reason");

      MothershipProdigyCluster invalidTest = {};
      invalidTest.name = "test-inline"_ctv;
      invalidTest.deploymentMode = MothershipClusterDeploymentMode::test;

      MothershipProviderCredential invalidTestOverride = {};
      invalidTestOverride.name = "test-inline-provider"_ctv;
      invalidTestOverride.provider = MothershipClusterProvider::aws;
      invalidTestOverride.material = "test-inline-secret"_ctv;

      bool resolveInvalidTest = resolveMothershipClusterInlineProviderCredentialOverride(invalidTest, invalidTestOverride, &failure);
      suite.expect(resolveInvalidTest == false, "resolve_inline_test_rejected");
      suite.expect(failure.equals("providerless clusters must not include providerCredentialOverride"_ctv), "resolve_inline_test_reason");

      MothershipProdigyCluster invalidMismatch = inlineNamed;
      invalidMismatch.providerCredentialName = "aws-prod"_ctv;

      MothershipProviderCredential invalidMismatchOverride = {};
      invalidMismatchOverride.name = "different-name"_ctv;
      invalidMismatchOverride.provider = MothershipClusterProvider::aws;
      invalidMismatchOverride.material = "different-secret"_ctv;

      bool resolveInvalidMismatch = resolveMothershipClusterInlineProviderCredentialOverride(invalidMismatch, invalidMismatchOverride, &failure);
      suite.expect(resolveInvalidMismatch == false, "resolve_inline_name_mismatch_rejected");
      suite.expect(failure.equals("providerCredentialOverride name does not match providerCredentialName"_ctv), "resolve_inline_name_mismatch_reason");
   }

   {
      MothershipProviderCredentialRegistry registry(dbPath);
      String failure;

      bool createAws = registry.createCredential(aws, &storedAws, &failure);
      if (!createAws) basics_log("detail create_aws: %s\n", failure.c_str());
      suite.expect(createAws, "create_aws");
      suite.expect(storedAws.createdAtMs > 0, "create_aws_createdAtMs");
      suite.expect(storedAws.updatedAtMs >= storedAws.createdAtMs, "create_aws_updatedAtMs");

      MothershipProviderCredential duplicateAws = aws;
      bool createDuplicateAws = registry.createCredential(duplicateAws, nullptr, &failure);
      suite.expect(createDuplicateAws == false, "create_duplicate_aws_rejected");
      suite.expect(failure.equals("provider credential already exists"_ctv), "create_duplicate_aws_reason");

      MothershipProviderCredential invalidMissingMaterial = {};
      invalidMissingMaterial.name = "missing-material"_ctv;
      invalidMissingMaterial.provider = MothershipClusterProvider::aws;
      invalidMissingMaterial.scope = "acct-prod/us-east-1"_ctv;
      bool createMissingMaterial = registry.createCredential(invalidMissingMaterial, nullptr, &failure);
      suite.expect(createMissingMaterial == false, "create_missing_material_rejected");
      suite.expect(failure.equals("provider credential material required"_ctv), "create_missing_material_reason");

      MothershipProviderCredential invalidUnknownProvider = aws;
      invalidUnknownProvider.name = "unknown-provider"_ctv;
      invalidUnknownProvider.provider = MothershipClusterProvider::unknown;
      bool createUnknownProvider = registry.createCredential(invalidUnknownProvider, nullptr, &failure);
      suite.expect(createUnknownProvider == false, "create_unknown_provider_rejected");
      suite.expect(failure.equals("provider credential provider required"_ctv), "create_unknown_provider_reason");

      MothershipProviderCredential gcpGcloud = {};
      gcpGcloud.name = "gcp-gcloud"_ctv;
      gcpGcloud.provider = MothershipClusterProvider::gcp;
      gcpGcloud.mode = MothershipProviderCredentialMode::gcloud;
      gcpGcloud.scope = "projects/example/zones/us-central1-a"_ctv;
      bool createGcpGcloud = registry.createCredential(gcpGcloud, &storedGcpGcloud, &failure);
      suite.expect(createGcpGcloud, "create_gcp_gcloud_profile");
      suite.expect(storedGcpGcloud.material.size() == 0, "create_gcp_gcloud_profile_material_cleared");
      suite.expect(storedGcpGcloud.mode == MothershipProviderCredentialMode::gcloud, "create_gcp_gcloud_profile_mode");

      MothershipProviderCredential awsCli = {};
      awsCli.name = "aws-cli"_ctv;
      awsCli.provider = MothershipClusterProvider::aws;
      awsCli.mode = MothershipProviderCredentialMode::awsCli;
      awsCli.scope = "acct-cli/us-east-1"_ctv;
      bool createAwsCli = registry.createCredential(awsCli, &storedAwsCli, &failure);
      suite.expect(createAwsCli, "create_aws_cli_profile");
      suite.expect(storedAwsCli.material.size() == 0, "create_aws_cli_profile_material_cleared");
      suite.expect(storedAwsCli.mode == MothershipProviderCredentialMode::awsCli, "create_aws_cli_profile_mode");

      MothershipProviderCredential awsImds = {};
      awsImds.name = "aws-imds"_ctv;
      awsImds.provider = MothershipClusterProvider::aws;
      awsImds.mode = MothershipProviderCredentialMode::awsImds;
      awsImds.scope = "acct-imds/us-east-1"_ctv;
      bool createAwsImds = registry.createCredential(awsImds, &storedAwsImds, &failure);
      suite.expect(createAwsImds, "create_aws_imds_profile");
      suite.expect(storedAwsImds.material.size() == 0, "create_aws_imds_profile_material_cleared");
      suite.expect(storedAwsImds.mode == MothershipProviderCredentialMode::awsImds, "create_aws_imds_profile_mode");

      MothershipProviderCredential gcpImpersonation = {};
      gcpImpersonation.name = "gcp-impersonation"_ctv;
      gcpImpersonation.provider = MothershipClusterProvider::gcp;
      gcpImpersonation.mode = MothershipProviderCredentialMode::gcloudImpersonation;
      gcpImpersonation.impersonateServiceAccount = "bootstrap@example.iam.gserviceaccount.com"_ctv;
      gcpImpersonation.scope = "projects/example/zones/us-central1-b"_ctv;
      bool createGcpImpersonation = registry.createCredential(gcpImpersonation, &storedGcpImpersonation, &failure);
      suite.expect(createGcpImpersonation, "create_gcp_impersonation_profile");
      suite.expect(storedGcpImpersonation.material.size() == 0, "create_gcp_impersonation_profile_material_cleared");
      suite.expect(storedGcpImpersonation.impersonateServiceAccount.equals("bootstrap@example.iam.gserviceaccount.com"_ctv), "create_gcp_impersonation_profile_service_account");

      MothershipProviderCredential gcpExternalAccount = {};
      gcpExternalAccount.name = "gcp-external-account"_ctv;
      gcpExternalAccount.provider = MothershipClusterProvider::gcp;
      gcpExternalAccount.mode = MothershipProviderCredentialMode::externalAccountFile;
      gcpExternalAccount.credentialPath.assign(externalAccountPath.c_str());
      gcpExternalAccount.scope = "projects/example/zones/us-central1-c"_ctv;
      bool createGcpExternalAccount = registry.createCredential(gcpExternalAccount, &storedGcpExternalAccount, &failure);
      suite.expect(createGcpExternalAccount, "create_gcp_external_account_profile");
      suite.expect(storedGcpExternalAccount.material.size() == 0, "create_gcp_external_account_profile_material_cleared");
      suite.expect(storedGcpExternalAccount.credentialPath.equals(gcpExternalAccount.credentialPath), "create_gcp_external_account_profile_path");

      ProdigyRuntimeEnvironmentConfig gcpRuntime = {};
      bool applyGcpRuntime = MothershipProviderCredentialRegistry::applyCredentialToRuntimeEnvironment(gcpGcloud, gcpRuntime, &failure);
      suite.expect(applyGcpRuntime, "apply_gcp_gcloud_runtime_environment");
      suite.expect(gcpRuntime.providerCredentialMaterial.equals("gcloud-token"_ctv), "apply_gcp_gcloud_runtime_environment_token");
      suite.expect(stringContains(gcpRuntime.gcp.bootstrapAccessTokenRefreshCommand, "gcloud auth print-access-token"), "apply_gcp_gcloud_runtime_environment_refresh_command");
      suite.expect(stringContains(gcpRuntime.gcp.bootstrapAccessTokenRefreshFailureHint, "gcloud auth login"), "apply_gcp_gcloud_runtime_environment_refresh_hint");

      ProdigyRuntimeEnvironmentConfig awsRuntime = {};
      bool applyAwsRuntime = MothershipProviderCredentialRegistry::applyCredentialToRuntimeEnvironment(storedAws, awsRuntime, &failure);
      suite.expect(applyAwsRuntime, "apply_aws_runtime_environment");
      suite.expect(awsRuntime.providerCredentialMaterial.equals(storedAws.material), "apply_aws_runtime_environment_material");
      suite.expect(awsRuntime.gcp.bootstrapAccessTokenRefreshCommand.size() == 0, "apply_aws_runtime_environment_no_gcp_refresh");

      ProdigyRuntimeEnvironmentConfig awsCliRuntime = {};
      bool applyAwsCliRuntime = MothershipProviderCredentialRegistry::applyCredentialToRuntimeEnvironment(storedAwsCli, awsCliRuntime, &failure);
      suite.expect(applyAwsCliRuntime, "apply_aws_cli_runtime_environment");
      suite.expect(awsCliRuntime.providerCredentialMaterial.equals("{\"Version\":1,\"AccessKeyId\":\"ASIAEXAMPLE\",\"SecretAccessKey\":\"secret\",\"SessionToken\":\"session\",\"Expiration\":\"2026-03-22T10:00:00Z\"}"_ctv), "apply_aws_cli_runtime_environment_material");
      suite.expect(stringContains(awsCliRuntime.aws.bootstrapCredentialRefreshCommand, "aws configure export-credentials --format process"), "apply_aws_cli_runtime_environment_refresh_command");

      MothershipProviderCredential azureCli = {};
      azureCli.name = "azure-cli"_ctv;
      azureCli.provider = MothershipClusterProvider::azure;
      azureCli.mode = MothershipProviderCredentialMode::azureCli;
      azureCli.scope = "subscriptions/example/resourceGroups/rg/locations/northcentralus"_ctv;

      ProdigyRuntimeEnvironmentConfig azureCliRuntime = {};
      bool applyAzureCliRuntime = MothershipProviderCredentialRegistry::applyCredentialToRuntimeEnvironment(azureCli, azureCliRuntime, &failure);
      suite.expect(applyAzureCliRuntime, "apply_azure_cli_runtime_environment");
      suite.expect(azureCliRuntime.providerCredentialMaterial.equals("azure-token"_ctv), "apply_azure_cli_runtime_environment_material");
      suite.expect(stringContains(azureCliRuntime.azure.bootstrapAccessTokenRefreshCommand, fakeAzPath.c_str()), "apply_azure_cli_runtime_environment_refresh_command_uses_absolute_path");
      suite.expect(stringContains(azureCliRuntime.azure.bootstrapAccessTokenRefreshCommand, "account get-access-token"), "apply_azure_cli_runtime_environment_refresh_command");
      suite.expect(stringContains(azureCliRuntime.azure.bootstrapAccessTokenRefreshFailureHint, "az login"), "apply_azure_cli_runtime_environment_refresh_hint");
      MothershipProviderCredential azureStaticMaterial = {};
      azureStaticMaterial.name = "azure-static"_ctv;
      azureStaticMaterial.provider = MothershipClusterProvider::azure;
      azureStaticMaterial.mode = MothershipProviderCredentialMode::staticMaterial;
      azureStaticMaterial.material = "{\"tenantId\":\"tenant-a\",\"clientId\":\"client-a\",\"clientSecret\":\"secret-a\"}"_ctv;
      azureStaticMaterial.scope = "subscriptions/example/resourceGroups/rg/locations/northcentralus"_ctv;

      ProdigyRuntimeEnvironmentConfig azureStaticRuntime = {};
      bool applyAzureStaticRuntime = MothershipProviderCredentialRegistry::applyCredentialToRuntimeEnvironment(azureStaticMaterial, azureStaticRuntime, &failure);
      suite.expect(applyAzureStaticRuntime, "apply_azure_static_runtime_environment");
      suite.expect(azureStaticRuntime.providerCredentialMaterial.equals(azureStaticMaterial.material), "apply_azure_static_runtime_environment_material");
      suite.expect(azureStaticRuntime.azure.bootstrapAccessTokenRefreshCommand.size() == 0, "apply_azure_static_runtime_environment_no_refresh_command");
      suite.expect(azureStaticRuntime.azure.bootstrapAccessTokenRefreshFailureHint.size() == 0, "apply_azure_static_runtime_environment_no_refresh_hint");
      suite.expect(stringContains(awsCliRuntime.aws.bootstrapCredentialRefreshFailureHint, "aws sso login"), "apply_aws_cli_runtime_environment_refresh_hint");
      suite.expect(awsCliRuntime.gcp.bootstrapAccessTokenRefreshCommand.size() == 0, "apply_aws_cli_runtime_environment_no_gcp_refresh");

      ProdigyRuntimeEnvironmentConfig awsImdsRuntime = {};
      bool applyAwsImdsRuntime = MothershipProviderCredentialRegistry::applyCredentialToRuntimeEnvironment(storedAwsImds, awsImdsRuntime, &failure);
      suite.expect(applyAwsImdsRuntime, "apply_aws_imds_runtime_environment");
      suite.expect(awsImdsRuntime.providerCredentialMaterial.size() == 0, "apply_aws_imds_runtime_environment_material_empty");
      suite.expect(awsImdsRuntime.aws.bootstrapCredentialRefreshCommand.size() == 0, "apply_aws_imds_runtime_environment_refresh_command_empty");
      suite.expect(awsImdsRuntime.aws.bootstrapCredentialRefreshFailureHint.size() == 0, "apply_aws_imds_runtime_environment_refresh_hint_empty");

      ProdigyRuntimeEnvironmentConfig gcpImpersonationRuntime = {};
      bool applyGcpImpersonationRuntime = MothershipProviderCredentialRegistry::applyCredentialToRuntimeEnvironment(storedGcpImpersonation, gcpImpersonationRuntime, &failure);
      suite.expect(applyGcpImpersonationRuntime, "apply_gcp_impersonation_runtime_environment");
      suite.expect(gcpImpersonationRuntime.providerCredentialMaterial.equals("impersonated-token"_ctv), "apply_gcp_impersonation_runtime_environment_material");
      suite.expect(stringContains(gcpImpersonationRuntime.gcp.bootstrapAccessTokenRefreshCommand, "--impersonate-service-account='bootstrap@example.iam.gserviceaccount.com'"), "apply_gcp_impersonation_runtime_environment_refresh_command");

      ProdigyRuntimeEnvironmentConfig gcpExternalRuntime = {};
      bool applyGcpExternalRuntime = MothershipProviderCredentialRegistry::applyCredentialToRuntimeEnvironment(storedGcpExternalAccount, gcpExternalRuntime, &failure);
      suite.expect(applyGcpExternalRuntime, "apply_gcp_external_runtime_environment");
      suite.expect(gcpExternalRuntime.providerCredentialMaterial.equals("external-token"_ctv), "apply_gcp_external_runtime_environment_material");
      suite.expect(stringContains(gcpExternalRuntime.gcp.bootstrapAccessTokenRefreshCommand, "GOOGLE_APPLICATION_CREDENTIALS='"), "apply_gcp_external_runtime_environment_refresh_env");
      suite.expect(stringContains(gcpExternalRuntime.gcp.bootstrapAccessTokenRefreshCommand, "gcloud auth application-default print-access-token 2>&1"), "apply_gcp_external_runtime_environment_refresh_command");

      MothershipProviderCredential invalidNonGcpMode = {};
      invalidNonGcpMode.name = "aws-gcloud"_ctv;
      invalidNonGcpMode.provider = MothershipClusterProvider::aws;
      invalidNonGcpMode.mode = MothershipProviderCredentialMode::gcloud;
      bool createInvalidNonGcpMode = registry.createCredential(invalidNonGcpMode, nullptr, &failure);
      suite.expect(createInvalidNonGcpMode == false, "create_non_gcp_gcloud_mode_rejected");
      suite.expect(failure.equals("non-static provider credential modes currently require provider=gcp"_ctv), "create_non_gcp_gcloud_mode_reason");

      MothershipProviderCredential invalidAwsCli = {};
      invalidAwsCli.name = "gcp-aws-cli"_ctv;
      invalidAwsCli.provider = MothershipClusterProvider::gcp;
      invalidAwsCli.mode = MothershipProviderCredentialMode::awsCli;
      bool createInvalidAwsCli = registry.createCredential(invalidAwsCli, nullptr, &failure);
      suite.expect(createInvalidAwsCli == false, "create_non_aws_aws_cli_mode_rejected");
      suite.expect(failure.equals("awsCli provider credential mode requires provider=aws"_ctv), "create_non_aws_aws_cli_mode_reason");

      MothershipProviderCredential invalidAwsImds = {};
      invalidAwsImds.name = "gcp-aws-imds"_ctv;
      invalidAwsImds.provider = MothershipClusterProvider::gcp;
      invalidAwsImds.mode = MothershipProviderCredentialMode::awsImds;
      bool createInvalidAwsImds = registry.createCredential(invalidAwsImds, nullptr, &failure);
      suite.expect(createInvalidAwsImds == false, "create_non_aws_aws_imds_mode_rejected");
      suite.expect(failure.equals("awsImds provider credential mode requires provider=aws"_ctv), "create_non_aws_aws_imds_mode_reason");

      MothershipProviderCredential invalidImpersonation = {};
      invalidImpersonation.name = "gcp-impersonation-missing"_ctv;
      invalidImpersonation.provider = MothershipClusterProvider::gcp;
      invalidImpersonation.mode = MothershipProviderCredentialMode::gcloudImpersonation;
      bool createInvalidImpersonation = registry.createCredential(invalidImpersonation, nullptr, &failure);
      suite.expect(createInvalidImpersonation == false, "create_gcp_impersonation_missing_sa_rejected");
      suite.expect(failure.equals("provider credential impersonateServiceAccount required"_ctv), "create_gcp_impersonation_missing_sa_reason");

      MothershipProviderCredential invalidExternalAccount = {};
      invalidExternalAccount.name = "gcp-external-relative"_ctv;
      invalidExternalAccount.provider = MothershipClusterProvider::gcp;
      invalidExternalAccount.mode = MothershipProviderCredentialMode::externalAccountFile;
      invalidExternalAccount.credentialPath = "relative.json"_ctv;
      bool createInvalidExternalAccount = registry.createCredential(invalidExternalAccount, nullptr, &failure);
      suite.expect(createInvalidExternalAccount == false, "create_gcp_external_relative_rejected");
      suite.expect(failure.equals("provider credential credentialPath must be absolute"_ctv), "create_gcp_external_relative_reason");

      MothershipProviderCredential invalidPropagate = gcpGcloud;
      invalidPropagate.name = "gcp-gcloud-propagate"_ctv;
      invalidPropagate.allowPropagateToProdigy = true;
      bool createInvalidPropagate = registry.createCredential(invalidPropagate, nullptr, &failure);
      suite.expect(createInvalidPropagate == false, "create_gcp_gcloud_propagate_rejected");
      suite.expect(failure.equals("only staticMaterial provider credentials may propagate to Prodigy"_ctv), "create_gcp_gcloud_propagate_reason");

      MothershipProviderCredential loadedAws = {};
      bool getAws = registry.getCredential("aws-prod"_ctv, loadedAws, &failure);
      if (!getAws) basics_log("detail get_aws: %s\n", failure.c_str());
      suite.expect(getAws, "get_aws");
      suite.expect(equalCredentials(storedAws, loadedAws), "get_aws_roundtrip");

      Vector<MothershipProviderCredential> listedCredentials;
      bool listOne = registry.listCredentials(listedCredentials, &failure);
      if (!listOne) basics_log("detail list_one: %s\n", failure.c_str());
      suite.expect(listOne, "list_one");
      suite.expect(listedCredentials.size() == 6, "list_one_count");
      suite.expect(listContainsCredential(listedCredentials, storedAws), "list_one_contains_aws");
      suite.expect(listContainsCredential(listedCredentials, storedAwsCli), "list_one_contains_aws_cli");
      suite.expect(listContainsCredential(listedCredentials, storedAwsImds), "list_one_contains_aws_imds");
      suite.expect(listContainsCredential(listedCredentials, storedGcpGcloud), "list_one_contains_gcp_gcloud");
      suite.expect(listContainsCredential(listedCredentials, storedGcpImpersonation), "list_one_contains_gcp_impersonation");
      suite.expect(listContainsCredential(listedCredentials, storedGcpExternalAccount), "list_one_contains_gcp_external_account");

      MothershipProviderCredential upsertedAws = storedAws;
      upsertedAws.material = "aws-secret-2"_ctv;
      upsertedAws.scope = "acct-prod/us-west-2"_ctv;
      upsertedAws.allowPropagateToProdigy = true;

      MothershipProviderCredential updatedAws = {};
      bool upsertAws = registry.upsertCredential(upsertedAws, &updatedAws, &failure);
      if (!upsertAws) basics_log("detail upsert_aws: %s\n", failure.c_str());
      suite.expect(upsertAws, "upsert_aws");
      suite.expect(updatedAws.createdAtMs == storedAws.createdAtMs, "upsert_aws_preserves_createdAtMs");
      suite.expect(updatedAws.updatedAtMs >= storedAws.updatedAtMs, "upsert_aws_updates_updatedAtMs");
      suite.expect(updatedAws.material.equals("aws-secret-2"_ctv), "upsert_aws_material_changed");
      suite.expect(updatedAws.allowPropagateToProdigy, "upsert_aws_allow_propagate");
      storedAws = updatedAws;

      bool createAzure = registry.createCredential(azure, &storedAzure, &failure);
      if (!createAzure) basics_log("detail create_azure: %s\n", failure.c_str());
      suite.expect(createAzure, "create_azure");

      Vector<MothershipProviderCredential> listedTwo;
      bool listTwo = registry.listCredentials(listedTwo, &failure);
      if (!listTwo) basics_log("detail list_two: %s\n", failure.c_str());
      suite.expect(listTwo, "list_two");
      suite.expect(listedTwo.size() == 7, "list_two_count");
      suite.expect(listContainsCredential(listedTwo, storedAws), "list_two_contains_aws");
      suite.expect(listContainsCredential(listedTwo, storedAwsCli), "list_two_contains_aws_cli");
      suite.expect(listContainsCredential(listedTwo, storedAwsImds), "list_two_contains_aws_imds");
      suite.expect(listContainsCredential(listedTwo, storedAzure), "list_two_contains_azure");
      suite.expect(listContainsCredential(listedTwo, storedGcpGcloud), "list_two_contains_gcp_gcloud");
      suite.expect(listContainsCredential(listedTwo, storedGcpImpersonation), "list_two_contains_gcp_impersonation");
      suite.expect(listContainsCredential(listedTwo, storedGcpExternalAccount), "list_two_contains_gcp_external_account");
   }

   {
      MothershipProviderCredentialRegistry registry(dbPath);
      String failure;

      MothershipProviderCredential loadedAws = {};
      MothershipProviderCredential loadedAwsCli = {};
      MothershipProviderCredential loadedAwsImds = {};
      MothershipProviderCredential loadedAzure = {};
      MothershipProviderCredential loadedGcpGcloud = {};
      MothershipProviderCredential loadedGcpImpersonation = {};
      MothershipProviderCredential loadedGcpExternalAccount = {};

      bool reopenGetAws = registry.getCredential("aws-prod"_ctv, loadedAws, &failure);
      if (!reopenGetAws) basics_log("detail reopen_get_aws: %s\n", failure.c_str());
      suite.expect(reopenGetAws, "reopen_get_aws");

      bool reopenGetAzure = registry.getCredential("azure-prod"_ctv, loadedAzure, &failure);
      if (!reopenGetAzure) basics_log("detail reopen_get_azure: %s\n", failure.c_str());
      suite.expect(reopenGetAzure, "reopen_get_azure");

      bool reopenGetAwsCli = registry.getCredential("aws-cli"_ctv, loadedAwsCli, &failure);
      if (!reopenGetAwsCli) basics_log("detail reopen_get_aws_cli: %s\n", failure.c_str());
      suite.expect(reopenGetAwsCli, "reopen_get_aws_cli");

      bool reopenGetAwsImds = registry.getCredential("aws-imds"_ctv, loadedAwsImds, &failure);
      if (!reopenGetAwsImds) basics_log("detail reopen_get_aws_imds: %s\n", failure.c_str());
      suite.expect(reopenGetAwsImds, "reopen_get_aws_imds");

      bool reopenGetGcpGcloud = registry.getCredential("gcp-gcloud"_ctv, loadedGcpGcloud, &failure);
      if (!reopenGetGcpGcloud) basics_log("detail reopen_get_gcp_gcloud: %s\n", failure.c_str());
      suite.expect(reopenGetGcpGcloud, "reopen_get_gcp_gcloud");

      bool reopenGetGcpImpersonation = registry.getCredential("gcp-impersonation"_ctv, loadedGcpImpersonation, &failure);
      if (!reopenGetGcpImpersonation) basics_log("detail reopen_get_gcp_impersonation: %s\n", failure.c_str());
      suite.expect(reopenGetGcpImpersonation, "reopen_get_gcp_impersonation");

      bool reopenGetGcpExternalAccount = registry.getCredential("gcp-external-account"_ctv, loadedGcpExternalAccount, &failure);
      if (!reopenGetGcpExternalAccount) basics_log("detail reopen_get_gcp_external_account: %s\n", failure.c_str());
      suite.expect(reopenGetGcpExternalAccount, "reopen_get_gcp_external_account");

      suite.expect(equalCredentials(storedAws, loadedAws), "reopen_aws_roundtrip");
      suite.expect(equalCredentials(storedAwsCli, loadedAwsCli), "reopen_aws_cli_roundtrip");
      suite.expect(equalCredentials(storedAwsImds, loadedAwsImds), "reopen_aws_imds_roundtrip");
      suite.expect(equalCredentials(storedAzure, loadedAzure), "reopen_azure_roundtrip");
      suite.expect(equalCredentials(storedGcpGcloud, loadedGcpGcloud), "reopen_gcp_gcloud_roundtrip");
      suite.expect(equalCredentials(storedGcpImpersonation, loadedGcpImpersonation), "reopen_gcp_impersonation_roundtrip");
      suite.expect(equalCredentials(storedGcpExternalAccount, loadedGcpExternalAccount), "reopen_gcp_external_account_roundtrip");

      bool removeAws = registry.removeCredential("aws-prod"_ctv, &failure);
      if (!removeAws) basics_log("detail remove_aws: %s\n", failure.c_str());
      suite.expect(removeAws, "remove_aws");

      bool removeAzure = registry.removeCredential("azure-prod"_ctv, &failure);
      if (!removeAzure) basics_log("detail remove_azure: %s\n", failure.c_str());
      suite.expect(removeAzure, "remove_azure");

      bool removeAwsCli = registry.removeCredential("aws-cli"_ctv, &failure);
      if (!removeAwsCli) basics_log("detail remove_aws_cli: %s\n", failure.c_str());
      suite.expect(removeAwsCli, "remove_aws_cli");

      bool removeAwsImds = registry.removeCredential("aws-imds"_ctv, &failure);
      if (!removeAwsImds) basics_log("detail remove_aws_imds: %s\n", failure.c_str());
      suite.expect(removeAwsImds, "remove_aws_imds");

      bool removeGcpGcloud = registry.removeCredential("gcp-gcloud"_ctv, &failure);
      if (!removeGcpGcloud) basics_log("detail remove_gcp_gcloud: %s\n", failure.c_str());
      suite.expect(removeGcpGcloud, "remove_gcp_gcloud");

      bool removeGcpImpersonation = registry.removeCredential("gcp-impersonation"_ctv, &failure);
      if (!removeGcpImpersonation) basics_log("detail remove_gcp_impersonation: %s\n", failure.c_str());
      suite.expect(removeGcpImpersonation, "remove_gcp_impersonation");

      bool removeGcpExternalAccount = registry.removeCredential("gcp-external-account"_ctv, &failure);
      if (!removeGcpExternalAccount) basics_log("detail remove_gcp_external_account: %s\n", failure.c_str());
      suite.expect(removeGcpExternalAccount, "remove_gcp_external_account");

      Vector<MothershipProviderCredential> listedCredentials;
      bool listEmpty = registry.listCredentials(listedCredentials, &failure);
      if (!listEmpty) basics_log("detail list_empty: %s\n", failure.c_str());
      suite.expect(listEmpty, "list_empty");
      suite.expect(listedCredentials.size() == 0, "list_empty_count");
   }

   std::error_code cleanupError;
   std::filesystem::remove_all(std::string(reinterpret_cast<const char *>(dbPath.data()), dbPath.size()), cleanupError);
   suite.expect(!cleanupError, "cleanup_registry_directory");
   if (originalPath.empty())
   {
      suite.expect(::unsetenv("PATH") == 0, "restore_original_path_empty");
   }
   else
   {
      suite.expect(::setenv("PATH", originalPath.c_str(), 1) == 0, "restore_original_path");
   }

   return (suite.failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
