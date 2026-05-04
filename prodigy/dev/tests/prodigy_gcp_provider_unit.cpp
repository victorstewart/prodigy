#include <networking/includes.h>
#include <services/debug.h>
#include <prodigy/iaas/gcp/gcp.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>

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

class TestableGcpBrainIaaS : public GcpBrainIaaS
{
public:

   bool ensureTokenForTest(String& failure)
   {
      return ensureProviderAccessToken(failure);
   }

   void invalidateCachedTokenForTest(void)
   {
      invalidateProviderAccessTokenCache();
   }
};

static bool writeTextFile(const std::filesystem::path& path, const char *text)
{
   FILE *file = std::fopen(path.c_str(), "wb");
   if (file == nullptr)
   {
      return false;
   }

   size_t textLength = std::strlen(text);
   bool ok = std::fwrite(text, 1, textLength, file) == textLength;
   ok = std::fclose(file) == 0 && ok;
   return ok;
}

static bool stringContains(const String& haystack, const char *needle);

static bool authHeaderContainsToken(TestableGcpBrainIaaS& brain, const char *tokenText)
{
   struct curl_slist *headers = nullptr;
   brain.buildAuthHeaders(headers);

   bool found = false;
   for (const struct curl_slist *cursor = headers; cursor != nullptr; cursor = cursor->next)
   {
      if (cursor->data != nullptr)
      {
         String header = {};
         header.assign(cursor->data);
         String expectedFragment = {};
         expectedFragment.assign("Bearer "_ctv);
         expectedFragment.append(tokenText);
         if (stringContains(header, expectedFragment.c_str()))
         {
            found = true;
            break;
         }
      }
   }

   curl_slist_free_all(headers);
   return found;
}

static bool stringContains(const String& haystack, const char *needle)
{
   size_t needleLength = std::strlen(needle);
   if (needleLength == 0)
   {
      return true;
   }

   return std::search(haystack.data(),
      haystack.data() + haystack.size(),
      needle,
      needle + needleLength) != (haystack.data() + haystack.size());
}

int main(void)
{
   TestSuite suite = {};

   GcpBrainIaaS gcpBrain = {};
   BrainIaaS& brain = gcpBrain;

   ProdigyRuntimeEnvironmentConfig runtimeEnvironment = {};
   runtimeEnvironment.kind = ProdigyEnvironmentKind::gcp;
   runtimeEnvironment.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
   runtimeEnvironment.providerCredentialMaterial = "test-token"_ctv;
   brain.configureRuntimeEnvironment(runtimeEnvironment);
   brain.configureBootstrapSSHAccess("root"_ctv, {}, {}, ""_ctv);

   suite.expect(brain.supportedMachineKindsMask() == 2u, "gcp_supports_vm_only");
   suite.expect(brain.supportsAutoProvision(), "gcp_supports_auto_provision");
   suite.expect(GcpBrainIaaS::parseRFC3339Ms("2026-03-21T15:16:37.741-07:00") == 1774131397741LL, "gcp_parse_rfc3339_ms_negative_offset");
   suite.expect(GcpBrainIaaS::parseRFC3339Ms("2026-03-21T15:16:37.741-07:00") == GcpBrainIaaS::parseRFC3339Ms("2026-03-21T22:16:37.741Z"), "gcp_parse_rfc3339_ms_equivalent_zulu");
   suite.expect(GcpBrainIaaS::parseRFC3339Ms("2026-03-22T00:16:37.741+02:00") == GcpBrainIaaS::parseRFC3339Ms("2026-03-21T22:16:37.741Z"), "gcp_parse_rfc3339_ms_positive_offset");
   {
      MachineCpuArchitecture architecture = MachineCpuArchitecture::unknown;
      suite.expect(GcpBrainIaaS::resolveMachineArchitecture("e2-medium"_ctv, {} /* architectureText */, architecture), "gcp_resolve_machine_architecture_defaults_missing_field");
      suite.expect(architecture == MachineCpuArchitecture::x86_64, "gcp_resolve_machine_architecture_defaults_to_x86_64");
      suite.expect(GcpBrainIaaS::resolveMachineArchitecture("t2a-standard-4"_ctv, "arm64"_ctv, architecture), "gcp_resolve_machine_architecture_accepts_explicit_text");
      suite.expect(architecture == MachineCpuArchitecture::aarch64, "gcp_resolve_machine_architecture_parses_explicit_text");
   }

   MachineConfig managedConfig = {};
   managedConfig.kind = MachineConfig::MachineKind::vm;
   managedConfig.slug = "gcp-managed"_ctv;
   managedConfig.vmImageURI = "projects/test-project/global/images/prodigy"_ctv;
   managedConfig.providerMachineType = "e2-medium"_ctv;

   String failure = {};
   suite.expect(gcpBrain.ensureManagedInstanceTemplate("prodigy-template"_ctv, {} /* serviceAccountEmail */, "global/networks/default"_ctv, {} /* subnetwork */, managedConfig, false, failure) == false, "gcp_managed_template_requires_service_account");
   suite.expect(failure == "gcp managed instance template requires serviceAccountEmail"_ctv, "gcp_managed_template_requires_service_account_reason");

   managedConfig.providerMachineType.clear();
   suite.expect(gcpBrain.ensureManagedInstanceTemplate("prodigy-template"_ctv, "prodigy@test-project.iam.gserviceaccount.com"_ctv, "global/networks/default"_ctv, {} /* subnetwork */, managedConfig, false, failure) == false, "gcp_managed_template_requires_machine_type");
   suite.expect(failure == "gcp managed instance template requires providerMachineType"_ctv, "gcp_managed_template_requires_machine_type_reason");

   managedConfig.providerMachineType = "e2-medium"_ctv;
   managedConfig.vmImageURI.clear();
   suite.expect(gcpBrain.ensureManagedInstanceTemplate("prodigy-template"_ctv, "prodigy@test-project.iam.gserviceaccount.com"_ctv, "global/networks/default"_ctv, {} /* subnetwork */, managedConfig, true, failure) == false, "gcp_managed_template_requires_vm_image");
   suite.expect(failure == "gcp managed instance template requires vmImageURI"_ctv, "gcp_managed_template_requires_vm_image_reason");

   char scratch[] = "/tmp/nametag-gcp-provider-unit-XXXXXX";
   char *created = mkdtemp(scratch);
   suite.expect(created != nullptr, "gcp_refreshable_bootstrap_tmpdir_created");
   if (created != nullptr)
   {
      std::filesystem::path tempDir(created);
      std::filesystem::path tokenPath = tempDir / "token.txt";
      suite.expect(writeTextFile(tokenPath, "refreshed-token-2\n"), "gcp_refreshable_bootstrap_token_file_written");

      TestableGcpBrainIaaS refreshableBrain = {};
      ProdigyRuntimeEnvironmentConfig refreshableRuntimeEnvironment = {};
      refreshableRuntimeEnvironment.kind = ProdigyEnvironmentKind::gcp;
      refreshableRuntimeEnvironment.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
      refreshableRuntimeEnvironment.providerCredentialMaterial = "cached-token-1"_ctv;
      refreshableRuntimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand.snprintf<"cat '{}'"_ctv>(String(tokenPath.c_str()));
      refreshableRuntimeEnvironment.gcp.bootstrapAccessTokenRefreshFailureHint = "run `gcloud auth login`"_ctv;
      refreshableBrain.configureRuntimeEnvironment(refreshableRuntimeEnvironment);

      failure.clear();
      suite.expect(refreshableBrain.ensureTokenForTest(failure), "gcp_refreshable_bootstrap_cached_token_valid");
      suite.expect(failure.size() == 0, "gcp_refreshable_bootstrap_cached_token_clears_failure");
      suite.expect(authHeaderContainsToken(refreshableBrain, "cached-token-1"), "gcp_refreshable_bootstrap_cached_header");

      TestableGcpBrainIaaS commandOnlyBrain = {};
      ProdigyRuntimeEnvironmentConfig commandOnlyRuntimeEnvironment = refreshableRuntimeEnvironment;
      commandOnlyRuntimeEnvironment.providerCredentialMaterial.reset();
      commandOnlyBrain.configureRuntimeEnvironment(commandOnlyRuntimeEnvironment);
      failure.clear();
      suite.expect(commandOnlyBrain.ensureTokenForTest(failure), "gcp_refreshable_bootstrap_refreshes_from_command");
      suite.expect(failure.size() == 0, "gcp_refreshable_bootstrap_refresh_clears_failure");
      suite.expect(authHeaderContainsToken(commandOnlyBrain, "refreshed-token-2"), "gcp_refreshable_bootstrap_refreshed_header");

      suite.expect(writeTextFile(tokenPath, "refreshed-token-3\n"), "gcp_refreshable_bootstrap_token_file_rewritten");
      commandOnlyBrain.invalidateCachedTokenForTest();
      failure.clear();
      suite.expect(commandOnlyBrain.ensureTokenForTest(failure), "gcp_refreshable_bootstrap_reruns_command_after_cache_invalidation");
      suite.expect(failure.size() == 0, "gcp_refreshable_bootstrap_rerun_clears_failure");
      suite.expect(authHeaderContainsToken(commandOnlyBrain, "refreshed-token-3"), "gcp_refreshable_bootstrap_rerun_header");

      ProdigyRuntimeEnvironmentConfig failingRuntimeEnvironment = refreshableRuntimeEnvironment;
      failingRuntimeEnvironment.providerCredentialMaterial.reset();
      failingRuntimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand = "sh -c 'printf refresh-broke; exit 7'"_ctv;

      TestableGcpBrainIaaS failingBrain = {};
      failingBrain.configureRuntimeEnvironment(failingRuntimeEnvironment);
      failure.clear();
      suite.expect(failingBrain.ensureTokenForTest(failure) == false, "gcp_refreshable_bootstrap_refresh_failure_rejected");
      suite.expect(stringContains(failure, "gcp bootstrap access token refresh failed"), "gcp_refreshable_bootstrap_refresh_failure_reason");
      suite.expect(stringContains(failure, "run `gcloud auth login`"), "gcp_refreshable_bootstrap_refresh_failure_hint");
   }

   GcpNeuronIaaS gcpNeuron = {};
   NeuronIaaS& neuron = gcpNeuron;
   neuron.configureRuntimeEnvironment(runtimeEnvironment);

   basics_log("SUMMARY: failed=%d\n", suite.failed);
   return suite.failed == 0 ? 0 : 1;
}
