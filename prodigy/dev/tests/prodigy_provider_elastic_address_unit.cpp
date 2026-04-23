#include <networking/includes.h>
#include <services/debug.h>
#include <prodigy/iaas/aws/aws.h>
#include <prodigy/iaas/gcp/gcp.h>
#include <prodigy/iaas/azure/azure.h>

#include <cstdio>

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

static bool stringContains(const String& haystack, const String& needle)
{
   if (needle.size() == 0)
   {
      return true;
   }

   if (haystack.size() < needle.size())
   {
      return false;
   }

   for (uint64_t index = 0; index + needle.size() <= haystack.size(); ++index)
   {
      if (memcmp(haystack.data() + index, needle.data(), needle.size()) == 0)
      {
         return true;
      }
   }

   return false;
}

class FakeGcpElasticIaaS : public GcpBrainIaaS
{
public:

   struct ExpectedCall
   {
      String method;
      String urlContains;
      String bodyContains;
      long httpStatus = 200;
      bool transportOk = true;
      String response;
   };

   TestSuite *suite = nullptr;
   Vector<ExpectedCall> expected = {};
   uint32_t nextExpected = 0;

protected:

   bool sendElasticComputeRequest(const char *method, const String& url, const String *body, String& response, long *httpStatus, String& failure) override
   {
      response.clear();
      failure.clear();
      if (httpStatus) *httpStatus = 0;

      bool matched = nextExpected < expected.size();
      if (suite)
      {
         suite->expect(matched, "gcp_expected_call_available");
      }
      if (matched == false)
      {
         failure.assign("unexpected gcp request"_ctv);
         return false;
      }

      const ExpectedCall& call = expected[nextExpected++];
      String methodText = {};
      methodText.assign(method);
      String urlText = {};
      urlText.assign(url);
      String bodyText = {};
      if (body != nullptr)
      {
         bodyText.assign(*body);
      }

      if (suite)
      {
         suite->expect(methodText == call.method, "gcp_method_matches");
         suite->expect(call.urlContains.size() == 0 || stringContains(urlText, call.urlContains), "gcp_url_matches");
         suite->expect(call.bodyContains.size() == 0 || stringContains(bodyText, call.bodyContains), "gcp_body_matches");
      }

      if (httpStatus) *httpStatus = call.httpStatus;
      response.assign(call.response);
      if (call.transportOk == false)
      {
         failure.assign("gcp transport failed"_ctv);
         return false;
      }

      return call.httpStatus >= 200 && call.httpStatus < 300;
   }
};

class FakeAwsElasticIaaS : public AwsBrainIaaS
{
public:

   struct ExpectedCall
   {
      String bodyContains;
      long httpStatus = 200;
      bool transportOk = true;
      String response;
   };

   TestSuite *suite = nullptr;
   Vector<ExpectedCall> expected = {};
   uint32_t nextExpected = 0;

protected:

   bool sendElasticEC2Request(const String& actionBody, String& response, String& failure, long *httpCode = nullptr) override
   {
      response.clear();
      failure.clear();
      if (httpCode) *httpCode = 0;

      bool matched = nextExpected < expected.size();
      if (suite)
      {
         suite->expect(matched, "aws_expected_call_available");
      }
      if (matched == false)
      {
         failure.assign("unexpected aws request"_ctv);
         return false;
      }

      const ExpectedCall& call = expected[nextExpected++];
      String bodyText = {};
      bodyText.assign(actionBody);

      if (suite)
      {
         suite->expect(call.bodyContains.size() == 0 || stringContains(bodyText, call.bodyContains), "aws_body_matches");
      }

      if (httpCode) *httpCode = call.httpStatus;
      response.assign(call.response);
      if (call.transportOk == false)
      {
         failure.assign("aws transport failed"_ctv);
         return false;
      }

      if (call.httpStatus < 200 || call.httpStatus >= 300)
      {
         if (awsExtractXMLValue(response, "Message", failure) == false)
         {
            failure.assign("aws request failed"_ctv);
         }
         return false;
      }

      return true;
   }
};

class FakeAzureElasticIaaS : public AzureBrainIaaS
{
public:

   struct ExpectedCall
   {
      String method;
      String urlContains;
      String bodyContains;
      long httpStatus = 200;
      bool transportOk = true;
      String response;
   };

   TestSuite *suite = nullptr;
   Vector<ExpectedCall> expected = {};
   uint32_t nextExpected = 0;

protected:

   bool sendARMRaw(const char *method, const String& url, const String *body, String& response, long *httpStatus, String& failure) override
   {
      response.clear();
      failure.clear();
      if (httpStatus) *httpStatus = 0;

      bool matched = nextExpected < expected.size();
      if (suite)
      {
         suite->expect(matched, "azure_expected_call_available");
      }
      if (matched == false)
      {
         failure.assign("unexpected azure request"_ctv);
         return false;
      }

      const ExpectedCall& call = expected[nextExpected++];
      String methodText = {};
      methodText.assign(method);
      String urlText = {};
      urlText.assign(url);
      String bodyText = {};
      if (body != nullptr)
      {
         bodyText.assign(*body);
      }

      if (suite)
      {
         suite->expect(methodText == call.method, "azure_method_matches");
         suite->expect(call.urlContains.size() == 0 || stringContains(urlText, call.urlContains), "azure_url_matches");
         suite->expect(call.bodyContains.size() == 0 || stringContains(bodyText, call.bodyContains), "azure_body_matches");
      }

      if (httpStatus) *httpStatus = call.httpStatus;
      response.assign(call.response);
      if (call.transportOk == false)
      {
         failure.assign("azure transport failed"_ctv);
         return false;
      }

      return true;
   }
};

static void testAwsAllocateElasticFromPool(TestSuite& suite)
{
   FakeAwsElasticIaaS aws = {};
   aws.suite = &suite;

   ProdigyRuntimeEnvironmentConfig runtime = {};
   runtime.kind = ProdigyEnvironmentKind::aws;
   runtime.providerScope = "us-east-1"_ctv;
   runtime.providerCredentialMaterial = "{\"accessKeyId\":\"a\",\"secretAccessKey\":\"b\"}"_ctv;
   aws.configureRuntimeEnvironment(runtime);

   FakeAwsElasticIaaS::ExpectedCall call = {};

   call = {};
   call.bodyContains = "PublicIpv4Pool=pool-1"_ctv;
   call.response = "<AllocateAddressResponse><publicIp>54.1.2.3</publicIp><allocationId>eipalloc-123</allocationId></AllocateAddressResponse>"_ctv;
   aws.expected.push_back(call);

   call = {};
   call.bodyContains = "Action=AssociateAddress"_ctv;
   call.response = "<AssociateAddressResponse><associationId>eipassoc-123</associationId></AssociateAddressResponse>"_ctv;
   aws.expected.push_back(call);

   Machine machine = {};
   machine.cloudID = "i-123"_ctv;

   IPAddress assigned = {};
   String allocationID = {};
   String associationID = {};
   bool releaseOnRemove = false;
   String error = {};
   bool ok = aws.assignProviderElasticAddress(
      &machine,
      ExternalAddressFamily::ipv4,
      String(),
      "pool-1"_ctv,
      assigned,
      allocationID,
      associationID,
      releaseOnRemove,
      error);

   suite.expect(ok, "aws_allocate_elastic_from_pool_success");
   suite.expect(error.size() == 0, "aws_allocate_elastic_from_pool_no_error");
   suite.expect(assigned.is6 == false && assigned.v4 != 0, "aws_allocate_elastic_from_pool_assigned_ipv4");
   suite.expect(allocationID == "eipalloc-123"_ctv, "aws_allocate_elastic_from_pool_allocation_id");
   suite.expect(associationID == "eipassoc-123"_ctv, "aws_allocate_elastic_from_pool_association_id");
   suite.expect(releaseOnRemove, "aws_allocate_elastic_from_pool_release_flag");
   suite.expect(aws.nextExpected == aws.expected.size(), "aws_allocate_elastic_from_pool_consumed_calls");

   aws.expected.clear();
   aws.nextExpected = 0;

   call = {};
   call.bodyContains = "Action=DisassociateAddress"_ctv;
   call.response = "<DisassociateAddressResponse/>"_ctv;
   aws.expected.push_back(call);

   call = {};
   call.bodyContains = "Action=ReleaseAddress"_ctv;
   call.response = "<ReleaseAddressResponse/>"_ctv;
   aws.expected.push_back(call);

   RegisteredRoutableAddress address = {};
   address.kind = RoutableAddressKind::providerElasticAddress;
   address.providerAllocationID = allocationID;
   address.providerAssociationID = associationID;
   address.releaseOnRemove = releaseOnRemove;

   error.clear();
   ok = aws.releaseProviderElasticAddress(address, error);
   suite.expect(ok, "aws_allocate_elastic_from_pool_release_success");
   suite.expect(error.size() == 0, "aws_allocate_elastic_from_pool_release_no_error");
   suite.expect(aws.nextExpected == aws.expected.size(), "aws_allocate_elastic_from_pool_release_consumed_calls");
}

static void testAwsParseProcessCredentialMaterial(TestSuite& suite)
{
   AwsCredentialMaterial credential = {};
   String failure = {};
   bool ok = parseAwsCredentialMaterial(
      "{\"Version\":1,\"AccessKeyId\":\"ASIAEXAMPLE\",\"SecretAccessKey\":\"secret\",\"SessionToken\":\"session\",\"Expiration\":\"2026-03-22T22:01:11+00:00\"}"_ctv,
      credential,
      &failure);

   suite.expect(ok, "aws_parse_process_credential_material_success");
   suite.expect(failure.size() == 0, "aws_parse_process_credential_material_no_error");
   suite.expect(credential.accessKeyID == "ASIAEXAMPLE"_ctv, "aws_parse_process_credential_material_access_key");
   suite.expect(credential.secretAccessKey == "secret"_ctv, "aws_parse_process_credential_material_secret_key");
   suite.expect(credential.sessionToken == "session"_ctv, "aws_parse_process_credential_material_session_token");
   suite.expect(credential.expirationMs > 0, "aws_parse_process_credential_material_expiration");
}

static void testAwsParseMetadataCredentialMaterial(TestSuite& suite)
{
   AwsCredentialMaterial credential = {};
   String failure = {};
   bool ok = parseAwsCredentialMaterial(
      "{\"Code\":\"Success\",\"AccessKeyId\":\"ASIAEXAMPLE\",\"SecretAccessKey\":\"secret\",\"Token\":\"metadata-session\",\"Expiration\":\"2026-03-22T22:01:11Z\"}"_ctv,
      credential,
      &failure);

   suite.expect(ok, "aws_parse_metadata_credential_material_success");
   suite.expect(failure.size() == 0, "aws_parse_metadata_credential_material_no_error");
   suite.expect(credential.accessKeyID == "ASIAEXAMPLE"_ctv, "aws_parse_metadata_credential_material_access_key");
   suite.expect(credential.secretAccessKey == "secret"_ctv, "aws_parse_metadata_credential_material_secret_key");
   suite.expect(credential.sessionToken == "metadata-session"_ctv, "aws_parse_metadata_credential_material_session_token");
   suite.expect(credential.expirationMs > 0, "aws_parse_metadata_credential_material_expiration");
}

static void testAwsExplicitCredentialMaterialWinsOverInstanceProfile(TestSuite& suite)
{
   FakeAwsElasticIaaS aws = {};
   aws.suite = &suite;

   ProdigyRuntimeEnvironmentConfig runtime = {};
   runtime.kind = ProdigyEnvironmentKind::aws;
   runtime.providerScope = "us-east-1"_ctv;
   runtime.providerCredentialMaterial = "{\"accessKeyId\":\"a\",\"secretAccessKey\":\"b\"}"_ctv;
   runtime.aws.instanceProfileName = "prodigy-controller-profile"_ctv;
   aws.configureRuntimeEnvironment(runtime);

   FakeAwsElasticIaaS::ExpectedCall call = {};
   call.bodyContains = "Action=AllocateAddress"_ctv;
   call.response = "<AllocateAddressResponse><publicIp>54.1.2.4</publicIp><allocationId>eipalloc-456</allocationId></AllocateAddressResponse>"_ctv;
   aws.expected.push_back(call);

   call = {};
   call.bodyContains = "Action=AssociateAddress"_ctv;
   call.response = "<AssociateAddressResponse><associationId>eipassoc-456</associationId></AssociateAddressResponse>"_ctv;
   aws.expected.push_back(call);

   Machine machine = {};
   machine.cloudID = "i-456"_ctv;

   IPAddress assigned = {};
   String allocationID = {};
   String associationID = {};
   bool releaseOnRemove = false;
   String error = {};
   bool ok = aws.assignProviderElasticAddress(
      &machine,
      ExternalAddressFamily::ipv4,
      String(),
      "pool-2"_ctv,
      assigned,
      allocationID,
      associationID,
      releaseOnRemove,
      error);

   suite.expect(ok, "aws_explicit_credential_material_wins_over_instance_profile_success");
   suite.expect(error.size() == 0, "aws_explicit_credential_material_wins_over_instance_profile_no_error");
   suite.expect(assigned.is6 == false && assigned.v4 != 0, "aws_explicit_credential_material_wins_over_instance_profile_assigned_ipv4");
   suite.expect(allocationID == "eipalloc-456"_ctv, "aws_explicit_credential_material_wins_over_instance_profile_allocation_id");
   suite.expect(associationID == "eipassoc-456"_ctv, "aws_explicit_credential_material_wins_over_instance_profile_association_id");
   suite.expect(releaseOnRemove, "aws_explicit_credential_material_wins_over_instance_profile_release_flag");
   suite.expect(aws.nextExpected == aws.expected.size(), "aws_explicit_credential_material_wins_over_instance_profile_consumed_calls");
}

static void testGcpRequestedElasticMove(TestSuite& suite)
{
   FakeGcpElasticIaaS gcp = {};
   gcp.suite = &suite;

   ProdigyRuntimeEnvironmentConfig runtime = {};
   runtime.kind = ProdigyEnvironmentKind::gcp;
   runtime.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
   runtime.providerCredentialMaterial = "test-token"_ctv;
   gcp.configureRuntimeEnvironment(runtime);

   FakeGcpElasticIaaS::ExpectedCall call = {};

   call = {};
   call.method = "GET"_ctv;
   call.response = "{\"items\":[{\"name\":\"target-brain\",\"id\":\"111\"}]}"_ctv;
   gcp.expected.push_back(call);

   call = {};
   call.method = "GET"_ctv;
   call.urlContains = "/regions/us-central1/addresses?fields=items(name,address,users),nextPageToken"_ctv;
   call.response = "{\"items\":[{\"name\":\"existing-ip\",\"address\":\"34.1.2.3\",\"users\":[\"https://compute.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/instances/old-brain\"]}]}"_ctv;
   gcp.expected.push_back(call);

   call = {};
   call.method = "GET"_ctv;
   call.urlContains = "/zones/us-central1-a/instances/old-brain?fields=networkInterfaces(name,accessConfigs(name,natIP,externalIpv6))"_ctv;
   call.response = "{\"networkInterfaces\":[{\"name\":\"nic0\",\"accessConfigs\":[{\"name\":\"External NAT\",\"natIP\":\"34.1.2.3\"}]}]}"_ctv;
   gcp.expected.push_back(call);

   call = {};
   call.method = "POST"_ctv;
   call.urlContains = "/instances/old-brain/deleteAccessConfig?networkInterface=nic0&accessConfig=External%20NAT"_ctv;
   call.response = "{\"name\":\"detach-old\"}"_ctv;
   gcp.expected.push_back(call);

   call = {};
   call.method = "GET"_ctv;
   call.urlContains = "/zones/us-central1-a/operations/detach-old"_ctv;
   call.response = "{\"status\":\"DONE\"}"_ctv;
   gcp.expected.push_back(call);

   call = {};
   call.method = "GET"_ctv;
   call.urlContains = "/zones/us-central1-a/instances/target-brain?fields=networkInterfaces(name,accessConfigs(name,natIP,externalIpv6))"_ctv;
   call.response = "{\"networkInterfaces\":[{\"name\":\"nic0\"}]}"_ctv;
   gcp.expected.push_back(call);

   call = {};
   call.method = "POST"_ctv;
   call.urlContains = "/instances/target-brain/addAccessConfig?networkInterface=nic0"_ctv;
   call.bodyContains = "\"natIP\":\"34.1.2.3\""_ctv;
   call.response = "{\"name\":\"attach-target\"}"_ctv;
   gcp.expected.push_back(call);

   call = {};
   call.method = "GET"_ctv;
   call.urlContains = "/zones/us-central1-a/operations/attach-target"_ctv;
   call.response = "{\"status\":\"DONE\"}"_ctv;
   gcp.expected.push_back(call);

   Machine machine = {};
   machine.cloudID = "111"_ctv;

   IPAddress assigned = {};
   String allocationID = {};
   String associationID = {};
   bool releaseOnRemove = false;
   String error = {};
   bool ok = gcp.assignProviderElasticAddress(
      &machine,
      ExternalAddressFamily::ipv4,
      "34.1.2.3"_ctv,
      String(),
      assigned,
      allocationID,
      associationID,
      releaseOnRemove,
      error);

   suite.expect(ok, "gcp_requested_elastic_move_success");
   suite.expect(error.size() == 0, "gcp_requested_elastic_move_no_error");
   suite.expect(assigned.is6 == false && assigned.v4 != 0, "gcp_requested_elastic_move_assigned_ipv4");
   suite.expect(allocationID == "existing-ip"_ctv, "gcp_requested_elastic_move_allocation_id");
   suite.expect(associationID == "target-brain|nic0|External NAT"_ctv, "gcp_requested_elastic_move_association_id");
   suite.expect(releaseOnRemove == false, "gcp_requested_elastic_move_release_flag");
   suite.expect(gcp.nextExpected == gcp.expected.size(), "gcp_requested_elastic_move_consumed_calls");

   gcp.expected.clear();
   gcp.nextExpected = 0;

   call = {};
   call.method = "POST"_ctv;
   call.urlContains = "/instances/target-brain/deleteAccessConfig?networkInterface=nic0&accessConfig=External%20NAT"_ctv;
   call.response = "{\"name\":\"detach-release\"}"_ctv;
   gcp.expected.push_back(call);

   call = {};
   call.method = "GET"_ctv;
   call.urlContains = "/zones/us-central1-a/operations/detach-release"_ctv;
   call.response = "{\"status\":\"DONE\"}"_ctv;
   gcp.expected.push_back(call);

   RegisteredRoutableAddress address = {};
   address.kind = RoutableAddressKind::providerElasticAddress;
   address.providerAllocationID = allocationID;
   address.providerAssociationID = associationID;
   address.releaseOnRemove = releaseOnRemove;

   error.clear();
   ok = gcp.releaseProviderElasticAddress(address, error);
   suite.expect(ok, "gcp_requested_elastic_release_success");
   suite.expect(error.size() == 0, "gcp_requested_elastic_release_no_error");
   suite.expect(gcp.nextExpected == gcp.expected.size(), "gcp_requested_elastic_release_consumed_calls");
}

static void testAzureAllocateElasticFromPrefix(TestSuite& suite)
{
   FakeAzureElasticIaaS azure = {};
   azure.suite = &suite;

   ProdigyRuntimeEnvironmentConfig runtime = {};
   runtime.kind = ProdigyEnvironmentKind::azure;
   runtime.providerScope = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/locations/eastus"_ctv;
   runtime.providerCredentialMaterial = "test-token"_ctv;
   azure.configureRuntimeEnvironment(runtime);

   FakeAzureElasticIaaS::ExpectedCall call = {};

   call = {};
   call.method = "GET"_ctv;
   call.urlContains = "/virtualMachines/vm1?api-version=2025-04-01"_ctv;
   call.response = "{\"properties\":{\"networkProfile\":{\"networkInterfaces\":[{\"id\":\"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic1\",\"properties\":{\"primary\":true}}]}}}"_ctv;
   azure.expected.push_back(call);

   call = {};
   call.method = "GET"_ctv;
   call.urlContains = "/networkInterfaces/nic1?api-version=2024-05-01"_ctv;
   call.response = "{\"properties\":{\"ipConfigurations\":[{\"name\":\"ipconfig1\",\"properties\":{\"primary\":true}}]}}"_ctv;
   azure.expected.push_back(call);

   call = {};
   call.method = "PUT"_ctv;
   call.urlContains = "/publicIPAddresses/ntg-pip-"_ctv;
   call.bodyContains = "\"publicIPPrefix\":{\"id\":\"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/publicIPPrefixes/poolA\"}"_ctv;
   call.response = "{}"_ctv;
   azure.expected.push_back(call);

   call = {};
   call.method = "GET"_ctv;
   call.urlContains = "/publicIPAddresses/ntg-pip-"_ctv;
   call.response = "{\"properties\":{\"provisioningState\":\"Succeeded\",\"ipAddress\":\"52.10.20.30\"}}"_ctv;
   azure.expected.push_back(call);

   call = {};
   call.method = "GET"_ctv;
   call.urlContains = "/networkInterfaces/nic1?api-version=2024-05-01"_ctv;
   call.response = "{\"properties\":{\"ipConfigurations\":[{\"name\":\"ipconfig1\",\"properties\":{\"primary\":true,\"subnet\":{\"id\":\"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/default\"},\"privateIPAllocationMethod\":\"Dynamic\",\"privateIPAddressVersion\":\"IPv4\"}}]}}"_ctv;
   azure.expected.push_back(call);

   call = {};
   call.method = "PATCH"_ctv;
   call.urlContains = "/networkInterfaces/nic1?api-version=2024-05-01"_ctv;
   call.bodyContains = "\"publicIPAddress\":{\"id\":\"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/ntg-pip-"_ctv;
   call.response = "{}"_ctv;
   azure.expected.push_back(call);

   call = {};
   call.method = "GET"_ctv;
   call.urlContains = "/publicIPAddresses/ntg-pip-"_ctv;
   call.response = "{\"properties\":{\"provisioningState\":\"Succeeded\",\"ipAddress\":\"52.10.20.30\",\"ipConfiguration\":{\"id\":\"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic1/ipConfigurations/ipconfig1\"}}}"_ctv;
   azure.expected.push_back(call);

   Machine machine = {};
   machine.cloudID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"_ctv;

   IPAddress assigned = {};
   String allocationID = {};
   String associationID = {};
   bool releaseOnRemove = false;
   String error = {};
   bool ok = azure.assignProviderElasticAddress(
      &machine,
      ExternalAddressFamily::ipv4,
      String(),
      "poolA"_ctv,
      assigned,
      allocationID,
      associationID,
      releaseOnRemove,
      error);

   suite.expect(ok, "azure_allocate_elastic_from_prefix_success");
   suite.expect(error.size() == 0, "azure_allocate_elastic_from_prefix_no_error");
   suite.expect(assigned.is6 == false && assigned.v4 != 0, "azure_allocate_elastic_from_prefix_assigned_ipv4");
   suite.expect(stringContains(allocationID, "/publicIPAddresses/ntg-pip-"_ctv), "azure_allocate_elastic_from_prefix_allocation_id");
   suite.expect(associationID == "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic1/ipConfigurations/ipconfig1"_ctv, "azure_allocate_elastic_from_prefix_association_id");
   suite.expect(releaseOnRemove, "azure_allocate_elastic_from_prefix_release_flag");
   suite.expect(azure.nextExpected == azure.expected.size(), "azure_allocate_elastic_from_prefix_consumed_calls");

   azure.expected.clear();
   azure.nextExpected = 0;

   call = {};
   call.method = "GET"_ctv;
   call.urlContains = "/networkInterfaces/nic1?api-version=2024-05-01"_ctv;
   call.response = "{\"properties\":{\"ipConfigurations\":[{\"name\":\"ipconfig1\",\"properties\":{\"primary\":true,\"subnet\":{\"id\":\"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/default\"},\"privateIPAllocationMethod\":\"Dynamic\",\"privateIPAddressVersion\":\"IPv4\",\"publicIPAddress\":{\"id\":\"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/ntg-pip-123\"}}}]}}"_ctv;
   azure.expected.push_back(call);

   call = {};
   call.method = "PATCH"_ctv;
   call.urlContains = "/networkInterfaces/nic1?api-version=2024-05-01"_ctv;
   call.response = "{}"_ctv;
   azure.expected.push_back(call);

   call = {};
   call.method = "GET"_ctv;
   call.urlContains = "/publicIPAddresses/ntg-pip-"_ctv;
   call.response = "{\"properties\":{\"provisioningState\":\"Succeeded\",\"ipAddress\":\"52.10.20.30\"}}"_ctv;
   azure.expected.push_back(call);

   call = {};
   call.method = "DELETE"_ctv;
   call.urlContains = "/publicIPAddresses/ntg-pip-"_ctv;
   call.response = "{}"_ctv;
   azure.expected.push_back(call);

   call = {};
   call.method = "GET"_ctv;
   call.urlContains = "/publicIPAddresses/ntg-pip-"_ctv;
   call.httpStatus = 404;
   call.response = "{\"error\":{\"message\":\"Not Found\"}}"_ctv;
   azure.expected.push_back(call);

   RegisteredRoutableAddress address = {};
   address.kind = RoutableAddressKind::providerElasticAddress;
   address.providerAllocationID = allocationID;
   address.providerAssociationID = associationID;
   address.releaseOnRemove = true;

   error.clear();
   ok = azure.releaseProviderElasticAddress(address, error);
   suite.expect(ok, "azure_allocate_elastic_from_prefix_release_success");
   suite.expect(error.size() == 0, "azure_allocate_elastic_from_prefix_release_no_error");
   suite.expect(azure.nextExpected == azure.expected.size(), "azure_allocate_elastic_from_prefix_release_consumed_calls");
}

int main(void)
{
   TestSuite suite = {};

   testAwsAllocateElasticFromPool(suite);
   testAwsParseProcessCredentialMaterial(suite);
   testAwsParseMetadataCredentialMaterial(suite);
   testAwsExplicitCredentialMaterialWinsOverInstanceProfile(suite);
   testGcpRequestedElasticMove(suite);
   testAzureAllocateElasticFromPrefix(suite);

   basics_log("SUMMARY: failed=%d\n", suite.failed);
   return suite.failed == 0 ? 0 : 1;
}
