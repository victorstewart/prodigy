#include <networking/includes.h>
#include <services/debug.h>
#include <prodigy/iaas/aws/aws.h>
#include <prodigy/iaas/gcp/gcp.h>
#include <prodigy/iaas/azure/azure.h>

#include <cstdio>

class TestSuite {
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    if (condition == false)
    {
      std::fprintf(stderr, "FAIL: %s\n", name);
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

class FakeAwsElasticIaaS : public AwsBrainIaaS {
public:

  struct ExpectedCall {
    String bodyContains;
    long httpStatus = 200;
    bool transportOk = true;
    String response;
  };

  TestSuite *suite = nullptr;
  Vector<ExpectedCall> expected = {};
  Vector<ExpectedCall> expectedIAM = {};
  uint32_t nextExpected = 0;
  uint32_t nextExpectedIAM = 0;

protected:

  ProdigyHostTask<bool> sendElasticEC2Request(CoroutineStack *,
                                              const String& actionBody,
                                              String& response,
                                              String& failure,
                                              long *httpCode = nullptr) override
  {
    response.clear();
    failure.clear();
    if (httpCode)
    {
      *httpCode = 0;
    }

    bool matched = nextExpected < expected.size();
    if (suite)
    {
      suite->expect(matched, "aws_expected_call_available");
    }
    if (matched == false)
    {
      failure.assign("unexpected aws request"_ctv);
      co_return false;
    }

    const ExpectedCall& call = expected[nextExpected++];
    String bodyText = {};
    bodyText.assign(actionBody);

    if (suite)
    {
      suite->expect(call.bodyContains.size() == 0 || stringContains(bodyText, call.bodyContains), "aws_body_matches");
    }

    if (httpCode)
    {
      *httpCode = call.httpStatus;
    }
    response.assign(call.response);
    if (call.transportOk == false)
    {
      failure.assign("aws transport failed"_ctv);
      co_return false;
    }

    if (call.httpStatus < 200 || call.httpStatus >= 300)
    {
      if (awsExtractXMLValue(response, "Message", failure) == false)
      {
        failure.assign("aws request failed"_ctv);
      }
      co_return false;
    }

    co_return true;
  }

  ProdigyHostTask<bool> sendIAMRequest(CoroutineStack *,
                                       const String& actionBody,
                                       String& response,
                                       String& failure,
                                       long *httpCode = nullptr) override
  {
    response.clear();
    failure.clear();
    if (httpCode)
    {
      *httpCode = 0;
    }

    bool matched = nextExpectedIAM < expectedIAM.size();
    if (suite)
    {
      suite->expect(matched, "aws_expected_iam_call_available");
    }
    if (matched == false)
    {
      failure.assign("unexpected aws iam request"_ctv);
      co_return false;
    }

    const ExpectedCall& call = expectedIAM[nextExpectedIAM++];
    String bodyText = {};
    bodyText.assign(actionBody);

    if (suite)
    {
      suite->expect(call.bodyContains.size() == 0 || stringContains(bodyText, call.bodyContains), "aws_iam_body_matches");
    }

    if (httpCode)
    {
      *httpCode = call.httpStatus;
    }
    response.assign(call.response);
    if (call.transportOk == false)
    {
      failure.assign("aws iam transport failed"_ctv);
      co_return false;
    }

    if (call.httpStatus < 200 || call.httpStatus >= 300)
    {
      if (awsExtractXMLValue(response, "Message", failure) == false)
      {
        failure.assign("aws iam request failed"_ctv);
      }
      co_return false;
    }

    co_return true;
  }
};

class FakeAzureElasticIaaS : public AzureBrainIaaS {
public:

  struct ExpectedCall {
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

  ProdigyHostTask<bool> sendARMRaw(CoroutineStack *,
                                   MultiCurlClient::Method method,
                                   const String& url,
                                   const String *body,
                                   String& response,
                                   long *httpStatus,
                                   String& failure) override
  {
    response.clear();
    failure.clear();
    if (httpStatus)
    {
      *httpStatus = 0;
    }

    bool matched = nextExpected < expected.size();
    if (suite)
    {
      suite->expect(matched, "azure_expected_call_available");
    }
    if (matched == false)
    {
      failure.assign("unexpected azure request"_ctv);
      co_return false;
    }

    const ExpectedCall& call = expected[nextExpected++];
    String methodText = {};
    switch (method)
    {
      case MultiCurlClient::Method::get: methodText.assign("GET"_ctv); break;
      case MultiCurlClient::Method::head: methodText.assign("HEAD"_ctv); break;
      case MultiCurlClient::Method::post: methodText.assign("POST"_ctv); break;
      case MultiCurlClient::Method::put: methodText.assign("PUT"_ctv); break;
      case MultiCurlClient::Method::patch: methodText.assign("PATCH"_ctv); break;
      case MultiCurlClient::Method::delete_: methodText.assign("DELETE"_ctv); break;
    }
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

    if (httpStatus)
    {
      *httpStatus = call.httpStatus;
    }
    response.assign(call.response);
    if (call.transportOk == false)
    {
      failure.assign("azure transport failed"_ctv);
      co_return false;
    }

    co_return true;
  }
};

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
  suite.expect(credential.accessKeyID() == "ASIAEXAMPLE"_ctv, "aws_parse_process_credential_material_access_key");
  suite.expect(credential.secretAccessKey() == "secret"_ctv, "aws_parse_process_credential_material_secret_key");
  suite.expect(credential.sessionToken() == "session"_ctv, "aws_parse_process_credential_material_session_token");
  suite.expect(credential.expirationMs() > 0, "aws_parse_process_credential_material_expiration");
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
  suite.expect(credential.accessKeyID() == "ASIAEXAMPLE"_ctv, "aws_parse_metadata_credential_material_access_key");
  suite.expect(credential.secretAccessKey() == "secret"_ctv, "aws_parse_metadata_credential_material_secret_key");
  suite.expect(credential.sessionToken() == "metadata-session"_ctv, "aws_parse_metadata_credential_material_session_token");
  suite.expect(credential.expirationMs() > 0, "aws_parse_metadata_credential_material_expiration");
}

static void testAwsPreflightRequiresInstanceProfile(TestSuite& suite)
{
  FakeAwsElasticIaaS aws = {};
  ProdigyRuntimeEnvironmentConfig runtime = {};
  runtime.kind = ProdigyEnvironmentKind::aws;
  runtime.providerScope = "us-east-1"_ctv;
  runtime.providerCredentialMaterial = "{\"accessKeyId\":\"a\",\"secretAccessKey\":\"b\"}"_ctv;
  aws.configureRuntimeEnvironment(runtime);

  MachineConfig config = {};
  config.kind = MachineConfig::MachineKind::vm;
  config.vmImageURI = "ami-123"_ctv;
  config.providerMachineType = "t3.micro"_ctv;
  BrainIaaSClusterCreatePreflight preflight = {};
  preflight.configs.push_back(config);

  String error = {};
  aws.preflightClusterCreate(nullptr, preflight, error);
  suite.expect(error.size() > 0, "aws_preflight_requires_instance_profile_rejected");
  suite.expect(stringContains(error, "instanceProfile"_ctv), "aws_preflight_requires_instance_profile_reason");
}

static void testAwsPreflightChecksProfileAndDryRuns(TestSuite& suite)
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
  call.bodyContains = "Action=GetInstanceProfile"_ctv;
  call.response = "<GetInstanceProfileResponse><InstanceProfile><InstanceProfileName>prodigy-controller-profile</InstanceProfileName></InstanceProfile></GetInstanceProfileResponse>"_ctv;
  aws.expectedIAM.push_back(call);

  call = {};
  call.bodyContains = "Action=DescribeInstances"_ctv;
  call.response = "<DescribeInstancesResponse><reservationSet/></DescribeInstancesResponse>"_ctv;
  aws.expected.push_back(call);

  call = {};
  call.bodyContains = "Action=DescribeVpcs"_ctv;
  call.response = "<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-1</vpcId><isDefault>true</isDefault></item></vpcSet></DescribeVpcsResponse>"_ctv;
  aws.expected.push_back(call);

  call = {};
  call.bodyContains = "Action=DescribeSubnets"_ctv;
  call.response = "<DescribeSubnetsResponse><subnetSet><item><subnetId>subnet-1</subnetId><defaultForAz>true</defaultForAz></item></subnetSet></DescribeSubnetsResponse>"_ctv;
  aws.expected.push_back(call);

  call = {};
  call.bodyContains = "Action=DescribeSecurityGroups"_ctv;
  call.response = "<DescribeSecurityGroupsResponse><securityGroupInfo><item><groupId>sg-1</groupId></item></securityGroupInfo></DescribeSecurityGroupsResponse>"_ctv;
  aws.expected.push_back(call);

  call = {};
  call.bodyContains = "Action=AuthorizeSecurityGroupIngress"_ctv;
  call.httpStatus = 412;
  call.response = "<Response><Errors><Error><Code>DryRunOperation</Code><Message>Request would have succeeded, but DryRun flag is set.</Message></Error></Errors></Response>"_ctv;
  aws.expected.push_back(call);

  call = {};
  call.bodyContains = "IpPermissions.1.IpProtocol=-1"_ctv;
  call.httpStatus = 412;
  call.response = "<Response><Errors><Error><Code>DryRunOperation</Code><Message>Request would have succeeded, but DryRun flag is set.</Message></Error></Errors></Response>"_ctv;
  aws.expected.push_back(call);

  call = {};
  call.bodyContains = "Action=CreateLaunchTemplate"_ctv;
  call.httpStatus = 412;
  call.response = "<Response><Errors><Error><Code>DryRunOperation</Code><Message>Request would have succeeded, but DryRun flag is set.</Message></Error></Errors></Response>"_ctv;
  aws.expected.push_back(call);

  call = {};
  call.bodyContains = "Action=DescribeLaunchTemplates"_ctv;
  call.response = "<DescribeLaunchTemplatesResponse><launchTemplateSet/></DescribeLaunchTemplatesResponse>"_ctv;
  aws.expected.push_back(call);

  call = {};
  call.bodyContains = "Action=RunInstances"_ctv;
  call.httpStatus = 412;
  call.response = "<Response><Errors><Error><Code>DryRunOperation</Code><Message>Request would have succeeded, but DryRun flag is set.</Message></Error></Errors></Response>"_ctv;
  aws.expected.push_back(call);

  MachineConfig config = {};
  config.kind = MachineConfig::MachineKind::vm;
  config.vmImageURI = "ami-123"_ctv;
  config.providerMachineType = "t3.micro"_ctv;
  BrainIaaSClusterCreatePreflight preflight = {};
  preflight.configs.push_back(config);

  String error = {};
  aws.preflightClusterCreate(nullptr, preflight, error);
  suite.expect(error.size() == 0, "aws_preflight_profile_and_dryruns_success");
  suite.expect(aws.nextExpectedIAM == aws.expectedIAM.size(), "aws_preflight_profile_and_dryruns_consumed_iam_calls");
  suite.expect(aws.nextExpected == aws.expected.size(), "aws_preflight_profile_and_dryruns_consumed_ec2_calls");
}

static void testAwsPreflightListsDryRunFailures(TestSuite& suite)
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
  call.bodyContains = "Action=GetInstanceProfile"_ctv;
  call.response = "<GetInstanceProfileResponse><InstanceProfile><InstanceProfileName>prodigy-controller-profile</InstanceProfileName></InstanceProfile></GetInstanceProfileResponse>"_ctv;
  aws.expectedIAM.push_back(call);

  call = {};
  call.bodyContains = "Action=DescribeInstances"_ctv;
  call.response = "<DescribeInstancesResponse><reservationSet/></DescribeInstancesResponse>"_ctv;
  aws.expected.push_back(call);

  call = {};
  call.bodyContains = "Action=DescribeVpcs"_ctv;
  call.response = "<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-1</vpcId><isDefault>true</isDefault></item></vpcSet></DescribeVpcsResponse>"_ctv;
  aws.expected.push_back(call);

  call = {};
  call.bodyContains = "Action=DescribeSubnets"_ctv;
  call.response = "<DescribeSubnetsResponse><subnetSet><item><subnetId>subnet-1</subnetId><defaultForAz>true</defaultForAz></item></subnetSet></DescribeSubnetsResponse>"_ctv;
  aws.expected.push_back(call);

  call = {};
  call.bodyContains = "Action=DescribeSecurityGroups"_ctv;
  call.response = "<DescribeSecurityGroupsResponse><securityGroupInfo><item><groupId>sg-1</groupId></item></securityGroupInfo></DescribeSecurityGroupsResponse>"_ctv;
  aws.expected.push_back(call);

  call = {};
  call.bodyContains = "Action=AuthorizeSecurityGroupIngress"_ctv;
  call.httpStatus = 403;
  call.response = "<Response><Errors><Error><Message>ssh ingress unauthorized</Message></Error></Errors></Response>"_ctv;
  aws.expected.push_back(call);

  call = {};
  call.bodyContains = "IpPermissions.1.IpProtocol=-1"_ctv;
  call.httpStatus = 403;
  call.response = "<Response><Errors><Error><Message>mesh ingress unauthorized</Message></Error></Errors></Response>"_ctv;
  aws.expected.push_back(call);

  call = {};
  call.bodyContains = "Action=CreateLaunchTemplate"_ctv;
  call.httpStatus = 403;
  call.response = "<Response><Errors><Error><Message>template create unauthorized</Message></Error></Errors></Response>"_ctv;
  aws.expected.push_back(call);

  call = {};
  call.bodyContains = "Action=DescribeLaunchTemplates"_ctv;
  call.response = "<DescribeLaunchTemplatesResponse><launchTemplateSet/></DescribeLaunchTemplatesResponse>"_ctv;
  aws.expected.push_back(call);

  call = {};
  call.bodyContains = "Action=RunInstances"_ctv;
  call.httpStatus = 403;
  call.response = "<Response><Errors><Error><Message>run unauthorized</Message></Error></Errors></Response>"_ctv;
  aws.expected.push_back(call);

  MachineConfig config = {};
  config.kind = MachineConfig::MachineKind::vm;
  config.vmImageURI = "ami-123"_ctv;
  config.providerMachineType = "t3.micro"_ctv;
  BrainIaaSClusterCreatePreflight preflight = {};
  preflight.configs.push_back(config);

  String error = {};
  aws.preflightClusterCreate(nullptr, preflight, error);
  suite.expect(error.size() > 0, "aws_preflight_dryrun_failures_rejected");
  suite.expect(stringContains(error, "AuthorizeSecurityGroupIngress(ssh)"_ctv), "aws_preflight_dryrun_failures_lists_ssh");
  suite.expect(stringContains(error, "AuthorizeSecurityGroupIngress(mesh)"_ctv), "aws_preflight_dryrun_failures_lists_mesh");
  suite.expect(stringContains(error, "CreateLaunchTemplate"_ctv), "aws_preflight_dryrun_failures_lists_template_create");
  suite.expect(stringContains(error, "RunInstances"_ctv), "aws_preflight_dryrun_failures_lists_run");
  suite.expect(aws.nextExpectedIAM == aws.expectedIAM.size(), "aws_preflight_dryrun_failures_consumed_iam_calls");
  suite.expect(aws.nextExpected == aws.expected.size(), "aws_preflight_dryrun_failures_consumed_ec2_calls");
}

static void testGcpPreflightRequiresServiceAccount(TestSuite& suite)
{
  GcpBrainIaaS gcp = {};

  ProdigyRuntimeEnvironmentConfig runtime = {};
  runtime.kind = ProdigyEnvironmentKind::gcp;
  runtime.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
  runtime.providerCredentialMaterial = "test-token"_ctv;
  gcp.configureRuntimeEnvironment(runtime);

  MachineConfig config = {};
  config.kind = MachineConfig::MachineKind::vm;
  config.vmImageURI = "projects/debian-cloud/global/images/family/debian-12"_ctv;
  config.providerMachineType = "e2-small"_ctv;
  BrainIaaSClusterCreatePreflight preflight = {};
  preflight.configs.push_back(config);

  String error = {};
  gcp.preflightClusterCreate(nullptr, preflight, error);
  suite.expect(error.size() > 0, "gcp_preflight_requires_service_account_rejected");
  suite.expect(stringContains(error, "serviceAccountEmail"_ctv), "gcp_preflight_requires_service_account_reason");
}

static void testAzurePreflightRequiresManagedIdentity(TestSuite& suite)
{
  FakeAzureElasticIaaS azure = {};

  ProdigyRuntimeEnvironmentConfig runtime = {};
  runtime.kind = ProdigyEnvironmentKind::azure;
  runtime.providerScope = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/locations/eastus"_ctv;
  runtime.providerCredentialMaterial = "test-token"_ctv;
  azure.configureRuntimeEnvironment(runtime);

  MachineConfig config = {};
  config.kind = MachineConfig::MachineKind::vm;
  config.vmImageURI = "Canonical:ubuntu-24_04-lts:server:latest"_ctv;
  config.providerMachineType = "Standard_B1s"_ctv;
  BrainIaaSClusterCreatePreflight preflight = {};
  preflight.configs.push_back(config);

  String error = {};
  azure.preflightClusterCreate(nullptr, preflight, error);
  suite.expect(error.size() > 0, "azure_preflight_requires_identity_rejected");
  suite.expect(stringContains(error, "managedIdentity"_ctv), "azure_preflight_requires_identity_reason");
}

static void testAzurePreflightChecksPermissions(TestSuite& suite)
{
  FakeAzureElasticIaaS azure = {};
  azure.suite = &suite;

  ProdigyRuntimeEnvironmentConfig runtime = {};
  runtime.kind = ProdigyEnvironmentKind::azure;
  runtime.providerScope = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/locations/eastus"_ctv;
  runtime.providerCredentialMaterial = "test-token"_ctv;
  azure.configureRuntimeEnvironment(runtime);

  FakeAzureElasticIaaS::ExpectedCall call = {};
  call.method = "GET"_ctv;
  call.urlContains = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"_ctv;
  call.response = "{\"value\":[{\"actions\":[\"*\"],\"notActions\":[]}]}"_ctv;
  azure.expected.push_back(call);

  MachineConfig config = {};
  config.kind = MachineConfig::MachineKind::vm;
  config.vmImageURI = "Canonical:ubuntu-24_04-lts:server:latest"_ctv;
  config.providerMachineType = "Standard_B1s"_ctv;
  BrainIaaSClusterCreatePreflight preflight = {};
  preflight.azureManagedIdentityResourceID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/prodigy-controller"_ctv;
  preflight.configs.push_back(config);

  String error = {};
  azure.preflightClusterCreate(nullptr, preflight, error);
  suite.expect(error.size() == 0, "azure_preflight_permissions_success");
  suite.expect(azure.nextExpected == azure.expected.size(), "azure_preflight_permissions_consumed_calls");
}

static void testAzurePreflightHonorsNotActions(TestSuite& suite)
{
  FakeAzureElasticIaaS azure = {};
  azure.suite = &suite;

  ProdigyRuntimeEnvironmentConfig runtime = {};
  runtime.kind = ProdigyEnvironmentKind::azure;
  runtime.providerScope = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/locations/eastus"_ctv;
  runtime.providerCredentialMaterial = "test-token"_ctv;
  azure.configureRuntimeEnvironment(runtime);

  FakeAzureElasticIaaS::ExpectedCall call = {};
  call.method = "GET"_ctv;
  call.urlContains = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"_ctv;
  call.response = "{\"value\":[{\"actions\":[\"*\"],\"notActions\":[\"Microsoft.Authorization/*/write\"]}]}"_ctv;
  azure.expected.push_back(call);

  MachineConfig config = {};
  config.kind = MachineConfig::MachineKind::vm;
  config.vmImageURI = "Canonical:ubuntu-24_04-lts:server:latest"_ctv;
  config.providerMachineType = "Standard_B1s"_ctv;
  BrainIaaSClusterCreatePreflight preflight = {};
  preflight.azureManagedIdentityResourceID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/prodigy-controller"_ctv;
  preflight.configs.push_back(config);

  String error = {};
  azure.preflightClusterCreate(nullptr, preflight, error);
  suite.expect(error.size() > 0, "azure_preflight_not_actions_rejected");
  suite.expect(stringContains(error, "roleAssignments/write"_ctv), "azure_preflight_not_actions_reason");
  suite.expect(azure.nextExpected == azure.expected.size(), "azure_preflight_not_actions_consumed_calls");
}

static void testAzurePreflightListsMissingPermissions(TestSuite& suite)
{
  FakeAzureElasticIaaS azure = {};
  azure.suite = &suite;

  ProdigyRuntimeEnvironmentConfig runtime = {};
  runtime.kind = ProdigyEnvironmentKind::azure;
  runtime.providerScope = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/locations/eastus"_ctv;
  runtime.providerCredentialMaterial = "test-token"_ctv;
  azure.configureRuntimeEnvironment(runtime);

  FakeAzureElasticIaaS::ExpectedCall call = {};
  call.method = "GET"_ctv;
  call.urlContains = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"_ctv;
  call.response = "{\"value\":[{\"actions\":[\"Microsoft.Compute/virtualMachines/read\"],\"notActions\":[]}]}"_ctv;
  azure.expected.push_back(call);

  MachineConfig config = {};
  config.kind = MachineConfig::MachineKind::vm;
  config.vmImageURI = "Canonical:ubuntu-24_04-lts:server:latest"_ctv;
  config.providerMachineType = "Standard_B1s"_ctv;
  BrainIaaSClusterCreatePreflight preflight = {};
  preflight.azureManagedIdentityResourceID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/prodigy-controller"_ctv;
  preflight.configs.push_back(config);

  String error = {};
  azure.preflightClusterCreate(nullptr, preflight, error);
  suite.expect(error.size() > 0, "azure_preflight_missing_permissions_rejected");
  suite.expect(stringContains(error, "Microsoft.Authorization/roleAssignments/write"_ctv), "azure_preflight_missing_permissions_lists_role_assignment_write");
  suite.expect(stringContains(error, "Microsoft.Compute/virtualMachines/write"_ctv), "azure_preflight_missing_permissions_lists_vm_write");
  suite.expect(stringContains(error, "Microsoft.Network/virtualNetworks/write"_ctv), "azure_preflight_missing_permissions_lists_vnet_write");
  suite.expect(azure.nextExpected == azure.expected.size(), "azure_preflight_missing_permissions_consumed_calls");
}

static void testUnprovenElasticProvidersFailClosed(TestSuite& suite)
{
  FakeAwsElasticIaaS aws;
  FakeAzureElasticIaaS azure;
  suite.expect(aws.supportsTransactionalElasticAddresses() == false,
               "aws_transactional_elastic_addresses_fail_closed");
  suite.expect(azure.supportsTransactionalElasticAddresses() == false,
               "azure_transactional_elastic_addresses_fail_closed");
}

int main(void)
{
  TestSuite suite = {};

  testAwsParseProcessCredentialMaterial(suite);
  testAwsParseMetadataCredentialMaterial(suite);
  testAwsPreflightRequiresInstanceProfile(suite);
  testAwsPreflightChecksProfileAndDryRuns(suite);
  testAwsPreflightListsDryRunFailures(suite);
  testGcpPreflightRequiresServiceAccount(suite);
  testAzurePreflightRequiresManagedIdentity(suite);
  testAzurePreflightChecksPermissions(suite);
  testAzurePreflightHonorsNotActions(suite);
  testAzurePreflightListsMissingPermissions(suite);
  testUnprovenElasticProvidersFailClosed(suite);

  std::fprintf(stderr, "SUMMARY: failed=%d\n", suite.failed);
  return suite.failed == 0 ? 0 : 1;
}
