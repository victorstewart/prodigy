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

class FakeGcpElasticIaaS : public GcpBrainIaaS {
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

  bool sendElasticComputeRequest(const char *method, const String& url, const String *body, String& response, long *httpStatus, String& failure) override
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

    if (httpStatus)
    {
      *httpStatus = call.httpStatus;
    }
    response.assign(call.response);
    if (call.transportOk == false)
    {
      failure.assign("gcp transport failed"_ctv);
      return false;
    }

    return call.httpStatus >= 200 && call.httpStatus < 300;
  }
};

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

  bool sendElasticEC2Request(const String& actionBody, String& response, String& failure, long *httpCode = nullptr) override
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
      return false;
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

  bool sendIAMRequest(const String& actionBody, String& response, String& failure, long *httpCode = nullptr) override
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
      return false;
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
      return false;
    }

    if (call.httpStatus < 200 || call.httpStatus >= 300)
    {
      if (awsExtractXMLValue(response, "Message", failure) == false)
      {
        failure.assign("aws iam request failed"_ctv);
      }
      return false;
    }

    return true;
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

  bool sendARMRaw(const char *method, const String& url, const String *body, String& response, long *httpStatus, String& failure) override
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

    if (httpStatus)
    {
      *httpStatus = call.httpStatus;
    }
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
  machine.privateAddress = "10.0.1.23"_ctv;

  IPPrefix assigned = {};
  IPPrefix delivery = {};
  String allocationID = {};
  String associationID = {};
  bool releaseOnRemove = false;
  String error = {};
  bool ok = aws.assignProviderElasticAddress(
      &machine,
      ExternalAddressFamily::ipv4,
      ElasticPrefixIntent::create,
      String(),
      "pool-1"_ctv,
      assigned,
      delivery,
      allocationID,
      associationID,
      releaseOnRemove,
      error);

  suite.expect(ok, "aws_allocate_elastic_from_pool_success");
  suite.expect(error.size() == 0, "aws_allocate_elastic_from_pool_no_error");
  suite.expect(assigned.cidr == 32 && assigned.network.is6 == false && assigned.network.v4 != 0, "aws_allocate_elastic_from_pool_assigned_ipv4_prefix");
  suite.expect(delivery.network.equals(IPAddress("10.0.1.23", false)) && delivery.cidr == 32, "aws_allocate_elastic_from_pool_delivery_prefix");
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

  DistributableExternalSubnet prefix = {};
  prefix.kind = RoutablePrefixKind::elastic;
  prefix.providerAllocationID = allocationID;
  prefix.providerAssociationID = associationID;
  prefix.releaseOnRemove = releaseOnRemove;

  error.clear();
  ok = aws.releaseProviderElasticAddress(prefix, error);
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
  machine.privateAddress = "10.0.1.45"_ctv;

  IPPrefix assigned = {};
  IPPrefix delivery = {};
  String allocationID = {};
  String associationID = {};
  bool releaseOnRemove = false;
  String error = {};
  bool ok = aws.assignProviderElasticAddress(
      &machine,
      ExternalAddressFamily::ipv4,
      ElasticPrefixIntent::create,
      String(),
      "pool-2"_ctv,
      assigned,
      delivery,
      allocationID,
      associationID,
      releaseOnRemove,
      error);

  suite.expect(ok, "aws_explicit_credential_material_wins_over_instance_profile_success");
  suite.expect(error.size() == 0, "aws_explicit_credential_material_wins_over_instance_profile_no_error");
  suite.expect(assigned.cidr == 32 && assigned.network.is6 == false && assigned.network.v4 != 0, "aws_explicit_credential_material_wins_over_instance_profile_assigned_ipv4_prefix");
  suite.expect(delivery.network.equals(IPAddress("10.0.1.45", false)) && delivery.cidr == 32, "aws_explicit_credential_material_wins_over_instance_profile_delivery_prefix");
  suite.expect(allocationID == "eipalloc-456"_ctv, "aws_explicit_credential_material_wins_over_instance_profile_allocation_id");
  suite.expect(associationID == "eipassoc-456"_ctv, "aws_explicit_credential_material_wins_over_instance_profile_association_id");
  suite.expect(releaseOnRemove, "aws_explicit_credential_material_wins_over_instance_profile_release_flag");
  suite.expect(aws.nextExpected == aws.expected.size(), "aws_explicit_credential_material_wins_over_instance_profile_consumed_calls");
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
  suite.expect(aws.preflightClusterCreate(preflight, error) == false, "aws_preflight_requires_instance_profile_rejected");
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
  suite.expect(aws.preflightClusterCreate(preflight, error), "aws_preflight_profile_and_dryruns_success");
  suite.expect(error.size() == 0, "aws_preflight_profile_and_dryruns_no_error");
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
  suite.expect(aws.preflightClusterCreate(preflight, error) == false, "aws_preflight_dryrun_failures_rejected");
  suite.expect(stringContains(error, "AuthorizeSecurityGroupIngress(ssh)"_ctv), "aws_preflight_dryrun_failures_lists_ssh");
  suite.expect(stringContains(error, "AuthorizeSecurityGroupIngress(mesh)"_ctv), "aws_preflight_dryrun_failures_lists_mesh");
  suite.expect(stringContains(error, "CreateLaunchTemplate"_ctv), "aws_preflight_dryrun_failures_lists_template_create");
  suite.expect(stringContains(error, "RunInstances"_ctv), "aws_preflight_dryrun_failures_lists_run");
  suite.expect(aws.nextExpectedIAM == aws.expectedIAM.size(), "aws_preflight_dryrun_failures_consumed_iam_calls");
  suite.expect(aws.nextExpected == aws.expected.size(), "aws_preflight_dryrun_failures_consumed_ec2_calls");
}

static void testGcpPreflightRequiresServiceAccount(TestSuite& suite)
{
  FakeGcpElasticIaaS gcp = {};

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
  suite.expect(gcp.preflightClusterCreate(preflight, error) == false, "gcp_preflight_requires_service_account_rejected");
  suite.expect(stringContains(error, "serviceAccountEmail"_ctv), "gcp_preflight_requires_service_account_reason");
}

static String gcpPreflightProjectPermissionsResponse(void)
{
  return String(
      "{\"permissions\":["
      "\"compute.disks.create\","
      "\"compute.disks.delete\","
      "\"compute.instanceTemplates.create\","
      "\"compute.instanceTemplates.delete\","
      "\"compute.instanceTemplates.get\","
      "\"compute.instanceTemplates.useReadOnly\","
      "\"compute.instances.create\","
      "\"compute.instances.delete\","
      "\"compute.instances.get\","
      "\"compute.instances.list\","
      "\"compute.instances.setLabels\","
      "\"compute.instances.setMetadata\","
      "\"compute.instances.setServiceAccount\","
      "\"compute.machineTypes.get\","
      "\"compute.networks.get\","
      "\"compute.subnetworks.get\","
      "\"compute.subnetworks.use\","
      "\"compute.subnetworks.useExternalIp\","
      "\"compute.zones.get\"]}"_ctv);
}

static void testGcpPreflightChecksProjectAndServiceAccountPermissions(TestSuite& suite)
{
  FakeGcpElasticIaaS gcp = {};
  gcp.suite = &suite;

  ProdigyRuntimeEnvironmentConfig runtime = {};
  runtime.kind = ProdigyEnvironmentKind::gcp;
  runtime.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
  runtime.providerCredentialMaterial = "test-token"_ctv;
  gcp.configureRuntimeEnvironment(runtime);

  FakeGcpElasticIaaS::ExpectedCall call = {};
  call.method = "POST"_ctv;
  call.urlContains = "cloudresourcemanager.googleapis.com/v1/projects/test-project:testIamPermissions"_ctv;
  call.bodyContains = "compute.instances.create"_ctv;
  call.response = gcpPreflightProjectPermissionsResponse();
  gcp.expected.push_back(call);

  call = {};
  call.method = "POST"_ctv;
  call.urlContains = "iam.googleapis.com/v1/projects/test-project/serviceAccounts/prodigy-controller%40test-project.iam.gserviceaccount.com:testIamPermissions"_ctv;
  call.bodyContains = "iam.serviceAccounts.actAs"_ctv;
  call.response = "{\"permissions\":[\"iam.serviceAccounts.actAs\"]}"_ctv;
  gcp.expected.push_back(call);

  MachineConfig config = {};
  config.kind = MachineConfig::MachineKind::vm;
  config.vmImageURI = "projects/debian-cloud/global/images/family/debian-12"_ctv;
  config.providerMachineType = "e2-small"_ctv;
  BrainIaaSClusterCreatePreflight preflight = {};
  preflight.gcpServiceAccountEmail = "prodigy-controller@test-project.iam.gserviceaccount.com"_ctv;
  preflight.configs.push_back(config);

  String error = {};
  suite.expect(gcp.preflightClusterCreate(preflight, error), "gcp_preflight_permissions_success");
  suite.expect(error.size() == 0, "gcp_preflight_permissions_no_error");
  suite.expect(gcp.nextExpected == gcp.expected.size(), "gcp_preflight_permissions_consumed_calls");
}

static void testGcpPreflightListsMissingPermissions(TestSuite& suite)
{
  FakeGcpElasticIaaS gcp = {};
  gcp.suite = &suite;

  ProdigyRuntimeEnvironmentConfig runtime = {};
  runtime.kind = ProdigyEnvironmentKind::gcp;
  runtime.providerScope = "projects/test-project/zones/us-central1-a"_ctv;
  runtime.providerCredentialMaterial = "test-token"_ctv;
  gcp.configureRuntimeEnvironment(runtime);

  FakeGcpElasticIaaS::ExpectedCall call = {};
  call.method = "POST"_ctv;
  call.urlContains = "cloudresourcemanager.googleapis.com/v1/projects/test-project:testIamPermissions"_ctv;
  call.response = "{\"permissions\":[\"compute.disks.create\"]}"_ctv;
  gcp.expected.push_back(call);

  call = {};
  call.method = "POST"_ctv;
  call.urlContains = "iam.googleapis.com/v1/projects/test-project/serviceAccounts/prodigy-controller%40test-project.iam.gserviceaccount.com:testIamPermissions"_ctv;
  call.response = "{\"permissions\":[]}"_ctv;
  gcp.expected.push_back(call);

  MachineConfig config = {};
  config.kind = MachineConfig::MachineKind::vm;
  config.vmImageURI = "projects/debian-cloud/global/images/family/debian-12"_ctv;
  config.providerMachineType = "e2-small"_ctv;
  BrainIaaSClusterCreatePreflight preflight = {};
  preflight.gcpServiceAccountEmail = "prodigy-controller@test-project.iam.gserviceaccount.com"_ctv;
  preflight.configs.push_back(config);

  String error = {};
  suite.expect(gcp.preflightClusterCreate(preflight, error) == false, "gcp_preflight_missing_permissions_rejected");
  suite.expect(stringContains(error, "compute.instanceTemplates.create"_ctv), "gcp_preflight_missing_permissions_lists_template_create");
  suite.expect(stringContains(error, "compute.instances.create"_ctv), "gcp_preflight_missing_permissions_lists_instances_create");
  suite.expect(stringContains(error, "iam.serviceAccounts.actAs"_ctv), "gcp_preflight_missing_permissions_lists_act_as");
  suite.expect(gcp.nextExpected == gcp.expected.size(), "gcp_preflight_missing_permissions_consumed_calls");
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
  machine.privateAddress = "10.2.3.4"_ctv;

  IPPrefix assigned = {};
  IPPrefix delivery = {};
  String allocationID = {};
  String associationID = {};
  bool releaseOnRemove = false;
  String error = {};
  bool ok = gcp.assignProviderElasticAddress(
      &machine,
      ExternalAddressFamily::ipv4,
      ElasticPrefixIntent::any,
      "34.1.2.3"_ctv,
      String(),
      assigned,
      delivery,
      allocationID,
      associationID,
      releaseOnRemove,
      error);

  suite.expect(ok, "gcp_requested_elastic_move_success");
  suite.expect(error.size() == 0, "gcp_requested_elastic_move_no_error");
  suite.expect(assigned.cidr == 32 && assigned.network.is6 == false && assigned.network.v4 != 0, "gcp_requested_elastic_move_assigned_ipv4_prefix");
  suite.expect(delivery.network.equals(IPAddress("10.2.3.4", false)) && delivery.cidr == 32, "gcp_requested_elastic_move_delivery_prefix");
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

  DistributableExternalSubnet prefix = {};
  prefix.kind = RoutablePrefixKind::elastic;
  prefix.providerAllocationID = allocationID;
  prefix.providerAssociationID = associationID;
  prefix.releaseOnRemove = releaseOnRemove;

  error.clear();
  ok = gcp.releaseProviderElasticAddress(prefix, error);
  suite.expect(ok, "gcp_requested_elastic_release_success");
  suite.expect(error.size() == 0, "gcp_requested_elastic_release_no_error");
  suite.expect(gcp.nextExpected == gcp.expected.size(), "gcp_requested_elastic_release_consumed_calls");
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
  suite.expect(azure.preflightClusterCreate(preflight, error) == false, "azure_preflight_requires_identity_rejected");
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
  suite.expect(azure.preflightClusterCreate(preflight, error), "azure_preflight_permissions_success");
  suite.expect(error.size() == 0, "azure_preflight_permissions_no_error");
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
  suite.expect(azure.preflightClusterCreate(preflight, error) == false, "azure_preflight_not_actions_rejected");
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
  suite.expect(azure.preflightClusterCreate(preflight, error) == false, "azure_preflight_missing_permissions_rejected");
  suite.expect(stringContains(error, "Microsoft.Authorization/roleAssignments/write"_ctv), "azure_preflight_missing_permissions_lists_role_assignment_write");
  suite.expect(stringContains(error, "Microsoft.Compute/virtualMachines/write"_ctv), "azure_preflight_missing_permissions_lists_vm_write");
  suite.expect(stringContains(error, "Microsoft.Network/virtualNetworks/write"_ctv), "azure_preflight_missing_permissions_lists_vnet_write");
  suite.expect(azure.nextExpected == azure.expected.size(), "azure_preflight_missing_permissions_consumed_calls");
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
  machine.privateAddress = "10.3.4.5"_ctv;

  IPPrefix assigned = {};
  IPPrefix delivery = {};
  String allocationID = {};
  String associationID = {};
  bool releaseOnRemove = false;
  String error = {};
  bool ok = azure.assignProviderElasticAddress(
      &machine,
      ExternalAddressFamily::ipv4,
      ElasticPrefixIntent::create,
      String(),
      "poolA"_ctv,
      assigned,
      delivery,
      allocationID,
      associationID,
      releaseOnRemove,
      error);

  suite.expect(ok, "azure_allocate_elastic_from_prefix_success");
  suite.expect(error.size() == 0, "azure_allocate_elastic_from_prefix_no_error");
  suite.expect(delivery.network.equals(IPAddress("10.3.4.5", false)) && delivery.cidr == 32, "azure_allocate_elastic_from_prefix_delivery_prefix");
  suite.expect(assigned.cidr == 32 && assigned.network.is6 == false && assigned.network.v4 != 0, "azure_allocate_elastic_from_prefix_assigned_ipv4_prefix");
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

  DistributableExternalSubnet prefix = {};
  prefix.kind = RoutablePrefixKind::elastic;
  prefix.providerAllocationID = allocationID;
  prefix.providerAssociationID = associationID;
  prefix.releaseOnRemove = true;

  error.clear();
  ok = azure.releaseProviderElasticAddress(prefix, error);
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
  testAwsPreflightRequiresInstanceProfile(suite);
  testAwsPreflightChecksProfileAndDryRuns(suite);
  testAwsPreflightListsDryRunFailures(suite);
  testGcpPreflightRequiresServiceAccount(suite);
  testGcpPreflightChecksProjectAndServiceAccountPermissions(suite);
  testGcpPreflightListsMissingPermissions(suite);
  testGcpRequestedElasticMove(suite);
  testAzurePreflightRequiresManagedIdentity(suite);
  testAzurePreflightChecksPermissions(suite);
  testAzurePreflightHonorsNotActions(suite);
  testAzurePreflightListsMissingPermissions(suite);
  testAzureAllocateElasticFromPrefix(suite);

  std::fprintf(stderr, "SUMMARY: failed=%d\n", suite.failed);
  return suite.failed == 0 ? 0 : 1;
}
