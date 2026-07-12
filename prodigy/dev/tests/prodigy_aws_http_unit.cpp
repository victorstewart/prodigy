#include <prodigy/iaas/aws/aws.h>

#include <cstdio>
#include <cstring>
#include <type_traits>

class TestSuite
{
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    if (!condition)
    {
      std::fprintf(stderr, "FAIL: %s\n", name);
      ++failed;
    }
  }
};

static const String *headerValue(const MultiCurlClient::Request& request, const char *name)
{
  const uint64_t nameSize = std::strlen(name);
  for (const MultiCurlClient::Header& header : request.headers)
  {
    if (header.name.size() == nameSize &&
        std::memcmp(header.name.data(), name, size_t(nameSize)) == 0)
    {
      return &header.value;
    }
  }
  return nullptr;
}

static bool contains(const String& value, const String& needle)
{
  if (needle.empty())
  {
    return true;
  }
  if (needle.size() > value.size())
  {
    return false;
  }
  for (uint64_t offset = 0; offset <= value.size() - needle.size(); ++offset)
  {
    if (std::memcmp(value.data() + offset, needle.data(), size_t(needle.size())) == 0)
    {
      return true;
    }
  }
  return false;
}

static bool requestContains(const MultiCurlClient::Request& request, const String& needle)
{
  if (contains(request.url, needle) || contains(request.authority, needle) ||
      contains(request.resolveHost, needle) || contains(request.body, needle))
  {
    return true;
  }
  for (const MultiCurlClient::Header& header : request.headers)
  {
    if (contains(header.name, needle) || contains(header.value, needle))
    {
      return true;
    }
  }
  return false;
}

static AwsCredentialMaterial exampleCredential(void)
{
  AwsCredentialMaterial credential;
  (void)credential.assign("AKIDEXAMPLE"_ctv,
                          "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"_ctv);
  return credential;
}

static AwsHttpRequest::Target exampleTarget(void)
{
  AwsHttpRequest::Target target;
  target.authority = "IAM.AMAZONAWS.COM"_ctv;
  target.path = "/"_ctv;
  target.region = "us-east-1"_ctv;
  target.service = "iam"_ctv;
  target.query.push_back({"Version"_ctv, "2010-05-08"_ctv});
  target.query.push_back({"Action"_ctv, "ListUsers"_ctv});
  return target;
}

class FakeHttp
{
public:

  MultiCurlClient::Request request;
  MultiCurlClient::Callback callback;
  MultiCurlClient::Ticket ticket {41, 7};

  static MultiCurlClient::Ticket submit(void *context,
                                        MultiCurlClient::Request&& request,
                                        MultiCurlClient::Callback callback)
  {
    FakeHttp& http = *static_cast<FakeHttp *>(context);
    http.request = std::move(request);
    http.callback = callback;
    return http.ticket;
  }

  static bool cancel(void *, MultiCurlClient::Ticket)
  {
    return true;
  }

  ProdigyHostHttpSubmission submission(void)
  {
    return {this, submit, cancel};
  }

  void complete(void)
  {
    MultiCurlClient::Result result;
    result.status = MultiCurlClient::Status::success;
    result.statusCode = 200;
    result.body.assign("ok"_ctv);
    callback.function(callback.context, ticket, std::move(result));
  }
};

class FakeDelay
{
public:

  TimeoutPacket *packet = nullptr;

  static void queue(void *context, TimeoutPacket *packet)
  {
    static_cast<FakeDelay *>(context)->packet = packet;
  }

  static void cancel(void *, TimeoutPacket *)
  {}

  ProdigyHostDelayOperation::Submission submission(void)
  {
    return {this, queue, cancel};
  }

  void complete(void)
  {
    TimeoutPacket *completed = packet;
    packet = nullptr;
    completed->dispatcher->dispatchTimeout(completed);
  }
};

class AwsHttpProbe
{
public:

  CoroutineStack stack;
  AwsHttpTransport& transport;
  MultiCurlClient::Result result;
  bool requestComplete = false;
  bool delayComplete = false;

  explicit AwsHttpProbe(AwsHttpTransport& requestedTransport)
      : transport(requestedTransport)
  {}

  void request(void)
  {
    AwsCredentialMaterial credential = exampleCredential();
    Vector<MultiCurlClient::Header> headers;
    result = co_await transport.sendSigned(&stack,
                                           exampleTarget(),
                                           MultiCurlClient::Method::get,
                                           headers,
                                           nullptr,
                                           credential);
    requestComplete = true;
  }

  void delay(void)
  {
    delayComplete = co_await transport.wait(&stack, 1234);
  }
};

int main(void)
{
  static_assert(!std::is_trivially_destructible_v<AwsCredentialMaterial>);

  TestSuite suite;
  const MultiCurlClient::TimePoint deadline = MultiCurlClient::TimePoint::max();

  {
    AwsCredentialMaterial credential = exampleCredential();
    AwsHttpRequest::Target target = exampleTarget();
    Vector<MultiCurlClient::Header> headers;
    headers.push_back({"Content-Type"_ctv,
                       "  application/x-www-form-urlencoded;\t charset=utf-8  "_ctv});
    MultiCurlClient::Request request;
    AwsHttpRequest::Error error = AwsHttpRequest::Error::signingFailure;
    const bool built = AwsHttpRequest::build(target,
                                             MultiCurlClient::Method::get,
                                             headers,
                                             String(),
                                             credential,
                                             1440938160,
                                             deadline,
                                             request,
                                             &error);
    const String *authorization = headerValue(request, "Authorization");
    const String *contentType = headerValue(request, "content-type");
    const String *payloadHash = headerValue(request, "x-amz-content-sha256");
    const String *amzDate = headerValue(request, "x-amz-date");
    suite.expect(built && error == AwsHttpRequest::Error::none,
                 "aws_http_builds_documented_deterministic_request");
    suite.expect(request.method == MultiCurlClient::Method::get && request.requireTls &&
                     request.pathAsIs && request.overallDeadline == deadline &&
                     request.authority == "iam.amazonaws.com"_ctv && request.resolveHost.empty(),
                 "aws_http_emits_bounded_multicurl_request_policy");
    suite.expect(request.url ==
                     "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08"_ctv,
                 "aws_http_canonicalizes_query_and_authority");
    suite.expect(contentType &&
                     *contentType == "application/x-www-form-urlencoded; charset=utf-8"_ctv,
                 "aws_http_normalizes_signed_header_value_on_wire");
    suite.expect(payloadHash &&
                     *payloadHash ==
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"_ctv,
                 "aws_http_emits_payload_digest");
    suite.expect(amzDate && *amzDate == "20150830T123600Z"_ctv,
                 "aws_http_emits_explicit_timestamp");
    suite.expect(authorization &&
                     *authorization ==
                         "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=dd479fa8a80364edf2119ec24bebde66712ee9c9cb2b0d92eb3ab9ccdc0c3947"_ctv,
                 "aws_http_signature_matches_independent_vector");
    suite.expect(!requestContains(request, credential.secretAccessKey()),
                 "aws_http_never_emits_raw_secret");
    AwsHttpRequest::secureReset(request);
  }

  {
    AwsCredentialMaterial credential = exampleCredential();
    suite.expect(credential.assign("AKIDEXAMPLE"_ctv,
                                   "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"_ctv,
                                   "temporary+/=token"_ctv),
                 "aws_http_credential_copies_literal_views_into_owned_storage");
    AwsHttpRequest::Target target = exampleTarget();
    target.path = "/folder name/%"_ctv;
    target.query.clear();
    target.query.push_back({"z"_ctv, "a/b"_ctv});
    target.query.push_back({"a b"_ctv, "+"_ctv});
    Vector<MultiCurlClient::Header> headers;
    MultiCurlClient::Request request;
    request.url = "stale-view-backed-output"_ctv;
    const bool built = AwsHttpRequest::build(target,
                                             MultiCurlClient::Method::post,
                                             headers,
                                             "payload"_ctv,
                                             credential,
                                             1440938160,
                                             deadline,
                                             request);
    const String *token = headerValue(request, "x-amz-security-token");
    const String *authorization = headerValue(request, "Authorization");
    suite.expect(built &&
                     request.url ==
                         "https://iam.amazonaws.com/folder%20name/%25?a%20b=%2B&z=a%2Fb"_ctv,
                 "aws_http_percent_encodes_path_and_sorted_query");
    suite.expect(token && *token == credential.sessionToken() && authorization &&
                     contains(*authorization, "x-amz-security-token"_ctv),
                 "aws_http_signs_temporary_session_token");
    suite.expect(!requestContains(request, credential.secretAccessKey()),
                 "aws_http_session_request_still_excludes_raw_secret");
    request.resolveHost = "view-backed-reset-fixture"_ctv;
    AwsHttpRequest::secureReset(request);
    suite.expect(request.url.empty() && request.resolveHost.empty() && request.headers.empty(),
                 "aws_http_explicit_reset_handles_owned_and_view_backed_fields");
  }

  {
    AwsCredentialMaterial credential = exampleCredential();
    AwsHttpRequest::Target target = exampleTarget();
    Vector<MultiCurlClient::Header> headers;
    headers.push_back({"X-Test"_ctv, "one"_ctv});
    headers.push_back({"x-test"_ctv, "two"_ctv});
    MultiCurlClient::Request request;
    AwsHttpRequest::Error error = AwsHttpRequest::Error::none;
    suite.expect(!AwsHttpRequest::build(target,
                                        MultiCurlClient::Method::get,
                                        headers,
                                        String(),
                                        credential,
                                        1440938160,
                                        deadline,
                                        request,
                                        &error) &&
                     error == AwsHttpRequest::Error::invalidHeaders && request.url.empty(),
                 "aws_http_rejects_case_insensitive_duplicate_headers_and_clears_output");
  }

  {
    AwsCredentialMaterial credential = exampleCredential();
    AwsHttpRequest::Target target = exampleTarget();
    Vector<MultiCurlClient::Header> headers;
    headers.push_back({"Authorization"_ctv, "caller-controlled"_ctv});
    MultiCurlClient::Request request;
    AwsHttpRequest::Error error = AwsHttpRequest::Error::none;
    suite.expect(!AwsHttpRequest::build(target,
                                        MultiCurlClient::Method::get,
                                        headers,
                                        String(),
                                        credential,
                                        1440938160,
                                        deadline,
                                        request,
                                        &error) &&
                     error == AwsHttpRequest::Error::invalidHeaders,
                 "aws_http_rejects_reserved_headers");

    headers.clear();
    headers.push_back({"X-Test"_ctv, "safe\r\ninjected: value"_ctv});
    suite.expect(!AwsHttpRequest::build(target,
                                        MultiCurlClient::Method::get,
                                        headers,
                                        String(),
                                        credential,
                                        1440938160,
                                        deadline,
                                        request,
                                        &error) &&
                     error == AwsHttpRequest::Error::invalidHeaders,
                 "aws_http_rejects_header_crlf");

    headers.clear();
    target.query.push_back({"bad\nname"_ctv, "value"_ctv});
    suite.expect(!AwsHttpRequest::build(target,
                                        MultiCurlClient::Method::get,
                                        headers,
                                        String(),
                                        credential,
                                        1440938160,
                                        deadline,
                                        request,
                                        &error) &&
                     error == AwsHttpRequest::Error::invalidTarget,
                 "aws_http_rejects_target_crlf");
  }

  {
    AwsCredentialMaterial credential = exampleCredential();
    suite.expect(credential.assign("AKIDEXAMPLE"_ctv, "bad\nsecret"_ctv),
                 "aws_http_test_credential_owns_invalid_secret_fixture");
    MultiCurlClient::Request request;
    AwsHttpRequest::Error error = AwsHttpRequest::Error::none;
    suite.expect(!AwsHttpRequest::build(exampleTarget(),
                                        MultiCurlClient::Method::get,
                                        Vector<MultiCurlClient::Header>(),
                                        String(),
                                        credential,
                                        1440938160,
                                        deadline,
                                        request,
                                        &error) &&
                     error == AwsHttpRequest::Error::invalidCredential,
                 "aws_http_rejects_credential_crlf");
  }

  {
    AwsCredentialMaterial credential;
    suite.expect(credential.assign("AKIDEXAMPLE"_ctv,
                                   "literal-secret"_ctv,
                                   "literal-token"_ctv,
                                   1234),
                 "aws_http_credential_accepts_literal_views_by_copy");
    AwsCredentialMaterial copied = credential;
    AwsCredentialMaterial moved = std::move(copied);
    credential.secureReset();
    moved.secureReset();
    suite.expect(!credential.valid() && !copied.valid() && !moved.valid(),
                 "aws_http_credential_copy_move_reset_never_scrubs_literal_view");
  }

  {
    FakeHttp http;
    FakeDelay delay;
    const MultiCurlClient::TimePoint operationDeadline =
        MultiCurlClient::Clock::now() + std::chrono::minutes(1);
    AwsHttpTransport transport(http.submission(), delay.submission(), operationDeadline);
    AwsHttpProbe probe(transport);
    probe.request();
    const String *authorization = headerValue(http.request, "Authorization");
    suite.expect(!probe.requestComplete && authorization &&
                     http.request.overallDeadline == operationDeadline,
                 "aws_transport_suspends_signed_request_and_clamps_deadline");
    suite.expect(http.request.originPolicy.requiredScheme == "https"_ctv &&
                     http.request.originPolicy.requiredHost == "iam.amazonaws.com"_ctv &&
                     http.request.originPolicy.requiredAuthority == "iam.amazonaws.com"_ctv &&
                     http.request.originPolicy.requiredService == "443"_ctv &&
                     http.request.responseBytes == AwsHttpTransport::maximumResponseBytes,
                 "aws_transport_enforces_bounded_exact_origin");
    suite.expect(!requestContains(http.request, "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"_ctv),
                 "aws_transport_submits_no_raw_secret");
    http.complete();
    suite.expect(probe.requestComplete && AwsHttpTransport::succeeded(probe.result),
                 "aws_transport_resumes_on_terminal_callback");

    probe.delay();
    suite.expect(!probe.delayComplete && delay.packet,
                 "aws_transport_wait_uses_injected_ring_delay");
    delay.complete();
    suite.expect(probe.delayComplete, "aws_transport_wait_resumes_on_timeout");
  }

  {
    MultiCurlClient::Request request = AwsHttpTransport::metadataGetRequest(
        "/latest/meta-data/placement/region"_ctv,
        "token"_ctv,
        MultiCurlClient::Clock::now() + std::chrono::seconds(3));
    suite.expect(request.url ==
                     "http://169.254.169.254/latest/meta-data/placement/region"_ctv &&
                     request.resolveHost == "169.254.169.254"_ctv &&
                     request.family == AsyncDnsResolver::Family::ipv4 && !request.requireTls,
                 "aws_metadata_uses_numeric_imdsv2_origin_without_dns");
    suite.expect(request.originPolicy.requiredScheme == "http"_ctv &&
                     request.originPolicy.requiredAuthority == "169.254.169.254"_ctv &&
                     request.originPolicy.requiredService == "80"_ctv &&
                     request.responseBytes == AwsHttpTransport::maximumMetadataResponseBytes,
                 "aws_metadata_enforces_exact_bounded_origin");
  }

  {
    String response;
    response.assign("x"_ctv);
    while (response.size() < 1024)
    {
      response.append('x');
    }
    String failure;
    AwsHttpTransport::assignHttpFailure("aws fixture failed"_ctv, 500, response, failure);
    suite.expect(failure.size() <= 560 && contains(failure, "[http=500]"_ctv),
                 "aws_http_failure_bounds_response_diagnostic");
    failure.assign("precise failure"_ctv);
    MultiCurlClient::Result result;
    result.status = MultiCurlClient::Status::deadlineExceeded;
    AwsHttpTransport::assignTransportFailure(result, failure);
    AwsHttpTransport::assignHttpFailure("generic"_ctv, 500, response, failure);
    suite.expect(failure == "precise failure"_ctv,
                 "aws_http_failure_preserves_existing_reason");
  }

  {
    Vector<String> components;
    components.push_back("cluster"_ctv);
    components.push_back("operation-42"_ctv);
    components.push_back("schema"_ctv);
    String first;
    String repeated;
    String changed;
    suite.expect(AwsHttpRequest::idempotencyToken(components, first) &&
                     AwsHttpRequest::idempotencyToken(components, repeated) &&
                     first.size() == 64 && first == repeated,
                 "aws_idempotency_token_is_stable_for_durable_intent");
    Vector<String> changedComponents;
    changedComponents.push_back("cluster"_ctv);
    changedComponents.push_back("operation-43"_ctv);
    changedComponents.push_back("schema"_ctv);
    suite.expect(AwsHttpRequest::idempotencyToken(changedComponents, changed) && changed != first,
                 "aws_idempotency_token_separates_distinct_intents");
  }

  {
    int64_t timestampMs = 0;
    suite.expect(awsParseRFC3339Ms("2024-01-01T00:00:00Z"_ctv, timestampMs) &&
                     timestampMs == 1'704'067'200'000,
                 "aws_spot_timestamp_strict_valid");
    suite.expect(awsParseRFC3339Ms("2024-01-01T00:00:00.125+01:00"_ctv, timestampMs) &&
                     timestampMs == 1'704'063'600'125,
                 "aws_spot_timestamp_strict_offset");
    suite.expect(!awsParseRFC3339Ms("bad"_ctv, timestampMs) &&
                     !awsParseRFC3339Ms("2024-13-01T00:00:00Z"_ctv, timestampMs) &&
                     !awsParseRFC3339Ms("2024-01-01T00:00:00"_ctv, timestampMs),
                 "aws_spot_timestamp_rejects_malformed_values");
  }

  {
    Vector<String> subnetBlocks;
    subnetBlocks.push_back("<subnetId>subnet-z</subnetId><availabilityZone>us-east-1c</availabilityZone><defaultForAz>false</defaultForAz>"_ctv);
    subnetBlocks.push_back("<subnetId>subnet-b</subnetId><availabilityZone>us-east-1b</availabilityZone><defaultForAz>true</defaultForAz>"_ctv);
    subnetBlocks.push_back("<subnetId>subnet-a</subnetId><availabilityZone>us-east-1a</availabilityZone><defaultForAz>true</defaultForAz>"_ctv);
    String subnetID;
    String availabilityZone;
    suite.expect(awsSelectBootstrapSubnet(subnetBlocks, subnetID, availabilityZone) &&
                     subnetID == "subnet-a"_ctv && availabilityZone == "us-east-1a"_ctv,
                 "aws_pricing_and_launch_share_deterministic_subnet_zone_policy");
  }

  {
    String description;
    suite.expect(awsBootstrapLaunchTemplateDescription(
                     "subnet-a"_ctv, "sg-a"_ctv, "profile-a"_ctv, String(),
                     description),
                 "aws_launch_template_fingerprint_builds");
    Vector<String> components;
    components.push_back(
        "LaunchTemplateData.MetadataOptions.HttpTokens=required&LaunchTemplateData.NetworkInterface.1.DeviceIndex=0&LaunchTemplateData.NetworkInterface.1.AssociatePublicIpAddress=true&LaunchTemplateData.NetworkInterface.1.SubnetId=subnet-a&LaunchTemplateData.NetworkInterface.1.SecurityGroupId.1=sg-a&LaunchTemplateData.IamInstanceProfile.Name=profile-a"_ctv);
    String token;
    String expected;
    suite.expect(AwsHttpRequest::idempotencyToken(components, token),
                 "aws_launch_template_fingerprint_expected_token_builds");
    expected.assign("prodigy-bootstrap-"_ctv);
    expected.append(token.substr(0, 32, Copy::yes));
    suite.expect(description == expected,
                 "aws_launch_template_fingerprint_covers_complete_desired_data");
  }

  return suite.failed == 0 ? 0 : 1;
}
