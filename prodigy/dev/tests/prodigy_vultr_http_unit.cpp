#include <prodigy/iaas/vultr/vultr.http.h>

#include <cstdio>

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
    result.statusCode = 202;
    result.body.assign("accepted"_ctv);
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

class Probe
{
public:

  CoroutineStack stack;
  VultrHttpTransport& transport;
  MultiCurlClient::Result result;
  bool requestComplete = false;
  bool delayComplete = false;

  explicit Probe(VultrHttpTransport& requestedTransport)
      : transport(requestedTransport)
  {}

  void request(void)
  {
    String url = "https://api.vultr.com/v2/instances/id"_ctv;
    String body = "{}"_ctv;
    result = co_await transport.send(
        &stack, transport.request(MultiCurlClient::Method::patch, url, &body));
    requestComplete = true;
  }

  void delay(void)
  {
    delayComplete = co_await transport.wait(&stack, std::chrono::microseconds(1234));
  }
};

static const String *header(const MultiCurlClient::Request& request, const String& name)
{
  for (const MultiCurlClient::Header& candidate : request.headers)
  {
    if (candidate.name == name)
    {
      return &candidate.value;
    }
  }
  return nullptr;
}

int main(void)
{
  TestSuite suite;
  FakeHttp http;
  FakeDelay delay;
  String credential;
  credential.assign("vultr-secret"_ctv);
  VultrHttpTransport transport(http.submission(),
                               delay.submission(),
                               MultiCurlClient::Clock::now() + std::chrono::minutes(1),
                               credential);
  Probe probe(transport);

  probe.request();
  const String *authorization = header(http.request, "Authorization"_ctv);
  suite.expect(probe.requestComplete == false &&
                   http.request.method == MultiCurlClient::Method::patch,
               "vultr_request_suspends_on_injected_http");
  suite.expect(http.request.originPolicy.requiredScheme == "https"_ctv &&
                   http.request.originPolicy.requiredHost == "api.vultr.com"_ctv &&
                   http.request.originPolicy.requiredService == "443"_ctv &&
                   http.request.responseBytes == VultrHttpTransport::maximumResponseBytes,
               "vultr_request_enforces_bounded_exact_origin");
  suite.expect(authorization && *authorization == "Bearer vultr-secret"_ctv &&
                   http.request.body == "{}"_ctv,
               "vultr_request_owns_bearer_header_and_body");
  http.complete();
  suite.expect(probe.requestComplete && VultrHttpTransport::succeeded(probe.result) &&
                   probe.result.body == "accepted"_ctv,
               "vultr_request_resumes_on_terminal_callback");

  probe.delay();
  suite.expect(probe.delayComplete == false && delay.packet,
               "vultr_wait_uses_injected_ring_delay");
  delay.complete();
  suite.expect(probe.delayComplete, "vultr_wait_resumes_on_timeout");
  return suite.failed == 0 ? 0 : 1;
}
