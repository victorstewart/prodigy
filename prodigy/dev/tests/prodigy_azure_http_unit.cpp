#include <prodigy/iaas/azure/azure.http.h>

class TestSuite
{
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    basics_log("%s: %s\n", condition ? "PASS" : "FAIL", name);
    failed += condition ? 0 : 1;
  }
};

class FakeHttp
{
public:

  MultiCurlClient::Request request;
  MultiCurlClient::Callback callback;
  MultiCurlClient::Ticket ticket {17, 3};

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

class AzureHttpProbe
{
public:

  CoroutineStack stack;
  AzureHttpTransport& transport;
  MultiCurlClient::Result result;
  bool requestComplete = false;
  bool delayComplete = false;

  explicit AzureHttpProbe(AzureHttpTransport& requestedTransport)
      : transport(requestedTransport)
  {}

  void request(void)
  {
    String url = "https://management.azure.com/subscriptions/test"_ctv;
    String body = "{}"_ctv;
    result = co_await transport.send(
        &stack,
        transport.request(MultiCurlClient::Method::patch, url, "management.azure.com"_ctv, &body));
    requestComplete = true;
  }

  void delay(void)
  {
    delayComplete = co_await transport.wait(&stack, 1234);
  }
};

int main(void)
{
  TestSuite suite;
  FakeHttp http;
  FakeDelay delay;
  AzureHttpTransport transport(
      http.submission(),
      delay.submission(),
      MultiCurlClient::Clock::now() + std::chrono::minutes(1));
  AzureHttpProbe probe(transport);

  probe.request();
  suite.expect(probe.requestComplete == false && http.request.method == MultiCurlClient::Method::patch,
               "azure_http_request_defers_on_injected_transport");
  suite.expect(http.request.originPolicy.requiredHost == "management.azure.com"_ctv &&
                   http.request.body == "{}"_ctv &&
                   http.request.responseBytes == AzureHttpTransport::maximumResponseBytes,
               "azure_http_request_preserves_bounded_origin_contract");
  http.complete();
  suite.expect(probe.requestComplete && AzureHttpTransport::succeeded(probe.result) && probe.result.body == "ok"_ctv,
               "azure_http_request_resumes_on_terminal_callback");

  probe.delay();
  suite.expect(probe.delayComplete == false && delay.packet != nullptr,
               "azure_delay_wait_uses_injected_ring_submission");
  delay.complete();
  suite.expect(probe.delayComplete, "azure_delay_wait_resumes_on_timeout");
  return suite.failed == 0 ? 0 : 1;
}
