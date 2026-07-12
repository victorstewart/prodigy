#include <networking/includes.h>
#include <prodigy/host.http.admission.h>
#include <prodigy/host.http.operation.h>
#include <cstdio>

class TestSuite
{
public:

  int failed = 0;

  void expect(bool condition, const char *name)
  {
    if (condition == false)
    {
      std::fprintf(stderr, "FAIL: %s\n", name);
    }
    failed += condition ? 0 : 1;
  }
};

class FakeHttpClient
{
public:

  using Operation = ProdigyHostHttpOperation;
  using Ticket = Operation::Ticket;
  using Request = Operation::Request;
  using Result = Operation::Result;
  using Callback = Operation::Callback;

  Ticket ticket {41, 7};
  Ticket inlineTicket {41, 7};
  Callback callback;
  MultiCurlClient::TimePoint deadline = MultiCurlClient::TimePoint::max();
  MultiCurlClient::Status inlineStatus = MultiCurlClient::Status::success;
  uint32_t submissions = 0;
  uint32_t cancellations = 0;
  bool completeInline = false;
  bool deferCancellation = false;
  bool cancelReturnsFalse = false;

  static Ticket submit(void *context, Request&& request, Callback callback)
  {
    FakeHttpClient& client = *static_cast<FakeHttpClient *>(context);
    client.submissions += 1;
    client.deadline = request.overallDeadline;
    client.callback = callback;
    if (client.completeInline)
    {
      Result result;
      result.status = client.inlineStatus;
      result.body = "inline";
      callback.function(callback.context, client.inlineTicket, std::move(result));
    }
    return client.ticket;
  }

  static bool cancel(void *context, Ticket ticket)
  {
    FakeHttpClient& client = *static_cast<FakeHttpClient *>(context);
    if (ticket.identifier != client.ticket.identifier ||
        ticket.generation != client.ticket.generation)
    {
      return false;
    }
    client.cancellations += 1;
    if (client.deferCancellation)
    {
      return client.cancelReturnsFalse == false;
    }
    Result result;
    result.status = MultiCurlClient::Status::canceled;
    client.callback.function(client.callback.context, ticket, std::move(result));
    return true;
  }

  Operation::Submission submission(void)
  {
    return {this, submit, cancel};
  }

  void complete(Ticket ticket, MultiCurlClient::Status status)
  {
    Result result;
    result.status = status;
    result.body = "deferred";
    callback.function(callback.context, ticket, std::move(result));
  }
};

class CountingStack : public CoroutineStack
{
public:

  uint32_t wakes = 0;

  void co_consume(void) override
  {
    wakes += 1;
  }
};

class DestroyingStack final : public CountingStack
{
public:

  ProdigyHostHttpOperation **operation = nullptr;

  void co_consume(void) override
  {
    wakes += 1;
    delete *operation;
    *operation = nullptr;
  }
};

class FakeBatchHttpClient
{
public:

  using Operation = ProdigyHostHttpBatchOperation;
  Vector<Operation::Callback> callbacks;
  Vector<Operation::Ticket> tickets;
  bytell_hash_set<uint32_t> inlineIndices;
  bytell_hash_set<uint32_t> invalidIndices;
  uint32_t cancellations = 0;
  bool deferCancellation = false;
  bool cancelReturnsFalse = false;

  static Operation::Ticket submit(void *context,
                                  Operation::Request&&,
                                  Operation::Callback callback)
  {
    FakeBatchHttpClient& client = *static_cast<FakeBatchHttpClient *>(context);
    const uint32_t index = uint32_t(client.callbacks.size());
    const Operation::Ticket ticket {uint64_t(index) + 1, 9};
    client.callbacks.push_back(callback);
    client.tickets.push_back(ticket);
    if (client.inlineIndices.contains(index))
    {
      Operation::Result result = {};
      result.status = MultiCurlClient::Status::success;
      result.body.snprintf<"inline-{itoa}"_ctv>(index);
      callback.function(callback.context, ticket, std::move(result));
    }
    return client.invalidIndices.contains(index) ? Operation::Ticket {} : ticket;
  }

  static bool cancel(void *context, Operation::Ticket ticket)
  {
    FakeBatchHttpClient& client = *static_cast<FakeBatchHttpClient *>(context);
    for (uint32_t index = 0; index < client.tickets.size(); ++index)
    {
      if (client.tickets[index].identifier == ticket.identifier &&
          client.tickets[index].generation == ticket.generation)
      {
        ++client.cancellations;
        if (client.deferCancellation)
        {
          return client.cancelReturnsFalse == false;
        }
        Operation::Result result = {};
        result.status = MultiCurlClient::Status::canceled;
        client.callbacks[index].function(client.callbacks[index].context,
                                         ticket,
                                         std::move(result));
        return true;
      }
    }
    return false;
  }

  Operation::Submission submission(void)
  {
    return {this, submit, cancel};
  }

  void complete(uint32_t index,
                MultiCurlClient::Status status,
                Operation::Ticket ticket = {})
  {
    Operation::Result result = {};
    result.status = status;
    result.body.snprintf<"deferred-{itoa}"_ctv>(index);
    callbacks[index].function(callbacks[index].context,
                              ticket ? ticket : tickets[index],
                              std::move(result));
  }
};

class DestroyingBatchStack final : public CountingStack
{
public:

  ProdigyHostHttpBatchOperation **operation = nullptr;

  void co_consume(void) override
  {
    ++wakes;
    delete *operation;
    *operation = nullptr;
  }
};

class FakeAdmissionHttpClient
{
public:

  using Operation = ProdigyHostHttpAdmission;
  Vector<Operation::Request> requests;
  Vector<Operation::Callback> callbacks;
  Vector<Operation::Ticket> tickets;
  Vector<uint8_t> pending;
  uint32_t cancellations = 0;
  uint64_t nextTicket = 1;
  bool completeInline = false;
  bool deferCancellation = false;
  bool cancelReturnsFalse = false;

  static Operation::Ticket submit(void *context,
                                  Operation::Request&& request,
                                  Operation::Callback callback)
  {
    FakeAdmissionHttpClient& client = *static_cast<FakeAdmissionHttpClient *>(context);
    const Operation::Ticket ticket {client.nextTicket++, 17};
    client.requests.push_back(std::move(request));
    client.callbacks.push_back(callback);
    client.tickets.push_back(ticket);
    client.pending.push_back(1);
    if (client.completeInline)
    {
      Operation::Result result;
      result.status = MultiCurlClient::Status::success;
      client.pending.back() = 0;
      callback.function(callback.context, ticket, std::move(result));
    }
    return ticket;
  }

  static bool cancel(void *context, Operation::Ticket ticket)
  {
    FakeAdmissionHttpClient& client = *static_cast<FakeAdmissionHttpClient *>(context);
    for (uint32_t index = 0; index < client.tickets.size(); ++index)
    {
      if (client.pending[index] &&
          client.tickets[index].identifier == ticket.identifier &&
          client.tickets[index].generation == ticket.generation)
      {
        ++client.cancellations;
        if (client.deferCancellation)
        {
          return client.cancelReturnsFalse == false;
        }
        client.pending[index] = 0;
        Operation::Result result;
        result.status = MultiCurlClient::Status::canceled;
        client.callbacks[index].function(client.callbacks[index].context,
                                         ticket,
                                         std::move(result));
        return true;
      }
    }
    return false;
  }

  Operation::Submission submission(void)
  {
    return {this, submit, cancel};
  }

  void complete(uint32_t index,
                MultiCurlClient::Status status = MultiCurlClient::Status::success)
  {
    if (pending[index] == 0)
    {
      return;
    }
    pending[index] = 0;
    Operation::Result result;
    result.status = status;
    callbacks[index].function(callbacks[index].context,
                              tickets[index],
                              std::move(result));
  }
};

class AdmissionCompletionSink
{
public:

  using Operation = ProdigyHostHttpAdmission;
  Vector<Operation::Ticket> tickets;
  Vector<MultiCurlClient::Status> statuses;

  static void completed(void *context, Operation::Ticket ticket, Operation::Result&& result)
  {
    AdmissionCompletionSink& sink = *static_cast<AdmissionCompletionSink *>(context);
    sink.tickets.push_back(ticket);
    sink.statuses.push_back(result.status);
  }

  Operation::Callback callback(void)
  {
    return {this, completed};
  }
};

class FakeAdmissionDelayQueue
{
public:

  TimeoutPacket *pending = nullptr;
  Vector<uint64_t> delays;
  uint32_t cancellations = 0;

  static void queue(void *context, TimeoutPacket *packet)
  {
    FakeAdmissionDelayQueue& delay = *static_cast<FakeAdmissionDelayQueue *>(context);
    delay.pending = packet;
    delay.delays.push_back(uint64_t(packet->timeout.tv_sec) * 1'000'000 +
                           uint64_t(packet->timeout.tv_nsec) / 1000);
  }

  static void cancel(void *context, TimeoutPacket *packet)
  {
    FakeAdmissionDelayQueue& delay = *static_cast<FakeAdmissionDelayQueue *>(context);
    if (delay.pending == packet)
    {
      delay.pending = nullptr;
      ++delay.cancellations;
      packet->dispatcher->dispatchTimeout(packet);
    }
  }

  ProdigyHostDelayOperation::Submission submission(void)
  {
    return {this, queue, cancel};
  }

  void complete(void)
  {
    TimeoutPacket *packet = pending;
    pending = nullptr;
    packet->dispatcher->dispatchTimeout(packet);
  }
};

class AdmissionShutdownSink
{
public:

  ProdigyHostHttpAdmission *admission = nullptr;
  bool safeDuringCallback = true;
  uint32_t calls = 0;

  static void completed(void *context,
                        ProdigyHostHttpAdmission::Ticket,
                        ProdigyHostHttpAdmission::Result&&)
  {
    AdmissionShutdownSink& sink = *static_cast<AdmissionShutdownSink *>(context);
    ++sink.calls;
    sink.admission->shutdown();
    sink.safeDuringCallback = sink.admission->shutdownSafe();
  }
};

static void testInlineCompletion(TestSuite& suite)
{
  FakeHttpClient client;
  client.completeInline = true;
  client.inlineStatus = MultiCurlClient::Status::deadlineExceeded;
  CountingStack stack;
  ProdigyHostHttpOperation operation(client.submission(), stack);
  ProdigyHostHttpOperation::Request request;
  request.overallDeadline = MultiCurlClient::Clock::now() + std::chrono::seconds(3);

  suite.expect(operation.submit(std::move(request)) && !operation.mustSuspend() &&
                   operation.hasResult() && stack.wakes == 0 &&
                   client.deadline != MultiCurlClient::TimePoint::max(),
               "host_http_inline_completion_never_suspends");
  ProdigyHostHttpOperation::Result result = operation.takeResult();
  suite.expect(result.status == MultiCurlClient::Status::deadlineExceeded &&
                   result.body == "inline"_ctv && !operation.hasResult(),
               "host_http_inline_completion_preserves_result");
}

static void testDeferredExactOnce(TestSuite& suite)
{
  FakeHttpClient client;
  CountingStack stack;
  ProdigyHostHttpOperation operation(client.submission(), stack);

  suite.expect(operation.submit({}) && operation.mustSuspend(),
               "host_http_deferred_completion_arms_wake");
  client.complete({client.ticket.identifier + 1, client.ticket.generation},
                  MultiCurlClient::Status::success);
  suite.expect(!operation.hasResult() && stack.wakes == 0,
               "host_http_deferred_completion_rejects_stale_ticket");
  client.complete(client.ticket, MultiCurlClient::Status::success);
  client.complete(client.ticket, MultiCurlClient::Status::transportFailure);
  suite.expect(operation.hasResult() && stack.wakes == 1,
               "host_http_deferred_completion_wakes_exactly_once");
  const ProdigyHostHttpOperation::Result result = operation.takeResult();
  suite.expect(result.status == MultiCurlClient::Status::success &&
                   result.body == "deferred"_ctv,
               "host_http_deferred_completion_keeps_first_exact_result");
}

static void testInvalidSubmissionTicket(TestSuite& suite)
{
  FakeHttpClient client;
  client.ticket = {};
  CountingStack stack;
  ProdigyHostHttpOperation operation(client.submission(), stack);

  suite.expect(operation.submit({}) && !operation.mustSuspend() &&
                   operation.hasResult() && stack.wakes == 0,
               "host_http_invalid_submission_ticket_never_suspends");
  const ProdigyHostHttpOperation::Result result = operation.takeResult();
  suite.expect(result.status == MultiCurlClient::Status::initializationFailure,
               "host_http_invalid_submission_ticket_fails_inline");
}

static void testInlineStaleTicket(TestSuite& suite)
{
  FakeHttpClient client;
  client.completeInline = true;
  client.inlineTicket.identifier += 1;
  CountingStack stack;
  ProdigyHostHttpOperation operation(client.submission(), stack);

  suite.expect(operation.submit({}) && operation.mustSuspend() &&
                   !operation.hasResult(),
               "host_http_inline_completion_postvalidates_returned_ticket");
  client.complete(client.ticket, MultiCurlClient::Status::success);
  suite.expect(operation.hasResult() && stack.wakes == 1,
               "host_http_inline_stale_ticket_leaves_real_request_pending");
}

static void testAbandonAndDestruction(TestSuite& suite)
{
  FakeHttpClient abandonedClient;
  CountingStack abandonedStack;
  {
    ProdigyHostHttpOperation operation(abandonedClient.submission(), abandonedStack);
    suite.expect(operation.submit({}) && operation.mustSuspend(),
                 "host_http_abandon_starts_pending_request");
    operation.abandon();
    suite.expect(abandonedClient.cancellations == 1 && abandonedStack.wakes == 0 &&
                     !operation.hasResult() && !operation.mustSuspend(),
                 "host_http_abandon_disarms_before_inline_cancel_callback");
  }
  suite.expect(abandonedClient.cancellations == 1,
               "host_http_abandon_prevents_destructor_recancel");

  FakeHttpClient destroyedClient;
  CountingStack destroyedStack;
  {
    ProdigyHostHttpOperation operation(destroyedClient.submission(), destroyedStack);
    operation.submit({});
    operation.mustSuspend();
  }
  suite.expect(destroyedClient.cancellations == 1 && destroyedStack.wakes == 0,
               "host_http_destructor_disarms_before_inline_cancel_callback");

  FakeHttpClient deferredClient;
  deferredClient.deferCancellation = true;
  deferredClient.cancelReturnsFalse = true;
  CountingStack deferredStack;
  {
    ProdigyHostHttpOperation operation(deferredClient.submission(), deferredStack);
    operation.submit({});
    operation.mustSuspend();
  }
  ProdigyHostHttpOperation::Ticket stale = deferredClient.ticket;
  ++stale.generation;
  deferredClient.complete(stale, MultiCurlClient::Status::canceled);
  deferredClient.complete(deferredClient.ticket, MultiCurlClient::Status::canceled);
  suite.expect(deferredClient.cancellations == 1 && deferredStack.wakes == 0,
               "host_http_destructor_detaches_until_deferred_terminal_callback");
}

static void testCallbackMayDestroyOperation(TestSuite& suite)
{
  FakeHttpClient client;
  DestroyingStack stack;
  ProdigyHostHttpOperation *operation =
      new ProdigyHostHttpOperation(client.submission(), stack);
  stack.operation = &operation;
  operation->submit({});
  operation->mustSuspend();

  client.complete(client.ticket, MultiCurlClient::Status::success);
  suite.expect(operation == nullptr && stack.wakes == 1 && client.cancellations == 0,
               "host_http_callback_may_destroy_operation_during_wake");
}

static void testBatchMixedCompletion(TestSuite& suite)
{
  FakeBatchHttpClient client = {};
  client.inlineIndices.insert(0);
  client.inlineIndices.insert(2);
  CountingStack stack = {};
  ProdigyHostHttpBatchOperation operation(client.submission(), stack);
  Vector<ProdigyHostHttpBatchOperation::Request> requests;
  requests.resize(3);

  suite.expect(operation.submit(std::move(requests)) &&
                   operation.pendingCount() == 1 && operation.mustSuspend(),
               "host_http_batch_submits_all_before_mixed_completion_wait");
  FakeBatchHttpClient::Operation::Ticket stale = client.tickets[1];
  ++stale.generation;
  client.complete(1, MultiCurlClient::Status::success, stale);
  suite.expect(operation.pendingCount() == 1 && stack.wakes == 0,
               "host_http_batch_rejects_stale_ticket");
  client.complete(1, MultiCurlClient::Status::success);
  client.complete(1, MultiCurlClient::Status::transportFailure);
  suite.expect(operation.pendingCount() == 0 && stack.wakes == 1,
               "host_http_batch_wakes_once_after_last_exact_completion");
  Vector<ProdigyHostHttpBatchOperation::Result> results = {};
  suite.expect(operation.takeResults(results) && results.size() == 3 &&
                   results[0].body == "inline-0"_ctv &&
                   results[1].body == "deferred-1"_ctv &&
                   results[2].body == "inline-2"_ctv &&
                   operation.takeResults(results) == false,
               "host_http_batch_preserves_indexed_results_once");
}

static void testBatchInvalidSubmission(TestSuite& suite)
{
  FakeBatchHttpClient client = {};
  client.invalidIndices.insert(0);
  client.inlineIndices.insert(1);
  CountingStack stack = {};
  ProdigyHostHttpBatchOperation operation(client.submission(), stack);
  Vector<ProdigyHostHttpBatchOperation::Request> requests;
  requests.resize(2);
  Vector<ProdigyHostHttpBatchOperation::Result> results = {};

  suite.expect(operation.takeResults(results) == false,
               "host_http_batch_cannot_take_results_before_submit");
  suite.expect(operation.submit(std::move(requests)) &&
                   operation.mustSuspend() == false && stack.wakes == 0 &&
                   operation.takeResults(results) && results.size() == 2 &&
                   results[0].status == MultiCurlClient::Status::initializationFailure &&
                   results[1].status == MultiCurlClient::Status::success,
               "host_http_batch_invalid_ticket_fails_only_its_index_inline");

  FakeBatchHttpClient emptyClient = {};
  CountingStack emptyStack = {};
  ProdigyHostHttpBatchOperation empty(emptyClient.submission(), emptyStack);
  Vector<ProdigyHostHttpBatchOperation::Request> emptyRequests = {};
  suite.expect(empty.submit(std::move(emptyRequests)) &&
                   empty.submit({}) == false && empty.mustSuspend() == false &&
                   empty.takeResults(results) && results.empty(),
               "host_http_batch_empty_submission_completes_once_inline");
}

static void testBatchCancellationAndCallbackDeletion(TestSuite& suite)
{
  FakeBatchHttpClient canceledClient = {};
  CountingStack canceledStack = {};
  {
    ProdigyHostHttpBatchOperation operation(canceledClient.submission(), canceledStack);
    Vector<ProdigyHostHttpBatchOperation::Request> requests;
    requests.resize(2);
    suite.expect(operation.submit(std::move(requests)) && operation.mustSuspend(),
                 "host_http_batch_cancellation_starts_pending_batch");
  }
  suite.expect(canceledClient.cancellations == 2 && canceledStack.wakes == 0,
               "host_http_batch_destruction_cancels_without_wake");

  FakeBatchHttpClient deferredCancelClient = {};
  deferredCancelClient.deferCancellation = true;
  deferredCancelClient.cancelReturnsFalse = true;
  CountingStack deferredCancelStack = {};
  {
    ProdigyHostHttpBatchOperation operation(deferredCancelClient.submission(), deferredCancelStack);
    Vector<ProdigyHostHttpBatchOperation::Request> deferredRequests;
    deferredRequests.resize(1);
    operation.submit(std::move(deferredRequests));
    operation.mustSuspend();
  }
  FakeBatchHttpClient::Operation::Ticket stale = deferredCancelClient.tickets[0];
  ++stale.generation;
  deferredCancelClient.complete(0, MultiCurlClient::Status::canceled, stale);
  deferredCancelClient.complete(0, MultiCurlClient::Status::canceled);
  suite.expect(deferredCancelClient.cancellations == 1 && deferredCancelStack.wakes == 0,
               "host_http_batch_detached_entry_ignores_stale_then_accepts_terminal_callback");

  FakeBatchHttpClient completedClient = {};
  CountingStack completedStack = {};
  ProdigyHostHttpBatchOperation *operation =
      new ProdigyHostHttpBatchOperation(completedClient.submission(), completedStack);
  Vector<ProdigyHostHttpBatchOperation::Request> requests;
  requests.resize(1);
  operation->submit(std::move(requests));
  operation->mustSuspend();
  completedClient.complete(0, MultiCurlClient::Status::success);
  suite.expect(operation->pendingCount() == 0 && completedStack.wakes == 1,
               "host_http_batch_normal_completion_remains_live_after_wake");
  delete operation;

  FakeBatchHttpClient deletingClient = {};
  DestroyingBatchStack deletingStack = {};
  operation = new ProdigyHostHttpBatchOperation(deletingClient.submission(), deletingStack);
  deletingStack.operation = &operation;
  Vector<ProdigyHostHttpBatchOperation::Request> deletingRequests;
  deletingRequests.resize(1);
  operation->submit(std::move(deletingRequests));
  operation->mustSuspend();
  deletingClient.complete(0, MultiCurlClient::Status::success);
  suite.expect(operation == nullptr && deletingStack.wakes == 1 &&
                   deletingClient.cancellations == 0,
               "host_http_batch_callback_may_delete_operation_during_wake");
}

static void testAdmissionQueuesAndRefills(TestSuite& suite)
{
  FakeAdmissionHttpClient client;
  ProdigyHostHttpAdmission admission(client.submission(),
                                     ProdigyHostDelayOperation::submission(),
                                     2,
                                     2);
  AdmissionCompletionSink sink;
  Vector<ProdigyHostHttpAdmission::Ticket> tickets;
  for (uint32_t index = 0; index < 4; ++index)
  {
    ProdigyHostHttpAdmission::Request request;
    request.url.snprintf<"request-{itoa}"_ctv>(index);
    tickets.push_back(admission.submit(std::move(request), sink.callback()));
  }

  suite.expect(client.requests.size() == 2 && admission.activeCount() == 2 &&
                   admission.pendingCount() == 4 && sink.statuses.empty(),
               "host_http_admission_limits_active_requests_and_queues_the_rest");
  client.complete(0);
  suite.expect(client.requests.size() == 3 && admission.activeCount() == 2 &&
                   admission.pendingCount() == 3 && sink.tickets[0].identifier == tickets[0].identifier,
               "host_http_admission_completion_refills_one_slot");
  suite.expect(admission.cancel(tickets[3]) && client.cancellations == 0 &&
                   admission.pendingCount() == 2 && sink.statuses.back() == MultiCurlClient::Status::canceled,
               "host_http_admission_cancels_queued_request_without_touching_client");
  client.complete(1);
  client.complete(2);
  suite.expect(admission.pendingCount() == 0 && admission.activeCount() == 0 &&
                   sink.statuses.size() == 4,
               "host_http_admission_delivers_every_terminal_result_once");
  admission.shutdown();
  suite.expect(admission.shutdownSafe(),
               "host_http_admission_empty_shutdown_is_immediately_safe");
}

static void testAdmissionOverloadActiveCancelAndInline(TestSuite& suite)
{
  FakeAdmissionHttpClient client;
  ProdigyHostHttpAdmission admission(client.submission(),
                                     ProdigyHostDelayOperation::submission(),
                                     1,
                                     1);
  AdmissionCompletionSink sink;
  const ProdigyHostHttpAdmission::Ticket active = admission.submit({}, sink.callback());
  const ProdigyHostHttpAdmission::Ticket queued = admission.submit({}, sink.callback());
  const ProdigyHostHttpAdmission::Ticket overloaded = admission.submit({}, sink.callback());
  suite.expect(active && queued && overloaded && client.requests.size() == 1 &&
                   admission.pendingCount() == 2 && sink.statuses.size() == 1 &&
                   sink.statuses[0] == MultiCurlClient::Status::overloaded,
               "host_http_admission_bounds_total_requests_with_inline_overload");
  suite.expect(admission.cancel(active) && client.cancellations == 1 &&
                   client.requests.size() == 2 && admission.pendingCount() == 1,
               "host_http_admission_active_cancel_refills_from_queue");
  admission.shutdown();
  suite.expect(client.cancellations == 1 && admission.shutdownSafe() == false &&
                   sink.statuses.size() == 2 &&
                   sink.statuses[1] == MultiCurlClient::Status::canceled &&
                   admission.activeCount() == 1,
               "host_http_admission_shutdown_leaves_active_request_to_client_shutdown");
  client.complete(1, MultiCurlClient::Status::shutdown);
  suite.expect(admission.shutdownSafe() && sink.statuses.size() == 3 &&
                   sink.statuses[2] == MultiCurlClient::Status::shutdown,
               "host_http_admission_becomes_safe_after_active_shutdown_callback");

  FakeAdmissionHttpClient shutdownClient;
  ProdigyHostHttpAdmission shutdownAdmission(shutdownClient.submission(),
                                             ProdigyHostDelayOperation::submission(),
                                             1,
                                             1);
  AdmissionCompletionSink shutdownSink;
  shutdownAdmission.submit({}, shutdownSink.callback());
  shutdownAdmission.submit({}, shutdownSink.callback());
  shutdownAdmission.shutdown();
  suite.expect(shutdownAdmission.pendingCount() == 1 && shutdownSink.statuses.size() == 1 &&
                   shutdownSink.statuses[0] == MultiCurlClient::Status::shutdown,
               "host_http_admission_shutdown_completes_queued_request_as_shutdown");
  shutdownClient.complete(0, MultiCurlClient::Status::shutdown);
  suite.expect(shutdownAdmission.shutdownSafe(),
               "host_http_admission_queued_and_active_shutdown_retires_cleanly");

  FakeAdmissionHttpClient inlineClient;
  inlineClient.completeInline = true;
  ProdigyHostHttpAdmission inlineAdmission(inlineClient.submission(),
                                           ProdigyHostDelayOperation::submission(),
                                           1,
                                           1);
  AdmissionCompletionSink inlineSink;
  const ProdigyHostHttpAdmission::Ticket inlineTicket =
      inlineAdmission.submit({}, inlineSink.callback());
  suite.expect(inlineTicket && inlineAdmission.pendingCount() == 0 &&
                   inlineAdmission.activeCount() == 0 && inlineSink.statuses.size() == 1 &&
                   inlineSink.statuses[0] == MultiCurlClient::Status::success,
               "host_http_admission_handles_inline_client_completion_without_suspension");
  inlineAdmission.shutdown();
}

static void testAdmissionByteBoundAndQueuedDeadline(TestSuite& suite)
{
  FakeAdmissionHttpClient byteClient;
  FakeAdmissionDelayQueue byteDelay;
  ProdigyHostHttpAdmission byteAdmission(byteClient.submission(), byteDelay.submission(), 1, 1, 4);
  AdmissionCompletionSink byteSink;
  byteAdmission.submit({}, byteSink.callback());
  ProdigyHostHttpAdmission::Request oversized;
  oversized.body = "12345"_ctv;
  const ProdigyHostHttpAdmission::Ticket rejected =
      byteAdmission.submit(std::move(oversized), byteSink.callback());
  ProdigyHostHttpAdmission::Request headerHeavy;
  headerHeavy.headers.push_back({"A"_ctv, "1234"_ctv});
  const ProdigyHostHttpAdmission::Ticket headerRejected =
      byteAdmission.submit(std::move(headerHeavy), byteSink.callback());
  suite.expect(rejected && byteAdmission.pendingCount() == 1 &&
                   headerRejected && byteAdmission.queuedCount() == 0 &&
                   byteSink.statuses.size() == 2 &&
                   byteSink.statuses[0] == MultiCurlClient::Status::overloaded &&
                   byteSink.statuses[1] == MultiCurlClient::Status::overloaded,
               "host_http_admission_bounds_retained_queued_request_and_header_bytes");
  byteAdmission.shutdown();
  byteClient.complete(0, MultiCurlClient::Status::shutdown);

  FakeAdmissionHttpClient deadlineClient;
  FakeAdmissionDelayQueue deadlineDelay;
  ProdigyHostHttpAdmission deadlineAdmission(deadlineClient.submission(),
                                             deadlineDelay.submission(),
                                             1,
                                             1,
                                             1024);
  AdmissionCompletionSink deadlineSink;
  deadlineAdmission.submit({}, deadlineSink.callback());
  ProdigyHostHttpAdmission::Request expiring;
  expiring.overallDeadline = MultiCurlClient::Clock::now() + std::chrono::milliseconds(2);
  const ProdigyHostHttpAdmission::Ticket expiringTicket =
      deadlineAdmission.submit(std::move(expiring), deadlineSink.callback());
  std::this_thread::sleep_for(std::chrono::milliseconds(3));
  deadlineDelay.complete();
  suite.expect(expiringTicket && deadlineAdmission.pendingCount() == 1 &&
                   deadlineAdmission.queuedCount() == 0 && deadlineSink.statuses.size() == 1 &&
                   deadlineSink.statuses[0] == MultiCurlClient::Status::deadlineExceeded,
               "host_http_admission_expires_queued_request_at_its_deadline");
  deadlineAdmission.shutdown();
  deadlineClient.complete(0, MultiCurlClient::Status::shutdown);
}

static void testAdmissionReentrantShutdownAndDeferredCancel(TestSuite& suite)
{
  FakeAdmissionHttpClient inlineClient;
  inlineClient.completeInline = true;
  ProdigyHostHttpAdmission inlineAdmission(inlineClient.submission(),
                                           ProdigyHostDelayOperation::submission(),
                                           1,
                                           1);
  AdmissionShutdownSink shutdownSink;
  shutdownSink.admission = &inlineAdmission;
  inlineAdmission.submit({}, {&shutdownSink, AdmissionShutdownSink::completed});
  suite.expect(shutdownSink.calls == 1 && shutdownSink.safeDuringCallback == false &&
                   inlineAdmission.shutdownSafe(),
               "host_http_admission_reentrant_shutdown_is_safe_only_after_callback_unwinds");

  FakeAdmissionHttpClient deferredClient;
  deferredClient.deferCancellation = true;
  deferredClient.cancelReturnsFalse = true;
  ProdigyHostHttpAdmission deferredAdmission(deferredClient.submission(),
                                             ProdigyHostDelayOperation::submission(),
                                             1,
                                             1);
  AdmissionCompletionSink deferredSink;
  const ProdigyHostHttpAdmission::Ticket ticket =
      deferredAdmission.submit({}, deferredSink.callback());
  suite.expect(deferredAdmission.cancel(ticket) == false &&
                   deferredAdmission.pendingCount() == 1 && deferredSink.statuses.empty(),
               "host_http_admission_active_cancel_false_retains_terminal_callback_ownership");
  deferredClient.complete(0, MultiCurlClient::Status::canceled);
  suite.expect(deferredAdmission.pendingCount() == 0 && deferredSink.statuses.size() == 1 &&
                   deferredSink.statuses[0] == MultiCurlClient::Status::canceled,
               "host_http_admission_active_cancel_false_accepts_later_exact_terminal_callback");
  deferredAdmission.shutdown();
}

int main(void)
{
  TestSuite suite;
  testInlineCompletion(suite);
  testDeferredExactOnce(suite);
  testInlineStaleTicket(suite);
  testInvalidSubmissionTicket(suite);
  testAbandonAndDestruction(suite);
  testCallbackMayDestroyOperation(suite);
  testBatchMixedCompletion(suite);
  testBatchInvalidSubmission(suite);
  testBatchCancellationAndCallbackDeletion(suite);
  testAdmissionQueuesAndRefills(suite);
  testAdmissionOverloadActiveCancelAndInline(suite);
  testAdmissionByteBoundAndQueuedDeadline(suite);
  testAdmissionReentrantShutdownAndDeferredCancel(suite);
  return suite.failed == 0 ? 0 : 1;
}
