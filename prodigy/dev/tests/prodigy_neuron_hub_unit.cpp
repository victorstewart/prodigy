#include <networking/includes.h>
#include <services/debug.h>
#include <services/bitsery.h>
#include <services/crypto.h>
#include <services/filesystem.h>
#include <networking/time.h>
#include <networking/ip.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/pool.h>
#include <networking/ring.h>
#include <prodigy/neuron/neuron.h>
#include <prodigy/sdk/cpp/opinionated/aegis_stream.h>
#include <prodigy/neuron.hub.h>

#include <cstdio>
#include <cstdlib>

class TestSuite {
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
      std::fprintf(stderr, "FAIL: %s\n", name);
      failed += 1;
    }
  }
};

class TestNeuronHubDispatch final : public NeuronHubDispatch {
public:

  void beginShutdown(void) override
  {}
};

class TestNeuronControlRuntime final : public Neuron {
public:

  uint32_t rawPollCompletions = 0;
  uint32_t closeCompletions = 0;
  uint32_t stopAfterCloseCompletions = 0;

  void closeHandler(void *socket) override
  {
    Neuron::closeHandler(socket);
    closeCompletions += 1;
    if (stopAfterCloseCompletions != 0 && closeCompletions >= stopAfterCloseCompletions)
    {
      Ring::exit = true;
    }
  }

  void rawFDPollHandler(void *owner, uint64_t generation, uint64_t ticket, int result) override
  {
    Neuron::rawFDPollHandler(owner, generation, ticket, result);
    rawPollCompletions += 1;
    Ring::exit = true;
  }

  void pushContainer(Container *container) override
  {
    (void)container;
  }

  void popContainer(Container *container) override
  {
    (void)container;
  }

  void downloadContainer(CoroutineStack *coro, uint64_t deploymentID) override
  {
    (void)coro;
    (void)deploymentID;
  }

  bool ensureHostNetworkingReady(String *failureReport = nullptr) override
  {
    if (failureReport)
    {
      failureReport->clear();
    }
    return true;
  }

  void testRetireBrainControlStream(NeuronBrainControlStream *stream)
  {
    retireBrainControlStream(stream, "unit-test");
  }

  bool testHasClosingBrainControl(NeuronBrainControlStream *stream) const
  {
    return closingBrainControls.contains(stream);
  }

  bool testRawStreamIsActive(Container *container) const
  {
    return rawStreamIsActive(container);
  }

  void testCloseHandler(void *socket)
  {
    closeHandler(socket);
  }

  void testRecvHandler(void *socket, int result)
  {
    recvHandler(socket, result);
  }

  void testConnectHandler(void *socket, int result)
  {
    connectHandler(socket, result);
  }

  bool testRetireContainerControlBeforeRestart(Container *container)
  {
    return retireContainerControlBeforeRestart(container);
  }
};

class ScopedRing final {
public:

  bool created = false;

  ScopedRing()
  {
    if (Ring::getRingFD() <= 0)
    {
      Ring::createRing(8, 8, 32, 32, -1, -1, 0);
      created = true;
    }
  }

  ~ScopedRing()
  {
    if (created)
    {
      Ring::shutdownForExec();
    }
  }
};

static void testNeuronHubCanQueueToNeuron(TestSuite& suite)
{
  suite.expect(prodigyNeuronHubCanQueueToNeuron(false, true, 7), "neuron_hub_can_queue_when_fixed_file_is_live");
  suite.expect(prodigyNeuronHubCanQueueToNeuron(true, true, 7) == false, "neuron_hub_rejects_closing_stream");
  suite.expect(prodigyNeuronHubCanQueueToNeuron(false, false, 7) == false, "neuron_hub_rejects_non_fixed_stream");
  suite.expect(prodigyNeuronHubCanQueueToNeuron(false, true, -1) == false, "neuron_hub_rejects_missing_fixed_slot");
}

static void testNeuronHubFlushesBufferedFramesWhenNeuronBecomesSendable(TestSuite& suite)
{
  suite.expect(
      prodigyNeuronHubShouldFlushBufferedNeuronFrames(true, false, 1),
      "neuron_hub_flushes_buffered_frame_once_sendable");
  suite.expect(
      prodigyNeuronHubShouldFlushBufferedNeuronFrames(true, false, 128),
      "neuron_hub_flushes_multiple_buffered_bytes_once_sendable");
  suite.expect(
      prodigyNeuronHubShouldFlushBufferedNeuronFrames(false, false, 128) == false,
      "neuron_hub_does_not_flush_before_stream_is_sendable");
  suite.expect(
      prodigyNeuronHubShouldFlushBufferedNeuronFrames(true, true, 128) == false,
      "neuron_hub_does_not_double_queue_while_send_is_pending");
  suite.expect(
      prodigyNeuronHubShouldFlushBufferedNeuronFrames(true, false, 0) == false,
      "neuron_hub_does_not_flush_empty_buffer");
}

static void testNeuronHubRetainsBuffersUntilCloseRetirement(TestSuite& suite)
{
  int listener = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  struct sockaddr_un address = {};
  address.sun_family = AF_UNIX;
  char path[] = "/tmp/prodigy-neuron-hub-retirement-XXXXXX";
  int pathFD = ::mkstemp(path);
  if (pathFD >= 0)
  {
    ::close(pathFD);
    ::unlink(path);
  }
  strncpy(address.sun_path, path, sizeof(address.sun_path) - 1);
  const bool listenerReady = listener >= 0 &&
      ::bind(listener, reinterpret_cast<struct sockaddr *>(&address), sizeof(address)) == 0 &&
      ::listen(listener, 4) == 0;
  suite.expect(listenerReady, "neuron_hub_retirement_creates_listener");
  if (listenerReady == false)
  {
    if (listener >= 0)
    {
      ::close(listener);
    }
    ::unlink(path);
    return;
  }

  String listenerText = {};
  listenerText.assignItoa(listener);
  ::setenv("PRODIGY_NEURON_LISTENER_FD", listenerText.c_str(), 1);

  TestNeuronHubDispatch dispatch = {};
  NeuronHub hub(&dispatch);
  int sockets[2] = {-1, -1};
  suite.expect(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0, "neuron_hub_retirement_creates_control_pair");
  if (sockets[0] >= 0)
  {
    hub.neuron.setUnixPairHalf(sockets[0]);
    Ring::installFDIntoFixedFileSlot(&hub.neuron);
    hub.neuron.rBuffer.reserve(64);
    hub.neuron.wBuffer.append("pending", 7);
    Ring::queueRecv(&hub.neuron);
    Ring::queueSend(&hub.neuron);
    const uint64_t activeGeneration = hub.neuron.ioGeneration;
    const uint64_t receiveCapacity = hub.neuron.rBuffer.remainingCapacity();

    hub.socketFailed(&hub.neuron);

    suite.expect(Ring::socketIsClosing(&hub.neuron), "neuron_hub_retirement_queues_identity_close");
    suite.expect(hub.neuron.ioGeneration == activeGeneration + 1, "neuron_hub_retirement_does_not_reset_before_close");
    suite.expect(hub.neuron.wBuffer.outstandingBytes() == 7, "neuron_hub_retirement_preserves_send_storage_until_cqe");
    suite.expect(hub.neuron.rBuffer.remainingCapacity() == receiveCapacity, "neuron_hub_retirement_preserves_recv_storage_until_cqe");
  }

  if (sockets[1] >= 0)
  {
    ::close(sockets[1]);
  }
  ::unsetenv("PRODIGY_NEURON_LISTENER_FD");
  ::unlink(path);
  ::close(listener);
}

static void testNeuronRetiredBrainCloseDoesNotDeleteReplacement(TestSuite& suite)
{
  TestNeuronControlRuntime runtime = {};

  NeuronBrainControlStream *retired = new NeuronBrainControlStream();
  retired->connected = false;
  retired->isFixedFile = true;
  retired->fslot = -1;
  retired->pendingRecv = true;
  runtime.brain = retired;

  runtime.testRetireBrainControlStream(retired);
  suite.expect(runtime.brain == nullptr, "neuron_control_retires_replaced_brain_stream");
  suite.expect(runtime.testHasClosingBrainControl(retired), "neuron_control_tracks_retired_brain_stream_until_close");

  NeuronBrainControlStream *replacement = new NeuronBrainControlStream();
  replacement->connected = true;
  runtime.brain = replacement;

  runtime.testCloseHandler(retired);
  suite.expect(runtime.brain == replacement, "neuron_control_retired_close_does_not_delete_replacement");
  suite.expect(runtime.testHasClosingBrainControl(retired) == false, "neuron_control_drops_retired_stream_after_close");

  replacement->isFixedFile = false;
  replacement->fd = -1;
  replacement->fslot = -1;
  runtime.testCloseHandler(replacement);
  suite.expect(runtime.brain == nullptr, "neuron_control_current_close_still_clears_current_stream");
}

static void testNeuronActiveBrainCloseRetainsPendingStreamUntilRecvDrain(TestSuite& suite)
{
  TestNeuronControlRuntime runtime = {};

  NeuronBrainControlStream *active = new NeuronBrainControlStream();
  active->connected = true;
  active->pendingRecv = true;
  runtime.brain = active;

  runtime.testCloseHandler(active);
  suite.expect(runtime.brain == nullptr, "neuron_control_active_close_clears_current_stream");
  bool retained = runtime.testHasClosingBrainControl(active);
  suite.expect(retained, "neuron_control_active_close_retains_pending_stream");

  NeuronBrainControlStream *replacement = new NeuronBrainControlStream();
  replacement->connected = true;
  runtime.brain = replacement;

  if (retained)
  {
    runtime.testRecvHandler(active, -ECONNRESET);
    suite.expect(runtime.brain == replacement, "neuron_control_stale_recv_does_not_close_replacement");
    suite.expect(runtime.testHasClosingBrainControl(active) == false, "neuron_control_stale_recv_releases_retained_stream");
  }

  replacement->isFixedFile = false;
  replacement->fd = -1;
  replacement->fslot = -1;
  runtime.testCloseHandler(replacement);
  suite.expect(runtime.brain == nullptr, "neuron_control_replacement_close_clears_current_stream");
}

static void testContainerRestartWaitsForControlRetirement(TestSuite& suite)
{
  TestNeuronControlRuntime runtime = {};
  Container container = {};
  int sockets[2] = {-1, -1};

  suite.expect(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0, "container_restart_retirement_creates_socket_pair");
  if (sockets[0] < 0)
  {
    return;
  }

  container.setUnixPairHalf(sockets[0]);
  Ring::installFDIntoFixedFileSlot(&container);
  container.rBuffer.reserve(64);
  container.wBuffer.append("pending", 7);
  Ring::queueRecv(&container);
  Ring::queueSend(&container);

  suite.expect(runtime.testRetireContainerControlBeforeRestart(&container), "container_restart_retirement_defers_live_control_stream");
  suite.expect(container.restartAfterClose, "container_restart_retirement_records_deferred_restart");
  suite.expect(Ring::socketIsClosing(&container), "container_restart_retirement_queues_identity_close");
  suite.expect(container.wBuffer.outstandingBytes() == 7, "container_restart_retirement_preserves_send_storage_until_cqe");
  suite.expect(container.rBuffer.remainingCapacity() == 64, "container_restart_retirement_preserves_recv_storage_until_cqe");

  ::close(sockets[1]);
}

static void testContainerUnixSocketRecreate(TestSuite& suite)
{
  Container container = {};
  suite.expect(container.fd == -1,
               "container_default_does_not_eagerly_allocate_control_socket");

  container.setSocketPath("/tmp/prodigy-neuron-hub-unit.sock");
  container.recreateSocket();
  int actualDomain = AF_UNSPEC;
  int actualType = 0;
  socklen_t actualDomainLength = sizeof(actualDomain);
  socklen_t actualTypeLength = sizeof(actualType);
  const bool validUnixStream = container.fd >= 0 &&
                               ::getsockopt(container.fd, SOL_SOCKET, SO_DOMAIN, &actualDomain, &actualDomainLength) == 0 &&
                               actualDomainLength == sizeof(actualDomain) && actualDomain == AF_UNIX &&
                               ::getsockopt(container.fd, SOL_SOCKET, SO_TYPE, &actualType, &actualTypeLength) == 0 &&
                               actualTypeLength == sizeof(actualType) && actualType == SOCK_STREAM;
  suite.expect(validUnixStream,
               "container_recreate_socket_opens_unix_stream_after_control_close");
  if (container.fd >= 0)
  {
    ::close(container.fd);
    container.fd = -1;
  }
}

static void testContainerControlExecQuiesce(TestSuite& suite)
{
  TestNeuronControlRuntime runtime = {};
  NeuronBase *previousNeuron = thisNeuron;
  RingInterface *previousInterfacer = Ring::interfacer;
  thisNeuron = &runtime;
  Ring::interfacer = &runtime;

  int socketPair[2] = {-1, -1};
  suite.expect(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, socketPair) == 0,
               "container_control_exec_quiesce_creates_socketpair");
  if (socketPair[0] < 0)
  {
    Ring::interfacer = previousInterfacer;
    thisNeuron = previousNeuron;
    return;
  }

  Container retained = {};
  retained.plan.uuid = 993;
  retained.pid = ::getpid();
  retained.neuronListenerPath.assign("/tmp/prodigy-neuron-control-reconnect-unit"_ctv);
  runtime.containers.insert_or_assign(retained.plan.uuid, &retained);

  // An ordinary live close still recreates and queues the addressful control
  // stream. Bundle exec must suppress only this rearm, not normal recovery.
  runtime.testCloseHandler(&retained);
  suite.expect(runtime.testRawStreamIsActive(&retained) && retained.pendingConnectUserData != 0,
               "container_control_exec_quiesce_normal_close_rearms_connect");
  const int reconnectFD = retained.fd;
  runtime.closeCompletions = 0;

  Container draining = {};
  draining.plan.uuid = 994;
  draining.pid = ::getpid();
  draining.fd = socketPair[0];
  Ring::installFDIntoFixedFileSlot(&draining);
  runtime.containers.insert_or_assign(draining.plan.uuid, &draining);
  Ring::queueRecv(&draining);
  suite.expect(runtime.testRawStreamIsActive(&draining) && draining.pendingRecv,
               "container_control_exec_quiesce_arms_real_control_recv");

  runtime.beginBundleExecQuiesce();
  runtime.testConnectHandler(&retained, -ECONNREFUSED);
  suite.expect(Ring::socketIsClosing(&retained) == false && retained.fd == reconnectFD,
               "container_control_exec_quiesce_blocks_connect_failure_rearm");

  suite.expect(runtime.quiesceContainerControlSocketsForBundleExec() == false,
               "container_control_exec_quiesce_waits_for_control_close_cqe");
  suite.expect(Ring::socketIsClosing(&retained) && Ring::socketIsClosing(&draining) &&
                   runtime.containers.find(retained.plan.uuid) != runtime.containers.end() &&
                   runtime.containers.find(draining.plan.uuid) != runtime.containers.end() &&
                   retained.pid == ::getpid() && draining.pid == ::getpid(),
               "container_control_exec_quiesce_preserves_live_container_owner");

  runtime.stopAfterCloseCompletions = 2;
  Ring::exit = false;
  Ring::start();
  Ring::exit = false;
  suite.expect(runtime.closeCompletions == 2 && runtime.testRawStreamIsActive(&retained) == false &&
                   runtime.testRawStreamIsActive(&draining) == false && retained.pendingConnectUserData == 0 &&
                   draining.pendingRecv == false,
               "container_control_exec_quiesce_drains_cancelled_control_operations");
  suite.expect(runtime.quiesceContainerControlSocketsForBundleExec() &&
                   runtime.containers.find(retained.plan.uuid) != runtime.containers.end() &&
                   runtime.containers.find(draining.plan.uuid) != runtime.containers.end() &&
                   retained.pid == ::getpid() && draining.pid == ::getpid(),
               "container_control_exec_quiesce_finishes_without_reopening_or_destroying");

  Container pendingDestroy = {};
  pendingDestroy.plan.uuid = 995;
  pendingDestroy.pendingDestroy = true;
  pendingDestroy.waitidPending = true;
  runtime.containers.insert_or_assign(pendingDestroy.plan.uuid, &pendingDestroy);
  runtime.testCloseHandler(&pendingDestroy);
  suite.expect(pendingDestroy.destroyCloseCompleted &&
                   runtime.containers.find(pendingDestroy.plan.uuid) != runtime.containers.end(),
               "container_control_exec_quiesce_preserves_pending_destroy_close_ack");

  runtime.testCloseHandler(&retained);
  suite.expect(runtime.testRawStreamIsActive(&retained) == false,
               "container_control_exec_quiesce_blocks_close_reconnect_after_drain");

  runtime.containers.erase(retained.plan.uuid);
  runtime.containers.erase(draining.plan.uuid);
  runtime.containers.erase(pendingDestroy.plan.uuid);
  ::close(socketPair[1]);
  Ring::interfacer = previousInterfacer;
  thisNeuron = previousNeuron;
}

static void testRetainedNonChildPidfdExecQuiesce(TestSuite& suite)
{
  TestNeuronControlRuntime runtime = {};
  NeuronBase *previousNeuron = thisNeuron;
  thisNeuron = &runtime;

  Container retained = {};
  retained.plan.uuid = 991;
  int retainedPidfd[2] = {-1, -1};
  suite.expect(::pipe2(retainedPidfd, O_CLOEXEC) == 0,
               "retained_pidfd_exec_quiesce_creates_liveness_pipe");
  if (retainedPidfd[0] < 0)
  {
    thisNeuron = previousNeuron;
    return;
  }

  retained.pid = 9911;
  retained.pidfd = retainedPidfd[0];
  retained.waitidPending = true;
  retained.nonChildPidfdLiveness = true;
  runtime.containers.insert_or_assign(retained.plan.uuid, &retained);

  RingInterface *previousInterfacer = Ring::interfacer;
  Ring::interfacer = &runtime;
  retained.nonChildPidfdTicket = Ring::queueRawFDPoll(
      &retained, uint64_t(retained.pid), retained.pidfd, POLLIN);
  suite.expect(retained.nonChildPidfdTicket != Ring::invalidRawPollTicket,
               "retained_pidfd_exec_quiesce_arms_real_raw_poll");
  const Ring::RawPollTicket firstTicket = retained.nonChildPidfdTicket;
  if (retained.nonChildPidfdTicket == Ring::invalidRawPollTicket)
  {
    Ring::interfacer = previousInterfacer;
    runtime.containers.erase(retained.plan.uuid);
    ::close(retainedPidfd[0]);
    ::close(retainedPidfd[1]);
    thisNeuron = previousNeuron;
    return;
  }

  Container directChild = {};
  directChild.plan.uuid = 992;
  directChild.pid = 9912;
  directChild.waitidPending = true;
  directChild.nonChildPidfdLiveness = false;
  directChild.nonChildPidfdTicket = Ring::invalidRawPollTicket;
  runtime.containers.insert_or_assign(directChild.plan.uuid, &directChild);

  suite.expect(ContainerManager::quiesceRetainedNonChildPidfdPollsForBundleExec() == false,
               "retained_pidfd_exec_quiesce_waits_for_terminal_cqe");
  suite.expect(retained.nonChildPidfdCancellationRequested && retained.nonChildPidfdTicket == firstTicket &&
                   runtime.containers.find(retained.plan.uuid) != runtime.containers.end(),
               "retained_pidfd_exec_quiesce_preserves_live_container_owner");
  suite.expect(directChild.waitidPending && directChild.nonChildPidfdTicket == Ring::invalidRawPollTicket,
               "retained_pidfd_exec_quiesce_leaves_direct_child_waitid_untouched");

  Ring::exit = false;
  Ring::start();
  Ring::exit = false;
  suite.expect(runtime.rawPollCompletions == 1,
               "retained_pidfd_exec_quiesce_dispatches_real_cancel_terminal_cqe");
  suite.expect(retained.nonChildPidfdLiveness == false && retained.waitidPending == false &&
                   retained.pid == 9911 && runtime.containers.find(retained.plan.uuid) != runtime.containers.end(),
               "retained_pidfd_exec_quiesce_cancel_preserves_live_process_plan_and_owner");
  suite.expect(ContainerManager::quiesceRetainedNonChildPidfdPollsForBundleExec(),
               "retained_pidfd_exec_quiesce_completes_after_terminal_cqe");

  retained.nonChildPidfdLiveness = true;
  retained.waitidPending = true;
  retained.nonChildPidfdTicket = 92;
  retained.nonChildPidfdCancellationRequested = false;
  suite.expect(ContainerManager::quiesceRetainedNonChildPidfdPollsForBundleExec() == false &&
                   retained.nonChildPidfdCancellationRequested,
               "retained_pidfd_exec_quiesce_fences_ticket_rearmed_during_retry");
  suite.expect(ContainerManager::completeNonChildPidfdPoll(&retained, uint64_t(retained.pid), firstTicket, -ECANCELED) == false &&
                   retained.nonChildPidfdTicket == 92 && retained.nonChildPidfdLiveness,
               "retained_pidfd_exec_quiesce_ignores_stale_cancel_completion_after_rearm");
  (void)ContainerManager::completeNonChildPidfdPoll(&retained, uint64_t(retained.pid), 92, -ECANCELED);

  runtime.containers.erase(retained.plan.uuid);
  runtime.containers.erase(directChild.plan.uuid);
  Ring::interfacer = previousInterfacer;
  ::close(retainedPidfd[1]);
  thisNeuron = previousNeuron;
}

static void testRetainedNonChildPidfdLiveness(TestSuite& suite)
{
  int childPIDPipe[2] = {-1, -1};
  suite.expect(::pipe2(childPIDPipe, O_CLOEXEC) == 0, "retained_pidfd_creates_pid_pipe");
  if (childPIDPipe[0] < 0)
  {
    return;
  }

  pid_t helper = ::fork();
  suite.expect(helper >= 0, "retained_pidfd_forks_helper");
  if (helper == 0)
  {
    ::close(childPIDPipe[0]);
    pid_t retained = ::fork();
    if (retained == 0)
    {
      ::sleep(1);
      _exit(37);
    }
    (void)::write(childPIDPipe[1], &retained, sizeof(retained));
    _exit(retained > 0 ? 0 : 1);
  }
  ::close(childPIDPipe[1]);
  pid_t retained = -1;
  const ssize_t received = ::read(childPIDPipe[0], &retained, sizeof(retained));
  ::close(childPIDPipe[0]);
  int helperStatus = 0;
  if (helper > 0)
  {
    (void)::waitpid(helper, &helperStatus, 0);
  }
  suite.expect(received == ssize_t(sizeof(retained)) && retained > 0 && WIFEXITED(helperStatus), "retained_pidfd_receives_nonchild_pid");
  if (retained <= 0)
  {
    return;
  }

  int pidfd = int(::syscall(SYS_pidfd_open, retained, 0));
  suite.expect(pidfd >= 0, "retained_pidfd_opens_nonchild_pidfd");
  if (pidfd < 0)
  {
    return;
  }
  siginfo_t unavailable = {};
  suite.expect(::waitid(static_cast<idtype_t>(P_PIDFD), id_t(pidfd), &unavailable, WEXITED | WNOHANG) < 0 && errno == ECHILD, "retained_pidfd_nonchild_waitid_is_echild");

  struct pollfd poller = {.fd = pidfd, .events = POLLIN, .revents = 0};
  suite.expect(::poll(&poller, 1, 0) == 0, "retained_pidfd_is_pending_while_process_lives");
  poller.revents = 0;
  suite.expect(::poll(&poller, 1, 5000) == 1 && (poller.revents & POLLIN), "retained_pidfd_signals_exit");

  Container observed = {};
  observed.pid = retained;
  observed.pidfd = pidfd;
  observed.waitidPending = true;
  observed.nonChildPidfdLiveness = true;
  observed.nonChildPidfdTicket = 77;
  suite.expect(ContainerManager::completeNonChildPidfdPoll(&observed, uint64_t(retained), 77, POLLIN), "retained_pidfd_marks_exit_without_waitid");
  suite.expect(observed.waitidPending && observed.pidfdExitStatusUnknown && observed.infop.si_pid == retained && observed.infop.si_code == 0 && observed.infop.si_status == 0, "retained_pidfd_exit_status_remains_unknown");
  int cancellationPidfd = ::dup(observed.pidfd);
  ::close(observed.pidfd);

  Container cancelled = {};
  cancelled.pid = retained;
  cancelled.pidfd = cancellationPidfd;
  cancelled.waitidPending = true;
  cancelled.nonChildPidfdLiveness = true;
  cancelled.nonChildPidfdTicket = 78;
  int invalidPidfd = ::dup(cancelled.pidfd);
  suite.expect(ContainerManager::completeNonChildPidfdPoll(&cancelled, uint64_t(retained), 78, -ECANCELED) == false, "retained_pidfd_cancellation_is_not_exit");
  suite.expect(cancelled.waitidPending == false && cancelled.nonChildPidfdTicket == Ring::invalidRawPollTicket && cancelled.pidfd == -1, "retained_pidfd_cancellation_releases_after_terminal_callback");

  Container invalidReadiness = {};
  invalidReadiness.pid = retained;
  invalidReadiness.pidfd = invalidPidfd;
  invalidReadiness.waitidPending = true;
  invalidReadiness.nonChildPidfdLiveness = true;
  invalidReadiness.nonChildPidfdTicket = 79;
  suite.expect(ContainerManager::completeNonChildPidfdPoll(&invalidReadiness, uint64_t(retained), 79, POLLERR) == false, "retained_pidfd_nonreadiness_is_not_exit");
  suite.expect(invalidReadiness.waitidPending && invalidReadiness.nonChildPidfdLiveness && invalidReadiness.nonChildPidfdTicket == Ring::invalidRawPollTicket && invalidReadiness.pidfdExitStatusUnknown == false, "retained_pidfd_nonreadiness_retains_owner");
  ::close(invalidPidfd);

  pid_t directChild = ::fork();
  suite.expect(directChild >= 0, "retained_pidfd_forks_direct_child");
  if (directChild == 0)
  {
    _exit(19);
  }
  if (directChild > 0)
  {
    int directPidfd = int(::syscall(SYS_pidfd_open, directChild, 0));
    suite.expect(directPidfd >= 0, "retained_pidfd_opens_direct_child_pidfd");
    if (directPidfd >= 0)
    {
      siginfo_t observedChild = {};
      suite.expect(::waitid(static_cast<idtype_t>(P_PIDFD), id_t(directPidfd), &observedChild, WEXITED | WNOWAIT) == 0 && observedChild.si_pid == directChild, "retained_pidfd_direct_child_is_waitable");
      siginfo_t reapedChild = {};
      suite.expect(::waitid(static_cast<idtype_t>(P_PIDFD), id_t(directPidfd), &reapedChild, WEXITED) == 0 && reapedChild.si_code == CLD_EXITED && reapedChild.si_status == 19, "retained_pidfd_direct_child_reaps_with_status");
      ::close(directPidfd);
    }
    else
    {
      (void)::waitpid(directChild, nullptr, 0);
    }
  }
}

int main(void)
{
  TestSuite suite = {};
  testContainerUnixSocketRecreate(suite);
  testRetainedNonChildPidfdLiveness(suite);

  ScopedRing ring = {};
  testContainerControlExecQuiesce(suite);
  testRetainedNonChildPidfdExecQuiesce(suite);
  testNeuronHubCanQueueToNeuron(suite);
  testNeuronHubFlushesBufferedFramesWhenNeuronBecomesSendable(suite);
  testNeuronHubRetainsBuffersUntilCloseRetirement(suite);
  testNeuronRetiredBrainCloseDoesNotDeleteReplacement(suite);
  testNeuronActiveBrainCloseRetainsPendingStreamUntilRecvDrain(suite);
  testContainerRestartWaitsForControlRetirement(suite);

  return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
