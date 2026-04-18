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

#include <cstdlib>

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

class TestNeuronControlRuntime final : public Neuron
{
public:

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

   void testCloseHandler(void *socket)
   {
      closeHandler(socket);
   }

   void testRecvHandler(void *socket, int result)
   {
      recvHandler(socket, result);
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

int main(void)
{
   TestSuite suite = {};

   testNeuronHubCanQueueToNeuron(suite);
   testNeuronHubFlushesBufferedFramesWhenNeuronBecomesSendable(suite);
   testNeuronRetiredBrainCloseDoesNotDeleteReplacement(suite);
   testNeuronActiveBrainCloseRetainsPendingStreamUntilRecvDrain(suite);

   return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
