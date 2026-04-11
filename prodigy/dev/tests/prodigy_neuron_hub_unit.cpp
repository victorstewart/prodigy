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

int main(void)
{
   TestSuite suite = {};

   testNeuronHubCanQueueToNeuron(suite);
   testNeuronHubFlushesBufferedFramesWhenNeuronBecomesSendable(suite);

   return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
