#include <includes.h>

#include <prodigy/transport.bulk.h>

#include <cstdio>
#include <cstring>

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
      failed += 1;
    }
  }
};

static String makeMessage(uint16_t topic, uint32_t payloadBytes)
{
  String payload = {};
  if (payload.reserve(payloadBytes))
  {
    for (uint32_t index = 0; index < payloadBytes; ++index)
    {
      uint8_t byte = uint8_t((index * 17u) & 0xffu);
      payload.append(&byte, 1);
    }
  }
  String message = {};
  Message::construct(message, topic, payload);
  return message;
}

static String takeFrame(StreamBuffer& buffer)
{
  String frame = {};
  frame.assign(buffer.pHead(), buffer.outstandingBytes());
  buffer.clear();
  return frame;
}

static ProdigyBulkTransfer::ConsumeResult consumeFrame(
    ProdigyBulkTransfer& receiver,
    String& frame,
    String& delivered,
    String& failure)
{
  Message *message = reinterpret_cast<Message *>(frame.data());
  return receiver.consume(message,
                          [&](String&& complete) -> void {
                            delivered = std::move(complete);
                          },
                          &failure);
}

static String makeFragment(uint64_t transferID, uint32_t total, uint32_t offset, const String& bytes)
{
  String frame = {};
  Message::construct(frame, ProdigyBulkTransfer::fragmentTopic, transferID, total, offset, bytes);
  return frame;
}

static void testLargeFragmentedRoundTrip(TestSuite& suite)
{
  ProdigyBulkTransfer sender = {};
  ProdigyBulkTransfer receiver = {};
  StreamBuffer outbound = {};
  String original = makeMessage(101, ProdigyBulkTransfer::maximumFragmentBytes * 2 + 93);
  String expected = original;
  String failure = {};
  String delivered = {};

  suite.expect(sender.queue(std::move(original), &failure), "bulk_queue_large_complete_message");
  uint32_t fragments = 0;
  ProdigyBulkTransfer::ConsumeResult finalResult = ProdigyBulkTransfer::ConsumeResult::notFragment;
  while (sender.appendNextChunk(outbound, &failure))
  {
    String fragment = takeFrame(outbound);
    finalResult = consumeFrame(receiver, fragment, delivered, failure);
    fragments += 1;
  }

  suite.expect(fragments == 3, "bulk_large_message_emits_three_bounded_fragments");
  suite.expect(finalResult == ProdigyBulkTransfer::ConsumeResult::complete, "bulk_large_message_completes");
  suite.expect(delivered.equals(expected), "bulk_large_message_preserves_exact_bytes");
  suite.expect(sender.queuedTransfers() == 0 && sender.queuedBytes() == 0, "bulk_large_message_drains_outbound_accounting");
}

static void testControlsDrainBetweenChunks(TestSuite& suite)
{
  ProdigyBulkTransfer sender = {};
  StreamBuffer outbound = {};
  String failure = {};
  String original = makeMessage(102, ProdigyBulkTransfer::maximumFragmentBytes + 1);
  suite.expect(sender.queue(std::move(original), &failure), "bulk_controls_queue_large_message");
  suite.expect(sender.appendNextChunk(outbound, &failure), "bulk_controls_emit_first_chunk");
  String firstChunk = takeFrame(outbound);
  suite.expect(reinterpret_cast<Message *>(firstChunk.data())->topic == ProdigyBulkTransfer::fragmentTopic,
               "bulk_controls_first_frame_is_fragment");

  Message::construct(outbound, uint16_t(103));
  suite.expect(sender.appendNextChunk(outbound, &failure) == false, "bulk_controls_nonempty_control_buffer_blocks_next_chunk");
  String control = takeFrame(outbound);
  suite.expect(reinterpret_cast<Message *>(control.data())->topic == 103, "bulk_controls_control_frame_remains_fifo_before_next_chunk");
  suite.expect(sender.appendNextChunk(outbound, &failure), "bulk_controls_emit_second_chunk_after_control_drain");
}

static void testConsumedSendBufferDoesNotAccumulateChunks(TestSuite& suite)
{
  ProdigyBulkTransfer sender = {};
  StreamBuffer outbound = {};
  String failure = {};
  String original = makeMessage(103, ProdigyBulkTransfer::maximumFragmentBytes * 3 + 17);
  suite.expect(sender.queue(std::move(original), &failure), "bulk_consumed_send_queue_large_message");

  uint32_t chunks = 0;
  while (sender.appendNextChunk(outbound, &failure))
  {
    ++chunks;
    const uint64_t frameBytes = outbound.outstandingBytes();
    suite.expect(frameBytes > 0 && frameBytes <= ProdigyBulkTransfer::maximumFragmentBytes + 128,
                 "bulk_consumed_send_chunk_is_bounded");
    outbound.consume(frameBytes, false);
    suite.expect(outbound.outstandingBytes() == 0 && outbound.size() == 0 &&
                     outbound.reservedBytes() <= ProdigyBulkTransfer::maximumFragmentBytes * 2u,
                 "bulk_consumed_send_buffer_is_reused_without_tail_growth");
  }
  suite.expect(chunks == 4 && sender.hasOutbound() == false,
               "bulk_consumed_send_all_chunks_drain_without_manual_clear");
}

static void testInvalidInboundSequences(TestSuite& suite)
{
  const String original = makeMessage(104, 20);
  String prefix = original.substr(0, 8, Copy::yes);
  String failure = {};
  String delivered = {};

  {
    ProdigyBulkTransfer receiver = {};
    String first = makeFragment(1, uint32_t(original.size()), 0, prefix);
    suite.expect(consumeFrame(receiver, first, delivered, failure) == ProdigyBulkTransfer::ConsumeResult::incomplete,
                 "bulk_invalid_partial_first_fragment_is_incomplete");
    String overlap = makeFragment(1, uint32_t(original.size()), 0, prefix);
    suite.expect(consumeFrame(receiver, overlap, delivered, failure) == ProdigyBulkTransfer::ConsumeResult::invalid,
                 "bulk_invalid_duplicate_offset_rejected");
  }

  {
    ProdigyBulkTransfer receiver = {};
    String first = makeFragment(2, uint32_t(original.size()), 0, prefix);
    suite.expect(consumeFrame(receiver, first, delivered, failure) == ProdigyBulkTransfer::ConsumeResult::incomplete,
                 "bulk_invalid_offset_first_fragment_is_incomplete");
    String gap = makeFragment(2, uint32_t(original.size()), 7, prefix);
    suite.expect(consumeFrame(receiver, gap, delivered, failure) == ProdigyBulkTransfer::ConsumeResult::invalid,
                 "bulk_invalid_different_offset_rejected");
  }

  {
    ProdigyBulkTransfer receiver = {};
    String oversized = makeFragment(2, ProdigyWire::maxControlFrameBytes + 1u, 0, prefix);
    suite.expect(consumeFrame(receiver, oversized, delivered, failure) == ProdigyBulkTransfer::ConsumeResult::invalid,
                 "bulk_invalid_oversized_total_rejected");
  }

  {
    ProdigyBulkTransfer receiver = {};
    String oneByte = {};
    oneByte.append(uint8_t(1));
    String claimedLarge = makeFragment(3, ProdigyWire::maxControlFrameBytes, 0, oneByte);
    suite.expect(consumeFrame(receiver, claimedLarge, delivered, failure) == ProdigyBulkTransfer::ConsumeResult::incomplete,
                 "bulk_large_claimed_start_accepts_only_actual_fragment");
    suite.expect(receiver.pendingIncomingReservedBytes() <= ProdigyBulkTransfer::maximumFragmentBytes * 2u,
                 "bulk_large_claimed_start_does_not_reserve_claimed_total");
  }

  {
    ProdigyBulkTransfer receiver = {};
    String invalidOriginal = {};
    invalidOriginal.append(uint8_t(7));
    String fragment = makeFragment(4, uint32_t(invalidOriginal.size()), 0, invalidOriginal);
    suite.expect(consumeFrame(receiver, fragment, delivered, failure) == ProdigyBulkTransfer::ConsumeResult::invalid,
                 "bulk_invalid_reassembled_message_rejected_before_callback");
  }

  {
    ProdigyBulkTransfer receiver = {};
    String control = makeMessage(106, 1);
    suite.expect(consumeFrame(receiver, control, delivered, failure) == ProdigyBulkTransfer::ConsumeResult::notFragment,
                 "bulk_non_fragment_is_left_for_existing_dispatch");
  }
}

static void testResetAndReplayFence(TestSuite& suite)
{
  String original = makeMessage(105, 20);
  String fragment = makeFragment(7, uint32_t(original.size()), 0, original);
  String failure = {};
  String delivered = {};
  ProdigyBulkTransfer receiver = {};

  suite.expect(consumeFrame(receiver, fragment, delivered, failure) == ProdigyBulkTransfer::ConsumeResult::complete,
               "bulk_replay_first_transfer_completes");
  suite.expect(consumeFrame(receiver, fragment, delivered, failure) == ProdigyBulkTransfer::ConsumeResult::invalid,
               "bulk_replay_same_transfer_rejected_within_stream");
  receiver.reset();
  suite.expect(consumeFrame(receiver, fragment, delivered, failure) == ProdigyBulkTransfer::ConsumeResult::complete,
               "bulk_reset_allows_new_transport_generation_to_reuse_id");
}

static void testOutboundLimits(TestSuite& suite)
{
  ProdigyBulkTransfer sender = {};
  String failure = {};
  for (uint32_t index = 0; index < ProdigyBulkTransfer::maximumQueuedTransfers; ++index)
  {
    suite.expect(sender.queue(makeMessage(uint16_t(110 + index), 1), &failure), "bulk_outbound_queue_accepts_within_count_limit");
  }
  suite.expect(sender.queue(makeMessage(200, 1), &failure) == false, "bulk_outbound_queue_rejects_count_limit");
}

int main()
{
  TestSuite suite = {};
  testLargeFragmentedRoundTrip(suite);
  testControlsDrainBetweenChunks(suite);
  testConsumedSendBufferDoesNotAccumulateChunks(suite);
  testInvalidInboundSequences(suite);
  testResetAndReplayFence(suite);
  testOutboundLimits(suite);
  if (suite.failed == 0)
  {
    basics_log("PASS: prodigy_transport_bulk_unit\n");
    return 0;
  }
  basics_log("FAIL: prodigy_transport_bulk_unit failed=%d\n", suite.failed);
  return 1;
}
