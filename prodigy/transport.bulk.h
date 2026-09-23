// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <prodigy/wire.h>

#include <networking/stream.h>
#include <types/types.containers.h>

#include <cstring>
#include <algorithm>
#include <limits>
#include <utility>

// Fragment opaque artifact frames on the already-authenticated control stream.
// Existing control frames retain FIFO ordering: a fragment is appended only to
// an empty write buffer, so queued control frames drain before the next chunk.
class ProdigyBulkTransfer {
public:
  static constexpr uint16_t fragmentTopic = uint16_t(65534);
  // Payload bytes only; the enclosing Message header and alignment add overhead.
  static constexpr uint32_t maximumFragmentBytes = 64u * 1024u;
  static constexpr uint32_t maximumQueuedTransfers = 16;
  static constexpr uint64_t maximumQueuedBytes = 512ull * 1024ull * 1024ull;

  enum class ConsumeResult : uint8_t {
    notFragment,
    incomplete,
    complete,
    invalid
  };

private:
  struct Outbound {
    uint64_t transferID = 0;
    uint32_t offset = 0;
    String frame = {};
  };

  Vector<Outbound> outbound = {};
  uint64_t queuedOutboundBytes = 0;
  uint64_t nextOutboundTransferID = 1;

  uint64_t incomingTransferID = 0;
  uint64_t lastCompletedIncomingTransferID = 0;
  uint32_t incomingTotal = 0;
  uint32_t incomingOffset = 0;
  String incomingFrame = {};

  static void setFailure(String *failure, const char *reason)
  {
    if (failure)
    {
      failure->assign(reason);
    }
  }

  static bool alignCursor(const uint8_t *&cursor, const uint8_t *terminal, uintptr_t alignment)
  {
    const uintptr_t value = reinterpret_cast<uintptr_t>(cursor);
    if (value > (std::numeric_limits<uintptr_t>::max() - (alignment - 1)))
    {
      return false;
    }
    const uintptr_t aligned = (value + alignment - 1) & ~(alignment - 1);
    cursor = reinterpret_cast<const uint8_t *>(aligned);
    return cursor <= terminal;
  }

  template <typename T>
  static bool readFixed(const uint8_t *&cursor, const uint8_t *terminal, T& value)
  {
    if (alignCursor(cursor, terminal, alignof(T)) == false ||
        uint64_t(terminal - cursor) < sizeof(T))
    {
      return false;
    }
    memcpy(&value, cursor, sizeof(T));
    cursor += sizeof(T);
    return true;
  }

  static bool readVariable(const uint8_t *&cursor, const uint8_t *terminal, const uint8_t *&bytes, uint32_t& bytesCount)
  {
    if (readFixed(cursor, terminal, bytesCount) == false ||
        alignCursor(cursor, terminal, uintptr_t(Alignment::eight)) == false ||
        uint64_t(terminal - cursor) < bytesCount)
    {
      return false;
    }
    bytes = cursor;
    cursor += bytesCount;
    return cursor == terminal;
  }

  static uint64_t alignOffset(uint64_t offset, uint64_t alignment)
  {
    return (offset + alignment - 1) & ~(alignment - 1);
  }

  static uint64_t fragmentFrameBytes(uint64_t offset, uint32_t payloadBytes)
  {
    offset = alignOffset(offset, alignof(uint32_t));
    offset += sizeof(uint32_t);
    offset = alignOffset(offset, alignof(uint16_t));
    offset += sizeof(uint16_t);
    offset += sizeof(uint8_t) * 2;
    offset = alignOffset(offset, alignof(uint64_t));
    offset += sizeof(uint64_t);
    offset = alignOffset(offset, alignof(uint32_t));
    offset += sizeof(uint32_t) * 2;
    offset = alignOffset(offset, alignof(uint32_t));
    offset += sizeof(uint32_t);
    offset = alignOffset(offset, uintptr_t(Alignment::eight));
    offset += payloadBytes;
    return alignOffset(offset, uintptr_t(Alignment::sixteen));
  }

  static bool validateMessageFraming(const uint8_t *bytes, uint32_t bytesCount, String *failure)
  {
    if (bytes == nullptr || bytesCount < 16 || bytesCount > ProdigyWire::maxControlFrameBytes)
    {
      setFailure(failure, "bulk Message frame size is invalid");
      return false;
    }

    // Keep the existing Stream parser as the single source of Message framing
    // rules. A view avoids copying an artifact-sized message.
    Stream parser = {};
    parser.rBuffer.setInvariant(bytes, bytesCount, bytesCount);
    bool parseFailed = false;
    uint32_t parsed = 0;
    uint32_t parsedBytes = 0;
    parser.extractMessages<Message>([&](Message *message) -> void {
      parsed += 1;
      parsedBytes = message->size;
    },
                                   false,
                                   1,
                                   16,
                                   ProdigyWire::maxControlFrameBytes,
                                   parseFailed);
    if (parseFailed || parsed != 1 || parsedBytes != bytesCount)
    {
      setFailure(failure, "bulk Message framing is invalid");
      return false;
    }
    return true;
  }

  static bool validateCompleteMessage(const String& frame, String *failure)
  {
    if (frame.size() > ProdigyWire::maxControlFrameBytes)
    {
      setFailure(failure, "bulk complete frame size is invalid");
      return false;
    }
    if (validateMessageFraming(frame.data(), uint32_t(frame.size()), failure) == false)
    {
      return false;
    }
    const Message *message = reinterpret_cast<const Message *>(frame.data());
    if (message->topic == fragmentTopic)
    {
      setFailure(failure, "bulk complete frame may not nest a bulk fragment");
      return false;
    }
    return true;
  }

  void clearIncoming(void)
  {
    incomingTransferID = 0;
    incomingTotal = 0;
    incomingOffset = 0;
    incomingFrame.reset();
  }

  ConsumeResult invalid(String *failure, const char *reason)
  {
    clearIncoming();
    setFailure(failure, reason);
    return ConsumeResult::invalid;
  }

public:
  void reset(void)
  {
    outbound.clear();
    queuedOutboundBytes = 0;
    nextOutboundTransferID = 1;
    lastCompletedIncomingTransferID = 0;
    clearIncoming();
  }

  uint64_t queuedBytes(void) const
  {
    return queuedOutboundBytes;
  }

  uint32_t queuedTransfers(void) const
  {
    return uint32_t(outbound.size());
  }

  uint64_t pendingOutboundBytes(void) const
  {
    return queuedOutboundBytes;
  }

  bool hasOutbound(void) const
  {
    return outbound.empty() == false;
  }

  uint64_t pendingIncomingReservedBytes(void) const
  {
    return incomingFrame.reservedBytes();
  }

  bool queue(String&& completeMessage, String *failure = nullptr)
  {
    if (failure)
    {
      failure->clear();
    }
    if (validateCompleteMessage(completeMessage, failure) == false)
    {
      return false;
    }
    if (outbound.size() >= maximumQueuedTransfers)
    {
      setFailure(failure, "bulk outbound transfer queue is full");
      return false;
    }
    if (completeMessage.size() > (maximumQueuedBytes - queuedOutboundBytes))
    {
      setFailure(failure, "bulk outbound transfer bytes exceed limit");
      return false;
    }
    if (nextOutboundTransferID == 0)
    {
      setFailure(failure, "bulk outbound transfer id exhausted");
      return false;
    }

    Outbound transfer = {};
    transfer.transferID = nextOutboundTransferID++;
    transfer.frame = std::move(completeMessage);
    queuedOutboundBytes += transfer.frame.size();
    outbound.emplace_back(std::move(transfer));
    return true;
  }

  // Returns true only when a fragment was appended. A non-empty stream buffer
  // is normal control backpressure, not an error.
  bool appendNextChunk(StreamBuffer& wBuffer, String *failure = nullptr)
  {
    if (failure)
    {
      failure->clear();
    }
    if (wBuffer.outstandingBytes() != 0 || outbound.empty())
    {
      return false;
    }

    // sendHandler consumes with zeroIfConsumed=false. Its completed frame has
    // no outstanding bytes but must not become the prefix of the next chunk.
    // Clear that consumed logical frame before reserving/appending so a long
    // transfer retains one fragment-sized send buffer rather than every tail.
    wBuffer.clear();

    Outbound& transfer = outbound.front();
    const uint32_t total = uint32_t(transfer.frame.size());
    if (transfer.transferID == 0 || total == 0 || transfer.offset >= total)
    {
      setFailure(failure, "bulk outbound transfer state is invalid");
      return false;
    }
    const uint32_t chunkBytes = std::min<uint32_t>(maximumFragmentBytes, total - transfer.offset);
    const uint64_t before = wBuffer.size();
    const uint64_t required = fragmentFrameBytes(before, chunkBytes);
    if (required < before || wBuffer.reserve(required) == false)
    {
      setFailure(failure, "bulk fragment buffer allocation failed");
      return false;
    }
    uint32_t headerOffset = Message::appendHeader(wBuffer, fragmentTopic);
    Message::append(wBuffer, transfer.transferID);
    Message::append(wBuffer, total);
    Message::append(wBuffer, transfer.offset);
    Message::appendValue(wBuffer, transfer.frame.data() + transfer.offset, chunkBytes);
    Message::finish(wBuffer, headerOffset);
    if (wBuffer.size() != required)
    {
      wBuffer.clear();
      setFailure(failure, "bulk fragment buffer allocation failed");
      return false;
    }

    transfer.offset += chunkBytes;
    if (transfer.offset == total)
    {
      queuedOutboundBytes -= transfer.frame.size();
      outbound.erase(outbound.begin());
    }
    return true;
  }

  template <typename Callback>
  ConsumeResult consume(Message *message, Callback&& completeMessage, String *failure = nullptr)
  {
    if (failure)
    {
      failure->clear();
    }
    if (message == nullptr || message->topic != fragmentTopic)
    {
      return ConsumeResult::notFragment;
    }
    if (message->size < 16 || message->size > ProdigyWire::maxControlFrameBytes ||
        validateMessageFraming(reinterpret_cast<const uint8_t *>(message), message->size, failure) == false)
    {
      return invalid(failure, "bulk fragment Message framing is invalid");
    }

    const uint8_t *cursor = message->args;
    const uint8_t *terminal = reinterpret_cast<const uint8_t *>(message) + message->size - message->padding;
    uint64_t transferID = 0;
    uint32_t total = 0;
    uint32_t offset = 0;
    const uint8_t *bytes = nullptr;
    uint32_t bytesCount = 0;
    if (cursor > terminal ||
        readFixed(cursor, terminal, transferID) == false ||
        readFixed(cursor, terminal, total) == false ||
        readFixed(cursor, terminal, offset) == false ||
        readVariable(cursor, terminal, bytes, bytesCount) == false)
    {
      return invalid(failure, "bulk fragment arguments are invalid");
    }
    if (transferID == 0 || total < 16 || total > ProdigyWire::maxControlFrameBytes ||
        bytesCount == 0 || bytesCount > maximumFragmentBytes || offset >= total ||
        bytesCount > (total - offset))
    {
      return invalid(failure, "bulk fragment bounds are invalid");
    }

    if (incomingTransferID == 0)
    {
      const uint32_t initialCapacity = std::min<uint32_t>(total, maximumFragmentBytes);
      if (transferID <= lastCompletedIncomingTransferID || offset != 0 || incomingFrame.reserve(initialCapacity) == false)
      {
        return invalid(failure, "bulk fragment starts an invalid or replayed transfer");
      }
      incomingTransferID = transferID;
      incomingTotal = total;
      incomingOffset = 0;
    }
    else if (transferID != incomingTransferID || total != incomingTotal || offset != incomingOffset)
    {
      return invalid(failure, "bulk fragment is out of order or overlaps a transfer");
    }

    if (incomingFrame.need(bytesCount) == false)
    {
      return invalid(failure, "bulk fragment allocation failed");
    }
    incomingFrame.append(bytes, bytesCount);
    incomingOffset += bytesCount;
    if (incomingOffset < incomingTotal)
    {
      return ConsumeResult::incomplete;
    }
    if (incomingOffset != incomingTotal || validateCompleteMessage(incomingFrame, failure) == false)
    {
      clearIncoming();
      return ConsumeResult::invalid;
    }

    lastCompletedIncomingTransferID = incomingTransferID;
    String completed = std::move(incomingFrame);
    incomingTransferID = 0;
    incomingTotal = 0;
    incomingOffset = 0;
    std::forward<Callback>(completeMessage)(std::move(completed));
    return ConsumeResult::complete;
  }
};
