#pragma once

#include <prodigy/transport.bulk.h>
#include <prodigy/transport.tls.h>
#include <networking/multiplexer.h>
#include <networking/ring.h>

// Artifact transfer shares the authenticated stream and its socket generation.
// Only explicitly queued artifact messages use this lane; ordinary control
// messages keep their existing write-buffer order.
class ProdigyArtifactStream : public ProdigyTransportTLSStream {
public:
  ProdigyBulkTransfer artifacts;
  bool artifactChunksEnabled = false;

  bool queueArtifactMessage(String&& frame, String *failure = nullptr)
  {
    if (artifactChunksEnabled == false)
    {
      if (!wBuffer.need(frame.size()))
      {
        if (failure) failure->assign("legacy artifact buffer allocation failed"_ctv);
        return false;
      }
      wBuffer.append(frame);
      return true;
    }
    return artifacts.queue(std::move(frame), failure);
  }

  void prepareNextArtifactChunk(void)
  {
    // Do not add another artifact chunk behind ciphertext already in flight.
    // Control messages can still append to wBuffer while that send completes.
    if (hasBufferedTransportCiphertext() == false)
    {
      String failure;
      (void)artifacts.appendNextChunk(wBuffer, &failure);
      if (!failure.empty())
      {
        std::fprintf(stderr, "artifact fragment send failed: %s\n", failure.c_str());
        // Ring normalizes the base pointer to the owning socket identity.
        // Reconnect replays the existing operation; do not silently leave a
        // transfer queued with no send completion capable of advancing it.
        if ((isFixedFile && fslot >= 0) || (!isFixedFile && fd >= 0)) Ring::queueClose(this);
      }
    }
  }

  uint32_t nBytesToSend(void) override
  {
    prepareNextArtifactChunk();
    return ProdigyTransportTLSStream::nBytesToSend();
  }

  void clearQueuedSendBytes(void) override
  {
    artifacts.reset();
    ProdigyTransportTLSStream::clearQueuedSendBytes();
  }

  void reset(void) override
  {
    artifacts.reset();
    artifactChunksEnabled = false;
    ProdigyTransportTLSStream::reset();
  }
};
