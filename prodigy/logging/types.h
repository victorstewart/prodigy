#pragma once

#include <base/includes.h>

namespace Prodigy {
namespace Logs {

enum class Stream : uint8_t { stdoutStream = 0, stderrStream = 1 };

struct LogPullRequest {
    uint128_t containerUUID;
    uint16_t appID;
    Stream which;           // stdout or stderr
    uint64_t fromOffset;    // absolute file offset to start at (0 for beginning)
    uint32_t tailBytes;     // if > 0 and fromOffset==0, send last N bytes then follow
    bool follow;            // if true, stream new bytes as appended
};

struct LogStreamFrame {
    uint128_t containerUUID;
    Stream which;
    uint64_t offset;        // file offset of first byte in payload
    uint32_t sequence;      // monotonically increasing frame id
    String payload;         // log bytes
};

} // namespace Logs
} // namespace Prodigy

