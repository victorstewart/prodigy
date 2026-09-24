#pragma once

#include <array>
#include <cerrno>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

#include <bpf/bpf.h>
#include <unistd.h>

#include <switchboard/common/structs.h>
#include <prodigy/artifact.io.h>
#include <switchboard/common/constants.h>
#include <switchboard/maglevhashv2.h>

// The worker receives this value-only snapshot. It must never retain a Portal,
// Switchboard, or BPFProgram pointer: Ring owns generation fencing and the
// map-of-maps publication after the prepared result returns.
class SwitchboardMaglevRingPrepareRequest {
public:
  uint64_t generation = 0;
  uint8_t datacenterPrefix = 0;
  std::vector<MaglevHashV2::Endpoint> endpoints = {};
};

class SwitchboardMaglevMapBackend {
public:
  std::function<int()> createInnerMap = {};
  std::function<bool(int, uint32_t, const container_id&)> updateInnerMap = {};
  std::function<void(int)> closeInnerMap = {};

  bool valid(void) const
  {
    return createInnerMap != nullptr && updateInnerMap != nullptr && closeInnerMap != nullptr;
  }
};

static inline SwitchboardMaglevMapBackend switchboardDefaultMaglevMapBackend(void)
{
  SwitchboardMaglevMapBackend backend = {};
  backend.createInnerMap = []() -> int {
    return bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(container_id), RING_SIZE, nullptr);
  };
  backend.updateInnerMap = [](int fd, uint32_t index, const container_id& entry) -> bool {
    return bpf_map_update_elem(fd, &index, &entry, BPF_ANY) == 0;
  };
  backend.closeInnerMap = [](int fd) {
    if (fd >= 0) ::close(fd);
  };
  return backend;
}

class SwitchboardMaglevRingPrepareResult {
public:
  enum class Error : uint8_t {
    none,
    invalidRequest,
    createInnerMap,
    updateInnerMap,
  };

  uint64_t generation = 0;
  std::array<uint32_t, RING_SIZE> ring = {};
  int innerMapFD = -1;
  Error error = Error::invalidRequest;
  // The worker captures the kernel failure for the Ring owner to log with its
  // portal/generation context. Fake backends may leave this at zero.
  int errorNumber = 0;

private:
  std::function<void(int)> closeInnerMap = {};

public:
  SwitchboardMaglevRingPrepareResult() { ring.fill(0); }
  SwitchboardMaglevRingPrepareResult(const SwitchboardMaglevRingPrepareResult&) = delete;
  SwitchboardMaglevRingPrepareResult& operator=(const SwitchboardMaglevRingPrepareResult&) = delete;

  SwitchboardMaglevRingPrepareResult(SwitchboardMaglevRingPrepareResult&& other) noexcept
      : generation(other.generation), ring(std::move(other.ring)), innerMapFD(other.innerMapFD),
        error(other.error), errorNumber(other.errorNumber), closeInnerMap(std::move(other.closeInnerMap))
  {
    other.innerMapFD = -1;
  }

  SwitchboardMaglevRingPrepareResult& operator=(SwitchboardMaglevRingPrepareResult&& other) noexcept
  {
    if (this != &other)
    {
      reset();
      generation = other.generation;
      ring = std::move(other.ring);
      innerMapFD = other.innerMapFD;
      error = other.error;
      errorNumber = other.errorNumber;
      closeInnerMap = std::move(other.closeInnerMap);
      other.innerMapFD = -1;
    }
    return *this;
  }

  ~SwitchboardMaglevRingPrepareResult() { reset(); }

  bool prepared(void) const { return error == Error::none && innerMapFD >= 0; }

  void reset(void)
  {
    if (innerMapFD >= 0 && closeInnerMap != nullptr) closeInnerMap(innerMapFD);
    innerMapFD = -1;
  }

  void adoptInnerMap(int fd, std::function<void(int)> close)
  {
    innerMapFD = fd;
    closeInnerMap = std::move(close);
  }
};

static inline uint64_t switchboardMaglevRingPrepareKernelMapBytes(void)
{
  // ARRAY values are rounded by the kernel to their natural eight-byte slot.
  constexpr uint64_t roundedValueBytes = (sizeof(container_id) + 7ULL) & ~7ULL;
  return uint64_t(RING_SIZE) * roundedValueBytes;
}

static inline uint64_t switchboardMaglevRingPrepareRetainedBytes(
    const std::vector<SwitchboardMaglevRingPrepareRequest>& requests)
{
  uint64_t bytes = 0;
  for (const SwitchboardMaglevRingPrepareRequest& request : requests)
  {
    if (request.endpoints.size() > MAX_CONTAINERS_PER_PORTAL) return ProdigyArtifactIO::maximumBytes + 1;

    // The value snapshot retains its endpoints. Maglev then allocates a
    // permutation, next, and cumulative-weight scratch vector. The result
    // retains the userspace ring while its inner ARRAY map retains every
    // translated container_id in the kernel.
    const uint64_t endpointBytes = uint64_t(request.endpoints.size()) * sizeof(MaglevHashV2::Endpoint);
    const uint64_t scratchBytes = uint64_t(request.endpoints.size()) *
        (sizeof(uint32_t) * 3ULL + sizeof(uint64_t));
    const uint64_t requestBytes = endpointBytes + scratchBytes +
        sizeof(SwitchboardMaglevRingPrepareResult) + switchboardMaglevRingPrepareKernelMapBytes();
    if (endpointBytes / sizeof(MaglevHashV2::Endpoint) != request.endpoints.size() ||
        requestBytes < endpointBytes || requestBytes > ProdigyArtifactIO::maximumBytes ||
        bytes > ProdigyArtifactIO::maximumBytes - requestBytes)
    {
      return ProdigyArtifactIO::maximumBytes + 1;
    }
    bytes += requestBytes;
  }
  return bytes;
}

static inline container_id switchboardMaglevRingContainerID(uint8_t datacenterPrefix, uint32_t containerKey)
{
  container_id entry = {};
  if (containerKey != 0)
  {
    entry.hasID = true;
    entry.value[0] = datacenterPrefix;
    entry.value[1] = static_cast<uint8_t>((containerKey >> 16) & 0xff);
    entry.value[2] = static_cast<uint8_t>((containerKey >> 8) & 0xff);
    entry.value[3] = static_cast<uint8_t>(containerKey & 0xff);
    entry.value[4] = static_cast<uint8_t>((containerKey >> 24) & 0xff);
  }
  return entry;
}

// Executes entirely on the ArtifactIO worker from value snapshots. Keeping this
// body separate lets the focused test compile the exact production path inline.
static inline std::vector<SwitchboardMaglevRingPrepareResult> switchboardPrepareMaglevRingsWorker(
    const std::vector<SwitchboardMaglevRingPrepareRequest>& requests,
    const SwitchboardMaglevMapBackend& backend)
{
  std::vector<SwitchboardMaglevRingPrepareResult> results = {};
  results.reserve(requests.size());
  for (const SwitchboardMaglevRingPrepareRequest& request : requests)
  {
    SwitchboardMaglevRingPrepareResult result = {};
    result.generation = request.generation;
    if (request.generation == 0 || request.endpoints.size() > MAX_CONTAINERS_PER_PORTAL)
    {
      result.error = SwitchboardMaglevRingPrepareResult::Error::invalidRequest;
      results.push_back(std::move(result));
      continue;
    }

    result.ring = request.endpoints.empty()
        ? std::array<uint32_t, RING_SIZE> {}
        : MaglevHashV2::generateHashRingForEndpoints(request.endpoints);
    errno = 0;
    const int fd = backend.createInnerMap();
    if (fd < 0)
    {
      result.error = SwitchboardMaglevRingPrepareResult::Error::createInnerMap;
      result.errorNumber = errno;
      results.push_back(std::move(result));
      continue;
    }
    result.adoptInnerMap(fd, backend.closeInnerMap);

    bool written = true;
    for (uint32_t index = 0; index < RING_SIZE; ++index)
    {
      const container_id entry = switchboardMaglevRingContainerID(request.datacenterPrefix, result.ring[index]);
      errno = 0;
      if (backend.updateInnerMap(fd, index, entry) == false)
      {
        written = false;
        result.errorNumber = errno;
        break;
      }
    }
    if (written)
    {
      result.error = SwitchboardMaglevRingPrepareResult::Error::none;
    }
    else
    {
      result.error = SwitchboardMaglevRingPrepareResult::Error::updateInnerMap;
      result.reset();
    }
    results.push_back(std::move(result));
  }
  return results;
}

// One ArtifactIO job prepares every requested inner map. Per-map failures are
// data results, preserving the other independent maps; only executor failures
// use the batch failure callback.
static inline bool switchboardPrepareMaglevRingsAsync(
    ProdigyArtifactIO& executor,
    std::vector<SwitchboardMaglevRingPrepareRequest> requests,
    SwitchboardMaglevMapBackend backend,
    std::function<void(std::vector<SwitchboardMaglevRingPrepareResult>&&)> completion,
    std::function<void(std::exception_ptr)> failure)
{
  const uint64_t retainedBytes = switchboardMaglevRingPrepareRetainedBytes(requests);
  if (requests.empty() || requests.size() > MAX_PORTALS || backend.valid() == false ||
      completion == nullptr || failure == nullptr || retainedBytes > ProdigyArtifactIO::maximumBytes)
  {
    return false;
  }

  struct State {
    std::vector<SwitchboardMaglevRingPrepareResult> results = {};
  };
  auto state = std::make_shared<State>();
  auto work = [state, requests = std::move(requests), backend] () mutable {
    state->results = switchboardPrepareMaglevRingsWorker(requests, backend);
  };
#ifdef PRODIGY_TEST_SYNCHRONOUS_MAGLEV_PREPARE
  work();
  completion(std::move(state->results));
  return true;
#else
  return executor.submit(
      retainedBytes,
      std::move(work),
      [state, completion = std::move(completion)] () mutable {
        completion(std::move(state->results));
      },
      [failure = std::move(failure)] (std::exception_ptr exception) mutable {
        failure(exception);
      });
#endif
}
