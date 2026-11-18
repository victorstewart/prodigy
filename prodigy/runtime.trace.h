#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <services/time.h>

inline bool prodigyRuntimeTraceEnabled()
{
  static const bool enabled = [] {
    const char *value = std::getenv("PRODIGY_RUNTIME_TRACE");
    return value && value[0] == '1' && value[1] == '\0';
  }();
  return enabled;
}

inline void prodigyTraceContainerStage(const char *stage, uint64_t deploymentID, __uint128_t uuid)
{
  if (!prodigyRuntimeTraceEnabled()) return;
  std::fprintf(stderr,
      "prodigy.container.stage stage=%s deploymentID=%llu uuid=%016llx%016llx monotonicMs=%lld wallMs=%lld\n",
      stage, (unsigned long long)deploymentID, (unsigned long long)(uuid >> 64),
      (unsigned long long)uuid, (long long)Time::msSinceBoot(), (long long)Time::now<TimeResolution::ms>());
}

inline void prodigyTraceMachineStage(const char *stage, __uint128_t uuid, uint64_t generation = 0)
{
  if (!prodigyRuntimeTraceEnabled()) return;
  std::fprintf(stderr,
      "prodigy.machine.stage stage=%s uuid=%016llx%016llx generation=%llu monotonicMs=%lld wallMs=%lld\n",
      stage, (unsigned long long)(uuid >> 64), (unsigned long long)uuid, (unsigned long long)generation,
      (long long)Time::msSinceBoot(), (long long)Time::now<TimeResolution::ms>());
}
