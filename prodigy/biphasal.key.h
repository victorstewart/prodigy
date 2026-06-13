#pragma once

#include <cstdint>

static inline uint8_t prodigyBiphasalKeyPhase(const uint8_t *key)
{
  return (key[0] >> 7) & 0x01;
}

static inline void prodigyForceBiphasalKeyPhase(uint8_t *key, uint8_t phase)
{
  key[0] = uint8_t((key[0] & 0x7fu) | ((phase & 0x01u) << 7));
}
