#pragma once

// Shared canonical byte primitives for pair derivation and control records.
// Keep durable public records independent of service routing and key owners.
#include <cstdint>
#include <types/types.containers.h>

static inline void clusterPairKeyAppendU64BE(String& bytes, uint64_t value)
{
  for (int shift = 56; shift >= 0; shift -= 8) bytes.append(uint8_t(value >> shift));
}

static inline void clusterPairKeyAppendU128BE(String& bytes, uint128_t value)
{
  for (int shift = 120; shift >= 0; shift -= 8) bytes.append(uint8_t(value >> shift));
}

static inline void clusterPairControlAppendU16BE(String& output, uint16_t value)
{
  output.append(uint8_t(value >> 8));
  output.append(uint8_t(value));
}

static inline void clusterPairControlAppendU32BE(String& output, uint32_t value)
{
  for (int shift = 24; shift >= 0; shift -= 8) output.append(uint8_t(value >> shift));
}

static inline bool clusterPairControlReadU16BE(const uint8_t *&cursor, const uint8_t *terminal, uint16_t& value)
{
  if (cursor == nullptr || terminal - cursor < 2) return false;
  value = uint16_t(uint16_t(cursor[0]) << 8 | cursor[1]); cursor += 2; return true;
}

static inline bool clusterPairControlReadU32BE(const uint8_t *&cursor, const uint8_t *terminal, uint32_t& value)
{
  if (cursor == nullptr || terminal - cursor < 4) return false;
  value = 0; for (uint32_t index = 0; index < 4; ++index) value = (value << 8) | cursor[index]; cursor += 4; return true;
}

static inline bool clusterPairControlReadU64BE(const uint8_t *&cursor, const uint8_t *terminal, uint64_t& value)
{
  if (cursor == nullptr || terminal - cursor < 8) return false;
  value = 0; for (uint32_t index = 0; index < 8; ++index) value = (value << 8) | cursor[index]; cursor += 8; return true;
}

static inline bool clusterPairControlReadU128BE(const uint8_t *&cursor, const uint8_t *terminal, uint128_t& value)
{
  if (cursor == nullptr || terminal - cursor < 16) return false;
  value = 0; for (uint32_t index = 0; index < 16; ++index) value = (value << 8) | cursor[index]; cursor += 16; return true;
}
