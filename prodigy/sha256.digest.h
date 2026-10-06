#pragma once

#include <cstdint>
#include <networking/includes.h>

static inline bool prodigyIsSHA256HexDigest(const String& digest)
{
  if (digest.size() != 64)
  {
    return false;
  }

  for (uint64_t index = 0; index < digest.size(); ++index)
  {
    unsigned char ch = static_cast<unsigned char>(digest[index]);
    bool isDigit = (ch >= '0' && ch <= '9');
    bool isLowerHex = (ch >= 'a' && ch <= 'f');
    if (isDigit == false && isLowerHex == false)
    {
      return false;
    }
  }

  return true;
}

