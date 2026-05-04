#pragma once

#include <cstddef>
#include <cstring>
#include <limits>

#include <services/memfd.h>

enum class MemfdBlobKind : uint16_t {
   neuronState = 1,
   brainPlans = 2
};

struct MemfdBlobHeader {
   uint32_t magic;      // 'PROD'
   uint16_t kind;       // MemfdBlobKind
   uint16_t reserved;   // 0
   uint64_t version;    // ProdigyBinaryVersion
   uint32_t size;       // payload size in bytes (following this header)
};

static bool writeMemfdBlobWithHeader(int fd, MemfdBlobKind kind, uint64_t version, const String& payload)
{
   if (payload.size() > std::numeric_limits<uint32_t>::max())
   {
      return false;
   }

   MemfdBlobHeader header = {};
   header.magic = 0x504F5244; // 'PROD'
   header.kind = static_cast<uint16_t>(kind);
   header.version = version;
   header.size = static_cast<uint32_t>(payload.size());

   String blob;
   if (blob.reserve(sizeof(MemfdBlobHeader) + payload.size()) == false)
   {
      return false;
   }

   blob.append(reinterpret_cast<const uint8_t *>(&header), sizeof(MemfdBlobHeader));
   blob.append(payload.data(), payload.size());
   return Memfd::writeAll(fd, blob);
}

static bool parseMemfdBlob(const String& blob, MemfdBlobHeader& header, const uint8_t *&payload, size_t& payloadSize)
{
   if (blob.size() < sizeof(MemfdBlobHeader))
   {
      return false;
   }

   memcpy(&header, blob.data(), sizeof(MemfdBlobHeader));
   if (header.magic != 0x504F5244)
   {
      return false;
   }

   size_t payloadOffset = sizeof(MemfdBlobHeader);
   if (size_t(header.size) > (blob.size() - payloadOffset))
   {
      return false;
   }

   payload = blob.data() + payloadOffset;
   payloadSize = header.size;
   return true;
}
