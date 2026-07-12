#pragma once

#include <networking/includes.h>
#include <prodigy/types.h>
#include <services/prodigy.h>

#include <openssl/crypto.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ProdigyDns
{

constexpr static char controlBootstrapMagic[] = "PDNSCTL1";
constexpr static uint32_t controlBootstrapVersion = 1;
constexpr static size_t controlBootstrapBytes = 87;
constexpr static char defaultProdigyControlBootstrapPath[] =
    "/etc/prodigy/dns-control.prodigy.bootstrap";
constexpr static char defaultMothershipControlBootstrapPath[] =
    "/etc/prodigy/dns-control.mothership.bootstrap";

inline const char *controlBootstrapPath(ProdigyDnsControlClientRole role)
{
   return role == ProdigyDnsControlClientRole::mothership
              ? defaultMothershipControlBootstrapPath
              : defaultProdigyControlBootstrapPath;
}

inline bool validControlBootstrapMetadata(const struct stat& metadata)
{
   return S_ISREG(metadata.st_mode) && metadata.st_uid == 0 &&
          (metadata.st_mode & 0777) == 0600;
}

class ControlBootstrap
{
public:

   IPAddress endpoint;
   uint16_t port = 0;
   uint64_t service = 0;
   uint128_t secret = 0;
   uint128_t leaseID = 0;
   uint64_t generation = 0;
   int64_t expiresAtMs = 0;
   ProdigyDnsControlClientRole role = ProdigyDnsControlClientRole::prodigy;

   bool valid(int64_t nowMs,
              String *failure = nullptr,
              const ProdigyDnsControlClientRole *expectedRole = nullptr) const
   {
      auto fail = [&](const auto& message) -> bool {
         if (failure)
         {
            failure->assign(message);
         }
         return false;
      };

      if (endpoint.is6 == false || endpoint.isNull())
      {
         return fail("DNS control endpoint must be a literal nonzero IPv6 address"_ctv);
      }
      if (port == 0)
      {
         return fail("DNS control endpoint port must be nonzero"_ctv);
      }
      if (service != MeshRegistry::DNS::resolver)
      {
         return fail("DNS control service identity is invalid"_ctv);
      }
      if (secret == 0 || leaseID == 0 || generation == 0)
      {
         return fail("DNS control pairing lease is incomplete"_ctv);
      }
      if (expiresAtMs <= nowMs)
      {
         return fail("DNS control pairing lease is expired"_ctv);
      }
      if ((role != ProdigyDnsControlClientRole::prodigy &&
           role != ProdigyDnsControlClientRole::mothership) ||
          (expectedRole && role != *expectedRole))
      {
         return fail("DNS control pairing lease role is invalid"_ctv);
      }

      if (failure)
      {
         failure->clear();
      }
      return true;
   }
};

inline void appendLittleEndian(String& bytes, uint64_t value, size_t width)
{
   for (size_t index = 0; index < width; index += 1)
   {
      bytes.append(uint8_t(value >> (index * 8)));
   }
}

inline bool readLittleEndian(const uint8_t *&cursor,
                             const uint8_t *terminal,
                             uint64_t& value,
                             size_t width)
{
   if (size_t(terminal - cursor) < width)
   {
      return false;
   }

   value = 0;
   for (size_t index = 0; index < width; index += 1)
   {
      value |= uint64_t(cursor[index]) << (index * 8);
   }
   cursor += width;
   return true;
}

inline void encodeControlBootstrap(const ControlBootstrap& config, String& bytes)
{
   bytes.clear();
   bytes.reserve(controlBootstrapBytes);
   bytes.append(reinterpret_cast<const uint8_t *>(controlBootstrapMagic),
                sizeof(controlBootstrapMagic) - 1);
   appendLittleEndian(bytes, controlBootstrapVersion, sizeof(uint32_t));
   bytes.append(config.endpoint.v6, sizeof(config.endpoint.v6));
   appendLittleEndian(bytes, config.port, sizeof(config.port));
   appendLittleEndian(bytes, config.service, sizeof(config.service));
   bytes.append(reinterpret_cast<const uint8_t *>(&config.secret),
                sizeof(config.secret));
   bytes.append(reinterpret_cast<const uint8_t *>(&config.leaseID),
                sizeof(config.leaseID));
   appendLittleEndian(bytes, config.generation, sizeof(config.generation));
   appendLittleEndian(bytes, uint64_t(config.expiresAtMs),
                      sizeof(config.expiresAtMs));
   bytes.append(uint8_t(config.role));
}

inline bool decodeControlBootstrap(const String& bytes,
                                   ControlBootstrap& config,
                                   int64_t nowMs,
                                   String *failure = nullptr)
{
   auto fail = [&](const auto& message) -> bool {
      config = {};
      if (failure)
      {
         failure->assign(message);
      }
      return false;
   };

   if (bytes.size() != controlBootstrapBytes)
   {
      return fail("DNS control bootstrap state has invalid size"_ctv);
   }

   const uint8_t *cursor = bytes.data();
   const uint8_t *terminal = cursor + bytes.size();
   if (std::memcmp(cursor, controlBootstrapMagic,
                   sizeof(controlBootstrapMagic) - 1) != 0)
   {
      return fail("DNS control bootstrap state has invalid magic"_ctv);
   }
   cursor += sizeof(controlBootstrapMagic) - 1;

   uint64_t value = 0;
   if (readLittleEndian(cursor, terminal, value, sizeof(uint32_t)) == false ||
       value != controlBootstrapVersion)
   {
      return fail("DNS control bootstrap state has unsupported version"_ctv);
   }

   config.endpoint = {};
   config.endpoint.is6 = true;
   std::memcpy(config.endpoint.v6, cursor, sizeof(config.endpoint.v6));
   cursor += sizeof(config.endpoint.v6);
   if (readLittleEndian(cursor, terminal, value, sizeof(config.port)) == false)
   {
      return fail("DNS control bootstrap state is truncated"_ctv);
   }
   config.port = uint16_t(value);
   if (readLittleEndian(cursor, terminal, config.service,
                        sizeof(config.service)) == false)
   {
      return fail("DNS control bootstrap state is truncated"_ctv);
   }
   std::memcpy(&config.secret, cursor, sizeof(config.secret));
   cursor += sizeof(config.secret);
   std::memcpy(&config.leaseID, cursor, sizeof(config.leaseID));
   cursor += sizeof(config.leaseID);
   if (readLittleEndian(cursor, terminal, config.generation,
                        sizeof(config.generation)) == false ||
       readLittleEndian(cursor, terminal, value,
                        sizeof(config.expiresAtMs)) == false)
   {
      return fail("DNS control bootstrap state is truncated"_ctv);
   }
   config.expiresAtMs = int64_t(value);
   if (cursor == terminal)
   {
      return fail("DNS control bootstrap state is truncated"_ctv);
   }
   config.role = ProdigyDnsControlClientRole(*cursor++);
   if (cursor != terminal)
   {
      return fail("DNS control bootstrap state has invalid size"_ctv);
   }
   return config.valid(nowMs, failure);
}

inline bool readControlBootstrap(String path,
                                 ControlBootstrap& config,
                                 int64_t nowMs,
                                 String *failure = nullptr)
{
   auto fail = [&](const auto& message) -> bool {
      config = {};
      if (failure)
      {
         failure->assign(message);
      }
      return false;
   };

   const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
   if (fd < 0)
   {
      if (failure)
      {
         failure->snprintf<"cannot open DNS control bootstrap state: {}"_ctv>(
             String(std::strerror(errno)));
      }
      return false;
   }

   struct stat metadata = {};
   if (::fstat(fd, &metadata) != 0 ||
       validControlBootstrapMetadata(metadata) == false)
   {
      ::close(fd);
      return fail("DNS control bootstrap state must be a root-owned 0600 regular file"_ctv);
   }

   String bytes;
   bytes.resize(controlBootstrapBytes);
   auto scrub = [&]() {
      if (bytes.reservedBytes() > 0)
      {
         OPENSSL_cleanse(bytes.data(), bytes.reservedBytes());
      }
      bytes.clear();
   };
   size_t offset = 0;
   while (offset < bytes.size())
   {
      const ssize_t count = ::read(fd, bytes.data() + offset,
                                   bytes.size() - offset);
      if (count < 0 && errno == EINTR)
      {
         continue;
      }
      if (count <= 0)
      {
         ::close(fd);
         scrub();
         return fail("DNS control bootstrap state is truncated"_ctv);
      }
      offset += size_t(count);
   }
   uint8_t extra = 0;
   const ssize_t extraBytes = ::read(fd, &extra, sizeof(extra));
   const int closeResult = ::close(fd);
   if (extraBytes != 0 || closeResult != 0)
   {
      scrub();
      return fail("DNS control bootstrap state has invalid size"_ctv);
   }

   const bool decoded = decodeControlBootstrap(bytes, config, nowMs, failure);
   scrub();
   return decoded;
}

} // namespace ProdigyDns
