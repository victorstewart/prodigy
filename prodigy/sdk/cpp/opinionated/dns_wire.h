// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <includes.h>
#include <types/types.containers.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace ProdigySDK::Opinionated::Dns {
inline constexpr std::uint32_t magic = 0x534e4450; // PDNS
inline constexpr std::uint16_t protocolVersion = 1;
inline constexpr std::size_t headerBytes = 16;
inline constexpr std::size_t cancelFrameBytes = 32;
inline constexpr std::size_t sessionFrameBytes = 48;
inline constexpr std::size_t maximumHostnameBytes = 253;
inline constexpr std::size_t maximumAnswers = 32;
inline constexpr std::size_t addressBytes = 16;
inline constexpr std::size_t addressRecordBytes = 24;
inline constexpr std::size_t maximumResolveFrameBytes =
    headerBytes + 28 + maximumHostnameBytes + maximumAnswers * addressRecordBytes;
inline constexpr std::uint32_t maximumDeadlineMilliseconds = 30000;

enum class Topic : std::uint8_t {
  resolve = 1,
  cancel = 2,
  session = 3,
};

enum class Family : std::uint8_t {
  any = 0,
  ipv4 = 1,
  ipv6 = 2,
};

enum class ResolveStatus : std::uint8_t {
  success = 0,
  canceled = 1,
  deadlineExceeded = 2,
  invalidHostname = 3,
  invalidService = 4,
  singleLabelRejected = 5,
  unsupportedFamily = 6,
  notFound = 7,
  noData = 8,
  tooManyAnswers = 9,
  overloaded = 10,
  backendFailure = 11,
  shutdown = 12,
};

enum class SessionPhase : std::uint8_t {
  serviceChallenge = 1,
  applicationEcho = 2,
  serviceAck = 3,
};

struct Address {
  Family family = Family::any;
  std::uint32_t ttlSeconds = 0;
  std::uint8_t bytes[addressBytes] = {};
};

// Direction defines whether this one operation payload carries a request or a
// result. Request-only and result-only fields are never serialized together.
struct Resolve {
  std::uint64_t requestID = 0;
  std::uint64_t generation = 0;
  std::uint32_t deadlineMilliseconds = 0;
  Family family = Family::any;
  String hostname;
  ResolveStatus status = ResolveStatus::backendFailure;
  String canonicalName;
  std::uint32_t canonicalNameTtlSeconds = 0;
  std::uint32_t timeouts = 0;
  Vector<Address> addresses;
};

struct Cancel {
  std::uint64_t requestID = 0;
  std::uint64_t generation = 0;
};

struct Session {
  SessionPhase phase = SessionPhase::serviceChallenge;
  std::uint16_t applicationID = 0;
  std::uint64_t service = 0;
  std::uint64_t nonce = 0;
  std::uint64_t generation = 0;
};

namespace Detail {
inline bool validTopic(Topic value)
{
  return value == Topic::resolve || value == Topic::cancel || value == Topic::session;
}

inline bool validFamily(Family value)
{
  return value == Family::any || value == Family::ipv4 || value == Family::ipv6;
}

inline bool validAddressFamily(Family value)
{
  return value == Family::ipv4 || value == Family::ipv6;
}

inline bool canonicalAddress(const Address& address)
{
  if (!validAddressFamily(address.family))
  {
    return false;
  }
  if (address.family == Family::ipv6)
  {
    return true;
  }
  for (std::size_t index = 4; index < sizeof(address.bytes); index += 1)
  {
    if (address.bytes[index] != 0)
    {
      return false;
    }
  }
  return true;
}

inline bool validStatus(ResolveStatus value)
{
  return std::uint8_t(value) <= std::uint8_t(ResolveStatus::shutdown);
}

inline bool validSessionPhase(SessionPhase value)
{
  return value == SessionPhase::serviceChallenge ||
         value == SessionPhase::applicationEcho ||
         value == SessionPhase::serviceAck;
}

inline bool validHostname(const String& hostname)
{
  if (hostname.empty() || hostname.size() > maximumHostnameBytes ||
      hostname[0] == '.' || hostname[hostname.size() - 1] == '.')
  {
    return false;
  }

  bool hasDot = false;
  std::size_t labelBegin = 0;
  for (std::size_t index = 0; index <= hostname.size(); index += 1)
  {
    if (index != hostname.size() && hostname[index] != '.')
    {
      const std::uint8_t byte = hostname[index];
      if ((byte < 'a' || byte > 'z') &&
          (byte < '0' || byte > '9') && byte != '-')
      {
        return false;
      }
      continue;
    }

    const std::size_t labelBytes = index - labelBegin;
    if (labelBytes == 0 || labelBytes > 63 ||
        hostname[labelBegin] == '-' || hostname[index - 1] == '-')
    {
      return false;
    }
    hasDot = hasDot || index != hostname.size();
    labelBegin = index + 1;
  }
  return hasDot;
}

class Writer {
private:

  std::uint8_t *cursor;
  std::uint8_t *terminal;

public:

  Writer(String& output, std::size_t size)
      : cursor(nullptr), terminal(nullptr)
  {
    output.clear();
    if (size == 0 || output.reserve(size) == false)
    {
      return;
    }
    output.resize(size);
    cursor = output.data();
    terminal = cursor + size;
    std::memset(cursor, 0, size);
  }

  bool ready(void) const
  {
    return cursor != nullptr;
  }

  bool done(void) const
  {
    return cursor != nullptr && cursor == terminal;
  }

  bool u8(std::uint8_t value)
  {
    if (cursor == nullptr || cursor == terminal)
    {
      return false;
    }
    *cursor++ = value;
    return true;
  }

  bool u16(std::uint16_t value)
  {
    return u8(std::uint8_t(value)) && u8(std::uint8_t(value >> 8));
  }

  bool u32(std::uint32_t value)
  {
    return u16(std::uint16_t(value)) && u16(std::uint16_t(value >> 16));
  }

  bool u64(std::uint64_t value)
  {
    return u32(std::uint32_t(value)) && u32(std::uint32_t(value >> 32));
  }

  bool bytes(const void *data, std::size_t size)
  {
    if (cursor == nullptr || size > std::size_t(terminal - cursor) ||
        (size != 0 && data == nullptr))
    {
      return false;
    }
    if (size != 0)
    {
      std::memcpy(cursor, data, size);
      cursor += size;
    }
    return true;
  }
};

class Reader {
private:

  const std::uint8_t *cursor;
  const std::uint8_t *terminal;

public:

  Reader(const std::uint8_t *data, std::size_t size)
      : cursor(data != nullptr && size != 0 && size <= maximumResolveFrameBytes
                   ? data
                   : nullptr),
        terminal(cursor == nullptr ? nullptr : cursor + size)
  {}

  bool ready(void) const
  {
    return cursor != nullptr && terminal != nullptr && cursor <= terminal;
  }

  bool done(void) const
  {
    return ready() && cursor == terminal;
  }

  bool u8(std::uint8_t& value)
  {
    if (!ready() || cursor == terminal)
    {
      return false;
    }
    value = *cursor++;
    return true;
  }

  bool u16(std::uint16_t& value)
  {
    std::uint8_t low = 0;
    std::uint8_t high = 0;
    if (!u8(low) || !u8(high))
    {
      return false;
    }
    value = std::uint16_t(low) | (std::uint16_t(high) << 8);
    return true;
  }

  bool u32(std::uint32_t& value)
  {
    std::uint16_t low = 0;
    std::uint16_t high = 0;
    if (!u16(low) || !u16(high))
    {
      return false;
    }
    value = std::uint32_t(low) | (std::uint32_t(high) << 16);
    return true;
  }

  bool u64(std::uint64_t& value)
  {
    std::uint32_t low = 0;
    std::uint32_t high = 0;
    if (!u32(low) || !u32(high))
    {
      return false;
    }
    value = std::uint64_t(low) | (std::uint64_t(high) << 32);
    return true;
  }

  bool bytes(void *output, std::size_t size)
  {
    if (!ready() || size > std::size_t(terminal - cursor) ||
        (size != 0 && output == nullptr))
    {
      return false;
    }
    if (size != 0)
    {
      std::memcpy(output, cursor, size);
      cursor += size;
    }
    return true;
  }

  bool string(String& output, std::size_t size)
  {
    if (!ready() || size > std::size_t(terminal - cursor))
    {
      return false;
    }
    output.assign(cursor, size);
    cursor += size;
    return true;
  }
};

inline bool header(Writer& writer, Topic topic, std::uint32_t frameBytes)
{
  return writer.u32(magic) && writer.u16(protocolVersion) &&
         writer.u8(std::uint8_t(topic)) && writer.u8(0) &&
         writer.u32(frameBytes) && writer.u32(0);
}

inline bool header(Reader& reader,
                   std::size_t availableBytes,
                   Topic expectedTopic)
{
  std::uint32_t parsedMagic = 0;
  std::uint16_t version = 0;
  std::uint8_t topic = 0;
  std::uint8_t flags = 0;
  std::uint32_t frameBytes = 0;
  std::uint32_t reserved = 0;
  return reader.u32(parsedMagic) && reader.u16(version) &&
         reader.u8(topic) && reader.u8(flags) && reader.u32(frameBytes) &&
         reader.u32(reserved) && parsedMagic == magic &&
         version == protocolVersion && Topic(topic) == expectedTopic &&
         flags == 0 && frameBytes == availableBytes && reserved == 0;
}
} // namespace Detail

inline bool frameTopic(const std::uint8_t *data,
                       std::size_t size,
                       Topic& topic)
{
  Detail::Reader reader(data, size);
  std::uint32_t parsedMagic = 0;
  std::uint16_t version = 0;
  std::uint8_t parsedTopic = 0;
  std::uint8_t flags = 0;
  std::uint32_t frameBytes = 0;
  std::uint32_t reserved = 0;
  if (size < headerBytes || size > maximumResolveFrameBytes ||
      !reader.u32(parsedMagic) || !reader.u16(version) ||
      !reader.u8(parsedTopic) || !reader.u8(flags) ||
      !reader.u32(frameBytes) || !reader.u32(reserved) ||
      parsedMagic != magic || version != protocolVersion || flags != 0 ||
      frameBytes != size || reserved != 0 || !Detail::validTopic(Topic(parsedTopic)))
  {
    return false;
  }
  topic = Topic(parsedTopic);
  return true;
}

inline bool encodeResolveRequest(const Resolve& request, String& output)
{
  if (request.requestID == 0 || request.generation == 0 ||
      request.deadlineMilliseconds == 0 ||
      request.deadlineMilliseconds > maximumDeadlineMilliseconds ||
      !Detail::validFamily(request.family) ||
      !Detail::validHostname(request.hostname) ||
      request.status != ResolveStatus::backendFailure ||
      !request.canonicalName.empty() || request.canonicalNameTtlSeconds != 0 ||
      request.timeouts != 0 || !request.addresses.empty())
  {
    return false;
  }
  const std::size_t size = headerBytes + 28 + request.hostname.size();
  Detail::Writer writer(output, size);
  return writer.ready() && Detail::header(writer, Topic::resolve, size) &&
         writer.u64(request.requestID) && writer.u64(request.generation) &&
         writer.u32(request.deadlineMilliseconds) &&
         writer.u8(std::uint8_t(request.family)) && writer.u8(0) &&
         writer.u16(std::uint16_t(request.hostname.size())) &&
         writer.u32(0) && writer.bytes(request.hostname.data(), request.hostname.size()) &&
         writer.done();
}

inline bool parseResolveRequest(const std::uint8_t *data,
                                std::size_t size,
                                Resolve& request)
{
  request = {};
  if (size < headerBytes + 28 || size > maximumResolveFrameBytes)
  {
    return false;
  }
  Detail::Reader reader(data, size);
  std::uint8_t family = 0;
  std::uint8_t reserved8 = 0;
  std::uint16_t hostnameBytes = 0;
  std::uint32_t reserved32 = 0;
  return Detail::header(reader, size, Topic::resolve) &&
         reader.u64(request.requestID) && reader.u64(request.generation) &&
         reader.u32(request.deadlineMilliseconds) && reader.u8(family) &&
         reader.u8(reserved8) && reader.u16(hostnameBytes) &&
         reader.u32(reserved32) &&
         reader.string(request.hostname, hostnameBytes) && reader.done() &&
         request.requestID != 0 && request.generation != 0 &&
         request.deadlineMilliseconds != 0 &&
         request.deadlineMilliseconds <= maximumDeadlineMilliseconds &&
         reserved8 == 0 && reserved32 == 0 &&
         Detail::validFamily(Family(family)) &&
         (request.family = Family(family), true) &&
         Detail::validHostname(request.hostname);
}

inline bool encodeResolveResult(const Resolve& result, String& output)
{
  if (result.requestID == 0 || result.generation == 0 ||
      !Detail::validStatus(result.status) ||
      result.deadlineMilliseconds != 0 || result.family != Family::any ||
      !result.hostname.empty() ||
      result.canonicalName.size() > maximumHostnameBytes ||
      (!result.canonicalName.empty() && !Detail::validHostname(result.canonicalName)) ||
      (result.canonicalName.empty() != (result.canonicalNameTtlSeconds == 0)) ||
      result.addresses.size() > maximumAnswers ||
      (result.status == ResolveStatus::success && result.addresses.empty()) ||
      (result.status != ResolveStatus::success &&
       (!result.addresses.empty() || !result.canonicalName.empty())))
  {
    return false;
  }
  for (const Address& address : result.addresses)
  {
    if (!Detail::canonicalAddress(address))
    {
      return false;
    }
  }

  const std::size_t size = headerBytes + 28 + result.canonicalName.size() +
                           result.addresses.size() * addressRecordBytes;
  if (size > maximumResolveFrameBytes)
  {
    return false;
  }
  Detail::Writer writer(output, size);
  if (!writer.ready() || !Detail::header(writer, Topic::resolve, size) ||
      !writer.u64(result.requestID) || !writer.u64(result.generation) ||
      !writer.u8(std::uint8_t(result.status)) ||
      !writer.u8(std::uint8_t(result.addresses.size())) ||
      !writer.u16(std::uint16_t(result.canonicalName.size())) ||
      !writer.u32(result.canonicalNameTtlSeconds) || !writer.u32(result.timeouts) ||
      !writer.bytes(result.canonicalName.data(), result.canonicalName.size()))
  {
    return false;
  }
  for (const Address& address : result.addresses)
  {
    const std::uint8_t usedBytes = address.family == Family::ipv4 ? 4 : 16;
    if (!writer.u8(std::uint8_t(address.family)) || !writer.u8(usedBytes) ||
        !writer.u16(0) || !writer.u32(address.ttlSeconds) ||
        !writer.bytes(address.bytes, sizeof(address.bytes)))
    {
      return false;
    }
  }
  return writer.done();
}

inline bool parseResolveResult(const std::uint8_t *data,
                               std::size_t size,
                               Resolve& result)
{
  result = {};
  if (size < headerBytes + 28 || size > maximumResolveFrameBytes)
  {
    return false;
  }
  Detail::Reader reader(data, size);
  std::uint8_t status = 0;
  std::uint8_t answerCount = 0;
  std::uint16_t canonicalBytes = 0;
  if (!Detail::header(reader, size, Topic::resolve) ||
      !reader.u64(result.requestID) || !reader.u64(result.generation) ||
      !reader.u8(status) || !reader.u8(answerCount) ||
      !reader.u16(canonicalBytes) ||
      !reader.u32(result.canonicalNameTtlSeconds) || !reader.u32(result.timeouts) ||
      result.requestID == 0 || result.generation == 0 ||
      !Detail::validStatus(ResolveStatus(status)) ||
      answerCount > maximumAnswers || canonicalBytes > maximumHostnameBytes ||
      !reader.string(result.canonicalName, canonicalBytes))
  {
    return false;
  }
  result.status = ResolveStatus(status);
  if ((!result.canonicalName.empty() && !Detail::validHostname(result.canonicalName)) ||
      (result.canonicalName.empty() != (result.canonicalNameTtlSeconds == 0)) ||
      (result.status == ResolveStatus::success && answerCount == 0) ||
      (result.status != ResolveStatus::success &&
       (answerCount != 0 || !result.canonicalName.empty() ||
        result.canonicalNameTtlSeconds != 0)))
  {
    return false;
  }

  result.addresses.reserve(answerCount);
  for (std::uint8_t index = 0; index < answerCount; index += 1)
  {
    Address address;
    std::uint8_t family = 0;
    std::uint8_t usedBytes = 0;
    std::uint16_t reserved = 0;
    if (!reader.u8(family) || !reader.u8(usedBytes) || !reader.u16(reserved) ||
        !reader.u32(address.ttlSeconds) || !reader.bytes(address.bytes, sizeof(address.bytes)) ||
        !Detail::validAddressFamily(Family(family)) || reserved != 0 ||
        usedBytes != (Family(family) == Family::ipv4 ? 4 : 16))
    {
      result = {};
      return false;
    }
    address.family = Family(family);
    if (!Detail::canonicalAddress(address))
    {
      result = {};
      return false;
    }
    result.addresses.push_back(address);
  }
  return reader.done();
}

inline bool encodeCancel(const Cancel& cancel, String& output)
{
  Detail::Writer writer(output, cancelFrameBytes);
  return cancel.requestID != 0 && cancel.generation != 0 && writer.ready() &&
         Detail::header(writer, Topic::cancel, cancelFrameBytes) &&
         writer.u64(cancel.requestID) && writer.u64(cancel.generation) && writer.done();
}

inline bool parseCancel(const std::uint8_t *data,
                        std::size_t size,
                        Cancel& cancel)
{
  cancel = {};
  Detail::Reader reader(data, size);
  return size == cancelFrameBytes && Detail::header(reader, size, Topic::cancel) &&
         reader.u64(cancel.requestID) && reader.u64(cancel.generation) && reader.done() &&
         cancel.requestID != 0 && cancel.generation != 0;
}

inline bool encodeSession(const Session& session, String& output)
{
  Detail::Writer writer(output, sessionFrameBytes);
  return Detail::validSessionPhase(session.phase) && session.applicationID != 0 &&
         session.service != 0 && session.nonce != 0 && session.generation != 0 &&
         writer.ready() && Detail::header(writer, Topic::session, sessionFrameBytes) &&
         writer.u8(std::uint8_t(session.phase)) && writer.u8(0) && writer.u16(0) &&
         writer.u16(session.applicationID) && writer.u16(0) &&
         writer.u64(session.service) && writer.u64(session.nonce) &&
         writer.u64(session.generation) && writer.done();
}

inline bool parseSession(const std::uint8_t *data,
                         std::size_t size,
                         Session& session)
{
  session = {};
  Detail::Reader reader(data, size);
  std::uint8_t phase = 0;
  std::uint8_t reserved8 = 0;
  std::uint16_t reserved16a = 0;
  std::uint16_t reserved16b = 0;
  return size == sessionFrameBytes && Detail::header(reader, size, Topic::session) &&
         reader.u8(phase) && reader.u8(reserved8) && reader.u16(reserved16a) &&
         reader.u16(session.applicationID) && reader.u16(reserved16b) &&
         reader.u64(session.service) && reader.u64(session.nonce) &&
         reader.u64(session.generation) && reader.done() &&
         reserved8 == 0 && reserved16a == 0 && reserved16b == 0 &&
         Detail::validSessionPhase(SessionPhase(phase)) &&
         (session.phase = SessionPhase(phase), true) && session.applicationID != 0 &&
         session.service != 0 && session.nonce != 0 && session.generation != 0;
}
} // namespace ProdigySDK::Opinionated::Dns
