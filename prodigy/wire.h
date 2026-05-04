#pragma once

#include <limits>

#include <networking/includes.h>
#include <services/bitsery.h>
#include <services/filesystem.h>
#include <networking/message.h>
#include <services/prodigy.h>
#include <prodigy/types.h>
#include <services/memfd.h>

namespace ProdigyWire
{
   static constexpr uint8_t containerParametersMagic[8] = {'P', 'R', 'D', 'P', 'A', 'R', '0', '1'};
   static constexpr uint8_t credentialBundleMagic[8] = {'P', 'R', 'D', 'B', 'U', 'N', '0', '1'};
   static constexpr uint8_t credentialDeltaMagic[8] = {'P', 'R', 'D', 'D', 'E', 'L', '0', '1'};
   static constexpr uint32_t maxControlFrameBytes = 256u * 1024u * 1024u;
   static constexpr uint32_t maxWireStringBytes = 16u * 1024u * 1024u;
   static constexpr uint32_t maxWireCollectionElements = 16u * 1024u;

   static bool deserializeCredentialDelta(const String& input, CredentialDelta& delta);
   static bool deserializeCredentialDeltaAuto(const String& input, CredentialDelta& delta);

   class Writer
   {
   public:
      explicit Writer(String& target) : out(target)
      {
      }

      void raw(const uint8_t *bytes, uint64_t count)
      {
         if (count == 0 || bytes == nullptr)
         {
            return;
         }

         out.append(bytes, count);
      }

      void header(const uint8_t (&magic)[8])
      {
         raw(magic, sizeof(magic));
      }

      void u8(uint8_t value)
      {
         raw(&value, sizeof(value));
      }

      void boolean(bool value)
      {
         u8(value ? uint8_t(1) : uint8_t(0));
      }

      void u16(uint16_t value)
      {
         uint8_t encoded[2] = {
            uint8_t(value & 0xffu),
            uint8_t((value >> 8) & 0xffu)
         };
         raw(encoded, sizeof(encoded));
      }

      void u32(uint32_t value)
      {
         uint8_t encoded[4] = {
            uint8_t(value & 0xffu),
            uint8_t((value >> 8) & 0xffu),
            uint8_t((value >> 16) & 0xffu),
            uint8_t((value >> 24) & 0xffu)
         };
         raw(encoded, sizeof(encoded));
      }

      void i32(int32_t value)
      {
         u32(static_cast<uint32_t>(value));
      }

      void u64(uint64_t value)
      {
         uint8_t encoded[8] = {
            uint8_t(value & 0xffu),
            uint8_t((value >> 8) & 0xffu),
            uint8_t((value >> 16) & 0xffu),
            uint8_t((value >> 24) & 0xffu),
            uint8_t((value >> 32) & 0xffu),
            uint8_t((value >> 40) & 0xffu),
            uint8_t((value >> 48) & 0xffu),
            uint8_t((value >> 56) & 0xffu)
         };
         raw(encoded, sizeof(encoded));
      }

      void i64(int64_t value)
      {
         u64(static_cast<uint64_t>(value));
      }

      void u128(uint128_t value)
      {
         uint8_t encoded[16] = {};

         for (uint32_t index = 0; index < 16; index += 1)
         {
            encoded[index] = uint8_t(value & uint128_t(0xffu));
            value >>= 8;
         }

         raw(encoded, sizeof(encoded));
      }

      bool sizedBytes(const uint8_t *bytes, uint64_t count)
      {
         if (count > std::numeric_limits<uint32_t>::max())
         {
            return false;
         }

         u32(static_cast<uint32_t>(count));
         raw(bytes, count);
         return true;
      }

      bool string(const String& value)
      {
         return sizedBytes(value.data(), value.size());
      }

   private:
      String& out;
   };

   class Reader
   {
   public:
      explicit Reader(const String& source) : cursor(source.data()), terminal(source.data() + source.size())
      {
      }

      Reader(const uint8_t *start, uint64_t size) : cursor(start), terminal(start + size)
      {
      }

      bool done(void) const
      {
         return cursor == terminal;
      }

      uint64_t remaining(void) const
      {
         return uint64_t(terminal - cursor);
      }

      bool header(const uint8_t (&magic)[8])
      {
         const uint8_t *bytes = nullptr;
         if (raw(bytes, sizeof(magic)) == false)
         {
            return false;
         }

         return (memcmp(bytes, magic, sizeof(magic)) == 0);
      }

      bool raw(const uint8_t *&bytes, uint64_t count)
      {
         if (count > remaining())
         {
            return false;
         }

         bytes = cursor;
         cursor += count;
         return true;
      }

      bool rawTo(uint8_t *output, uint64_t count)
      {
         const uint8_t *bytes = nullptr;
         if (raw(bytes, count) == false)
         {
            return false;
         }

         if (count > 0 && output != nullptr)
         {
            memcpy(output, bytes, count);
         }

         return true;
      }

      bool u8(uint8_t& value)
      {
         const uint8_t *bytes = nullptr;
         if (raw(bytes, 1) == false)
         {
            return false;
         }

         value = bytes[0];
         return true;
      }

      bool boolean(bool& value)
      {
         uint8_t encoded = 0;
         if (u8(encoded) == false)
         {
            return false;
         }

         if (encoded > 1)
         {
            return false;
         }

         value = (encoded == 1);
         return true;
      }

      bool u16(uint16_t& value)
      {
         const uint8_t *bytes = nullptr;
         if (raw(bytes, 2) == false)
         {
            return false;
         }

         value = uint16_t(bytes[0]) |
            (uint16_t(bytes[1]) << 8);
         return true;
      }

      bool u32(uint32_t& value)
      {
         const uint8_t *bytes = nullptr;
         if (raw(bytes, 4) == false)
         {
            return false;
         }

         value = uint32_t(bytes[0]) |
            (uint32_t(bytes[1]) << 8) |
            (uint32_t(bytes[2]) << 16) |
            (uint32_t(bytes[3]) << 24);
         return true;
      }

      bool boundedU32(uint32_t& value, uint32_t maxValue)
      {
         return u32(value) && value <= maxValue;
      }

      bool i32(int32_t& value)
      {
         uint32_t encoded = 0;
         if (u32(encoded) == false)
         {
            return false;
         }

         value = static_cast<int32_t>(encoded);
         return true;
      }

      bool u64(uint64_t& value)
      {
         const uint8_t *bytes = nullptr;
         if (raw(bytes, 8) == false)
         {
            return false;
         }

         value = uint64_t(bytes[0]) |
            (uint64_t(bytes[1]) << 8) |
            (uint64_t(bytes[2]) << 16) |
            (uint64_t(bytes[3]) << 24) |
            (uint64_t(bytes[4]) << 32) |
            (uint64_t(bytes[5]) << 40) |
            (uint64_t(bytes[6]) << 48) |
            (uint64_t(bytes[7]) << 56);
         return true;
      }

      bool i64(int64_t& value)
      {
         uint64_t encoded = 0;
         if (u64(encoded) == false)
         {
            return false;
         }

         value = static_cast<int64_t>(encoded);
         return true;
      }

      bool u128(uint128_t& value)
      {
         const uint8_t *bytes = nullptr;
         if (raw(bytes, 16) == false)
         {
            return false;
         }

         value = 0;
         for (uint32_t index = 0; index < 16; index += 1)
         {
            value |= (uint128_t(bytes[index]) << (index * 8));
         }

         return true;
      }

      bool string(String& value)
      {
         uint32_t size = 0;
         if (boundedU32(size, maxWireStringBytes) == false || remaining() < size)
         {
            return false;
         }

         value.assign(const_cast<uint8_t *>(cursor), size);
         cursor += size;
         return true;
      }

   private:
      const uint8_t *cursor = nullptr;
      const uint8_t *terminal = nullptr;
   };

   template <typename T>
   static bool extractLegacyAligned(const uint8_t *&cursor, const uint8_t *terminal, T& value)
   {
      static_assert(std::is_trivially_copyable_v<T>);

      constexpr uintptr_t alignmentMask = uintptr_t(alignof(T) - 1);
      uintptr_t aligned = (reinterpret_cast<uintptr_t>(cursor) + alignmentMask) & ~alignmentMask;
      const uint8_t *alignedCursor = reinterpret_cast<const uint8_t *>(aligned);

      if (alignedCursor > terminal || (terminal - alignedCursor) < ptrdiff_t(sizeof(T)))
      {
         return false;
      }

      memcpy(&value, alignedCursor, sizeof(T));
      cursor = alignedCursor + sizeof(T);
      return true;
   }

   static bool extractLegacyVariable(const uint8_t *input, uint64_t inputSize, String& output)
   {
      const uint8_t *cursor = input;
      const uint8_t *terminal = input + inputSize;

      uint32_t length = 0;
      if (extractLegacyAligned(cursor, terminal, length) == false || length > maxWireStringBytes)
      {
         return false;
      }

      static constexpr uintptr_t alignmentMask = uintptr_t(8 - 1);
      uintptr_t aligned = (reinterpret_cast<uintptr_t>(cursor) + alignmentMask) & ~alignmentMask;
      const uint8_t *alignedCursor = reinterpret_cast<const uint8_t *>(aligned);
      if (alignedCursor > terminal || uint64_t(terminal - alignedCursor) < uint64_t(length))
      {
         return false;
      }

      output.setInvariant(const_cast<uint8_t *>(alignedCursor), length);
      return (alignedCursor + length) == terminal;
   }

   static bool appendIPAddress(Writer& writer, const IPAddress& address)
   {
      writer.raw(address.v6, sizeof(address.v6));
      writer.boolean(address.is6);
      return true;
   }

   static bool extractIPAddress(Reader& reader, IPAddress& address)
   {
      if (reader.rawTo(address.v6, sizeof(address.v6)) == false)
      {
         return false;
      }

      return reader.boolean(address.is6);
   }

   static bool appendIPPrefix(Writer& writer, const IPPrefix& prefix)
   {
      appendIPAddress(writer, prefix.network);
      writer.u8(prefix.cidr);
      return true;
   }

   static bool extractIPPrefix(Reader& reader, IPPrefix& prefix)
   {
      if (extractIPAddress(reader, prefix.network) == false)
      {
         return false;
      }

      return reader.u8(prefix.cidr);
   }

   static bool appendStringVector(Writer& writer, const Vector<String>& values)
   {
      if (values.size() > std::numeric_limits<uint32_t>::max())
      {
         return false;
      }

      writer.u32(static_cast<uint32_t>(values.size()));
      for (const String& value : values)
      {
         if (writer.string(value) == false)
         {
            return false;
         }
      }

      return true;
   }

   static bool extractStringVector(Reader& reader, Vector<String>& values)
   {
      uint32_t count = 0;
      if (reader.boundedU32(count, maxWireCollectionElements) == false)
      {
         return false;
      }

      values.clear();
      values.reserve(count);

      for (uint32_t index = 0; index < count; index += 1)
      {
         String value;
         if (reader.string(value) == false)
         {
            return false;
         }

         values.push_back(std::move(value));
      }

      return true;
   }

   static bool appendIPAddressVector(Writer& writer, const Vector<IPAddress>& values)
   {
      if (values.size() > std::numeric_limits<uint32_t>::max())
      {
         return false;
      }

      writer.u32(static_cast<uint32_t>(values.size()));
      for (const IPAddress& value : values)
      {
         if (appendIPAddress(writer, value) == false)
         {
            return false;
         }
      }

      return true;
   }

   static bool extractIPAddressVector(Reader& reader, Vector<IPAddress>& values)
   {
      uint32_t count = 0;
      if (reader.boundedU32(count, maxWireCollectionElements) == false)
      {
         return false;
      }

      values.clear();
      values.reserve(count);

      for (uint32_t index = 0; index < count; index += 1)
      {
         IPAddress value;
         if (extractIPAddress(reader, value) == false)
         {
            return false;
         }

         values.push_back(value);
      }

      return true;
   }

   static bool appendTlsIdentityFields(Writer& writer, const TlsIdentity& identity)
   {
      return writer.string(identity.name) &&
         (writer.u64(identity.generation), true) &&
         (writer.i64(identity.notBeforeMs), true) &&
         (writer.i64(identity.notAfterMs), true) &&
         writer.string(identity.certPem) &&
         writer.string(identity.keyPem) &&
         writer.string(identity.chainPem) &&
         appendStringVector(writer, identity.dnsSans) &&
         appendIPAddressVector(writer, identity.ipSans) &&
         appendStringVector(writer, identity.tags);
   }

   static bool extractTlsIdentityFields(Reader& reader, TlsIdentity& identity)
   {
      return reader.string(identity.name) &&
         reader.u64(identity.generation) &&
         reader.i64(identity.notBeforeMs) &&
         reader.i64(identity.notAfterMs) &&
         reader.string(identity.certPem) &&
         reader.string(identity.keyPem) &&
         reader.string(identity.chainPem) &&
         extractStringVector(reader, identity.dnsSans) &&
         extractIPAddressVector(reader, identity.ipSans) &&
         extractStringVector(reader, identity.tags);
   }

   static bool appendApiCredentialFields(Writer& writer, const ApiCredential& credential)
   {
      if (writer.string(credential.name) == false ||
         writer.string(credential.provider) == false)
      {
         return false;
      }

      writer.u64(credential.generation);
      writer.i64(credential.expiresAtMs);
      writer.i64(credential.activeFromMs);
      writer.i64(credential.sunsetAtMs);
      if (writer.string(credential.material) == false)
      {
         return false;
      }

      if (credential.metadata.size() > std::numeric_limits<uint32_t>::max())
      {
         return false;
      }

      writer.u32(static_cast<uint32_t>(credential.metadata.size()));
      for (const auto& [key, value] : credential.metadata)
      {
         if (writer.string(key) == false || writer.string(value) == false)
         {
            return false;
         }
      }

      return true;
   }

   static bool extractApiCredentialFields(Reader& reader, ApiCredential& credential)
   {
      if (reader.string(credential.name) == false ||
         reader.string(credential.provider) == false ||
         reader.u64(credential.generation) == false ||
         reader.i64(credential.expiresAtMs) == false ||
         reader.i64(credential.activeFromMs) == false ||
         reader.i64(credential.sunsetAtMs) == false ||
         reader.string(credential.material) == false)
      {
         return false;
      }

      uint32_t metadataCount = 0;
      if (reader.boundedU32(metadataCount, maxWireCollectionElements) == false)
      {
         return false;
      }

      credential.metadata.clear();
      for (uint32_t index = 0; index < metadataCount; index += 1)
      {
         String key;
         String value;
         if (reader.string(key) == false || reader.string(value) == false)
         {
            return false;
         }

         credential.metadata.insert_or_assign(std::move(key), std::move(value));
      }

      return true;
   }

   static bool appendCredentialBundleFields(Writer& writer, const CredentialBundle& bundle)
   {
      if (bundle.tlsIdentities.size() > std::numeric_limits<uint32_t>::max() ||
         bundle.apiCredentials.size() > std::numeric_limits<uint32_t>::max())
      {
         return false;
      }

      writer.u32(static_cast<uint32_t>(bundle.tlsIdentities.size()));
      for (const TlsIdentity& identity : bundle.tlsIdentities)
      {
         if (appendTlsIdentityFields(writer, identity) == false)
         {
            return false;
         }
      }

      writer.u32(static_cast<uint32_t>(bundle.apiCredentials.size()));
      for (const ApiCredential& credential : bundle.apiCredentials)
      {
         if (appendApiCredentialFields(writer, credential) == false)
         {
            return false;
         }
      }

      writer.u64(bundle.bundleGeneration);
      return true;
   }

   static bool extractCredentialBundleFields(Reader& reader, CredentialBundle& bundle)
   {
      uint32_t tlsCount = 0;
      if (reader.boundedU32(tlsCount, maxWireCollectionElements) == false)
      {
         return false;
      }

      bundle.tlsIdentities.clear();
      bundle.tlsIdentities.reserve(tlsCount);
      for (uint32_t index = 0; index < tlsCount; index += 1)
      {
         TlsIdentity identity;
         if (extractTlsIdentityFields(reader, identity) == false)
         {
            return false;
         }

         bundle.tlsIdentities.push_back(std::move(identity));
      }

      uint32_t apiCount = 0;
      if (reader.boundedU32(apiCount, maxWireCollectionElements) == false)
      {
         return false;
      }

      bundle.apiCredentials.clear();
      bundle.apiCredentials.reserve(apiCount);
      for (uint32_t index = 0; index < apiCount; index += 1)
      {
         ApiCredential credential;
         if (extractApiCredentialFields(reader, credential) == false)
         {
            return false;
         }

         bundle.apiCredentials.push_back(std::move(credential));
      }

      return reader.u64(bundle.bundleGeneration);
   }

   static bool appendCredentialDeltaFields(Writer& writer, const CredentialDelta& delta)
   {
      writer.u64(delta.bundleGeneration);

      if (delta.updatedTls.size() > std::numeric_limits<uint32_t>::max() ||
         delta.updatedApi.size() > std::numeric_limits<uint32_t>::max())
      {
         return false;
      }

      writer.u32(static_cast<uint32_t>(delta.updatedTls.size()));
      for (const TlsIdentity& identity : delta.updatedTls)
      {
         if (appendTlsIdentityFields(writer, identity) == false)
         {
            return false;
         }
      }

      if (appendStringVector(writer, delta.removedTlsNames) == false)
      {
         return false;
      }

      writer.u32(static_cast<uint32_t>(delta.updatedApi.size()));
      for (const ApiCredential& credential : delta.updatedApi)
      {
         if (appendApiCredentialFields(writer, credential) == false)
         {
            return false;
         }
      }

      return appendStringVector(writer, delta.removedApiNames) &&
         writer.string(delta.reason);
   }

   static bool extractCredentialDeltaFields(Reader& reader, CredentialDelta& delta)
   {
      if (reader.u64(delta.bundleGeneration) == false)
      {
         return false;
      }

      uint32_t updatedTlsCount = 0;
      if (reader.boundedU32(updatedTlsCount, maxWireCollectionElements) == false)
      {
         return false;
      }

      delta.updatedTls.clear();
      delta.updatedTls.reserve(updatedTlsCount);
      for (uint32_t index = 0; index < updatedTlsCount; index += 1)
      {
         TlsIdentity identity;
         if (extractTlsIdentityFields(reader, identity) == false)
         {
            return false;
         }

         delta.updatedTls.push_back(std::move(identity));
      }

      if (extractStringVector(reader, delta.removedTlsNames) == false)
      {
         return false;
      }

      uint32_t updatedApiCount = 0;
      if (reader.boundedU32(updatedApiCount, maxWireCollectionElements) == false)
      {
         return false;
      }

      delta.updatedApi.clear();
      delta.updatedApi.reserve(updatedApiCount);
      for (uint32_t index = 0; index < updatedApiCount; index += 1)
      {
         ApiCredential credential;
         if (extractApiCredentialFields(reader, credential) == false)
         {
            return false;
         }

         delta.updatedApi.push_back(std::move(credential));
      }

      return extractStringVector(reader, delta.removedApiNames) &&
         reader.string(delta.reason);
   }

   template <typename TopicType>
   static bool constructPackedFrame(StringDescendent auto& output, TopicType topic, const String& payload)
   {
      if (payload.size() > std::numeric_limits<uint32_t>::max())
      {
         return false;
      }

      uint32_t headerOffset = Message::appendHeader(output, topic);
      if (payload.size() > 0)
      {
         Message::append<Alignment::one>(output, payload.data(), static_cast<uint32_t>(payload.size()));
      }

      uint8_t *paddingStart = output.pTail();
      Message::finish(output, headerOffset);

      if (output.pTail() > paddingStart)
      {
         std::memset(paddingStart, 0, size_t(output.pTail() - paddingStart));
      }

      return true;
   }

   static bool serializeResourceDeltaPayload(
      String& output,
      uint16_t logicalCores,
      uint32_t memoryMB,
      uint32_t storageMB,
      bool isDownscale,
      uint32_t graceSeconds)
   {
      output.clear();
      Writer writer(output);
      writer.u16(logicalCores);
      writer.u32(memoryMB);
      writer.u32(storageMB);
      writer.boolean(isDownscale);
      writer.u32(graceSeconds);
      return true;
   }

   static bool deserializeResourceDeltaPayload(
      const uint8_t *input,
      uint64_t inputSize,
      uint16_t& logicalCores,
      uint32_t& memoryMB,
      uint32_t& storageMB,
      bool& isDownscale,
      uint32_t& graceSeconds)
   {
      Reader reader(input, inputSize);
      return reader.u16(logicalCores) &&
         reader.u32(memoryMB) &&
         reader.u32(storageMB) &&
         reader.boolean(isDownscale) &&
         reader.u32(graceSeconds) &&
         reader.done();
   }

   static bool deserializeResourceDeltaPayloadAuto(
      const uint8_t *input,
      uint64_t inputSize,
      uint16_t& logicalCores,
      uint32_t& memoryMB,
      uint32_t& storageMB,
      bool& isDownscale,
      uint32_t& graceSeconds)
   {
      if (deserializeResourceDeltaPayload(input, inputSize, logicalCores, memoryMB, storageMB, isDownscale, graceSeconds))
      {
         return true;
      }

      const uint8_t *cursor = input;
      const uint8_t *terminal = input + inputSize;
      if (extractLegacyAligned(cursor, terminal, logicalCores) == false ||
         extractLegacyAligned(cursor, terminal, memoryMB) == false ||
         extractLegacyAligned(cursor, terminal, storageMB) == false)
      {
         return false;
      }

      isDownscale = false;
      graceSeconds = 0;
      if (cursor == terminal)
      {
         return true;
      }

      if (extractLegacyAligned(cursor, terminal, isDownscale) == false)
      {
         return false;
      }

      if (cursor == terminal)
      {
         return true;
      }

      return extractLegacyAligned(cursor, terminal, graceSeconds) && cursor == terminal;
   }

   static bool serializeAdvertisementPairingPayload(
      String& output,
      uint128_t secret,
      uint128_t address,
      uint64_t service,
      uint16_t applicationID,
      bool activate)
   {
      output.clear();
      Writer writer(output);
      writer.u128(secret);
      writer.u128(address);
      writer.u64(service);
      writer.u16(applicationID);
      writer.boolean(activate);
      return true;
   }

   static bool deserializeAdvertisementPairingPayload(
      const uint8_t *input,
      uint64_t inputSize,
      uint128_t& secret,
      uint128_t& address,
      uint64_t& service,
      uint16_t& applicationID,
      bool& activate)
   {
      Reader reader(input, inputSize);
      return reader.u128(secret) &&
         reader.u128(address) &&
         reader.u64(service) &&
         reader.u16(applicationID) &&
         reader.boolean(activate) &&
         reader.done();
   }

   static bool deserializeAdvertisementPairingPayloadAuto(
      const uint8_t *input,
      uint64_t inputSize,
      uint128_t& secret,
      uint128_t& address,
      uint64_t& service,
      uint16_t& applicationID,
      bool& activate)
   {
      if (deserializeAdvertisementPairingPayload(input, inputSize, secret, address, service, applicationID, activate))
      {
         return true;
      }

      const uint8_t *cursor = input;
      const uint8_t *terminal = input + inputSize;
      if (extractLegacyAligned(cursor, terminal, secret) == false ||
         extractLegacyAligned(cursor, terminal, address) == false ||
         extractLegacyAligned(cursor, terminal, service) == false)
      {
         return false;
      }

      const uint8_t *beforeOptional = cursor;
      if (extractLegacyAligned(cursor, terminal, applicationID) &&
         extractLegacyAligned(cursor, terminal, activate) &&
         cursor == terminal)
      {
         return true;
      }

      cursor = beforeOptional;
      applicationID = uint16_t(service >> 48);
      return extractLegacyAligned(cursor, terminal, activate) && cursor == terminal;
   }

   static bool serializeSubscriptionPairingPayload(
      String& output,
      uint128_t secret,
      uint128_t address,
      uint64_t service,
      uint16_t port,
      uint16_t applicationID,
      bool activate)
   {
      output.clear();
      Writer writer(output);
      writer.u128(secret);
      writer.u128(address);
      writer.u64(service);
      writer.u16(port);
      writer.u16(applicationID);
      writer.boolean(activate);
      return true;
   }

   static bool deserializeSubscriptionPairingPayload(
      const uint8_t *input,
      uint64_t inputSize,
      uint128_t& secret,
      uint128_t& address,
      uint64_t& service,
      uint16_t& port,
      uint16_t& applicationID,
      bool& activate)
   {
      Reader reader(input, inputSize);
      return reader.u128(secret) &&
         reader.u128(address) &&
         reader.u64(service) &&
         reader.u16(port) &&
         reader.u16(applicationID) &&
         reader.boolean(activate) &&
         reader.done();
   }

   static bool deserializeSubscriptionPairingPayloadAuto(
      const uint8_t *input,
      uint64_t inputSize,
      uint128_t& secret,
      uint128_t& address,
      uint64_t& service,
      uint16_t& port,
      uint16_t& applicationID,
      bool& activate)
   {
      if (deserializeSubscriptionPairingPayload(input, inputSize, secret, address, service, port, applicationID, activate))
      {
         return true;
      }

      const uint8_t *cursor = input;
      const uint8_t *terminal = input + inputSize;
      if (extractLegacyAligned(cursor, terminal, secret) == false ||
         extractLegacyAligned(cursor, terminal, address) == false ||
         extractLegacyAligned(cursor, terminal, service) == false ||
         extractLegacyAligned(cursor, terminal, port) == false)
      {
         return false;
      }

      const uint8_t *beforeOptional = cursor;
      if (extractLegacyAligned(cursor, terminal, applicationID) &&
         extractLegacyAligned(cursor, terminal, activate) &&
         cursor == terminal)
      {
         return true;
      }

      cursor = beforeOptional;
      applicationID = uint16_t(service >> 48);
      return extractLegacyAligned(cursor, terminal, activate) && cursor == terminal;
   }

   static bool deserializeCredentialDeltaFramePayloadAuto(const uint8_t *input, uint64_t inputSize, CredentialDelta& delta)
   {
      String payload;
      payload.setInvariant(const_cast<uint8_t *>(input), inputSize);
      if (deserializeCredentialDelta(payload, delta))
      {
         return true;
      }

      String extracted;
      return extractLegacyVariable(input, inputSize, extracted) && deserializeCredentialDeltaAuto(extracted, delta);
   }

   static uint32_t countSubscriptionPairings(const ContainerParameters& parameters)
   {
      uint64_t count = 0;

      for (const auto& [service, pairings] : parameters.subscriptionPairings.map)
      {
         (void)service;
         count += pairings.size();
      }

      if (count > std::numeric_limits<uint32_t>::max())
      {
         return 0;
      }

      return static_cast<uint32_t>(count);
   }

   static uint32_t countAdvertisementPairings(const ContainerParameters& parameters)
   {
      uint64_t count = 0;

      for (const auto& [service, pairings] : parameters.advertisementPairings.map)
      {
         (void)service;
         count += pairings.size();
      }

      if (count > std::numeric_limits<uint32_t>::max())
      {
         return 0;
      }

      return static_cast<uint32_t>(count);
   }

   static bool serializeCredentialBundle(String& output, const CredentialBundle& bundle)
   {
      output.clear();
      Writer writer(output);
      writer.header(credentialBundleMagic);
      return appendCredentialBundleFields(writer, bundle);
   }

   static bool deserializeCredentialBundle(const String& input, CredentialBundle& bundle)
   {
      Reader reader(input);
      CredentialBundle decoded;
      if (reader.header(credentialBundleMagic) == false ||
         extractCredentialBundleFields(reader, decoded) == false ||
         reader.done() == false)
      {
         return false;
      }

      bundle = std::move(decoded);
      return true;
   }

   static bool serializeCredentialDelta(String& output, const CredentialDelta& delta)
   {
      output.clear();
      Writer writer(output);
      writer.header(credentialDeltaMagic);
      return appendCredentialDeltaFields(writer, delta);
   }

   static bool deserializeCredentialDelta(const String& input, CredentialDelta& delta)
   {
      Reader reader(input);
      CredentialDelta decoded;
      if (reader.header(credentialDeltaMagic) == false ||
         extractCredentialDeltaFields(reader, decoded) == false ||
         reader.done() == false)
      {
         return false;
      }

      delta = std::move(decoded);
      return true;
   }

   static bool serializeContainerParameters(String& output, const ContainerParameters& parameters)
   {
      if (parameters.advertisesOnPorts.size() > std::numeric_limits<uint32_t>::max() ||
         parameters.flags.size() > std::numeric_limits<uint32_t>::max())
      {
         return false;
      }

      uint32_t subscriptionCount = countSubscriptionPairings(parameters);
      uint32_t advertisementCount = countAdvertisementPairings(parameters);
      if ((subscriptionCount == 0 && parameters.subscriptionPairings.isEmpty() == false) ||
         (advertisementCount == 0 && parameters.advertisementPairings.isEmpty() == false))
      {
         return false;
      }

      output.clear();
      Writer writer(output);
      writer.header(containerParametersMagic);
      writer.u128(parameters.uuid);
      writer.u32(parameters.memoryMB);
      writer.u32(parameters.storageMB);
      writer.u16(parameters.nLogicalCores);
      writer.i32(parameters.neuronFD);
      writer.i32(parameters.lowCPU);
      writer.i32(parameters.highCPU);

      writer.u32(static_cast<uint32_t>(parameters.advertisesOnPorts.size()));
      for (const auto& [service, port] : parameters.advertisesOnPorts)
      {
         writer.u64(service);
         writer.u16(port);
      }

      writer.u32(subscriptionCount);
      for (const auto& [service, pairings] : parameters.subscriptionPairings.map)
      {
         (void)service;
         for (const SubscriptionPairing& pairing : pairings)
         {
            writer.u128(pairing.secret);
            writer.u128(pairing.address);
            writer.u64(pairing.service);
            writer.u16(pairing.port);
         }
      }

      writer.u32(advertisementCount);
      for (const auto& [service, pairings] : parameters.advertisementPairings.map)
      {
         (void)service;
         for (const AdvertisementPairing& pairing : pairings)
         {
            writer.u128(pairing.secret);
            writer.u128(pairing.address);
            writer.u64(pairing.service);
         }
      }

      appendIPPrefix(writer, parameters.private6);
      writer.boolean(parameters.justCrashed);
      writer.u8(parameters.datacenterUniqueTag);

      writer.u32(static_cast<uint32_t>(parameters.flags.size()));
      for (uint64_t flag : parameters.flags)
      {
         writer.u64(flag);
      }

      writer.boolean(parameters.hasCredentialBundle);
      if (parameters.hasCredentialBundle)
      {
         if (appendCredentialBundleFields(writer, parameters.credentialBundle) == false)
         {
            output.clear();
            return false;
         }
      }

      return true;
   }

   static bool deserializeContainerParameters(const String& input, ContainerParameters& parameters)
   {
      auto decode = [&] (bool consumeLegacyPublicEgressFields) -> bool {
         Reader reader(input);
         ContainerParameters decoded;

         if (reader.header(containerParametersMagic) == false ||
            reader.u128(decoded.uuid) == false ||
            reader.u32(decoded.memoryMB) == false ||
            reader.u32(decoded.storageMB) == false ||
            reader.u16(decoded.nLogicalCores) == false ||
            reader.i32(decoded.neuronFD) == false ||
            reader.i32(decoded.lowCPU) == false ||
            reader.i32(decoded.highCPU) == false)
         {
            return false;
         }

         uint32_t advertiseCount = 0;
         if (reader.boundedU32(advertiseCount, maxWireCollectionElements) == false)
         {
            return false;
         }

         for (uint32_t index = 0; index < advertiseCount; index += 1)
         {
            uint64_t service = 0;
            uint16_t port = 0;
            if (reader.u64(service) == false || reader.u16(port) == false)
            {
               return false;
            }

            decoded.advertisesOnPorts[service] = port;
         }

         uint32_t subscriptionCount = 0;
         if (reader.boundedU32(subscriptionCount, maxWireCollectionElements) == false)
         {
            return false;
         }

         for (uint32_t index = 0; index < subscriptionCount; index += 1)
         {
            SubscriptionPairing pairing;
            if (reader.u128(pairing.secret) == false ||
               reader.u128(pairing.address) == false ||
               reader.u64(pairing.service) == false ||
               reader.u16(pairing.port) == false)
            {
               return false;
            }

            decoded.subscriptionPairings.insert(pairing.service, pairing);
         }

         uint32_t advertisementCount = 0;
         if (reader.boundedU32(advertisementCount, maxWireCollectionElements) == false)
         {
            return false;
         }

         for (uint32_t index = 0; index < advertisementCount; index += 1)
         {
            AdvertisementPairing pairing;
            if (reader.u128(pairing.secret) == false ||
               reader.u128(pairing.address) == false ||
               reader.u64(pairing.service) == false)
            {
               return false;
            }

            decoded.advertisementPairings.insert(pairing.service, pairing);
         }

         if (extractIPPrefix(reader, decoded.private6) == false)
         {
            return false;
         }

         if (consumeLegacyPublicEgressFields)
         {
            IPPrefix ignoredPublic6;
            bool ignoredRequiresPublic4 = false;
            bool ignoredRequiresPublic6 = false;
            if (extractIPPrefix(reader, ignoredPublic6) == false ||
               reader.boolean(ignoredRequiresPublic4) == false ||
               reader.boolean(ignoredRequiresPublic6) == false)
            {
               return false;
            }
         }

         if (reader.boolean(decoded.justCrashed) == false ||
            reader.u8(decoded.datacenterUniqueTag) == false)
         {
            return false;
         }

         uint32_t flagCount = 0;
         if (reader.boundedU32(flagCount, maxWireCollectionElements) == false)
         {
            return false;
         }

         decoded.flags.clear();
         decoded.flags.reserve(flagCount);
         for (uint32_t index = 0; index < flagCount; index += 1)
         {
            uint64_t flag = 0;
            if (reader.u64(flag) == false)
            {
               return false;
            }

            decoded.flags.push_back(flag);
         }

         if (reader.boolean(decoded.hasCredentialBundle) == false)
         {
            return false;
         }

         if (decoded.hasCredentialBundle)
         {
            if (extractCredentialBundleFields(reader, decoded.credentialBundle) == false)
            {
               return false;
            }
         }
         else
         {
            decoded.credentialBundle = CredentialBundle();
         }

         if (reader.done() == false)
         {
            return false;
         }

         parameters = std::move(decoded);
         return true;
      };

      if (decode(false))
      {
         return true;
      }

      return decode(true);
   }

   static bool deserializeContainerParametersAuto(const String& input, ContainerParameters& parameters)
   {
      if (deserializeContainerParameters(input, parameters))
      {
         return true;
      }

      return BitseryEngine::deserializeSafe(input, parameters);
   }

   static bool deserializeCredentialDeltaAuto(const String& input, CredentialDelta& delta)
   {
      if (deserializeCredentialDelta(input, delta))
      {
         return true;
      }

      return BitseryEngine::deserializeSafe(input, delta);
   }

   static bool readContainerParametersFromProcessArgs(int argc, char *argv[], ContainerParameters& parameters)
   {
      const char *fdEnv = getenv("PRODIGY_PARAMS_FD");
      if (fdEnv && *fdEnv)
      {
         int fd = atoi(fdEnv);
         String buffer;
         if (fd >= 0 && Memfd::readAll(fd, buffer))
         {
            return deserializeContainerParametersAuto(buffer, parameters);
         }
      }
      else if (argc > 1 && argv[1])
      {
         String serializedParameters;
         serializedParameters.setInvariant(argv[1]);
         return deserializeContainerParametersAuto(serializedParameters, parameters);
      }

      return false;
   }
}
