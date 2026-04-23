/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ProdigySDK
{
   inline constexpr char SDKVersion[] = "1.0.0";
   inline constexpr char WireSeries[] = "WIRE_V1";
   inline constexpr std::uint32_t WireProtocolVersion = 1;

   enum class Result : std::int32_t
   {
      ok = 0,
      again = 1,
      eof = -1,
      io = -2,
      protocol = -3,
      argument = -4,
   };

   using Bytes = std::vector<std::uint8_t>;
   using U128 = std::array<std::uint8_t, 16>;

   struct IPAddress
   {
      U128 address{};
      bool isIPv6 = false;
   };

   struct IPPrefix
   {
      U128 address{};
      std::uint8_t cidr = 0;
      bool isIPv6 = false;
   };

   struct TlsIdentity
   {
      std::string name;
      std::uint64_t generation = 0;
      std::int64_t notBeforeMs = 0;
      std::int64_t notAfterMs = 0;
      std::string certPEM;
      std::string keyPEM;
      std::string chainPEM;
      std::vector<std::string> dnsSANs;
      std::vector<IPAddress> ipSANs;
      std::vector<std::string> tags;
   };

   struct ApiCredential
   {
      std::string name;
      std::string provider;
      std::uint64_t generation = 0;
      std::int64_t expiresAtMs = 0;
      std::int64_t activeFromMs = 0;
      std::int64_t sunsetAtMs = 0;
      std::string material;
      std::map<std::string, std::string> metadata;
   };

   struct CredentialBundle
   {
      std::vector<TlsIdentity> tlsIdentities;
      std::vector<ApiCredential> apiCredentials;
      std::uint64_t bundleGeneration = 0;
   };

   struct CredentialDelta
   {
      std::uint64_t bundleGeneration = 0;
      std::vector<TlsIdentity> updatedTLS;
      std::vector<std::string> removedTLSNames;
      std::vector<ApiCredential> updatedAPI;
      std::vector<std::string> removedAPINames;
      std::string reason;
   };

   struct AdvertisedPort
   {
      std::uint64_t service = 0;
      std::uint16_t port = 0;
   };

   struct AdvertisementPairing
   {
      U128 secret{};
      U128 address{};
      std::uint64_t service = 0;
      std::uint16_t applicationID = 0;
      bool activate = false;
   };

   struct SubscriptionPairing
   {
      U128 secret{};
      U128 address{};
      std::uint64_t service = 0;
      std::uint16_t port = 0;
      std::uint16_t applicationID = 0;
      bool activate = false;
   };

   struct ResourceDelta
   {
      std::uint16_t logicalCores = 0;
      std::uint32_t memoryMB = 0;
      std::uint32_t storageMB = 0;
      bool isDownscale = false;
      std::uint32_t graceSeconds = 0;
   };

   struct MetricPair
   {
      std::uint64_t key = 0;
      std::uint64_t value = 0;
   };

   struct ControlPolicy
   {
      std::optional<bool> resourceDeltaAck;
      bool credentialsRefreshAck = false;
   };

   struct ContainerParameters
   {
      U128 uuid{};
      std::uint32_t memoryMB = 0;
      std::uint32_t storageMB = 0;
      std::uint16_t logicalCores = 0;
      std::int32_t neuronFD = -1;
      std::int32_t lowCPU = 0;
      std::int32_t highCPU = 0;
      std::vector<AdvertisedPort> advertises;
      std::vector<SubscriptionPairing> subscriptionPairings;
      std::vector<AdvertisementPairing> advertisementPairings;
      IPPrefix private6;
      bool justCrashed = false;
      std::uint8_t datacenterUniqueTag = 0;
      std::vector<std::uint64_t> flags;
      std::optional<CredentialBundle> credentialBundle;
   };

   enum class ContainerTopic : std::uint16_t
   {
      none = 0,
      ping = 1,
      pong = 2,
      stop = 3,
      advertisementPairing = 4,
      subscriptionPairing = 5,
      healthy = 6,
      message = 7,
      resourceDelta = 8,
      datacenterUniqueTag = 9,
      statistics = 10,
      resourceDeltaAck = 11,
      credentialsRefresh = 12,
   };

   struct MessageFrame
   {
      ContainerTopic topic = ContainerTopic::none;
      Bytes payload;
   };

   using ReadAllFromFD = std::function<Result(int, Bytes&)>;

   class NeuronHub;

   class Dispatch
   {
   public:

      virtual ~Dispatch() = default;

      virtual void beginShutdown(NeuronHub& hub)
      {
         (void)hub;
      }

      virtual void endOfDynamicArgs(NeuronHub& hub)
      {
         (void)hub;
      }

      virtual void advertisementPairing(NeuronHub& hub, const AdvertisementPairing& pairing)
      {
         (void)hub;
         (void)pairing;
      }

      virtual void subscriptionPairing(NeuronHub& hub, const SubscriptionPairing& pairing)
      {
         (void)hub;
         (void)pairing;
      }

      virtual void resourceDelta(NeuronHub& hub, const ResourceDelta& delta)
      {
         (void)hub;
         (void)delta;
      }

      virtual void credentialsRefresh(NeuronHub& hub, const CredentialDelta& delta)
      {
         (void)hub;
         (void)delta;
      }

      virtual void messageFromProdigy(NeuronHub& hub, const Bytes& payload)
      {
         (void)hub;
         (void)payload;
      }
   };

   namespace Detail
   {
      static constexpr std::uint8_t frameHeaderSize = 8;
      static constexpr std::uint8_t frameAlignment = 16;
      static constexpr std::array<std::uint8_t, 8> containerParametersMagic = {'P', 'R', 'D', 'P', 'A', 'R', '0', '1'};
      static constexpr std::array<std::uint8_t, 8> credentialBundleMagic = {'P', 'R', 'D', 'B', 'U', 'N', '0', '1'};
      static constexpr std::array<std::uint8_t, 8> credentialDeltaMagic = {'P', 'R', 'D', 'D', 'E', 'L', '0', '1'};

      static inline std::uint16_t inferredApplicationID(std::uint64_t service)
      {
         return static_cast<std::uint16_t>((service >> 48) & 0xffffu);
      }

      static inline std::uint32_t readU32LE(const std::uint8_t *data)
      {
         return std::uint32_t(data[0])
            | (std::uint32_t(data[1]) << 8)
            | (std::uint32_t(data[2]) << 16)
            | (std::uint32_t(data[3]) << 24);
      }

      static inline std::uint16_t readU16LE(const std::uint8_t *data)
      {
         return std::uint16_t(data[0]) | (std::uint16_t(data[1]) << 8);
      }

      static inline std::uint64_t readU64LE(const std::uint8_t *data)
      {
         return std::uint64_t(data[0])
            | (std::uint64_t(data[1]) << 8)
            | (std::uint64_t(data[2]) << 16)
            | (std::uint64_t(data[3]) << 24)
            | (std::uint64_t(data[4]) << 32)
            | (std::uint64_t(data[5]) << 40)
            | (std::uint64_t(data[6]) << 48)
            | (std::uint64_t(data[7]) << 56);
      }

      static inline std::int32_t readI32LE(const std::uint8_t *data)
      {
         const std::uint32_t raw = readU32LE(data);
         std::int32_t value = 0;
         std::memcpy(&value, &raw, sizeof(value));
         return value;
      }

      static inline std::int64_t readI64LE(const std::uint8_t *data)
      {
         const std::uint64_t raw = readU64LE(data);
         std::int64_t value = 0;
         std::memcpy(&value, &raw, sizeof(value));
         return value;
      }

      static inline void appendU8(Bytes& output, std::uint8_t value)
      {
         output.push_back(value);
      }

      static inline void appendU16LE(Bytes& output, std::uint16_t value)
      {
         output.push_back(static_cast<std::uint8_t>(value & 0xffu));
         output.push_back(static_cast<std::uint8_t>((value >> 8) & 0xffu));
      }

      static inline void appendU32LE(Bytes& output, std::uint32_t value)
      {
         output.push_back(static_cast<std::uint8_t>(value & 0xffu));
         output.push_back(static_cast<std::uint8_t>((value >> 8) & 0xffu));
         output.push_back(static_cast<std::uint8_t>((value >> 16) & 0xffu));
         output.push_back(static_cast<std::uint8_t>((value >> 24) & 0xffu));
      }

      static inline void appendU64LE(Bytes& output, std::uint64_t value)
      {
         for (std::uint32_t shift = 0; shift < 64; shift += 8)
         {
            output.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
         }
      }

      static inline bool appendString(Bytes& output, const std::string& value)
      {
         if (value.size() > std::numeric_limits<std::uint32_t>::max())
         {
            return false;
         }

         appendU32LE(output, static_cast<std::uint32_t>(value.size()));
         output.insert(output.end(), value.begin(), value.end());
         return true;
      }

      class Reader
      {
      private:

         const std::uint8_t *data = nullptr;
         std::size_t size = 0;
         std::size_t offset = 0;

      public:

         Reader(const std::uint8_t *input, std::size_t inputSize)
            : data(input),
              size(inputSize)
         {
         }

         std::size_t remaining(void) const
         {
            return size - offset;
         }

         bool done(void) const
         {
            return offset == size;
         }

         bool raw(std::size_t count, const std::uint8_t *&value)
         {
            if (count > remaining())
            {
               return false;
            }

            value = (count == 0 || data == nullptr) ? nullptr : data + offset;
            offset += count;
            return true;
         }

         bool u8(std::uint8_t& value)
         {
            const std::uint8_t *bytes = nullptr;
            if (raw(1, bytes) == false || bytes == nullptr)
            {
               return false;
            }

            value = bytes[0];
            return true;
         }

         bool boolean(bool& value)
         {
            std::uint8_t rawValue = 0;
            if (u8(rawValue) == false || rawValue > 1)
            {
               return false;
            }

            value = rawValue != 0;
            return true;
         }

         bool u16(std::uint16_t& value)
         {
            const std::uint8_t *bytes = nullptr;
            if (raw(2, bytes) == false || bytes == nullptr)
            {
               return false;
            }

            value = readU16LE(bytes);
            return true;
         }

         bool u32(std::uint32_t& value)
         {
            const std::uint8_t *bytes = nullptr;
            if (raw(4, bytes) == false || bytes == nullptr)
            {
               return false;
            }

            value = readU32LE(bytes);
            return true;
         }

         bool i32(std::int32_t& value)
         {
            const std::uint8_t *bytes = nullptr;
            if (raw(4, bytes) == false || bytes == nullptr)
            {
               return false;
            }

            value = readI32LE(bytes);
            return true;
         }

         bool u64(std::uint64_t& value)
         {
            const std::uint8_t *bytes = nullptr;
            if (raw(8, bytes) == false || bytes == nullptr)
            {
               return false;
            }

            value = readU64LE(bytes);
            return true;
         }

         bool i64(std::int64_t& value)
         {
            const std::uint8_t *bytes = nullptr;
            if (raw(8, bytes) == false || bytes == nullptr)
            {
               return false;
            }

            value = readI64LE(bytes);
            return true;
         }

         bool u128(U128& value)
         {
            const std::uint8_t *bytes = nullptr;
            if (raw(value.size(), bytes) == false || bytes == nullptr)
            {
               return false;
            }

            std::memcpy(value.data(), bytes, value.size());
            return true;
         }

         bool string(std::string& value)
         {
            std::uint32_t length = 0;
            if (u32(length) == false)
            {
               return false;
            }

            const std::uint8_t *bytes = nullptr;
            if (raw(length, bytes) == false)
            {
               return false;
            }

            value.assign(reinterpret_cast<const char *>(bytes), length);
            return true;
         }
      };

      static inline bool consumeMagic(Reader& reader, const std::array<std::uint8_t, 8>& magic)
      {
         const std::uint8_t *bytes = nullptr;
         if (reader.raw(magic.size(), bytes) == false || bytes == nullptr)
         {
            return false;
         }

         return std::memcmp(bytes, magic.data(), magic.size()) == 0;
      }

      static inline bool decodeIPAddress(Reader& reader, IPAddress& address)
      {
         return reader.u128(address.address) &&
            reader.boolean(address.isIPv6);
      }

      static inline bool decodeIPPrefix(Reader& reader, IPPrefix& prefix)
      {
         return reader.u128(prefix.address) &&
            reader.boolean(prefix.isIPv6) &&
            reader.u8(prefix.cidr);
      }

      static inline bool decodeStringVector(Reader& reader, std::vector<std::string>& values)
      {
         std::uint32_t count = 0;
         if (reader.u32(count) == false)
         {
            return false;
         }

         values.clear();
         values.reserve(count);
         for (std::uint32_t index = 0; index < count; index += 1)
         {
            std::string value;
            if (reader.string(value) == false)
            {
               return false;
            }

            values.push_back(std::move(value));
         }

         return true;
      }

      static inline bool decodeIPAddressVector(Reader& reader, std::vector<IPAddress>& values)
      {
         std::uint32_t count = 0;
         if (reader.u32(count) == false)
         {
            return false;
         }

         values.clear();
         values.reserve(count);
         for (std::uint32_t index = 0; index < count; index += 1)
         {
            IPAddress value;
            if (decodeIPAddress(reader, value) == false)
            {
               return false;
            }

            values.push_back(value);
         }

         return true;
      }

      static inline bool decodeTlsIdentity(Reader& reader, TlsIdentity& identity)
      {
         return reader.string(identity.name) &&
            reader.u64(identity.generation) &&
            reader.i64(identity.notBeforeMs) &&
            reader.i64(identity.notAfterMs) &&
            reader.string(identity.certPEM) &&
            reader.string(identity.keyPEM) &&
            reader.string(identity.chainPEM) &&
            decodeStringVector(reader, identity.dnsSANs) &&
            decodeIPAddressVector(reader, identity.ipSANs) &&
            decodeStringVector(reader, identity.tags);
      }

      static inline bool decodeApiCredential(Reader& reader, ApiCredential& credential)
      {
         std::uint32_t metadataCount = 0;
         if (reader.string(credential.name) == false ||
            reader.string(credential.provider) == false ||
            reader.u64(credential.generation) == false ||
            reader.i64(credential.expiresAtMs) == false ||
            reader.i64(credential.activeFromMs) == false ||
            reader.i64(credential.sunsetAtMs) == false ||
            reader.string(credential.material) == false ||
            reader.u32(metadataCount) == false)
         {
            return false;
         }

         credential.metadata.clear();
         for (std::uint32_t index = 0; index < metadataCount; index += 1)
         {
            std::string key;
            std::string value;
            if (reader.string(key) == false || reader.string(value) == false)
            {
               return false;
            }

            credential.metadata[std::move(key)] = std::move(value);
         }

         return true;
      }

      static inline bool decodeCredentialBundleFields(Reader& reader, CredentialBundle& bundle)
      {
         std::uint32_t tlsCount = 0;
         std::uint32_t apiCount = 0;
         if (reader.u32(tlsCount) == false)
         {
            return false;
         }

         bundle.tlsIdentities.clear();
         bundle.tlsIdentities.reserve(tlsCount);
         for (std::uint32_t index = 0; index < tlsCount; index += 1)
         {
            TlsIdentity identity;
            if (decodeTlsIdentity(reader, identity) == false)
            {
               return false;
            }

            bundle.tlsIdentities.push_back(std::move(identity));
         }

         if (reader.u32(apiCount) == false)
         {
            return false;
         }

         bundle.apiCredentials.clear();
         bundle.apiCredentials.reserve(apiCount);
         for (std::uint32_t index = 0; index < apiCount; index += 1)
         {
            ApiCredential credential;
            if (decodeApiCredential(reader, credential) == false)
            {
               return false;
            }

            bundle.apiCredentials.push_back(std::move(credential));
         }

         return reader.u64(bundle.bundleGeneration);
      }

      static inline bool decodeAdvertisementPairingPayload(Reader& reader, AdvertisementPairing& pairing)
      {
         return reader.u128(pairing.secret) &&
            reader.u128(pairing.address) &&
            reader.u64(pairing.service) &&
            reader.u16(pairing.applicationID) &&
            reader.boolean(pairing.activate) &&
            reader.done();
      }

      static inline bool decodeSubscriptionPairingPayload(Reader& reader, SubscriptionPairing& pairing)
      {
         return reader.u128(pairing.secret) &&
            reader.u128(pairing.address) &&
            reader.u64(pairing.service) &&
            reader.u16(pairing.port) &&
            reader.u16(pairing.applicationID) &&
            reader.boolean(pairing.activate) &&
            reader.done();
      }

      static inline bool decodeResourceDeltaPayload(Reader& reader, ResourceDelta& delta)
      {
         return reader.u16(delta.logicalCores) &&
            reader.u32(delta.memoryMB) &&
            reader.u32(delta.storageMB) &&
            reader.boolean(delta.isDownscale) &&
            reader.u32(delta.graceSeconds) &&
            reader.done();
      }

      static inline bool validTopic(std::uint16_t rawTopic)
      {
         return rawTopic <= static_cast<std::uint16_t>(ContainerTopic::credentialsRefresh);
      }
   }

   inline Result decodeCredentialBundle(const std::uint8_t *data, std::size_t size, CredentialBundle& bundle)
   {
      if (data == nullptr && size > 0)
      {
         return Result::argument;
      }

      Detail::Reader reader(data, size);
      if (Detail::consumeMagic(reader, Detail::credentialBundleMagic) == false ||
         Detail::decodeCredentialBundleFields(reader, bundle) == false ||
         reader.done() == false)
      {
         return Result::protocol;
      }

      return Result::ok;
   }

   inline Result decodeCredentialBundle(const Bytes& input, CredentialBundle& bundle)
   {
      return decodeCredentialBundle(input.data(), input.size(), bundle);
   }

   inline Result decodeCredentialDelta(const std::uint8_t *data, std::size_t size, CredentialDelta& delta)
   {
      if (data == nullptr && size > 0)
      {
         return Result::argument;
      }

      Detail::Reader reader(data, size);
      std::uint32_t updatedTLSCount = 0;
      std::uint32_t updatedAPICount = 0;
      if (Detail::consumeMagic(reader, Detail::credentialDeltaMagic) == false ||
         reader.u64(delta.bundleGeneration) == false ||
         reader.u32(updatedTLSCount) == false)
      {
         return Result::protocol;
      }

      delta.updatedTLS.clear();
      delta.updatedTLS.reserve(updatedTLSCount);
      for (std::uint32_t index = 0; index < updatedTLSCount; index += 1)
      {
         TlsIdentity identity;
         if (Detail::decodeTlsIdentity(reader, identity) == false)
         {
            return Result::protocol;
         }

         delta.updatedTLS.push_back(std::move(identity));
      }

      if (Detail::decodeStringVector(reader, delta.removedTLSNames) == false ||
         reader.u32(updatedAPICount) == false)
      {
         return Result::protocol;
      }

      delta.updatedAPI.clear();
      delta.updatedAPI.reserve(updatedAPICount);
      for (std::uint32_t index = 0; index < updatedAPICount; index += 1)
      {
         ApiCredential credential;
         if (Detail::decodeApiCredential(reader, credential) == false)
         {
            return Result::protocol;
         }

         delta.updatedAPI.push_back(std::move(credential));
      }

      if (Detail::decodeStringVector(reader, delta.removedAPINames) == false ||
         reader.string(delta.reason) == false ||
         reader.done() == false)
      {
         return Result::protocol;
      }

      return Result::ok;
   }

   inline Result decodeCredentialDelta(const Bytes& input, CredentialDelta& delta)
   {
      return decodeCredentialDelta(input.data(), input.size(), delta);
   }

   inline Result decodeContainerParameters(const std::uint8_t *data, std::size_t size, ContainerParameters& parameters)
   {
      if (data == nullptr && size > 0)
      {
         return Result::argument;
      }

      auto decode = [&] (bool consumeLegacyPublicEgressFields) -> Result {
         Detail::Reader reader(data, size);
         ContainerParameters decoded;
         std::uint32_t advertiseCount = 0;
         std::uint32_t subscriptionPairingCount = 0;
         std::uint32_t advertisementPairingCount = 0;
         std::uint32_t flagCount = 0;
         bool hasCredentialBundle = false;

         if (Detail::consumeMagic(reader, Detail::containerParametersMagic) == false ||
            reader.u128(decoded.uuid) == false ||
            reader.u32(decoded.memoryMB) == false ||
            reader.u32(decoded.storageMB) == false ||
            reader.u16(decoded.logicalCores) == false ||
            reader.i32(decoded.neuronFD) == false ||
            reader.i32(decoded.lowCPU) == false ||
            reader.i32(decoded.highCPU) == false ||
            reader.u32(advertiseCount) == false)
         {
            return Result::protocol;
         }

         decoded.advertises.clear();
         decoded.advertises.reserve(advertiseCount);
         for (std::uint32_t index = 0; index < advertiseCount; index += 1)
         {
            AdvertisedPort port;
            if (reader.u64(port.service) == false || reader.u16(port.port) == false)
            {
               return Result::protocol;
            }

            decoded.advertises.push_back(port);
         }

         if (reader.u32(subscriptionPairingCount) == false)
         {
            return Result::protocol;
         }

         decoded.subscriptionPairings.clear();
         decoded.subscriptionPairings.reserve(subscriptionPairingCount);
         for (std::uint32_t index = 0; index < subscriptionPairingCount; index += 1)
         {
            SubscriptionPairing pairing;
            if (reader.u128(pairing.secret) == false ||
               reader.u128(pairing.address) == false ||
               reader.u64(pairing.service) == false ||
               reader.u16(pairing.port) == false)
            {
               return Result::protocol;
            }

            pairing.applicationID = Detail::inferredApplicationID(pairing.service);
            pairing.activate = true;
            decoded.subscriptionPairings.push_back(pairing);
         }

         if (reader.u32(advertisementPairingCount) == false)
         {
            return Result::protocol;
         }

         decoded.advertisementPairings.clear();
         decoded.advertisementPairings.reserve(advertisementPairingCount);
         for (std::uint32_t index = 0; index < advertisementPairingCount; index += 1)
         {
            AdvertisementPairing pairing;
            if (reader.u128(pairing.secret) == false ||
               reader.u128(pairing.address) == false ||
               reader.u64(pairing.service) == false)
            {
               return Result::protocol;
            }

            pairing.applicationID = Detail::inferredApplicationID(pairing.service);
            pairing.activate = true;
            decoded.advertisementPairings.push_back(pairing);
         }

         if (Detail::decodeIPPrefix(reader, decoded.private6) == false)
         {
            return Result::protocol;
         }

         if (consumeLegacyPublicEgressFields)
         {
            IPPrefix ignoredPublic6;
            bool ignoredRequiresPublic4 = false;
            bool ignoredRequiresPublic6 = false;
            if (Detail::decodeIPPrefix(reader, ignoredPublic6) == false ||
               reader.boolean(ignoredRequiresPublic4) == false ||
               reader.boolean(ignoredRequiresPublic6) == false)
            {
               return Result::protocol;
            }
         }

         if (reader.boolean(decoded.justCrashed) == false ||
            reader.u8(decoded.datacenterUniqueTag) == false ||
            reader.u32(flagCount) == false)
         {
            return Result::protocol;
         }

         decoded.flags.clear();
         decoded.flags.reserve(flagCount);
         for (std::uint32_t index = 0; index < flagCount; index += 1)
         {
            std::uint64_t flag = 0;
            if (reader.u64(flag) == false)
            {
               return Result::protocol;
            }

            decoded.flags.push_back(flag);
         }

         if (reader.boolean(hasCredentialBundle) == false)
         {
            return Result::protocol;
         }

         if (hasCredentialBundle)
         {
            CredentialBundle bundle;
            if (Detail::decodeCredentialBundleFields(reader, bundle) == false)
            {
               return Result::protocol;
            }

            decoded.credentialBundle = std::move(bundle);
         }
         else
         {
            decoded.credentialBundle.reset();
         }

         if (reader.done() == false)
         {
            return Result::protocol;
         }

         parameters = std::move(decoded);
         return Result::ok;
      };

      Result result = decode(false);
      if (result == Result::ok)
      {
         return result;
      }

      return decode(true);
   }

   inline Result decodeContainerParameters(const Bytes& input, ContainerParameters& parameters)
   {
      return decodeContainerParameters(input.data(), input.size(), parameters);
   }

   inline Result loadContainerParametersFromEnvOrArgv(
      int argc,
      char *argv[],
      ContainerParameters& parameters,
      const ReadAllFromFD& readAllFromFD = {})
   {
      if (const char *fdText = std::getenv("PRODIGY_PARAMS_FD"); fdText != nullptr && *fdText != '\0')
      {
         if (!readAllFromFD)
         {
            return Result::argument;
         }

         char *end = nullptr;
         long fd = std::strtol(fdText, &end, 10);
         if (end == fdText ||
            end == nullptr ||
            *end != '\0' ||
            fd < std::numeric_limits<int>::min() ||
            fd > std::numeric_limits<int>::max())
         {
            return Result::argument;
         }

         Bytes bytes;
         Result result = readAllFromFD(static_cast<int>(fd), bytes);
         if (result != Result::ok)
         {
            return result;
         }

         return decodeContainerParameters(bytes, parameters);
      }

      if (argc > 1 && argv != nullptr && argv[1] != nullptr)
      {
         const auto *data = reinterpret_cast<const std::uint8_t *>(argv[1]);
         return decodeContainerParameters(data, std::strlen(argv[1]), parameters);
      }

      return Result::argument;
   }

   inline Result decodeAdvertisementPairingPayload(const std::uint8_t *payload, std::size_t payloadSize, AdvertisementPairing& pairing)
   {
      if (payload == nullptr && payloadSize > 0)
      {
         return Result::argument;
      }

      Detail::Reader reader(payload, payloadSize);
      return Detail::decodeAdvertisementPairingPayload(reader, pairing) ? Result::ok : Result::protocol;
   }

   inline Result decodeAdvertisementPairingPayload(const Bytes& payload, AdvertisementPairing& pairing)
   {
      return decodeAdvertisementPairingPayload(payload.data(), payload.size(), pairing);
   }

   inline Result decodeSubscriptionPairingPayload(const std::uint8_t *payload, std::size_t payloadSize, SubscriptionPairing& pairing)
   {
      if (payload == nullptr && payloadSize > 0)
      {
         return Result::argument;
      }

      Detail::Reader reader(payload, payloadSize);
      return Detail::decodeSubscriptionPairingPayload(reader, pairing) ? Result::ok : Result::protocol;
   }

   inline Result decodeSubscriptionPairingPayload(const Bytes& payload, SubscriptionPairing& pairing)
   {
      return decodeSubscriptionPairingPayload(payload.data(), payload.size(), pairing);
   }

   inline Result decodeResourceDeltaPayload(const std::uint8_t *payload, std::size_t payloadSize, ResourceDelta& delta)
   {
      if (payload == nullptr && payloadSize > 0)
      {
         return Result::argument;
      }

      Detail::Reader reader(payload, payloadSize);
      return Detail::decodeResourceDeltaPayload(reader, delta) ? Result::ok : Result::protocol;
   }

   inline Result decodeResourceDeltaPayload(const Bytes& payload, ResourceDelta& delta)
   {
      return decodeResourceDeltaPayload(payload.data(), payload.size(), delta);
   }

   inline Result buildMessageFrame(
      Bytes& output,
      ContainerTopic topic,
      const std::uint8_t *payload,
      std::size_t payloadSize)
   {
      if (payload == nullptr && payloadSize > 0)
      {
         return Result::argument;
      }

      if (payloadSize > std::numeric_limits<std::uint32_t>::max())
      {
         return Result::argument;
      }

      const std::size_t baseSize = Detail::frameHeaderSize + payloadSize;
      const std::uint8_t padding = static_cast<std::uint8_t>((Detail::frameAlignment - (baseSize % Detail::frameAlignment)) % Detail::frameAlignment);
      const std::size_t frameSize = baseSize + padding;

      output.assign(frameSize, 0);
      output[0] = static_cast<std::uint8_t>(frameSize & 0xffu);
      output[1] = static_cast<std::uint8_t>((frameSize >> 8) & 0xffu);
      output[2] = static_cast<std::uint8_t>((frameSize >> 16) & 0xffu);
      output[3] = static_cast<std::uint8_t>((frameSize >> 24) & 0xffu);

      const std::uint16_t rawTopic = static_cast<std::uint16_t>(topic);
      output[4] = static_cast<std::uint8_t>(rawTopic & 0xffu);
      output[5] = static_cast<std::uint8_t>((rawTopic >> 8) & 0xffu);
      output[6] = padding;
      output[7] = Detail::frameHeaderSize;

      if (payloadSize > 0)
      {
         std::memcpy(output.data() + Detail::frameHeaderSize, payload, payloadSize);
      }

      return Result::ok;
   }

   inline Result buildMessageFrame(Bytes& output, ContainerTopic topic, const Bytes& payload)
   {
      return buildMessageFrame(output, topic, payload.data(), payload.size());
   }

   inline Result buildReadyFrame(Bytes& output)
   {
      return buildMessageFrame(output, ContainerTopic::healthy, nullptr, 0);
   }

   template <typename MetricPairs>
   Result buildStatisticsFrame(Bytes& output, const MetricPairs& metrics)
   {
      Bytes payload;
      for (const auto& metric : metrics)
      {
         Detail::appendU64LE(payload, static_cast<std::uint64_t>(metric.key));
         Detail::appendU64LE(payload, static_cast<std::uint64_t>(metric.value));
      }

      return buildMessageFrame(output, ContainerTopic::statistics, payload);
   }

   inline Result buildResourceDeltaAckFrame(Bytes& output, bool accepted)
   {
      const std::uint8_t value = accepted ? 1 : 0;
      return buildMessageFrame(output, ContainerTopic::resourceDeltaAck, &value, 1);
   }

   inline Result buildCredentialsRefreshAckFrame(Bytes& output)
   {
      return buildMessageFrame(output, ContainerTopic::credentialsRefresh, nullptr, 0);
   }

   inline Result encodeMessageFrames(const std::vector<MessageFrame>& frames, std::vector<Bytes>& output)
   {
      output.clear();
      output.reserve(frames.size());
      for (const MessageFrame& frame : frames)
      {
         Bytes bytes;
         Result result = buildMessageFrame(bytes, frame.topic, frame.payload);
         if (result != Result::ok)
         {
            output.clear();
            return result;
         }

         output.push_back(std::move(bytes));
      }

      return Result::ok;
   }

   inline Result parseMessageFrame(const std::uint8_t *data, std::size_t size, MessageFrame& frame)
   {
      if (data == nullptr)
      {
         return size == 0 ? Result::protocol : Result::argument;
      }

      if (size < Detail::frameHeaderSize)
      {
         return Result::protocol;
      }

      const std::uint32_t frameSize = Detail::readU32LE(data);
      const std::uint16_t rawTopic = Detail::readU16LE(data + 4);
      const std::uint8_t padding = data[6];
      const std::uint8_t headerSize = data[7];

      if (headerSize != Detail::frameHeaderSize ||
         frameSize != size ||
         frameSize < Detail::frameHeaderSize ||
         (frameSize % Detail::frameAlignment) != 0 ||
         Detail::validTopic(rawTopic) == false)
      {
         return Result::protocol;
      }

      const std::size_t payloadSize = size - Detail::frameHeaderSize;
      if (padding > payloadSize)
      {
         return Result::protocol;
      }

      frame.topic = static_cast<ContainerTopic>(rawTopic);
      frame.payload.assign(
         data + Detail::frameHeaderSize,
         data + Detail::frameHeaderSize + (payloadSize - padding));
      return Result::ok;
   }

   inline Result parseMessageFrame(const Bytes& input, MessageFrame& frame)
   {
      return parseMessageFrame(input.data(), input.size(), frame);
   }

   inline Result decodeMetricPairs(const std::uint8_t *payload, std::size_t payloadSize, std::vector<MetricPair>& metrics)
   {
      if (payload == nullptr && payloadSize > 0)
      {
         return Result::argument;
      }

      if ((payloadSize % 16) != 0)
      {
         return Result::protocol;
      }

      metrics.clear();
      metrics.reserve(payloadSize / 16);
      for (std::size_t offset = 0; offset < payloadSize; offset += 16)
      {
         MetricPair pair;
         pair.key = Detail::readU64LE(payload + offset);
         pair.value = Detail::readU64LE(payload + offset + 8);
         metrics.push_back(pair);
      }

      return Result::ok;
   }

   inline Result decodeMetricPairs(const Bytes& payload, std::vector<MetricPair>& metrics)
   {
      return decodeMetricPairs(payload.data(), payload.size(), metrics);
   }

   class FrameDecoder
   {
   private:

      Bytes buffer;

   public:

      void clear(void)
      {
         buffer.clear();
      }

      Result feed(const std::uint8_t *data, std::size_t size, std::vector<MessageFrame>& frames)
      {
         if (data == nullptr && size > 0)
         {
            return Result::argument;
         }

         if (size > 0)
         {
            buffer.insert(buffer.end(), data, data + size);
         }

         while (true)
         {
            if (buffer.size() < Detail::frameHeaderSize)
            {
               return Result::ok;
            }

            const std::uint32_t frameSize = Detail::readU32LE(buffer.data());
            const std::uint8_t headerSize = buffer[7];
            if (headerSize != Detail::frameHeaderSize ||
               frameSize < Detail::frameHeaderSize ||
               (frameSize % Detail::frameAlignment) != 0)
            {
               return Result::protocol;
            }

            if (frameSize > buffer.size())
            {
               return Result::ok;
            }

            MessageFrame frame;
            Result result = parseMessageFrame(buffer.data(), frameSize, frame);
            if (result != Result::ok)
            {
               return result;
            }

            frames.push_back(std::move(frame));
            buffer.erase(buffer.begin(), buffer.begin() + frameSize);
         }
      }

      Result feed(const Bytes& input, std::vector<MessageFrame>& frames)
      {
         return feed(input.data(), input.size(), frames);
      }
   };

   class NeuronHub
   {
   private:

      Dispatch *dispatch = nullptr;
      ControlPolicy controlPolicy;
      bool shutdown = false;
      std::vector<MessageFrame> queuedResponses;

   public:

      ContainerParameters parameters;

      explicit NeuronHub(Dispatch *target, ContainerParameters startupParameters)
         : dispatch(target),
           parameters(std::move(startupParameters))
      {
      }

      NeuronHub& withControlPolicy(ControlPolicy policy)
      {
         controlPolicy = std::move(policy);
         return *this;
      }

      NeuronHub& withAutoAcks(bool acceptResourceDelta = true)
      {
         controlPolicy.resourceDeltaAck = acceptResourceDelta;
         controlPolicy.credentialsRefreshAck = true;
         return *this;
      }

      bool shutdownRequested(void) const
      {
         return shutdown;
      }

      Result signalReady(Bytes& output) const
      {
         return buildReadyFrame(output);
      }

      Result publishStatistic(Bytes& output, std::uint64_t metricKey, std::uint64_t metricValue) const
      {
         return buildStatisticsFrame(output, std::vector<MetricPair> {{metricKey, metricValue}});
      }

      template <typename MetricPairs>
      Result publishStatistics(Bytes& output, const MetricPairs& metrics) const
      {
         return buildStatisticsFrame(output, metrics);
      }

      Result acknowledgeResourceDelta(Bytes& output, bool accepted) const
      {
         return buildResourceDeltaAckFrame(output, accepted);
      }

      Result acknowledgeCredentialsRefresh(Bytes& output) const
      {
         return buildCredentialsRefreshAckFrame(output);
      }

      void queueReady(void)
      {
         queuedResponses.push_back(MessageFrame {ContainerTopic::healthy, {}});
      }

      template <typename MetricPairs>
      void queueStatistics(const MetricPairs& metrics)
      {
         Bytes payload;
         for (const auto& metric : metrics)
         {
            Detail::appendU64LE(payload, static_cast<std::uint64_t>(metric.key));
            Detail::appendU64LE(payload, static_cast<std::uint64_t>(metric.value));
         }

         queuedResponses.push_back(MessageFrame {
            ContainerTopic::statistics,
            std::move(payload),
         });
      }

      void queueResourceDeltaAck(bool accepted)
      {
         queuedResponses.push_back(MessageFrame {
            ContainerTopic::resourceDeltaAck,
            Bytes {static_cast<std::uint8_t>(accepted ? 1u : 0u)},
         });
      }

      void queueCredentialsRefreshAck(void)
      {
         queuedResponses.push_back(MessageFrame {ContainerTopic::credentialsRefresh, {}});
      }

      Result drainQueuedResponseBytes(std::vector<Bytes>& output)
      {
         std::vector<MessageFrame> frames;
         frames.swap(queuedResponses);
         return encodeMessageFrames(frames, output);
      }

      Result handleFrame(const MessageFrame& frame, std::vector<MessageFrame>& automaticResponses)
      {
         switch (frame.topic)
         {
            case ContainerTopic::none:
            {
               if (dispatch != nullptr)
               {
                  dispatch->endOfDynamicArgs(*this);
               }

               return Result::ok;
            }
            case ContainerTopic::ping:
            {
               automaticResponses.push_back(MessageFrame {ContainerTopic::ping, {}});
               return Result::ok;
            }
            case ContainerTopic::pong:
            case ContainerTopic::healthy:
            case ContainerTopic::statistics:
            case ContainerTopic::resourceDeltaAck:
            {
               return Result::ok;
            }
            case ContainerTopic::stop:
            {
               shutdown = true;
               if (dispatch != nullptr)
               {
                  dispatch->beginShutdown(*this);
               }

               return Result::ok;
            }
            case ContainerTopic::advertisementPairing:
            {
               AdvertisementPairing pairing;
               Result result = decodeAdvertisementPairingPayload(frame.payload, pairing);
               if (result != Result::ok)
               {
                  return result;
               }

               if (dispatch != nullptr)
               {
                  dispatch->advertisementPairing(*this, pairing);
               }

               return Result::ok;
            }
            case ContainerTopic::subscriptionPairing:
            {
               SubscriptionPairing pairing;
               Result result = decodeSubscriptionPairingPayload(frame.payload, pairing);
               if (result != Result::ok)
               {
                  return result;
               }

               if (dispatch != nullptr)
               {
                  dispatch->subscriptionPairing(*this, pairing);
               }

               return Result::ok;
            }
            case ContainerTopic::resourceDelta:
            {
               ResourceDelta delta;
               Result result = decodeResourceDeltaPayload(frame.payload, delta);
               if (result != Result::ok)
               {
                  return result;
               }

               if (dispatch != nullptr)
               {
                  dispatch->resourceDelta(*this, delta);
               }

               if (controlPolicy.resourceDeltaAck.has_value())
               {
                  queueResourceDeltaAck(*controlPolicy.resourceDeltaAck);
               }

               return Result::ok;
            }
            case ContainerTopic::datacenterUniqueTag:
            {
               if (frame.payload.size() != 1)
               {
                  return Result::protocol;
               }

               parameters.datacenterUniqueTag = frame.payload[0];
               return Result::ok;
            }
            case ContainerTopic::message:
            {
               if (dispatch != nullptr)
               {
                  dispatch->messageFromProdigy(*this, frame.payload);
               }

               return Result::ok;
            }
            case ContainerTopic::credentialsRefresh:
            {
               if (frame.payload.empty())
               {
                  return Result::ok;
               }

               CredentialDelta delta;
               Result result = decodeCredentialDelta(frame.payload, delta);
               if (result != Result::ok)
               {
                  return result;
               }

               if (dispatch != nullptr)
               {
                  dispatch->credentialsRefresh(*this, delta);
               }

               if (controlPolicy.credentialsRefreshAck)
               {
                  queueCredentialsRefreshAck();
               }

               return Result::ok;
            }
         }

         return Result::protocol;
      }
   };
}
