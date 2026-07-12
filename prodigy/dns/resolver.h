#pragma once

#include <networking/async.dns.cares.h>
#include <prodigy/sdk/cpp/opinionated/dns_wire.h>

namespace ProdigyDns
{

namespace Wire = ProdigySDK::Opinionated::Dns;

class Resolver final
{
private:

   RingAsyncDnsResolver backend;

   static Wire::ResolveStatus wireStatus(AsyncDnsResolver::Status status)
   {
      using BackendStatus = AsyncDnsResolver::Status;
      using WireStatus = Wire::ResolveStatus;

      switch (status)
      {
         case BackendStatus::success:
            return WireStatus::success;
         case BackendStatus::canceled:
            return WireStatus::canceled;
         case BackendStatus::deadlineExceeded:
            return WireStatus::deadlineExceeded;
         case BackendStatus::invalidHostname:
            return WireStatus::invalidHostname;
         case BackendStatus::invalidService:
            return WireStatus::invalidService;
         case BackendStatus::singleLabelRejected:
            return WireStatus::singleLabelRejected;
         case BackendStatus::unsupportedFamily:
            return WireStatus::unsupportedFamily;
         case BackendStatus::notFound:
            return WireStatus::notFound;
         case BackendStatus::noData:
            return WireStatus::noData;
         case BackendStatus::tooManyAnswers:
            return WireStatus::tooManyAnswers;
         case BackendStatus::overloaded:
            return WireStatus::overloaded;
         case BackendStatus::shutdown:
            return WireStatus::shutdown;
         case BackendStatus::pending:
         case BackendStatus::backendRequired:
         case BackendStatus::backendFailure:
         default:
            return WireStatus::backendFailure;
      }
   }

   static AsyncDnsResolver::Family backendFamily(Wire::Family family)
   {
      switch (family)
      {
         case Wire::Family::ipv4:
            return AsyncDnsResolver::Family::ipv4;
         case Wire::Family::ipv6:
            return AsyncDnsResolver::Family::ipv6;
         case Wire::Family::any:
         default:
            return AsyncDnsResolver::Family::any;
      }
   }

   static bool appendAddress(const AsyncDnsResolver::Address& source,
                             Wire::Address& destination)
   {
      if (source.family() == AF_INET && source.length == sizeof(sockaddr_in))
      {
         const sockaddr_in *address =
             reinterpret_cast<const sockaddr_in *>(&source.storage);
         destination.family = Wire::Family::ipv4;
         memcpy(destination.bytes, &address->sin_addr, sizeof(address->sin_addr));
      }
      else if (source.family() == AF_INET6 &&
               source.length == sizeof(sockaddr_in6))
      {
         const sockaddr_in6 *address =
             reinterpret_cast<const sockaddr_in6 *>(&source.storage);
         destination.family = Wire::Family::ipv6;
         memcpy(destination.bytes, &address->sin6_addr, sizeof(address->sin6_addr));
      }
      else
      {
         return false;
      }

      destination.ttlSeconds = source.ttlSeconds;
      return true;
   }

   static void normalizeCanonicalName(String& name)
   {
      if (name.size() > Wire::maximumHostnameBytes)
      {
         name.clear();
         return;
      }

      while (name.empty() == false && name[name.size() - 1] == '.')
      {
         name.resize(name.size() - 1);
      }
      for (size_t index = 0; index < name.size(); index += 1)
      {
         if (name[index] >= 'A' && name[index] <= 'Z')
         {
            name[index] = uint8_t(name[index] + ('a' - 'A'));
         }
      }
      if (Wire::Detail::validHostname(name) == false)
      {
         name.clear();
      }
   }

public:

   explicit Resolver(AsyncDnsResolver::Config resolverConfig,
                     RingAsyncDnsResolver::BackendConfig backendConfig)
       : backend(std::move(resolverConfig), std::move(backendConfig))
   {}

   RingAsyncDnsResolver::InitializationStatus initializationStatus(void) const
   {
      return backend.initializationStatus();
   }

   AsyncDnsResolver::Ticket resolve(const Wire::Resolve& request,
                                    AsyncDnsResolver::Callback callback)
   {
      const auto deadline = AsyncDnsResolver::Clock::now() +
                            std::chrono::milliseconds(request.deadlineMilliseconds);
      return backend.resolve(request.hostname,
                             String(),
                             backendFamily(request.family),
                             callback,
                             deadline);
   }

   bool cancel(AsyncDnsResolver::Ticket ticket)
   {
      return backend.cancel(ticket);
   }

   bool shutdown(void)
   {
      return backend.shutdown();
   }

   bool shutdownSafe(void) const
   {
      return backend.shutdownSafe();
   }

   static bool encodeResult(uint64_t requestID,
                            uint64_t generation,
                            AsyncDnsResolver::Result&& backendResult,
                            String& frame)
   {
      Wire::Resolve result;
      result.requestID = requestID;
      result.generation = generation;
      result.status = wireStatus(backendResult.status);
      result.timeouts = backendResult.timeouts;

      if (result.status == Wire::ResolveStatus::success)
      {
         result.canonicalName = std::move(backendResult.canonicalName);
         normalizeCanonicalName(result.canonicalName);
         result.canonicalNameTtlSeconds = result.canonicalName.empty()
                                                  ? 0
                                                  : backendResult.canonicalNameTtlSeconds;
         if (result.canonicalNameTtlSeconds == 0)
         {
            result.canonicalName.clear();
         }

         result.addresses.reserve(backendResult.addresses.size());
         for (const AsyncDnsResolver::Address& address : backendResult.addresses)
         {
            Wire::Address converted;
            if (appendAddress(address, converted) == false)
            {
               result.status = Wire::ResolveStatus::backendFailure;
               result.canonicalName.clear();
               result.canonicalNameTtlSeconds = 0;
               result.addresses.clear();
               break;
            }
            result.addresses.push_back(converted);
         }
      }

      return Wire::encodeResolveResult(result, frame);
   }
};

} // namespace ProdigyDns
