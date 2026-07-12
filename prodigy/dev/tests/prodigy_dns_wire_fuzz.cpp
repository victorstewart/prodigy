#include <prodigy/sdk/cpp/opinionated/dns_wire.h>

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
   namespace Dns = ProdigySDK::Opinionated::Dns;

   Dns::Resolve resolve;
   Dns::Cancel cancel;
   Dns::Session session;
   Dns::parseResolveRequest(data, size, resolve);
   Dns::parseResolveResult(data, size, resolve);
   Dns::parseCancel(data, size, cancel);
   Dns::parseSession(data, size, session);
   return 0;
}
