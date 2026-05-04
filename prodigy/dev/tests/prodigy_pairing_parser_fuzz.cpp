#include <networking/includes.h>
#include <services/prodigy.h>
#include <prodigy/types.h>

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
   if (data == nullptr || size == 0)
   {
      return 0;
   }

   ContainerPlan plan;
   std::vector<uint8_t> bytes(data, data + size);

   uint8_t mode = bytes.front() & 0x1U;
   uint8_t *args = bytes.data() + 1;
   uint8_t *terminal = bytes.data() + bytes.size();

   if (args > terminal)
   {
      return 0;
   }

   if (mode == 0)
   {
      plan.updateAdvertisement(args, terminal);
   }
   else
   {
      plan.updateSubscription(args, terminal);
   }

   return 0;
}
