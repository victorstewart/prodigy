#include <networking/includes.h>
#include <services/prodigy.h>
#include <prodigy/ingress.validation.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
   if (data == nullptr || size == 0)
   {
      return 0;
   }

   static constexpr std::array<ContainerTopic, 14> topics = {
      ContainerTopic::none,
      ContainerTopic::ping,
      ContainerTopic::pong,
      ContainerTopic::stop,
      ContainerTopic::advertisementPairing,
      ContainerTopic::subscriptionPairing,
      ContainerTopic::healthy,
      ContainerTopic::message,
      ContainerTopic::resourceDelta,
      ContainerTopic::datacenterUniqueTag,
      ContainerTopic::statistics,
      ContainerTopic::resourceDeltaAck,
      ContainerTopic::credentialsRefresh,
      ContainerTopic::wormholesRefresh,
   };

   std::vector<uint8_t> bytes(data, data + size);
   ContainerTopic topic = topics[bytes.front() % topics.size()];

   uint8_t *args = bytes.data() + 1;
   uint8_t *terminal = bytes.data() + bytes.size();

   (void)ProdigyIngressValidation::validateContainerPayloadForNeuron(uint16_t(topic), args, terminal);
   (void)ProdigyIngressValidation::validateContainerPayloadForHub(uint16_t(topic), args, terminal);
   return 0;
}
