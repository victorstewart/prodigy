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

   static constexpr std::array<NeuronTopic, 32> topics = {
      NeuronTopic::spinContainer,
      NeuronTopic::killContainer,
      NeuronTopic::advertisementPairing,
      NeuronTopic::subscriptionPairing,
      NeuronTopic::refreshContainerCredentials,
      NeuronTopic::adjustContainerResources,
      NeuronTopic::containerHealthy,
      NeuronTopic::containerFailed,
      NeuronTopic::registration,
      NeuronTopic::machineHardwareProfile,
      NeuronTopic::requestContainerBlob,
      NeuronTopic::assignFragment,
      NeuronTopic::changeContainerLifetime,
      NeuronTopic::containerResourcesAdjusted,
      NeuronTopic::ping,
      NeuronTopic::pong,
      NeuronTopic::stateUpload,
      NeuronTopic::hardwareFailure,
      NeuronTopic::updateOS,
      NeuronTopic::replicateDeployment,
      NeuronTopic::spotTerminationImminent,
      NeuronTopic::containerStatistics,
      NeuronTopic::refreshContainerWormholes,
      NeuronTopic::configureRuntimeEnvironment,
      NeuronTopic::resetSwitchboardState,
      NeuronTopic::configureSwitchboardRoutableSubnets,
      NeuronTopic::configureSwitchboardHostedIngressPrefixes,
      NeuronTopic::configureSwitchboardOverlayRoutes,
      NeuronTopic::openSwitchboardWormholes,
      NeuronTopic::closeSwitchboardWormholesToContainer,
      NeuronTopic::openSwitchboardWhiteholes,
      NeuronTopic::closeSwitchboardWhiteholesToContainer,
   };

   std::vector<uint8_t> bytes(data, data + size);
   NeuronTopic topic = topics[bytes.front() % topics.size()];

   uint8_t *args = bytes.data() + 1;
   uint8_t *terminal = bytes.data() + bytes.size();

   (void)ProdigyIngressValidation::validateNeuronPayloadForBrain(uint16_t(topic), args, terminal);
   (void)ProdigyIngressValidation::validateNeuronPayloadForNeuron(uint16_t(topic), args, terminal);
   return 0;
}
