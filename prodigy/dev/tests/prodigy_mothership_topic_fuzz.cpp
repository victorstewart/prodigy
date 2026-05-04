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

   static constexpr std::array<MothershipTopic, 22> topics = {
      MothershipTopic::configure,
      MothershipTopic::upsertMachineSchemas,
      MothershipTopic::deltaMachineBudget,
      MothershipTopic::deleteMachineSchema,
      MothershipTopic::updateProdigy,
      MothershipTopic::measureApplication,
      MothershipTopic::addMachines,
      MothershipTopic::reserveApplicationID,
      MothershipTopic::reserveServiceID,
      MothershipTopic::upsertTlsVaultFactory,
      MothershipTopic::upsertApiCredentialSet,
      MothershipTopic::mintClientTlsIdentity,
      MothershipTopic::registerRoutableSubnet,
      MothershipTopic::unregisterRoutableSubnet,
      MothershipTopic::registerRoutableAddress,
      MothershipTopic::unregisterRoutableAddress,
      MothershipTopic::spinApplication,
      MothershipTopic::destroyApplication,
      MothershipTopic::pullApplicationReport,
      MothershipTopic::pullClusterReport,
      MothershipTopic::pullRoutableSubnets,
      MothershipTopic::pullRoutableAddresses,
   };

   std::vector<uint8_t> bytes(data, data + size);
   MothershipTopic topic = topics[bytes.front() % topics.size()];

   uint8_t *args = bytes.data() + 1;
   uint8_t *terminal = bytes.data() + bytes.size();

   (void)ProdigyIngressValidation::validateMothershipPayload(uint16_t(topic), args, terminal);
   return 0;
}
