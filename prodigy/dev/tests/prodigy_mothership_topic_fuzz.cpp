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

  constexpr static std::array<MothershipTopic, 27> topics = {
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
      MothershipTopic::spinApplication,
      MothershipTopic::destroyApplication,
      MothershipTopic::pullApplicationReport,
      MothershipTopic::pullClusterReport,
      MothershipTopic::pullRoutableSubnets,
      MothershipTopic::pullRoutableResourceLeases,
      MothershipTopic::upsertDNSBinding,
      MothershipTopic::deleteDNSBinding,
      MothershipTopic::pullDNSBindings,
      MothershipTopic::teardownDNSBindings,
      MothershipTopic::presentACMEDNS01Challenge,
      MothershipTopic::cleanupACMEDNS01Challenge,
      MothershipTopic::importACMELineage,
  };

  std::vector<uint8_t> bytes(data, data + size);
  MothershipTopic topic = topics[bytes.front() % topics.size()];

  uint8_t *args = bytes.data() + 1;
  uint8_t *terminal = bytes.data() + bytes.size();

  (void)ProdigyIngressValidation::validateMothershipPayload(uint16_t(topic), args, terminal);
  return 0;
}
