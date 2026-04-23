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

   static constexpr std::array<BrainTopic, 22> topics = {
      BrainTopic::cullDeployment,
      BrainTopic::reconcileState,
      BrainTopic::registration,
      BrainTopic::peerAddressCandidates,
      BrainTopic::masterMissing,
      BrainTopic::updateBundle,
      BrainTopic::transitionToNewBundle,
      BrainTopic::relinquishMasterStatus,
      BrainTopic::replicateDeployment,
      BrainTopic::replicateBrainConfig,
      BrainTopic::replicateClusterTopology,
      BrainTopic::replicateApplicationIDReservation,
      BrainTopic::replicateApplicationServiceReservation,
      BrainTopic::replicateTlsVaultFactory,
      BrainTopic::replicateApiCredentialSet,
      BrainTopic::replicateMasterAuthorityState,
      BrainTopic::replicateMetricsSnapshot,
      BrainTopic::reconcileMetrics,
      BrainTopic::replicateMetricsAppend,
      BrainTopic::reconcileTd,
      BrainTopic::replicateTdAppend,
      BrainTopic::replicateContainerHealthy,
   };

   std::vector<uint8_t> bytes(data, data + size);
   BrainTopic topic = topics[bytes.front() % topics.size()];

   uint8_t *args = bytes.data() + 1;
   uint8_t *terminal = bytes.data() + bytes.size();

   (void)ProdigyIngressValidation::validateBrainPayload(uint16_t(topic), args, terminal);
   return 0;
}
