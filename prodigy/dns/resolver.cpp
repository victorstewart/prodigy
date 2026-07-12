#include <memory>

#include <networking/includes.h>
#include <prodigy/dns/resolver.service.h>
#include <prodigy/neuron.hub.h>

namespace ProdigyDns
{

class Application final : public NeuronHubDispatch
{
private:

   std::unique_ptr<NeuronHub> neuron;
   std::unique_ptr<Service> service;

   bool loadInitialPairings(void)
   {
      for (const auto& [serviceKey, pairings] : neuron->parameters.advertisementPairings)
      {
         if (serviceKey != MeshRegistry::DNS::resolver)
         {
            return false;
         }
         for (const AdvertisementPairing& pairing : pairings)
         {
            if (pairing.secret == 0 || pairing.address == 0 ||
                pairing.service != MeshRegistry::DNS::resolver)
            {
               return false;
            }
            service->pairing(pairing.secret, pairing.service, true);
         }
      }
      return true;
   }

public:

   bool prepare(int argc, char *argv[])
   {
      Ring::createRing(128, 256, 1536, 256, -1, -1, 0);

      neuron = std::make_unique<NeuronHub>(this);
      neuron->fillFromMainArgs(argc, argv);
      neuron->afterRing();

      RuntimeConfig config;
      if (configure(neuron->parameters, config) == false)
      {
         return false;
      }

      service = std::make_unique<Service>(std::move(config));
      if (loadInitialPairings() == false || service->start() == false)
      {
         return false;
      }

      neuron->signalReady();
      neuron->signalRuntimeReady();
      return true;
   }

   void run(void)
   {
      Ring::start();
   }

   void beginShutdown(void) override
   {
      if (service)
      {
         service->shutdown();
      }
   }

   void advertisementPairing(uint128_t secret,
                             uint128_t address,
                             uint64_t advertisedService,
                             uint16_t applicationID,
                             bool activate) override
   {
      (void)applicationID;
      if (service == nullptr || address == 0)
      {
         return;
      }
      service->pairing(secret, advertisedService, activate);
   }

   void resourceDelta(uint16_t nLogicalCores,
                      uint32_t memoryMB,
                      uint32_t storageMB,
                      bool isDownscale,
                      uint32_t graceSeconds) override
   {
      (void)isDownscale;
      (void)graceSeconds;
      neuron->acknowledgeResourceDelta(nLogicalCores > 0 && memoryMB > 0 &&
                                       storageMB > 0);
   }

   void credentialsRefresh(const CredentialDelta&) override
   {
      if (service)
      {
         service->shutdown();
      }
      Ring::shuttingDown = true;
   }
};

} // namespace ProdigyDns

int main(int argc, char *argv[])
{
   ProdigyDns::Application application;
   if (application.prepare(argc, argv) == false)
   {
      return 1;
   }
   application.run();
   return 0;
}
