#include <networking/includes.h>
#include <services/debug.h>
#include <services/bitsery.h>
#include <services/crypto.h>
#include <services/filesystem.h>
#include <networking/time.h>
#include <networking/ip.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/pool.h>
#include <networking/ring.h>
#include <prodigy/neuron.hub.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

class ReadyContainer final : public NeuronHubDispatch
{
private:

   std::unique_ptr<NeuronHub> neuronHub;
   bool readySignaled = false;

   void signalReadyOnce()
   {
      if (readySignaled || neuronHub == nullptr)
      {
         return;
      }

      readySignaled = true;
      neuronHub->signalReady();
   }

public:

   void beginShutdown(void) override
   {
   }

   void endOfDynamicArgs(void) override
   {
      signalReadyOnce();
   }

   void prepare(int argc, char *argv[])
   {
      Ring::createRing(64, 128, 512, 128, -1, -1, 0);

      neuronHub = std::make_unique<NeuronHub>(this);
      neuronHub->fillFromMainArgs(argc, argv);
      neuronHub->afterRing();
      signalReadyOnce();
   }

   void start(void)
   {
      Ring::start();
   }
};

int main(int argc, char *argv[])
{
   ReadyContainer container;
   container.prepare(argc, argv);
   container.start();
   return 0;
}
