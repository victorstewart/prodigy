#pragma once

#include <networking/includes.h>
#include <services/prodigy.h>
#include <prodigy/types.h>

#include <enums/datacenter.h>

#include <prodigy/neuron/neuron.h>
#include <prodigy/brain/base.h>
/*

1) monitor hardware failures
	* cache
	* memory
	* disk drives (would only be the non-operating system disk) https://manpages.ubuntu.com/manpages/xenial/man8/smartd.8.html
	* NICs (if this fails we won't be able to tell anyone anyway)
	* what about CPU cores failing?

	stop all the running processes and report the error if we can? otherwise another machine will report us missing?

	Uncorrected memory errors – that is data corruption – are reported using a machine check exception and handled directly by the kernel, for example by killing the affected process or shutting down the system down.

	we observe DRAM error rates that are orders of magnitude higher than previously reported, with 25,000 to 70,000 errors per billion device hours per Mbit and more than 8% of DIMMs affected by errors per year.

	In many production environments, including ours, a single un- correctable error is considered serious enough to replace the dual in-line memory module (DIMM) that caused it.
*/

// listen for SIGUSR1 for hardware failures
// read the /run/hardwarefailure.txt file to get the error, send it through the provider support/escalation path, then poweroff machine, 

template <typename NeuronType, typename BrainType>
class Prodigy : public RingMultiplexer {
private:

	TimeoutPacket shutdownTimer;

	NeuronType *neuron = nullptr;
	// the only way master brain is relinquished, is either by choice when we 1) update the operating system or 2) update this program, or by force when 3) the machine fails

	void beforeRing(void)
   {
   	Ring::signals[0] = SIGINT;
   	Ring::signals[1] = SIGUSR1;
   }

	   void afterRing(void)
	   {
	   	neuron = new NeuronType();
	   	thisNeuron = neuron;

	   	neuron->boot(); // all networking (if any) is sync for now, so we'd block
         std::fprintf(stderr, "prodigy afterRing neuronIsBrain=%d private4=%u\n", int(neuron->isBrain), ntohl(neuron->private4.v4));
	   	
	   	if (neuron->isBrain)
	   	{
   		BrainType *brain = new BrainType();
   		thisBrain = brain;

   		brain->getBrains();
   	}
   }

   void queueShutdown(void)
   {
		shutdownTimer.setTimeoutMs(1'000);
		shutdownTimer.dispatcher = this;
		shutdownTimer.originator = this; // route back to this Prodigy instance
		Ring::queueTimeout(&shutdownTimer);
   }

   void timeoutHandler(TimeoutPacket *packet, int result)
	{
		beginShutdown();
	}

   bool signalHandler(const struct signalfd_siginfo& sigInfo)
   {
   	switch (sigInfo.ssi_signo)
   	{
   		case SIGINT: 
   		{
   			beginShutdown();
   			return false;
   		}
   		case SIGUSR1:
   		{
   			neuron->hardwareFailureOccured();
   			return false;
   		}
   		default: return true;
   	}
   }

   void beginShutdown(void)
	{
		Guardian::signalHandler(SIGINT, NULL, NULL);
	}

public:

	void prepare(int argc, char *argv[])
	{
		RingDispatcher::installMultiplexer(this);
		// Also register this Prodigy instance for timeout routing
		RingDispatcher::installMultiplexee(this, this);
		BrainBase::captureLaunchArguments(argc, argv);

			uint32_t sqeCount = 128;
			uint32_t cqeCount = 128;
			uint32_t nFixedFiles = 8192;
			uint32_t nReservedFixedFiles = 2048;

		Ring::createRing(sqeCount, cqeCount, nFixedFiles, nReservedFixedFiles, -1, -1, 0);
	}

	void start(void)
	{
		Ring::start();
	}
};
