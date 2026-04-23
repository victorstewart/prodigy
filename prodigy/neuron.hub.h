// Internal Prodigy container runtime hub for local/runtime probes.
// This is distinct from the public SDK NeuronHub surface.

#include <networking/includes.h>
#include <networking/multiplexer.h>
#include <services/prodigy.h>
#include <macros/bytes.h>
#include <prodigy/types.h>
#include <prodigy/wire.h>
#include <prodigy/ingress.validation.h>
#include <prodigy/statistics.h>

#pragma once

class NeuronHubDispatch {
public:

	virtual void endOfDynamicArgs(void) {}
	virtual void beginShutdown(void) = 0;
	virtual void advertisementPairing(uint128_t secret, uint128_t address, uint64_t service, uint16_t applicationID, bool activate) {} // sent to advertiser
	virtual void subscriptionPairing(uint128_t secret, uint128_t address, uint64_t service, uint16_t port, uint16_t applicationID, bool activate) {} // sent to subscriber
	virtual void resourceDelta(uint16_t nLogicalCores, uint32_t memoryMB, uint32_t storageMB, bool isDownscale, uint32_t graceSeconds) {}
	virtual void credentialsRefresh(const CredentialDelta& delta) {}
   virtual void wormholesRefresh(const Vector<Wormhole>& wormholes) {}
	virtual void messageFromProdigy(Message *message) {}
};

static inline bool prodigyNeuronHubCanQueueToNeuron(bool isClosing, bool isFixedFile, int fslot)
{
   return isClosing == false
      && isFixedFile
      && fslot >= 0;
}

static inline bool prodigyNeuronHubShouldFlushBufferedNeuronFrames(bool canQueueToNeuron, bool pendingSend, uint32_t bufferedBytes)
{
   return canQueueToNeuron
      && pendingSend == false
      && bufferedBytes > 0;
}

class NeuronHub : public RingMultiplexer {
private:

	NeuronHubDispatch *target;
	UnixSocket soc; // if the neuron crashes, it will connect to us 
	bool ringLive = false;
	bool listenerInstalled = false;
	bool listenerMultiplexed = false;
	bool neuronInstalled = false;
	bool neuronMultiplexed = false;
	bool pendingResourceDeltaValid = false;
	uint16_t pendingResourceDeltaCores = 0;
	uint32_t pendingResourceDeltaMemoryMB = 0;
	uint32_t pendingResourceDeltaStorageMB = 0;

	bool queuePackedFrame(ContainerTopic topic, const String& payload)
	{
		if (ProdigyWire::constructPackedFrame(neuron.wBuffer, topic, payload) == false)
		{
			basics_log("NeuronHub::queuePackedFrame failed topic=%u payloadBytes=%u\n",
				unsigned(topic),
				unsigned(payload.size()));
			return false;
		}

		queueSendToNeuron();
		return true;
	}

	bool queueEmptyFrame(ContainerTopic topic)
	{
		String payload;
		return queuePackedFrame(topic, payload);
	}

	template <typename MetricPairs>
	bool queueStatisticsFrame(const MetricPairs& metricPairs)
	{
		String payload;
		ProdigyWire::Writer writer(payload);

		for (const auto& metric : metricPairs)
		{
			writer.u64(uint64_t(metric.first));
			writer.u64(uint64_t(metric.second));
		}

		return queuePackedFrame(ContainerTopic::statistics, payload);
	}

	static void writeNeuronStage(const char *stage)
	{
		if (stage == nullptr)
		{
			return;
		}

		int fd = open("/bootstage.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd >= 0)
		{
			(void)write(fd, stage, strlen(stage));
			(void)close(fd);
		}
	}

	template <typename T>
	static bool extractFixedArgBounded(uint8_t *&cursor, uint8_t *terminal, T& value)
	{
		static_assert(std::is_trivially_copyable_v<T>);

		constexpr uintptr_t alignmentMask = uintptr_t(alignof(T) - 1);
		uintptr_t aligned = (reinterpret_cast<uintptr_t>(cursor) + alignmentMask) & ~alignmentMask;
		uint8_t *alignedCursor = reinterpret_cast<uint8_t *>(aligned);

		if (alignedCursor > terminal || (terminal - alignedCursor) < ptrdiff_t(sizeof(T)))
		{
			return false;
		}

		value = *reinterpret_cast<T *>(alignedCursor);
		cursor = alignedCursor + sizeof(T);
		return true;
	}

	void installListenerIfReady(void)
	{
		if (ringLive == false)
		{
			return;
		}

		if (listenerInstalled == false)
		{
			Ring::installFDIntoFixedFileSlot(&soc);
			listenerInstalled = true;
		}

		if (listenerMultiplexed == false)
		{
			RingDispatcher::installMultiplexee(&soc, this);
			listenerMultiplexed = true;
		}

		Ring::queueAccept(&soc);
	}

	void installNeuronIfReady(void)
	{
		if (ringLive == false)
		{
			return;
		}
		writeNeuronStage("worker:neuron:installNeuronIfReady-enter");

		if (neuron.isFixedFile == false)
		{
			// no connected neuron half yet
			if (neuron.fd < 0)
			{
				writeNeuronStage("worker:neuron:installNeuronIfReady-no-fd");
				return;
			}

			writeNeuronStage("worker:neuron:installNeuronIfReady-before-install-fd");
			Ring::installFDIntoFixedFileSlot(&neuron);
			writeNeuronStage("worker:neuron:installNeuronIfReady-after-install-fd");
		}

		neuronInstalled = true;

		if (neuronMultiplexed == false)
		{
			writeNeuronStage("worker:neuron:installNeuronIfReady-before-multiplex");
			RingDispatcher::installMultiplexee(&neuron, this);
			neuronMultiplexed = true;
			writeNeuronStage("worker:neuron:installNeuronIfReady-after-multiplex");
		}

		writeNeuronStage("worker:neuron:installNeuronIfReady-before-queueRecv");
		Ring::queueRecv(&neuron);
		writeNeuronStage("worker:neuron:installNeuronIfReady-after-queueRecv");

      if (prodigyNeuronHubShouldFlushBufferedNeuronFrames(
            prodigyNeuronHubCanQueueToNeuron(Ring::socketIsClosing(&neuron), neuron.isFixedFile, neuron.fslot),
            neuron.pendingSend,
            uint32_t(neuron.wBuffer.outstandingBytes())))
      {
         writeNeuronStage("worker:neuron:installNeuronIfReady-before-queueSend");
         Ring::queueSend(&neuron);
         writeNeuronStage("worker:neuron:installNeuronIfReady-after-queueSend");
      }
	}

public:

	UnixStream neuron;
	ContainerParameters parameters;
	Statistics statistics;

	void queueSendToNeuron(void)
	{
		if (prodigyNeuronHubCanQueueToNeuron(Ring::socketIsClosing(&neuron), neuron.isFixedFile, neuron.fslot) == false)
		{
			// Disconnected until the next accepted fixed-file stream arrives.
			if (neuron.isFixedFile == false && neuron.fslot < 0)
			{
				return;
			}

			basics_log("NeuronHub::queueSendToNeuron requires fixed-file neuron fd=%d fslot=%d isFixed=%d\n",
				neuron.fd, neuron.fslot, int(neuron.isFixedFile));
			std::abort();
		}

		Ring::queueSend(&neuron);
	}

	    void fillFromMainArgs(int argc, char *argv[])
	    {
	        parameters = ContainerParameters{};
	        bool loaded = ProdigyWire::readContainerParametersFromProcessArgs(argc, argv, parameters);

	        if (loaded == false || parameters.neuronFD < 0)
	        {
	            basics_log("NeuronHub::fillFromMainArgs invalid parameters loaded=%d neuronFD=%d argc=%d\n",
	               int(loaded), parameters.neuronFD, argc);
	            std::abort();
	        }

	        basics_log("NeuronHub::fillFromMainArgs loaded=1 neuronFD=%d lowCPU=%d highCPU=%d nWormholes=%u nWhiteholes=%u nAdvertises=%u nSubPairings=%u nAdvPairings=%u\n",
	           parameters.neuronFD,
	           parameters.lowCPU,
	           parameters.highCPU,
	           unsigned(parameters.wormholes.size()),
	           unsigned(parameters.whiteholes.size()),
	           unsigned(parameters.advertisesOnPorts.size()),
	           unsigned(parameters.subscriptionPairings.size()),
	           unsigned(parameters.advertisementPairings.size()));

	        int dumpFD = open("/params.dump", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	        if (dumpFD >= 0)
	        {
	           char header[256] = {0};
	           int headerWritten = snprintf(
	              header,
	              sizeof(header),
	              "loaded=1 neuronFD=%d lowCPU=%d highCPU=%d nWormholes=%u nWhiteholes=%u nAdvertises=%u nSubPairings=%u nAdvPairings=%u\n",
	              parameters.neuronFD,
	              parameters.lowCPU,
	              parameters.highCPU,
	              unsigned(parameters.wormholes.size()),
	              unsigned(parameters.whiteholes.size()),
	              unsigned(parameters.advertisesOnPorts.size()),
	              unsigned(parameters.subscriptionPairings.size()),
	              unsigned(parameters.advertisementPairings.size()));
	           if (headerWritten > 0)
	           {
	              size_t headerSize = size_t(headerWritten);
	              if (headerSize >= sizeof(header))
	              {
	                 headerSize = sizeof(header) - 1;
	              }
	              (void)write(dumpFD, header, headerSize);
	           }
	        }

	        for (const auto& [service, port] : parameters.advertisesOnPorts)
	        {
	           basics_log("NeuronHub::fillFromMainArgs advertise service=%llu port=%u\n",
	              (unsigned long long)service,
	              unsigned(port));

	           if (dumpFD >= 0)
	           {
	              char line[128] = {0};
	              int lineWritten = snprintf(
	                 line,
	                 sizeof(line),
	                 "advertise service=%llu port=%u\n",
	                 (unsigned long long)service,
	                 unsigned(port));
	              if (lineWritten > 0)
	              {
	                 size_t lineSize = size_t(lineWritten);
	                 if (lineSize >= sizeof(line))
	                 {
	                    lineSize = sizeof(line) - 1;
	                 }
	                 (void)write(dumpFD, line, lineSize);
	              }
	           }
	        }

	        for (const auto& [serviceKey, pairings] : parameters.subscriptionPairings)
	        {
	           for (const SubscriptionPairing& pairing : pairings)
	           {
	              uint64_t hash = AegisStream::generateSecretServiceHash(pairing.secret, pairing.service);
	              basics_log("NeuronHub::fillFromMainArgs subpair serviceKey=%llu pairService=%llu port=%u hash=%llu\n",
	                 (unsigned long long)serviceKey,
	                 (unsigned long long)pairing.service,
	                 unsigned(pairing.port),
	                 (unsigned long long)hash);

	              if (dumpFD >= 0)
	              {
	                 char line[256] = {0};
	                 int lineWritten = snprintf(
	                    line,
	                    sizeof(line),
	                    "subpair serviceKey=%llu pairService=%llu port=%u hash=%llu\n",
	                    (unsigned long long)serviceKey,
	                    (unsigned long long)pairing.service,
	                    unsigned(pairing.port),
	                    (unsigned long long)hash);
	                 if (lineWritten > 0)
	                 {
	                    size_t lineSize = size_t(lineWritten);
	                    if (lineSize >= sizeof(line))
	                    {
	                       lineSize = sizeof(line) - 1;
	                    }
	                    (void)write(dumpFD, line, lineSize);
	                 }
	              }
	           }
	        }

	        for (const auto& [serviceKey, pairings] : parameters.advertisementPairings)
	        {
	           for (const AdvertisementPairing& pairing : pairings)
	           {
	              uint64_t hash = AegisStream::generateSecretServiceHash(pairing.secret, pairing.service);
	              basics_log("NeuronHub::fillFromMainArgs advpair serviceKey=%llu pairService=%llu hash=%llu\n",
	                 (unsigned long long)serviceKey,
	                 (unsigned long long)pairing.service,
	                 (unsigned long long)hash);

	              if (dumpFD >= 0)
	              {
	                 char line[256] = {0};
	                 int lineWritten = snprintf(
	                    line,
	                    sizeof(line),
	                    "advpair serviceKey=%llu pairService=%llu hash=%llu\n",
	                    (unsigned long long)serviceKey,
	                    (unsigned long long)pairing.service,
	                    (unsigned long long)hash);
	                 if (lineWritten > 0)
	                 {
	                    size_t lineSize = size_t(lineWritten);
	                    if (lineSize >= sizeof(line))
	                    {
	                       lineSize = sizeof(line) - 1;
	                    }
	                    (void)write(dumpFD, line, lineSize);
	                 }
	              }
	           }
	        }

	        if (dumpFD >= 0)
	        {
	           (void)close(dumpFD);
	        }

	        takeNeuronUnixPairHalf(parameters.neuronFD); // already open
	    }

	void afterRing(void)
	{
		writeNeuronStage("worker:neuron:afterRing-enter");
		ringLive = true;
		writeNeuronStage("worker:neuron:afterRing-install-listener");
		installListenerIfReady();
		writeNeuronStage("worker:neuron:afterRing-install-neuron");
		installNeuronIfReady();
		writeNeuronStage("worker:neuron:afterRing-done");
	}

	void signalReady(void)
	{
		(void)queueEmptyFrame(ContainerTopic::healthy);
	}

	void signalReadyToNeuron(void)
	{
		signalReady();
	}

	void signalRuntimeReadyToNeuron(void)
	{
		(void)queueEmptyFrame(ContainerTopic::runtimeReady);
	}

	void pushStatisticsToNeuron(void)
	{
		String payload;
		ProdigyWire::Writer writer(payload);

		for (const auto& [key, stat] : statistics.stats)
		{
			if (!stat) continue;
			writer.u64(key);
			writer.u64(stat->consume());
		}

		(void)queuePackedFrame(ContainerTopic::statistics, payload);
	}

	void takeNeuronUnixPairHalf(int fd)
	{
		// if a previous fixed-file neuron is still bound, release that slot before replacing it
		if (neuron.isFixedFile && neuron.fslot >= 0)
		{
			Ring::uninstallFromFixedFileSlot(&neuron);
			neuronInstalled = false;
		}

		neuron.setUnixPairHalf(fd);
		neuronInstalled = false;
		installNeuronIfReady();
	}

	void publishStatistic(uint64_t metricKey, uint64_t metricValue)
	{
		String payload;
		ProdigyWire::Writer writer(payload);
		writer.u64(metricKey);
		writer.u64(metricValue);
		(void)queuePackedFrame(ContainerTopic::statistics, payload);
	}

	void acknowledgeResourceDelta(bool accepted)
	{
		if (accepted && pendingResourceDeltaValid)
		{
			parameters.nLogicalCores = pendingResourceDeltaCores;
			parameters.memoryMB = pendingResourceDeltaMemoryMB;
			parameters.storageMB = pendingResourceDeltaStorageMB;
		}

		pendingResourceDeltaValid = false;
		String payload;
		ProdigyWire::Writer writer(payload);
		writer.u8(accepted ? uint8_t(1) : uint8_t(0));
		(void)queuePackedFrame(ContainerTopic::resourceDeltaAck, payload);
	}

	void acknowledgeCredentialsRefresh(void)
	{
		(void)queueEmptyFrame(ContainerTopic::credentialsRefresh);
	}

	template <typename MetricPairs>
	void publishStatistics(const MetricPairs& metricPairs)
	{
		(void)queueStatisticsFrame(metricPairs);
	}

	void neuronHandler(Message *message)
	{
		uint8_t *args = message->args;
		uint8_t *terminal = message->terminal();

		if (ProdigyIngressValidation::validateContainerPayloadForHub(message->topic, args, terminal) == false)
		{
			return;
		}

		ContainerTopic topic = (ContainerTopic)message->topic;

		switch (topic)
		{
			case ContainerTopic::none:
			{
				target->endOfDynamicArgs();
				break;
			}
				case ContainerTopic::ping:
				{
					(void)queueEmptyFrame(ContainerTopic::ping);
					break;
				}
				case ContainerTopic::pong:
				case ContainerTopic::healthy:
				case ContainerTopic::runtimeReady:
				{
					// pong/healthy/runtimeReady are produced by containers toward neuron, not expected inbound here.
					break;
				}
				case ContainerTopic::stop:
				{
					Ring::shuttingDown = true;
					target->beginShutdown();
				break;
			}
			case ContainerTopic::resourceDelta:
			{
				uint16_t nLogicalCores = parameters.nLogicalCores;
				uint32_t memoryMB = parameters.memoryMB;
				uint32_t storageMB = parameters.storageMB;
				bool isDownscale = false;
				uint32_t graceSeconds = 0;
				pendingResourceDeltaValid = false;

				if (ProdigyWire::deserializeResourceDeltaPayloadAuto(
					args,
					uint64_t(terminal - args),
					nLogicalCores,
					memoryMB,
					storageMB,
					isDownscale,
					graceSeconds) == false)
				{
					break;
				}

				pendingResourceDeltaCores = nLogicalCores;
				pendingResourceDeltaMemoryMB = memoryMB;
				pendingResourceDeltaStorageMB = storageMB;
				pendingResourceDeltaValid = true;

				target->resourceDelta(nLogicalCores, memoryMB, storageMB, isDownscale, graceSeconds);
				break;
			}
			case ContainerTopic::advertisementPairing:
			{
				uint128_t secret = 0;
				uint128_t address = 0;
				uint64_t service = 0;
				uint16_t applicationID = 0;
				bool activate = false;

				if (ProdigyWire::deserializeAdvertisementPairingPayloadAuto(
					args,
					uint64_t(terminal - args),
					secret,
					address,
					service,
					applicationID,
					activate) == false) break;

				uint64_t hash = AegisStream::generateSecretServiceHash(secret, service);
				basics_log("NeuronHub::neuronHandler advertisementPairing service=%llu app=%u activate=%d hash=%llu\n",
					(unsigned long long)service,
					unsigned(applicationID),
					int(activate),
					(unsigned long long)hash);

				target->advertisementPairing(secret, address, service, applicationID, activate);
				break;
			}
			case ContainerTopic::subscriptionPairing:
			{
				uint128_t secret = 0;
				uint128_t address = 0;
				uint64_t service = 0;
				uint16_t port = 0;
				uint16_t applicationID = 0;
				bool activate = false;

				if (ProdigyWire::deserializeSubscriptionPairingPayloadAuto(
					args,
					uint64_t(terminal - args),
					secret,
					address,
					service,
					port,
					applicationID,
					activate) == false) break;

				uint64_t hash = AegisStream::generateSecretServiceHash(secret, service);
				basics_log("NeuronHub::neuronHandler subscriptionPairing service=%llu port=%u app=%u activate=%d hash=%llu\n",
					(unsigned long long)service,
					unsigned(port),
					unsigned(applicationID),
					int(activate),
					(unsigned long long)hash);

				target->subscriptionPairing(secret, address, service, port, applicationID, activate);
				break;
			}
			case ContainerTopic::datacenterUniqueTag:
			{
				if ((terminal - args) != 1)
				{
					break;
				}

				parameters.datacenterUniqueTag = *args;
				break;
			}
				case ContainerTopic::message:
				{
					target->messageFromProdigy(message);
					break;
				}
				case ContainerTopic::statistics:
				{
					// statistics is a container->neuron path and should not arrive from neuron.
					break;
				}
				case ContainerTopic::resourceDeltaAck:
				{
					// resourceDeltaAck is a container->neuron path and should not arrive from neuron.
					break;
				}
				case ContainerTopic::credentialsRefresh:
				{
					if (args >= terminal)
					{
						// Empty payload is ack semantics in the container->neuron direction;
						// inbound empty refresh from neuron is ignored.
						break;
					}

					CredentialDelta delta;
					if (ProdigyWire::deserializeCredentialDeltaFramePayloadAuto(args, uint64_t(terminal - args), delta))
					{
						target->credentialsRefresh(delta);
					}

					break;
				}
            case ContainerTopic::wormholesRefresh:
            {
               if (args >= terminal)
               {
                  break;
               }

               String serializedWormholes = {};
               Message::extractToStringView(args, serializedWormholes);

               Vector<Wormhole> wormholes = {};
               if (BitseryEngine::deserializeSafe(serializedWormholes, wormholes))
               {
                  parameters.wormholes = wormholes;
                  target->wormholesRefresh(wormholes);
               }

               break;
            }
			}
		}
	
	  	void recvHandler(void *socket, int result) 
	  	{
	  		neuron.pendingRecv = false;
	  			
				if (unlikely(result <= 0)) socketFailed(&neuron);
				else
	  		{
	  			const uint64_t remaining = neuron.rBuffer.remainingCapacity();
	  			if (uint64_t(result) > remaining)
	  			{
	  				basics_log("NeuronHub::recv overflow result=%d remaining=%llu fd=%d fslot=%d\n",
	  					result,
	  					(unsigned long long)remaining,
	  					neuron.fd,
	  					neuron.fslot);
	  				neuron.rBuffer.clear();
	  				socketFailed(&neuron);
	  				return;
	  			}

	  			neuron.rBuffer.advance(result);

  			neuron.extractMessagesUnsafe<Message>([&] (Message *message) -> void {

		      neuronHandler(message);
		  	});

  			if (neuron.wBuffer.outstandingBytes() > 0) 
  			{
  				queueSendToNeuron();
  			}

		  	Ring::queueRecv(&neuron);
  		}
  	}

	void sendHandler(void *socket, int result)
	{
		if (socket != static_cast<void *>(&neuron))
		{
			return;
		}

		if (neuron.pendingSend == false)
		{
			// Ignore stale/duplicate send completions from prior socket generations.
			return;
		}

		neuron.pendingSend = false;
		uint32_t submittedBytes = neuron.pendingSendBytes;
		neuron.pendingSendBytes = 0;

		if (unlikely(result <= 0))
		{
			neuron.wBuffer.noteSendCompleted();
			// Failed sends can leave a partial frame at head. Drop it before reconnect.
			neuron.wBuffer.clear();
			socketFailed(&neuron);
			return;
		}

		if (submittedBytes == 0 || uint32_t(result) > submittedBytes)
		{
			const uint64_t outstanding = neuron.wBuffer.outstandingBytes();
			basics_log("NeuronHub::send overflow result=%d outstanding=%llu fd=%d fslot=%d\n",
				result,
				(unsigned long long)outstanding,
				neuron.fd,
				neuron.fslot);
			neuron.wBuffer.noteSendCompleted();
			neuron.wBuffer.clear();
			socketFailed(&neuron);
			return;
		}

		neuron.wBuffer.consume(result, false);
		neuron.wBuffer.noteSendCompleted();
		if (neuron.wBuffer.outstandingBytes() > 0)
		{
			queueSendToNeuron();
		}
	}

	 	void acceptHandler(void *socket, int fslot)
	 	{
	 		if (fslot >= 0)
	 		{
	 			neuron.fslot = fslot;
				neuron.isFixedFile = true;
				neuronInstalled = true;
				if (neuronMultiplexed == false)
				{
					RingDispatcher::installMultiplexee(&neuron, this);
					neuronMultiplexed = true;
				}
	 			Ring::queueRecv(&neuron);

	  			if (neuron.wBuffer.size() > 0)
	  			{
	  				queueSendToNeuron();
  			}
  		}
  		else
  		{
  			Ring::queueAccept(&soc);
  		}
  	}

   void shutdown(void)
   {
		Guardian::signalHandler(SIGINT, NULL, NULL);
   }

   void socketFailed(void *socket)
   {
		if (socket != static_cast<void *>(&neuron))
		{
			return;
		}

		if (Ring::socketIsClosing(&neuron))
		{
			return;
		}

		if (neuron.isFixedFile)
		{
			if (neuron.fslot >= 0)
			{
				Ring::queueCancelAll(&neuron);
				Ring::queueClose(&neuron);
			}
		}
		else if (neuron.fd >= 0)
		{
			basics_log("NeuronHub::socketFailed expected fixed-file neuron fd=%d fslot=%d isFixed=%d\n",
				neuron.fd, neuron.fslot, int(neuron.isFixedFile));
			std::abort();
		}

			neuron.reset();
			neuron.fslot = -1;
			neuron.isFixedFile = false;
			neuronInstalled = false;
	   }

		 	NeuronHub(NeuronHubDispatch *_target) : target(_target)
		 	{
		 		RingDispatcher::installMultiplexer(this);
	 		
	 		soc.setSocketPath("/neuron.soc");
				soc.saddr_storage = soc.daddr_storage;
				soc.saddrLen = soc.daddrLen;
				soc.recreateSocket();
				soc.bindThenListen();
				neuron.rBuffer.reserve(8_KB);
				neuron.wBuffer.reserve(16_KB);
		  	}
};
