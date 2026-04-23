#include <networking/icmp.h>

#pragma once

class PingSubscriber {
public:

	virtual void machinePingable(MachineBase *machine) = 0;
	virtual void machineUnpingable(MachineBase *machine) = 0;
};

class MachinePinger : public ICMPSocket, public RingInterface, public RecvmsgMultishoter {
private:

  class Pingee {
  public:

      MachineBase *machine;

      uint32_t nOutstanding = 0;

      // one of these is non-zero
      int64_t untilMs = 0;
      uint32_t nRemaining = 0;
      bool finiteCount = false;

      // basic rate limiting / backoff scheduling
      int64_t nextMs = 0;     // earliest time to send next ping

		bool indefinitely(void)
		{
			return (untilMs == 0 && finiteCount == false);
		}
	};

	#define IP_DF 0x4000

	static inline constexpr uint32_t ping_interval_ms = 250;

	using ICMPMessage = msg<0, sizeof(struct iphdr) + sizeof(struct icmphdr) >;

	Pool<ICMPMessage, true> pool{256};
	bytell_hash_map<uint32_t, Pingee *> pingeesByPrivate4;

	PingSubscriber *subscriber;
	uint32_t src;

	TimeoutPacket timer;

	uint16_t calculate_checksum(const uint8_t *data, size_t length) 
	{
   	uint32_t sum = 0;

    	// Sum up all 16-bit words
    	for (size_t i = 0; i < length; i += 2) 
    	{
      	uint16_t word = (data[i] << 8) + (i + 1 < length ? data[i + 1] : 0);
        	sum += word;
    	}

    	// Add the carry bits back to the sum
    	while (sum >> 16) 
    	{
      	sum = (sum & 0xFFFF) + (sum >> 16);
    	}

   	// Return the one's complement of the sum
    	return ~sum;
	}

	Pingee* createPingee(MachineBase *machine)
	{
		Pingee *pingee = new Pingee();
		pingee->machine = machine;
		pingee->finiteCount = false;
		pingee->nRemaining = 0;
		pingee->nextMs = 0;
		pingeesByPrivate4.insert_or_assign(machine->private4, pingee);

		if (pingeesByPrivate4.size() == 1) Ring::queueTimeoutMultishot(&timer);

		return pingee;
	}

public:

	MachinePinger() = default;

	~MachinePinger()
	{
		RingDispatcher::eraseMultiplexee(this);
		Ring::queueCancelTimeout(&timer);

		if (isFixedFile && fslot >= 0 && Ring::getRingFD() > 0)
		{
			Ring::queueCloseRaw(fslot);
			fslot = -1;
		}
		else if (isFixedFile == false && fd >= 0)
		{
			::close(fd);
			fd = -1;
		}

		isFixedFile = false;

		for (auto& [private4, pingee] : pingeesByPrivate4)
		{
			(void)private4;
			delete pingee;
		}
		pingeesByPrivate4.clear();
	}

   void sendPing(Pingee *pingee)
   {
      pingee->nOutstanding += 1;

      ICMPMessage *message = pool.get();

      struct iphdr *ip_hdr = (struct iphdr *)message->payload();
      ip_hdr->ihl = 5;  // Header length (5 words, 20 bytes)
      ip_hdr->version = 4;
      ip_hdr->tos = 0;
      ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
      ip_hdr->id = 0;
      ip_hdr->frag_off = htons(IP_DF); // don't frag
      ip_hdr->ttl = 64;
      ip_hdr->protocol = IPPROTO_ICMP;
      ip_hdr->check = 0;
      ip_hdr->saddr = src;
      ip_hdr->daddr = pingee->machine->private4;
      ip_hdr->check = calculate_checksum((uint8_t *)ip_hdr, sizeof(*ip_hdr));

      struct icmphdr *icmp_hdr = (struct icmphdr *)(message->payload() + sizeof(struct iphdr));
      icmp_hdr->type = ICMP_ECHO;
      icmp_hdr->checksum = calculate_checksum((uint8_t *)icmp_hdr, sizeof(struct icmphdr));

      message->setPayloadLen(sizeof(struct iphdr) + sizeof(struct icmphdr));

      Ring::queueSendmsg(this, reinterpret_cast<msghdr *>(message));

      if (pingee->finiteCount && pingee->nRemaining > 0)
      {
         pingee->nRemaining -= 1;
      }

      int64_t jitter = Random::generateNumberWithNBits<16, uint32_t>() % 50;
      pingee->nextMs = Time::now<TimeResolution::ms>() + ping_interval_ms + jitter;
   }

   void pingSent(struct msghdr *msg, int result)
   {
      // check the result?

      ICMPMessage *message = reinterpret_cast<ICMPMessage *>(msg);

      pool.relinquish(message);
   }

   void receivePing(uint8_t *payload)
   {
      // read the source address on the ip header
      struct iphdr *ip_hdr = (struct iphdr *)payload;

      auto it = pingeesByPrivate4.find(ip_hdr->saddr);

      if (it != pingeesByPrivate4.end())
      {
         Pingee *pingee = it->second;
         pingee->nOutstanding = 0;

         if (pingee->indefinitely() == false)
         {
            subscriber->machinePingable(pingee->machine);

            delete pingee;
            pingeesByPrivate4.erase(it);
            if (pingeesByPrivate4.size() == 0) Ring::queueCancelTimeout(&timer);
         }
      }
   }

   void sendPings(void)
   {
      int64_t nowMs = Time::now<TimeResolution::ms>();

      for (auto it = pingeesByPrivate4.begin(); it != pingeesByPrivate4.end(); )
      {
         Pingee *pingee = it->second;
         bool erase = false;

         if (pingee->untilMs > 0 && nowMs >= pingee->untilMs)
         {
            if (pingee->nOutstanding > 0)
            {
               subscriber->machineUnpingable(pingee->machine);
            }

            erase = true;
         }
         else if (pingee->nextMs <= nowMs)
         {
            if (pingee->finiteCount)
            {
               if (pingee->nRemaining == 0)
               {
                  if (pingee->nOutstanding > 0)
                  {
                     subscriber->machineUnpingable(pingee->machine);
                  }

                  erase = true;
               }
               else
               {
                  sendPing(pingee);
               }
            }
            else
            {
               sendPing(pingee);
            }
         }

         if (erase)
         {
            delete pingee;
            auto eraseIt = it++;
            pingeesByPrivate4.erase(eraseIt);
         }
         else
         {
            ++it;
         }
      }

      if (pingeesByPrivate4.size() == 0) Ring::queueCancelTimeout(&timer);
   }

   void pingMachine(MachineBase *machine)
   {
      Pingee *pingee = createPingee(machine);

      pingee->finiteCount = false;
      pingee->nRemaining = 0;

      sendPing(pingee);
   }

   void pingMachineN(MachineBase *machine, uint32_t nTimes)
   {
      Pingee *pingee = createPingee(machine);
      pingee->finiteCount = true;
      pingee->nRemaining = nTimes;

      sendPing(pingee);
   }

   void pingMachineUntil(MachineBase *machine, int64_t nMs)
   {
      Pingee *pingee = createPingee(machine);
      pingee->untilMs = nMs + Time::now<TimeResolution::ms>();
      pingee->finiteCount = false;
      pingee->nRemaining = 0;

      sendPing(pingee);
   }

	void removeMachine(MachineBase *machine)
	{
		if (auto it = pingeesByPrivate4.find(machine->private4); it != pingeesByPrivate4.end())
		{
			Pingee *pingee = it->second;
			delete pingee;
			pingeesByPrivate4.erase(it);

			if (pingeesByPrivate4.size() == 0) Ring::queueCancelTimeout(&timer);
		}
	}

		void configure(PingSubscriber *_subscriber, uint32_t ourPrivate4)
		{
			subscriber = _subscriber;
			src = ourPrivate4;
			RingDispatcher::installMultiplexee(this, this);
			Ring::installFDIntoFixedFileSlot(this);

			bgid = Ring::createBufferRing(sizeof(struct io_uring_recvmsg_out) + sizeof(struct iphdr) + sizeof(struct icmphdr), 256);
			Ring::queueRecvmsgMultishot(this);

		timer.originator = this;
		timer.setTimeoutMs(ping_interval_ms);
	}

	void recvmsgMultishotHandler(void *socket, struct io_uring_recvmsg_out *package, int result, bool mustRefresh)
	{
		if (result > 0 && package)
		{
			uint8_t *payload = reinterpret_cast<uint8_t *>(io_uring_recvmsg_payload(package, &msgh));
			receivePing(payload);
		}

		if (package)
		{
			Ring::relinquishBufferToRing(this, reinterpret_cast<uint8_t *>(package));
		}
		if (mustRefresh) Ring::queueRecvmsgMultishot(this);
	}

	void sendmsgHandler(void *socket, struct msghdr *msg, int result)
	{
		pingSent(msg, result);
	}

	void timeoutMultishotHandler(TimeoutPacket *packet, int result)
	{
		sendPings();
	}
};
