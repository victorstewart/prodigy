#pragma once

#include <networking/bgp.h>
#include <prodigy/iaas/iaas.h>
#include <prodigy/types.h>

class NeuronBGPHub final : public BGPHub {
public:

   void hasShutdownBGP(void) override
   {
   }
};

class NeuronBGPRuntime {
private:

   NeuronBGPHub hub;
   NeuronBGPConfig config;
   bool configured = false;
   Vector<IPPrefix> machinePrefixes;
   Vector<IPPrefix> publicPrefixes;

   static bool prefixPresent(const Vector<IPPrefix>& haystack, const IPPrefix& needle)
   {
      for (const IPPrefix& candidate : haystack)
      {
         if (candidate.equals(needle))
         {
            return true;
         }
      }

      return false;
   }

   void announcePrefixIfPossible(const IPPrefix& prefix)
   {
      if (configured == false)
      {
         return;
      }

      const IPAddress& nextHop = prefix.network.is6 ? config.nextHop6 : config.nextHop4;
      if (nextHop.isNull())
      {
         return;
      }

      if (config.community > 0)
      {
         hub.announceWithCommunity(prefix, nextHop, config.community);
      }
      else
      {
         hub.announceLocalPrefix(prefix, nextHop);
      }
   }

   void withdrawPrefixIfUnused(const IPPrefix& prefix, const Vector<IPPrefix>& retained)
   {
      if (configured == false)
      {
         return;
      }

      if (prefixPresent(retained, prefix))
      {
         return;
      }

      hub.withdrawPrefix(prefix);
   }

   void reconcilePrefixSet(Vector<IPPrefix>& currentSet, const Vector<IPPrefix>& desiredSet, const Vector<IPPrefix>& otherSet)
   {
      Vector<IPPrefix> previousSet = currentSet;

      for (const IPPrefix& prefix : previousSet)
      {
         if (prefixPresent(desiredSet, prefix) == false)
         {
            withdrawPrefixIfUnused(prefix, otherSet);
         }
      }

      currentSet = desiredSet;

      for (const IPPrefix& prefix : currentSet)
      {
         if (prefixPresent(previousSet, prefix) == false && prefixPresent(otherSet, prefix) == false)
         {
            announcePrefixIfPossible(prefix);
         }
      }
   }

public:

   void configure(const NeuronBGPConfig& newConfig)
   {
      if (configured)
      {
         return;
      }

      config = newConfig;
      if (config.enabled == false)
      {
         return;
      }

      configured = true;
      hub.ourBGPID = config.ourBGPID;

      for (const NeuronBGPPeerConfig& peer : config.peers)
      {
         if (peer.md5Password.size() > 0)
         {
            if (peer.hopLimit > 0)
            {
               hub.addPeer(peer.peerASN, peer.peerAddress, peer.sourceAddress, peer.md5Password, peer.hopLimit);
            }
            else
            {
               hub.addPeer(peer.peerASN, peer.peerAddress, peer.sourceAddress, peer.md5Password);
            }
         }
         else
         {
            hub.addPeer(peer.peerASN, peer.peerAddress, peer.sourceAddress);
         }
      }

      for (const IPPrefix& prefix : machinePrefixes)
      {
         announcePrefixIfPossible(prefix);
      }

      for (const IPPrefix& prefix : publicPrefixes)
      {
         if (prefixPresent(machinePrefixes, prefix) == false)
         {
            announcePrefixIfPossible(prefix);
         }
      }
   }

   void resetPublicRoutablePrefixes(void)
   {
      Vector<IPPrefix> noPrefixes;
      reconcilePrefixSet(publicPrefixes, noPrefixes, machinePrefixes);
   }

   void setMachinePrefixes(const Vector<IPPrefix>& desiredPrefixes)
   {
      reconcilePrefixSet(machinePrefixes, desiredPrefixes, publicPrefixes);
   }

   void setPublicRoutableSubnets(const Vector<DistributableExternalSubnet>& subnets)
   {
      Vector<IPPrefix> desiredPrefixes;

      for (const DistributableExternalSubnet& subnet : subnets)
      {
         if (subnet.routing == ExternalSubnetRouting::switchboardBGP)
         {
            desiredPrefixes.push_back(subnet.subnet);
         }
      }

      reconcilePrefixSet(publicPrefixes, desiredPrefixes, machinePrefixes);
   }
};
