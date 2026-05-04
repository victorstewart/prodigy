#pragma once

#include <prodigy/iaas/iaas.h>
#include <prodigy/brain/machine.h>

static inline bool mothershipDestroyProviderMachines(BrainIaaS& iaas, const Vector<String>& cloudIDs, String *failure = nullptr)
{
   if (failure) failure->clear();

   for (const String& cloudID : cloudIDs)
   {
      if (cloudID.size() == 0)
      {
         if (failure) failure->assign("cloudID required"_ctv);
         return false;
      }

      Machine machine = {};
      machine.cloudID = cloudID;
      iaas.destroyMachine(&machine);
   }

   return true;
}

static inline bool mothershipDestroyProviderClusterMachines(BrainIaaS& iaas, const String& clusterUUID, uint32_t& destroyed, String *failure = nullptr)
{
   if (failure) failure->clear();
   destroyed = 0;

   if (clusterUUID.size() == 0)
   {
      if (failure) failure->assign("clusterUUID required"_ctv);
      return false;
   }

   String error = {};
   if (iaas.destroyClusterMachines(clusterUUID, destroyed, error) == false)
   {
      if (failure) *failure = error;
      return false;
   }

   return true;
}
