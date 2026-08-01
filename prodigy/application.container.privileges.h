#pragma once

#include <sys/capability.h>

#include <prodigy/types.h>

static inline bool prodigyApplicationContainerPrivilegesAllowed(
    bool useHostNetworkNamespace,
    const ApplicationConfig& config)
{
   if (useHostNetworkNamespace)
   {
      return false;
   }
   for (int capability : config.capabilities)
   {
      if (capability != CAP_NET_BIND_SERVICE && capability != CAP_IPC_LOCK)
      {
         return false;
      }
   }
   return true;
}
