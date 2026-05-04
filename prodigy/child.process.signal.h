#pragma once

#include <signal.h>

static inline bool prodigySigchldIsDefaultWaitable(const struct sigaction& action)
{
   return action.sa_handler == SIG_DFL && (action.sa_flags & SA_NOCLDWAIT) == 0;
}

static inline bool prodigyEnsureSigchldDefaultWaitable(void)
{
   struct sigaction currentSigChld = {};
   if (sigaction(SIGCHLD, nullptr, &currentSigChld) != 0)
   {
      return false;
   }

   if (prodigySigchldIsDefaultWaitable(currentSigChld))
   {
      return true;
   }

   struct sigaction defaultSigChld = {};
   sigemptyset(&defaultSigChld.sa_mask);
   defaultSigChld.sa_handler = SIG_DFL;
   defaultSigChld.sa_flags = 0;
   return sigaction(SIGCHLD, &defaultSigChld, nullptr) == 0;
}
