#pragma once

#include <utility>
#include <cstring>

#include <prodigy/types.h>

static inline const String mothershipNonRetryableFailurePrefix = "[mothership-final] "_ctv;

static inline bool mothershipFailureIsNonRetryable(const String& failure)
{
   return failure.size() >= mothershipNonRetryableFailurePrefix.size()
      && std::memcmp(failure.data(), mothershipNonRetryableFailurePrefix.data(), size_t(mothershipNonRetryableFailurePrefix.size())) == 0;
}

static inline void mothershipMarkFailureNonRetryable(String& failure)
{
   if (mothershipFailureIsNonRetryable(failure))
   {
      return;
   }

   String marked = {};
   marked.append(mothershipNonRetryableFailurePrefix);
   marked.append(failure);
   failure = marked;
}

static inline void mothershipStripNonRetryableFailurePrefix(String& failure)
{
   if (mothershipFailureIsNonRetryable(failure) == false)
   {
      return;
   }

   failure.assign(failure.substr(mothershipNonRetryableFailurePrefix.size(), failure.size() - mothershipNonRetryableFailurePrefix.size(), Copy::yes));
}

template<typename ReceiveNextResponseFn, typename ProgressFn>
static inline bool mothershipAwaitAddMachinesResponse(ReceiveNextResponseFn&& receiveNextResponse, ProgressFn&& onProgress, AddMachines& response, String& failure)
{
   response = {};

   for (;;)
   {
      String serializedResponse = {};
      if (receiveNextResponse(serializedResponse, failure) == false)
      {
         response = {};
         return false;
      }

      if (BitseryEngine::deserializeSafe(serializedResponse, response) == false)
      {
         response = {};
         failure.assign("addMachines response decode failed"_ctv);
         return false;
      }

      if (response.isProgress)
      {
         onProgress(response.provisioningProgress);
         response = {};
         continue;
      }

      break;
   }

   if (response.success == false)
   {
      failure = response.failure.size() > 0 ? response.failure : "addMachines failed"_ctv;
      mothershipMarkFailureNonRetryable(failure);
      return false;
   }

   failure.clear();
   return true;
}
