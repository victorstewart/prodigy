#pragma once

#include <networking/includes.h>
#include <types/types.containers.h>

#include <future>
#include <type_traits>
#include <utility>
#include <vector>

template <typename Item, typename BootstrapFn, typename RollbackFn>
static inline bool prodigyBootstrapItemsConcurrently(const Vector<Item>& items, BootstrapFn&& bootstrapFn, RollbackFn&& rollbackFn, Vector<Item>* bootstrappedItems, String& failure)
{
   failure.clear();
   if (bootstrappedItems != nullptr)
   {
      bootstrappedItems->clear();
   }

   if (items.empty())
   {
      return true;
   }

   class BootstrapResult
   {
   public:

      Item item = {};
      bool success = false;
      String failure;
   };

   std::vector<std::future<BootstrapResult>> futures;
   futures.reserve(items.size());

   auto bootstrap = std::ref(bootstrapFn);
   for (const Item& item : items)
   {
      futures.emplace_back(std::async(std::launch::async, [bootstrap, item]() mutable -> BootstrapResult {

         BootstrapResult result = {};
         result.item = item;
         result.success = bootstrap.get()(result.item, result.failure);
         return result;
      }));
   }

   bool failed = false;
   auto rollback = std::ref(rollbackFn);
   for (std::future<BootstrapResult>& future : futures)
   {
      BootstrapResult result = future.get();
      if (result.success)
      {
         if (bootstrappedItems != nullptr)
         {
            bootstrappedItems->push_back(result.item);
         }

         continue;
      }

      if (failed == false)
      {
         failure = result.failure;
         failed = true;
      }
   }

   if (failed == false)
   {
      return true;
   }

   if (bootstrappedItems != nullptr)
   {
      for (const Item& item : *bootstrappedItems)
      {
         rollback.get()(item);
      }
   }

   return false;
}
