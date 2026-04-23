#include <prodigy/cluster.bootstrap.h>
#include <services/debug.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <thread>

class TestSuite
{
public:

   int failed = 0;

   void expect(bool condition, const char *name)
   {
      if (condition)
      {
         basics_log("PASS: %s\n", name);
      }
      else
      {
         basics_log("FAIL: %s\n", name);
         failed += 1;
      }
   }
};

static bool sameUIntVector(const Vector<uint32_t>& lhs, std::initializer_list<uint32_t> rhs)
{
   if (lhs.size() != rhs.size())
   {
      return false;
   }

   uint32_t index = 0;
   for (uint32_t value : rhs)
   {
      if (lhs[index] != value)
      {
         return false;
      }

      index += 1;
   }

   return true;
}

int main(void)
{
   TestSuite suite;

   {
      Vector<uint32_t> items;
      items.push_back(1);
      items.push_back(2);
      items.push_back(3);

      std::mutex gateMutex;
      std::condition_variable gateCondition;
      uint32_t entered = 0;
      std::atomic<uint32_t> inFlight{0};
      std::atomic<uint32_t> maxInFlight{0};
      Vector<uint32_t> bootstrappedItems;
      String failure = {};

      bool ok = prodigyBootstrapItemsConcurrently<uint32_t>(
         items,
         [&](const uint32_t& item, String& bootstrapFailure) -> bool {

            (void)item;
            bootstrapFailure.clear();

            uint32_t currentInFlight = inFlight.fetch_add(1) + 1;
            uint32_t observedMax = maxInFlight.load();
            while (currentInFlight > observedMax && maxInFlight.compare_exchange_weak(observedMax, currentInFlight) == false)
            {
            }

            {
               std::unique_lock<std::mutex> lock(gateMutex);
               entered += 1;
               gateCondition.notify_all();
               gateCondition.wait(lock, [&]() -> bool {

                  return entered == items.size();
               });
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            inFlight.fetch_sub(1);
            return true;
         },
         [&](const uint32_t&) -> void {
         },
         &bootstrappedItems,
         failure);

      suite.expect(ok, "bootstrap_items_concurrently_success");
      suite.expect(failure.size() == 0, "bootstrap_items_concurrently_success_failure_empty");
      suite.expect(maxInFlight.load() >= 2, "bootstrap_items_concurrently_overlaps_work");
      suite.expect(sameUIntVector(bootstrappedItems, { 1, 2, 3 }), "bootstrap_items_concurrently_tracks_successes");
   }

   {
      Vector<uint32_t> items;
      items.push_back(1);
      items.push_back(2);
      items.push_back(3);

      std::mutex gateMutex;
      std::condition_variable gateCondition;
      uint32_t entered = 0;
      Vector<uint32_t> stoppedItems;
      Vector<uint32_t> bootstrappedItems;
      String failure = {};

      bool ok = prodigyBootstrapItemsConcurrently<uint32_t>(
         items,
         [&](const uint32_t& item, String& bootstrapFailure) -> bool {

            {
               std::unique_lock<std::mutex> lock(gateMutex);
               entered += 1;
               gateCondition.notify_all();
               gateCondition.wait(lock, [&]() -> bool {

                  return entered == items.size();
               });
            }

            if (item == 2)
            {
               bootstrapFailure.assign("machine 2 failed"_ctv);
               return false;
            }

            bootstrapFailure.clear();
            return true;
         },
         [&](const uint32_t& item) -> void {

            stoppedItems.push_back(item);
         },
         &bootstrappedItems,
         failure);

      suite.expect(ok == false, "bootstrap_items_concurrently_failure");
      suite.expect(failure == "machine 2 failed"_ctv, "bootstrap_items_concurrently_failure_reason");
      suite.expect(sameUIntVector(bootstrappedItems, { 1, 3 }), "bootstrap_items_concurrently_records_successes_before_rollback");
      suite.expect(sameUIntVector(stoppedItems, { 1, 3 }), "bootstrap_items_concurrently_rolls_back_only_successes");
   }

   return suite.failed == 0 ? 0 : 1;
}
