#pragma once

#include <prodigy/overload.metrics.h>
#include <utility>
#include <time.h>

class InboundLatencyExporter
{
private:

   static constexpr uint64_t defaultFlushIntervalNs = 10'000'000'000ULL; // 10s

   ProdigyOverloadMetrics metrics;
   Vector<ProdigyOverloadMetrics::MetricPoint> metricPoints;
   Vector<std::pair<uint64_t, uint64_t>> metricPairs;
   uint64_t flushIntervalNs = defaultFlushIntervalNs;
   int64_t nextFlushAtNs = 0;

   static int64_t monotonicNowNs(void)
   {
      struct timespec ts = {};
      clock_gettime(CLOCK_MONOTONIC, &ts);
      return (int64_t(ts.tv_sec) * 1'000'000'000LL) + int64_t(ts.tv_nsec);
   }

   template <typename PublishFn>
   bool flushInternal(PublishFn&& publish)
   {
      metrics.flush(metricPoints);
      if (metricPoints.size() == 0)
      {
         return false;
      }

      metricPairs.clear();
      metricPairs.reserve(metricPoints.size());

      for (const auto& metric : metricPoints)
      {
         metricPairs.push_back({metric.key, metric.value});
      }

      return publish(metricPairs);
   }

public:

   void setFlushIntervalMs(uint64_t intervalMs)
   {
      if (intervalMs == 0)
      {
         return;
      }

      flushIntervalNs = intervalMs * 1'000'000ULL;
   }

   void observe(uint64_t queueWaitNs, uint64_t handlerNs)
   {
      metrics.observe(queueWaitNs, handlerNs);
   }

   template <typename PublishFn>
   void flushIfDue(PublishFn&& publish)
   {
      int64_t nowNs = monotonicNowNs();

      if (nextFlushAtNs == 0)
      {
         nextFlushAtNs = nowNs + int64_t(flushIntervalNs);
         return;
      }

      if (nowNs < nextFlushAtNs)
      {
         return;
      }

      (void)flushInternal(std::forward<PublishFn>(publish));
      nextFlushAtNs = nowNs + int64_t(flushIntervalNs);
   }

   template <typename PublishFn>
   void flushNow(PublishFn&& publish)
   {
      int64_t nowNs = monotonicNowNs();
      (void)flushInternal(std::forward<PublishFn>(publish));
      nextFlushAtNs = nowNs + int64_t(flushIntervalNs);
   }
};
