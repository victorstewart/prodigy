#include <prodigy/brain/metrics.h>
#include <services/debug.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static bool approximatelyEqual(double lhs, double rhs, double epsilon = 1e-6)
{
   return std::fabs(lhs - rhs) <= epsilon;
}

static double interpolatePercentile(Vector<float> samples, double percentile)
{
   if (samples.size() == 0) return 0;
   if (samples.size() == 1) return samples[0];

   std::sort(samples.begin(), samples.end());

   const double position = percentile * double(samples.size() - 1);
   const uint32_t lowerIndex = uint32_t(position);
   const uint32_t upperIndex = (lowerIndex + 1 < samples.size()) ? (lowerIndex + 1) : lowerIndex;
   const double fraction = position - double(lowerIndex);

   const double lowerValue = samples[lowerIndex];
   const double upperValue = samples[upperIndex];
   return lowerValue + ((upperValue - lowerValue) * fraction);
}

static void makeDeterministicSamples(Vector<float>& out, uint32_t count, uint64_t seed)
{
   out.clear();
   out.reserve(count);

   uint64_t state = seed;
   for (uint32_t i = 0; i < count; ++i)
   {
      state = (state * 6364136223846793005ULL) + 1442695040888963407ULL;
      const uint32_t high = uint32_t(state >> 32);
      const double normalized = double(high) / double(0xFFFFFFFFu);
      const float jitter = float((int64_t(i % 37) - 18) * 0.03125);
      out.push_back(float((normalized * 2000.0) - 1000.0) + jitter);
   }
}

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

int main(void)
{
   TestSuite suite;

   MetricsStore store;

   const uint64_t deploymentID = 11;
   const uint64_t metricKey = 0xAA55;
   const uint128_t containerA = uint128_t(0x1001);
   const uint128_t containerB = uint128_t(0x1002);

   {
      Vector<float> out;
      store.collectValues(deploymentID, nullptr, metricKey, 10'000, 5'000, true, out);
      suite.expect(out.size() == 0, "empty_collect_fleet");
   }

   // Insert base samples for two containers.
   store.record(deploymentID, containerA, metricKey, 1'000, 10.0);
   store.record(deploymentID, containerA, metricKey, 2'000, 20.0);
   store.record(deploymentID, containerB, metricKey, 2'500, 30.0);
   store.record(deploymentID, containerB, metricKey, 3'000, 40.0);

   {
      Vector<float> out;
      store.collectValues(deploymentID, nullptr, metricKey, 3'000, 2'000, true, out); // cutoff = 1'000
      suite.expect(out.size() == 4, "fleet_collect_count");
   }

   {
      Vector<float> out;
      store.collectValues(deploymentID, &containerA, metricKey, 3'000, 2'000, false, out); // cutoff = 1'000
      suite.expect(out.size() == 2, "container_collect_count");
      suite.expect(approximatelyEqual(out[0], 10.0) && approximatelyEqual(out[1], 20.0), "container_collect_values");
   }

   {
      Vector<float> out;
      store.collectValues(deploymentID, nullptr, metricKey, 3'000, 500, true, out); // cutoff = 2'500
      suite.expect(out.size() == 2, "lookback_cutoff_count");
      suite.expect(approximatelyEqual(out[0], 30.0) && approximatelyEqual(out[1], 40.0), "lookback_cutoff_boundary_inclusive");
   }

   {
      MetricsStore monotonicStore;
      monotonicStore.record(deploymentID, containerA, metricKey, 10'000, 1.0);
      monotonicStore.record(deploymentID, containerA, metricKey, 9'000, 2.0); // out-of-order timestamp
      Vector<float> out;
      monotonicStore.collectValues(deploymentID, &containerA, metricKey, 10'000, 100, false, out); // cutoff = 9'900
      suite.expect(out.size() == 2, "monotonic_timestamp_clamp");
   }

   {
      MetricsStore growthStore;
      for (uint32_t i = 0; i < 8'192; ++i)
      {
         growthStore.record(deploymentID, containerA, metricKey, int64_t(i + 1), double(i));
      }

      Vector<float> out;
      growthStore.collectValues(deploymentID, nullptr, metricKey, 8'192, 8'192, true, out);
      suite.expect(out.size() == 8'192, "ring_growth_preserves_all_samples");
      suite.expect(approximatelyEqual(out.front(), 0.0) && approximatelyEqual(out.back(), 8'191.0), "ring_growth_value_order");
   }

   {
      MetricsStore trimStore;
      for (uint32_t i = 0; i < 100; ++i)
      {
         trimStore.record(deploymentID, containerA, metricKey, int64_t(i * 100), double(i));
      }

      trimStore.trimRetention(9'900, 2'000); // cutoff = 7'900

      Vector<float> out;
      trimStore.collectValues(deploymentID, nullptr, metricKey, 9'900, 10'000, true, out);
      suite.expect(out.size() == 21, "retention_trim_count");
      suite.expect(approximatelyEqual(out.front(), 79.0) && approximatelyEqual(out.back(), 99.0), "retention_trim_values");
   }

   {
      MetricsStore wrapStore;
      for (uint32_t i = 0; i < 20'000; ++i)
      {
         const int64_t nowMs = int64_t(i + 1);
         wrapStore.record(deploymentID, containerA, metricKey, nowMs, double(i % 100));
         if ((i % 64) == 0)
         {
            wrapStore.trimRetention(nowMs, 2'048);
         }
      }

      Vector<float> out;
      wrapStore.collectValues(deploymentID, nullptr, metricKey, 20'000, 2'048, true, out);
      suite.expect(out.size() > 0 && out.size() <= (2'048 + 64), "wraparound_collect_respects_window");
   }

   {
      Vector<float> out;
      store.collectValues(deploymentID, nullptr, metricKey, 3'000, 2'000, true, out);
      const double p9137 = interpolatePercentile(out, 0.9137);
      const double p50 = interpolatePercentile(out, 0.50);
      suite.expect(approximatelyEqual(p9137, 37.411, 1e-3), "arbitrary_percentile_91_37");
      suite.expect(approximatelyEqual(p50, 25.0, 1e-6), "median_percentile_50");
   }

   {
      Vector<float> samples;
      makeDeterministicSamples(samples, 4'096, 0xBADC0FFEEULL);

      const double percentiles[] = {
         0.001,
         0.0175,
         0.1375,
         0.333333,
         0.5,
         0.9137,
         0.950001,
         0.999
      };

      for (uint32_t i = 0; i < uint32_t(sizeof(percentiles) / sizeof(percentiles[0])); ++i)
      {
         const double p = percentiles[i];

         Vector<float> expectedSamples = samples;
         const double expected = interpolatePercentile(expectedSamples, p);

         Vector<float> scalarSamples = samples;
         const double scalar = metricsPercentileSelectScalar(scalarSamples, p);

         Vector<float> dispatchSamples = samples;
         const double dispatch = metricsPercentileSelect(dispatchSamples, p);

         char scalarName[96];
         char dispatchName[96];
         std::snprintf(scalarName, sizeof(scalarName), "percentile_scalar_ab_%u", i);
         std::snprintf(dispatchName, sizeof(dispatchName), "percentile_dispatch_ab_%u", i);
         suite.expect(approximatelyEqual(scalar, expected, 1e-4), scalarName);
         suite.expect(approximatelyEqual(dispatch, expected, 1e-4), dispatchName);

         #if defined(__x86_64__) || defined(__i386__)
         if (metricsCpuSupportsAVX512F())
         {
            Vector<float> avxSamples = samples;
            const double avx = metricsPercentileSelectAVX512Kernel(avxSamples, p);
            char avxName[96];
            std::snprintf(avxName, sizeof(avxName), "percentile_avx512_ab_%u", i);
            suite.expect(approximatelyEqual(avx, expected, 1e-4), avxName);
         }
         #endif
      }
   }

   {
      Vector<float> repeated;
      repeated.reserve(2'048);
      for (uint32_t i = 0; i < 2'048; ++i)
      {
         repeated.push_back(float(i % 16));
      }

      Vector<float> expectedSamples = repeated;
      const double expected = interpolatePercentile(expectedSamples, 0.9255);
      Vector<float> scalarSamples = repeated;
      Vector<float> dispatchSamples = repeated;
      const double scalar = metricsPercentileSelectScalar(scalarSamples, 0.9255);
      const double dispatch = metricsPercentileSelect(dispatchSamples, 0.9255);
      suite.expect(approximatelyEqual(scalar, expected, 1e-6), "percentile_repeated_scalar");
      suite.expect(approximatelyEqual(dispatch, expected, 1e-6), "percentile_repeated_dispatch");
   }

   {
      float src[1024];
      float dst[1024];
      for (uint32_t i = 0; i < 1024; ++i)
      {
         src[i] = float(i) * 0.25f;
         dst[i] = 0.0f;
      }
      metricsCopyFloat(src, dst, 1024);
      suite.expect(std::memcmp(src, dst, sizeof(src)) == 0, "simd_copy_matches_memcpy");
   }

   {
      MetricsStore multiMetricStore;
      const uint64_t metricA = 100;
      const uint64_t metricB = 101;

      for (uint32_t i = 0; i < 500; ++i)
      {
         multiMetricStore.record(deploymentID, containerA, metricA, int64_t(i + 1), double(i));
         multiMetricStore.record(deploymentID, containerA, metricB, int64_t(i + 1), double(500 - i));
      }

      Vector<float> outA;
      Vector<float> outB;
      multiMetricStore.collectValues(deploymentID, nullptr, metricA, 500, 250, true, outA);
      multiMetricStore.collectValues(deploymentID, nullptr, metricB, 500, 250, true, outB);

      suite.expect(outA.size() == 251 && outB.size() == 251, "multi_metric_group_window_count");
      suite.expect(approximatelyEqual(outA.front(), 249.0) && approximatelyEqual(outB.front(), 251.0), "multi_metric_group_window_values");
   }

   {
      ProdigyMetricSamplesSnapshot snapshot = {};
      constexpr uint32_t sampleCount = 70'000;
      snapshot.samples.reserve(sampleCount);

      for (uint32_t index = 0; index < sampleCount; ++index)
      {
         ProdigyMetricSample sample = {};
         sample.ms = 1800000000000 + int64_t(index);
         sample.deploymentID = deploymentID;
         sample.containerUUID = containerA + index;
         sample.metricKey = metricKey;
         sample.value = float(index % 4096);
         snapshot.samples.push_back(sample);
      }

      String serialized = {};
      BitseryEngine::serialize(serialized, snapshot);

      ProdigyMetricSamplesSnapshot decoded = {};
      const bool deserialized = BitseryEngine::deserializeSafe(serialized, decoded);
      suite.expect(deserialized, "metric_snapshot_above_uint16_deserializes");
      suite.expect(decoded.samples.size() == sampleCount, "metric_snapshot_above_uint16_count");
      suite.expect(
         decoded.samples.size() == sampleCount
            && decoded.samples.front() == snapshot.samples.front()
            && decoded.samples.back() == snapshot.samples.back(),
         "metric_snapshot_above_uint16_edges");
   }

   if (suite.failed != 0)
   {
      basics_log("METRICS_UNIT_FAIL failed=%d\n", suite.failed);
      return EXIT_FAILURE;
   }

   basics_log("METRICS_UNIT_PASS\n");
   return EXIT_SUCCESS;
}
