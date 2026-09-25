#pragma once

#include <networking/includes.h>
#include <prodigy/types.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <vector>

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#endif

struct Measurement {
  int64_t ms;
  uint64_t deploymentID;
  uint128_t containerUUID;
  uint64_t metricKey;
  float value;
};

inline bool metricsCpuSupportsAVX512F(void)
{
#if defined(__x86_64__) || defined(__i386__)
#if defined(__clang__) || defined(__GNUC__)
  static int supported = -1;
  if (supported == -1)
  {
    __builtin_cpu_init();
    supported = __builtin_cpu_supports("avx512f") ? 1 : 0;
  }
  return supported == 1;
#else
  return false;
#endif
#else
  return false;
#endif
}

#if defined(__x86_64__) || defined(__i386__)
__attribute__((target("avx512f"))) inline void metricsCopyFloatAVX512(const float *src, float *dst, size_t count)
{
  size_t i = 0;
  for (; i + 16 <= count; i += 16)
  {
    __m512 v = _mm512_loadu_ps(src + i);
    _mm512_storeu_ps(dst + i, v);
  }
  if (i < count)
  {
    memcpy(dst + i, src + i, (count - i) * sizeof(float));
  }
}
#endif

inline void metricsCopyFloat(const float *src, float *dst, size_t count)
{
  if (count == 0)
  {
    return;
  }

#if defined(__x86_64__) || defined(__i386__)
  // Large contiguous windows benefit from explicit AVX-512 copy when available.
  if (count >= 128 && metricsCpuSupportsAVX512F())
  {
    metricsCopyFloatAVX512(src, dst, count);
    return;
  }
#endif

  memcpy(dst, src, count * sizeof(float));
}

inline float metricsMedianOf3(float a, float b, float c)
{
  if (a > b)
  {
    std::swap(a, b);
  }
  if (b > c)
  {
    std::swap(b, c);
  }
  if (a > b)
  {
    std::swap(a, b);
  }
  return b;
}

inline double metricsPercentileSelectScalar(Vector<float>& samples, double percentile)
{
  if (samples.size() == 0)
  {
    return 0;
  }
  if (samples.size() == 1)
  {
    return samples[0];
  }

  const double position = percentile * double(samples.size() - 1);
  const uint32_t lowerIndex = uint32_t(position);
  const uint32_t upperIndex = (lowerIndex + 1 < samples.size()) ? (lowerIndex + 1) : lowerIndex;
  const double fraction = position - double(lowerIndex);

  std::nth_element(samples.begin(), samples.begin() + lowerIndex, samples.end());
  const double lowerValue = samples[lowerIndex];
  if (upperIndex == lowerIndex)
  {
    return lowerValue;
  }

  std::nth_element(samples.begin(), samples.begin() + upperIndex, samples.end());
  const double upperValue = samples[upperIndex];
  return lowerValue + ((upperValue - lowerValue) * fraction);
}

#if defined(__x86_64__) || defined(__i386__)
__attribute__((target("avx512f"))) inline void metricsPartitionCountAVX512(const float *input, size_t count, float pivot, size_t& lessThanCount, size_t& equalCount)
{
  lessThanCount = 0;
  equalCount = 0;

  const __m512 pivotV = _mm512_set1_ps(pivot);
  size_t index = 0;
  for (; index + 16 <= count; index += 16)
  {
    const __m512 valuesV = _mm512_loadu_ps(input + index);
    const __mmask16 lessMask = _mm512_cmplt_ps_mask(valuesV, pivotV);
    const __mmask16 equalMask = _mm512_cmpeq_ps_mask(valuesV, pivotV);
    lessThanCount += size_t(__builtin_popcount(uint32_t(lessMask)));
    equalCount += size_t(__builtin_popcount(uint32_t(equalMask)));
  }

  for (; index < count; ++index)
  {
    const float value = input[index];
    if (value < pivot)
    {
      ++lessThanCount;
    }
    else if (value == pivot)
    {
      ++equalCount;
    }
  }
}

__attribute__((target("avx512f"))) inline void metricsPartitionScatterAVX512(const float *input, size_t count, float pivot, float *output, size_t lessThanCount, size_t equalCount)
{
  size_t lessIndex = 0;
  size_t equalIndex = lessThanCount;
  size_t greaterIndex = lessThanCount + equalCount;

  const __m512 pivotV = _mm512_set1_ps(pivot);
  size_t index = 0;
  for (; index + 16 <= count; index += 16)
  {
    const __m512 valuesV = _mm512_loadu_ps(input + index);
    const __mmask16 lessMask = _mm512_cmplt_ps_mask(valuesV, pivotV);
    const __mmask16 equalMask = _mm512_cmpeq_ps_mask(valuesV, pivotV);
    const __mmask16 greaterMask = __mmask16(uint32_t(0xFFFF) ^ uint32_t(lessMask | equalMask));

    _mm512_mask_compressstoreu_ps(output + lessIndex, lessMask, valuesV);
    _mm512_mask_compressstoreu_ps(output + equalIndex, equalMask, valuesV);
    _mm512_mask_compressstoreu_ps(output + greaterIndex, greaterMask, valuesV);

    lessIndex += size_t(__builtin_popcount(uint32_t(lessMask)));
    equalIndex += size_t(__builtin_popcount(uint32_t(equalMask)));
    greaterIndex += size_t(__builtin_popcount(uint32_t(greaterMask)));
  }

  for (; index < count; ++index)
  {
    const float value = input[index];
    if (value < pivot)
    {
      output[lessIndex++] = value;
    }
    else if (value == pivot)
    {
      output[equalIndex++] = value;
    }
    else
    {
      output[greaterIndex++] = value;
    }
  }
}

__attribute__((target("avx512f"))) inline float metricsSelectKthAVX512(const float *samples, size_t count, size_t kth)
{
  if (count == 0)
  {
    return 0.0f;
  }
  if (count == 1)
  {
    return samples[0];
  }

  Vector<float> workA;
  Vector<float> workB;
  workA.resize(count);
  workB.resize(count);
  metricsCopyFloat(samples, workA.data(), count);

  float *baseA = workA.data();
  float *baseB = workB.data();
  float *current = baseA;
  bool currentOnA = true;
  size_t currentCount = count;
  size_t targetIndex = kth;

  while (true)
  {
    if (currentCount <= 64)
    {
      std::nth_element(current, current + targetIndex, current + currentCount);
      return current[targetIndex];
    }

    const float pivot = metricsMedianOf3(current[0], current[currentCount >> 1], current[currentCount - 1]);

    size_t lessCount = 0;
    size_t equalCount = 0;
    metricsPartitionCountAVX512(current, currentCount, pivot, lessCount, equalCount);

    if (equalCount == currentCount)
    {
      return pivot;
    }

    float *outputBase = currentOnA ? baseB : baseA;
    const bool outputOnA = !currentOnA;
    metricsPartitionScatterAVX512(current, currentCount, pivot, outputBase, lessCount, equalCount);

    if (targetIndex < lessCount)
    {
      current = outputBase;
      currentOnA = outputOnA;
      currentCount = lessCount;
      continue;
    }

    const size_t lessOrEqual = lessCount + equalCount;
    if (targetIndex < lessOrEqual)
    {
      return pivot;
    }

    targetIndex -= lessOrEqual;
    current = outputBase + lessOrEqual;
    currentOnA = outputOnA;
    currentCount -= lessOrEqual;
  }
}

__attribute__((target("avx512f"))) inline double metricsPercentileSelectAVX512Kernel(Vector<float>& samples, double percentile)
{
  if (samples.size() == 0)
  {
    return 0;
  }
  if (samples.size() == 1)
  {
    return samples[0];
  }

  const double position = percentile * double(samples.size() - 1);
  const uint32_t lowerIndex = uint32_t(position);
  const uint32_t upperIndex = (lowerIndex + 1 < samples.size()) ? (lowerIndex + 1) : lowerIndex;
  const double fraction = position - double(lowerIndex);

  const double lowerValue = metricsSelectKthAVX512(samples.data(), samples.size(), lowerIndex);
  if (upperIndex == lowerIndex)
  {
    return lowerValue;
  }

  const double upperValue = metricsSelectKthAVX512(samples.data(), samples.size(), upperIndex);
  return lowerValue + ((upperValue - lowerValue) * fraction);
}
#endif

inline double metricsPercentileSelect(Vector<float>& samples, double percentile)
{
#if defined(__x86_64__) || defined(__i386__)
  if (samples.size() >= 1024 && metricsCpuSupportsAVX512F())
  {
    return metricsPercentileSelectAVX512Kernel(samples, percentile);
  }
#endif
  return metricsPercentileSelectScalar(samples, percentile);
}

class MetricRing {
private:
  static constexpr uint32_t samplesPerBlock = 1024;
  struct Block {
    std::array<int64_t, samplesPerBlock> timestamps = {};
    std::array<float, samplesPerBlock> values = {};
  };
  std::vector<std::shared_ptr<Block>> blocks;
  uint32_t slotsMask = 0;
  uint64_t headIndex = 0;
  uint64_t tailIndex = 0;
  int64_t newestMs = std::numeric_limits<int64_t>::min();

  static uint32_t nextPowerOfTwo(uint32_t value)
  {
    uint32_t power = 1;
    while (power < value)
    {
      power <<= 1;
    }
    return power;
  }

  uint64_t lowerBoundTimestamp(int64_t cutoffMs) const
  {
    uint64_t lo = headIndex;
    uint64_t hi = tailIndex;
    while (lo < hi)
    {
      const uint64_t mid = lo + ((hi - lo) >> 1);
      if (timestampAt(mid) < cutoffMs)
      {
        lo = mid + 1;
      }
      else
      {
        hi = mid;
      }
    }
    return lo;
  }

  void normalizeLargeIndices(void)
  {
    if (headIndex <= (1ULL << 58))
    {
      return;
    }

    const uint64_t live = size();
    if (live == 0)
    {
      headIndex = 0;
      tailIndex = 0;
      newestMs = std::numeric_limits<int64_t>::min();
      return;
    }

    // Removing a whole table period preserves every physical block and offset.
    // No sample needs to move, including samples retained by a frozen view.
    const uint64_t shift = headIndex & ~uint64_t(slotsMask);
    headIndex -= shift;
    tailIndex -= shift;
  }

  size_t blockSlot(uint64_t index) const
  {
    return size_t((index >> 10) & ((capacity() / samplesPerBlock) - 1));
  }

  int64_t timestampAt(uint64_t index) const
  {
    const auto& block = blocks[blockSlot(index)];
    return block->timestamps[index & (samplesPerBlock - 1)];
  }

  float valueAt(uint64_t index) const
  {
    const auto& block = blocks[blockSlot(index)];
    return block->values[index & (samplesPerBlock - 1)];
  }

  Block& writableBlock(uint64_t index)
  {
    auto& block = blocks[blockSlot(index)];
    if (!block) block = std::make_shared<Block>();
    else if (!block.unique()) block = std::make_shared<Block>(*block);
    return *block;
  }

public:

  class Frozen {
  private:
    std::vector<std::shared_ptr<const Block>> blocks;
    uint32_t slotsMask = 0;
    uint64_t headIndex = 0;
    uint64_t tailIndex = 0;
    size_t retained = 0;

    size_t blockSlot(uint64_t index) const
    {
      return size_t((index >> 10) & (((slotsMask + 1) / samplesPerBlock) - 1));
    }

  public:
    Frozen(std::vector<std::shared_ptr<const Block>> requestedBlocks, uint32_t requestedMask,
           uint64_t requestedHead, uint64_t requestedTail)
        : blocks(std::move(requestedBlocks)), slotsMask(requestedMask), headIndex(requestedHead),
          tailIndex(requestedTail)
    {
      retained = sizeof(Frozen) + 128 + blocks.capacity() * sizeof(std::shared_ptr<const Block>);
      for (const auto& block : blocks) if (block) retained += sizeof(Block) + 64;
    }

    size_t sampleCount(void) const { return size_t(tailIndex - headIndex); }
    size_t retainedBytes(void) const { return retained; }

    template <typename Handler>
    void forEachSample(Handler&& handler) const
    {
      for (uint64_t index = headIndex; index < tailIndex; ++index)
      {
        const auto& block = blocks[blockSlot(index)];
        handler(block->timestamps[index & (samplesPerBlock - 1)], block->values[index & (samplesPerBlock - 1)]);
      }
    }
  };

  MetricRing()
  {
    reserveCapacity(1024);
  }

  uint32_t capacity(void) const
  {
    return uint32_t(blocks.size() * samplesPerBlock);
  }

  uint64_t size(void) const
  {
    return tailIndex - headIndex;
  }

  bool empty(void) const
  {
    return headIndex == tailIndex;
  }

  void reserveCapacity(uint32_t minCapacity)
  {
    const uint32_t targetCapacity = nextPowerOfTwo(std::max<uint32_t>(1024, minCapacity));
    if (targetCapacity <= capacity())
    {
      return;
    }

    // Re-map logical chunks to the larger power-of-two table. A wrapped live
    // range can refer to one old physical block from two new positions; both
    // positions share it until a later append copy-on-writes that block.
    const uint32_t oldBlockMask = uint32_t(blocks.size() - 1);
    std::vector<std::shared_ptr<Block>> grown(targetCapacity / samplesPerBlock);
    if (!empty())
    {
      const uint64_t firstChunk = headIndex >> 10;
      const uint64_t lastChunk = (tailIndex - 1) >> 10;
      const uint32_t newBlockMask = uint32_t(grown.size() - 1);
      for (uint64_t chunk = firstChunk; chunk <= lastChunk; ++chunk)
        grown[size_t(chunk & newBlockMask)] = blocks[size_t(chunk & oldBlockMask)];
    }
    blocks.swap(grown);
    slotsMask = targetCapacity - 1;
  }

  void push(int64_t sampleMs, float sampleValue)
  {
    if (sampleMs < newestMs)
    {
      sampleMs = newestMs;
    }
    else
    {
      newestMs = sampleMs;
    }

    if (capacity() == 0)
    {
      reserveCapacity(1024);
    }
    if (size() >= capacity())
    {
      reserveCapacity(capacity() << 1);
    }

    Block& block = writableBlock(tailIndex);
    block.timestamps[tailIndex & (samplesPerBlock - 1)] = sampleMs;
    block.values[tailIndex & (samplesPerBlock - 1)] = sampleValue;
    ++tailIndex;
  }

  void trimOlderThan(int64_t cutoffMs)
  {
    headIndex = lowerBoundTimestamp(cutoffMs);

    if (headIndex == tailIndex)
    {
      headIndex = 0;
      tailIndex = 0;
      newestMs = std::numeric_limits<int64_t>::min();
    }
    else
    {
      normalizeLargeIndices();
    }
  }

  void collectValuesSince(int64_t cutoffMs, Vector<float>& out) const
  {
    out.clear();
    if (empty())
    {
      return;
    }

    const uint64_t start = lowerBoundTimestamp(cutoffMs);
    if (start >= tailIndex)
    {
      return;
    }

    const uint64_t count = tailIndex - start;
    out.resize(size_t(count));

    for (uint64_t copied = 0; copied < count;)
    {
      const uint64_t index = start + copied;
      const size_t offset = size_t(index & (samplesPerBlock - 1));
      const size_t span = size_t(std::min<uint64_t>(count - copied, samplesPerBlock - offset));
      metricsCopyFloat(blocks[blockSlot(index)]->values.data() + offset, out.data() + copied, span);
      copied += span;
    }
  }

  template <typename Handler>
  void forEachSample(Handler&& handler) const
  {
    for (uint64_t index = headIndex; index < tailIndex; ++index)
    {
      handler(timestampAt(index), valueAt(index));
    }
  }

  std::shared_ptr<const Frozen> captureFrozen(void) const
  {
    std::vector<std::shared_ptr<const Block>> frozenBlocks;
    frozenBlocks.reserve(blocks.size());
    for (const auto& block : blocks) frozenBlocks.push_back(block);
    return std::make_shared<const Frozen>(std::move(frozenBlocks), slotsMask, headIndex, tailIndex);
  }
};

class MetricsStore {
public:

  class Snapshot {
  public:
    class SeriesView {
    public:
      uint64_t deploymentID = 0;
      uint128_t containerUUID = 0;
      uint64_t metricKey = 0;
      std::shared_ptr<const MetricRing::Frozen> ring;
    };

  private:
    std::vector<SeriesView> views;
    size_t samples = 0;
    size_t retained = sizeof(Snapshot) + 128;

    friend class MetricsStore;

  public:
    size_t sampleCount(void) const { return samples; }
    size_t retainedBytes(void) const { return retained; }

    void exportSamples(Vector<ProdigyMetricSample>& out) const
    {
      out.clear();
      out.reserve(samples);
      for (const SeriesView& view : views)
      {
        if (!view.ring) continue;
        view.ring->forEachSample([&](int64_t sampleMs, float sampleValue) {
          ProdigyMetricSample sample = {};
          sample.ms = sampleMs;
          sample.deploymentID = view.deploymentID;
          sample.containerUUID = view.containerUUID;
          sample.metricKey = view.metricKey;
          sample.value = sampleValue;
          out.push_back(sample);
        });
      }
    }
  };

  // deploymentID -> containerUUID -> metricKey -> SoA ring
  bytell_hash_map<uint64_t, bytell_hash_map<uint128_t, bytell_hash_map<uint64_t, MetricRing>>> series;
  // deploymentID -> metricKey -> SoA ring across all instances
  bytell_hash_map<uint64_t, bytell_hash_map<uint64_t, MetricRing>> fleetSeries;

  void clear(void)
  {
    series.clear();
    fleetSeries.clear();
  }

  void record(uint64_t dep, uint128_t uuid, uint64_t key, int64_t ms, double v)
  {
    const float sample = static_cast<float>(v);
    series[dep][uuid][key].push(ms, sample);
    fleetSeries[dep][key].push(ms, sample);
  }

  // Trim retention by timestamp: remove entries older than nowMs - retentionMs
  void trimRetention(int64_t nowMs, int64_t retentionMs)
  {
    const int64_t cutoff = nowMs - retentionMs;

    for (auto depIt = series.begin(); depIt != series.end();)
    {
      auto& byContainer = depIt->second;
      for (auto containerIt = byContainer.begin(); containerIt != byContainer.end();)
      {
        auto& byMetric = containerIt->second;
        for (auto metricIt = byMetric.begin(); metricIt != byMetric.end();)
        {
          metricIt->second.trimOlderThan(cutoff);
          if (metricIt->second.empty())
          {
            metricIt = byMetric.erase(metricIt);
          }
          else
          {
            ++metricIt;
          }
        }

        if (byMetric.size() == 0)
        {
          containerIt = byContainer.erase(containerIt);
        }
        else
        {
          ++containerIt;
        }
      }

      if (byContainer.size() == 0)
      {
        depIt = series.erase(depIt);
      }
      else
      {
        ++depIt;
      }
    }

    for (auto depIt = fleetSeries.begin(); depIt != fleetSeries.end();)
    {
      auto& byMetric = depIt->second;
      for (auto metricIt = byMetric.begin(); metricIt != byMetric.end();)
      {
        metricIt->second.trimOlderThan(cutoff);
        if (metricIt->second.empty())
        {
          metricIt = byMetric.erase(metricIt);
        }
        else
        {
          ++metricIt;
        }
      }

      if (byMetric.size() == 0)
      {
        depIt = fleetSeries.erase(depIt);
      }
      else
      {
        ++depIt;
      }
    }
  }

  // Collect values for percentile calculation over a lookback window
  void collectValues(uint64_t dep, const uint128_t *uuidOpt, uint64_t key, int64_t nowMs, int64_t lookbackMs, bool fleetScope, Vector<float>& out) const
  {
    out.clear();
    if (lookbackMs <= 0)
    {
      return;
    }
    const int64_t cutoff = nowMs - lookbackMs;

    if (fleetScope)
    {
      if (auto dit = fleetSeries.find(dep); dit != fleetSeries.end())
      {
        if (auto mit = dit->second.find(key); mit != dit->second.end())
        {
          mit->second.collectValuesSince(cutoff, out);
        }
      }
      return;
    }

    if (!uuidOpt)
    {
      return;
    }
    if (auto dit = series.find(dep); dit != series.end())
    {
      if (auto cit = dit->second.find(*uuidOpt); cit != dit->second.end())
      {
        if (auto mit = cit->second.find(key); mit != cit->second.end())
        {
          mit->second.collectValuesSince(cutoff, out);
        }
      }
    }
  }

  void exportSamples(Vector<ProdigyMetricSample>& out) const
  {
    out.clear();

    for (const auto& [deploymentID, byContainer] : series)
    {
      for (const auto& [containerUUID, byMetric] : byContainer)
      {
        for (const auto& [metricKey, ring] : byMetric)
        {
          ring.forEachSample([&](int64_t sampleMs, float sampleValue) -> void {
            ProdigyMetricSample sample = {};
            sample.ms = sampleMs;
            sample.deploymentID = deploymentID;
            sample.containerUUID = containerUUID;
            sample.metricKey = metricKey;
            sample.value = sampleValue;
            out.push_back(sample);
          });
        }
      }
    }
  }

  std::shared_ptr<const Snapshot> captureSnapshot(void) const
  {
    auto snapshot = std::make_shared<Snapshot>();
    for (const auto& [deploymentID, byContainer] : series)
    {
      for (const auto& [containerUUID, byMetric] : byContainer)
      {
        for (const auto& [metricKey, ring] : byMetric)
        {
          auto frozen = ring.captureFrozen();
          snapshot->samples += frozen->sampleCount();
          snapshot->retained += frozen->retainedBytes();
          snapshot->views.push_back({deploymentID, containerUUID, metricKey, std::move(frozen)});
        }
      }
    }
    snapshot->retained += snapshot->views.capacity() * sizeof(Snapshot::SeriesView);
    return snapshot;
  }

  void importSamples(const Vector<ProdigyMetricSample>& samples)
  {
    clear();
    for (const ProdigyMetricSample& sample : samples)
    {
      record(sample.deploymentID, sample.containerUUID, sample.metricKey, sample.ms, sample.value);
    }
  }
};
