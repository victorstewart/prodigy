#pragma once

#include <prodigy/types.h>
#include <cstring>
#include <string>

class ProdigyOverloadMetrics
{
public:

	struct MetricPoint
	{
		uint64_t key = 0;
		uint64_t value = 0;
	};

private:

	static constexpr uint32_t nFineBuckets = 32;

	struct Dimension
	{
		uint64_t count = 0;
		uint64_t fineBuckets[nFineBuckets] = {};
	};

	struct DimensionMetricKeys
	{
		uint64_t fineBuckets[nFineBuckets] = {};
	};

	struct MetricKeys
	{
		DimensionMetricKeys queueWait;
		DimensionMetricKeys handler;
	};

	Dimension queueWait;
	Dimension handler;
	MetricKeys keys;

	static uint64_t nsToUsCeil(uint64_t ns)
	{
		if (ns == 0)
		{
			return 0;
		}

		return 1 + ((ns - 1) / 1'000);
	}

	static uint32_t fineBucketIndexForUs(uint64_t us)
	{
		if (us == 0)
		{
			return 0;
		}

		uint32_t index = uint32_t(64 - __builtin_clzll(us));
		if (index >= nFineBuckets)
		{
			return nFineBuckets - 1;
		}

		return index;
	}

	static void addObservation(Dimension& dimension, uint64_t valueUs)
	{
		dimension.count += 1;
		uint32_t fineBucket = fineBucketIndexForUs(valueUs);
		dimension.fineBuckets[fineBucket] += 1;
	}

	static void clearDimension(Dimension& dimension)
	{
		dimension.count = 0;
		memset(dimension.fineBuckets, 0, sizeof(dimension.fineBuckets));
	}

	static void initializeDimensionKeys(DimensionMetricKeys& dimensionKeys, const char *base)
	{
		for (uint32_t index = 0; index < nFineBuckets; index++)
		{
			String name;
			name.assign(base);
			name.append(".fine.bucket."_ctv);
			std::string indexText = std::to_string(index);
			name.append(indexText.data(), indexText.size());
			dimensionKeys.fineBuckets[index] = ProdigyMetrics::metricKeyForName(name);
		}
	}

	static void appendDimensionMetrics(Vector<MetricPoint>& out, const DimensionMetricKeys& dimensionKeys, const Dimension& dimension)
	{
		for (uint32_t index = 0; index < nFineBuckets; index++)
		{
			out.push_back({dimensionKeys.fineBuckets[index], dimension.fineBuckets[index]});
		}
	}

public:

	ProdigyOverloadMetrics()
	{
		initializeDimensionKeys(keys.queueWait, "runtime.ingress.queue_wait_us");
		initializeDimensionKeys(keys.handler, "runtime.ingress.handler_us");
	}

	void observe(uint64_t queueWaitNs, uint64_t handlerNs)
	{
		addObservation(queueWait, nsToUsCeil(queueWaitNs));
		addObservation(handler, nsToUsCeil(handlerNs));
	}

	void flush(Vector<MetricPoint>& out)
	{
		out.clear();

		if (queueWait.count == 0 && handler.count == 0)
		{
			return;
		}

		out.reserve(nFineBuckets * 2);
		appendDimensionMetrics(out, keys.queueWait, queueWait);
		appendDimensionMetrics(out, keys.handler, handler);

		clearDimension(queueWait);
		clearDimension(handler);
	}
};
