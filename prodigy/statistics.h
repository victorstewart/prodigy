#pragma once

enum class StatisticType : uint16_t {

	single,
	average
};

class Statistics {
private:

	friend class NeuronHub;

	class Statistic {
	public:

		virtual void takeMeasurement(uint64_t measurement) = 0;
		virtual uint64_t consume(void) = 0;
	};

	class Single : public Statistic {
	public:

		uint64_t value {0};

		void takeMeasurement(uint64_t measurement)
		{
			value = measurement;
		}

		uint64_t consume(void)
		{
			uint64_t copy = value;
			value = 0;
			return copy;
		}
	};

	class Average : public Statistic {
	public:

		uint32_t atLeastN; // at least these many measurements to calculate anything
		uint64_t total {0};
		uint32_t nMeasurements {0};

		void takeMeasurement(uint64_t value)
		{
			total += value;
			nMeasurements += 1;
		}

		uint64_t consume(void) // we can configure this to calculate metrics besdies averages in the future
		{
			uint64_t avg = 0;

			// we don't want a couple measurments to spark chaos
			// also unless we're heavily loaded this is irrelevant anyway
			if (nMeasurements > atLeastN) avg = total / nMeasurements;

			total = 0;
			nMeasurements = 0;

			return avg;
		}

		Average(uint32_t _atLeastN) : atLeastN(_atLeastN), total(0), nMeasurements(0) {}
	};

	bytell_hash_map<uint64_t, Statistic *> stats;

	void writeStatistics(String& buffer)
	{
		uint32_t headerOffset = Message::appendHeader(buffer, ContainerTopic::statistics);

		for (const auto& [key, stat] : stats)
		{
			if (!stat) continue;
			Message::append(buffer, key);
			Message::append(buffer, stat->consume());
		}

		Message::finish(buffer, headerOffset);
	}

public:

	template <StatisticType type, typename... Args>
	void installMetric(uint64_t key, Args&& ...args)
	{
		Statistic *stat = nullptr;

		if constexpr (type == StatisticType::single)
		{
			stat = new Single(); // args
		}
		else if constexpr (type == StatisticType::average)
		{
			stat = new Average(std::forward<Args>(args)...);
		}
		else return;

		stats.insert_or_assign(key, stat);
	}

	void collectMeasurement(uint64_t key, uint64_t value)
	{
		auto it = stats.find(key);
		if (it == stats.end() || it->second == nullptr) return;
		it->second->takeMeasurement(value);
	}

	~Statistics()
	{
		for (auto &kv : stats)
		{
			delete kv.second;
		}
		stats.clear();
	}
};
