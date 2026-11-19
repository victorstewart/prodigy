#pragma once

#include <prodigy/brain/metrics.h>

#include <deque>
#include <map>
#include <tuple>

struct ProdigyMetricCheckpointPoint {
  int64_t ms = 0;
  float value = 0;
};

struct ProdigyMetricCheckpointRow {
  uint64_t deploymentID = 0;
  uint128_t containerUUID = 0;
  uint64_t metricKey = 0;
  // Retain this many samples from the end of the prior committed series.
  uint32_t keep = 0;
  Vector<ProdigyMetricCheckpointPoint> appended;
};

struct ProdigyMetricCheckpointFrame {
  Vector<ProdigyMetricCheckpointRow> rows;
};

template <typename S>
static void serialize(S& s, ProdigyMetricCheckpointPoint& point)
{
  s.value8b(point.ms);
  s.value4b(point.value);
}

template <typename S>
static void serialize(S& s, ProdigyMetricCheckpointRow& row)
{
  s.value8b(row.deploymentID);
  s.value16b(row.containerUUID);
  s.value8b(row.metricKey);
  s.value4b(row.keep);
  s.container(row.appended, UINT32_MAX);
}

template <typename S>
static void serialize(S& s, ProdigyMetricCheckpointFrame& frame)
{
  s.container(frame.rows, UINT32_MAX);
}

using ProdigyMetricSeriesKey = std::tuple<uint64_t, uint128_t, uint64_t>;
struct ProdigyMetricCheckpointCursor {
  uint64_t incarnation, head, tail;
  size_t position;
  bool operator==(const ProdigyMetricCheckpointCursor&) const = default;
};
using ProdigyMetricCheckpointCursors = std::map<ProdigyMetricSeriesKey, ProdigyMetricCheckpointCursor>;

inline bool prodigyBuildMetricCheckpoint(const MetricsStore::Snapshot& snapshot,
                                         const ProdigyMetricCheckpointCursors *previous,
                                         ProdigyMetricCheckpointFrame& frame,
                                         ProdigyMetricCheckpointCursors& next,
                                         bool& changed)
{
  const auto& views = snapshot.seriesViews();
  if (snapshot.sampleCount() > UINT32_MAX || views.size() > UINT32_MAX) return false;
  frame.rows.clear();
  frame.rows.reserve(views.size());
  next.clear();
  changed = !previous || previous->size() != views.size();
  for (const auto& view : views)
  {
    const auto& ring = *view.ring;
    ProdigyMetricSeriesKey key{view.deploymentID, view.containerUUID, view.metricKey};
    const ProdigyMetricCheckpointCursor current{ring.incarnation(), ring.head(), ring.tail(), frame.rows.size()};
    next.emplace(key, current);
    uint64_t from = current.head;
    if (previous)
    {
      const auto old = previous->find(key);
      if (old == previous->end()) changed = true;
      else
      {
        const auto& prior = old->second;
        if (current != prior) changed = true;
        if (prior.incarnation == current.incarnation && prior.head <= current.head &&
            current.head <= prior.tail && prior.tail <= current.tail) from = prior.tail;
      }
    }
    auto& row = frame.rows.emplace_back();
    row.deploymentID = view.deploymentID;
    row.containerUUID = view.containerUUID;
    row.metricKey = view.metricKey;
    row.keep = uint32_t(from - current.head);
    row.appended.reserve(current.tail - from);
    if (!ring.forEachSampleFrom(from, [&](int64_t ms, float value) {
          row.appended.push_back({ms, value});
        })) return false;
  }
  return true;
}

class ProdigyMetricCheckpointReplay {
  using Points = std::deque<ProdigyMetricCheckpointPoint>;
  std::map<ProdigyMetricSeriesKey, Points> series;
  Vector<ProdigyMetricSeriesKey> order;
  uint64_t count = 0;

public:
  bool apply(const ProdigyMetricCheckpointFrame& frame, bool base)
  {
    std::map<ProdigyMetricSeriesKey, Points> next;
    order.clear();
    count = 0;
    for (const auto& row : frame.rows)
    {
      ProdigyMetricSeriesKey key{row.deploymentID, row.containerUUID, row.metricKey};
      const uint64_t size = uint64_t(row.keep) + row.appended.size();
      if (size > UINT32_MAX - count || (base && row.keep)) return false;
      auto [dest, inserted] = next.try_emplace(key);
      if (!inserted) return false;
      auto& points = dest->second;
      if (row.keep)
      {
        auto prior = series.find(key);
        if (prior == series.end() || row.keep > prior->second.size()) return false;
        points.swap(prior->second);
        while (points.size() > row.keep) points.pop_front();
      }
      for (const auto& point : row.appended)
      {
        if (!points.empty() && point.ms < points.back().ms) return false;
        points.push_back(point);
      }
      count += size;
      order.push_back(key);
    }
    series.swap(next);
    return true;
  }

  void exportSamples(Vector<ProdigyMetricSample>& out) const
  {
    out.clear();
    out.reserve(count);
    for (const auto& key : order)
    {
      const auto& [deploymentID, containerUUID, metricKey] = key;
      for (const auto& point : series.at(key))
        out.push_back({point.ms, deploymentID, containerUUID, metricKey, point.value});
    }
  }
};
