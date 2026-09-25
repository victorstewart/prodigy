#pragma once

#include <atomic>
#include <cstdlib>
#include <functional>
#include <limits>
#include <memory>
#include <tuple>
#include <type_traits>

#include <bitsery/adapter/measure_size.h>

#include <prodigy/artifact.io.h>
#include <prodigy/persistent.state.h>

// While a request is pending, this is the sole live user of its store.
// Work runs on ArtifactIO's worker and completions run on its Ring callback.
// Every request shares ArtifactIO's FIFO, job limit, and retained-byte budget.
// A false submit result means no callback will occur; callers retry genuine
// capacity rejection from their Ring-owned recovery path.
class ProdigyPersistentStateWriter {
public:
  static constexpr uint64_t maximumRetainedBytes = ProdigyArtifactIO::maximumBytes;
  static constexpr uint32_t maximumPendingRequests = ProdigyArtifactIO::maximumJobs;
  struct Result {
    uint64_t sequence = 0;
    bool durable = false;
    bool snapshotDurable = false;
    bool bootStateDurable = false;
    String failure;
  };
  using Completion = std::function<void(Result&&)>;

  // Replays the persistent Bitsery schema without producing I/O.  Unlike a
  // normal String copy, borrowed text fields become heap-owned before a Request
  // can outlive the Ring callback that supplied it. Already-owned storage moves
  // with the Request and needs no second copy. This deliberately follows
  // the serialization schema rather than maintaining a second field list.
  class OwningSchemaVisitor {
    bool valid = true;
    struct Adapter {
      bool isCompletedSuccessfully() const { return true; }
      bitsery::ReaderError error() const { return bitsery::ReaderError::NoError; }
      void error(bitsery::ReaderError) {}
    } adapterValue;

    void own(String& value)
    {
      if (!valid || value.size() == 0 || value.ownsMemory()) return;
      String copied(const_cast<uint8_t *>(value.data()), value.size(), Copy::yes, value.size());
      if (copied.size() != value.size()) { valid = false; return; }
      value = std::move(copied);
    }

    template <typename T>
    void visit(T& value)
    {
      if constexpr (std::is_same_v<std::remove_cvref_t<T>, String>) own(value);
      else if constexpr (requires { serialize(*this, value); }) serialize(*this, value);
    }

  public:
    static constexpr bool isProdigyPersistentWriter = true;
    bool ok() const { return valid; }
    Adapter& adapter() { return adapterValue; }
    const Adapter& adapter() const { return adapterValue; }
    template <typename T> void value1b(T&) {}
    template <typename T> void value2b(T&) {}
    template <typename T> void value4b(T&) {}
    template <typename T> void value8b(T&) {}
    template <typename T> void value16b(T&) {}
    template <typename T> void text1b(T& value, uint64_t) { own(value); }
    template <typename T> void text2b(T& value, uint64_t) { own(value); }
    template <typename T> void text4b(T& value, uint64_t) { own(value); }
    template <typename T> void object(T& value) { visit(value); }
    void frozenMetricSamples(Vector<ProdigyMetricSample>&,
                             const std::shared_ptr<const MetricsStore::Snapshot>&) {}
    template <typename T> void detachPersistentValue(T& value) { visit(value); }
    template <typename Map> void detachPersistentMap(Map& values)
    {
      Map detached = {};
      detached.reserve(values.size());
      for (const auto& item : values)
      {
        auto key = item.first;
        auto value = item.second;
        visit(key);
        visit(value);
        detached.insert_or_assign(std::move(key), std::move(value));
      }
      values = std::move(detached);
    }
    template <typename T> void container(T& values, uint64_t)
    {
      for (auto& value : values) visit(value);
    }
    template <typename T> void container1b(T& values, uint64_t) { container(values, 0); }
    template <typename T> void container2b(T& values, uint64_t) { container(values, 0); }
    template <typename T> void container4b(T& values, uint64_t) { container(values, 0); }
    template <typename T> void container8b(T& values, uint64_t) { container(values, 0); }
    template <typename T> void container16b(T& values, uint64_t) { container(values, 0); }
    template <typename T, typename Fn>
    void container(T& values, uint64_t, Fn&& entry)
    {
      for (auto& value : values) entry(*this, value);
    }
    template <typename Map, typename Extension, typename Fn>
    void ext(Map& values, Extension, Fn&& entry)
    {
      if constexpr (requires (typename Map::value_type item) { item.first; item.second; })
      {
        // Map keys are intentionally exposed as const. Rebuild the map with
        // detached mutable copies instead of casting away that invariant.
        Map detached = values;
        detached.clear();
        for (const auto& item : values)
        {
          std::remove_cvref_t<decltype(item.first)> key = item.first;
          std::remove_cvref_t<decltype(item.second)> value = item.second;
          entry(*this, key, value);
          detached.insert_or_assign(std::move(key), std::move(value));
        }
        values = std::move(detached);
      }
      else
      {
        for (auto& item : values)
        {
          if constexpr (requires { entry(*this, item); }) entry(*this, item);
        }
      }
    }
    template <typename T, typename Extension>
    void ext(T&, Extension) {}
  };

  // This mirrors the schema traversal used for ownership capture, but charges
  // detached heap graph overhead rather than writing bytes. In particular,
  // many short Strings and hash entries must not be admitted based only on
  // their compact wire representation.
  class RetainedSchemaVisitor {
    uint64_t bytes = 0;
    bool valid = true;
    struct Adapter {
      bool isCompletedSuccessfully() const { return true; }
      bitsery::ReaderError error() const { return bitsery::ReaderError::NoError; }
      void error(bitsery::ReaderError) {}
    } adapterValue;
    static constexpr uint64_t allocationOverhead = 64;

    void add(uint64_t amount)
    {
      if (!valid || amount > maximumRetainedBytes - bytes) { valid = false; return; }
      bytes += amount;
    }
    template <typename T>
    void visit(T& value)
    {
      if constexpr (std::is_same_v<std::remove_cvref_t<T>, String>)
      {
        add(sizeof(String) + value.size() + allocationOverhead);
      }
      else if constexpr (requires { serialize(*this, value); })
      {
        serialize(*this, value);
      }
    }

  public:
    static constexpr bool isProdigyPersistentWriter = true;
    bool ok() const { return valid; }
    uint64_t retained() const { return bytes; }
    Adapter& adapter() { return adapterValue; }
    const Adapter& adapter() const { return adapterValue; }
    template <typename T> void value1b(T& value) { add(sizeof(value)); }
    template <typename T> void value2b(T& value) { add(sizeof(value)); }
    template <typename T> void value4b(T& value) { add(sizeof(value)); }
    template <typename T> void value8b(T& value) { add(sizeof(value)); }
    template <typename T> void value16b(T& value) { add(sizeof(value)); }
    template <typename T> void text1b(T& value, uint64_t) { visit(value); }
    template <typename T> void text2b(T& value, uint64_t) { visit(value); }
    template <typename T> void text4b(T& value, uint64_t) { visit(value); }
    template <typename T> void object(T& value) { add(sizeof(value)); visit(value); }
    void frozenMetricSamples(Vector<ProdigyMetricSample>& samples,
                             const std::shared_ptr<const MetricsStore::Snapshot>& capture)
    {
      if (capture) add(capture->retainedBytes());
      else container(samples, UINT32_MAX);
    }
    template <typename T> void detachPersistentValue(T& value)
    {
      if constexpr (std::is_same_v<std::remove_cvref_t<T>, String>) visit(value);
      else { add(sizeof(value)); visit(value); }
    }
    template <typename Map> void detachPersistentMap(Map& values)
    {
      add(sizeof(values) + uint64_t(values.size()) * allocationOverhead);
      for (const auto& item : values)
      {
        auto key = item.first;
        auto value = item.second;
        visit(key);
        visit(value);
      }
    }
    template <typename T> void container(T& values, uint64_t)
    {
      add(sizeof(values) + uint64_t(values.size()) * allocationOverhead);
      for (auto& value : values) visit(value);
    }
    template <typename T> void container1b(T& values, uint64_t limit) { container(values, limit); }
    template <typename T> void container2b(T& values, uint64_t limit) { container(values, limit); }
    template <typename T> void container4b(T& values, uint64_t limit) { container(values, limit); }
    template <typename T> void container8b(T& values, uint64_t limit) { container(values, limit); }
    template <typename T> void container16b(T& values, uint64_t limit) { container(values, limit); }
    template <typename T, typename Fn> void container(T& values, uint64_t, Fn&& entry)
    {
      add(sizeof(values) + uint64_t(values.size()) * allocationOverhead);
      for (auto& value : values) entry(*this, value);
    }
    template <typename Map, typename Extension, typename Fn> void ext(Map& values, Extension, Fn&& entry)
    {
      add(sizeof(values) + uint64_t(values.size()) * allocationOverhead);
      for (auto& item : values)
      {
        if constexpr (requires { item.first; item.second; })
        {
          // Bitsery map callbacks take mutable references. Use ephemeral
          // copies for this read-only accounting pass rather than violating
          // the container's const-key invariant.
          std::remove_cvref_t<decltype(item.first)> key = item.first;
          std::remove_cvref_t<decltype(item.second)> value = item.second;
          entry(*this, key, value);
        }
        else if constexpr (requires { entry(*this, item); }) entry(*this, item);
      }
    }
    template <typename T, typename Extension> void ext(T&, Extension) {}
  };

  template <typename T>
  static bool detach(T& value)
  {
    OwningSchemaVisitor visitor;
    visitor.object(value);
    return visitor.ok();
  }

  // Run the production schema twice without producing a payload: Bitsery's
  // exact wire counter and the detached allocation counter above.
  template <typename T>
  static uint64_t retainedBytesFor(T& value)
  {
    using Context = std::tuple<PointerLinkingContext>;
    Context context;
    bitsery::Serializer<bitsery::BasicMeasureSize<FastConfig>, Context> serializer {context};
    serializer.object(value);
    serializer.adapter().flush();
    const uint64_t serialized = serializer.adapter().writtenBytesCount();
    RetainedSchemaVisitor retained;
    retained.object(value);
    if (serialized == 0 || !retained.ok() || retained.retained() > maximumRetainedBytes / 2 ||
        serialized > (maximumRetainedBytes - retained.retained() * 2) / 3) return 0;
    // Encoded payload, record envelope, and serialization growth may coexist.
    return retained.retained() * 2 + serialized * 3;
  }

  static uint64_t retainedBytesFor(ProdigyPersistentBrainSnapshot& value)
  {
    if (!value.metricCapture) return retainedBytesFor<ProdigyPersistentBrainSnapshot>(value);
    // Measure the ordinary schema with its empty flat vector, then charge the
    // immutable graph, worker-only flat vector and encoded sample bytes. No
    // live sample is visited, copied or serialized for admission accounting.
    struct RestoreCapture {
      ProdigyPersistentBrainSnapshot& snapshot;
      std::shared_ptr<const MetricsStore::Snapshot> capture;
      ~RestoreCapture() { snapshot.metricCapture = std::move(capture); }
    } restore {value, std::move(value.metricCapture)};
    if (!value.metricSamples.empty()) return 0;
    const uint64_t base = retainedBytesFor<ProdigyPersistentBrainSnapshot>(value);
    const uint64_t count = restore.capture->sampleCount();
    if (!base || count > UINT32_MAX) return 0;
    using Context = std::tuple<PointerLinkingContext>;
    Context context;
    bitsery::Serializer<bitsery::BasicMeasureSize<FastConfig>, Context> measure {context};
    ProdigyMetricSample sample = {};
    measure.object(sample);
    measure.adapter().flush();
    // Five bytes conservatively cover the schema's variable count prefix.
    const uint64_t perSample = sizeof(ProdigyMetricSample) + 3 * measure.adapter().writtenBytesCount();
    const uint64_t captured = restore.capture->retainedBytes();
    if (captured > maximumRetainedBytes / 2 || count > maximumRetainedBytes / perSample) return 0;
    const uint64_t extra = captured * 2 + count * perSample + 15;
    if (extra > maximumRetainedBytes || base > maximumRetainedBytes - extra) return 0;
    return base + extra;
  }

public:
  struct Request {
    Result result;
    ProdigyPersistentBrainSnapshot snapshot;
    ProdigyPersistentBootState bootState;
    ProdigyPersistentLocalBrainState localState;
    bool writeSnapshot = false;
    bool writeLocalState = false;
    Completion completion;
  };
  using Commit = std::function<void(ProdigyPersistentStateStore&, Request&)>;

private:
  ProdigyPersistentStateStore& store;
  ProdigyArtifactIO& io;
  Commit commit;
  uint64_t nextSequence = 1;
  uint32_t pendingRequests = 0;
  bool accepting = true;
  bool commitFailureLatched = false;
  std::atomic<bool> workerFailureLatched = false;

  static bool commitFailed(const Request& request)
  {
    if (request.writeSnapshot) return !request.result.snapshotDurable || !request.result.bootStateDurable;
    if (request.writeLocalState) return !request.result.durable;
    return !request.result.bootStateDurable;
  }

  void commitRequest(const std::shared_ptr<Request>& request)
  {
    // The worker can reach another queued request before the Ring receives
    // this one's completion. Fence failed dependencies here, before any
    // later write reaches the store, while delivering receipts on the Ring.
    if (workerFailureLatched.load(std::memory_order_acquire))
    {
      request->result.failure.assign("persistent state failure fenced later commits"_ctv);
      return;
    }
    try
    {
      commit(store, *request);
      if (commitFailed(*request)) workerFailureLatched.store(true, std::memory_order_release);
    }
    catch (...)
    {
      workerFailureLatched.store(true, std::memory_order_release);
      throw;
    }
  }

  void finish(const std::shared_ptr<Request>& request, bool workerFailed)
  {
    if (workerFailed) request->result.failure.assign("persistent state worker failed"_ctv);
    if (workerFailed || commitFailed(*request)) commitFailureLatched = true;
    // ArtifactIO retains the request's byte lease through this callback.
    // Exec drain must also continue counting the callback's live request.
    request->completion(std::move(request->result));
    --pendingRequests;
  }

  bool submit(std::shared_ptr<Request> request, uint64_t requestBytes)
  {
    if (!accepting || commitFailureLatched || requestBytes == 0 || requestBytes > maximumRetainedBytes ||
        pendingRequests == maximumPendingRequests) return false;
    // Charge the actual detached request, including serialization growth,
    // to the same owner as artifacts. In particular, an artifact's publish
    // completion can enqueue its durable snapshot before releasing its own
    // lease; it does not need exclusive ownership of the entire worker.
    if (!io.submit(requestBytes,
                   [this, request] { commitRequest(request); },
                   [this, request] { finish(request, false); },
                   [this, request](std::exception_ptr) { finish(request, true); })) return false;
    ++pendingRequests;
    return true;
  }

public:
  ProdigyPersistentStateWriter(ProdigyPersistentStateStore& store, ProdigyArtifactIO& io, Commit commit = {})
      : store(store), io(io), commit(std::move(commit))
  {
    if (!this->commit)
    {
      this->commit = [](ProdigyPersistentStateStore& store, Request& request) {
        if (request.writeSnapshot)
        {
          if (!store.saveBrainSnapshot(request.snapshot, &request.result.failure)) return;
          request.result.snapshotDurable = true;
          // Preserve this acknowledgement even if the ordered boot-state
          // follow-up throws before it can set bootStateDurable below.
          request.result.durable = true;
        }
        if (request.writeLocalState)
        {
          request.result.durable = store.saveLocalBrainState(request.localState, &request.result.failure);
          return;
        }
        request.result.bootStateDurable = store.saveBootState(request.bootState, &request.result.failure);
        // Snapshot durability remains a successful result even when its
        // ordered boot-state follow-up failed. Callers use the separate flag
        // to report/fence that partial commit without rolling back a snapshot
        // that is already durable on disk.
        if (!request.writeSnapshot) request.result.durable = request.result.bootStateDurable;
      };
    }
  }

  ~ProdigyPersistentStateWriter()
  {
    // Destruction cannot safely cancel a durable request: ArtifactIO closures
    // retain this owner. Lifecycle must drain first and fail closed otherwise.
    if (hasPending()) std::abort();
  }

  // retainedBytes must cover the detached domain payload, including owned
  // blobs and serialization growth; it is an admission contract, not a hint.
  bool submitSnapshot(ProdigyPersistentBrainSnapshot snapshot, ProdigyPersistentBootState bootState,
                      uint64_t retainedBytes, Completion completion)
  {
    if (!completion) return false;
    auto request = std::make_shared<Request>();
    request->result.sequence = nextSequence++;
    request->snapshot = std::move(snapshot);
    request->bootState = std::move(bootState);
    if (!detach(request->snapshot) || !detach(request->bootState)) return false;
    request->writeSnapshot = true;
    request->completion = std::move(completion);
    return submit(std::move(request), retainedBytes);
  }

  // See submitSnapshot's retainedBytes contract.
  bool submitBootState(ProdigyPersistentBootState bootState, uint64_t retainedBytes, Completion completion)
  {
    if (!completion) return false;
    auto request = std::make_shared<Request>();
    request->result.sequence = nextSequence++;
    request->bootState = std::move(bootState);
    if (!detach(request->bootState)) return false;
    request->completion = std::move(completion);
    return submit(std::move(request), retainedBytes);
  }

  // See submitSnapshot's retainedBytes contract.
  bool submitLocalBrainState(ProdigyPersistentLocalBrainState localState, uint64_t retainedBytes, Completion completion)
  {
    if (!completion) return false;
    auto request = std::make_shared<Request>();
    request->result.sequence = nextSequence++;
    request->localState = std::move(localState);
    if (!detach(request->localState)) return false;
    request->writeLocalState = true;
    request->completion = std::move(completion);
    return submit(std::move(request), retainedBytes);
  }

  bool hasPending(void) const { return pendingRequests != 0; }
  bool drainForExec(void) { accepting = false; return !hasPending(); }
};
