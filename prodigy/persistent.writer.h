#pragma once

#include <deque>
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
// A false submit result means no callback will occur. The initial full-worker
// lease intentionally excludes unrelated artifact work until this batch drains;
// callers retry false admission from their Ring-owned recovery path.
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
  // normal String copy, text fields become heap-owned before a Request can
  // outlive the Ring callback that supplied it.  This deliberately follows
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
      if (!valid || value.size() == 0) return;
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

public:
  struct Request {
    Result result;
    ProdigyPersistentBrainSnapshot snapshot;
    ProdigyPersistentBootState bootState;
    ProdigyPersistentLocalBrainState localState;
    bool writeSnapshot = false;
    bool writeLocalState = false;
    uint64_t retainedBytes = 0;
    Completion completion;
  };
  using Commit = std::function<void(ProdigyPersistentStateStore&, Request&)>;

private:
  ProdigyPersistentStateStore& store;
  ProdigyArtifactIO& io;
  Commit commit;
  std::deque<std::shared_ptr<Request>> pending;
  uint64_t nextSequence = 1;
  uint64_t retainedBytes = 0;
  bool accepting = true;
  bool inFlight = false;
  bool commitFailureLatched = false;
  // Callers declare the bytes retained by their detached payload. Admission
  // sums those declarations against ArtifactIO's existing maximum; the
  // worker holds one full ArtifactIO lease for the whole FIFO batch because
  // continueWith intentionally preserves that lease between requests.
  void rejectPendingAfterFailure()
  {
    while (!pending.empty())
    {
      auto request = std::move(pending.front());
      pending.pop_front();
      retainedBytes -= request->retainedBytes;
      request->result.failure.assign("persistent state failure fenced later commits"_ctv);
      request->completion(std::move(request->result));
    }
  }

  static bool commitFailed(const Request& request)
  {
    if (request.writeSnapshot) return !request.result.snapshotDurable || !request.result.bootStateDurable;
    if (request.writeLocalState) return !request.result.durable;
    return !request.result.bootStateDurable;
  }

  void finish(std::shared_ptr<Request> request, bool workerFailed)
  {
    if (workerFailed) request->result.failure.assign("persistent state worker failed"_ctv);
    if (workerFailed || commitFailed(*request)) commitFailureLatched = true;
    // The active closure still retains this request during the user callback.
    // Reentrant admission must count its bytes and queue slot until it returns.
    request->completion(std::move(request->result));
    pending.pop_front();
    retainedBytes -= request->retainedBytes;
    if (commitFailureLatched)
    {
      rejectPendingAfterFailure();
      inFlight = false;
      return;
    }
    if (pending.empty())
    {
      inFlight = false;
      return;
    }
    // This is a Ring completion. Reuse its ArtifactIO lease so the next FIFO
    // request is not rejected while this callback still owns that lease.
    auto next = pending.front();
    const bool continued = io.continueWith(
        [this, next] { commit(store, *next); },
        [this, next] { finish(next, false); },
        [this, next](std::exception_ptr) { finish(next, true); });
    if (!continued)
    {
      pending.pop_front();
      retainedBytes -= next->retainedBytes;
      next->result.failure.assign("persistent state continuation rejected"_ctv);
      commitFailureLatched = true;
      next->completion(std::move(next->result));
      rejectPendingAfterFailure();
      inFlight = false;
    }
  }

  bool startNext()
  {
    if (inFlight || pending.empty()) return true;
    auto request = pending.front();
    inFlight = true;
    if (!io.submit(ProdigyArtifactIO::maximumBytes,
                   [this, request] { commit(store, *request); },
                   [this, request] { finish(request, false); },
                   [this, request](std::exception_ptr) { finish(request, true); }))
    {
      // Artifact contention is an admission/backpressure result, never a
      // disk-commit failure and therefore must not trip the snapshot latch.
      inFlight = false;
      pending.pop_front();
      retainedBytes -= request->retainedBytes;
      return false;
    }
    return true;
  }

  bool submit(std::shared_ptr<Request> request, uint64_t requestBytes)
  {
    if (!accepting || commitFailureLatched || requestBytes == 0 || requestBytes > maximumRetainedBytes ||
        pending.size() == maximumPendingRequests || retainedBytes > maximumRetainedBytes - requestBytes) return false;
    request->retainedBytes = requestBytes;
    retainedBytes += requestBytes;
    pending.push_back(std::move(request));
    return startNext();
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
    if (inFlight || !pending.empty()) std::abort();
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

  bool hasPending(void) const { return inFlight || !pending.empty(); }
  bool drainForExec(void) { accepting = false; return !hasPending(); }
};
