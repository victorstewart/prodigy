#pragma once

#include <prodigy/host.http.admission.h>
#include <prodigy/iaas/gcp/gcp.compute.transaction.h>

class GcpClusterDestroyTransaction final
{
public:

  constexpr static uint32_t maximumRequestsPerWave = ProdigyHostHttpAdmission::defaultCapacity;
  constexpr static uint32_t maximumObservations = GcpComputeTransaction::maximumObservations;
  constexpr static uint32_t maximumInstanceNameBytes = 63;
  constexpr static uint32_t maximumOperationNameBytes = 2048;

private:

  class Target
  {
  public:

    String name;
    String cloudID;
    String operation;
    bool absent = false;
    bool blocked = false;
    bool observeAfterMutation = false;
  };

  enum class LabelMatch : uint8_t
  {
    exact,
    different,
    malformed
  };

  GcpComputeTransaction compute;
  ProdigyHostHttpOperation::Submission http;
  MultiCurlClient::TimePoint deadline;

  static bool validClusterLabel(const String& value)
  {
    if (value.empty() || value.size() > 63)
    {
      return false;
    }
    const auto alphanumeric = [](uint8_t byte) -> bool {
      return (byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9');
    };
    if (alphanumeric(value[0]) == false || alphanumeric(value[value.size() - 1]) == false)
    {
      return false;
    }
    for (uint64_t index = 0; index < value.size(); ++index)
    {
      const uint8_t byte = value[index];
      if (alphanumeric(byte) == false && byte != '-' && byte != '_')
      {
        return false;
      }
    }
    return true;
  }

  static LabelMatch exactLabels(simdjson::dom::element instance, const String& clusterLabel)
  {
    simdjson::dom::element labels;
    const simdjson::error_code labelsResult = instance["labels"].get(labels);
    if (labelsResult == simdjson::NO_SUCH_FIELD)
    {
      return LabelMatch::different;
    }
    if (labelsResult != simdjson::SUCCESS || labels.is_object() == false)
    {
      return LabelMatch::malformed;
    }

    String app;
    String cluster;
    const simdjson::error_code appResult = prodigyJSONString(labels["app"], app);
    const simdjson::error_code clusterResult = prodigyJSONString(labels["prodigy_cluster_uuid"], cluster);
    if (appResult == simdjson::NO_SUCH_FIELD || clusterResult == simdjson::NO_SUCH_FIELD)
    {
      return LabelMatch::different;
    }
    if (appResult != simdjson::SUCCESS || clusterResult != simdjson::SUCCESS)
    {
      return LabelMatch::malformed;
    }
    return app == "prodigy"_ctv && cluster == clusterLabel ?
        LabelMatch::exact : LabelMatch::different;
  }

  static void preserveFirstFailure(String& failure, const String& candidate)
  {
    if (failure.empty())
    {
      failure.assign(candidate);
    }
  }

  static bool parseDiscoveryPage(const String& response,
                                 const String& clusterLabel,
                                 Vector<Target>& targets,
                                 bytell_hash_map<String, uint32_t>& names,
                                 uint32_t& instances,
                                 String& nextPageToken,
                                 String& failure)
  {
    simdjson::dom::parser parser;
    simdjson::dom::element document;
    String text = response;
    if (parser.parse(text.c_str(), text.size()).get(document) || document.is_object() == false)
    {
      failure.assign("gcp cluster destroy instance list response parse failed"_ctv);
      return false;
    }

    simdjson::dom::element items;
    const simdjson::error_code itemsResult = document["items"].get(items);
    if (itemsResult == simdjson::SUCCESS)
    {
      if (items.is_array() == false)
      {
        failure.assign("gcp cluster destroy instance list items malformed"_ctv);
        return false;
      }
      for (simdjson::dom::element instance : items.get_array())
      {
        if (instances >= GcpComputeTransaction::maximumInstances)
        {
          failure.assign("gcp cluster destroy instance list exceeds 128000 items"_ctv);
          return false;
        }
        ++instances;
        const LabelMatch labelMatch = exactLabels(instance, clusterLabel);
        if (labelMatch == LabelMatch::malformed)
        {
          failure.assign("gcp cluster destroy instance list labels malformed"_ctv);
          return false;
        }
        if (labelMatch != LabelMatch::exact)
        {
          continue;
        }

        String name;
        String cloudID;
        if (prodigyJSONString(instance["name"], name) != simdjson::SUCCESS ||
            prodigyJSONString(instance["id"], cloudID) != simdjson::SUCCESS ||
            name.empty() || name.size() > maximumInstanceNameBytes || cloudID.empty())
        {
          failure.assign("gcp cluster destroy matching instance identity malformed"_ctv);
          return false;
        }
        String copiedName;
        copiedName.assign(name);
        const auto existing = names.find(copiedName);
        if (existing != names.end())
        {
          if (GcpComputeTransaction::view(targets[existing->second].cloudID) != cloudID)
          {
            failure.assign("gcp cluster destroy instance name resolves to multiple identities"_ctv);
            return false;
          }
          continue;
        }
        Target& target = targets.emplace_back();
        target.name = std::move(copiedName);
        target.cloudID.assign(cloudID);
        if (GcpComputeTransaction::validDecimalID(target.cloudID) == false)
        {
          failure.assign("gcp cluster destroy matching instance id malformed"_ctv);
          return false;
        }
        String ownedName;
        ownedName.assign(target.name);
        names.emplace(std::move(ownedName), uint32_t(targets.size() - 1));
      }
    }
    else if (itemsResult != simdjson::NO_SUCH_FIELD)
    {
      failure.assign("gcp cluster destroy instance list items malformed"_ctv);
      return false;
    }

    nextPageToken.clear();
    String token;
    const simdjson::error_code tokenResult = prodigyJSONString(document["nextPageToken"], token);
    if (tokenResult == simdjson::SUCCESS)
    {
      if (token.size() > GcpComputeTransaction::maximumPageTokenBytes)
      {
        failure.assign("gcp cluster destroy page token exceeds 2048 bytes"_ctv);
        return false;
      }
      nextPageToken.assign(token);
    }
    else if (tokenResult != simdjson::NO_SUCH_FIELD)
    {
      failure.assign("gcp cluster destroy page token malformed"_ctv);
      return false;
    }
    return true;
  }

  static bool parseOwnership(const String& response,
                             const Target& target,
                             const String& clusterLabel,
                             bool& owned,
                             bool& replacement,
                             String& failure)
  {
    owned = false;
    replacement = false;
    simdjson::dom::parser parser;
    simdjson::dom::element instance;
    String cloudID;
    String text = response;
    if (parser.parse(text.c_str(), text.size()).get(instance) ||
        prodigyJSONString(instance["id"], cloudID) != simdjson::SUCCESS || cloudID.empty())
    {
      failure.assign("gcp cluster destroy instance ownership response malformed"_ctv);
      return false;
    }
    replacement = cloudID != GcpComputeTransaction::view(target.cloudID);
    const LabelMatch labelMatch = exactLabels(instance, clusterLabel);
    if (labelMatch == LabelMatch::malformed)
    {
      failure.assign("gcp cluster destroy instance ownership response malformed"_ctv);
      return false;
    }
    owned = replacement == false && labelMatch == LabelMatch::exact;
    return true;
  }

  void submit(CoroutineStack *coro,
              Vector<MultiCurlClient::Request> requests,
              Vector<MultiCurlClient::Result>& results,
              bool& complete)
  {
    complete = false;
    if (coro == nullptr || http.submit == nullptr || http.cancel == nullptr ||
        requests.empty() || requests.size() > maximumRequestsPerWave || compute.expired())
    {
      co_return;
    }
    const MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now();
    for (MultiCurlClient::Request& request : requests)
    {
      const MultiCurlClient::Clock::duration budget =
          request.method == MultiCurlClient::Method::get ?
              std::chrono::seconds(3) : std::chrono::seconds(8);
      request.overallDeadline = std::min(deadline, now + budget);
    }
    ProdigyHostHttpBatchOperation operation(http, *coro);
    if (operation.submit(std::move(requests)) == false)
    {
      co_return;
    }
    if (operation.mustSuspend())
    {
      co_await coro->suspend();
    }
    complete = operation.takeResults(results);
  }

  void discover(CoroutineStack *coro,
                const String& clusterLabel,
                Vector<Target>& targets,
                bool& complete,
                String& failure)
  {
    complete = false;
    String pageToken;
    bytell_hash_set<String> requestedTokens;
    bytell_hash_map<String, uint32_t> names;
    uint32_t instances = 0;
    for (uint32_t page = 0; page < GcpComputeTransaction::maximumPages; ++page)
    {
      if (compute.expired())
      {
        failure.assign("gcp cluster destroy deadline exceeded"_ctv);
        co_return;
      }
      String requestedToken;
      requestedToken.assign(pageToken);
      if (requestedTokens.insert(std::move(requestedToken)).second == false)
      {
        failure.assign("gcp cluster destroy repeated page token"_ctv);
        co_return;
      }

      String url = compute.instancesUrl();
      String filter;
      filter.assign("(labels.app = prodigy) (labels.prodigy_cluster_uuid = "_ctv);
      filter.append(clusterLabel);
      filter.append(')');
      url.append("?maxResults=500&filter="_ctv);
      GcpComputeTransaction::appendPercentEncoded(url, filter);
      url.append("&fields=items(id,name,labels),nextPageToken"_ctv);
      if (pageToken.empty() == false)
      {
        url.append("&pageToken="_ctv);
        GcpComputeTransaction::appendPercentEncoded(url, pageToken);
      }
      MultiCurlClient::Result result;
      bool requestComplete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            compute.submit(coro,
                           compute.request(MultiCurlClient::Method::get, std::move(url)),
                           result,
                           requestComplete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (requestComplete == false || result.status != MultiCurlClient::Status::success ||
          result.statusCode < 200 || result.statusCode >= 300)
      {
        GcpComputeTransaction::assignRequestFailure(result,
                                                    "gcp cluster destroy instance list"_ctv,
                                                    failure);
        co_return;
      }

      String followingToken;
      if (parseDiscoveryPage(result.body,
                             clusterLabel,
                             targets,
                             names,
                             instances,
                             followingToken,
                             failure) == false)
      {
        co_return;
      }
      if (followingToken.empty())
      {
        complete = true;
        co_return;
      }
      if (requestedTokens.contains(followingToken))
      {
        failure.assign("gcp cluster destroy repeated page token"_ctv);
        co_return;
      }
      pageToken = std::move(followingToken);
    }
    failure.assign("gcp cluster destroy instance list exceeds 256 pages"_ctv);
  }

  void preflightWave(CoroutineStack *coro,
                     const String& clusterLabel,
                     Vector<Target>& targets,
                     uint32_t offset,
                     uint32_t count,
                     bool& complete,
                     String& failure)
  {
    complete = false;
    Vector<MultiCurlClient::Request> requests;
    requests.reserve(count);
    for (uint32_t index = 0; index < count; ++index)
    {
      requests.push_back(compute.request(MultiCurlClient::Method::get,
                                         compute.instanceUrl(targets[offset + index].name,
                                                             "id,labels"_ctv)));
    }
    Vector<MultiCurlClient::Result> results;
    bool waveComplete = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          submit(coro, std::move(requests), results, waveComplete);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (waveComplete == false || results.size() != count)
    {
      failure.assign("gcp cluster destroy ownership preflight failed"_ctv);
      co_return;
    }
    for (uint32_t index = 0; index < count; ++index)
    {
      Target& target = targets[offset + index];
      const MultiCurlClient::Result& result = results[index];
      if (result.status == MultiCurlClient::Status::success && result.statusCode == 404)
      {
        target.absent = true;
        continue;
      }
      if (result.status != MultiCurlClient::Status::success ||
          result.statusCode < 200 || result.statusCode >= 300)
      {
        GcpComputeTransaction::assignRequestFailure(result,
                                                    "gcp cluster destroy ownership preflight"_ctv,
                                                    failure);
        co_return;
      }
      bool owned = false;
      bool replacement = false;
      if (parseOwnership(result.body, target, clusterLabel, owned, replacement, failure) == false)
      {
        co_return;
      }
      if (owned == false)
      {
        if (replacement)
        {
          failure.assign("gcp cluster destroy target identity changed before mutation"_ctv);
        }
        else
        {
          failure.assign("gcp cluster destroy target labels changed before mutation"_ctv);
        }
        co_return;
      }
    }
    complete = true;
  }

  void submitDeleteWave(CoroutineStack *coro,
                        Vector<Target>& targets,
                        uint32_t offset,
                        uint32_t count,
                        bool& complete,
                        bool& deletePhaseStarted,
                        String& failure)
  {
    complete = false;
    Vector<uint32_t> indices;
    Vector<MultiCurlClient::Request> requests;
    for (uint32_t index = offset; index < offset + count; ++index)
    {
      if (targets[index].absent == false)
      {
        indices.push_back(index);
        requests.push_back(compute.request(MultiCurlClient::Method::delete_,
                                           compute.instancesUrl(&targets[index].name)));
      }
    }
    if (requests.empty())
    {
      complete = true;
      co_return;
    }
    if (compute.expired())
    {
      preserveFirstFailure(failure, "gcp cluster destroy deletion submission failed"_ctv);
      co_return;
    }
    deletePhaseStarted = true;
    for (uint32_t index : indices)
    {
      targets[index].observeAfterMutation = true;
    }
    Vector<MultiCurlClient::Result> results;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          submit(coro, std::move(requests), results, complete);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (complete == false || results.size() != indices.size())
    {
      preserveFirstFailure(failure, "gcp cluster destroy deletion submission failed"_ctv);
      co_return;
    }
    for (uint32_t resultIndex = 0; resultIndex < results.size(); ++resultIndex)
    {
      Target& target = targets[indices[resultIndex]];
      const MultiCurlClient::Result& result = results[resultIndex];
      if (result.status == MultiCurlClient::Status::success && result.statusCode == 404)
      {
        target.absent = true;
        target.observeAfterMutation = false;
        continue;
      }
      if (result.status == MultiCurlClient::Status::success &&
          result.statusCode >= 200 && result.statusCode < 300)
      {
        String parseFailure;
        if (GcpComputeTransaction::parseOperationName(result.body,
                                                      target.operation,
                                                      parseFailure) == false)
        {
          preserveFirstFailure(failure, parseFailure);
        }
        else if (target.operation.size() > maximumOperationNameBytes)
        {
          target.operation.clear();
          preserveFirstFailure(failure,
                               "gcp cluster destroy operation name exceeds 2048 bytes"_ctv);
        }
        continue;
      }
      String requestFailure;
      GcpComputeTransaction::assignRequestFailure(result,
                                                  "gcp cluster destroy deletion"_ctv,
                                                  requestFailure);
      preserveFirstFailure(failure, requestFailure);
      target.blocked = GcpComputeTransaction::mutationMayBeAccepted(result) == false;
      target.observeAfterMutation = target.blocked == false;
    }
  }

  void mutate(CoroutineStack *coro,
              const String& clusterLabel,
              Vector<Target>& targets,
              bool& deletePhaseStarted,
              String& failure)
  {
    deletePhaseStarted = false;
    for (uint32_t offset = 0; offset < targets.size(); offset += maximumRequestsPerWave)
    {
      const uint32_t count = std::min<uint32_t>(maximumRequestsPerWave,
                                                uint32_t(targets.size() - offset));
      bool preflightComplete = false;
      String preflightFailure;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            preflightWave(coro,
                          clusterLabel,
                          targets,
                          offset,
                          count,
                          preflightComplete,
                          preflightFailure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (preflightComplete == false)
      {
        preserveFirstFailure(failure,
                             preflightFailure.empty() ?
                                 String("gcp cluster destroy ownership preflight failed"_ctv) :
                                 preflightFailure);
        co_return;
      }

      bool deleteComplete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            submitDeleteWave(coro,
                             targets,
                             offset,
                             count,
                             deleteComplete,
                             deletePhaseStarted,
                             failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (deleteComplete == false)
      {
        co_return;
      }
    }
  }

  void pollOperations(CoroutineStack *coro,
                      Vector<Target>& targets,
                      String& failure)
  {
    for (uint32_t observation = 0; observation < maximumObservations; ++observation)
    {
      bool pending = false;
      for (uint32_t offset = 0; offset < targets.size(); offset += maximumRequestsPerWave)
      {
        Vector<uint32_t> indices;
        Vector<MultiCurlClient::Request> requests;
        for (uint32_t index = offset;
             index < targets.size() && index < offset + maximumRequestsPerWave;
             ++index)
        {
          if (targets[index].absent == false && targets[index].operation.empty() == false)
          {
            indices.push_back(index);
            requests.push_back(compute.request(MultiCurlClient::Method::get,
                                               compute.operationUrl(targets[index].operation)));
          }
        }
        if (requests.empty())
        {
          continue;
        }
        Vector<MultiCurlClient::Result> results;
        bool complete = false;
        if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
              submit(coro, std::move(requests), results, complete);
            }))
        {
          co_await coro->suspendAtIndex(suspendIndex);
        }
        if (complete == false || results.size() != indices.size())
        {
          preserveFirstFailure(failure, "gcp cluster destroy operation observation failed"_ctv);
          co_return;
        }
        for (uint32_t resultIndex = 0; resultIndex < results.size(); ++resultIndex)
        {
          Target& target = targets[indices[resultIndex]];
          const MultiCurlClient::Result& result = results[resultIndex];
          if (result.status == MultiCurlClient::Status::success && result.statusCode == 404)
          {
            target.operation.clear();
            continue;
          }
          if (result.status != MultiCurlClient::Status::success ||
              result.statusCode < 200 || result.statusCode >= 300)
          {
            String requestFailure;
            GcpComputeTransaction::assignRequestFailure(result,
                                                        "gcp cluster destroy operation observation"_ctv,
                                                        requestFailure);
            preserveFirstFailure(failure, requestFailure);
            target.operation.clear();
            continue;
          }
          String operationFailure;
          const GcpComputeTransaction::OperationState state =
              GcpComputeTransaction::parseOperation(result.body, operationFailure);
          if (state == GcpComputeTransaction::OperationState::pending)
          {
            pending = true;
          }
          else
          {
            target.operation.clear();
            if (state != GcpComputeTransaction::OperationState::done)
            {
              preserveFirstFailure(failure, operationFailure);
              target.blocked = state == GcpComputeTransaction::OperationState::failed;
            }
          }
        }
      }
      if (pending == false)
      {
        co_return;
      }
      if (observation + 1 >= maximumObservations || compute.canWait() == false)
      {
        preserveFirstFailure(failure, "gcp cluster destroy operation deadline exceeded"_ctv);
        co_return;
      }
      bool delayComplete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            compute.wait(coro, delayComplete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (delayComplete == false)
      {
        preserveFirstFailure(failure, "gcp cluster destroy operation delay failed"_ctv);
        co_return;
      }
    }
  }

  void verifyAbsence(CoroutineStack *coro,
                     const String& clusterLabel,
                     Vector<Target>& targets,
                     String& failure)
  {
    for (uint32_t observation = 0; observation < maximumObservations; ++observation)
    {
      bool pending = false;
      for (uint32_t offset = 0; offset < targets.size(); offset += maximumRequestsPerWave)
      {
        Vector<uint32_t> indices;
        Vector<MultiCurlClient::Request> requests;
        for (uint32_t index = offset;
             index < targets.size() && index < offset + maximumRequestsPerWave;
             ++index)
        {
          if (targets[index].absent == false && targets[index].blocked == false &&
              targets[index].observeAfterMutation)
          {
            indices.push_back(index);
            requests.push_back(compute.request(MultiCurlClient::Method::get,
                                               compute.instanceUrl(targets[index].name,
                                                                   "id,labels"_ctv)));
          }
        }
        if (requests.empty())
        {
          continue;
        }
        Vector<MultiCurlClient::Result> results;
        bool complete = false;
        if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
              submit(coro, std::move(requests), results, complete);
            }))
        {
          co_await coro->suspendAtIndex(suspendIndex);
        }
        if (complete == false || results.size() != indices.size())
        {
          preserveFirstFailure(failure, "gcp cluster destroy absence observation failed"_ctv);
          co_return;
        }
        for (uint32_t resultIndex = 0; resultIndex < results.size(); ++resultIndex)
        {
          Target& target = targets[indices[resultIndex]];
          const MultiCurlClient::Result& result = results[resultIndex];
          if (result.status == MultiCurlClient::Status::success && result.statusCode == 404)
          {
            target.absent = true;
            continue;
          }
          if (result.status != MultiCurlClient::Status::success ||
              result.statusCode < 200 || result.statusCode >= 300)
          {
            String requestFailure;
            GcpComputeTransaction::assignRequestFailure(result,
                                                        "gcp cluster destroy absence observation"_ctv,
                                                        requestFailure);
            preserveFirstFailure(failure, requestFailure);
            pending = true;
            continue;
          }
          bool owned = false;
          bool replacement = false;
          String ownershipFailure;
          if (parseOwnership(result.body,
                             target,
                             clusterLabel,
                             owned,
                             replacement,
                             ownershipFailure) == false)
          {
            preserveFirstFailure(failure, ownershipFailure);
            target.blocked = true;
          }
          else if (replacement || owned == false)
          {
            if (replacement)
            {
              preserveFirstFailure(failure, "gcp cluster destroy target name was replaced"_ctv);
            }
            else
            {
              preserveFirstFailure(failure,
                                   "gcp cluster destroy surviving target labels changed"_ctv);
            }
            target.blocked = true;
          }
          else
          {
            pending = true;
          }
        }
      }
      if (pending == false)
      {
        co_return;
      }
      if (observation + 1 >= maximumObservations || compute.canWait() == false)
      {
        preserveFirstFailure(failure, "gcp cluster destroy deadline exceeded"_ctv);
        co_return;
      }
      bool delayComplete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            compute.wait(coro, delayComplete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (delayComplete == false)
      {
        preserveFirstFailure(failure, "gcp cluster destroy absence delay failed"_ctv);
        co_return;
      }
    }
  }

  static void finish(const Vector<Target>& targets, uint32_t& destroyed, String& failure)
  {
    destroyed = 0;
    for (const Target& target : targets)
    {
      destroyed += target.absent;
    }
    if (destroyed == targets.size())
    {
      failure.clear();
      return;
    }
    if (failure.empty())
    {
      failure.assign("gcp cluster destroy incomplete"_ctv);
    }
    failure.append("; gcp cluster destroy cloud state may be partial for: "_ctv);
    bool first = true;
    for (const Target& target : targets)
    {
      if (target.absent)
      {
        continue;
      }
      if (first == false)
      {
        failure.append(',');
      }
      failure.append(target.name);
      first = false;
    }
  }

public:

  GcpClusterDestroyTransaction(ProdigyHostHttpOperation::Submission http,
                               ProdigyHostDelayOperation::Submission delay,
                               String project,
                               String zone,
                               String token,
                               MultiCurlClient::TimePoint deadline)
      : compute(http,
                delay,
                std::move(project),
                std::move(zone),
                std::move(token),
                deadline),
        http(http),
        deadline(deadline)
  {}

  void run(CoroutineStack *coro,
           const String& clusterUUID,
           uint32_t& destroyed,
           String& failure)
  {
    String clusterLabel;
    clusterLabel.assign(clusterUUID);
    destroyed = 0;
    failure.clear();
    if (coro == nullptr || compute.runtimeAvailable() == false)
    {
      failure.assign("gcp cluster destroy runtime unavailable"_ctv);
      co_return;
    }
    if (compute.identityAvailable() == false || validClusterLabel(clusterLabel) == false)
    {
      failure.assign("gcp cluster destroy requires valid project, zone, token, and cluster UUID label"_ctv);
      co_return;
    }
    if (compute.expired())
    {
      failure.assign("gcp cluster destroy deadline exceeded"_ctv);
      co_return;
    }

    Vector<Target> targets;
    bool discoveryComplete = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          discover(coro, clusterLabel, targets, discoveryComplete, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (failure.empty() == false || discoveryComplete == false || targets.empty())
    {
      if (failure.empty() && discoveryComplete == false)
      {
        failure.assign("gcp cluster destroy discovery failed"_ctv);
      }
      co_return;
    }

    bool deletePhaseStarted = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          mutate(coro, clusterLabel, targets, deletePhaseStarted, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (failure.empty() == false && deletePhaseStarted == false)
    {
      co_return;
    }
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          pollOperations(coro, targets, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          verifyAbsence(coro, clusterLabel, targets, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    finish(targets, destroyed, failure);
  }
};
