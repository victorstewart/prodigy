#pragma once

#include <prodigy/iaas/gcp/gcp.compute.transaction.h>
#include <prodigy/json.h>

class GcpInstanceLabelsTransaction final
{
public:

  constexpr static uint32_t maximumLabels = 64;
  constexpr static uint32_t maximumFingerprintBytes = 2048;
  constexpr static uint32_t maximumMutationAttempts = 4;

private:

  class Label
  {
  public:

    String key;
    String value;
  };

  GcpComputeTransaction compute;

  static bool validLabelValue(const String& value)
  {
    if (value.empty())
    {
      return true;
    }
    if (value.size() > 63)
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

  static int64_t findLabel(const Vector<Label>& labels, const String& key)
  {
    for (uint32_t index = 0; index < labels.size(); ++index)
    {
      if (GcpComputeTransaction::view(labels[index].key) == key)
      {
        return index;
      }
    }
    return -1;
  }

  static bool parseLabels(const String& response,
                          const String& cloudID,
                          const String& clusterUUID,
                          String& fingerprint,
                          Vector<Label>& labels,
                          bool& current,
                          String& failure)
  {
    fingerprint.clear();
    labels.clear();
    current = false;

    simdjson::dom::parser parser;
    simdjson::dom::element instance;
    String text = response;
    if (parser.parse(text.c_str(), text.size()).get(instance))
    {
      failure.assign("gcp instance labels response parse failed"_ctv);
      return false;
    }

    String id;
    String parsedFingerprint;
    if (prodigyJSONString(instance["id"], id) != simdjson::SUCCESS || id.empty() ||
        prodigyJSONString(instance["labelFingerprint"], parsedFingerprint) != simdjson::SUCCESS ||
        parsedFingerprint.empty() ||
        parsedFingerprint.size() > maximumFingerprintBytes)
    {
      failure.assign("gcp instance labels identity or fingerprint malformed"_ctv);
      return false;
    }
    if (id != GcpComputeTransaction::view(cloudID))
    {
      failure.assign("gcp instance labels target identity changed before mutation"_ctv);
      return false;
    }
    fingerprint.assign(parsedFingerprint);

    simdjson::dom::element parsedLabels;
    if (instance["labels"].get(parsedLabels) == simdjson::SUCCESS)
    {
      if (parsedLabels.is_object() == false)
      {
        failure.assign("gcp instance labels object malformed"_ctv);
        return false;
      }
      for (simdjson::dom::key_value_pair field : parsedLabels.get_object())
      {
        if (labels.size() >= maximumLabels)
        {
          failure.assign("gcp instance labels exceed 64 entries"_ctv);
          return false;
        }
        String key;
        String value;
        key.assign(field.key);
        if (prodigyJSONString(field.value, value) != simdjson::SUCCESS ||
            field.key.empty() || field.key.size() > 63 || value.size() > 63 ||
            findLabel(labels, key) >= 0)
        {
          failure.assign("gcp instance label entry malformed"_ctv);
          return false;
        }
        Label& label = labels.emplace_back();
        label.key = std::move(key);
        label.value.assign(value);
      }
    }

    const int64_t app = findLabel(labels, "app"_ctv);
    const int64_t cluster = findLabel(labels, "prodigy_cluster_uuid"_ctv);
    current = app >= 0 && cluster >= 0 && labels[uint64_t(app)].value == "prodigy"_ctv &&
              labels[uint64_t(cluster)].value == clusterUUID;
    return true;
  }

  static bool buildBody(const String& fingerprint,
                        const String& clusterUUID,
                        const Vector<Label>& labels,
                        String& body,
                        String& failure)
  {
    uint32_t retained = 0;
    for (const Label& label : labels)
    {
      if (label.key != "app"_ctv && label.key != "prodigy_cluster_uuid"_ctv)
      {
        ++retained;
      }
    }
    if (retained + 2 > maximumLabels)
    {
      failure.assign("gcp instance labels cannot preserve existing labels within 64-entry limit"_ctv);
      return false;
    }

    body.clear();
    body.append("{\"labelFingerprint\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(body, fingerprint);
    body.append(",\"labels\":{"_ctv);
    bool first = true;
    for (const Label& label : labels)
    {
      if (label.key == "app"_ctv || label.key == "prodigy_cluster_uuid"_ctv)
      {
        continue;
      }
      if (first == false)
      {
        body.append(',');
      }
      prodigyAppendEscapedJSONStringLiteral(body, label.key);
      body.append(':');
      prodigyAppendEscapedJSONStringLiteral(body, label.value);
      first = false;
    }
    if (first == false)
    {
      body.append(',');
    }
    body.append("\"app\":\"prodigy\",\"prodigy_cluster_uuid\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(body, clusterUUID);
    body.append("}}"_ctv);
    return true;
  }

public:

  GcpInstanceLabelsTransaction(ProdigyHostHttpOperation::Submission http,
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
                deadline)
  {}

  void run(CoroutineStack *coro,
           const String& cloudID,
           const String& clusterUUID,
           String& failure)
  {
    String targetCloudID;
    String targetClusterUUID;
    targetCloudID.assign(cloudID);
    targetClusterUUID.assign(clusterUUID);
    failure.clear();
    if (coro == nullptr || compute.runtimeAvailable() == false)
    {
      failure.assign("gcp instance labels runtime unavailable"_ctv);
      co_return;
    }
    if (compute.identityAvailable() == false || targetCloudID.empty() || targetClusterUUID.empty() ||
        validLabelValue(targetClusterUUID) == false)
    {
      failure.assign("gcp instance labels require cloudID and valid cluster UUID label"_ctv);
      co_return;
    }
    if (compute.expired())
    {
      failure.assign("gcp instance labels deadline exceeded"_ctv);
      co_return;
    }

    String name;
    bool discoveryComplete = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          compute.resolveName(coro, targetCloudID, name, discoveryComplete, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (failure.empty() == false || discoveryComplete == false)
    {
      if (failure.empty())
      {
        failure.assign("gcp instance labels discovery failed"_ctv);
      }
      co_return;
    }
    if (name.empty())
    {
      failure.assign("gcp instance labels target not found"_ctv);
      co_return;
    }

    for (uint32_t attempt = 0; attempt < maximumMutationAttempts; ++attempt)
    {
      MultiCurlClient::Result instanceResult;
      bool instanceComplete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            compute.fetchInstance(coro,
                                  name,
                                  "id,labelFingerprint,labels"_ctv,
                                  instanceResult,
                                  instanceComplete,
                                  failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (failure.empty() == false)
      {
        co_return;
      }
      if (instanceComplete == false || instanceResult.statusCode == 404)
      {
        failure.assign("gcp instance labels target not found"_ctv);
        co_return;
      }

      String fingerprint;
      Vector<Label> labels;
      bool current = false;
      if (parseLabels(instanceResult.body,
                      targetCloudID,
                      targetClusterUUID,
                      fingerprint,
                      labels,
                      current,
                      failure) == false)
      {
        co_return;
      }
      if (current)
      {
        co_return;
      }

      String body;
      if (buildBody(fingerprint, targetClusterUUID, labels, body, failure) == false)
      {
        co_return;
      }
      String url = compute.instancesUrl(&name);
      url.append("/setLabels"_ctv);
      MultiCurlClient::Result mutationResult;
      bool mutationComplete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            compute.submit(coro,
                           compute.request(MultiCurlClient::Method::post, std::move(url), &body),
                           mutationResult,
                           mutationComplete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (mutationComplete == false)
      {
        failure.assign("gcp instance labels mutation submission failed"_ctv);
        co_return;
      }
      if (mutationResult.status == MultiCurlClient::Status::success && mutationResult.statusCode == 412 &&
          attempt + 1 < maximumMutationAttempts)
      {
        if (compute.canWait() == false)
        {
          failure.assign("gcp instance labels fingerprint retry deadline exceeded"_ctv);
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
          failure.assign("gcp instance labels fingerprint retry delay failed"_ctv);
          co_return;
        }
        continue;
      }
      if (mutationResult.status == MultiCurlClient::Status::success && mutationResult.statusCode == 412)
      {
        failure.assign("gcp instance labels fingerprint conflict retry limit exceeded"_ctv);
        co_return;
      }
      if (mutationResult.status != MultiCurlClient::Status::success ||
          mutationResult.statusCode < 200 || mutationResult.statusCode >= 300)
      {
        GcpComputeTransaction::assignRequestFailure(mutationResult,
                                                    "gcp instance labels mutation"_ctv,
                                                    failure);
        if (GcpComputeTransaction::mutationMayBeAccepted(mutationResult))
        {
          GcpComputeTransaction::appendPartial(name, failure);
        }
        co_return;
      }

      String operationName;
      if (GcpComputeTransaction::parseOperationName(mutationResult.body, operationName, failure) == false)
      {
        GcpComputeTransaction::appendPartial(name, failure);
        co_return;
      }
      GcpComputeTransaction::OperationState state = GcpComputeTransaction::OperationState::invalid;
      bool missing = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            compute.pollOperation(coro, operationName, state, missing, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (state == GcpComputeTransaction::OperationState::done)
      {
        co_return;
      }
      if (state == GcpComputeTransaction::OperationState::failed)
      {
        co_return;
      }
      if (missing && failure.empty())
      {
        failure.assign("gcp instance labels operation disappeared"_ctv);
      }
      GcpComputeTransaction::appendPartial(name, failure);
      co_return;
    }
    failure.assign("gcp instance labels fingerprint conflict retry limit exceeded"_ctv);
  }
};
