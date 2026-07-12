#pragma once

#include <prodigy/host.http.admission.h>
#include <prodigy/iaas/bootstrap.ssh.h>
#include <prodigy/iaas/gcp/gcp.compute.transaction.h>
#include <prodigy/json.h>
#include <prodigy/types.h>

class GcpMachineProvisioningTransaction final
{
public:

  class Spec
  {
  public:

    String name;
    String body;
  };

  constexpr static uint32_t maximumMachines = 256;
  constexpr static uint32_t maximumRequestsPerWave = ProdigyHostHttpAdmission::defaultCapacity;
  constexpr static uint32_t maximumObservations = 1200;
  constexpr static uint64_t pollDelayUs = 500 * 1000;
  constexpr static size_t responseBytes = 1024 * 1024;

private:

  using OperationState = GcpComputeTransaction::OperationState;

  enum class MutationState : uint8_t
  {
    unsubmitted,
    rejected,
    accepted,
    ambiguous
  };

  class State
  {
  public:

    String name;
    String operation;
    MutationState mutation = MutationState::unsubmitted;
    bool operationDone = false;
    bool ready = false;
  };

  ProdigyHostHttpOperation::Submission http;
  ProdigyHostDelayOperation::Submission delay;
  String project;
  String zone;
  String token;
  MultiCurlClient::TimePoint deadline;
  MultiCurlClient::TimePoint requestDeadline;

  static void assignRequestFailure(const MultiCurlClient::Result& result,
                                   const String& operation,
                                   String& failure)
  {
    if (GcpComputeTransaction::parseApiFailure(result.body, failure))
    {
      return;
    }
    if (result.status == MultiCurlClient::Status::deadlineExceeded)
    {
      failure.assign("gcp provisioning deadline exceeded"_ctv);
    }
    else if (result.status == MultiCurlClient::Status::responseTooLarge)
    {
      failure.assign("gcp provisioning response exceeds 1 MiB"_ctv);
    }
    else if (result.status == MultiCurlClient::Status::success)
    {
      failure.snprintf<"{} failed with HTTP {itoa}"_ctv>(operation, uint32_t(result.statusCode));
    }
    else
    {
      failure.assign(operation);
      failure.append(" transport failed"_ctv);
    }
  }

  static MutationState classifyMutation(const MultiCurlClient::Result& result)
  {
    if (result.statusCode >= 200 && result.statusCode < 300)
    {
      return MutationState::accepted;
    }
    return GcpComputeTransaction::mutationMayBeAccepted(result) ?
        MutationState::ambiguous : MutationState::rejected;
  }

  MultiCurlClient::Request request(MultiCurlClient::Method method,
                                   String url,
                                   const String *body = nullptr) const
  {
    return GcpComputeTransaction::request(method,
                                          std::move(url),
                                          body,
                                          token,
                                          requestDeadline,
                                          responseBytes);
  }

  String instancesUrl(const String *name = nullptr) const
  {
    String url = {};
    url.assign("https://compute.googleapis.com/compute/v1/projects/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, project);
    url.append("/zones/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, zone);
    url.append("/instances"_ctv);
    if (name)
    {
      url.append('/');
      GcpComputeTransaction::appendPercentEncoded(url, *name);
    }
    return url;
  }

  String instanceUrl(const String& name) const
  {
    String url = instancesUrl(&name);
    url.append("?fields=id,creationTimestamp,labels,networkInterfaces(networkIP,ipv6Address,accessConfigs(natIP,externalIpv6)),zone,scheduling(preemptible,provisioningModel),reservationAffinity(consumeReservationType),resourceStatus(physicalHost,physicalHostTopology(cluster,block,subblock)),disks(boot,initializeParams(sourceImage),source)"_ctv);
    return url;
  }

  String operationUrl(const String& name) const
  {
    String url = {};
    url.assign("https://compute.googleapis.com/compute/v1/projects/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, project);
    url.append("/zones/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, zone);
    url.append("/operations/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, name);
    url.append("?fields=status,error,httpErrorStatusCode,httpErrorMessage,statusMessage"_ctv);
    return url;
  }

  MultiCurlClient::Request createRequest(const Spec& spec, const String& templateName) const
  {
    String url = instancesUrl();
    url.append("?sourceInstanceTemplate=projects/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, project);
    url.append("/global/instanceTemplates/"_ctv);
    GcpComputeTransaction::appendPercentEncoded(url, templateName);
    return request(MultiCurlClient::Method::post, std::move(url), &spec.body);
  }

  void submit(CoroutineStack *coro,
              Vector<MultiCurlClient::Request> requests,
              Vector<MultiCurlClient::Result>& results,
              bool& complete)
  {
    complete = false;
    if (coro == nullptr || http.submit == nullptr || http.cancel == nullptr)
    {
      co_return;
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

  void submitWaves(CoroutineStack *coro,
                   Vector<MultiCurlClient::Request> requests,
                   Vector<MultiCurlClient::Result>& results,
                   bool& complete)
  {
    complete = false;
    results.clear();
    results.reserve(requests.size());
    for (uint32_t offset = 0; offset < requests.size(); offset += maximumRequestsPerWave)
    {
      if (MultiCurlClient::Clock::now() >= requestDeadline)
      {
        co_return;
      }

      const uint32_t count = std::min<uint32_t>(maximumRequestsPerWave,
                                                uint32_t(requests.size() - offset));
      Vector<MultiCurlClient::Request> wave;
      wave.reserve(count);
      const MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now();
      for (uint32_t index = 0; index < count; ++index)
      {
        MultiCurlClient::Request& pending = requests[offset + index];
        const MultiCurlClient::Clock::duration budget =
            pending.method == MultiCurlClient::Method::get ?
                std::chrono::seconds(3) : std::chrono::seconds(8);
        pending.overallDeadline = std::min(requestDeadline, now + budget);
        wave.push_back(std::move(pending));
      }

      Vector<MultiCurlClient::Result> waveResults;
      bool waveComplete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            submit(coro, std::move(wave), waveResults, waveComplete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (waveComplete == false || waveResults.size() != count)
      {
        co_return;
      }
      for (MultiCurlClient::Result& result : waveResults)
      {
        results.push_back(std::move(result));
      }
    }
    complete = results.size() == requests.size();
  }

  void appendPartialNames(const Vector<State>& states,
                          const Vector<uint8_t>& absent,
                          String& failure) const
  {
    bool any = false;
    for (uint32_t index = 0; index < states.size(); ++index)
    {
      any = any || (states[index].mutation != MutationState::rejected &&
                    absent[index] == false);
    }
    if (any == false)
    {
      return;
    }
    failure.append("; gcp provisioning cloud state may be partial for: "_ctv);
    bool first = true;
    for (uint32_t index = 0; index < states.size(); ++index)
    {
      if (states[index].mutation == MutationState::rejected || absent[index])
      {
        continue;
      }
      if (first == false)
      {
        failure.append(',');
      }
      failure.append(states[index].name);
      first = false;
    }
  }

  void settleCreateOperations(CoroutineStack *coro,
                              Vector<State>& states)
  {
    for (uint32_t observation = 0; observation < maximumObservations; ++observation)
    {
      Vector<uint32_t> indices;
      Vector<MultiCurlClient::Request> requests;
      for (uint32_t index = 0; index < states.size(); ++index)
      {
        if (states[index].mutation == MutationState::accepted &&
            states[index].operationDone == false &&
            states[index].operation.empty() == false)
        {
          indices.push_back(index);
          requests.push_back(request(MultiCurlClient::Method::get,
                                     operationUrl(states[index].operation)));
        }
      }
      if (requests.empty() || MultiCurlClient::Clock::now() >= deadline)
      {
        co_return;
      }

      Vector<MultiCurlClient::Result> results;
      bool complete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            submitWaves(coro, std::move(requests), results, complete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (complete == false)
      {
        co_return;
      }

      bool pending = false;
      for (uint32_t resultIndex = 0; resultIndex < results.size(); ++resultIndex)
      {
        const uint32_t index = indices[resultIndex];
        const MultiCurlClient::Result& result = results[resultIndex];
        if (result.status != MultiCurlClient::Status::success ||
            result.statusCode < 200 || result.statusCode >= 300)
        {
          pending = true;
          continue;
        }
        String ignored;
        const OperationState state = GcpComputeTransaction::parseOperation(result.body, ignored);
        if (state == OperationState::done || state == OperationState::failed)
        {
          states[index].operationDone = true;
        }
        else
        {
          pending = true;
        }
      }
      if (pending == false)
      {
        co_return;
      }

      const MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now();
      if (now >= deadline || deadline - now < std::chrono::microseconds(pollDelayUs))
      {
        co_return;
      }
      bool delayComplete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            GcpComputeTransaction::wait(delay, coro, pollDelayUs, delayComplete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (delayComplete == false)
      {
        co_return;
      }
    }
  }

  void settleDeleteOperations(CoroutineStack *coro,
                              Vector<String>& operations,
                              Vector<uint8_t>& absent)
  {
    for (uint32_t observation = 0; observation < maximumObservations; ++observation)
    {
      Vector<uint32_t> indices;
      Vector<MultiCurlClient::Request> requests;
      for (uint32_t index = 0; index < operations.size(); ++index)
      {
        if (absent[index] == 0 && operations[index].empty() == false)
        {
          indices.push_back(index);
          requests.push_back(request(MultiCurlClient::Method::get,
                                     operationUrl(operations[index])));
        }
      }
      if (requests.empty() || MultiCurlClient::Clock::now() >= deadline)
      {
        co_return;
      }

      Vector<MultiCurlClient::Result> results;
      bool complete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            submitWaves(coro, std::move(requests), results, complete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (complete == false)
      {
        co_return;
      }

      bool pending = false;
      for (uint32_t resultIndex = 0; resultIndex < results.size(); ++resultIndex)
      {
        const uint32_t index = indices[resultIndex];
        const MultiCurlClient::Result& result = results[resultIndex];
        if (result.status != MultiCurlClient::Status::success ||
            result.statusCode < 200 || result.statusCode >= 300)
        {
          pending = true;
          continue;
        }
        String ignored;
        const OperationState state = GcpComputeTransaction::parseOperation(result.body, ignored);
        if (state == OperationState::done)
        {
          absent[index] = 1;
          operations[index].clear();
        }
        else if (state == OperationState::failed)
        {
          operations[index].clear();
        }
        else
        {
          pending = true;
        }
      }
      if (pending == false)
      {
        co_return;
      }

      const MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now();
      if (now >= deadline || deadline - now < std::chrono::microseconds(pollDelayUs))
      {
        co_return;
      }
      bool delayComplete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            GcpComputeTransaction::wait(delay, coro, pollDelayUs, delayComplete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (delayComplete == false)
      {
        co_return;
      }
    }
  }

  void cleanup(CoroutineStack *coro, Vector<State>& states, String& failure)
  {
    requestDeadline = deadline;
    Vector<uint8_t> absent;
    Vector<String> deleteOperations;
    absent.resize(states.size(), 0);
    deleteOperations.resize(states.size());

    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          settleCreateOperations(coro, states);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }

    if (MultiCurlClient::Clock::now() < deadline)
    {
      Vector<uint32_t> indices;
      Vector<MultiCurlClient::Request> requests;
      for (uint32_t index = 0; index < states.size(); ++index)
      {
        if (states[index].mutation == MutationState::accepted && states[index].operationDone)
        {
          indices.push_back(index);
          requests.push_back(request(MultiCurlClient::Method::delete_,
                                     instancesUrl(&states[index].name)));
        }
      }
      Vector<MultiCurlClient::Result> results;
      bool complete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            submitWaves(coro, std::move(requests), results, complete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (complete)
      {
        for (uint32_t resultIndex = 0; resultIndex < results.size(); ++resultIndex)
        {
          const uint32_t index = indices[resultIndex];
          const MultiCurlClient::Result& result = results[resultIndex];
          if (result.status == MultiCurlClient::Status::success && result.statusCode == 404)
          {
            absent[index] = 1;
          }
          else if (result.status == MultiCurlClient::Status::success &&
                   result.statusCode >= 200 && result.statusCode < 300)
          {
            String ignored;
            (void)GcpComputeTransaction::parseOperationName(result.body,
                                                            deleteOperations[index],
                                                            ignored);
          }
        }
      }
    }

    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          settleDeleteOperations(coro, deleteOperations, absent);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }

    if (MultiCurlClient::Clock::now() < deadline)
    {
      Vector<uint32_t> indices;
      Vector<MultiCurlClient::Request> requests;
      for (uint32_t index = 0; index < states.size(); ++index)
      {
        if (states[index].mutation == MutationState::accepted &&
            states[index].operationDone && absent[index] == 0)
        {
          indices.push_back(index);
          requests.push_back(request(MultiCurlClient::Method::get,
                                     instanceUrl(states[index].name)));
        }
      }
      Vector<MultiCurlClient::Result> results;
      bool complete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            submitWaves(coro, std::move(requests), results, complete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (complete)
      {
        for (uint32_t resultIndex = 0; resultIndex < results.size(); ++resultIndex)
        {
          const uint32_t index = indices[resultIndex];
          absent[index] = results[resultIndex].status == MultiCurlClient::Status::success &&
                          results[resultIndex].statusCode == 404;
        }
      }
    }
    appendPartialNames(states, absent, failure);
  }
public:

  GcpMachineProvisioningTransaction(ProdigyHostHttpOperation::Submission http,
                                    ProdigyHostDelayOperation::Submission delay,
                                    String project,
                                    String zone,
                                    String token,
                                    MultiCurlClient::TimePoint deadline)
      : http(http),
        delay(delay),
        deadline(deadline),
        requestDeadline(deadline)
  {
    this->project.assign(project);
    this->zone.assign(zone);
    this->token.assign(token);
  }

  static bool buildSpec(const String& name,
                        const String& zone,
                        const String& vmImage,
                        const String& machineType,
                        const String& cpuPlatform,
                        uint32_t storageMB,
                        bool brain,
                        const String& clusterUUID,
                        const String& bootstrapUser,
                        const String& bootstrapPublicKey,
                        const Vault::SSHKeyPackage& bootstrapHostKey,
                        Spec& spec,
                        String& failure)
  {
    failure.clear();
    if (name.empty() || zone.empty() || vmImage.empty() || machineType.empty())
    {
      failure.assign("gcp provisioning spec identity incomplete"_ctv);
      return false;
    }
    spec.name.assign(name);
    String& body = spec.body;
    body.clear();
    body.append("{\"name\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(body, name);
    body.append(",\"disks\":[{\"boot\":true,\"autoDelete\":true,\"type\":\"PERSISTENT\",\"initializeParams\":{\"sourceImage\":"_ctv);
    prodigyAppendEscapedJSONStringLiteral(body, vmImage);
    const uint64_t diskGB = storageMB == 0 ? 20 : (uint64_t(storageMB) + 1023) / 1024;
    body.snprintf_add<",\"diskSizeGb\":{itoa}}}]"_ctv>(diskGB);
    body.append(",\"machineType\":"_ctv);
    String machineTypeUrl = {};
    machineTypeUrl.snprintf<"zones/{}/machineTypes/{}"_ctv>(zone, machineType);
    prodigyAppendEscapedJSONStringLiteral(body, machineTypeUrl);
    if (cpuPlatform.empty() == false)
    {
      body.append(",\"minCpuPlatform\":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, cpuPlatform);
    }
    body.append(",\"labels\":{\"app\":\"prodigy\",\"brain\":"_ctv);
    if (brain)
    {
      prodigyAppendEscapedJSONStringLiteral(body, "true"_ctv);
    }
    else
    {
      prodigyAppendEscapedJSONStringLiteral(body, "false"_ctv);
    }
    if (clusterUUID.empty() == false)
    {
      body.append(",\"prodigy_cluster_uuid\":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, clusterUUID);
    }
    body.append("},\"metadata\":{\"items\":[{\"key\":\"brain\",\"value\":"_ctv);
    if (brain)
    {
      prodigyAppendEscapedJSONStringLiteral(body, "true"_ctv);
    }
    else
    {
      prodigyAppendEscapedJSONStringLiteral(body, "false"_ctv);
    }
    body.append("}"_ctv);
    if (bootstrapPublicKey.empty() == false)
    {
      String startupScript = {};
      prodigyBuildBootstrapSSHUserData(bootstrapUser,
                                       bootstrapPublicKey,
                                       bootstrapHostKey,
                                       startupScript);
      body.append(",{\"key\":\"startup-script\",\"value\":"_ctv);
      prodigyAppendEscapedJSONStringLiteral(body, startupScript);
      body.append("}"_ctv);
    }
    body.append("]}}"_ctv);
    return true;
  }

  template <typename Ready>
  void run(CoroutineStack *coro,
           const String& templateName,
           const Vector<Spec>& specs,
           Ready ready,
           String& failure)
  {
    failure.clear();
    if (coro == nullptr || http.submit == nullptr || http.cancel == nullptr ||
        delay.queue == nullptr || delay.cancel == nullptr)
    {
      failure.assign("gcp provisioning runtime unavailable"_ctv);
      co_return;
    }
    if (project.empty() || zone.empty() || token.empty() || templateName.empty())
    {
      failure.assign("gcp provisioning identity unavailable"_ctv);
      co_return;
    }
    if (specs.empty() || specs.size() > maximumMachines)
    {
      failure.assign("gcp provisioning requires between 1 and 256 machines"_ctv);
      co_return;
    }
    bytell_hash_set<String> names = {};
    for (const Spec& spec : specs)
    {
      if (spec.name.empty() || spec.body.empty() || names.insert(spec.name).second == false)
      {
        failure.assign("gcp provisioning contains invalid or duplicate spec"_ctv);
        co_return;
      }
    }
    const MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now();
    if (now >= deadline)
    {
      failure.assign("gcp provisioning deadline exceeded"_ctv);
      co_return;
    }
    const MultiCurlClient::Clock::duration cleanupReserve = std::min(
        (deadline - now) / 4,
        std::chrono::duration_cast<MultiCurlClient::Clock::duration>(
            std::chrono::seconds(30)));
    requestDeadline = deadline - cleanupReserve;

    Vector<State> states;
    states.resize(specs.size());
    Vector<MultiCurlClient::Request> createRequests = {};
    createRequests.reserve(specs.size());
    for (uint32_t index = 0; index < specs.size(); ++index)
    {
      states[index].name = specs[index].name;
      createRequests.push_back(createRequest(specs[index], templateName));
    }
    Vector<MultiCurlClient::Result> createResults = {};
    bool createComplete = false;
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          submitWaves(coro, std::move(createRequests), createResults, createComplete);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
    if (createComplete == false)
    {
      failure.assign("gcp provisioning create batch submission failed"_ctv);
    }
    else
    {
      for (uint32_t index = 0; index < createResults.size(); ++index)
      {
        const MultiCurlClient::Result& result = createResults[index];
        states[index].mutation = classifyMutation(result);
        if (result.status != MultiCurlClient::Status::success ||
            result.statusCode < 200 || result.statusCode >= 300)
        {
          if (failure.empty())
          {
            assignRequestFailure(result, "gcp provisioning create"_ctv, failure);
          }
          continue;
        }
        String detail = {};
        if (GcpComputeTransaction::parseOperationName(result.body,
                                                      states[index].operation,
                                                      detail) == false && failure.empty())
        {
          failure = std::move(detail);
        }
      }
    }
    if (failure.empty() == false)
    {
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            cleanup(coro, states, failure);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      co_return;
    }

    for (uint32_t observation = 0; observation < maximumObservations; ++observation)
    {
      Vector<uint32_t> pending = {};
      Vector<MultiCurlClient::Request> instanceRequests = {};
      for (uint32_t index = 0; index < states.size(); ++index)
      {
        if (states[index].ready == false)
        {
          pending.push_back(index);
          instanceRequests.push_back(request(MultiCurlClient::Method::get,
                                             instanceUrl(states[index].name)));
        }
      }
      if (pending.empty())
      {
        co_return;
      }
      if (MultiCurlClient::Clock::now() >= requestDeadline)
      {
        failure.assign("gcp provisioning deadline exceeded"_ctv);
        break;
      }

      Vector<MultiCurlClient::Result> instanceResults = {};
      bool instanceComplete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            submitWaves(coro, std::move(instanceRequests), instanceResults, instanceComplete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (instanceComplete == false)
      {
        failure.assign("gcp provisioning instance observation submission failed"_ctv);
        break;
      }
      for (uint32_t resultIndex = 0; resultIndex < instanceResults.size(); ++resultIndex)
      {
        const uint32_t stateIndex = pending[resultIndex];
        const MultiCurlClient::Result& result = instanceResults[resultIndex];
        if (result.status == MultiCurlClient::Status::success &&
            result.statusCode >= 200 && result.statusCode < 300)
        {
          String detail = {};
          states[stateIndex].ready = ready(stateIndex, result.body, detail);
          if (detail.empty() == false)
          {
            failure = std::move(detail);
            break;
          }
        }
        else if (!(result.status == MultiCurlClient::Status::success && result.statusCode == 404))
        {
          assignRequestFailure(result, "gcp provisioning instance observation"_ctv, failure);
          break;
        }
      }
      if (failure.empty() == false)
      {
        break;
      }

      Vector<uint32_t> operationIndices = {};
      Vector<MultiCurlClient::Request> operationRequests = {};
      for (uint32_t index : pending)
      {
        if (states[index].ready == false && states[index].operationDone == false)
        {
          operationIndices.push_back(index);
          operationRequests.push_back(request(MultiCurlClient::Method::get,
                                              operationUrl(states[index].operation)));
        }
      }
      if (operationRequests.empty() == false)
      {
        Vector<MultiCurlClient::Result> operationResults = {};
        bool operationComplete = false;
        if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
              submitWaves(coro, std::move(operationRequests), operationResults, operationComplete);
            }))
        {
          co_await coro->suspendAtIndex(suspendIndex);
        }
        if (operationComplete == false)
        {
          failure.assign("gcp provisioning operation observation submission failed"_ctv);
          break;
        }
        for (uint32_t resultIndex = 0; resultIndex < operationResults.size(); ++resultIndex)
        {
          const uint32_t stateIndex = operationIndices[resultIndex];
          const MultiCurlClient::Result& result = operationResults[resultIndex];
          if (result.status == MultiCurlClient::Status::success && result.statusCode == 404)
          {
            continue;
          }
          if (result.status != MultiCurlClient::Status::success ||
              result.statusCode < 200 || result.statusCode >= 300)
          {
            assignRequestFailure(result, "gcp provisioning operation observation"_ctv, failure);
            break;
          }
          const OperationState operationState =
              GcpComputeTransaction::parseOperation(result.body, failure);
          if (operationState == OperationState::failed || operationState == OperationState::invalid)
          {
            break;
          }
          states[stateIndex].operationDone = operationState == OperationState::done;
        }
      }
      if (failure.empty() == false)
      {
        break;
      }

      bool allReady = true;
      for (const State& state : states)
      {
        allReady = allReady && state.ready;
      }
      if (allReady)
      {
        co_return;
      }
      if (observation + 1 >= maximumObservations)
      {
        failure.assign("gcp provisioning observation limit exceeded"_ctv);
        break;
      }
      const MultiCurlClient::TimePoint now = MultiCurlClient::Clock::now();
      if (now >= requestDeadline ||
          requestDeadline - now < std::chrono::microseconds(pollDelayUs))
      {
        failure.assign("gcp provisioning deadline exceeded"_ctv);
        break;
      }
      bool delayComplete = false;
      if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
            GcpComputeTransaction::wait(delay, coro, pollDelayUs, delayComplete);
          }))
      {
        co_await coro->suspendAtIndex(suspendIndex);
      }
      if (delayComplete == false)
      {
        failure.assign("gcp provisioning delay failed"_ctv);
        break;
      }
    }

    if (failure.empty())
    {
      failure.assign("gcp provisioning failed"_ctv);
    }
    if (uint32_t suspendIndex = coro->nextSuspendIndex(); coro->didSuspend([&](void) -> void {
          cleanup(coro, states, failure);
        }))
    {
      co_await coro->suspendAtIndex(suspendIndex);
    }
  }
};
